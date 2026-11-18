/**
 * @file pgsql-direct_tls_unix_socket-t.cpp
 * @brief Checks that direct TLS (a ClientHello as the first bytes, no SSLRequest) is refused on a PgSQL
 *        Unix socket, as PostgreSQL does in ProcessSSLStartup(). pgsql-interfaces cannot change at runtime
 *        and the shared ProxySQL has no PgSQL Unix listener, so a secondary ProxySQL is started.
 */

#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mysql.h>

#include "command_line.h"
#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

using std::string;
namespace fs = std::filesystem;

namespace {

constexpr const char* ADMIN_HOST = "127.0.0.1";
constexpr int ADMIN_PORT = 26094;
constexpr int PGSQL_ADMIN_PORT = 26095;
constexpr int SECONDARY_MYSQL_PORT = 26096;
constexpr int WAIT_TIMEOUT_S = 25;
constexpr int RECV_TIMEOUT_S = 5;
const string ALPN_PG = string("\x0a" "postgresql", 11);

class TemporaryRuntimeDirectory {
public:
	TemporaryRuntimeDirectory() {
		// Short pattern: the socket path must fit in sockaddr_un::sun_path.
		const string template_value = (fs::temp_directory_path() / "proxysql-dtu-XXXXXX").string();
		std::vector<char> path_template(template_value.begin(), template_value.end());
		path_template.push_back('\0');
		char* created = mkdtemp(path_template.data()); // NOSONAR: mkdtemp creates the directory atomically with owner-only permissions.
		if (created != nullptr) path_ = created;
	}
	~TemporaryRuntimeDirectory() {
		if (path_.empty()) return;
		std::error_code cleanup_error;
		fs::remove_all(path_, cleanup_error);
	}
	TemporaryRuntimeDirectory(const TemporaryRuntimeDirectory&) = delete;
	TemporaryRuntimeDirectory& operator=(const TemporaryRuntimeDirectory&) = delete;
	bool valid() const { return !path_.empty(); }
	const fs::path& path() const { return path_; }
private:
	fs::path path_ {};
};

int prepare_runtime(const CommandLine& cl, const fs::path& dir, const fs::path& cfg_file, const fs::path& pgsql_socket) {
	std::ofstream cfg { cfg_file };
	if (!cfg.is_open()) return EXIT_FAILURE;
	cfg
		<< "datadir=\"" << dir.string() << "\"\n"
		<< "errorlog=\"" << (dir / "proxysql.log").string() << "\"\n\n"
		<< "admin_variables=\n{\n"
		<< "\tadmin_credentials=\"admin:admin;" << cl.admin_username << ":" << cl.admin_password << "\"\n"
		<< "\tmysql_ifaces=\"" << ADMIN_HOST << ":" << ADMIN_PORT << "\"\n"
		<< "\tpgsql_ifaces=\"" << ADMIN_HOST << ":" << PGSQL_ADMIN_PORT << "\"\n}\n\n"
		<< "mysql_variables=\n{\n\tinterfaces=\"" << ADMIN_HOST << ":" << SECONDARY_MYSQL_PORT << "\"\n}\n\n"
		<< "pgsql_variables=\n{\n\tinterfaces=\"" << pgsql_socket.string() << "\"\n}\n\n"
		<< "pgsql_users=\n(\n"
		<< "\t{ username=\"tapuser\" password=\"tappass\" active=1 default_hostgroup=0 frontend=1 backend=0 }\n"
		<< ")\n";
	cfg.flush();
	return cfg.good() ? EXIT_SUCCESS : EXIT_FAILURE;
}

/** Connects to the Unix socket with a 5 s receive timeout; -1 on failure. */
int unix_connect(const fs::path& socket_path) {
	const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) return -1;
	sockaddr_un addr {};
	addr.sun_family = AF_UNIX;
	const string path = socket_path.string();
	if (path.size() >= sizeof(addr.sun_path)) {
		close(fd);
		return -1;
	}
	memcpy(addr.sun_path, path.c_str(), path.size() + 1);
	timeval timeout { RECV_TIMEOUT_S, 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/** Protocol 3.0 StartupMessage for tapuser/postgres. */
std::vector<uint8_t> startup_packet() {
	std::vector<uint8_t> pkt(4);
	pkt.insert(pkt.end(), { 0x00, 0x03, 0x00, 0x00 });
	for (const string& p : { string("user"), string("tapuser"), string("database"), string("postgres") }) {
		pkt.insert(pkt.end(), p.begin(), p.end());
		pkt.push_back(0);
	}
	pkt.push_back(0);
	const uint32_t len = pkt.size();
	pkt[0] = (len >> 24) & 0xFF;
	pkt[1] = (len >> 16) & 0xFF;
	pkt[2] = (len >> 8) & 0xFF;
	pkt[3] = len & 0xFF;
	return pkt;
}

/** Plaintext startup over the Unix socket; returns the type byte of the first reply, '?' when none. */
char plaintext_startup_reply(const fs::path& socket_path) {
	char type = '?';
	const int fd = unix_connect(socket_path);
	if (fd == -1) return type;
	const std::vector<uint8_t> pkt = startup_packet();
	if (send(fd, pkt.data(), pkt.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(pkt.size())) {
		if (recv(fd, &type, 1, 0) != 1) type = '?';
	}
	close(fd);
	return type;
}

/** Direct TLS (ALPN postgresql, no SSLRequest). tls_established tells whether the handshake succeeded;
 *  closed tells whether the server then closed the socket (recv 0 or an error other than a timeout). */
void direct_tls_attempt(const fs::path& socket_path, bool& tls_established, bool& closed) {
	tls_established = true;
	closed = false;
	const int fd = unix_connect(socket_path);
	if (fd == -1) return;
	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	SSL* tls = ctx ? SSL_new(ctx) : nullptr;
	if (tls != nullptr) {
		// On the SSL object: SSL_new() already copied the (empty) ctx list.
		SSL_set_alpn_protos(tls, reinterpret_cast<const unsigned char*>(ALPN_PG.data()), ALPN_PG.size());
		SSL_set_fd(tls, fd);
		tls_established = SSL_connect(tls) == 1;
		if (!tls_established) {
			char b;
			const ssize_t n = recv(fd, &b, 1, 0);
			closed = n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK);
		}
	}
	if (tls) SSL_free(tls);
	if (ctx) SSL_CTX_free(ctx);
	close(fd);
}

string read_file(const fs::path& path) {
	std::ifstream in { path };
	return string { std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>() };
}

} // namespace

int main(int, char**) {
	CommandLine cl;
	const char* workspace = getenv("WORKSPACE");
	if (cl.getEnv() || workspace == nullptr) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}
	plan(6);

	TemporaryRuntimeDirectory tmp;
	if (!tmp.valid()) {
		diag("Failed to create a private ProxySQL runtime directory: %s", strerror(errno));
		return EXIT_FAILURE;
	}
	const fs::path& dir = tmp.path();
	const fs::path config_file { dir / "proxysql.cfg" };
	const fs::path pgsql_socket { dir / "pgsql.sock" };
	const fs::path log_file { dir / "proxysql.log" };
	if (prepare_runtime(cl, dir, config_file, pgsql_socket) != EXIT_SUCCESS) {
		diag("Failed to write the secondary ProxySQL config");
		return EXIT_FAILURE;
	}

	std::atomic<int> launch_result { -1 };
	string launch_stdout;
	string launch_stderr;
	std::thread launch_proxy([&]() {
		to_opts_t opts {};
		opts.poll_to_us = 100 * 1000;
		opts.waitpid_delay_us = 500 * 1000;
		opts.timeout_us = 30000 * 1000;
		opts.sigkill_to_us = 3000 * 1000;
		const string binary = string { workspace } + "/src/proxysql";
		const string config = config_file.string();
		const string datadir = dir.string();
		const std::vector<const char*> args { "-f", "-M", "--reload", "-c", config.c_str(), "-D", datadir.c_str() };
		launch_result.store(wexecvp(binary, args, opts, launch_stdout, launch_stderr));
	});

	conn_opts_t admin_opts { ADMIN_HOST, cl.admin_username, cl.admin_password, ADMIN_PORT, 0 };
	MYSQL* admin = wait_for_proxysql(admin_opts, WAIT_TIMEOUT_S);
	ok(admin != nullptr, "secondary ProxySQL started with a PgSQL Unix-socket listener");

	bool failed = admin == nullptr;
	if (admin != nullptr) {
		const char type = plaintext_startup_reply(pgsql_socket);
		ok(type == 'R', "plaintext startup over the PgSQL Unix socket: answered with an authentication request (got '%c')", type);
		failed |= type != 'R';

		bool tls_established = true, closed = false;
		direct_tls_attempt(pgsql_socket, tls_established, closed);
		ok(!tls_established && closed, "direct TLS (ALPN postgresql) over the PgSQL Unix socket: refused, connection closed");
		failed |= tls_established || !closed;

		const char type2 = plaintext_startup_reply(pgsql_socket);
		ok(type2 == 'R', "plaintext startup over the Unix socket still works after the refusal (got '%c')", type2);
		failed |= type2 != 'R';

		if (mysql_query(admin, "PROXYSQL SHUTDOWN SLOW") != 0) diag("Shutdown query failed: %s", mysql_error(admin));
		mysql_close(admin);
	} else {
		for (int i = 0; i < 3; i++) ok(false, "skipped: secondary ProxySQL did not start");
	}

	launch_proxy.join();
	// With -f ProxySQL logs to stderr (errorlog applies only when daemonized); look in all three places,
	// after shutdown so the captured output is complete.
	const string needle = "refused: not supported on a Unix socket";
	const bool logged = launch_stderr.find(needle) != string::npos || launch_stdout.find(needle) != string::npos ||
		read_file(log_file).find(needle) != string::npos;
	if (admin != nullptr) {
		ok(logged, "secondary ProxySQL logged 'Direct TLS connection from ... refused: not supported on a Unix socket'");
		failed |= !logged;
	} else {
		ok(false, "skipped: secondary ProxySQL did not start");
	}
	ok(launch_result.load() == EXIT_SUCCESS, "secondary ProxySQL exited cleanly");
	failed |= launch_result.load() != EXIT_SUCCESS;

	if (failed) {
		const string log = read_file(log_file);
		diag("secondary stdout: %s", launch_stdout.c_str());
		diag("secondary stderr: %s", launch_stderr.c_str());
		diag("proxysql.log tail: %s", log.substr(log.size() > 3000 ? log.size() - 3000 : 0).c_str());
	}
	return exit_status();
}
