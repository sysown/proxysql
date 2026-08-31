/**
 * @file mysql-server_version_by_interface-t.cpp
 * @brief Verify that frontend handshakes use the version mapped to the exact
 *        mysql-interfaces token that accepted the connection.
 */

#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "command_line.h"
#include "mysqld_error.h"
#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

using std::string;
namespace fs = std::filesystem;

namespace {

constexpr const char* ADMIN_HOST = "127.0.0.1";
constexpr int ADMIN_PORT = 26084;
constexpr int FRONTEND_PORT = 36084;
constexpr int FALLBACK_PORT = 36085;
constexpr int IPV6_PORT = 36086;
constexpr int WAIT_TIMEOUT_S = 25;
constexpr const char* FALLBACK_VERSION = "8.0.11-fallback";
constexpr const char* IPV4_A_VERSION = "8.1.0-interface-a";
constexpr const char* IPV4_B_VERSION = "5.7.44-interface-b";
constexpr const char* SOCKET_VERSION = "8.1.4-interface-socket";
constexpr const char* IPV6_VERSION = "8.1.0-interface-v6";
constexpr const char* RELOADED_IPV4_A_VERSION = "5.7.99-reloaded";

class TemporaryRuntimeDirectory {
public:
	TemporaryRuntimeDirectory() {
		const string template_value =
			(fs::temp_directory_path() / "proxysql-svbi-XXXXXX").string();
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
	TemporaryRuntimeDirectory(TemporaryRuntimeDirectory&&) = delete;
	TemporaryRuntimeDirectory& operator=(TemporaryRuntimeDirectory&&) = delete;

	bool valid() const { return !path_.empty(); }
	const fs::path& path() const { return path_; }

private:
	fs::path path_ {};
};

bool ipv6_loopback_available() {
	const int fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) return false;

	sockaddr_in6 addr {};
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(IPV6_PORT);
	addr.sin6_addr = in6addr_loopback;
	const bool available = bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
	close(fd);
	return available;
}

bool read_exact(int fd, void* buffer, size_t length) {
	auto* cursor = static_cast<unsigned char*>(buffer);
	while (length != 0) {
		const ssize_t count = recv(fd, cursor, length, 0);
		if (count <= 0) return false;
		cursor += count;
		length -= static_cast<size_t>(count);
	}
	return true;
}

string make_catalog(const fs::path& mysql_socket, bool use_ipv6, const char* ipv4_a_version) {
	string catalog =
		"{\"127.0.0.1:36084\":\"" + string { ipv4_a_version } +
		"\",\"127.0.0.2:36084\":\"" + IPV4_B_VERSION +
		"\",\"" + mysql_socket.string() + "\":\"" + SOCKET_VERSION +
		"\",\"192.0.2.10:49999\":\"9.9.9-unused\"";
	if (use_ipv6) {
		catalog += ",\"[::1]:36086\":\"" + string { IPV6_VERSION } + "\"";
	}
	return catalog + "}";
}

string escape_libconfig_string(const string& value) {
	string escaped;
	escaped.reserve(value.size() * 2);
	for (const char ch : value) {
		if (ch == '\\' || ch == '"') escaped += '\\';
		escaped += ch;
	}
	return escaped;
}

string read_handshake_version(int fd) {
	unsigned char header[4] {};
	if (!read_exact(fd, header, sizeof(header))) return {};
	const size_t payload_length =
		static_cast<size_t>(header[0]) |
		(static_cast<size_t>(header[1]) << 8) |
		(static_cast<size_t>(header[2]) << 16);
	std::vector<unsigned char> payload(payload_length);
	if (payload_length < 2 || !read_exact(fd, payload.data(), payload.size())) return {};

	const auto* begin = reinterpret_cast<const char*>(payload.data() + 1);
	const size_t available = payload.size() - 1;
	const size_t version_length = strnlen(begin, available);
	if (version_length == available) return {};
	return string(begin, version_length);
}

string tcp_handshake_version(const char* host, int port, int family) {
	const int fd = socket(family, SOCK_STREAM, 0);
	if (fd == -1) return {};

	int rc = -1;
	if (family == AF_INET) {
		sockaddr_in addr {};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		if (inet_pton(AF_INET, host, &addr.sin_addr) == 1) {
			rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
		}
	} else {
		sockaddr_in6 addr {};
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(port);
		if (inet_pton(AF_INET6, host, &addr.sin6_addr) == 1) {
			rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
		}
	}

	const string version = rc == 0 ? read_handshake_version(fd) : string {};
	close(fd);
	return version;
}

string unix_handshake_version(const fs::path& socket_path) {
	const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) return {};

	sockaddr_un addr {};
	addr.sun_family = AF_UNIX;
	const string path = socket_path.string();
	if (path.size() >= sizeof(addr.sun_path)) {
		close(fd);
		return {};
	}
	memcpy(addr.sun_path, path.c_str(), path.size() + 1);
	const int rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
	const string version = rc == 0 ? read_handshake_version(fd) : string {};
	close(fd);
	return version;
}

MYSQL* connect_frontend(const char* host, int port, const char* socket_path = nullptr) {
	MYSQL* mysql = mysql_init(nullptr);
	if (mysql == nullptr) return nullptr;
	if (mysql_real_connect(mysql, host, "tapuser", "tappass", nullptr, port, socket_path, 0) == nullptr) {
		diag("Frontend connection failed: %s", mysql_error(mysql));
		mysql_close(mysql);
		return nullptr;
	}
	return mysql;
}

bool query_returns_version(MYSQL* mysql, const char* query, const char* expected, string& actual) {
	auto [error, rows] = mysql_query_ext_rows(mysql, query);
	if (error == EXIT_SUCCESS && rows.size() == 1 && !rows.front().empty()) {
		actual = rows.front().front();
	}
	return error == EXIT_SUCCESS && rows.size() == 1 && rows.front().size() == 1 && actual == expected;
}

bool admin_variable_equals(
	MYSQL* admin,
	const char* table,
	const char* variable_name,
	const string& expected,
	string& actual
) {
	const string query =
		"SELECT variable_value FROM " + string { table } +
		" WHERE variable_name='" + variable_name + "'";
	auto [error, rows] = mysql_query_ext_rows(admin, query);
	if (error == EXIT_SUCCESS && rows.size() == 1 && rows.front().size() == 1) {
		actual = rows.front().front();
	}
	return error == EXIT_SUCCESS && rows.size() == 1 && rows.front().size() == 1 && actual == expected;
}

bool dollar_quote_error_matches(MYSQL* mysql, bool supports_dollar_quotes, string& actual) {
	const int rc = mysql_query(mysql, "SELECT $$");
	const int expected_code = supports_dollar_quotes ? ER_PARSE_ERROR : ER_BAD_FIELD_ERROR;
	const int actual_code = mysql_errno(mysql);
	actual = std::to_string(actual_code) + " (" + mysql_error(mysql) + ")";
	return rc != 0 && actual_code == expected_code;
}

int prepare_runtime(
	const CommandLine& cl,
	const fs::path& runtime_dir,
	const fs::path& config_file,
	const fs::path& mysql_socket,
	bool use_ipv6
) {
	try {
		std::ofstream cfg { config_file };
		if (!cfg.is_open()) return EXIT_FAILURE;

		string interfaces =
			"127.0.0.1:36084;127.0.0.2:36084;127.0.0.1:36085;" + mysql_socket.string();
		if (use_ipv6) interfaces += ";[::1]:36086";

		const string catalog = escape_libconfig_string(make_catalog(mysql_socket, use_ipv6, IPV4_A_VERSION));

		cfg
			<< "datadir=\"" << runtime_dir.string() << "\"\n"
			<< "errorlog=\"" << (runtime_dir / "proxysql.log").string() << "\"\n\n"
			<< "admin_variables=\n{\n"
			<< "\tadmin_credentials=\"admin:admin;" << cl.admin_username << ":" << cl.admin_password << "\"\n"
			<< "\tmysql_ifaces=\"" << ADMIN_HOST << ":" << ADMIN_PORT << "\"\n}\n\n"
			<< "mysql_variables=\n{\n"
			<< "\tinterfaces=\"" << interfaces << "\"\n"
			<< "\tserver_version=\"" << FALLBACK_VERSION << "\"\n"
			<< "\tserver_version_by_interface=\"" << catalog << "\"\n"
			<< "\tselect_version_forwarding=0\n}\n\n"
			<< "mysql_users=\n(\n"
			<< "\t{ username=\"tapuser\" password=\"tappass\" active=1 default_hostgroup=0 frontend=1 backend=0 }\n"
			<< ")\n";
		return EXIT_SUCCESS;
	} catch (const std::exception& ex) {
		diag("Failed to prepare secondary ProxySQL runtime: %s", ex.what());
		return EXIT_FAILURE;
	}
}

} // namespace

int main(int, char**) {
	CommandLine cl;
	const char* workspace = getenv("WORKSPACE");
	if (cl.getEnv() || workspace == nullptr) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const bool use_ipv6 = ipv6_loopback_available();
	plan(use_ipv6 ? 28 : 27);

	// Keep the Unix listener below sockaddr_un::sun_path even when TAP_WORKDIR
	// is an absolute repository path supplied by the isolated test harness.
	TemporaryRuntimeDirectory temporary_runtime_directory;
	if (!temporary_runtime_directory.valid()) {
		diag("Failed to create a private ProxySQL runtime directory: %s", strerror(errno));
		return EXIT_FAILURE;
	}
	const fs::path& runtime_dir = temporary_runtime_directory.path();
	const fs::path config_file { runtime_dir / "proxysql.cfg" };
	const fs::path mysql_socket { runtime_dir / "mysql.sock" };
	if (prepare_runtime(cl, runtime_dir, config_file, mysql_socket, use_ipv6) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	std::atomic<int> launch_result { -1 };
	string launch_stdout;
	string launch_stderr;
	std::thread launch_proxy([
		workspace, &runtime_dir, &config_file, &launch_result, &launch_stdout, &launch_stderr
	]() {
		to_opts_t opts {};
		opts.poll_to_us = 100 * 1000;
		opts.waitpid_delay_us = 500 * 1000;
		opts.timeout_us = 30000 * 1000;
		opts.sigkill_to_us = 3000 * 1000;
		const string binary = string { workspace } + "/src/proxysql";
		const string config = config_file.string();
		const string datadir = runtime_dir.string();
		const std::vector<const char*> args {
			"-f", "-M", "--reload", "-c", config.c_str(), "-D", datadir.c_str()
		};
		launch_result.store(wexecvp(binary, args, opts, launch_stdout, launch_stderr));
	});

	conn_opts_t admin_opts { ADMIN_HOST, cl.admin_username, cl.admin_password, ADMIN_PORT, 0 };
	MYSQL* admin = wait_for_proxysql(admin_opts, WAIT_TIMEOUT_S);
	MYSQL* original_ipv4_a = nullptr;
	MYSQL* socket_client = nullptr;
	MYSQL* reloaded_ipv4_a = nullptr;
	ok(admin != nullptr, "Secondary ProxySQL started with per-interface version configuration");

	if (admin != nullptr) {
		const string ipv4_a = tcp_handshake_version("127.0.0.1", FRONTEND_PORT, AF_INET);
		ok(ipv4_a == IPV4_A_VERSION, "First IPv4 interface uses its exact mapped version (received '%s')", ipv4_a.c_str());
		const string ipv4_b = tcp_handshake_version("127.0.0.2", FRONTEND_PORT, AF_INET);
		ok(ipv4_b == IPV4_B_VERSION, "Second IPv4 interface sharing the port uses its mapping (received '%s')", ipv4_b.c_str());
		const string fallback = tcp_handshake_version("127.0.0.1", FALLBACK_PORT, AF_INET);
		ok(fallback == FALLBACK_VERSION, "Unmapped interface uses mysql-server_version fallback (received '%s')", fallback.c_str());
		const string socket = unix_handshake_version(mysql_socket);
		ok(socket == SOCKET_VERSION, "Unix socket uses its exact mapped version (received '%s')", socket.c_str());
		if (use_ipv6) {
			const string ipv6 = tcp_handshake_version("::1", IPV6_PORT, AF_INET6);
			ok(ipv6 == IPV6_VERSION, "Bracketed IPv6 token uses its exact mapped version (received '%s')", ipv6.c_str());
		}

		original_ipv4_a = connect_frontend("127.0.0.1", FRONTEND_PORT);
		ok(original_ipv4_a != nullptr, "Authenticated session connects through the mapped IPv4 interface");
		if (original_ipv4_a != nullptr) {
			ok(strcmp(mysql_get_server_info(original_ipv4_a), IPV4_A_VERSION) == 0,
				"Authenticated IPv4 session receives the mapped handshake version");
			string actual;
			bool matches = query_returns_version(original_ipv4_a, "SELECT @@version", IPV4_A_VERSION, actual);
			ok(matches,
				"SELECT @@version uses the pinned interface version (received '%s')", actual.c_str());
			matches = query_returns_version(original_ipv4_a, "SELECT VERSION()", IPV4_A_VERSION, actual);
			ok(matches,
				"SELECT VERSION() uses the pinned interface version (received '%s')", actual.c_str());
			matches = dollar_quote_error_matches(original_ipv4_a, true, actual);
			ok(matches,
				"SELECT $$ uses the pinned 8.1+ error semantics (received '%s')", actual.c_str());
		} else {
			for (int i = 0; i < 4; ++i) ok(false, "IPv4 session assertion unavailable");
		}

		socket_client = connect_frontend(nullptr, 0, mysql_socket.c_str());
		ok(socket_client != nullptr, "Authenticated session connects through the mapped Unix socket");
		if (socket_client != nullptr) {
			ok(strcmp(mysql_get_server_info(socket_client), SOCKET_VERSION) == 0,
				"Authenticated Unix-socket session receives the mapped handshake version");
			string actual;
			bool matches = query_returns_version(socket_client, "SELECT @@version", SOCKET_VERSION, actual);
			ok(matches,
				"Unix-socket SELECT @@version uses its pinned version (received '%s')", actual.c_str());
			matches = dollar_quote_error_matches(socket_client, true, actual);
			ok(matches,
				"Unix-socket SELECT $$ uses its pinned version semantics (received '%s')", actual.c_str());
		} else {
			for (int i = 0; i < 3; ++i) ok(false, "Unix-socket session assertion unavailable");
		}

		const string reloaded_catalog = make_catalog(mysql_socket, use_ipv6, RELOADED_IPV4_A_VERSION);
		MYSQL_QUERY_T(admin, (
			"UPDATE global_variables SET variable_value='" + reloaded_catalog +
			"' WHERE variable_name='mysql-server_version_by_interface'"
		).c_str());
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		if (original_ipv4_a != nullptr) {
			ok(strcmp(mysql_get_server_info(original_ipv4_a), IPV4_A_VERSION) == 0,
				"Existing session retains its original handshake version after reload");
			string actual;
			bool matches = query_returns_version(original_ipv4_a, "SELECT @@version", IPV4_A_VERSION, actual);
			ok(matches,
				"Existing session retains its pinned internal version after reload (received '%s')", actual.c_str());
			matches = dollar_quote_error_matches(original_ipv4_a, true, actual);
			ok(matches,
				"Existing session retains its pinned error semantics after reload (received '%s')", actual.c_str());
		} else {
			for (int i = 0; i < 3; ++i) ok(false, "Reload assertion unavailable without original session");
		}

		reloaded_ipv4_a = connect_frontend("127.0.0.1", FRONTEND_PORT);
		ok(reloaded_ipv4_a != nullptr, "New IPv4 session connects after catalog reload");
		if (reloaded_ipv4_a != nullptr) {
			ok(strcmp(mysql_get_server_info(reloaded_ipv4_a), RELOADED_IPV4_A_VERSION) == 0,
				"New session receives the reloaded handshake version");
			string actual;
			bool matches = query_returns_version(
				reloaded_ipv4_a, "SELECT VERSION()", RELOADED_IPV4_A_VERSION, actual
			);
			ok(matches,
				"New session uses the reloaded internal version (received '%s')", actual.c_str());
			matches = dollar_quote_error_matches(reloaded_ipv4_a, false, actual);
			ok(matches,
				"New session uses the reloaded pre-8.1 error semantics (received '%s')", actual.c_str());
		} else {
			for (int i = 0; i < 3; ++i) ok(false, "Reloaded session assertion unavailable");
		}

		MYSQL_QUERY_T(admin, "SAVE MYSQL VARIABLES TO DISK");
		string actual;
		bool matches = admin_variable_equals(
			admin, "disk.global_variables", "mysql-server_version_by_interface", reloaded_catalog, actual
		);
		ok(matches, "SAVE MYSQL VARIABLES persists the exact JSON catalog (received '%s')", actual.c_str());

		MYSQL_QUERY_T(admin,
			"UPDATE global_variables SET variable_value='{}' "
			"WHERE variable_name='mysql-server_version_by_interface'");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		MYSQL* cleared_ipv4_a = connect_frontend("127.0.0.1", FRONTEND_PORT);
		matches = cleared_ipv4_a != nullptr &&
			strcmp(mysql_get_server_info(cleared_ipv4_a), FALLBACK_VERSION) == 0;
		ok(matches, "An empty runtime catalog makes new sessions use mysql-server_version fallback");
		if (cleared_ipv4_a != nullptr) mysql_close(cleared_ipv4_a);

		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES FROM DISK");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		actual.clear();
		matches = admin_variable_equals(
			admin, "global_variables", "mysql-server_version_by_interface", reloaded_catalog, actual
		);
		ok(matches, "LOAD MYSQL VARIABLES restores the exact JSON catalog (received '%s')", actual.c_str());
		actual.clear();
		matches = admin_variable_equals(
			admin, "runtime_global_variables", "mysql-server_version_by_interface", reloaded_catalog, actual
		);
		ok(matches, "The restored JSON catalog is loaded to runtime unchanged (received '%s')", actual.c_str());

		MYSQL* restored_ipv4_a = connect_frontend("127.0.0.1", FRONTEND_PORT);
		matches = restored_ipv4_a != nullptr &&
			strcmp(mysql_get_server_info(restored_ipv4_a), RELOADED_IPV4_A_VERSION) == 0;
		ok(matches, "A new session uses the per-interface version restored from disk");
		if (restored_ipv4_a != nullptr) mysql_close(restored_ipv4_a);

		if (reloaded_ipv4_a != nullptr) mysql_close(reloaded_ipv4_a);
		if (socket_client != nullptr) mysql_close(socket_client);
		if (original_ipv4_a != nullptr) mysql_close(original_ipv4_a);

		const int shutdown_rc = mysql_query(admin, "PROXYSQL SHUTDOWN SLOW");
		if (shutdown_rc != 0) diag("Shutdown query failed: %s", mysql_error(admin));
		mysql_close(admin);
	} else {
		for (int i = 0; i < (use_ipv6 ? 26 : 25); ++i) {
			ok(false, "Handshake version unavailable because secondary ProxySQL did not start");
		}
	}

	if (launch_proxy.joinable()) launch_proxy.join();
	ok(launch_result.load() == EXIT_SUCCESS, "Secondary ProxySQL exited cleanly");
	if (tests_failed()) {
		diag("Secondary ProxySQL stdout:\n%s", launch_stdout.c_str());
		diag("Secondary ProxySQL stderr:\n%s", launch_stderr.c_str());
	}
	return exit_status();
}
