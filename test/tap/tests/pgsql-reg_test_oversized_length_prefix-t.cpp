/**
 * @file pgsql-reg_test_oversized_length_prefix-t.cpp
 * @brief Regression test for GHSA-33xp-q4g3-r79r.
 *
 * @details ProxySQL used to allocate whatever size a PostgreSQL client announced in the 4-byte
 *   length prefix of a message, before authentication, without checking the allocation. A
 *   5-byte header could make it reserve up to ~4GiB, and a failed allocation crashed the proxy.
 *   Oversized messages must now be rejected by closing the connection right away:
 *   - before authentication, anything above 64KiB. The first (startup) packet already had a
 *     dedicated check; the authentication messages following it did not;
 *   - after authentication, anything above PostgreSQL's 1GB message limit.
 *   The test checks that ProxySQL closes such connections promptly (instead of waiting for the
 *   announced payload) and stays operational.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

namespace {

// Pre-fix ProxySQL waits for the announced payload until 'pgsql-connect_timeout_client' (10s by
// default) before authentication, and forever after it; the fixed one closes immediately.
constexpr int CLOSE_WAIT_MS = 3000;

int raw_connect(const std::string& host, int port) {
	struct addrinfo hints {};
	struct addrinfo* res = nullptr;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
		return -1;
	}
	int fd = -1;
	for (struct addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0) continue;
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

bool send_all(int fd, const std::vector<uint8_t>& buf) {
	size_t sent = 0;
	while (sent < buf.size()) {
		ssize_t n = send(fd, buf.data() + sent, buf.size() - sent, MSG_NOSIGNAL);
		if (n <= 0) return false;
		sent += n;
	}
	return true;
}

/**
 * @brief Returns true if the peer closes the connection within 'timeout_ms'.
 * @details Any data sent before the close (e.g. an ErrorResponse) is discarded.
 */
bool closed_by_peer(int fd, int timeout_ms) {
	char buf[4096];
	int waited = 0;
	while (waited < timeout_ms) {
		struct pollfd pfd { fd, POLLIN, 0 };
		int r = poll(&pfd, 1, 100);
		waited += 100;
		if (r < 0) return false;
		if (r == 0) continue;
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		if (n == 0) return true;
		if (n < 0) return errno == ECONNRESET;
	}
	return false;
}

std::vector<uint8_t> be32(uint32_t v) {
	return { uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v) };
}

std::vector<uint8_t> typed_header(char type, uint32_t len) {
	std::vector<uint8_t> h { uint8_t(type) };
	auto l = be32(len);
	h.insert(h.end(), l.begin(), l.end());
	return h;
}

bool preauth_rejected(const std::string& host, int port, const std::vector<uint8_t>& pkt) {
	int fd = raw_connect(host, port);
	if (fd < 0) {
		diag("Connection to %s:%d failed", host.c_str(), port);
		return false;
	}
	bool res = send_all(fd, pkt) && closed_by_peer(fd, CLOSE_WAIT_MS);
	close(fd);
	return res;
}

/**
 * @brief Sends a valid startup message, waits for the authentication request, then sends 'pkt'
 *   as the (pre-auth) authentication response.
 * @details The first packet has a dedicated size check; the messages following it go through
 *   the generic message parser, which is where the unbounded allocation was.
 */
bool postStartup_rejected(const std::string& host, int port, const std::string& user, const std::vector<uint8_t>& pkt) {
	int fd = raw_connect(host, port);
	if (fd < 0) {
		diag("Connection to %s:%d failed", host.c_str(), port);
		return false;
	}
	std::vector<uint8_t> body = be32(196608);
	for (const std::string& kv : { std::string("user"), user, std::string("database"), user }) {
		body.insert(body.end(), kv.begin(), kv.end());
		body.push_back(0);
	}
	body.push_back(0);
	std::vector<uint8_t> startup = be32(body.size() + 4);
	startup.insert(startup.end(), body.begin(), body.end());

	bool res = false;
	uint8_t type = 0;
	struct pollfd pfd { fd, POLLIN, 0 };
	if (send_all(fd, startup) && poll(&pfd, 1, CLOSE_WAIT_MS) == 1 && recv(fd, &type, 1, MSG_PEEK) == 1) {
		if (type != 'R') {
			diag("Unexpected reply to startup message: '%c'", type);
		} else {
			res = send_all(fd, pkt) && closed_by_peer(fd, CLOSE_WAIT_MS);
		}
	} else {
		diag("No reply to startup message");
	}
	close(fd);
	return res;
}

std::string conninfo(const std::string& host, int port, const std::string& user, const std::string& pass) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass << " sslmode=disable";
	return ss.str();
}

bool query_works(const std::string& ci, const std::string& query = "SELECT 1") {
	PGconn* conn = PQconnectdb(ci.c_str());
	bool res = false;
	if (PQstatus(conn) == CONNECTION_OK) {
		PGresult* r = PQexec(conn, query.c_str());
		res = PQresultStatus(r) == PGRES_TUPLES_OK;
		if (!res) diag("Query failed: %s", PQresultErrorMessage(r));
		PQclear(r);
	} else {
		diag("Connection failed: %s", PQerrorMessage(conn));
	}
	PQfinish(conn);
	return res;
}

bool postauth_rejected(const std::string& ci, const std::vector<uint8_t>& pkt) {
	PGconn* conn = PQconnectdb(ci.c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection failed: %s", PQerrorMessage(conn));
		PQfinish(conn);
		return false;
	}
	int fd = PQsocket(conn);
	bool res = send_all(fd, pkt) && closed_by_peer(fd, CLOSE_WAIT_MS);
	PQfinish(conn);
	return res;
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	struct target_t {
		const char* name;
		std::string host;
		int port;
		std::string user;
		std::string ci;
	};
	const std::vector<target_t> targets {
		{ "BACKEND", cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, conninfo(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password) },
		{ "ADMIN", cl.admin_host, cl.pgsql_admin_port, cl.admin_username, conninfo(cl.admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password) },
	};

	plan(targets.size() * 8);

	for (const auto& t : targets) {
		ok(query_works(t.ci), "%s: baseline connection and query work", t.name);

		// Typed message announcing ~2GiB (the first byte being non-zero makes it typed).
		ok(preauth_rejected(t.host, t.port, typed_header('p', 0x7FFFFFFF)),
			"%s: pre-auth typed message announcing 2GiB is rejected", t.name);

		// Startup (untyped) message announcing 1MiB, above the pre-auth limit.
		std::vector<uint8_t> startup = be32(1024 * 1024);
		auto ver = be32(196608);
		startup.insert(startup.end(), ver.begin(), ver.end());
		ok(preauth_rejected(t.host, t.port, startup),
			"%s: pre-auth startup message announcing 1MiB is rejected", t.name);

		// Authentication response announcing ~2GiB / 1MiB, after a valid startup message.
		ok(postStartup_rejected(t.host, t.port, t.user, typed_header('p', 0x7FFFFFFF)),
			"%s: pre-auth password message announcing 2GiB is rejected", t.name);
		ok(postStartup_rejected(t.host, t.port, t.user, typed_header('p', 1024 * 1024)),
			"%s: pre-auth password message announcing 1MiB is rejected", t.name);

		// Authenticated client announcing a message above PostgreSQL's 1GB limit.
		ok(postauth_rejected(t.ci, typed_header('Q', 0x60000000)),
			"%s: post-auth Query announcing 1.5GiB is rejected", t.name);

		// Regular startup packets and queries keep working.
		ok(query_works(t.ci), "%s: connections and queries still work", t.name);
		// The pre-auth limit must not apply after authentication.
		ok(query_works(t.ci, "SELECT '" + std::string(200 * 1024, 'x') + "'"),
			"%s: post-auth 200KiB query (above the pre-auth limit) works", t.name);
	}

	return exit_status();
}
