/**
 * @file reg_test_mysql_empty_command_packet-t.cpp
 * @brief Regression test for GHSA-w9p8-gf9c-hffr (empty command packet).
 *
 * @details An authenticated client could send a MySQL packet with an empty payload (length 0).
 *   ProxySQL read the command byte one byte past the 4-byte allocation, and the stale byte picked
 *   the command handler: COM_INIT_DB then underflowed 'pkt.size - 5', and on the admin interface
 *   COM_QUERY made admin_session_handler() copy 'query_length - 1' (~4GiB) bytes into an empty
 *   buffer. ProxySQL now closes the connection when a command packet has no payload.
 *
 *   For the MySQL frontend and for the admin interface, the test sends empty packets on an
 *   authenticated connection, checks that ProxySQL closes the connection promptly, and that it
 *   keeps serving clients afterwards. The stale byte made the crash depend on heap contents, so
 *   an unfixed ProxySQL may survive a few packets; the size checks themselves are covered by
 *   unit/mysql_client_packet_size_unit-t.
 */

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

namespace {

constexpr int WAIT_MS = 3000;
constexpr int ATTEMPTS = 20;

/** @brief Returns true if the peer closes the connection within 'timeout_ms'. */
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

MYSQL* connect_to(const char* host, int port, const char* user, const char* pass) {
	MYSQL* conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, host, user, pass, NULL, port, NULL, 0)) {
		diag("Connection to %s:%d failed: %s", host, port, mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}
	return conn;
}

bool query_works(const char* host, int port, const char* user, const char* pass) {
	MYSQL* conn = connect_to(host, port, user, pass);
	if (conn == NULL) return false;
	bool res = mysql_query(conn, "SELECT 1") == 0;
	if (res) {
		MYSQL_RES* r = mysql_store_result(conn);
		if (r == NULL) {
			diag("Fetching the result failed: %s", mysql_error(conn));
			res = false;
		}
		mysql_free_result(r);
	} else {
		diag("Query failed: %s", mysql_error(conn));
	}
	mysql_close(conn);
	return res;
}

/**
 * @brief Sends a packet with an empty payload (sequence id 0) on 'attempts' fresh authenticated
 *   connections; returns true if ProxySQL closed every one of them promptly.
 */
bool empty_packets_rejected(const char* host, int port, const char* user, const char* pass, int attempts) {
	for (int i = 0; i < attempts; i++) {
		MYSQL* conn = connect_to(host, port, user, pass);
		if (conn == NULL) return false;
		const unsigned char pkt[4] = { 0, 0, 0, 0 };
		const int fd = conn->net.fd;
		bool closed = send(fd, pkt, sizeof(pkt), MSG_NOSIGNAL) == sizeof(pkt) && closed_by_peer(fd, WAIT_MS);
		mysql_close(conn);
		if (!closed) {
			diag("Attempt %d: connection to %s:%d was not closed", i + 1, host, port);
			return false;
		}
	}
	return true;
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
		const char* host;
		int port;
		const char* user;
		const char* pass;
	};
	const std::vector<target_t> targets {
		{ "FRONTEND", cl.host, cl.port, cl.username, cl.password },
		{ "ADMIN", cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password },
	};

	plan(targets.size() * 3);

	for (const auto& t : targets) {
		ok(query_works(t.host, t.port, t.user, t.pass), "%s: baseline connection and query work", t.name);
		ok(empty_packets_rejected(t.host, t.port, t.user, t.pass, ATTEMPTS),
			"%s: %d connections sending an empty command packet are closed", t.name, ATTEMPTS);
		ok(query_works(t.host, t.port, t.user, t.pass), "%s: connections and queries still work", t.name);
	}

	return exit_status();
}
