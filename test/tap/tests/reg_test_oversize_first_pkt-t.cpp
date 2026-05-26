/**
 * @file reg_test_oversize_first_pkt-t.cpp
 * @brief Regression test for GHSA-58ww-865x-grpr: pre-authentication
 *        heap-buffer-overflow in the MySQL and PostgreSQL first-packet
 *        read paths.
 * @details An unauthenticated client could declare an oversized first-packet
 *        length and ProxySQL would pass that length straight to recv() while
 *        writing into the fixed 32 KB queueIN buffer, producing an
 *        out-of-bounds heap write in:
 *          - MySQL_Data_Stream::read_from_net (lib/mysql_data_stream.cpp:665)
 *          - PgSQL_Data_Stream::read_from_net (lib/PgSQL_Data_Stream.cpp:534)
 *
 *        The fix bounds the second recv() against the remaining queueIN
 *        capacity and shut_soft()'s the connection when the declared length
 *        exceeds that bound.
 *
 *        This test connects raw sockets to the MySQL and PostgreSQL frontend
 *        listeners, sends only the protocol header with an oversized declared
 *        length, and asserts:
 *          1. The server closes the connection promptly.
 *          2. ProxySQL admin remains responsive afterward (no crash).
 *
 *        Under an ASAN-instrumented build, the pre-fix code would crash with
 *        heap-buffer-overflow on the first iteration; the post-fix code
 *        passes cleanly.
 */

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

static int tcp_connect(const char* host, int port) {
	// `host` is whatever cl.host / cl.pgsql_host resolves to. In CI it is
	// the Docker DNS hostname ("proxysql") of the proxy container, not a
	// numeric IP, so inet_pton(AF_INET, host, ...) returned 0 and made
	// every probe in this test fail before any byte was sent. getaddrinfo
	// handles both hostnames and numeric IPs, which is what we actually
	// want.
	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", port);
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	struct addrinfo* res = nullptr;
	int rc = getaddrinfo(host, port_str, &hints, &res);
	if (rc != 0 || res == nullptr) {
		diag("tcp_connect: getaddrinfo(%s:%d) failed: %s",
		     host, port, gai_strerror(rc));
		return -1;
	}
	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0) {
		freeaddrinfo(res);
		return -1;
	}
	if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
		close(fd);
		freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);
	return fd;
}

// Returns 1 if the peer closed the socket within timeout_ms, 0 otherwise.
//
// The naive single-poll-then-recv version doesn't work for protocols where
// the server sends bytes before the client does anything. MySQL is exactly
// that case: the server emits its ~80-byte Initial Handshake Packet
// immediately on accept, so by the time we poll the client socket those
// bytes are already in the recv buffer. A single recv() returns the
// handshake (n > 0) and a single-shot check would conclude "peer still
// talking" -- a false negative -- even though ProxySQL is about to close
// the connection in response to our oversized header.
//
// Loop instead: drain any bytes that arrive and keep polling until either
// recv() returns 0 (EOF) / negative non-EAGAIN (RST) within the deadline,
// or the deadline expires with the connection still up.
static int peer_closed_within(int fd, int timeout_ms) {
	using clock = std::chrono::steady_clock;
	const auto deadline = clock::now() + std::chrono::milliseconds(timeout_ms);
	for (;;) {
		const auto now = clock::now();
		if (now >= deadline) return 0;
		const int remaining_ms = static_cast<int>(
			std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
		struct pollfd p;
		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;
		int pr = poll(&p, 1, remaining_ms);
		if (pr == 0) return 0;          // deadline elapsed
		if (pr < 0) {
			if (errno == EINTR) continue;
			return 0;
		}
		char buf[1024];
		ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (n == 0) return 1;           // peer EOF
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
			return 1;                   // RST or other terminal error
		}
		// n > 0: server chatter (e.g. MySQL Initial Handshake). Drain and
		// keep polling for the actual close.
	}
}

static int probe_mysql_oversize(const char* host, int port, uint32_t declared_pkt_len) {
	int fd = tcp_connect(host, port);
	if (fd < 0) {
		diag("MySQL probe: connect to %s:%d failed: %s", host, port, strerror(errno));
		return -1;
	}
	unsigned char hdr[4];
	hdr[0] = declared_pkt_len & 0xff;
	hdr[1] = (declared_pkt_len >> 8) & 0xff;
	hdr[2] = (declared_pkt_len >> 16) & 0xff;
	hdr[3] = 1; // sequence id
	ssize_t s = send(fd, hdr, sizeof(hdr), MSG_NOSIGNAL);
	if (s != static_cast<ssize_t>(sizeof(hdr))) {
		close(fd);
		return -1;
	}
	int closed = peer_closed_within(fd, 3000);
	close(fd);
	return closed;
}

static int probe_pgsql_oversize(const char* host, int port, uint32_t declared_len) {
	int fd = tcp_connect(host, port);
	if (fd < 0) {
		diag("PgSQL probe: connect to %s:%d failed: %s", host, port, strerror(errno));
		return -1;
	}
	// PgSQL_Data_Stream::read_from_net consumes 5 bytes on the first read.
	// The parser uses byte 0 as a message type: when type8 != 0 it reads
	// bytes 1..4 as the big-endian length; when type8 == 0 (startup-style)
	// it reads bytes 0..3 as the length, which makes the high byte always
	// zero and silently caps the declared length at 0x00FFFFFF. We need
	// the parser to read OUR full declared length, so we set type8 to a
	// non-zero byte and place the 32-bit length in bytes 1..4.
	unsigned char hdr[5];
	hdr[0] = 'X';
	hdr[1] = (declared_len >> 24) & 0xff;
	hdr[2] = (declared_len >> 16) & 0xff;
	hdr[3] = (declared_len >> 8) & 0xff;
	hdr[4] = declared_len & 0xff;
	ssize_t s = send(fd, hdr, sizeof(hdr), MSG_NOSIGNAL);
	if (s != static_cast<ssize_t>(sizeof(hdr))) {
		close(fd);
		return -1;
	}
	int closed = peer_closed_within(fd, 3000);
	close(fd);
	return closed;
}

int main(int /*argc*/, char** /*argv*/) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	// Each declared length is just above the queueIN capacity boundary,
	// at common round values, and at the protocol-max for the respective
	// length field.
	const std::vector<uint32_t> mysql_lens = { 32765u, 65535u, 100000u, 0x00FFFFFFu };
	const std::vector<uint32_t> pgsql_lens = { 32765u, 65535u, 100000u, 0xFFFFFFFFu };

	// Probe whether the PgSQL listener is reachable in this infra.
	int pgsql_probe = tcp_connect(cl.pgsql_host, cl.pgsql_port);
	const bool have_pgsql = (pgsql_probe >= 0);
	if (have_pgsql) close(pgsql_probe);

	int planned = static_cast<int>(mysql_lens.size()) + 1; // +1 for admin liveness
	if (have_pgsql) planned += static_cast<int>(pgsql_lens.size());
	plan(planned);

	for (uint32_t L : mysql_lens) {
		int closed = probe_mysql_oversize(cl.host, cl.port, L);
		ok(closed == 1,
		   "MySQL listener closed connection on oversize first-packet pkt_length=%u (closed=%d)",
		   L, closed);
	}

	if (have_pgsql) {
		for (uint32_t L : pgsql_lens) {
			int closed = probe_pgsql_oversize(cl.pgsql_host, cl.pgsql_port, L);
			ok(closed == 1,
			   "PgSQL listener closed connection on oversize first-packet length=%u (closed=%d)",
			   L, closed);
		}
	} else {
		diag("PgSQL listener not reachable at %s:%d; skipping PgSQL probes",
		     cl.pgsql_host, cl.pgsql_port);
	}

	// Liveness: a normal admin connection must still succeed after the attacks.
	MYSQL* admin = mysql_init(NULL);
	bool admin_ok = mysql_real_connect(admin, cl.admin_host, cl.admin_username,
	                                   cl.admin_password, NULL, cl.admin_port,
	                                   NULL, 0) != NULL;
	ok(admin_ok,
	   "ProxySQL admin still accepting connections after oversize first-packet attacks");
	if (admin) mysql_close(admin);

	return exit_status();
}
