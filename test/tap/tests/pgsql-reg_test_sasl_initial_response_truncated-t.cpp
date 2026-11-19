/**
 * @file pgsql-reg_test_sasl_initial_response_truncated-t.cpp
 * @brief Regression test for GHSA-5xv5-24pg-gmq8.
 *
 * @details In the SCRAM handshake, ProxySQL read the 4-byte length of the SASLInitialResponse
 *   without checking that 4 bytes were left in the message. A message whose body ended right
 *   after the "SCRAM-SHA-256\0" mechanism name made ProxySQL read 4 bytes past the packet buffer
 *   before authentication, and the bounds check that followed wrapped around, so those bytes
 *   were used as the length of a second, larger out-of-bounds read.
 *
 *   The test drives the raw handshake for a known user and for an unknown user (the
 *   anti-enumeration mock path takes the same branch), sends truncated or inconsistent
 *   SASLInitialResponse messages, and checks that ProxySQL closes each connection promptly
 *   and keeps serving clients afterwards.
 *
 *   The out-of-bounds bytes are leftover heap contents, so without AddressSanitizer an unfixed
 *   ProxySQL does not fail this test deterministically; the exact parsing rules are covered by
 *   unit/pgsql_sasl_initial_response_unit-t.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

namespace {

constexpr int WAIT_MS = 3000;
const char* UNKNOWN_USER = "reg_test_sasl_no_such_user";

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

bool recv_exact(int fd, uint8_t* buf, size_t len, int timeout_ms) {
	size_t got = 0;
	while (got < len) {
		struct pollfd pfd { fd, POLLIN, 0 };
		if (poll(&pfd, 1, timeout_ms) != 1) return false;
		ssize_t n = recv(fd, buf + got, len - got, 0);
		if (n <= 0) return false;
		got += n;
	}
	return true;
}

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

void append_be32(std::vector<uint8_t>& b, uint32_t v) {
	b.push_back(uint8_t(v >> 24));
	b.push_back(uint8_t(v >> 16));
	b.push_back(uint8_t(v >> 8));
	b.push_back(uint8_t(v));
}

std::vector<uint8_t> startup_message(const std::string& user) {
	std::vector<uint8_t> body;
	append_be32(body, 196608);
	for (const std::string& kv : { std::string("user"), user, std::string("database"), user }) {
		body.insert(body.end(), kv.begin(), kv.end());
		body.push_back(0);
	}
	body.push_back(0);
	std::vector<uint8_t> msg;
	append_be32(msg, body.size() + 4);
	msg.insert(msg.end(), body.begin(), body.end());
	return msg;
}

/** @brief A 'p' message carrying 'body' verbatim. */
std::vector<uint8_t> sasl_initial_response(const std::vector<uint8_t>& body) {
	std::vector<uint8_t> msg { 'p' };
	append_be32(msg, body.size() + 4);
	msg.insert(msg.end(), body.begin(), body.end());
	return msg;
}

std::vector<uint8_t> mech_body() {
	const std::string mech = "SCRAM-SHA-256";
	std::vector<uint8_t> b(mech.begin(), mech.end());
	b.push_back(0);
	return b;
}

/**
 * @brief Sends a startup message for 'user', expects AuthenticationSASL, sends 'body' as the
 *   SASLInitialResponse, and returns true if ProxySQL then closes the connection promptly.
 */
bool malformed_initial_response_rejected(const std::string& host, int port, const std::string& user,
	const std::vector<uint8_t>& body) {
	int fd = raw_connect(host, port);
	if (fd < 0) {
		diag("Connection to %s:%d failed", host.c_str(), port);
		return false;
	}
	bool res = false;
	uint8_t hdr[5];
	if (!send_all(fd, startup_message(user)) || !recv_exact(fd, hdr, sizeof(hdr), WAIT_MS)) {
		diag("No reply to the startup message");
	} else {
		const uint32_t len = (uint32_t(hdr[1]) << 24) | (uint32_t(hdr[2]) << 16) | (uint32_t(hdr[3]) << 8) | hdr[4];
		std::vector<uint8_t> payload(len >= 4 ? len - 4 : 0);
		if (len < 8 || len > 4096 || !recv_exact(fd, payload.data(), payload.size(), WAIT_MS)) {
			diag("Malformed reply to the startup message: type '%c', length %u", hdr[0], len);
		} else {
			const uint32_t auth = (uint32_t(payload[0]) << 24) | (uint32_t(payload[1]) << 16) | (uint32_t(payload[2]) << 8) | payload[3];
			if (hdr[0] != 'R' || auth != 10) {
				diag("Expected AuthenticationSASL (R/10), got '%c'/%u", hdr[0], auth);
			} else {
				res = send_all(fd, sasl_initial_response(body)) && closed_by_peer(fd, WAIT_MS);
			}
		}
	}
	close(fd);
	return res;
}

std::string conninfo(const std::string& host, int port, const std::string& user, const std::string& pass) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass << " sslmode=disable";
	return ss.str();
}

bool query_works(const std::string& ci) {
	PGconn* conn = PQconnectdb(ci.c_str());
	bool res = false;
	if (PQstatus(conn) == CONNECTION_OK) {
		PGresult* r = PQexec(conn, "SELECT 1");
		res = PQresultStatus(r) == PGRES_TUPLES_OK;
		if (!res) diag("Query failed: %s", PQresultErrorMessage(r));
		PQclear(r);
	} else {
		diag("Connection failed: %s", PQerrorMessage(conn));
	}
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

	struct body_case_t {
		const char* name;
		std::vector<uint8_t> body;
	};
	std::vector<body_case_t> bodies;
	bodies.push_back({ "mechanism only, no length field", mech_body() });
	{
		auto b = mech_body();
		b.insert(b.end(), { 0, 0 });
		bodies.push_back({ "mechanism + 2 of the 4 length bytes", b });
	}
	{
		auto b = mech_body();
		append_be32(b, 1024);
		b.insert(b.end(), { 'n', ',', ',' });
		bodies.push_back({ "length larger than the remaining bytes", b });
	}

	const std::vector<std::string> users { cl.pgsql_username, UNKNOWN_USER };
	const std::string ci = conninfo(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password);

	plan(2 + users.size() * bodies.size());

	ok(query_works(ci), "baseline connection and query work");

	for (const auto& user : users) {
		for (const auto& c : bodies) {
			ok(malformed_initial_response_rejected(cl.pgsql_host, cl.pgsql_port, user, c.body),
				"user '%s': SASLInitialResponse with %s is rejected", user.c_str(), c.name);
		}
	}

	ok(query_works(ci), "connections and queries still work");

	return exit_status();
}
