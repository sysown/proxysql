/**
 * @file reg_test_stmt_reset_short_packet-t.cpp
 * @brief Regression test for GHSA-85h9-mr8r-6j4j.
 *
 * @details The COM_STMT_RESET handler read the 4-byte statement id without checking the packet
 *   size, reading past the end of a short packet. A truncated COM_STMT_RESET must now get an
 *   ERR packet, the connection must remain usable, and well-formed resets must keep working.
 */

#include <cstdlib>
#include <cstring>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"

namespace {

constexpr uint8_t kComStmtReset = 0x1a;

bool send_all(int fd, const std::vector<uint8_t>& buf) {
	size_t sent = 0;
	while (sent < buf.size()) {
		ssize_t n = send(fd, buf.data() + sent, buf.size() - sent, MSG_NOSIGNAL);
		if (n <= 0) return false;
		sent += n;
	}
	return true;
}

bool recv_all(int fd, uint8_t* buf, size_t len) {
	size_t got = 0;
	while (got < len) {
		struct pollfd pfd { fd, POLLIN, 0 };
		if (poll(&pfd, 1, 5000) != 1) return false;
		ssize_t n = recv(fd, buf + got, len - got, 0);
		if (n <= 0) return false;
		got += n;
	}
	return true;
}

std::vector<uint8_t> read_packet(int fd) {
	uint8_t hdr[4];
	if (!recv_all(fd, hdr, 4)) return {};
	size_t len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16);
	std::vector<uint8_t> payload(len);
	if (len && !recv_all(fd, payload.data(), len)) return {};
	return payload;
}

bool query_returns_one(MYSQL* mysql) {
	if (mysql_query(mysql, "SELECT 1")) {
		diag("SELECT 1 failed: %s", mysql_error(mysql));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	bool ok = row && row[0] && strcmp(row[0], "1") == 0;
	if (res) mysql_free_result(res);
	return ok;
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(6);

	MYSQL* mysql = mysql_init(nullptr);
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Connection failed: %s", mysql_error(mysql));
		return exit_status();
	}

	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	const char q[] = "SELECT 1";
	ok(stmt && mysql_stmt_prepare(stmt, q, sizeof(q) - 1) == 0 && mysql_stmt_reset(stmt) == 0,
		"Well-formed COM_STMT_RESET succeeds. err='%s'", stmt ? mysql_stmt_error(stmt) : "");

	// Command byte only, and command byte plus 2 of the 4 statement id bytes.
	const std::vector<std::vector<uint8_t>> malformed {
		{ 0x01, 0x00, 0x00, 0x00, kComStmtReset },
		{ 0x03, 0x00, 0x00, 0x00, kComStmtReset, 0x01, 0x00 },
	};
	for (const auto& pkt : malformed) {
		std::vector<uint8_t> reply;
		if (send_all(mysql->net.fd, pkt)) {
			reply = read_packet(mysql->net.fd);
		}
		ok(!reply.empty() && reply[0] == 0xff,
			"COM_STMT_RESET with a %zu-byte payload gets ERR. First reply byte: %d",
			pkt.size() - 4, reply.empty() ? -1 : reply[0]);
		ok(query_returns_one(mysql), "Connection still usable after the malformed COM_STMT_RESET");
	}

	ok(mysql_stmt_reset(stmt) == 0 && mysql_stmt_execute(stmt) == 0,
		"Prepared statement still resets and executes. err='%s'", mysql_stmt_error(stmt));
	mysql_stmt_close(stmt);
	mysql_close(mysql);

	return exit_status();
}
