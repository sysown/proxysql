/**
 * @file reg_test_stmt_execute_bind_overread-t.cpp
 * @brief Regression test for GHSA-r23x-jg5r-jmcc and GHSA-x23w-3v26-vgvj (call site B).
 *
 * @details 'MySQL_Protocol::get_binds_from_pkt()' checked a string parameter's length against
 *   the whole packet instead of the bytes left in it, and didn't check fixed-width and temporal
 *   parameters at all. The last parameter could then point past the end of the packet, and the
 *   bytes following the packet in ProxySQL's heap were forwarded to the backend as its value.
 *   For each parameter kind, the test sends a COM_STMT_EXECUTE whose last parameter claims more
 *   bytes than the packet holds, and checks that ProxySQL rejects it with an ERR packet (instead
 *   of executing the statement), and that the connection remains usable.
 */

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"

namespace {

constexpr uint8_t COM_STMT_EXECUTE = 0x17;

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

/**
 * @brief Reads one packet and returns its payload. Empty on failure.
 */
std::vector<uint8_t> read_packet(int fd) {
	uint8_t hdr[4];
	if (!recv_all(fd, hdr, 4)) return {};
	size_t len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16);
	std::vector<uint8_t> payload(len);
	if (len && !recv_all(fd, payload.data(), len)) return {};
	return payload;
}

/**
 * @brief Builds a COM_STMT_EXECUTE for a single parameter of 'type', with 'value' as its raw
 *   (possibly truncated) value bytes.
 */
std::vector<uint8_t> build_execute(uint32_t stmt_id, uint8_t type, const std::vector<uint8_t>& value) {
	std::vector<uint8_t> payload {
		COM_STMT_EXECUTE,
		uint8_t(stmt_id), uint8_t(stmt_id >> 8), uint8_t(stmt_id >> 16), uint8_t(stmt_id >> 24),
		0x00,                   // flags: CURSOR_TYPE_NO_CURSOR
		0x01, 0x00, 0x00, 0x00, // iteration count
		0x00,                   // NULL bitmap (1 parameter)
		0x01,                   // new_params_bound_flag
		type, 0x00,             // parameter type
	};
	payload.insert(payload.end(), value.begin(), value.end());
	std::vector<uint8_t> pkt { uint8_t(payload.size()), uint8_t(payload.size() >> 8), uint8_t(payload.size() >> 16), 0x00 };
	pkt.insert(pkt.end(), payload.begin(), payload.end());
	return pkt;
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

bool prepared_echo_works(MYSQL* mysql) {
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	const char q[] = "SELECT ?";
	char in[] = "hello";
	unsigned long in_len = 5;
	MYSQL_BIND bind {};
	bind.buffer_type = MYSQL_TYPE_STRING;
	bind.buffer = in;
	bind.buffer_length = sizeof(in);
	bind.length = &in_len;

	char out[16] = {0};
	unsigned long out_len = 0;
	MYSQL_BIND rbind {};
	rbind.buffer_type = MYSQL_TYPE_STRING;
	rbind.buffer = out;
	rbind.buffer_length = sizeof(out);
	rbind.length = &out_len;

	bool ok = stmt
		&& mysql_stmt_prepare(stmt, q, sizeof(q) - 1) == 0
		&& mysql_stmt_bind_param(stmt, &bind) == 0
		&& mysql_stmt_execute(stmt) == 0
		&& mysql_stmt_bind_result(stmt, &rbind) == 0
		&& mysql_stmt_store_result(stmt) == 0
		&& mysql_stmt_fetch(stmt) == 0
		&& out_len == 5 && memcmp(out, "hello", 5) == 0;
	if (!ok && stmt) diag("Prepared echo failed: %s", mysql_stmt_error(stmt));
	if (stmt) mysql_stmt_close(stmt);
	return ok;
}

struct overread_case_t {
	const char* name;
	uint8_t type;
	std::vector<uint8_t> value;
};

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const std::vector<overread_case_t> cases {
		// Length 15 is below the packet size (19) but no value bytes follow.
		{ "STRING length exceeding the remaining bytes", MYSQL_TYPE_STRING, { 15 } },
		// 2-byte length-encoded integer truncated by the end of the packet.
		{ "STRING with truncated length-encoded integer", MYSQL_TYPE_STRING, { 0xfc, 0x10 } },
		{ "LONGLONG with 3 of 8 bytes", MYSQL_TYPE_LONGLONG, { 1, 2, 3 } },
		{ "LONG with no bytes", MYSQL_TYPE_LONG, { } },
		{ "DATETIME claiming 11 bytes with 2", MYSQL_TYPE_DATETIME, { 11, 0xe8, 0x07 } },
		{ "TIME claiming 12 bytes with none", MYSQL_TYPE_TIME, { 12 } },
	};

	plan(2 + cases.size() * 2);

	MYSQL* mysql = mysql_init(nullptr);
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Connection failed: %s", mysql_error(mysql));
		return exit_status();
	}
	ok(prepared_echo_works(mysql), "Baseline: well-formed prepared statement with a string parameter works");

	for (const auto& c : cases) {
		MYSQL_STMT* stmt = mysql_stmt_init(mysql);
		const char q[] = "SELECT ?";
		if (stmt == nullptr || mysql_stmt_prepare(stmt, q, sizeof(q) - 1)) {
			diag("Prepare failed: %s", stmt ? mysql_stmt_error(stmt) : "stmt_init");
			ok(false, "%s: rejected with ERR", c.name);
			ok(false, "%s: connection still usable", c.name);
			continue;
		}
		const auto pkt = build_execute(static_cast<uint32_t>(stmt->stmt_id), c.type, c.value);
		std::vector<uint8_t> reply;
		if (send_all(mysql->net.fd, pkt)) {
			reply = read_packet(mysql->net.fd);
		}
		const bool is_err = !reply.empty() && reply[0] == 0xff;
		if (!is_err) {
			diag("Reply first byte: %s", reply.empty() ? "<none>" : std::to_string(reply[0]).c_str());
		}
		ok(is_err, "%s: rejected with ERR", c.name);
		if (!is_err) {
			// A resultset was sent back: the connection is out of sync, reconnect.
			mysql_close(mysql);
			mysql = mysql_init(nullptr);
			mysql_real_connect(mysql, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0);
			ok(false, "%s: connection still usable", c.name);
			continue;
		}
		ok(query_returns_one(mysql), "%s: connection still usable", c.name);
		mysql_stmt_close(stmt);
	}

	ok(prepared_echo_works(mysql), "Well-formed prepared statements still work at the end");
	mysql_close(mysql);

	return exit_status();
}
