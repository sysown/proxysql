/**
 * @file reg_test_5930_mysql_client_pipelining-t.cpp
 * @brief Regression test for #5930: MySQL client command pipelining.
 *
 * @details MariaDB Connector/J (default 'disablePipeline=false') pipelines a JDBC batch: it writes
 *   several COM_QUERY packets without waiting for the responses, then reads all the responses. A
 *   MySQL server processes the commands sequentially from the socket. ProxySQL used to treat every
 *   packet received while a command was in flight as unexpected and to close the connection
 *   ("Unexpected packet from client ... Disconnecting it", PMC-10001).
 *
 *   The test connects with libmariadb, then writes raw command packets on the connection socket
 *   without reading in between, and validates each response in order:
 *   - N pipelined INSERTs: N OK packets, all rows applied.
 *   - A pipelined batch where one statement fails: ERR for that one only, the others are applied.
 *   - Pipelined SELECTs (and a COM_PING) get their responses in order.
 *   - A slow first query, with the following commands in the same write, or in a later write that
 *     arrives while the query is running.
 *   - A large batch, written concurrently with the reads, that exceeds the proxy input buffers.
 *   - Pipelined COM_STMT_EXECUTE of a server side prepared statement (Connector/J with
 *     'useServerPrepStmts=true' prepares, then pipelines the executions).
 *   - A COM_QUIT pipelined after a query closes the connection.
 *   The connections remain usable afterwards, and 'mysql_unexpected_frontend_packets' does not grow.
 *   Run with 'mysql-multiplexing=true', so every command can use a different backend connection.
 */

#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using std::string;
using std::vector;

namespace {

constexpr uint8_t kComQuit = 0x01;
constexpr uint8_t kComQuery = 0x03;
constexpr uint8_t kComPing = 0x0e;
constexpr uint8_t kComStmtExecute = 0x17;
constexpr int kRecvTimeoutMs = 10000;
const char* kTable = "test.reg_test_5930";

enum class RespKind { NONE, OK, ERR, RESULTSET };

struct Resp {
	RespKind kind = RespKind::NONE;
	uint64_t affected_rows = 0;
	uint16_t err_code = 0;
	vector<vector<string>> rows;
};

void append_cmd(vector<uint8_t>& buf, uint8_t cmd, const string& arg = "") {
	const size_t len = 1 + arg.size();
	buf.push_back(len & 0xff);
	buf.push_back((len >> 8) & 0xff);
	buf.push_back((len >> 16) & 0xff);
	buf.push_back(0); // sequence id: every command starts a new exchange
	buf.push_back(cmd);
	buf.insert(buf.end(), arg.begin(), arg.end());
}

void append_query(vector<uint8_t>& buf, const string& query) {
	append_cmd(buf, kComQuery, query);
}

bool send_all(int fd, const vector<uint8_t>& buf) {
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
		if (poll(&pfd, 1, kRecvTimeoutMs) != 1) return false;
		ssize_t n = recv(fd, buf + got, len - got, 0);
		if (n <= 0) return false;
		got += n;
	}
	return true;
}

bool read_packet(int fd, vector<uint8_t>& payload) {
	uint8_t hdr[4];
	if (!recv_all(fd, hdr, 4)) return false;
	const size_t len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16);
	payload.assign(len, 0);
	return len == 0 || recv_all(fd, payload.data(), len);
}

/** @brief Decodes a length-encoded integer at 'pos', advancing it. */
uint64_t lenenc_int(const vector<uint8_t>& p, size_t& pos) {
	if (pos >= p.size()) return 0;
	const uint8_t c = p[pos++];
	if (c < 0xfb) return c;
	size_t n = c == 0xfc ? 2 : (c == 0xfd ? 3 : 8);
	uint64_t v = 0;
	for (size_t i = 0; i < n && pos < p.size(); i++) {
		v |= static_cast<uint64_t>(p[pos++]) << (8 * i);
	}
	return v;
}

/**
 * @brief Reads one full command response: OK, ERR, or a text resultset.
 * @param deprecate_eof Whether 'CLIENT_DEPRECATE_EOF' was negotiated.
 */
Resp read_response(int fd, bool deprecate_eof) {
	Resp r {};
	vector<uint8_t> p;
	if (!read_packet(fd, p) || p.empty()) return r;
	if (p[0] == 0x00) {
		size_t pos = 1;
		r.kind = RespKind::OK;
		r.affected_rows = lenenc_int(p, pos);
		return r;
	}
	if (p[0] == 0xff) {
		r.kind = RespKind::ERR;
		r.err_code = p.size() >= 3 ? (p[1] | (p[2] << 8)) : 0;
		return r;
	}
	size_t pos = 0;
	const uint64_t ncols = lenenc_int(p, pos);
	for (uint64_t i = 0; i < ncols; i++) {
		if (!read_packet(fd, p)) return r;
	}
	if (!deprecate_eof) {
		if (!read_packet(fd, p) || p.empty() || p[0] != 0xfe) return r;
	}
	for (;;) {
		if (!read_packet(fd, p) || p.empty()) return r;
		if (p[0] == 0xfe && p.size() < 0xffffff) break; // EOF, or OK terminator with DEPRECATE_EOF
		if (p[0] == 0xff) {
			r.kind = RespKind::ERR;
			r.err_code = p.size() >= 3 ? (p[1] | (p[2] << 8)) : 0;
			return r;
		}
		vector<string> row;
		size_t rpos = 0;
		for (uint64_t i = 0; i < ncols; i++) {
			if (rpos < p.size() && p[rpos] == 0xfb) {
				rpos++;
				row.push_back("NULL");
				continue;
			}
			const uint64_t len = lenenc_int(p, rpos);
			if (rpos + len > p.size()) return r;
			row.emplace_back(reinterpret_cast<const char*>(p.data() + rpos), len);
			rpos += len;
		}
		r.rows.push_back(row);
	}
	r.kind = RespKind::RESULTSET;
	return r;
}

string describe(const Resp& r) {
	switch (r.kind) {
		case RespKind::OK: return "OK(affected=" + std::to_string(r.affected_rows) + ")";
		case RespKind::ERR: return "ERR(" + std::to_string(r.err_code) + ")";
		case RespKind::RESULTSET: {
			string s = "RS[";
			for (const auto& row : r.rows) { s += (row.empty() ? "" : row[0]) + ";"; }
			return s + "]";
		}
		default: return "NONE(connection closed or timeout)";
	}
}

bool is_rs_value(const Resp& r, const string& v) {
	return r.kind == RespKind::RESULTSET && r.rows.size() == 1 && r.rows[0].size() == 1 && r.rows[0][0] == v;
}

MYSQL* open_conn(const CommandLine& cl) {
	MYSQL* mysql = mysql_init(nullptr);
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Connection to ProxySQL failed: %s", mysql_error(mysql));
		mysql_close(mysql);
		return nullptr;
	}
	return mysql;
}

bool deprecate_eof(MYSQL* mysql) {
	return (mysql->server_capabilities & CLIENT_DEPRECATE_EOF) && (mysql->client_flag & CLIENT_DEPRECATE_EOF);
}

/** @brief Returns the single value of a single-row query, or "" on failure. */
string query_value(MYSQL* mysql, const string& q) {
	if (mysql_query(mysql, q.c_str())) {
		diag("Query '%s' failed: %s", q.c_str(), mysql_error(mysql));
		return "";
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	string v = row && row[0] ? row[0] : "";
	if (res) mysql_free_result(res);
	return v;
}

/** @brief Counts rows in [lo, hi] reading from the writer, regardless of read/write split rules. */
string count_rows(MYSQL* mysql, int lo, int hi) {
	return query_value(mysql, "SELECT COUNT(*) FROM " + string(kTable) + " WHERE id BETWEEN "
		+ std::to_string(lo) + " AND " + std::to_string(hi) + " FOR UPDATE");
}

string unexpected_packets(MYSQL* admin) {
	return query_value(admin,
		"SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='mysql_unexpected_frontend_packets'");
}

/** @brief Sends 'buf' on the connection socket and reads 'n' responses. */
vector<Resp> pipeline(MYSQL* mysql, const vector<uint8_t>& buf, size_t n) {
	vector<Resp> resps;
	if (!send_all(mysql->net.fd, buf)) {
		diag("Failed to write the pipelined commands");
		return resps;
	}
	const bool deof = deprecate_eof(mysql);
	for (size_t i = 0; i < n; i++) {
		resps.push_back(read_response(mysql->net.fd, deof));
		if (resps.back().kind == RespKind::NONE) break;
	}
	return resps;
}

/** @brief Waits until the peer closes the socket. Data received before EOF is discarded. */
bool wait_for_close(int fd) {
	uint8_t buf[4096];
	for (;;) {
		struct pollfd pfd { fd, POLLIN, 0 };
		if (poll(&pfd, 1, kRecvTimeoutMs) != 1) return false;
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		if (n == 0) return true;
		if (n < 0) return errno == ECONNRESET;
	}
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(16);

	MYSQL* admin = mysql_init(nullptr);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		diag("Admin connection failed: %s", mysql_error(admin));
		return exit_status();
	}
	const string orig_multiplexing = query_value(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-multiplexing'");
	MYSQL_QUERY(admin, "SET mysql-multiplexing='true'");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* setup = open_conn(cl);
	if (!setup) return exit_status();
	MYSQL_QUERY(setup, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(setup, ("DROP TABLE IF EXISTS " + string(kTable)).c_str());
	MYSQL_QUERY(setup, ("CREATE TABLE " + string(kTable) + " (id INT PRIMARY KEY, v INT)").c_str());

	const string unexp_before = unexpected_packets(admin);
	diag("mysql_unexpected_frontend_packets before the test: %s", unexp_before.c_str());

	// 1. N pipelined INSERTs, in one write.
	{
		MYSQL* mysql = open_conn(cl);
		const size_t n = 10;
		vector<uint8_t> buf;
		for (size_t i = 0; i < n; i++) {
			append_query(buf, "INSERT INTO " + string(kTable) + " VALUES (" + std::to_string(1 + i) + ", 1)");
		}
		vector<Resp> resps = mysql ? pipeline(mysql, buf, n) : vector<Resp> {};
		size_t oks = 0;
		string got;
		for (const auto& r : resps) {
			if (r.kind == RespKind::OK && r.affected_rows == 1) oks++;
			got += describe(r) + " ";
		}
		ok(oks == n, "%zu pipelined INSERTs get %zu OK packets in order. Got: %s", n, n, got.c_str());
		ok(count_rows(setup, 1, n) == std::to_string(n), "All the pipelined INSERTs were applied");
		if (mysql) mysql_close(mysql);
	}

	// 2. A pipelined batch where the second statement fails (duplicate key).
	{
		MYSQL* mysql = open_conn(cl);
		vector<uint8_t> buf;
		append_query(buf, "INSERT INTO " + string(kTable) + " VALUES (100, 1)");
		append_query(buf, "INSERT INTO " + string(kTable) + " VALUES (100, 2)");
		append_query(buf, "INSERT INTO " + string(kTable) + " VALUES (101, 1)");
		vector<Resp> resps = mysql ? pipeline(mysql, buf, 3) : vector<Resp> {};
		ok(resps.size() == 3 && resps[0].kind == RespKind::OK && resps[1].kind == RespKind::ERR
			&& resps[1].err_code == 1062 && resps[2].kind == RespKind::OK,
			"Failing statement gets ERR 1062, the others OK. Got: %s %s %s",
			resps.size() > 0 ? describe(resps[0]).c_str() : "-", resps.size() > 1 ? describe(resps[1]).c_str() : "-",
			resps.size() > 2 ? describe(resps[2]).c_str() : "-");
		ok(count_rows(setup, 100, 101) == "2", "The statements around the failing one were applied");
		if (mysql) mysql_close(mysql);
	}

	// 3. Pipelined SELECTs, with a COM_PING in the middle.
	{
		MYSQL* mysql = open_conn(cl);
		vector<uint8_t> buf;
		append_query(buf, "SELECT 1");
		append_query(buf, "SELECT 2");
		append_cmd(buf, kComPing);
		append_query(buf, "SELECT 3");
		vector<Resp> resps = mysql ? pipeline(mysql, buf, 4) : vector<Resp> {};
		string got;
		for (const auto& r : resps) got += describe(r) + " ";
		ok(resps.size() == 4 && is_rs_value(resps[0], "1") && is_rs_value(resps[1], "2")
			&& resps[2].kind == RespKind::OK && is_rs_value(resps[3], "3"),
			"Pipelined SELECTs and COM_PING get their responses in order. Got: %s", got.c_str());
		if (mysql) mysql_close(mysql);
	}

	// 4. Slow first query, the following commands in the same write.
	{
		MYSQL* mysql = open_conn(cl);
		vector<uint8_t> buf;
		append_query(buf, "SELECT SLEEP(1)");
		append_query(buf, "INSERT INTO " + string(kTable) + " VALUES (200, 1)");
		append_query(buf, "SELECT 'x'");
		vector<Resp> resps = mysql ? pipeline(mysql, buf, 3) : vector<Resp> {};
		string got;
		for (const auto& r : resps) got += describe(r) + " ";
		ok(resps.size() == 3 && is_rs_value(resps[0], "0") && resps[1].kind == RespKind::OK && is_rs_value(resps[2], "x"),
			"Commands pipelined behind a slow query get their responses in order. Got: %s", got.c_str());
		if (mysql) mysql_close(mysql);
	}

	// 5. Slow first query, the following commands written while it is running.
	{
		MYSQL* mysql = open_conn(cl);
		vector<uint8_t> first;
		append_query(first, "SELECT SLEEP(1)");
		vector<uint8_t> rest;
		append_query(rest, "INSERT INTO " + string(kTable) + " VALUES (201, 1)");
		append_query(rest, "SELECT 'y'");
		vector<Resp> resps;
		if (mysql && send_all(mysql->net.fd, first)) {
			usleep(300 * 1000);
			resps = pipeline(mysql, rest, 3);
		}
		string got;
		for (const auto& r : resps) got += describe(r) + " ";
		ok(resps.size() == 3 && is_rs_value(resps[0], "0") && resps[1].kind == RespKind::OK && is_rs_value(resps[2], "y"),
			"Commands received while a query is running get their responses in order. Got: %s", got.c_str());
		ok(count_rows(setup, 200, 201) == "2", "The INSERTs pipelined behind slow queries were applied");
		if (mysql) mysql_close(mysql);
	}

	// 6. A large batch exceeding the proxy input buffers, written while the responses are read.
	{
		MYSQL* mysql = open_conn(cl);
		const int n = 2000;
		const int base = 1000;
		vector<uint8_t> buf;
		for (int i = 0; i < n; i++) {
			append_query(buf, "INSERT INTO " + string(kTable) + " VALUES (" + std::to_string(base + i) + ", 1) /* pad pad pad pad pad pad */");
		}
		diag("Large batch: %d INSERTs, %zu bytes", n, buf.size());
		int oks = 0;
		string first_bad;
		if (mysql) {
			bool sent = false;
			std::thread writer([&]() { sent = send_all(mysql->net.fd, buf); });
			const bool deof = deprecate_eof(mysql);
			for (int i = 0; i < n; i++) {
				Resp r = read_response(mysql->net.fd, deof);
				if (r.kind == RespKind::OK && r.affected_rows == 1) {
					oks++;
				} else {
					first_bad = "response #" + std::to_string(i) + ": " + describe(r);
					break;
				}
			}
			writer.join();
			if (!sent) diag("The writer failed to send the whole batch");
		}
		ok(oks == n, "%d pipelined INSERTs in a large batch get %d OK packets. %s", n, oks, first_bad.c_str());
		ok(count_rows(setup, base, base + n - 1) == std::to_string(n), "All the INSERTs of the large batch were applied");

		// 7. The connection is still usable with regular, non pipelined, traffic.
		ok(mysql && query_value(mysql, "SELECT 1") == "1", "Connection still usable after the pipelined batches");
		if (mysql) mysql_close(mysql);
	}

	// 8. Pipelined COM_STMT_EXECUTE of a statement prepared beforehand.
	{
		MYSQL* mysql = open_conn(cl);
		MYSQL_STMT* stmt = mysql ? mysql_stmt_init(mysql) : nullptr;
		const string q = "UPDATE " + string(kTable) + " SET v=v+1 WHERE id=1";
		const bool prepared = stmt && mysql_stmt_prepare(stmt, q.c_str(), q.size()) == 0;
		if (!prepared) diag("mysql_stmt_prepare failed: %s", stmt ? mysql_stmt_error(stmt) : "");
		const size_t n = 5;
		vector<Resp> resps;
		if (prepared) {
			const uint32_t id = static_cast<uint32_t>(stmt->stmt_id);
			// stmt_id (4), flags (1), iteration_count (4): no parameters
			const string args {
				static_cast<char>(id & 0xff), static_cast<char>((id >> 8) & 0xff),
				static_cast<char>((id >> 16) & 0xff), static_cast<char>((id >> 24) & 0xff),
				0, 1, 0, 0, 0
			};
			vector<uint8_t> buf;
			for (size_t i = 0; i < n; i++) append_cmd(buf, kComStmtExecute, args);
			resps = pipeline(mysql, buf, n);
		}
		size_t oks = 0;
		string got;
		for (const auto& r : resps) {
			if (r.kind == RespKind::OK && r.affected_rows == 1) oks++;
			got += describe(r) + " ";
		}
		ok(oks == n, "%zu pipelined COM_STMT_EXECUTE get %zu OK packets. Got: %s", n, n, got.c_str());
		ok(query_value(setup, "SELECT v FROM " + string(kTable) + " WHERE id=1 FOR UPDATE") == std::to_string(1 + n),
			"All the pipelined COM_STMT_EXECUTE were applied");
		if (stmt) mysql_stmt_close(stmt);
		if (mysql) mysql_close(mysql);
	}

	// 9. No packet was treated as unexpected.
	const string unexp_after = unexpected_packets(admin);
	ok(unexp_before != "" && unexp_before == unexp_after,
		"mysql_unexpected_frontend_packets unchanged. Before: %s After: %s", unexp_before.c_str(), unexp_after.c_str());

	// 10. A COM_QUIT pipelined behind a query closes the connection, as before.
	{
		MYSQL* mysql = open_conn(cl);
		vector<uint8_t> buf;
		append_query(buf, "SELECT SLEEP(1)");
		append_cmd(buf, kComQuit);
		const bool closed = mysql && send_all(mysql->net.fd, buf) && wait_for_close(mysql->net.fd);
		ok(closed, "COM_QUIT pipelined behind a query closes the connection");
		if (mysql) mysql_close(mysql);
		MYSQL* again = open_conn(cl);
		ok(again && query_value(again, "SELECT 1") == "1", "New connections still work after the pipelined COM_QUIT");
		if (again) mysql_close(again);
	}

	mysql_query(setup, ("DROP TABLE IF EXISTS " + string(kTable)).c_str());
	mysql_close(setup);
	if (orig_multiplexing.empty() == false) {
		mysql_query(admin, ("SET mysql-multiplexing='" + orig_multiplexing + "'").c_str());
		mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}
	mysql_close(admin);

	return exit_status();
}
