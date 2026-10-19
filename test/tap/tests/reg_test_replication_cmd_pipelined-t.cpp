/**
 * @file reg_test_replication_cmd_pipelined-t.cpp
 * @brief Regression test: a replication command followed by other client packets must not abort ProxySQL.
 *
 * @details COM_REGISTER_SLAVE, COM_BINLOG_DUMP and COM_BINLOG_DUMP_GTID switch the session to
 *   permanent fast-forward. The switch re-queues the command as the first packet to forward to the
 *   backend, and used to call assert(0) ("UNEXPECTED PACKET FROM CLIENT -- PLEASE REPORT A BUG")
 *   when the client had already sent further packets. Asserts are enabled in release builds, so any
 *   authenticated client could abort the whole process by writing, for example, COM_REGISTER_SLAVE
 *   and COM_PING in a single write(), or by pipelining them behind a slow query (#5930).
 *
 *   ProxySQL now rejects only the replication command with an ERR packet (1815) and keeps the
 *   session in its previous state; the packets that follow are processed normally. The test writes
 *   raw command packets on the socket of a libmariadb connection and checks, in order:
 *   - COM_REGISTER_SLAVE + COM_PING in one write: ERR for the first, OK for the ping.
 *   - COM_BINLOG_DUMP + COM_PING in one write: ERR, then OK.
 *   - SELECT SLEEP(1) + COM_REGISTER_SLAVE + COM_PING in one write (the last two are deferred while
 *     the query runs, then replayed): resultset, ERR, OK.
 *   - Each connection remains usable afterwards (SELECT 1), and ProxySQL is still alive: a new
 *     client connection and the admin interface both answer.
 *   Without the fix the first case aborts ProxySQL and every later check fails.
 *   No binlog-capable backend is needed: the commands never reach a backend.
 */

#include <cerrno>
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
#include "utils.h"

using std::string;
using std::vector;

namespace {

constexpr uint8_t kComQuery = 0x03;
constexpr uint8_t kComPing = 0x0e;
constexpr uint8_t kComBinlogDump = 0x12;
constexpr uint8_t kComRegisterSlave = 0x15;
constexpr uint16_t kErrRejected = 1815;
constexpr int kRecvTimeoutMs = 10000;

enum class RespKind { NONE, OK, ERR, RESULTSET };

struct Resp {
	RespKind kind = RespKind::NONE;
	uint16_t err_code = 0;
	vector<string> first_col;
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

void put_le(string& s, uint64_t v, size_t n) {
	for (size_t i = 0; i < n; i++) s.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
}

/** @brief COM_REGISTER_SLAVE body: server_id, hostname, user, password, port, rank, master_id. */
string register_slave_body() {
	string s;
	put_le(s, 4242, 4);
	const string host = "replica";
	s.push_back(static_cast<char>(host.size()));
	s += host;
	s.push_back(0); // user
	s.push_back(0); // password
	put_le(s, 3306, 2);
	put_le(s, 0, 4);
	put_le(s, 0, 4);
	return s;
}

/** @brief COM_BINLOG_DUMP body: binlog_pos, flags, server_id, binlog filename. */
string binlog_dump_body() {
	string s;
	put_le(s, 4, 4);
	put_le(s, 0, 2);
	put_le(s, 4242, 4);
	s += "binlog.000001";
	return s;
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

/** @brief Reads one command response: OK, ERR, or a text resultset (first column only). */
Resp read_response(int fd, bool deprecate_eof) {
	Resp r {};
	vector<uint8_t> p;
	if (!read_packet(fd, p) || p.empty()) return r;
	if (p[0] == 0x00) {
		r.kind = RespKind::OK;
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
		if (p[0] == 0xfe && p.size() < 0xffffff) break;
		if (p[0] == 0xff) {
			r.kind = RespKind::ERR;
			r.err_code = p.size() >= 3 ? (p[1] | (p[2] << 8)) : 0;
			return r;
		}
		size_t rpos = 0;
		if (p[0] == 0xfb) {
			r.first_col.push_back("NULL");
			continue;
		}
		const uint64_t len = lenenc_int(p, rpos);
		if (rpos + len > p.size()) return r;
		r.first_col.emplace_back(reinterpret_cast<const char*>(p.data() + rpos), len);
	}
	r.kind = RespKind::RESULTSET;
	return r;
}

string describe(const Resp& r) {
	switch (r.kind) {
		case RespKind::OK: return "OK";
		case RespKind::ERR: return "ERR(" + std::to_string(r.err_code) + ")";
		case RespKind::RESULTSET: {
			string s = "RS[";
			for (const auto& v : r.first_col) { s += v + ";"; }
			return s + "]";
		}
		default: return "NONE(connection closed or timeout)";
	}
}

string describe(const vector<Resp>& rs) {
	string s;
	for (const auto& r : rs) s += describe(r) + " ";
	return s;
}

bool is_rs_value(const Resp& r, const string& v) {
	return r.kind == RespKind::RESULTSET && r.first_col.size() == 1 && r.first_col[0] == v;
}

bool is_rejected(const Resp& r) {
	return r.kind == RespKind::ERR && r.err_code == kErrRejected;
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

/** @brief Writes 'buf' in one call on the connection socket, then reads 'n' responses. */
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

/** @brief Checks that the raw connection still answers a query. */
bool conn_still_usable(MYSQL* mysql) {
	vector<uint8_t> buf;
	append_cmd(buf, kComQuery, "SELECT 1");
	vector<Resp> rs = pipeline(mysql, buf, 1);
	return rs.size() == 1 && is_rs_value(rs[0], "1");
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(8);

	// 1. COM_REGISTER_SLAVE and COM_PING in a single write.
	{
		MYSQL* mysql = open_conn(cl);
		vector<uint8_t> buf;
		append_cmd(buf, kComRegisterSlave, register_slave_body());
		append_cmd(buf, kComPing);
		vector<Resp> rs = mysql ? pipeline(mysql, buf, 2) : vector<Resp> {};
		ok(rs.size() == 2 && is_rejected(rs[0]) && rs[1].kind == RespKind::OK,
			"COM_REGISTER_SLAVE + COM_PING in one write: ERR(%u) then OK. Got: %s",
			kErrRejected, describe(rs).c_str());
		ok(mysql && conn_still_usable(mysql), "Connection is still usable after the rejected COM_REGISTER_SLAVE");
		if (mysql) mysql_close(mysql);
	}

	// 2. COM_BINLOG_DUMP and COM_PING in a single write.
	{
		MYSQL* mysql = open_conn(cl);
		vector<uint8_t> buf;
		append_cmd(buf, kComBinlogDump, binlog_dump_body());
		append_cmd(buf, kComPing);
		vector<Resp> rs = mysql ? pipeline(mysql, buf, 2) : vector<Resp> {};
		ok(rs.size() == 2 && is_rejected(rs[0]) && rs[1].kind == RespKind::OK,
			"COM_BINLOG_DUMP + COM_PING in one write: ERR(%u) then OK. Got: %s",
			kErrRejected, describe(rs).c_str());
		ok(mysql && conn_still_usable(mysql), "Connection is still usable after the rejected COM_BINLOG_DUMP");
		if (mysql) mysql_close(mysql);
	}

	// 3. Replication command pipelined behind a running query: deferred, then replayed.
	{
		MYSQL* mysql = open_conn(cl);
		vector<uint8_t> buf;
		append_cmd(buf, kComQuery, "SELECT SLEEP(1)");
		append_cmd(buf, kComRegisterSlave, register_slave_body());
		append_cmd(buf, kComPing);
		vector<Resp> rs = mysql ? pipeline(mysql, buf, 3) : vector<Resp> {};
		ok(rs.size() == 3 && is_rs_value(rs[0], "0") && is_rejected(rs[1]) && rs[2].kind == RespKind::OK,
			"SELECT SLEEP(1) + COM_REGISTER_SLAVE + COM_PING: resultset, ERR(%u), OK. Got: %s",
			kErrRejected, describe(rs).c_str());
		ok(mysql && conn_still_usable(mysql), "Connection is still usable after the deferred rejection");
		if (mysql) mysql_close(mysql);
	}

	// 4. ProxySQL is still alive.
	{
		MYSQL* mysql = open_conn(cl);
		bool alive = mysql && mysql_query(mysql, "SELECT 1") == 0;
		if (alive) {
			MYSQL_RES* res = mysql_store_result(mysql);
			if (res) mysql_free_result(res);
		}
		ok(alive, "A new client connection to ProxySQL still works");
		if (mysql) mysql_close(mysql);

		MYSQL* admin = mysql_init(nullptr);
		bool admin_alive = mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
			nullptr, cl.admin_port, nullptr, 0) && mysql_query(admin, "SELECT 1") == 0;
		if (admin_alive) {
			MYSQL_RES* res = mysql_store_result(admin);
			if (res) mysql_free_result(res);
		}
		ok(admin_alive, "The admin interface still answers");
		mysql_close(admin);
	}

	return exit_status();
}
