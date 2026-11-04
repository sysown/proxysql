/**
 * Replication commands switch to permanent fast-forward. If another command is
 * already queued, close the frontend before the handoff: no ERR, no replay, and
 * no special flushing for COM_QUIT. Single commands must still reach a backend.
 * Uses the normal TAP CommandLine fixture and a backend replication-capable user.
 */
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <poll.h>
#include <sys/socket.h>
#include "mysql.h"
#include "command_line.h"
#include "tap.h"

using std::string;
using std::vector;
namespace {
constexpr uint8_t QUERY = 0x03, QUIT = 0x01, PING = 0x0e;
constexpr uint8_t DUMP = 0x12, REGISTER = 0x15, GTID = 0x1e;
constexpr int deadline_ms = 5000;
using Clock = std::chrono::steady_clock;

void append(vector<uint8_t>& b, uint8_t command, const string& body = "") {
	size_t n = body.size() + 1;
	b.insert(b.end(), {uint8_t(n), uint8_t(n >> 8), uint8_t(n >> 16), 0, command});
	b.insert(b.end(), body.begin(), body.end());
}
void le(string& b, uint64_t value, size_t n) {
	for (size_t i = 0; i < n; ++i) b.push_back(uint8_t(value >> (8 * i)));
}
string body(uint8_t command) {
	string b;
	if (command == REGISTER) {
		le(b, 4242, 4); b += char(7); b += "replica";
		b += char(0); b += char(0); // empty replication user and password
		le(b, 3306, 2); le(b, 0, 4); le(b, 0, 4);
	} else if (command == DUMP) {
		le(b, 4, 4); le(b, 0, 2); le(b, 4242, 4);
		b += "proxysql-regression-missing.000001";
	} else {
		le(b, 0, 2); le(b, 4242, 4);
		const string filename = "proxysql-regression-missing.000001";
		le(b, filename.size(), 4); b += filename; le(b, 4, 8);
		le(b, 8, 4); le(b, 0, 8); // empty GTID set
	}
	return b;
}

struct Packet { uint8_t sequence; vector<uint8_t> payload; };
vector<Packet> packets(const vector<uint8_t>& bytes) {
	vector<Packet> result;
	for (size_t i = 0; i + 4 <= bytes.size();) {
		const size_t n = bytes[i] | (size_t(bytes[i + 1]) << 8) | (size_t(bytes[i + 2]) << 16);
		if (i + 4 + n > bytes.size()) break;
		result.push_back({bytes[i + 3], vector<uint8_t>(bytes.begin() + i + 4, bytes.begin() + i + 4 + n)});
		i += 4 + n;
	}
	return result;
}
enum class End { PACKETS, EOF_REACHED, RESET, TIMEOUT, ERROR };
struct Wire {
	End end = End::ERROR;
	int error = 0;
	vector<uint8_t> bytes;
	bool closed() const { return end == End::EOF_REACHED || end == End::RESET; }
};

// One absolute deadline bounds the whole exchange, including partial reads.
// wanted == 0 drains until a genuine TCP EOF/reset, never treating timeout as close.
Wire receive(int fd, size_t wanted = 0) {
	Wire r;
	const auto deadline = Clock::now() + std::chrono::milliseconds(deadline_ms);
	for (;;) {
		int remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
		if (remaining <= 0) { r.end = End::TIMEOUT; return r; }
		pollfd pfd {fd, POLLIN, 0};
		int ready = poll(&pfd, 1, remaining);
		if (ready < 0 && errno == EINTR) continue;
		if (ready == 0) { r.end = End::TIMEOUT; return r; }
		if (ready < 0) { r.error = errno; return r; }
		uint8_t chunk[4096];
		ssize_t n = recv(fd, chunk, sizeof(chunk), MSG_DONTWAIT);
		if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
		if (n == 0) { r.end = End::EOF_REACHED; return r; }
		if (n < 0) {
			r.error = errno;
			if (errno == ECONNRESET) r.end = End::RESET;
			return r;
		}
		r.bytes.insert(r.bytes.end(), chunk, chunk + n);
		if (wanted && packets(r.bytes).size() >= wanted) { r.end = End::PACKETS; return r; }
		if (r.bytes.size() > 65536) { r.error = EMSGSIZE; return r; }
	}
}

MYSQL* connect(const CommandLine& cl, bool admin = false) {
	MYSQL* m = mysql_init(nullptr);
	if (!m) return nullptr;
	unsigned timeout = deadline_ms / 1000;
	mysql_options(m, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	mysql_options(m, MYSQL_OPT_READ_TIMEOUT, &timeout);
	mysql_options(m, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
#ifdef MARIADB_BASE_VERSION
	my_bool tls = 0;
	mysql_options(m, MYSQL_OPT_SSL_ENFORCE, &tls);
#else
	mysql_ssl_mode tls = SSL_MODE_DISABLED;
	mysql_options(m, MYSQL_OPT_SSL_MODE, &tls);
#endif
	// No CLIENT_SSL and no TLS options: the raw socket exchanges require plaintext.
	if (!mysql_real_connect(m, admin ? cl.admin_host : cl.host,
		admin ? cl.admin_username : cl.username, admin ? cl.admin_password : cl.password,
		nullptr, admin ? cl.admin_port : cl.port, nullptr, 0) || mysql_get_ssl_cipher(m)) {
		diag("%s connection failed or negotiated TLS: %s", admin ? "Admin" : "Client", mysql_error(m));
		mysql_close(m);
		return nullptr;
	}
	return m;
}
bool send_once(MYSQL* m, const vector<uint8_t>& bytes) {
	if (!m) return false;
	ssize_t n = send(m->net.fd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
	if (n != ssize_t(bytes.size())) diag("Single pipeline send: %zd/%zu bytes, errno=%d", n, bytes.size(), errno);
	return n == ssize_t(bytes.size());
}
bool query_alive(const CommandLine& cl, bool admin) {
	MYSQL* m = connect(cl, admin);
	bool alive = m && mysql_query(m, "SELECT 1") == 0;
	MYSQL_RES* result = alive ? mysql_store_result(m) : nullptr;
	MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
	alive = row && row[0] && string(row[0]) == "1";
	if (result) mysql_free_result(result);
	if (m) mysql_close(m);
	return alive;
}
void health(const CommandLine& cl, const char* after) {
	ok(query_alive(cl, false), "Fresh client answers after %s", after);
	ok(query_alive(cl, true), "Admin answers after %s", after);
}

void closes(const CommandLine& cl, const char* name, const vector<uint8_t>& bytes, bool deferred = false) {
	MYSQL* m = connect(cl);
	bool sent = send_once(m, bytes);
	Wire r = sent ? receive(m->net.fd) : Wire{};
	bool valid = r.closed() && (deferred || r.bytes.empty());
	if (deferred) {
		// Allow any flushed prefix of SLEEP's resultset, including a partial last
		// packet. A subsequent command's response restarts at sequence 1.
		uint8_t sequence = 1;
		for (size_t i = 0; i + 5 <= r.bytes.size(); ++sequence) {
			const size_t n = r.bytes[i] | (size_t(r.bytes[i + 1]) << 8) | (size_t(r.bytes[i + 2]) << 16);
			if (r.bytes[i + 3] != sequence || r.bytes[i + 4] == 0xff
				|| (sequence == 1 && (n != 1 || r.bytes[i + 4] != 1))) valid = false;
			if (i + 4 + n > r.bytes.size()) break;
			i += 4 + n;
		}
	}
	ok(sent && valid, "%s closes without replication/PING response (end=%d, errno=%d, bytes=%zu)",
		name, int(r.end), r.error, r.bytes.size());
	if (m) mysql_close(m);
	health(cl, name);
}
bool is_ok(const Packet& p) {
	return p.sequence == 1 && !p.payload.empty() && p.payload[0] == 0;
}
} // namespace

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	plan(24);
	const uint8_t commands[] {REGISTER, DUMP, GTID};
	const char* names[] {"REGISTER + PING", "BINLOG_DUMP + PING", "BINLOG_DUMP_GTID + PING"};
	for (size_t i = 0; i < 3; ++i) {
		vector<uint8_t> b;
		append(b, commands[i], body(commands[i])); append(b, PING);
		closes(cl, names[i], b);
	}
	{
		vector<uint8_t> b;
		append(b, REGISTER, body(REGISTER)); append(b, QUIT);
		closes(cl, "REGISTER + QUIT", b);
	}
	{
		vector<uint8_t> b;
		append(b, REGISTER, body(REGISTER)); append(b, GTID, body(GTID)); append(b, PING);
		closes(cl, "Consecutive replication commands + PING", b);
	}
	{
		vector<uint8_t> b;
		append(b, QUERY, "SELECT SLEEP(1)"); append(b, REGISTER, body(REGISTER)); append(b, PING);
		closes(cl, "Deferred SLEEP + REGISTER + PING", b, true);
	}
	// Ordinary pipelining continues to return one response per command.
	{
		MYSQL* m = connect(cl);
		vector<uint8_t> b;
		append(b, QUERY, "DO 1"); append(b, PING);
		Wire r = send_once(m, b) ? receive(m->net.fd, 2) : Wire{};
		auto ps = packets(r.bytes);
		ok(r.end == End::PACKETS && ps.size() == 2 && is_ok(ps[0]) && is_ok(ps[1]),
			"Ordinary query + PING still returns two OK responses");
		if (m) mysql_close(m);
	}
	for (uint8_t command : commands) {
		MYSQL* m = connect(cl);
		// Replication selects the preceding query's hostgroup. Establish it before
		// exercising an unchanged single-command handoff on this fresh connection.
		bool routed = m && mysql_query(m, "DO 1") == 0;
		vector<uint8_t> b;
		append(b, command, body(command));
		Wire r = routed && send_once(m, b) ? receive(m->net.fd, 1) : Wire{};
		auto ps = packets(r.bytes);
		bool reply = r.end == End::PACKETS && ps.size() == 1 && ps[0].sequence == 1 && !ps[0].payload.empty();
		// Accept only the missing-binlog error, or MariaDB's unsupported GTID
		// command error. ProxySQL connection/routing errors do not prove handoff.
		if (reply && command == REGISTER) reply = is_ok(ps[0]);
		if (reply && command != REGISTER) {
			int error = ps[0].payload.size() >= 3 && ps[0].payload[0] == 0xff
				? ps[0].payload[1] | (ps[0].payload[2] << 8) : 0;
			reply = error == 1236 || (command == GTID && error == 1047);
			if (!reply) diag("Unexpected replication response error=%d", error);
		}
		ok(reply, "Single replication command 0x%02x receives backend response (end=%d, bytes=%zu)",
			command, int(r.end), r.bytes.size());
		if (command == REGISTER) {
			b.clear(); append(b, PING);
			Wire ping = reply && send_once(m, b) ? receive(m->net.fd, 1) : Wire{};
			auto response = packets(ping.bytes);
			ok(response.size() == 1 && is_ok(response[0]), "PING after registration response works in fast-forward");
		}
		if (m) mysql_close(m);
	}
	ok(query_alive(cl, false) && query_alive(cl, true), "Client and admin remain usable after controls");
	return exit_status();
}
