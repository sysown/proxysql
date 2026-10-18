/**
 * @file reg_test_5930_mysql_client_no_read_backpressure-t.cpp
 * @brief Regression test: a MySQL client that keeps sending commands without reading the responses
 *   must not make ProxySQL buffer the responses without limit.
 *
 * @details Since client command pipelining was allowed (#5930), a client may send new commands while
 *   the responses to the previous ones are still queued, instead of being disconnected. Commands
 *   that ProxySQL answers by itself (COM_PING, tracked SET statements, query rules with OK_msg) are
 *   executed as soon as they are read, each appending a response packet to the client output queue.
 *   If the client never reads, and ProxySQL keeps reading from it, that queue grows with every
 *   command the client sends, until the host runs out of memory.
 *
 *   ProxySQL must apply backpressure instead, as a MySQL server does when its writes block: once the
 *   pending output is above a limit it stops reading from the client, so the commands stay in the
 *   kernel buffers and TCP flow control eventually blocks the client writes.
 *
 *   The test connects with libmariadb, then on the connection socket:
 *   - Writes COM_PING packets with non-blocking sends, never reading. It checks that the writes
 *     stall (EAGAIN, then no progress for several seconds) well before a cap that is larger than any
 *     kernel buffering, i.e. that ProxySQL stopped reading.
 *   - Checks that the jemalloc allocated memory of ProxySQL ('stats_memory_metrics') grew by much
 *     less than the responses to every ping would take (skipped when jemalloc stats are missing).
 *   - Completes the last (possibly partial) packet, appends "SELECT 'last'", and reads everything:
 *     one OK packet per COM_PING, then the resultset of the final SELECT, in order.
 *   - Checks that the connection is still usable with regular traffic.
 *   Without the backpressure, ProxySQL reads every ping: the writes never stall and its memory grows
 *   by hundreds of MB.
 */

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
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

constexpr uint8_t kComQuery = 0x03;
constexpr uint8_t kComPing = 0x0e;
constexpr size_t kPingPktLen = 5; // 4 bytes header + command byte
constexpr int kRecvTimeoutMs = 20000;
// No write progress for this long, with the socket send buffer full, means the peer stopped reading.
constexpr int kStallMs = 3000;
constexpr int kMaxFloodSecs = 120;
// Memory growth allowed while the client does not read. Without backpressure the growth is at least
// 16 bytes per ping (one allocation per OK packet), i.e. several hundred MB at the flood cap.
constexpr uint64_t kMaxMemGrowth = 32ULL * 1024 * 1024;

void append_cmd(vector<uint8_t>& buf, uint8_t cmd, const string& arg = "") {
	const size_t len = 1 + arg.size();
	buf.push_back(len & 0xff);
	buf.push_back((len >> 8) & 0xff);
	buf.push_back((len >> 16) & 0xff);
	buf.push_back(0); // sequence id: every command starts a new exchange
	buf.push_back(cmd);
	buf.insert(buf.end(), arg.begin(), arg.end());
}

bool send_all(int fd, const uint8_t* data, size_t len) {
	size_t sent = 0;
	while (sent < len) {
		ssize_t n = send(fd, data + sent, len - sent, MSG_NOSIGNAL);
		if (n <= 0) return false;
		sent += n;
	}
	return true;
}

/** @brief Buffered packet reader: millions of small OK packets are read in bulk. */
class PktReader {
public:
	explicit PktReader(int fd) : fd_(fd), buf_(1024 * 1024), pos_(0), end_(0) {}

	bool read_packet(vector<uint8_t>& payload) {
		uint8_t hdr[4];
		if (!read_bytes(hdr, 4)) return false;
		const size_t len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16);
		payload.resize(len);
		return len == 0 || read_bytes(payload.data(), len);
	}

private:
	bool read_bytes(uint8_t* dst, size_t len) {
		while (len) {
			if (pos_ == end_ && !fill()) return false;
			const size_t n = std::min(len, end_ - pos_);
			memcpy(dst, buf_.data() + pos_, n);
			pos_ += n;
			dst += n;
			len -= n;
		}
		return true;
	}

	bool fill() {
		struct pollfd pfd { fd_, POLLIN, 0 };
		if (poll(&pfd, 1, kRecvTimeoutMs) != 1) return false;
		ssize_t n = recv(fd_, buf_.data(), buf_.size(), 0);
		if (n <= 0) return false;
		pos_ = 0;
		end_ = n;
		return true;
	}

	int fd_;
	vector<uint8_t> buf_;
	size_t pos_;
	size_t end_;
};

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
 * @brief Reads a text resultset with a single column and returns its rows, or false on any
 *   unexpected packet. The first packet (column count) is passed in 'p'.
 */
bool read_single_col_resultset(PktReader& rd, vector<uint8_t> p, bool deprecate_eof, vector<string>& rows) {
	size_t pos = 0;
	if (p.empty() || p[0] == 0x00 || p[0] == 0xff || lenenc_int(p, pos) != 1) return false;
	if (!rd.read_packet(p)) return false; // column definition
	if (!deprecate_eof && (!rd.read_packet(p) || p.empty() || p[0] != 0xfe)) return false;
	for (;;) {
		if (!rd.read_packet(p) || p.empty() || p[0] == 0xff) return false;
		if (p[0] == 0xfe && p.size() < 0xffffff) return true; // EOF, or OK terminator with DEPRECATE_EOF
		size_t rpos = 0;
		const uint64_t len = lenenc_int(p, rpos);
		if (rpos + len > p.size()) return false;
		rows.emplace_back(reinterpret_cast<const char*>(p.data() + rpos), len);
	}
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

/** @brief jemalloc allocated bytes of ProxySQL, or -1 when not available (e.g. NOJEMALLOC builds). */
int64_t proxysql_allocated(MYSQL* admin) {
	const string v = query_value(admin,
		"SELECT variable_value FROM stats_memory_metrics WHERE variable_name='jemalloc_allocated'");
	return v.empty() ? -1 : std::stoll(v);
}

/** @brief Largest TCP receive buffer the kernel may autotune to, or 0 if unknown. */
uint64_t tcp_rmem_max() {
	std::ifstream f("/proc/sys/net/ipv4/tcp_rmem");
	uint64_t lo = 0, def = 0, hi = 0;
	if (f >> lo >> def >> hi) return hi;
	return 0;
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(4);

	MYSQL* admin = mysql_init(nullptr);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		diag("Admin connection failed: %s", mysql_error(admin));
		return exit_status();
	}
	diag("mysql-threshold_resultset_size: %s", query_value(admin,
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-threshold_resultset_size'").c_str());

	MYSQL* mysql = open_conn(cl);
	if (!mysql) return exit_status();
	const int fd = mysql->net.fd;
	const bool deof = deprecate_eof(mysql);

	// Keep the client side kernel buffering small, so that what the proxy holds dominates.
	const int small_buf = 64 * 1024;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &small_buf, sizeof(small_buf));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small_buf, sizeof(small_buf));

	// Comfortably more than the kernel can buffer on both ends of the connection.
	const uint64_t flood_cap = std::max<uint64_t>(64ULL * 1024 * 1024, 2 * tcp_rmem_max() + 16ULL * 1024 * 1024);

	vector<uint8_t> chunk;
	for (size_t i = 0; i < 64 * 1024 / kPingPktLen; i++) {
		append_cmd(chunk, kComPing);
	}

	const int64_t mem_before = proxysql_allocated(admin);

	// 1. Flood COM_PING without reading, until the writes stall or the cap is reached.
	uint64_t sent_bytes = 0;
	size_t chunk_off = 0;
	bool stalled = false;
	string send_error;
	const auto t0 = std::chrono::steady_clock::now();
	while (sent_bytes < flood_cap) {
		if (std::chrono::steady_clock::now() - t0 > std::chrono::seconds(kMaxFloodSecs)) {
			send_error = "flood time limit reached";
			break;
		}
		ssize_t n = send(fd, chunk.data() + chunk_off, chunk.size() - chunk_off, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (n > 0) {
			sent_bytes += n;
			chunk_off = (chunk_off + n) % chunk.size();
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			struct pollfd pfd { fd, POLLOUT, 0 };
			const int rc = poll(&pfd, 1, kStallMs);
			if (rc == 0) {
				stalled = true;
				break;
			}
			if (rc < 0 || (pfd.revents & (POLLERR | POLLHUP))) {
				send_error = "socket error while waiting for POLLOUT";
				break;
			}
		} else {
			send_error = string("send() failed: ") + strerror(errno);
			break;
		}
	}
	diag("Bytes of COM_PING written without reading: %lu (cap %lu)%s%s", sent_bytes, flood_cap,
		send_error.empty() ? "" : ", ", send_error.c_str());
	ok(stalled, "ProxySQL stops reading from a client that does not read its responses. Written %lu of %lu bytes",
		sent_bytes, flood_cap);

	// 2. The responses to every ping were not buffered in memory.
	const int64_t mem_after = proxysql_allocated(admin);
	if (mem_before < 0 || mem_after < 0) {
		skip(1, "jemalloc_allocated not available in stats_memory_metrics");
	} else {
		const int64_t growth = mem_after - mem_before;
		diag("jemalloc_allocated before: %ld after: %ld growth: %ld", mem_before, mem_after, growth);
		ok(growth < static_cast<int64_t>(kMaxMemGrowth),
			"ProxySQL memory growth while the client does not read is bounded: %ld bytes (limit %lu)",
			growth, kMaxMemGrowth);
	}

	// 3. Complete the last ping, add a final SELECT, then read every response in order.
	const uint64_t n_pings = (sent_bytes + kPingPktLen - 1) / kPingPktLen;
	vector<uint8_t> tail(chunk.begin() + chunk_off, chunk.begin() + (chunk_off + kPingPktLen - 1) / kPingPktLen * kPingPktLen);
	append_cmd(tail, kComQuery, "SELECT 'last'");
	bool tail_sent = false;
	std::thread writer([&]() { tail_sent = send_all(fd, tail.data(), tail.size()); });

	PktReader rd(fd);
	vector<uint8_t> p;
	uint64_t oks = 0;
	string first_bad;
	for (; oks < n_pings; oks++) {
		if (!rd.read_packet(p) || p.empty() || p[0] != 0x00) {
			first_bad = "response #" + std::to_string(oks) + (p.empty() ? ": none" : ": first byte " + std::to_string(p[0]));
			break;
		}
	}
	vector<string> rows;
	bool last_ok = false;
	if (oks == n_pings) {
		last_ok = rd.read_packet(p) && read_single_col_resultset(rd, p, deof, rows) && rows.size() == 1 && rows[0] == "last";
		if (!last_ok) first_bad = "the final SELECT did not return 'last'";
	}
	writer.join();
	if (!tail_sent) diag("The writer failed to send the final packets");
	ok(oks == n_pings && last_ok, "All %lu COM_PING get an OK packet, then the final SELECT its resultset. Got %lu OK. %s",
		n_pings, oks, first_bad.c_str());

	// 4. The connection is still usable with regular, non pipelined, traffic.
	ok(query_value(mysql, "SELECT 1") == "1", "Connection still usable after the client drained its responses");

	mysql_close(mysql);
	mysql_close(admin);

	return exit_status();
}
