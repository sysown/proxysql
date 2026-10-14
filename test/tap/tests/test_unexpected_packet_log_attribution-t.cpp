/**
 * @file test_unexpected_packet_log_attribution-t.cpp
 * @brief Regression: the "unexpected packet from client" error log lines carry
 *        the frontend user and routing hostgroup, so connection churn can be
 *        attributed to a service behind a shared pool, not just a client IP.
 *
 * Reproduces the overlap without a driver: a held 'DO SLEEP' keeps the session
 * in PROCESSING_QUERY while a trailing COM_QUIT is read as unexpected, and the
 * COM_QUIT line must carry the user and the hostgroup.
 *
 * A trailing COM_QUERY used to be logged as an unexpected packet (PMC-10001)
 * too. Since #5930 a command received while another one is in flight is client
 * pipelining: it is queued and executed after the first one. The test now
 * asserts that the overlapping COM_QUERY gets its response, after the held one,
 * and that no PMC-10001 line is logged for it. Mutates no admin state --
 * default_hostgroup is only read.
 */

#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

static constexpr int MAX_LOG_CHECK_ATTEMPTS = 20;
static constexpr useconds_t LOG_CHECK_RETRY_DELAY_US = 100000;
// Upper bound for each wait on the frontend socket: a missing response fails
// the check instead of hanging the test.
static constexpr int RECV_TIMEOUT_MS = 10000;

// Held server-side so the session stays in PROCESSING_QUERY while the trailing
// packet is read. 'DO' (not 'SELECT') avoids '^SELECT' reader rules, so routing
// lands on the user's default_hostgroup and the logged hostgroup is predictable.
static const string OVERLAP_SLEEP_QUERY = "DO SLEEP(5)";

static int admin_query_one_int(MYSQL* admin, const string& sql, int& out) {
	if (mysql_query(admin, sql.c_str())) {
		diag("admin query failed: %s: %s", sql.c_str(), mysql_error(admin));
		return -1;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (!r) return -1;
	int rc = -1;
	MYSQL_ROW row = mysql_fetch_row(r);
	if (row && row[0]) {
		out = atoi(row[0]);
		rc = 0;
	}
	mysql_free_result(r);
	return rc;
}

// COM_QUERY packet: 3-byte LE length, seq 0, 0x03, query (< 16 MiB).
static std::vector<unsigned char> com_query_packet(const string& query) {
	const size_t payload_len = 1 + query.size();
	std::vector<unsigned char> pkt;
	pkt.reserve(4 + payload_len);
	pkt.push_back(static_cast<unsigned char>(payload_len & 0xff));
	pkt.push_back(static_cast<unsigned char>((payload_len >> 8) & 0xff));
	pkt.push_back(static_cast<unsigned char>((payload_len >> 16) & 0xff));
	pkt.push_back(0x00);
	pkt.push_back(0x03);
	pkt.insert(pkt.end(), query.begin(), query.end());
	return pkt;
}

// COM_QUIT packet.
static std::vector<unsigned char> com_quit_packet() {
	return { 0x01, 0x00, 0x00, 0x00, 0x01 };
}

static bool send_all(int fd, const unsigned char* data, size_t len) {
	size_t total_sent = 0;
	while (total_sent < len) {
		const ssize_t sent = send(fd, data + total_sent, len - total_sent, MSG_NOSIGNAL);
		if (sent <= 0) {
			return false;
		}
		total_sent += sent;
	}
	return true;
}

// Whether a log line matches all three needles.
static bool attributed_line_found(
	const std::vector<string>& lines,
	const string& event,
	const string& user_needle,
	const string& hg_needle
) {
	for (const string& l : lines) {
		if (l.find(event) != string::npos
			&& l.find(user_needle) != string::npos
			&& l.find(hg_needle) != string::npos) {
			return true;
		}
	}
	return false;
}

// Send the held query + `trailing` in one write so the trailing packet is read
// mid-query, then poll the log for a line carrying `event`, the user, and the
// hostgroup. Lines accumulate across attempts.
static bool trigger_and_find(
	CommandLine& cl,
	int hg,
	std::fstream& log,
	const std::vector<unsigned char>& trailing,
	const string& event
) {
	MYSQL* attack = mysql_init(NULL);
	if (!attack || !mysql_real_connect(attack, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("frontend connect failed: %s", attack ? mysql_error(attack) : "mysql_init");
		if (attack) mysql_close(attack);
		return false;
	}

	std::vector<unsigned char> buf = com_query_packet(OVERLAP_SLEEP_QUERY);
	buf.insert(buf.end(), trailing.begin(), trailing.end());
	const bool wrote = send_all(mysql_get_socket(attack), buf.data(), buf.size());
	if (!wrote) diag("send_all failed on frontend connection");

	const string user_needle { "user '" + string(cl.username) + "'" };
	const string hg_needle { "hostgroup " + std::to_string(hg) };
	std::vector<string> lines;
	bool found = false;
	string line {};
	for (int attempt = 0; wrote && attempt < MAX_LOG_CHECK_ATTEMPTS && !found; ++attempt) {
		log.clear(log.rdstate() & ~std::ios_base::eofbit & ~std::ios_base::failbit);
		while (getline(log, line)) lines.push_back(line);

		if (attributed_line_found(lines, event, user_needle, hg_needle)) {
			found = true;
		} else {
			usleep(LOG_CHECK_RETRY_DELAY_US);   // attributed line not logged yet
		}
	}

	mysql_close(attack);
	return found;
}

static bool recv_all(int fd, unsigned char* buf, size_t len) {
	size_t got = 0;
	while (got < len) {
		struct pollfd pfd { fd, POLLIN, 0 };
		if (poll(&pfd, 1, RECV_TIMEOUT_MS) != 1) return false;
		const ssize_t n = recv(fd, buf + got, len - got, 0);
		if (n <= 0) return false;
		got += n;
	}
	return true;
}

// First payload byte of the next packet received on `fd`, or -1.
static int read_packet_first_byte(int fd) {
	unsigned char hdr[4];
	if (!recv_all(fd, hdr, sizeof(hdr))) return -1;
	const size_t len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16);
	if (len == 0) return -1;
	std::vector<unsigned char> payload(len);
	if (!recv_all(fd, payload.data(), len)) return -1;
	return payload[0];
}

// Send the held query + a second COM_QUERY in one write: since #5930 the second
// one is queued and executed after the held one. Both must get an OK packet, and
// no PMC-10001 line may be logged.
static bool overlapping_query_is_pipelined(CommandLine& cl, std::fstream& log) {
	MYSQL* conn = mysql_init(NULL);
	if (!conn || !mysql_real_connect(conn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("frontend connect failed: %s", conn ? mysql_error(conn) : "mysql_init");
		if (conn) mysql_close(conn);
		return false;
	}
	std::vector<unsigned char> buf = com_query_packet(OVERLAP_SLEEP_QUERY);
	const std::vector<unsigned char> trailing = com_query_packet("DO 1");
	buf.insert(buf.end(), trailing.begin(), trailing.end());

	const int fd = mysql_get_socket(conn);
	bool res = send_all(fd, buf.data(), buf.size());
	if (!res) diag("send_all failed on frontend connection");
	for (int i = 0; res && i < 2; i++) {
		const int first = read_packet_first_byte(fd);
		if (first != 0x00) {
			diag("Response %d to the overlapping commands is not an OK packet (first byte %d)", i + 1, first);
			res = false;
		}
	}
	mysql_close(conn);

	const string user_needle { "user '" + string(cl.username) + "'" };
	string line {};
	log.clear(log.rdstate() & ~std::ios_base::eofbit & ~std::ios_base::failbit);
	while (getline(log, line)) {
		if (line.find("Unexpected packet from client") != string::npos && line.find(user_needle) != string::npos) {
			diag("Unexpected PMC-10001 line: %s", line.c_str());
			res = false;
		}
	}
	return res;
}

int main() {
	CommandLine cl;

	plan(5);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	const string log_dir { get_env("REGULAR_INFRA_DATADIR") };
	ok(!log_dir.empty(), "REGULAR_INFRA_DATADIR is set");

	const string log_path { log_dir + "/proxysql.log" };
	std::fstream proxysql_log {};
	const int log_res = log_dir.empty() ? EXIT_FAILURE : open_file_and_seek_end(log_path, proxysql_log);
	ok(log_res == EXIT_SUCCESS, "Opened ProxySQL log at end");

	MYSQL* admin = mysql_init(NULL);
	int hg = -1;
	if (admin && mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		const string q = string("SELECT default_hostgroup FROM mysql_users WHERE username = '")
			+ cl.username + "' LIMIT 1";
		admin_query_one_int(admin, q, hg);
	} else {
		diag("admin connect failed: %s", admin ? mysql_error(admin) : "mysql_init");
	}
	if (admin) mysql_close(admin);
	ok(hg >= 0, "Discovered default_hostgroup=%d for user '%s'", hg, cl.username);

	const bool ready = (log_res == EXIT_SUCCESS && hg >= 0);

	// Overlapping COM_QUERY -> pipelined (#5930): both commands answered, no PMC-10001 line.
	ok(ready && overlapping_query_is_pipelined(cl, proxysql_log),
		"Overlapping COM_QUERY is executed after the held one, without a PMC-10001 line");

	// Site 2: overlapping COM_QUIT -> COM_QUIT line.
	ok(ready && trigger_and_find(cl, hg, proxysql_log, com_quit_packet(),
			"Unexpected COM_QUIT from client"),
		"COM_QUIT line carries 'user %s' and 'hostgroup %d'", cl.username, hg);

	if (proxysql_log.is_open()) proxysql_log.close();

	return exit_status();
}
