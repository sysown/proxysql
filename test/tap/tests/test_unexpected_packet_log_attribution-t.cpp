/**
 * @file test_unexpected_packet_log_attribution-t.cpp
 * @brief Regression: the "unexpected packet from client" error log lines carry
 *        the frontend user and routing hostgroup, so connection churn can be
 *        attributed to a service behind a shared pool, not just a client IP.
 *
 * Reproduces the overlap without a driver: a held 'DO SLEEP' keeps the session
 * in PROCESSING_QUERY while a trailing packet (a second COM_QUERY, then a
 * COM_QUIT) is read as unexpected. The overlap case also asserts the logged
 * connection id of the attached backend. Covers 2 of the 3
 * enriched sites; the third (WAITING_CLIENT_DATA default) is an unreachable
 * defensive branch. Mutates no admin state -- default_hostgroup is only read.
 */

#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

static constexpr int MAX_LOG_CHECK_ATTEMPTS = 20;
static constexpr useconds_t LOG_CHECK_RETRY_DELAY_US = 100000;

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

// The unsigned value immediately after `key` in `line`, or -1 if `key` absent.
static long value_after(const string& line, const string& key) {
	const size_t p = line.find(key);
	if (p == string::npos) return -1;
	return atol(line.c_str() + p + key.size());
}

// The connection id from the first log line matching all three needles, or -1.
static long attributed_connection(
	const std::vector<string>& lines,
	const string& event,
	const string& user_needle,
	const string& hg_needle
) {
	for (const string& l : lines) {
		if (l.find(event) != string::npos
			&& l.find(user_needle) != string::npos
			&& l.find(hg_needle) != string::npos) {
			return value_after(l, ", connection ");
		}
	}
	return -1;
}

// Send the held query + `trailing` in one write so the trailing packet is read
// mid-query, then poll the log for a line carrying `event`, the user, and the
// hostgroup. At the overlap site the line must also carry a non-zero backend
// `connection` id (a real attached backend). Lines accumulate across attempts.
static bool trigger_and_find(
	CommandLine& cl,
	int hg,
	std::fstream& log,
	const std::vector<unsigned char>& trailing,
	const string& event,
	bool overlap_site
) {
	MYSQL* attack = mysql_init(NULL);
	if (!attack || !mysql_real_connect(attack, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("frontend connect failed: %s", attack ? mysql_error(attack) : "mysql_init");
		if (attack) mysql_close(attack);
		return false;
	}

	// Pin an established backend so the overlap logs a real connection id. A cold
	// connection was observed to log connection 0 (no backend attached at overlap
	// time); a transaction attaches and pins one. 'DO' (not 'SELECT') keeps it on
	// default_hostgroup, no '^SELECT' reader reroute.
	if (overlap_site) {
		if (mysql_query(attack, "BEGIN") || mysql_query(attack, "DO 1")) {
			diag("backend warmup failed: %s", mysql_error(attack));
		}
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

		const long backend = attributed_connection(lines, event, user_needle, hg_needle);
		if (backend < 0) {
			usleep(LOG_CHECK_RETRY_DELAY_US);   // attributed line not logged yet
			continue;
		}
		// Site 2 (COM_QUIT): the attributed line is the whole assertion. Overlap
		// site: also require a non-zero backend connection id (a real attached
		// backend). The matching KILL isn't asserted -- warming the backend for a
		// non-zero id pins it in a transaction, which suppresses the kill; the
		// kill only fires on a non-pinned in-flight overlap, which raw sockets
		// can't arrange deterministically.
		if (!overlap_site) {
			found = true;
		} else if (backend > 0) {
			found = true;
		} else {
			usleep(LOG_CHECK_RETRY_DELAY_US);   // connection still 0, retry
		}
	}

	mysql_close(attack);
	return found;
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

	// Site 1: overlapping COM_QUERY -> PMC-10001 packet line with a backend connection id.
	ok(ready && trigger_and_find(cl, hg, proxysql_log, com_query_packet("DO 1"),
			"Unexpected packet from client", true),
		"PMC-10001 line carries 'user %s'/'hostgroup %d' and a backend connection id", cl.username, hg);

	// Site 2: overlapping COM_QUIT -> COM_QUIT line.
	ok(ready && trigger_and_find(cl, hg, proxysql_log, com_quit_packet(),
			"Unexpected COM_QUIT from client", false),
		"COM_QUIT line carries 'user %s' and 'hostgroup %d'", cl.username, hg);

	if (proxysql_log.is_open()) proxysql_log.close();

	return exit_status();
}
