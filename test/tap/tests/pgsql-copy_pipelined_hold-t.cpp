/**
 * @file pgsql-copy_pipelined_hold-t.cpp
 * @brief A client may send its next messages before a COPY's ReadyForQuery: ProxySQL must run them
 *        after the COPY, in normal mode.
 *
 * PostgreSQL runs a message sent before the COPY's ReadyForQuery once the COPY is done. ProxySQL
 * relayed every client message to the backend during a COPY, and left fast forward at the COPY's own
 * ReadyForQuery. The backend went back to the pool with the pipelined message's reply still on its way,
 * and the next client of that backend got it. A SET or a BEGIN stayed on the pooled backend, and a
 * Terminate pooled a closed one, and a Sync left its ReadyForQuery there. ProxySQL now relays only
 * CopyData, CopyDone and CopyFail, and keeps the rest queued until the COPY ends, as it does for a query
 * pipelined behind any other query.
 *
 * Messages are written raw on the socket of a libpq connection. Whether a reply leaks depends on timing,
 * so the checks do not rely on that alone: a query rule rewrites the pipelined query, and only a query
 * run in normal mode is rewritten, and only a Terminate ProxySQL sees closes the client's connection.
 * The checks on what the next client gets fail only when it gets the same backend. A client that leaves
 * while a held message stalls its COPY must free its backend. One Query may run several COPYs: the data of each one must still reach the
 * backend. Everything runs with libpq and with the native protocol (where the build has it).
 */

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using Clock = std::chrono::steady_clock;
// A protocol message: its type and body. Type '!' with body "EOF" or "TIMEOUT" ends a read early.
using Msg = std::pair<char, std::string>;
using Group = std::vector<Msg>;

static const std::string PID = std::to_string(getpid());
static const std::string TBL = "cplh_" + PID;
static const std::string MARK_IN = "cplh_in_" + PID;
static const std::string MARK_OUT = "cplh_out_" + PID;
// The pause before its last row keeps the COPY TO running when the pipelined messages arrive.
static const std::string COPY_OUT_SQL =
	"COPY (SELECT g FROM generate_series(1, 2000) g UNION ALL SELECT 0 FROM pg_sleep(0.3)) TO STDOUT";
static const int ROUNDS = 3;
// A correct reply comes at once: past this, the reply went missing.
static const int READ_MS = 3000;
// A bad first row, then this many good rows behind it: about 64 KB the backend may still be sent when
// the COPY's error arrives.
static const int BACKLOG_ROWS = 9000;
// Twice the fast forward read limit (4 x pgsql-threshold_resultset_size, 16 MB by default): a read
// limit on what waits behind a held message would stop reading the client before this.
static const long long VANISH_BYTES = 32LL << 20;
// Per round: 10 pipelined-query cases with 4 checks each, two_copies 2, set_leak 2, begin_leak 2,
// terminate 2, held_vanish 1.
static const int CHECKS_PER_ROUND = 10 * 4 + 2 + 2 + 2 + 2 + 1;

static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr open_client_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execSQL(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	ExecStatusType st = PQresultStatus(res);
	bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(res);
	return good;
}

static std::string queryOneValue(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	std::string out;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		out = PQgetvalue(res, 0, 0);
	PQclear(res);
	return out;
}

// Dropping the servers drops their pooled connections, so the next ones use the protocol set here. The
// harness loads the config from disk before every test, so the disk copy is the one to put back.
static bool use_protocol(PGconn* admin, const std::string& native) {
	const bool good = execSQL(admin, "SET pgsql-use_native_backend_protocol='" + native + "'")
		&& execSQL(admin, "LOAD PGSQL VARIABLES TO RUNTIME") && execSQL(admin, "DELETE FROM pgsql_servers")
		&& execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME") && execSQL(admin, "LOAD PGSQL SERVERS FROM DISK")
		&& execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	usleep(300000);
	return good;
}

static std::string msg(char type, const std::string& body = "") {
	const uint32_t len = htonl((uint32_t)body.size() + 4);
	std::string m(1, type);
	m.append((const char*)&len, sizeof(len));
	return m + body;
}

static std::string query(const std::string& sql) {
	return msg('Q', sql + std::string(1, '\0'));
}

static const std::string COPY_ROW = msg('d', "x\n");
static const std::string COPY_DONE = msg('c');

static bool send_all(int fd, const std::string& bytes) {
	for (size_t off = 0; off < bytes.size();) {
		const ssize_t n = send(fd, bytes.data() + off, bytes.size() - off, MSG_NOSIGNAL);
		if (n <= 0) return false;
		off += n;
	}
	return true;
}

static Msg read_msg(int fd, std::string& buf) {
	const auto stop = Clock::now() + std::chrono::milliseconds(READ_MS);
	for (;;) {
		if (buf.size() >= 5) {
			uint32_t len;
			memcpy(&len, buf.data() + 1, sizeof(len));
			len = ntohl(len);
			if (buf.size() >= 1 + (size_t)len) {
				Msg m { buf[0], buf.substr(5, len - 4) };
				buf.erase(0, 1 + len);
				return m;
			}
		}
		const long left = std::chrono::duration_cast<std::chrono::milliseconds>(stop - Clock::now()).count();
		struct pollfd pfd = { fd, POLLIN, 0 };
		if (left <= 0 || poll(&pfd, 1, (int)left) <= 0) return { '!', "TIMEOUT" };
		char tmp[65536];
		const ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
		if (n <= 0) return { '!', "EOF" };
		buf.append(tmp, n);
	}
}

// The messages up to and including the next ReadyForQuery, without CopyData.
static Group read_group(int fd, std::string& buf) {
	Group g;
	for (;;) {
		Msg m = read_msg(fd, buf);
		if (m.first != 'd') g.push_back(m);
		if (m.first == 'Z' || m.first == '!') return g;
	}
}

static std::string text_of(const Msg& m) {
	return m.second.substr(0, m.second.find('\0'));
}

// The first column of the group's first DataRow.
static std::string value_of(const Group& g) {
	for (const Msg& m : g) {
		if (m.first != 'D' || m.second.size() < 6) continue;
		uint32_t len;
		memcpy(&len, m.second.data() + 2, sizeof(len));
		len = ntohl(len);
		return len == 0xFFFFFFFF ? "" : m.second.substr(6, len);
	}
	return "";
}

static bool has_tag(const Group& g, const std::string& tag) {
	for (const Msg& m : g) if (m.first == 'C' && text_of(m) == tag) return true;
	return false;
}

static bool has_type(const Group& g, char type) {
	for (const Msg& m : g) if (m.first == type) return true;
	return false;
}

static char ready_status(const Group& g) {
	return (!g.empty() && g.back().first == 'Z' && !g.back().second.empty()) ? g.back().second[0] : '?';
}

static std::string show(const Group& g) {
	std::string s;
	for (const Msg& m : g) {
		if (!s.empty()) s += " ";
		s += m.first;
		if (m.first == 'C' || m.first == '!') s += "(" + text_of(m) + ")";
		if (m.first == 'Z') s += "(" + m.second.substr(0, 1) + ")";
		if (m.first == 'E') s += "(" + m.second.substr(0, 40) + ")";
		if (m.first == 'D') s += "(" + value_of({ m }) + ")";
	}
	return s;
}

// A client session whose socket is written raw. The libpq connection only logs in, and closes it.
struct RawSession {
	PGConnPtr conn { open_client_conn() };
	int fd = PQstatus(conn.get()) == CONNECTION_OK ? PQsocket(conn.get()) : -1;
	std::string buf;

	// Sends the COPY and waits for its CopyInResponse ('G') or CopyOutResponse ('H').
	bool start_copy(const std::string& sql, char want) {
		if (fd < 0 || !send_all(fd, query(sql))) return false;
		const Msg m = read_msg(fd, buf);
		if (m.first != want) diag("COPY got '%c' (%s) instead of '%c'", m.first, text_of(m).c_str(), want);
		return m.first == want;
	}
};

// SELECT '<value>' on a new session: true when it gets its own answer and the session is idle.
static bool new_session_ok(const std::string& value) {
	auto c = open_client_conn();
	const bool good = PQstatus(c.get()) == CONNECTION_OK && queryOneValue(c.get(), "SELECT '" + value + "'") == value
		&& PQtransactionStatus(c.get()) == PQTRANS_IDLE;
	if (!good) diag("new session: %s", PQerrorMessage(c.get()));
	return good;
}

// The COPY, then `pipelined` in one write once the COPY has started. The pipelined query is the marker,
// optionally behind a lone Sync. 4 checks.
static void query_case(const std::string& what, int round, const std::string& copy_sql, char want,
	const std::string& pipelined, bool sync, const std::function<bool(const Group&)>& copy_good) {
	RawSession s;
	const bool started = s.start_copy(copy_sql, want);
	Group copy, sync_reply, marker, next;
	if (started && send_all(s.fd, pipelined)) {
		copy = read_group(s.fd, s.buf);
		if (sync) sync_reply = read_group(s.fd, s.buf);
		marker = read_group(s.fd, s.buf);
		const std::string r = "r" + std::to_string(round);
		if (send_all(s.fd, query("SELECT '" + r + "'"))) next = read_group(s.fd, s.buf);
	}
	ok(started && copy_good(copy) && ready_status(copy) == 'I', "%s round %d: the COPY gets its own result [%s]",
		what.c_str(), round, show(copy).c_str());
	const bool sync_good = !sync || (sync_reply.size() == 1 && ready_status(sync_reply) == 'I');
	ok(sync_good && value_of(marker) == MARK_OUT && ready_status(marker) == 'I',
		"%s round %d: the pipelined query runs after the COPY, rewritten by the query rule%s [%s%s%s]",
		what.c_str(), round, sync ? ", after the Sync's ReadyForQuery" : "",
		sync ? show(sync_reply).c_str() : "", sync ? " | " : "", show(marker).c_str());
	ok(value_of(next) == "r" + std::to_string(round) && ready_status(next) == 'I',
		"%s round %d: the session's next query gets its own answer [%s]", what.c_str(), round, show(next).c_str());
	ok(new_session_ok("n" + std::to_string(round)), "%s round %d: a new session gets its own answer", what.c_str(), round);
}

// One Query that runs two COPY FROM STDIN, with the pipelined query behind the second CopyDone. The
// first CopyDone must not hold the second COPY's data. 2 checks.
static void two_copies_case(const std::string& what, int round, const std::string& marker) {
	RawSession s;
	const std::string copy = "COPY " + TBL + " FROM STDIN";
	const bool started = s.start_copy(copy + "; " + copy, 'G');
	Group first, second, pipelined;
	Msg m { '!', "" };
	if (started && send_all(s.fd, COPY_ROW + COPY_DONE)) {
		// The first COPY's result, then the second COPY's CopyInResponse, with no ReadyForQuery between.
		do {
			m = read_msg(s.fd, s.buf);
			first.push_back(m);
		} while (m.first != 'G' && m.first != 'Z' && m.first != '!');
	}
	if (m.first == 'G' && send_all(s.fd, COPY_ROW + COPY_DONE + marker)) {
		second = read_group(s.fd, s.buf);
		pipelined = read_group(s.fd, s.buf);
	}
	ok(started && has_tag(first, "COPY 1") && m.first == 'G' && has_tag(second, "COPY 1") && ready_status(second) == 'I',
		"%s round %d: both COPYs of one Query get their data [%s | %s]", what.c_str(), round,
		show(first).c_str(), show(second).c_str());
	ok(value_of(pipelined) == MARK_OUT && ready_status(pipelined) == 'I',
		"%s round %d: the pipelined query runs after them, rewritten by the query rule [%s]", what.c_str(), round,
		show(pipelined).c_str());
}

// A SET after CopyDone, then the client leaves. 2 checks.
static void set_leak_case(const std::string& what, int round) {
	{
		RawSession s;
		Group copy, set;
		if (s.start_copy("COPY " + TBL + " FROM STDIN", 'G')
			&& send_all(s.fd, COPY_ROW + COPY_DONE + query("SET maintenance_work_mem = '7777kB'"))) {
			copy = read_group(s.fd, s.buf);
			set = read_group(s.fd, s.buf);
		}
		ok(has_tag(copy, "COPY 1") && has_tag(set, "SET") && ready_status(set) == 'I',
			"%s round %d: SET after CopyDone runs after the COPY [%s | %s]", what.c_str(), round,
			show(copy).c_str(), show(set).c_str());
	}
	auto c = open_client_conn();
	const std::string v = queryOneValue(c.get(), "SHOW maintenance_work_mem");
	ok(!v.empty() && v != "7777kB", "%s round %d: a new session does not get that setting (maintenance_work_mem=%s)",
		what.c_str(), round, v.c_str());
}

// A BEGIN after CopyDone, then the client leaves. 2 checks.
static void begin_leak_case(const std::string& what, int round) {
	{
		RawSession s;
		Group copy, begin;
		if (s.start_copy("COPY " + TBL + " FROM STDIN", 'G')
			&& send_all(s.fd, COPY_ROW + COPY_DONE + query("BEGIN"))) {
			copy = read_group(s.fd, s.buf);
			begin = read_group(s.fd, s.buf);
		}
		ok(has_tag(copy, "COPY 1") && has_tag(begin, "BEGIN") && ready_status(begin) == 'T',
			"%s round %d: BEGIN after CopyDone runs after the COPY [%s | %s]", what.c_str(), round,
			show(copy).c_str(), show(begin).c_str());
	}
	ok(new_session_ok("b" + std::to_string(round)), "%s round %d: a new session is not inside that transaction",
		what.c_str(), round);
}

// A Terminate after CopyDone. 2 checks.
static void terminate_case(const std::string& what, int round) {
	{
		RawSession s;
		Group g;
		Msg end { '!', "" };
		if (s.start_copy("COPY " + TBL + " FROM STDIN", 'G') && send_all(s.fd, COPY_ROW + COPY_DONE + msg('X'))) {
			g = read_group(s.fd, s.buf);
			end = read_msg(s.fd, s.buf);
		}
		// ProxySQL itself must see the Terminate, and close the client's connection.
		ok(has_tag(g, "COPY 1") && ready_status(g) == 'I' && end.first == '!' && end.second == "EOF",
			"%s round %d: the COPY gets its result, then the connection closes [%s | %s]", what.c_str(), round,
			show(g).c_str(), show({ end }).c_str());
	}
	RawSession b;
	Group done;
	if (b.start_copy("COPY " + TBL + " FROM STDIN", 'G') && send_all(b.fd, COPY_DONE)) done = read_group(b.fd, b.buf);
	ok(has_tag(done, "COPY 0") && ready_status(done) == 'I', "%s round %d: the next client's COPY still works [%s]",
		what.c_str(), round, show(done).c_str());
}

// A Sync during a COPY FROM waits for the COPY's end, and so does the CopyData sent behind it, so that
// COPY ends only with the client. The client sends 32 MB more, then leaves without a word: its backend
// must be released, not left in the COPY. 1 check.
static void held_vanish_case(PGconn* probe, const std::string& what, int round) {
	long long sent = 0;
	{
		RawSession s;
		if (s.start_copy("COPY " + TBL + " FROM STDIN", 'G') && send_all(s.fd, msg('S'))) {
			const std::string chunk = msg('d', std::string(65535, 'x') + "\n");
			const auto stop = Clock::now() + std::chrono::seconds(3);
			size_t off = 0;
			while (sent < VANISH_BYTES && Clock::now() < stop) {
				const ssize_t n = send(s.fd, chunk.data() + off, chunk.size() - off, MSG_NOSIGNAL | MSG_DONTWAIT);
				if (n > 0) {
					sent += n;
					off = (off + n) % chunk.size();
					continue;
				}
				if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) break;
				struct pollfd pfd = { s.fd, POLLOUT, 0 };
				poll(&pfd, 1, 100);
			}
		}
		// A FIN, nothing more: no Terminate, and nothing unread that would turn it into a reset.
		if (s.fd >= 0) shutdown(s.fd, SHUT_RDWR);
	}
	const std::string active = "FROM pg_stat_activity WHERE query LIKE 'COPY " + TBL + " FROM STDIN%' AND state = 'active'";
	std::string left;
	for (int i = 0; i < 50 && (left = queryOneValue(probe, "SELECT count(*) " + active)) != "0"; i++) usleep(100000);
	ok(sent >= VANISH_BYTES && left == "0", "%s round %d: the client leaves while a held Sync stalls its COPY: the "
		"backend is released (sent %lld of %lld MB; COPYs left: '%s')", what.c_str(), round, sent >> 20,
		VANISH_BYTES >> 20, left.c_str());
	// Free a backend left in the COPY, or the rest of the test waits on its lock.
	if (left != "0") queryOneValue(probe, "SELECT count(pg_terminate_backend(pid)) " + active);
}

int main(int argc, char** argv) {
	if (cl.getEnv())
		return exit_status();

	auto admin = open_admin_conn();
	if (PQstatus(admin.get()) != CONNECTION_OK) {
		plan(1);
		ok(false, "ADMIN connection created: %s", PQerrorMessage(admin.get()));
		return exit_status();
	}
	const bool native_supported = pgsql_native_supported(admin.get());
	const std::vector<std::string> protocols = native_supported
		? std::vector<std::string> { "libpq", "native" } : std::vector<std::string> { "libpq" };
	plan(1 + (int)protocols.size() * ROUNDS * CHECKS_PER_ROUND);
	const std::string saved_native = queryOneValue(admin.get(),
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");

	// Only a query run in normal mode goes through the query rules.
	const std::string drop_rule = "DELETE FROM pgsql_query_rules WHERE match_pattern='" + MARK_IN + "'";
	auto setup = open_client_conn();
	const bool setup_ok = PQstatus(setup.get()) == CONNECTION_OK
		&& execSQL(setup.get(), "DROP TABLE IF EXISTS " + TBL) && execSQL(setup.get(), "CREATE TABLE " + TBL + " (a text)")
		&& execSQL(admin.get(), drop_rule)
		&& execSQL(admin.get(), "INSERT INTO pgsql_query_rules (active, match_pattern, replace_pattern, apply) VALUES (1, '"
			+ MARK_IN + "', '" + MARK_OUT + "', 1)")
		&& execSQL(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
	const std::string rewritten = setup_ok ? queryOneValue(setup.get(), "SELECT '" + MARK_IN + "'") : "";
	ok(setup_ok && rewritten == MARK_OUT, "Setup: table created, and the query rule rewrites the marker (got '%s')",
		rewritten.c_str());
	if (!setup_ok || rewritten != MARK_OUT) BAIL_OUT("setup failed");

	const std::string marker = query("SELECT '" + MARK_IN + "'");
	const std::string copy_in = "COPY " + TBL + " FROM STDIN";
	for (const std::string& protocol : protocols) {
		if (native_supported && !use_protocol(admin.get(), protocol == "native" ? "true" : "false"))
			BAIL_OUT("could not switch the backend protocol to %s", protocol.c_str());
		for (int r = 0; r < ROUNDS; r++) {
			query_case(protocol + " CopyDone+Query", r, copy_in, 'G', COPY_ROW + COPY_DONE + marker, false,
				[](const Group& g) { return has_tag(g, "COPY 1"); });
			// PostgreSQL takes STDIN and STDOUT for the same client stream.
			query_case(protocol + " FROM STDOUT+Query", r, "COPY " + TBL + " FROM STDOUT", 'G',
				COPY_ROW + COPY_DONE + marker, false, [](const Group& g) { return has_tag(g, "COPY 1"); });
			// After the COPY, PostgreSQL answers a Sync with a ReadyForQuery, and a Flush with nothing.
			query_case(protocol + " CopyDone+Sync+Query", r, copy_in, 'G', COPY_ROW + COPY_DONE + msg('S') + marker, true,
				[](const Group& g) { return has_tag(g, "COPY 1"); });
			query_case(protocol + " CopyDone+Flush+Query", r, copy_in, 'G', COPY_ROW + COPY_DONE + msg('H') + marker, false,
				[](const Group& g) { return has_tag(g, "COPY 1"); });
			// PostgreSQL ignores a Flush during a COPY FROM: the rows and the CopyDone behind it still end the COPY.
			query_case(protocol + " Flush+CopyData+CopyDone+Query", r, copy_in, 'G',
				COPY_ROW + msg('H') + COPY_ROW + COPY_DONE + marker, false, [](const Group& g) { return has_tag(g, "COPY 2"); });
			// A bad first row (an extra column) fails the COPY while the client is still sending, alone and
			// with a backlog of rows behind it.
			query_case(protocol + " bad row+Query", r, copy_in, 'G', msg('d', "x\ty\n") + COPY_DONE + marker, false,
				[](const Group& g) { return has_type(g, 'E'); });
			std::string backlog;
			for (int i = 0; i < BACKLOG_ROWS; i++) backlog += COPY_ROW;
			query_case(protocol + " bad row+backlog+Query", r, copy_in, 'G', msg('d', "x\ty\n") + backlog + COPY_DONE + marker,
				false, [](const Group& g) { return has_type(g, 'E'); });
			two_copies_case(protocol + " two COPYs", r, marker);
			query_case(protocol + " CopyFail+Query", r, copy_in, 'G', COPY_ROW + msg('f', std::string("stop") + '\0') + marker,
				false, [](const Group& g) { return has_type(g, 'E'); });
			query_case(protocol + " COPY TO+Query", r, COPY_OUT_SQL, 'H', marker, false,
				[](const Group& g) { return has_tag(g, "COPY 2001"); });
			query_case(protocol + " COPY TO+Sync+Query", r, COPY_OUT_SQL, 'H', msg('S') + marker, true,
				[](const Group& g) { return has_tag(g, "COPY 2001"); });
			set_leak_case(protocol + " SET", r);
			begin_leak_case(protocol + " BEGIN", r);
			terminate_case(protocol + " Terminate", r);
			held_vanish_case(setup.get(), protocol + " Sync+CopyData+leave", r);
		}
	}

	if (native_supported && !saved_native.empty()) use_protocol(admin.get(), saved_native);
	execSQL(admin.get(), drop_rule);
	execSQL(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
	execSQL(setup.get(), "DROP TABLE IF EXISTS " + TBL);

	return exit_status();
}
