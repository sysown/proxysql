/**
 * @file pgsql-reg_test_6628_fast_forward_flood-t.cpp
 * @brief Regression #6628: a fast forward client that sends faster than the backend reads must be
 *        held back, and the backend's answers must still reach it.
 *
 * A session is in fast forward during a COPY FROM STDIN, and for its whole life when its user has
 * pgsql_users.fast_forward=1. ProxySQL then queues every client message for the backend. It used to read
 * the client without limit while the backend was behind, so its memory grew with whatever the client sent.
 * And it closed the session when the backend answered while client data was still queued for it ("Data at
 * both ends of a PgSQL data stream").
 *
 * Cases, with the backend held on the COPY's first row by an advisory lock unless said otherwise:
 *  - COPY FROM STDIN: the client must be held back, ProxySQL stay idle and keep answering other sessions
 *    meanwhile, and once the backend is released the COPY complete with every row;
 *  - the same with messages larger than the limit (the limit lowered to 4 MB, 8 MB messages), and with
 *    many tiny messages (one row each): nothing may wait forever on a message it cannot take whole;
 *  - the client vanishes while held back: once the backend catches up, ProxySQL must close its
 *    connection, not leave it waiting in the COPY or pool it;
 *  - the backend is killed while the client is held back: the client must get an error at once;
 *  - fast_forward user, pipelined queries: the client must be held back, then every query be answered;
 *  - fast_forward user, pipelined queries that each raise a NOTICE, backend not held: every answer and
 *    every NOTICE must reach the client;
 *  - fast_forward user, COPY FROM STDIN with an error row after the held one, or cancelled: the client
 *    must get the error, and the connection keep working.
 * "Held back" means the client could not send for a while, after at most the ProxySQL limit, one message
 * and what the kernel buffers hold. Each case runs over plain and TLS client connections, plain and TLS
 * backend connections, and the native and libpq backend protocols (native only where the build has it).
 * Where the build has the fast forward traffic observer (FFTO), the held COPY and the fast_forward user's
 * cases run again with it on, over a plain backend: it reads every message ProxySQL relays.
 * The test infra logs every statement with its parameters; for the test's role the parameters are cut to
 * 64 bytes while it runs, or the pipelined 256 KB ones would add hundreds of MB to the backend's log.
 */

#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using Clock = std::chrono::steady_clock;

static const int BACKEND_HG = 0;
static const std::string TBL = "ff_flood_" + std::to_string(getpid());
static const std::string SEQ = TBL + "_rows";
static const std::string FN = TBL + "_trg";
static const std::string NOTICE_FN = TBL + "_notice";
static const std::string LOCK_KEY = std::to_string(890000000LL + getpid());
// Large rows keep the trigger cheap per byte, so the backend works off a held-back queue quickly.
static const std::string ROW = "x\t" + std::string(4093, 'y') + "\n";
static const std::string TINY_ROW = "x\t" + std::string(61, 'y') + "\n";
static const size_t MSG_BYTES = 256 * 1024;
static const size_t BIG_MSG_BYTES = 8 << 20;
// For the messages larger than the limit: pgsql-threshold_resultset_size, the limit being 4 times it.
static const char* SMALL_THRESHOLD = "1048576";
static const std::string PAYLOAD(MSG_BYTES, 'p');
// Small queries cost the backend more per byte than they cost the client, so a queue builds up. Tiny, as
// the test infra logs every statement with its parameters (log_statement=all).
static const std::string NOTICE_PAYLOAD(16, 'n');
// The client sends these far faster than the backend runs them, so the queue builds well before the cap. It
// also bounds the backend's statement log.
static const long MAX_NOTICE_QUERIES = 5000;
static const int FLOOD_S = 3;
// The client counts as held back once nothing more went out for this long.
static const double HELD_S = 1.5;
// Beyond the ProxySQL limit, the client's send buffer, ProxySQL's receive and send buffers and the
// backend's receive buffer can each hold several MB.
static const long long KERNEL_BUFFERS = 128LL << 20;
// While a client is held back, ProxySQL must not spin, and another session must still get an answer.
static const double MAX_PAUSED_CPU = 30;
static const double PROBE_MAX_S = 1.0;
// Once released, the backend works off what was queued in well under this.
static const int GONE_S = 15;
// A client whose backend was killed gets the error within this.
static const double ERROR_MAX_S = 5.0;
static const int RESULT_TIMEOUT_S = 60;
static const int QUERY_TIMEOUT_S = 10;

static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr open_client_conn(const char* sslmode) {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username << " sslmode=" << sslmode;
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr open_direct_backend() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_server_host << " port=" << cl.pgsql_server_port
	   << " user=" << cl.pgsql_server_username << " password=" << cl.pgsql_server_password
	   << " dbname=postgres sslmode=disable";
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

static bool setVar(PGconn* admin, const std::string& name, const std::string& value) {
	return execSQL(admin, "SET " + name + "='" + value + "'") && execSQL(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static bool setFastForward(PGconn* admin, bool on) {
	return execSQL(admin, std::string("UPDATE pgsql_users SET fast_forward=") + (on ? "1" : "0")
			+ " WHERE username='" + cl.pgsql_username + "'")
		&& execSQL(admin, "LOAD PGSQL USERS TO RUNTIME");
}

// A hostgroup no server is in, used to move the servers out of BACKEND_HG for a moment.
static const int SPARE_HG = 9628;

struct ServerRow { std::string hostname, port, use_ssl; };

static std::vector<ServerRow> readServers(PGconn* admin) {
	std::vector<ServerRow> rows;
	PGresult* res = PQexec(admin,
		("SELECT hostname, port, use_ssl FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(BACKEND_HG)).c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(res); i++)
			rows.push_back(ServerRow { PQgetvalue(res,i,0), PQgetvalue(res,i,1), PQgetvalue(res,i,2) });
	}
	PQclear(res);
	return rows;
}

// Taking the servers out of the hostgroup drops every pooled connection to them, so the next query opens a
// fresh one under the use_ssl and backend protocol set now. use_ssl < 0 puts back each row's own value.
// Moving the rows keeps every other column as it was.
static bool reloadServers(PGconn* admin, const std::vector<ServerRow>& rows, int use_ssl) {
	if (rows.empty()) return false;
	const std::string hg = std::to_string(BACKEND_HG), spare = std::to_string(SPARE_HG);
	bool good = true;
	for (const auto& r : rows)
		good = execSQL(admin, "UPDATE pgsql_servers SET use_ssl=" + (use_ssl < 0 ? r.use_ssl : std::to_string(use_ssl))
			+ " WHERE hostgroup_id=" + hg + " AND hostname='" + r.hostname + "' AND port=" + r.port) && good;
	good = execSQL(admin, "UPDATE pgsql_servers SET hostgroup_id=" + spare + " WHERE hostgroup_id=" + hg)
		&& execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME") && good;
	// Moved back even if a step above failed, so the hostgroup is not left empty.
	good = execSQL(admin, "UPDATE pgsql_servers SET hostgroup_id=" + hg + " WHERE hostgroup_id=" + spare)
		&& execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME") && good;
	usleep(300000);
	return good;
}

static void wait_socket(int fd, bool for_write, int ms) {
	fd_set r, w;
	FD_ZERO(&r); FD_ZERO(&w);
	FD_SET(fd, &r);
	if (for_write) FD_SET(fd, &w);
	timeval tv { ms / 1000, (ms % 1000) * 1000 };
	select(fd + 1, &r, for_write ? &w : nullptr, nullptr, &tv);
}

// Sends what libpq holds, reading meanwhile: the server may be blocked sending to us.
static bool flush_all(PGconn* c, Clock::time_point stop) {
	int f;
	while ((f = PQflush(c)) == 1) {
		if (Clock::now() > stop || PQsocket(c) < 0) return false;
		wait_socket(PQsocket(c), true, 50);
		if (PQconsumeInput(c) == 0) return false;
	}
	return f == 0;
}

struct Flood { long sent = 0; double idle_s = 0; };

// Queues a message at a time, once libpq has sent the previous ones, for FLOOD_S seconds. idle_s is how
// long, at the end, nothing went out.
static Flood flood(PGconn* c, const std::function<bool()>& queue_one) {
	const auto stop = Clock::now() + std::chrono::seconds(FLOOD_S);
	auto last = Clock::now();
	Flood f;
	while (Clock::now() < stop && flush_all(c, stop)) {
		last = Clock::now();
		if (PQconsumeInput(c) == 0 || !queue_one()) break;
		f.sent++;
	}
	f.idle_s = std::chrono::duration<double>(Clock::now() - last).count();
	return f;
}

// Reads results until the command is done. Returns "" on success, "ERR <sqlstate>" on an error,
// "COPY_IN" when a COPY FROM STDIN starts, or "timeout". *val gets the first value of a row result.
static std::string collect(PGconn* c, int timeout_s, std::string* val = nullptr) {
	const auto stop = Clock::now() + std::chrono::seconds(timeout_s);
	std::string out;
	for (;;) {
		if (!flush_all(c, stop)) return Clock::now() > stop ? "timeout" : "ERR connection lost";
		PQconsumeInput(c);
		while (PQisBusy(c) == 0) {
			PGresult* r = PQgetResult(c);
			if (r == nullptr) return out;
			const ExecStatusType st = PQresultStatus(r);
			if (st == PGRES_COPY_IN) {
				PQclear(r);
				return "COPY_IN";
			}
			if (st == PGRES_FATAL_ERROR) {
				const char* s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
				out = std::string("ERR ") + (s ? s : "(no SQLSTATE)");
			} else if (st == PGRES_TUPLES_OK && val && PQntuples(r) > 0) {
				*val = PQgetvalue(r, 0, 0);
			}
			PQclear(r);
		}
		if (PQsocket(c) < 0 || PQstatus(c) == CONNECTION_BAD) return "ERR connection lost";
		if (Clock::now() > stop) return "timeout";
		wait_socket(PQsocket(c), false, 50);
	}
}

// Reads a pipeline's results up to its sync. Returns "" or what went wrong; *answers counts the results
// whose value is 'want'.
static std::string pipeline_results(PGconn* c, const std::string& want, long* answers) {
	const auto stop = Clock::now() + std::chrono::seconds(RESULT_TIMEOUT_S);
	std::string err;
	*answers = 0;
	for (;;) {
		if (!flush_all(c, stop)) return Clock::now() > stop ? "timeout" : "ERR connection lost";
		PQconsumeInput(c);
		int nulls = 0;
		while (PQisBusy(c) == 0 && nulls < 2) {
			PGresult* r = PQgetResult(c);
			if (r == nullptr) { nulls++; continue; }  // the end of one query's results
			nulls = 0;
			const ExecStatusType st = PQresultStatus(r);
			if (st == PGRES_PIPELINE_SYNC) {
				PQclear(r);
				return err;
			}
			if (st == PGRES_TUPLES_OK && PQntuples(r) == 1 && want == PQgetvalue(r, 0, 0)) {
				++*answers;
			} else if (st == PGRES_FATAL_ERROR && err.empty()) {
				const char* s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
				err = std::string("ERR ") + (s ? s : "(no SQLSTATE)");
			} else if (st == PGRES_PIPELINE_ABORTED && err.empty()) {
				err = "aborted";
			}
			PQclear(r);
		}
		if (PQsocket(c) < 0 || PQstatus(c) == CONNECTION_BAD) return "ERR connection lost";
		if (Clock::now() > stop) return "timeout";
		wait_socket(PQsocket(c), false, 50);
	}
}

// Every query in the cases goes through here, with a time limit: a broken build can leave a backend out
// of step, where a blocking PQexec() would wait forever.
static std::string query(PGconn* c, const std::string& q) {
	PQsetnonblocking(c, 1);
	if (PQsendQuery(c, q.c_str()) != 1) return std::string("ERR send: ") + PQerrorMessage(c);
	std::string v;
	const std::string st = collect(c, QUERY_TIMEOUT_S, &v);
	return st.empty() ? v : st;
}

static bool start_copy(PGconn* c) {
	const std::string st = query(c, "COPY " + TBL + " FROM STDIN");
	if (st != "COPY_IN") diag("COPY did not start: %s", st.c_str());
	return st == "COPY_IN";
}

static std::string end_copy(PGconn* c) {
	const auto stop = Clock::now() + std::chrono::seconds(RESULT_TIMEOUT_S);
	int r;
	while ((r = PQputCopyEnd(c, nullptr)) == 0) {
		if (!flush_all(c, stop)) return Clock::now() > stop ? "timeout" : "ERR connection lost";
	}
	if (r < 0) return std::string("ERR copy end: ") + PQerrorMessage(c);
	return collect(c, RESULT_TIMEOUT_S);
}

static std::string copy_msg(const std::string& row, size_t bytes) {
	std::string m;
	while (m.size() + row.size() <= bytes) m += row;
	return m;
}

static bool hold_backend(PGconn* holder) {
	return query(holder, "BEGIN").empty() && query(holder, "SELECT pg_advisory_xact_lock(" + LOCK_KEY + ")").empty();
}

// The backend running this test's COPY ("" when none does).
static std::string copy_pid(PGconn* be) {
	return queryOneValue(be, "SELECT pid FROM pg_stat_activity WHERE query LIKE 'COPY " + TBL + "%' AND state='active' LIMIT 1");
}

static bool wait_for(const std::function<bool()>& cond, int seconds) {
	const auto stop = Clock::now() + std::chrono::seconds(seconds);
	while (Clock::now() < stop) {
		if (cond()) return true;
		usleep(100000);
	}
	return cond();
}

static double seconds_since(Clock::time_point t) {
	return std::chrono::duration<double>(Clock::now() - t).count();
}

// The flood got through to the point where the client was held back, no further than the limit allows,
// with one message past it. 1 check.
static void check_held_back(const std::string& what, const Flood& f, size_t step_bytes, long long limit) {
	const long long pushed = (long long)f.sent * (long long)step_bytes;
	ok(f.idle_s >= HELD_S && pushed <= limit + (long long)step_bytes + KERNEL_BUFFERS,
		"%s: the client is held back (sent %lld MB, then nothing for %.1f s; limit %lld MB + %lld MB of kernel buffers)",
		what.c_str(), pushed >> 20, f.idle_s, limit >> 20, KERNEL_BUFFERS >> 20);
}

// Starts a COPY on c with its first row held by the backend, and floods it with 'puts' copies of msg per
// step. Returns false if the COPY did not start.
static bool start_held_copy(PGconn* c, PGconn* holder, const std::string& msg, int puts, Flood* f) {
	if (!hold_backend(holder)) {
		diag("could not hold the backend");
		return false;
	}
	if (PQstatus(c) != CONNECTION_OK || !start_copy(c)) {
		query(holder, "COMMIT");
		return false;
	}
	PQputCopyData(c, "S\ts\n", 4);
	*f = flood(c, [&]() {
		for (int i = 0; i < puts; i++)
			if (PQputCopyData(c, msg.data(), (int)msg.size()) != 1) return false;
		return true;
	});
	return true;
}

// A held COPY FROM STDIN, flooded with 'puts' copies of msg per step. 2 checks, 4 with 'cost': ProxySQL's CPU
// and another session's answer time while the client is held back.
static void copy_held_case(const std::string& what, const char* sslmode, PGconn* holder, long long limit,
	const std::string& msg, int puts, bool cost) {
	PGConnPtr c = open_client_conn(sslmode);
	query(holder, "SELECT setval('" + SEQ + "', 1, false)");
	Flood f;
	std::string got = "COPY did not start";
	double cpu = -1, probe_s = -1;
	std::string probe = "not run";
	if (start_held_copy(c.get(), holder, msg, puts, &f)) {
		if (cost) {
			if (get_proxysql_cpu_usage(cl, cpu, 5) != EXIT_SUCCESS) cpu = -1;
			const auto t0 = Clock::now();
			PGConnPtr p = open_client_conn("disable");
			probe = query(p.get(), "SELECT 1");
			probe_s = seconds_since(t0);
		}
		query(holder, "COMMIT");
		got = end_copy(c.get());
	}
	const long rows_per_msg = std::count(msg.begin(), msg.end(), '\n');
	const long expected = f.sent > 0 ? 1 + f.sent * puts * rows_per_msg : 0;
	const std::string counted = query(holder, "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM " + SEQ);
	check_held_back(what, f, msg.size() * puts, limit);
	if (cost) {
		ok(cpu >= 0 && cpu < MAX_PAUSED_CPU, "%s: ProxySQL stays idle while the client is held back (CPU %.1f%%, below %.0f%%)",
			what.c_str(), cpu, MAX_PAUSED_CPU);
		ok(probe == "1" && probe_s < PROBE_MAX_S, "%s: another session gets an answer meanwhile (SELECT 1 got '%s' in %.2f s)",
			what.c_str(), probe.c_str(), probe_s);
	}
	ok(got.empty() && counted == std::to_string(expected), "%s: once the backend is released the COPY completes"
		" with every row (got '%s'; rows sent %ld, counted %s)", what.c_str(), got.c_str(), expected, counted.c_str());
}

// The client vanishes, without a word, while held back. 2 checks.
static void vanish_case(const std::string& what, const char* sslmode, PGconn* holder, PGconn* be) {
	const std::string w = what + ", client vanishes while held back";
	PGConnPtr c = open_client_conn(sslmode);
	const std::string msg = copy_msg(ROW, MSG_BYTES);
	Flood f;
	std::string pid;
	if (start_held_copy(c.get(), holder, msg, 1, &f)) {
		pid = copy_pid(be);
		shutdown(PQsocket(c.get()), SHUT_RDWR);
		c.reset();
		query(holder, "COMMIT");
	}
	// The backend itself must go: a COPY ended but its connection kept, or pooled, still has this pid.
	const bool gone = !pid.empty() && wait_for([&]() {
		return queryOneValue(be, "SELECT count(*) FROM pg_stat_activity WHERE pid=" + pid) == "0"; }, GONE_S);
	ok(gone, "%s: once the backend catches up, its connection is closed (backend pid %s; watched for %d s)",
		w.c_str(), pid.empty() ? "not found" : pid.c_str(), GONE_S);
	PGConnPtr n = open_client_conn(sslmode);
	const std::string v = query(n.get(), "SELECT 1");
	ok(v == "1", "%s: a new session works (SELECT 1 got '%s')", w.c_str(), v.c_str());
}

// The backend is killed while the client is held back. 2 checks.
static void backend_killed_case(const std::string& what, const char* sslmode, PGconn* holder, PGconn* be) {
	const std::string w = what + ", backend killed while the client is held back";
	PGConnPtr c = open_client_conn(sslmode);
	const std::string msg = copy_msg(ROW, MSG_BYTES);
	Flood f;
	std::string got = "COPY did not start", pid;
	double took = -1;
	if (start_held_copy(c.get(), holder, msg, 1, &f)) {
		pid = copy_pid(be);
		const auto t0 = Clock::now();
		if (!pid.empty()) queryOneValue(be, "SELECT pg_terminate_backend(" + pid + ")");
		got = end_copy(c.get());
		took = seconds_since(t0);
		query(holder, "COMMIT");
	}
	ok(!pid.empty() && got.rfind("ERR", 0) == 0 && took < ERROR_MAX_S, "%s: the client gets an error at once"
		" (got '%s' in %.1f s, backend pid %s)", w.c_str(), got.c_str(), took, pid.empty() ? "not found" : pid.c_str());
	PGConnPtr n = open_client_conn(sslmode);
	const std::string v = query(n.get(), "SELECT 1");
	ok(v == "1", "%s: a new session works (SELECT 1 got '%s')", w.c_str(), v.c_str());
}

// Pipelined queries on a fast_forward connection, the first held by the backend. 3 checks.
static void pipeline_held_case(const std::string& what, const char* sslmode, PGconn* holder, long long limit) {
	const std::string w = what + ", pipeline with the backend held";
	PGConnPtr c = open_client_conn(sslmode);
	const bool held = hold_backend(holder);
	Flood f;
	long answers = 0;
	std::string got = "no pipeline";
	PQsetnonblocking(c.get(), 1);
	if (held && PQstatus(c.get()) == CONNECTION_OK && PQenterPipelineMode(c.get()) == 1) {
		const std::string lock_q = "SELECT pg_advisory_lock(" + LOCK_KEY + "), pg_advisory_unlock(" + LOCK_KEY + ")";
		PQsendQueryParams(c.get(), lock_q.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0);
		const char* vals[1] = { PAYLOAD.c_str() };
		f = flood(c.get(), [&]() {
			return PQsendQueryParams(c.get(), "SELECT length($1)", 1, nullptr, vals, nullptr, nullptr, 0) == 1;
		});
		query(holder, "COMMIT");
		got = PQpipelineSync(c.get()) == 1 ? pipeline_results(c.get(), std::to_string(PAYLOAD.size()), &answers) : "no sync";
		if (got.empty() && PQexitPipelineMode(c.get()) != 1) got = std::string("exit pipeline: ") + PQerrorMessage(c.get());
	} else if (held) {
		query(holder, "COMMIT");
	}
	check_held_back(w, f, PAYLOAD.size(), limit);
	ok(got.empty() && answers == f.sent, "%s: every query is answered once the backend is released"
		" (%ld of %ld, result '%s')", w.c_str(), answers, f.sent, got.c_str());
	const std::string v = query(c.get(), "SELECT 1");
	ok(v == "1", "%s: the connection still works (SELECT 1 got '%s')", w.c_str(), v.c_str());
}

static void count_notice(void* arg, const char* message) {
	if (strstr(message, "ff flood notice")) ++*static_cast<long*>(arg);
}

// Pipelined queries on a fast_forward connection, each raising a NOTICE while the client keeps sending.
// 2 checks.
static void pipeline_notice_case(const std::string& what, const char* sslmode) {
	const std::string w = what + ", pipeline with a NOTICE per query";
	PGConnPtr c = open_client_conn(sslmode);
	long notices = 0, answers = 0;
	PQsetNoticeProcessor(c.get(), count_notice, &notices);
	Flood f;
	std::string got = "no pipeline";
	PQsetnonblocking(c.get(), 1);
	if (PQstatus(c.get()) == CONNECTION_OK && PQenterPipelineMode(c.get()) == 1) {
		const std::string q = "SELECT " + NOTICE_FN + "($1)";
		const char* vals[1] = { NOTICE_PAYLOAD.c_str() };
		long queued = 0;
		f = flood(c.get(), [&]() {
			return queued++ < MAX_NOTICE_QUERIES && PQsendQueryParams(c.get(), q.c_str(), 1, nullptr, vals, nullptr, nullptr, 0) == 1;
		});
		got = PQpipelineSync(c.get()) == 1 ? pipeline_results(c.get(), std::to_string(NOTICE_PAYLOAD.size()), &answers) : "no sync";
		if (got.empty() && PQexitPipelineMode(c.get()) != 1) got = std::string("exit pipeline: ") + PQerrorMessage(c.get());
	}
	ok(got.empty() && answers == f.sent && notices == f.sent, "%s: every answer and NOTICE reaches the client"
		" (sent %ld, answers %ld, NOTICEs %ld, result '%s')", w.c_str(), f.sent, answers, notices, got.c_str());
	const std::string v = query(c.get(), "SELECT 1");
	ok(v == "1", "%s: the connection still works (SELECT 1 got '%s')", w.c_str(), v.c_str());
}

// A COPY FROM STDIN on a fast_forward connection, with an error row. The backend is held on the row before
// it while the client sends, so the error comes with client data still queued. 2 checks.
static void copy_error_case(const std::string& what, const char* sslmode, PGconn* holder) {
	const std::string w = what + ", COPY with an error row";
	PGConnPtr c = open_client_conn(sslmode);
	const bool held = hold_backend(holder);
	std::string got = "COPY did not start";
	if (held && PQstatus(c.get()) == CONNECTION_OK && start_copy(c.get())) {
		const std::string msg = copy_msg(ROW, MSG_BYTES);
		PQputCopyData(c.get(), "S\ts\nE\te\n", 8);
		flood(c.get(), [&]() { return PQputCopyData(c.get(), msg.data(), (int)msg.size()) == 1; });
		query(holder, "COMMIT");
		got = end_copy(c.get());
	} else if (held) {
		query(holder, "COMMIT");
	}
	ok(got == "ERR P0001", "%s: the client gets the backend's error (expected ERR P0001, got %s)",
		w.c_str(), got.c_str());
	const std::string v = query(c.get(), "SELECT 1");
	ok(v == "1", "%s: the connection still works (SELECT 1 got '%s')", w.c_str(), v.c_str());
}

// A COPY FROM STDIN on a fast_forward connection, cancelled while the client is held back. 2 checks.
static void copy_cancel_case(const std::string& what, const char* sslmode, PGconn* holder) {
	const std::string w = what + ", COPY cancelled while the client is held back";
	PGConnPtr c = open_client_conn(sslmode);
	const std::string msg = copy_msg(ROW, MSG_BYTES);
	Flood f;
	std::string got = "COPY did not start";
	if (start_held_copy(c.get(), holder, msg, 1, &f)) {
		char err[256] = "";
		PGcancel* cn = PQgetCancel(c.get());
		if (cn == nullptr || PQcancel(cn, err, sizeof(err)) == 0) diag("%s: PQcancel failed: %s", w.c_str(), err);
		if (cn) PQfreeCancel(cn);
		got = end_copy(c.get());
		query(holder, "COMMIT");
	}
	ok(got == "ERR 57014", "%s: the client gets the cancel (expected ERR 57014, got %s)", w.c_str(), got.c_str());
	const std::string v = query(c.get(), "SELECT 1");
	ok(v == "1", "%s: the connection still works (SELECT 1 got '%s')", w.c_str(), v.c_str());
}

// Backend protocol of the pooled connections, as ProxySQL records it.
static std::string poolMode(PGconn* admin) {
	const std::string info = queryOneValue(admin, std::string("SELECT group_concat(pgsql_info) FROM stats_pgsql_free_connections"
		" WHERE user='") + cl.pgsql_username + "'");
	const bool native = info.find("\"native_mode\":true") != std::string::npos;
	const bool libpq = info.find("\"native_mode\":false") != std::string::npos;
	return native && !libpq ? "native" : libpq && !native ? "libpq" : "(" + info + ")";
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
	// 1 + per protocol and backend TLS: 1 + per client sslmode: 4 + 2 + 2 + 2 + 2 (COPY) + 3 + 2 + 2 + 2
	// (fast_forward user)
	const bool ffto_supported = queryOneValue(admin.get(),
		"SELECT count(*) FROM global_variables WHERE variable_name='pgsql-ffto_enabled'") == "1";
	// With FFTO, per protocol and client sslmode: 2 (COPY) + 3 + 2 + 2 + 2 (fast_forward user)
	plan(1 + (int)protocols.size() * 2 * (1 + 2 * 21) + (ffto_supported ? (int)protocols.size() * 2 * 11 : 0));

	const std::vector<ServerRow> saved = readServers(admin.get());
	if (saved.empty()) BAIL_OUT("no servers in hostgroup %d to work with", BACKEND_HG);
	const std::string saved_native = queryOneValue(admin.get(),
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	const std::string threshold = queryOneValue(admin.get(),
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-threshold_resultset_size'");
	const long long limit = 4 * std::atoll(threshold.c_str());
	const long long small_limit = 4 * std::atoll(SMALL_THRESHOLD);
	auto be = open_direct_backend();
	if (PQstatus(be.get()) != CONNECTION_OK)
		BAIL_OUT("direct backend connection failed: %s", PQerrorMessage(be.get()));
	const std::string role_log = std::string("ALTER ROLE ") + cl.pgsql_username;
	execSQL(be.get(), role_log + " SET log_parameter_max_length = 64");

	// Opened before the user is switched to fast_forward, so it stays a normal session: it creates the
	// objects and holds the advisory lock. The sink keeps nothing: a trigger counts each row in a sequence
	// and drops it. Row 'S' waits for the lock, row 'E' raises an error.
	setFastForward(admin.get(), false);
	auto setup = open_client_conn("disable");
	if (PQstatus(setup.get()) != CONNECTION_OK)
		BAIL_OUT("setup connection failed: %s", PQerrorMessage(setup.get()));
	const bool setup_ok = execSQL(setup.get(), "DROP TABLE IF EXISTS " + TBL)
		&& execSQL(setup.get(), "DROP SEQUENCE IF EXISTS " + SEQ)
		&& execSQL(setup.get(), "CREATE TABLE " + TBL + " (a text, b text)")
		&& execSQL(setup.get(), "CREATE SEQUENCE " + SEQ)
		&& execSQL(setup.get(), "CREATE OR REPLACE FUNCTION " + FN + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN"
			" IF NEW.a = 'S' THEN PERFORM pg_advisory_lock(" + LOCK_KEY + "); PERFORM pg_advisory_unlock(" + LOCK_KEY + "); END IF;"
			" IF NEW.a = 'E' THEN RAISE EXCEPTION 'ff flood error'; END IF;"
			" PERFORM nextval('" + SEQ + "'); RETURN NULL; END $$")
		&& execSQL(setup.get(), "CREATE TRIGGER " + FN + " BEFORE INSERT ON " + TBL
			+ " FOR EACH ROW EXECUTE FUNCTION " + FN + "()")
		&& execSQL(setup.get(), "CREATE OR REPLACE FUNCTION " + NOTICE_FN + "(t text) RETURNS int LANGUAGE plpgsql AS $$"
			" BEGIN RAISE NOTICE 'ff flood notice'; RETURN length(t); END $$");
	ok(setup_ok && limit > 0, "COPY sink and NOTICE function created; ProxySQL limit %lld MB", limit >> 20);

	for (const std::string& protocol : protocols) {
		if (native_supported) setVar(admin.get(), "pgsql-use_native_backend_protocol", protocol == "native" ? "true" : "false");
		for (int use_ssl : { 0, 1 }) {
			const std::string phase = protocol + (use_ssl ? ", backend TLS" : ", backend plain");
			diag("---- %s ----", phase.c_str());
			bool reloaded = reloadServers(admin.get(), saved, use_ssl);
			// pg_backend_pid() is answered by ProxySQL itself: find this backend by the text of the query.
			std::string leg;
			{
				auto probe = open_client_conn("disable");
				leg = queryOneValue(probe.get(), "SELECT s.ssl FROM pg_stat_ssl s JOIN pg_stat_activity a ON s.pid = a.pid"
					" WHERE a.state = 'active' AND a.query LIKE '%ff_flood_leg_marker%' LIMIT 1");
			}
			const std::string pm = poolMode(admin.get());
			ok(reloaded && leg == (use_ssl ? "t" : "f") && pm == protocol, "%s: backend connections are %s and %s"
				" (pg_stat_ssl says '%s', pool says '%s')", phase.c_str(), use_ssl ? "encrypted" : "plain",
				protocol.c_str(), leg.c_str(), pm.c_str());
			for (const char* sslmode : { "disable", "require" }) {
				const std::string what = phase + ", client sslmode=" + sslmode + ", COPY";
				copy_held_case(what + " with the backend held", sslmode, setup.get(), limit, copy_msg(ROW, MSG_BYTES), 1, true);
				setVar(admin.get(), "pgsql-threshold_resultset_size", SMALL_THRESHOLD);
				copy_held_case(what + " with 8 MB messages and a 4 MB limit", sslmode, setup.get(), small_limit,
					copy_msg(ROW, BIG_MSG_BYTES), 1, false);
				setVar(admin.get(), "pgsql-threshold_resultset_size", threshold);
				copy_held_case(what + " with one row per message", sslmode, setup.get(), limit, TINY_ROW, 1024, false);
				vanish_case(what, sslmode, setup.get(), be.get());
				backend_killed_case(what, sslmode, setup.get(), be.get());
			}
			setFastForward(admin.get(), true);
			for (const char* sslmode : { "disable", "require" }) {
				const std::string what = phase + ", client sslmode=" + sslmode + ", fast_forward user";
				pipeline_held_case(what, sslmode, setup.get(), limit);
				pipeline_notice_case(what, sslmode);
				copy_error_case(what, sslmode, setup.get());
				copy_cancel_case(what, sslmode, setup.get());
			}
			setFastForward(admin.get(), false);
		}
	}

	if (ffto_supported) {
		const std::string saved_ffto = queryOneValue(admin.get(),
			"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-ffto_enabled'");
		setVar(admin.get(), "pgsql-ffto_enabled", "true");
		for (const std::string& protocol : protocols) {
			if (native_supported) setVar(admin.get(), "pgsql-use_native_backend_protocol", protocol == "native" ? "true" : "false");
			reloadServers(admin.get(), saved, 0);
			const std::string phase = protocol + ", backend plain, FFTO on";
			diag("---- %s ----", phase.c_str());
			for (const char* sslmode : { "disable", "require" }) {
				copy_held_case(phase + ", client sslmode=" + sslmode + ", COPY with the backend held", sslmode, setup.get(),
					limit, copy_msg(ROW, MSG_BYTES), 1, false);
			}
			setFastForward(admin.get(), true);
			for (const char* sslmode : { "disable", "require" }) {
				const std::string what = phase + ", client sslmode=" + sslmode + ", fast_forward user";
				pipeline_held_case(what, sslmode, setup.get(), limit);
				pipeline_notice_case(what, sslmode);
				copy_error_case(what, sslmode, setup.get());
				copy_cancel_case(what, sslmode, setup.get());
			}
			setFastForward(admin.get(), false);
		}
		setVar(admin.get(), "pgsql-ffto_enabled", saved_ffto.empty() ? "false" : saved_ffto);
	}

	if (native_supported && !saved_native.empty()) setVar(admin.get(), "pgsql-use_native_backend_protocol", saved_native);
	reloadServers(admin.get(), saved, -1);
	query(setup.get(), "DROP TABLE IF EXISTS " + TBL);
	query(setup.get(), "DROP FUNCTION IF EXISTS " + FN + "()");
	query(setup.get(), "DROP FUNCTION IF EXISTS " + NOTICE_FN + "(text)");
	query(setup.get(), "DROP SEQUENCE IF EXISTS " + SEQ);
	execSQL(be.get(), role_log + " RESET log_parameter_max_length");

	return exit_status();
}
