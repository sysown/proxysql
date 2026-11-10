/**
 * @file pgsql-extended_query_flush-t.cpp
 * @brief A client Flush ('H') in the PostgreSQL extended query protocol behaves as in PostgreSQL.
 *
 * A Flush asks the server for the replies to everything sent so far, without ending the group of
 * messages: no ReadyForQuery, the implicit transaction stays open, portals stay alive, and the
 * client ends the group later with its own Sync. postgres.js sends Parse + Describe + Flush for
 * every query with an untyped parameter, node-postgres cursors page a portal with
 * Execute(n) + Flush, and libpq pipeline mode has PQsendFlushRequest().
 *
 * Every case runs in the three backend modes:
 *   - LIBPQ: pgsql-use_native_backend_protocol off;
 *   - NATIVE: on, so a group goes to the backend in batches;
 *   - NATIVE_UNBATCHED: on, but the client sets an untracked startup option, which keeps the
 *     session's first group one message at a time.
 * Pooled connections keep the mode they were opened in, so the pool is emptied after every switch,
 * and each mode must land on a backend pid the previous mode did not use.
 *
 * Expected reply sequences were taken from PostgreSQL 17 directly
 * (docs/superpowers/specs/2026-10-26-pgsql-client-flush-design.md, section 2).
 * Replies are read until the socket stays quiet; a closed socket fails the case.
 * Configuration is only loaded to runtime, never saved to disk.
 */
#include <cerrno>
#include <chrono>
#include <array>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <functional>
#include <memory>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <vector>
#include <unistd.h>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // MUST precede utils.h (mysql.h clash)
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using Msgs = std::vector<std::pair<char, std::vector<uint8_t>>>;
CommandLine cl;

static const int HG = 0;
static const int QUIET_MS = 300;

enum class Mode { LIBPQ, NATIVE, NATIVE_UNBATCHED };

static const char* mode_name(Mode m) {
	switch (m) {
	case Mode::LIBPQ: return "libpq";
	case Mode::NATIVE: return "native";
	default: return "native-unbatched";
	}
}

static PGConnPtr open_conn(const char* host, int port, const char* user, const char* pass, const char* db) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool exec(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	const bool good = (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
	if (!good) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return good;
}

static std::string scalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}

// Direct connection to PostgreSQL, in the database the client uses (named after the user).
static PGConnPtr backend() {
	return open_conn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username,
		cl.pgsql_server_password, cl.pgsql_username);
}

// Empties the pool: pooled connections keep the protocol they were opened with, so after a mode
// switch they must go, or the next mode quietly reuses them.
static void reset_pool(PGconn* admin) {
	const std::string hg = std::to_string(HG);
	if (!exec(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)
		|| !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not take hostgroup %s down", hg.c_str());
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	std::string n;
	while (std::chrono::steady_clock::now() < deadline) {
		n = scalar(admin,
			"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + hg);
		if (!n.empty() && atoi(n.c_str()) == 0) break;
		usleep(100000);
	}
	// A connection left in the pool keeps the previous mode, and the cases that count on an empty
	// pool would run on it.
	if (n.empty() || atoi(n.c_str()) != 0)
		BAIL_OUT("hostgroup %s pool did not empty in 10s (%s connections left)", hg.c_str(), n.c_str());
	if (!exec(admin, "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=" + hg)
		|| !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not bring hostgroup %s back", hg.c_str());
	usleep(200000);
}

static bool set_mode(PGconn* admin, Mode m) {
	const std::string want = (m == Mode::LIBPQ) ? "false" : "true";
	if (!exec(admin, "SET pgsql-use_native_backend_protocol='" + want + "'")
		|| !exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME"))
		return false;
	const std::string got = scalar(admin, "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-use_native_backend_protocol'");
	reset_pool(admin);
	return got == want;
}

static std::unique_ptr<PgConnection> client(Mode m) {
	auto c = std::make_unique<PgConnection>(5000);
	// An untracked startup option keeps the session's first group one message at a time.
	if (m == Mode::NATIVE_UNBATCHED) c->setOptions("-c work_mem=4MB");
	c->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
	return c;
}

static std::string field(const std::vector<uint8_t>& b, char code) {
	size_t i = 0;
	while (i < b.size() && b[i] != 0) {
		const char k = (char)b[i++];
		std::string v;
		while (i < b.size() && b[i] != 0) v += (char)b[i++];
		i++;
		if (k == code) return v;
	}
	return "";
}

// Reply messages as space-separated tokens: Z(status), E(sqlstate), C(tag), the type byte otherwise.
// ParameterStatus and NoticeResponse are left out: they may come at any point and answer nothing.
static std::string tokens(const Msgs& msgs) {
	std::string out;
	for (const auto& m : msgs) {
		std::string t;
		switch (m.first) {
		case 'S': case 'N': continue;
		case 'Z': t = std::string("Z(") + (m.second.empty() ? '?' : (char)m.second[0]) + ")"; break;
		case 'E': t = "E(" + field(m.second, 'C') + ")"; break;
		case 'C': t = "C(" + std::string(m.second.begin(), m.second.end() - (m.second.empty() ? 0 : 1)) + ")"; break;
		default: t = std::string(1, m.first);
		}
		if (!out.empty()) out += ' ';
		out += t;
	}
	return out;
}

// Sends, then returns the replies that arrive before the socket goes quiet. A connection that is
// closed or broken is reported as such, never as "no reply".
static std::string run(PgConnection& c, const std::function<void()>& send, int quiet_ms = QUIET_MS) {
	try {
		send();
		return tokens(c.readUntilQuiet(quiet_ms));
	} catch (const PgException& e) {
		return std::string("CLOSED:") + e.what();
	}
}

// The backend pid of the connection this session runs on. The bare pg_backend_pid() is answered by
// ProxySQL itself, so it is read from pg_stat_activity.
static std::string proxy_pid(PgConnection& c) {
	try {
		c.sendQuery("SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()");
		std::string pid;
		for (const auto& m : c.readUntilQuiet(QUIET_MS)) {
			if (m.first == 'D' && m.second.size() > 6) {
				const auto& b = m.second;
				const int32_t len = (b[2] << 24) | (b[3] << 16) | (b[4] << 8) | b[5];
				if (len > 0 && (size_t)(6 + len) <= b.size()) pid.assign(b.begin() + 6, b.begin() + 6 + len);
			}
		}
		return pid;
	} catch (const PgException&) {
		return "";
	}
}

// Statement text new to this run: ProxySQL answers a Parse of text it already knows by itself, which
// changes the reply path under test.
static std::string uniq() {
	static long n = 0;
	return "/*flush-" + std::to_string((long)time(nullptr)) + "-" + std::to_string(++n) + "*/ ";
}

static void check(const std::string& got, const std::string& want, const char* what, Mode m, bool txn) {
	ok(got == want, "%s [%s%s]: got '%s', expected '%s'", what, mode_name(m), txn ? ", in txn" : "",
		got.c_str(), want.c_str());
}

// ===== Bounded client diagnostic markers (opt-in, FLUSH_DIAG_PASSIVE exactly "1"). =====
// The marker is a TAP comment with one strict fixed-key JSON object. It carries integers and a
// bounded TYPE list only: no SQL, payload, values, addresses, credentials or pointers.
static const char* const DIAG_PREFIX = "# PGFLUSH_DIAG ";
static const int DIAG_MAX_RECORDS = 4096;
static const int DIAG_MAX_RECORD_BYTES = 512;
static const int DIAG_MAX_TYPES = 64;
static const size_t DIAG_MAX_EVENTS = 256;

static std::string diag_json(int seq, int stage, int event, int logical_mode, int effective_mode,
		int clock_id, long long t0_us, long long t_us, int local_port, long long ret, int err,
		int revents, int poll_ms, long long bytes, long long msgs, const std::vector<int>& types,
		int types_total, int types_trunc, int invalid, int phase,
		long long c0, long long c1, long long c2, long long c3);
static bool diag_write_line(const std::string& line) noexcept;

enum {
	DIAG_EV_START = 1,
	DIAG_EV_STAGE = 2,
	DIAG_EV_CACHE = 3,
	DIAG_EV_PORTAL = 4,
	DIAG_EV_ASSERT = 5,
	DIAG_EV_PEEK = 6,
	DIAG_EV_CAP = 7,
	DIAG_EV_IO_SEND = 10,
	DIAG_EV_IO_POLL = 11,
	DIAG_EV_IO_FRAME = 12,
	DIAG_EV_FINAL = 13
};

enum {
	DIAG_ST_START = 0,
	DIAG_ST_RELEASE_CREATE = 1,
	DIAG_ST_ROW11_VAR_GOOD = 2,
	DIAG_ST_GROUP_LOCK_ROUTE = 3,
	DIAG_ST_ROW11_SELECT42 = 4,
	DIAG_ST_ROW15_LOCAL_SET = 5,
	DIAG_ST_ROW15_CACHE_BES = 6,
	DIAG_ST_ROW11_NATIVE_PORTAL = 7,
	DIAG_ST_ROW15_ASSERT = 8
};

enum {
	DIAG_PH_NONE = 0,
	DIAG_PH_PEEK_POSITIVE = 1,
	DIAG_PH_DEADLINE = 2,
	DIAG_PH_POLL_ERROR = 3,
	DIAG_PH_SOCKET_INVALID = 4,
	DIAG_PH_SOCKET_ERROR = 5,
	DIAG_PH_CLOSED = 6,
	DIAG_PH_RECV_ERROR = 7,
	DIAG_PH_UNEXPECTED = 8,
	DIAG_PH_PEEK_AFTER_DEADLINE = 9,
	DIAG_PH_NO_SEND_TIMESTAMP = 10
};

static bool diag_enabled() noexcept {
	static const bool enabled = [] {
		const int saved_errno = errno;
		const char* v = getenv("FLUSH_DIAG_PASSIVE");
		const bool result = v != nullptr && v[0] == '1' && v[1] == '\0';
		errno = saved_errno;
		return result;
	}();
	return enabled;
}

static int diag_pick_clock() noexcept {
	static const int clock_id = [] {
		const int saved_errno = errno;
		int result = static_cast<int>(CLOCK_MONOTONIC);
#ifdef CLOCK_MONOTONIC_RAW
		struct timespec ts;
		if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0)
			result = static_cast<int>(CLOCK_MONOTONIC_RAW);
#endif
		errno = saved_errno;
		return result;
	}();
	return clock_id;
}

static int diag_seq = 0;
static bool diag_invalid = false;
static bool diag_capped = false;
static bool diag_terminal_emitted = false;
static bool diag_final_emitted = false;
static bool diag_output_failed = false;

// Fixed valid numeric-only fallback statuses (no allocation, no recursion). The prefix and
// schema are identical to the normal records; parent validation applies unchanged.
static const char DIAG_FALLBACK_STATUS[] =
	"# PGFLUSH_DIAG {\"v\":1,\"q\":4096,\"s\":0,\"e\":7,\"l\":0,\"m\":0,\"c\":1,"
	"\"a\":0,\"t\":0,\"p\":0,\"r\":0,\"x\":0,\"R\":0,\"P\":0,\"b\":0,\"n\":0,"
	"\"u\":4096,\"k\":512,\"y\":[],\"T\":0,\"N\":0,\"I\":1,\"h\":0,"
	"\"C0\":0,\"C1\":0,\"C2\":0,\"C3\":0}";
static const char DIAG_FALLBACK_FINAL[] =
	"# PGFLUSH_DIAG {\"v\":1,\"q\":4096,\"s\":0,\"e\":13,\"l\":0,\"m\":0,\"c\":1,"
	"\"a\":0,\"t\":0,\"p\":0,\"r\":0,\"x\":0,\"R\":0,\"P\":0,\"b\":0,\"n\":0,"
	"\"u\":4096,\"k\":512,\"y\":[],\"T\":0,\"N\":0,\"I\":1,\"h\":0,"
	"\"C0\":1,\"C1\":1,\"C2\":1,\"C3\":0}";

static bool diag_write_raw(const char* text) noexcept {
	const int saved_errno = errno;
	if (text == nullptr || strlen(text) > static_cast<size_t>(DIAG_MAX_RECORD_BYTES)) {
		diag_output_failed = true;
		errno = saved_errno;
		return false;
	}
	const bool ok = fputs(text, stdout) >= 0 && fputc('\n', stdout) != EOF && fflush(stdout) == 0;
	if (!ok) diag_output_failed = true;
	errno = saved_errno;
	return ok;
}

static void diag_fallback_status() noexcept {
	if (diag_terminal_emitted) return;
	diag_capped = true;
	diag_invalid = true;
	if (diag_write_raw(DIAG_FALLBACK_STATUS)) diag_terminal_emitted = true;
}

static void diag_emit_final() noexcept {
	if (!diag_enabled() || diag_final_emitted) return;
	diag_final_emitted = true;
	const int saved_errno = errno;
	try {
		const int seq = diag_seq < DIAG_MAX_RECORDS ? diag_seq + 1 : DIAG_MAX_RECORDS;
		const int inv = (diag_invalid || diag_capped || diag_output_failed) ? 1 : 0;
		std::string line = DIAG_PREFIX + diag_json(seq, DIAG_ST_START, DIAG_EV_FINAL, 0, 0,
			diag_pick_clock(), 0, 0, 0, 0, 0, 0, 0, 0, 0, {}, 0, 0, inv, DIAG_PH_NONE,
			1, inv, 1, 0);
		if (diag_write_line(line)) {
			diag_seq = seq;
			errno = saved_errno;
			return;
		}
	} catch (...) {
		diag_invalid = true;
	}
	if (!diag_write_raw(DIAG_FALLBACK_FINAL)) diag_output_failed = true;
	errno = saved_errno;
}

static std::string diag_json(int seq, int stage, int event, int logical_mode, int effective_mode,
		int clock_id, long long t0_us, long long t_us, int local_port, long long ret, int err,
		int revents, int poll_ms, long long bytes, long long msgs, const std::vector<int>& types,
		int types_total, int types_trunc, int invalid, int phase,
		long long c0 = 0, long long c1 = 0, long long c2 = 0, long long c3 = 0) {
	std::string s;
	s.reserve(512);
	s += "{\"v\":1,\"q\":"; s += std::to_string(seq);
	s += ",\"s\":"; s += std::to_string(stage);
	s += ",\"e\":"; s += std::to_string(event);
	s += ",\"l\":"; s += std::to_string(logical_mode);
	s += ",\"m\":"; s += std::to_string(effective_mode);
	s += ",\"c\":"; s += std::to_string(clock_id);
	s += ",\"a\":"; s += std::to_string(t0_us);
	s += ",\"t\":"; s += std::to_string(t_us);
	s += ",\"p\":"; s += std::to_string(local_port);
	s += ",\"r\":"; s += std::to_string(ret);
	s += ",\"x\":"; s += std::to_string(err);
	s += ",\"R\":"; s += std::to_string(revents);
	s += ",\"P\":"; s += std::to_string(poll_ms);
	s += ",\"b\":"; s += std::to_string(bytes);
	s += ",\"n\":"; s += std::to_string(msgs);
	s += ",\"u\":"; s += std::to_string(DIAG_MAX_RECORDS);
	s += ",\"k\":"; s += std::to_string(DIAG_MAX_RECORD_BYTES);
	s += ",\"y\":[";
	for (size_t i = 0; i < types.size(); i++) {
		if (i) s += ',';
		s += std::to_string(types[i]);
	}
	s += "],\"T\":"; s += std::to_string(types_total);
	s += ",\"N\":"; s += std::to_string(types_trunc);
	s += ",\"I\":"; s += std::to_string(invalid);
	s += ",\"h\":"; s += std::to_string(phase);
	s += ",\"C0\":"; s += std::to_string(c0);
	s += ",\"C1\":"; s += std::to_string(c1);
	s += ",\"C2\":"; s += std::to_string(c2);
	s += ",\"C3\":"; s += std::to_string(c3);
	s += '}';
	return s;
}

static bool diag_write_line(const std::string& line) noexcept {
	const int saved_errno = errno;
	if (line.size() > static_cast<size_t>(DIAG_MAX_RECORD_BYTES)) {
		diag_invalid = true;
		errno = saved_errno;
		return false;
	}
	const bool ok = fputs(line.c_str(), stdout) >= 0 && fputc('\n', stdout) != EOF && fflush(stdout) == 0;
	if (!ok) {
		diag_invalid = true;
		diag_output_failed = true;
	}
	errno = saved_errno;
	return ok;
}

static void diag_emit_cap() noexcept {
	if (!diag_enabled() || diag_terminal_emitted) return;
	const int saved_errno = errno;
	try {
		const int seq = diag_seq < DIAG_MAX_RECORDS ? diag_seq + 1 : DIAG_MAX_RECORDS;
		std::string line = DIAG_PREFIX + diag_json(seq, DIAG_ST_START, DIAG_EV_CAP, 0, 0,
			diag_pick_clock(), 0, 0, 0, 0, 0, 0, 0, 0, 0, {}, 0, 0, 1, DIAG_PH_NONE);
		if (diag_write_line(line)) {
			diag_seq = seq;
			diag_capped = true;
			diag_terminal_emitted = true;
			errno = saved_errno;
			return;
		}
	} catch (...) {
		diag_invalid = true;
	}
	diag_fallback_status();
	errno = saved_errno;
}

static void diag_emit(int stage, int event, int logical_mode, int effective_mode, int clock_id,
		long long t0_us, long long t_us, int local_port, long long ret, int err, int revents,
		int poll_ms, long long bytes, long long msgs, const std::vector<int>& types,
		int types_total, int types_trunc, int invalid, int phase,
		long long c0 = 0, long long c1 = 0, long long c2 = 0, long long c3 = 0) noexcept {
	if (!diag_enabled() || diag_capped) return;
	const int saved_errno = errno;
	try {
		if (diag_seq >= DIAG_MAX_RECORDS - 2) {
			diag_invalid = true;
			diag_emit_cap();
			errno = saved_errno;
			return;
		}
		const int seq = ++diag_seq;
		std::vector<int> bounded_types = types;
		int bounded_trunc = types_trunc;
		int bounded_invalid = (invalid || types_trunc) ? 1 : 0;
		std::string line;
		for (;;) {
			line = DIAG_PREFIX + diag_json(seq, stage, event, logical_mode, effective_mode,
				clock_id, t0_us, t_us, local_port, ret, err, revents, poll_ms, bytes, msgs,
				bounded_types, types_total, bounded_trunc, bounded_invalid, phase, c0, c1, c2, c3);
			if (line.size() <= static_cast<size_t>(DIAG_MAX_RECORD_BYTES)) break;
			if (bounded_types.empty()) {
				diag_invalid = true;
				diag_emit_cap();
				errno = saved_errno;
				return;
			}
			bounded_types.pop_back();
			bounded_trunc = 1;
			bounded_invalid = 1;
		}
		if (!diag_write_line(line)) {
			diag_invalid = true;
			diag_fallback_status();
		}
	} catch (...) {
		// Diagnostic allocation/write failure invalidates the measurement, never the test flow.
		diag_invalid = true;
		diag_fallback_status();
	}
	errno = saved_errno;
}

static void diag_start() noexcept {
	if (!diag_enabled()) return;
	diag_emit(DIAG_ST_START, DIAG_EV_START, 0, 0, diag_pick_clock(), 0, 0, 0, 0, 0, 0, 0,
		0, 0, {}, 0, 0, 0, DIAG_PH_NONE, 1);
}

static void diag_finalize() noexcept {
	if (!diag_enabled()) return;
	if ((diag_invalid || diag_capped || diag_output_failed) && !diag_terminal_emitted)
		diag_emit_cap();
	diag_emit_final();
}

struct DiagStageData {
	Msgs msgs;
	std::string got;
	bool closed = false;
	bool saw_send_event = false;
	bool event_overflow = false;
	std::array<PgDiagEvent, DIAG_MAX_EVENTS> events{};
	size_t event_count = 0;
	long long send_t0_us = 0;
	long long send_end_us = 0;
	int clock_id = 0;
	long long send_bytes = 0;
	long long send_ret = 0;
	int send_err = 0;
	int polls = 0;
	long long last_poll_ret = 0;
	int last_poll_err = 0;
	int last_poll_revents = 0;
	int last_poll_ms = 0;
	int reads = 0;
	long long read_bytes = 0;
	int last_msg_type = 0;
};

static void diag_collect_types(const Msgs& msgs, std::vector<int>& types, int& total, int& trunc) {
	total = static_cast<int>(msgs.size());
	trunc = total > DIAG_MAX_TYPES ? 1 : 0;
	const size_t n = msgs.size() < static_cast<size_t>(DIAG_MAX_TYPES)
		? msgs.size() : static_cast<size_t>(DIAG_MAX_TYPES);
	for (size_t i = 0; i < n; i++) types.push_back(static_cast<unsigned char>(msgs[i].first));
}

static DiagStageData read_stage(PgConnection& c, int stage, int logical_mode, int effective_mode,
		const std::function<void()>& send, int quiet_ms = QUIET_MS) {
	DiagStageData d;
	auto run_original = [&](bool stamp_send_end) {
		try {
			send();
			if (stamp_send_end && d.send_end_us <= 0) diag_invalid = true;
			d.msgs = c.readUntilQuiet(quiet_ms);
			d.got = tokens(d.msgs);
		} catch (const PgException& e) {
			d.closed = true;
			d.got = std::string("CLOSED:") + e.what();
		}
	};
	if (!diag_enabled()) {
		run_original(false);
		return d;
	}
	PgDiagCallback cb;
	const int saved_errno = errno;
	try {
		cb = [&d](const PgDiagEvent& e) {
			if (d.event_count < d.events.size()) d.events[d.event_count++] = e;
			else d.event_overflow = true;
			d.clock_id = e.clock_id;
			if (e.event == 1) {
				d.saw_send_event = true;
				d.send_t0_us = e.t0_us;
				d.send_end_us = e.t_us;  // last actual send boundary, never a post-lambda clock
				d.send_bytes = e.bytes;
				d.send_ret = e.ret;
				d.send_err = e.err;
			} else if (e.event == 2) {
				d.polls++;
				d.last_poll_ret = e.ret;
				d.last_poll_err = e.err;
				d.last_poll_revents = e.revents;
				d.last_poll_ms = e.poll_ms;
			} else if (e.event == 3) {
				d.reads++;
				d.read_bytes += e.bytes;
				d.last_msg_type = e.msg_type;
			}
		};
	} catch (...) {
		// Diagnostic setup failure: run the exact original send/read path and mark invalid.
		errno = saved_errno;
		diag_invalid = true;
		run_original(false);
		return d;
	}
	errno = saved_errno;
	{
		PgDiagScope scope(c, stage, logical_mode, effective_mode, std::move(cb));
		run_original(true);
	}
	if (c.diagInvalid()) diag_invalid = true;
	return d;
}

static void diag_emit_stage(PgConnection& c, int stage, int event, int logical_mode,
		int effective_mode, const DiagStageData& d, int phase, bool force_invalid = false,
		long long c0 = 0, long long c1 = 0, long long c2 = 0, long long c3 = 0) noexcept {
	if (!diag_enabled()) return;
	const int saved_errno = errno;
	try {
		std::vector<int> types;
		int total = 0, trunc = 0;
		diag_collect_types(d.msgs, types, total, trunc);
		const int clock_id = d.clock_id != 0 ? d.clock_id : c.diagClockId();
		const int invalid = (force_invalid || d.closed || d.event_overflow || trunc ||
			c.diagInvalid() || diag_invalid) ? 1 : 0;
		diag_emit(stage, event, logical_mode, effective_mode, clock_id, d.send_t0_us, d.send_end_us,
			c.localPort(), d.send_ret, d.send_err, d.last_poll_revents, d.last_poll_ms,
			d.read_bytes, static_cast<long long>(d.msgs.size()), types, total, trunc, invalid, phase,
			c0, c1, c2, c3);
	} catch (...) {
		diag_invalid = true;
		diag_fallback_status();
	}
	errno = saved_errno;
}

// Emit each captured send/poll/frame boundary as its own I/O record. Called only after the
// original assertion has run; never from inside the send/poll callback.
static void diag_emit_io_events(PgConnection& c, int stage, int logical_mode, int effective_mode,
		const DiagStageData& d, bool force_invalid = false) noexcept {
	if (!diag_enabled()) return;
	const int saved_errno = errno;
	try {
		const int invalid = (force_invalid || d.closed || d.event_overflow ||
			c.diagInvalid() || diag_invalid) ? 1 : 0;
		for (size_t i = 0; i < d.event_count; i++) {
			const PgDiagEvent& e = d.events[i];
			int event = 0;
			if (e.event == 1) event = DIAG_EV_IO_SEND;
			else if (e.event == 2) event = DIAG_EV_IO_POLL;
			else if (e.event == 3) event = DIAG_EV_IO_FRAME;
			if (event == 0) continue;
			std::vector<int> types;
			int total = 0, trunc = 0;
			if (event == DIAG_EV_IO_FRAME) {
				types.push_back(static_cast<unsigned char>(e.msg_type));
				total = 1;
			}
			diag_emit(stage, event, logical_mode, effective_mode, e.clock_id, e.t0_us, e.t_us,
				e.local_port, e.ret, e.err, e.revents, e.poll_ms, e.bytes,
				event == DIAG_EV_IO_FRAME ? 1 : 0, types, total, trunc, invalid, DIAG_PH_NONE);
		}
	} catch (...) {
		diag_invalid = true;
		diag_fallback_status();
	}
	errno = saved_errno;
}

static void diag_emit_peek(PgConnection& c, int stage, int logical_mode, int effective_mode,
		long long t0_us, long long t_us, long long ret, int err, int revents, int poll_ms,
		long long bytes, int phase) noexcept {
	diag_emit(stage, DIAG_EV_PEEK, logical_mode, effective_mode, c.diagClockId(), t0_us, t_us,
		c.localPort(), ret, err, revents, poll_ms, bytes, 0, {}, 0, 0,
		(phase == DIAG_PH_RECV_ERROR || phase == DIAG_PH_NO_SEND_TIMESTAMP) ? 1 : 0, phase);
}

// Non-consuming observation after an actual failed expected-positive assertion whose filtered got
// is exactly empty. Deadline is the original send end + 2 s; no write, no consume, no restart.
static void diag_passive_peek(PgConnection& c, int stage, int logical_mode, int effective_mode,
		long long send_end_us) noexcept {
	struct EntryErrnoGuard {
		int saved;
		~EntryErrnoGuard() { errno = saved; }
	} entry_errno{errno};
	const int fd = c.getSocket();
	if (fd < 0) {
		diag_emit_peek(c, stage, logical_mode, effective_mode, 0, 0, 0, 0, 0, 0, 0,
			DIAG_PH_SOCKET_INVALID);
		return;
	}
	if (c.diagInvalid()) {
		diag_invalid = true;
		diag_emit_peek(c, stage, logical_mode, effective_mode, 0, 0, 0, 0, 0, 0, 0,
			DIAG_PH_NO_SEND_TIMESTAMP);
		return;
	}
	if (send_end_us <= 0) {
		// No valid original send timestamp: mark invalid and skip the observation entirely.
		diag_invalid = true;
		diag_emit_peek(c, stage, logical_mode, effective_mode, 0, 0, 0, 0, 0, 0, 0,
			DIAG_PH_NO_SEND_TIMESTAMP);
		return;
	}
	const long long deadline = send_end_us + 2000000LL;
	for (;;) {
		const long long now = c.diagClockNowUs();
		if (now <= 0) {
			diag_invalid = true;
			diag_emit_peek(c, stage, logical_mode, effective_mode, 0, 0, 0, 0, 0, 0, 0,
				DIAG_PH_NO_SEND_TIMESTAMP);
			return;
		}
		if (now >= deadline) {
			diag_emit_peek(c, stage, logical_mode, effective_mode, now, now, 0, 0, 0, 0, 0,
				DIAG_PH_DEADLINE);
			return;
		}
		long long remain_us = deadline - now;
		int remain_ms = static_cast<int>((remain_us + 999) / 1000);
		if (remain_ms < 1) remain_ms = 1;
		struct pollfd p = { fd, POLLIN | POLLHUP | POLLERR, 0 };
		const long long t0_us = c.diagClockNowUs();
		const int r = poll(&p, 1, remain_ms);
		const int after_errno = errno;  // immediately after the original poll
		const long long t_us = c.diagClockNowUs();
		errno = after_errno;
		if (t_us <= 0) {
			diag_invalid = true;
			diag_emit_peek(c, stage, logical_mode, effective_mode, t0_us, 0, 0, 0, 0, 0, 0,
				DIAG_PH_NO_SEND_TIMESTAMP);
			return;
		}
		if (r < 0) {
			diag_emit_peek(c, stage, logical_mode, effective_mode, t0_us, t_us, r,
				after_errno, p.revents, remain_ms, 0, DIAG_PH_POLL_ERROR);
			if (after_errno == EINTR) continue;  // absolute deadline is rechecked at the top
			return;
		}
		if (r == 0) continue;  // rounded-down timeout; deadline rechecked at the top
		if (p.revents & POLLNVAL) {
			diag_emit_peek(c, stage, logical_mode, effective_mode, t0_us, t_us, r, 0,
				p.revents, remain_ms, 0, DIAG_PH_SOCKET_INVALID);
			return;
		}
		if (p.revents & POLLERR) {
			diag_emit_peek(c, stage, logical_mode, effective_mode, t0_us, t_us, r, 0,
				p.revents, remain_ms, 0, DIAG_PH_SOCKET_ERROR);
			return;
		}
		if (p.revents & POLLIN) {
			const long long pre_recv_now = c.diagClockNowUs();
			if (pre_recv_now <= 0) {
				diag_invalid = true;
				diag_emit_peek(c, stage, logical_mode, effective_mode, t0_us, t_us, r, 0,
					p.revents, remain_ms, 0, DIAG_PH_NO_SEND_TIMESTAMP);
				return;
			}
			if (pre_recv_now >= deadline) {
				diag_emit_peek(c, stage, logical_mode, effective_mode, t0_us, t_us, r, 0,
					p.revents, remain_ms, 0, DIAG_PH_DEADLINE);
				return;
			}
			uint8_t one = 0;
			const long long rt0_us = c.diagClockNowUs();
			const ssize_t n = recv(fd, &one, 1, MSG_PEEK | MSG_DONTWAIT);
			const int after_recv_errno = errno;  // immediately after recv
			const int recv_errno = (n < 0) ? after_recv_errno : 0;
			const long long rt_us = c.diagClockNowUs();
			errno = after_recv_errno;
			if (rt_us <= 0) {
				diag_invalid = true;
				diag_emit_peek(c, stage, logical_mode, effective_mode, rt0_us, 0, 0, 0, 0, 0, 0,
					DIAG_PH_NO_SEND_TIMESTAMP);
				return;
			}
			int phase = DIAG_PH_UNEXPECTED;
			if (n == 1) phase = (rt_us >= deadline) ? DIAG_PH_PEEK_AFTER_DEADLINE : DIAG_PH_PEEK_POSITIVE;
			else if (n == 0) phase = DIAG_PH_CLOSED;
			else if (recv_errno == EINTR) phase = DIAG_PH_POLL_ERROR;
			else if (recv_errno == EAGAIN || recv_errno == EWOULDBLOCK) phase = DIAG_PH_DEADLINE;
			else phase = DIAG_PH_RECV_ERROR;
			diag_emit_peek(c, stage, logical_mode, effective_mode, rt0_us, rt_us, n,
				recv_errno, p.revents, remain_ms, n == 1 ? 1 : 0, phase);
			if (n == 1) return;
			if (recv_errno == EINTR) continue;
			if (recv_errno == EAGAIN || recv_errno == EWOULDBLOCK) {
				const int saved = errno;
				poll(nullptr, 0, 1);  // bounded 1 ms pause; deadline is rechecked at the top
				errno = saved;
				continue;
			}
			return;
		}
		if (p.revents & POLLHUP) {
			diag_emit_peek(c, stage, logical_mode, effective_mode, t0_us, t_us, r, 0,
				p.revents, remain_ms, 0, DIAG_PH_CLOSED);
			return;
		}
		diag_emit_peek(c, stage, logical_mode, effective_mode, t0_us, t_us, r, 0,
			p.revents, remain_ms, 0, DIAG_PH_UNEXPECTED);
		return;
	}
}

// Original assertion FIRST, then the stage marker, then (only for an actual empty failure) the
// non-consuming passive observation. With diagnostics off this is exactly check(run(...)).
static void check_initial(PgConnection& c, int stage, int logical_mode, int effective_mode,
		const std::function<void()>& send, const std::string& want, const char* what, Mode m, bool txn) {
	if (!diag_enabled()) {
		check(run(c, send), want, what, m, txn);
		return;
	}
	const DiagStageData d = read_stage(c, stage, logical_mode, effective_mode, send);
	check(d.got, want, what, m, txn);  // unchanged exact assertion
	diag_emit_stage(c, stage, DIAG_EV_STAGE, logical_mode, effective_mode, d, DIAG_PH_NONE, d.closed);
	diag_emit_io_events(c, stage, logical_mode, effective_mode, d, d.closed);
	if (d.closed || !d.got.empty() || d.got == want) return;
	diag_passive_peek(c, stage, logical_mode, effective_mode, d.send_end_us);
}

// Logging-only assertion wrapper: original assertion FIRST, no passive wait.
static void check_logged(PgConnection& c, int stage, int event, int logical_mode, int effective_mode,
		const std::function<void()>& send, const std::string& want, const char* what, Mode m, bool txn) {
	if (!diag_enabled()) {
		check(run(c, send), want, what, m, txn);
		return;
	}
	const DiagStageData d = read_stage(c, stage, logical_mode, effective_mode, send);
	check(d.got, want, what, m, txn);
	diag_emit_stage(c, stage, event, logical_mode, effective_mode, d, DIAG_PH_NONE, d.closed);
	diag_emit_io_events(c, stage, logical_mode, effective_mode, d, d.closed);
}

// BEGIN as a simple Query, when the case runs inside an explicit transaction.
static void maybe_begin(PgConnection& c, bool txn) {
	if (txn) run(c, [&] { c.sendQuery("BEGIN"); });
}

static char txn_z(bool txn) { return txn ? 'T' : 'I'; }

// ===== Cases. Each makes exactly the number of ok() calls in its CASES row. =====

// Control: the same statement ended by Sync, which works today.
static void case_sync_control(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	const std::string z = std::string("Z(") + txn_z(txn) + ")";
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT $1::text AS x", false); c->describeStatement("", true); }),
		"1 t T " + z, "sync control: P D(S) S", m, txn);
	check(run(*c, [&] { c->bindStatement("", "", { { std::string("a"), 0 } }, {}, false); c->executePortal("", 0, true); }),
		"2 D C(SELECT 1) " + z, "sync control: B E S", m, txn);
}

// Row 1, postgres.js: Parse + Describe(statement) + Flush, then Bind + Execute + Sync.
static void case_row1(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	const std::string z = std::string("Z(") + txn_z(txn) + ")";
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT $1 AS x", false); c->describeStatement("", false); c->sendFlush(); }),
		"1 t T", "row 1: P D(S) H", m, txn);
	check(run(*c, [&] { c->bindStatement("", "", { { std::string("a"), 0 } }, {}, false); c->executePortal("", 0, true); }),
		"2 D C(SELECT 1) " + z, "row 1: B E S", m, txn);
}

static const char* SER = "SELECT g FROM generate_series(1,5) g";
static const std::string ALL5 = "D D D D D C(SELECT 5)";

// Admin and a direct backend connection, for cases that change runtime settings or count rows.
static PGconn* g_admin = nullptr;
static PGconn* g_be = nullptr;

static long rows(const std::string& tag) {
	const std::string n = scalar(g_be, "SELECT count(*) FROM flush_t WHERE tag = '" + tag + "'");
	return n.empty() ? -1 : atol(n.c_str());
}

static std::string tag_for(const char* what, Mode m, bool txn) {
	return std::string(what) + "_" + std::to_string((int)m) + (txn ? "t" : "a") + "_" + std::to_string((long)time(nullptr));
}

// The first column of the first DataRow, as text.
static std::string first_value(const Msgs& msgs) {
	for (const auto& m : msgs) {
		if (m.first == 'D' && m.second.size() >= 6) {
			const auto& b = m.second;
			const int32_t len = (b[2] << 24) | (b[3] << 16) | (b[4] << 8) | b[5];
			if (len > 0 && (size_t)(6 + len) <= b.size()) return std::string(b.begin() + 6, b.begin() + 6 + len);
		}
	}
	return "";
}

static bool admin_set(const std::string& var, const std::string& value) {
	return exec(g_admin, "SET " + var + "='" + value + "'") && exec(g_admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

// Task 3: Bind and Describe(portal) with no Execute after it. The Bind must reach the backend
// before the Describe; in libpq mode it does not (no bind-only call), a known gap.
static void case_describe_portal_no_execute(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	const std::string z = std::string("Z(") + txn_z(txn) + ")";
	const std::string got = run(*c, [&] {
		c->prepareStatement("", uniq() + "SELECT g FROM generate_series(1,3) g", false);
		c->bindStatement("", "", {}, {}, false);
		c->describePortal("", true);
	});
	if (m == Mode::LIBPQ) {
		// libpq has no bind-only call: whatever it answers, the session must survive it.
		ok(got.rfind("CLOSED", 0) != 0, "describe portal, no execute [libpq%s]: session survives (known gap, got '%s')",
			txn ? ", in txn" : "", got.c_str());
		return;
	}
	check(got, "1 2 T " + z, "describe portal, no execute: P B D(P) S", m, txn);
	check(run(*c, [&] { c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, true); }),
		"2 D D D C(SELECT 3) " + z, "describe portal, no execute: then B E S", m, txn);
}

// Task 4: a row limit on the unnamed portal, ended by Sync. Native follows PostgreSQL; libpq keeps
// returning every row (by design) and has no suspended portal to continue.
static void case_unnamed_row_limit(Mode m, bool) {
	const bool lp = (m == Mode::LIBPQ);
	const std::string all = "D D D D D C(SELECT 5)";
	{   // (a) outside a transaction the portal ends at the Sync
		auto c = client(m);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 2, true); }),
			lp ? "1 2 " + all + " Z(I)" : "1 2 D D s Z(I)", "row limit (a): P B E(2) S", m, false);
		check(run(*c, [&] { c->executePortal("", 2, true); }), "E(34000) Z(I)", "row limit (a): E(2) S after the Sync", m, false);
	}
	if (lp) return;  // (b)-(f) need a suspended portal, which libpq mode never has (by design)
	{   // (b) in a transaction the suspended portal continues
		auto c = client(m);
		maybe_begin(*c, true);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 2, true); }),
			"1 2 D D s Z(T)", "row limit (b): P B E(2) S", m, true);
		check(run(*c, [&] { c->executePortal("", 2, true); }), "D D s Z(T)", "row limit (b): E(2) S continues", m, true);
		check(run(*c, [&] { c->executePortal("", 0, true); }), "D C(SELECT 1) Z(T)", "row limit (b): E(0) S finishes", m, true);
	}
	{   // (c) Close of the suspended portal
		auto c = client(m);
		maybe_begin(*c, true);
		run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 2, true); });
		// closePortal(.., true) would read the replies itself: send the Sync separately.
		check(run(*c, [&] { c->closePortal("", false); c->sendSync(); }), "3 Z(T)", "row limit (c): C(P) S", m, true);
		check(run(*c, [&] { c->executePortal("", 2, true); }), "E(34000) Z(E)", "row limit (c): E(2) S after the Close", m, true);
	}
	{   // (d) a simple Query destroys the unnamed portal
		auto c = client(m);
		maybe_begin(*c, true);
		run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 2, true); });
		run(*c, [&] { c->sendQuery("SELECT 1"); });
		check(run(*c, [&] { c->executePortal("", 2, true); }), "E(34000) Z(E)", "row limit (d): E(2) S after a simple Query", m, true);
	}
	{   // (e) a new Bind replaces the suspended portal
		auto c = client(m);
		maybe_begin(*c, true);
		run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 2, true); });
		check(run(*c, [&] { c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, true); }),
			"2 " + all + " Z(T)", "row limit (e): B E S replaces the portal", m, true);
	}
	{   // (f) suspended and continued inside one unit
		auto c = client(m);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 2, false); c->executePortal("", 2, true); }),
			"1 2 D D s D D s Z(I)", "row limit (f): P B E(2) E(2) S", m, false);
	}
}

// An unnamed portal whose Execute finished, read in steps with row limits or all at once, stays open
// until the group or transaction ends, as in PostgreSQL: a Describe still answers its columns and
// another Execute returns no rows. Checked inside one Flush group, and across Syncs in an explicit
// transaction. Native mode only: libpq mode keeps no portal between messages (by design).
// (e)-(g): a Describe, Execute, Close or new Bind in the same batched unit as the Execute sees it in
// the order the client sent them.
static void case_unnamed_exhausted(Mode m, bool) {
	if (m == Mode::LIBPQ) return;
	{   // (a) one group, every part ended with Flush
		auto c = client(m);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 2, false); c->sendFlush(); }), "1 2 D D s", "exhausted (a): P B E(2) H", m, false);
		check(run(*c, [&] { c->executePortal("", 5, false); c->sendFlush(); }), "D D D C(SELECT 3)",
			"exhausted (a): E(5) H reads the rest", m, false);
		check(run(*c, [&] { c->describePortal("", false); c->sendFlush(); }), "T", "exhausted (a): D(P) H", m, false);
		check(run(*c, [&] { c->executePortal("", 0, false); c->sendFlush(); }), "C(SELECT 0)", "exhausted (a): E H", m, false);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "exhausted (a): S", m, false);
	}
	{   // (b) an explicit transaction, every part ended with Sync
		auto c = client(m);
		maybe_begin(*c, true);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 2, true); }), "1 2 D D s Z(T)", "exhausted (b): P B E(2) S", m, true);
		check(run(*c, [&] { c->executePortal("", 5, true); }), "D D D C(SELECT 3) Z(T)", "exhausted (b): E(5) S reads the rest", m, true);
		check(run(*c, [&] { c->describePortal("", true); }), "T Z(T)", "exhausted (b): D(P) S", m, true);
		check(run(*c, [&] { c->executePortal("", 0, true); }), "C(SELECT 0) Z(T)", "exhausted (b): E S", m, true);
	}
	{   // (c) no row limit: the Execute runs to the end, in one group ended with Flush
		auto c = client(m);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 0, false); c->sendFlush(); }), "1 2 " + ALL5, "exhausted (c): P B E H", m, false);
		check(run(*c, [&] { c->describePortal("", false); c->sendFlush(); }), "T", "exhausted (c): D(P) H", m, false);
		check(run(*c, [&] { c->executePortal("", 0, false); c->sendFlush(); }), "C(SELECT 0)", "exhausted (c): E H", m, false);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "exhausted (c): S", m, false);
	}
	{   // (d) no row limit, in an explicit transaction, every part ended with Sync
		auto c = client(m);
		maybe_begin(*c, true);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 0, true); }), "1 2 " + ALL5 + " Z(T)", "exhausted (d): P B E S", m, true);
		check(run(*c, [&] { c->describePortal("", true); }), "T Z(T)", "exhausted (d): D(P) S", m, true);
		check(run(*c, [&] { c->executePortal("", 0, true); }), "C(SELECT 0) Z(T)", "exhausted (d): E S", m, true);
	}
	{   // (e) Describe and Execute right after the Execute, in the same segment; then Close it
		auto c = client(m);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 0, false); c->describePortal("", false); c->executePortal("", 0, false); c->sendFlush(); }),
			"1 2 " + ALL5 + " T C(SELECT 0)", "exhausted (e): P B E D(P) E H", m, false);
		check(run(*c, [&] { c->closePortal("", false); c->describePortal("", false); c->sendFlush(); }), "3 E(34000)",
			"exhausted (e): C(P) D(P) H", m, false);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "exhausted (e): S", m, false);
	}
	{   // (f) Closed in the same segment as its Execute: not kept
		auto c = client(m);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 0, false); c->closePortal("", false); c->sendFlush(); }), "1 2 " + ALL5 + " 3",
			"exhausted (f): P B E C(P) H", m, false);
		check(run(*c, [&] { c->describePortal("", false); c->sendFlush(); }), "E(34000)", "exhausted (f): D(P) H", m, false);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "exhausted (f): S", m, false);
	}
	{   // (g) Replaced by a new Bind, then closed, in the same unit as its Execute: not kept
		auto c = client(m);
		maybe_begin(*c, true);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 0, false); c->bindStatement("", "", {}, {}, false); c->closePortal("", false); c->sendSync(); }),
			"1 2 " + ALL5 + " 2 3 Z(T)", "exhausted (g): P B E B C(P) S", m, true);
		check(run(*c, [&] { c->describePortal("", true); }), "E(34000) Z(E)", "exhausted (g): D(P) S", m, true);
	}
}

// Row 2: a whole statement before the Flush, then the Sync alone.
static void case_row2(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
			c->describePortal("", false); c->executePortal("", 0, false); c->sendFlush(); }),
		"1 2 T " + ALL5, "row 2: P B D(P) E H", m, txn);
	check(run(*c, [&] { c->sendSync(); }), std::string("Z(") + txn_z(txn) + ")", "row 2: S", m, txn);
}

// Row 3, unnamed portal: a cursor paged across Flushes. libpq returns every row (by design).
static void case_row3a(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	const std::string first = run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
		c->describePortal("", false); c->executePortal("", 2, false); c->sendFlush(); });
	if (m == Mode::LIBPQ) {
		check(first, "1 2 T " + ALL5, "row 3a: P B D(P) E(2) H (libpq: every row)", m, txn);
		return;
	}
	check(first, "1 2 T D D s", "row 3a: P B D(P) E(2) H", m, txn);
	check(run(*c, [&] { c->executePortal("", 2, false); c->sendFlush(); }), "D D s", "row 3a: E(2) H", m, txn);
	check(run(*c, [&] { c->executePortal("", 0, false); c->sendFlush(); }), "D C(SELECT 1)", "row 3a: E(0) H", m, txn);
	check(run(*c, [&] { c->closePortal("", false); c->sendSync(); }), std::string("3 Z(") + txn_z(txn) + ")", "row 3a: C(P) S", m, txn);
}

// Row 3, named portal (native only: libpq mode refuses named portals, see the error cases).
static void case_row3b(Mode m, bool txn) {
	if (m == Mode::LIBPQ) return;
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "p1", {}, {}, false);
			c->describePortal("p1", false); c->executePortal("p1", 2, false); c->sendFlush(); }),
		"1 2 T D D s", "row 3b: P B(p1) D(P p1) E(p1,2) H", m, txn);
	check(run(*c, [&] { c->executePortal("p1", 2, false); c->sendFlush(); }), "D D s", "row 3b: E(p1,2) H", m, txn);
	check(run(*c, [&] { c->executePortal("p1", 0, false); c->sendFlush(); }), "D C(SELECT 1)", "row 3b: E(p1,0) H", m, txn);
	check(run(*c, [&] { c->closePortal("p1", false); c->sendSync(); }), std::string("3 Z(") + txn_z(txn) + ")", "row 3b: C(P p1) S", m, txn);
}

// Row 4: a named portal bound before a Flush and executed after it (native only).
static void case_row4(Mode m, bool txn) {
	if (m == Mode::LIBPQ) return;
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "p1", {}, {}, false); c->sendFlush(); }),
		"1 2", "row 4: P B(p1) H", m, txn);
	check(run(*c, [&] { c->executePortal("p1", 0, true); }), ALL5 + " Z(" + txn_z(txn) + ")", "row 4: E(p1) S", m, txn);
}

// Row 10: Flush with nothing queued, several Flushes, and a Flush between two messages.
static void case_row10(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->sendFlush(); }), "", "row 10: H alone", m, txn);
	check(run(*c, [&] { c->sendFlush(); c->sendFlush(); }), "", "row 10: H H", m, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT 1", false); c->sendFlush(); c->sendFlush();
			c->describeStatement("", false); c->sendFlush(); }), "1 t T", "row 10: P H H D(S) H", m, txn);
	check(run(*c, [&] { c->sendSync(); }), std::string("Z(") + txn_z(txn) + ")", "row 10: S", m, txn);
}

// Row 12: an explicit transaction opened and written through the extended protocol across Flushes.
static void case_row12(Mode m, bool) {
	auto c = client(m);
	const std::string tag = tag_for("row12", m, false);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "BEGIN", false); c->bindStatement("", "", {}, {}, false);
			c->executePortal("", 0, false); c->sendFlush(); }), "1 2 C(BEGIN)", "row 12: P(BEGIN) B E H", m, false);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "INSERT INTO flush_t VALUES ('" + tag + "', 1)", false);
			c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush(); }),
		"1 2 C(INSERT 0 1)", "row 12: P(INSERT) B E H", m, false);
	check(run(*c, [&] { c->sendSync(); }), "Z(T)", "row 12: S keeps the transaction", m, false);
	ok(rows(tag) == 0, "row 12 [%s]: not committed before COMMIT (rows=%ld)", mode_name(m), rows(tag));
	check(run(*c, [&] { c->sendQuery("COMMIT"); }), "C(COMMIT) Z(I)", "row 12: COMMIT", m, false);
	ok(rows(tag) == 1, "row 12 [%s]: committed by COMMIT (rows=%ld)", mode_name(m), rows(tag));
}

// The connection holding a Flush-ended group stays with it, also when connection_delay_multiplex_ms
// would otherwise hand an idle connection back to the pool after the delay.
static void case_pin_delay_multiplex(Mode m, bool) {
	const std::string before = scalar(g_admin, "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-connection_delay_multiplex_ms'");
	admin_set("pgsql-connection_delay_multiplex_ms", "100");
	auto c = client(m);
	const std::string tag = tag_for("pin", m, false);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "INSERT INTO flush_t VALUES ('" + tag + "', pg_backend_pid())", false);
			c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush(); }),
		"1 2 C(INSERT 0 1)", "pin: P B E(INSERT) H", m, false);
	usleep(6500000);  // past the delay and past a maintenance pass (pgsql-poll_timeout)
	std::string pid2;
	try {
		c->prepareStatement("", uniq() + "SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()", false);
		c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush();
		pid2 = first_value(c->readUntilQuiet(QUIET_MS));
	} catch (const PgException& e) { pid2 = std::string("CLOSED:") + e.what(); }
	check(run(*c, [&] { c->sendSync(); }), "Z(I)", "pin: S", m, false);
	const std::string pid1 = scalar(g_be, "SELECT v::text FROM flush_t WHERE tag = '" + tag + "'");
	ok(!pid1.empty() && pid1 == pid2, "pin [%s]: the group stayed on one backend across the delay (insert pid %s, later pid %s)",
		mode_name(m), pid1.c_str(), pid2.c_str());
	ok(rows(tag) == 1, "pin [%s]: the row is committed by the client's Sync (rows=%ld)", mode_name(m), rows(tag));
	admin_set("pgsql-connection_delay_multiplex_ms", before.empty() ? "0" : before);
}

// Row 16: a Flush changes nothing in the digest statistics. The same two Executes with a Sync
// in place of the Flush give the control count (ProxySQL counts the Parse too).
static void case_row16_stats(Mode m, bool) {
	auto count = [&](bool flush) {
		const std::string alias = std::string(flush ? "flush16h_" : "flush16s_") + std::to_string((int)m) + "_" + std::to_string((long)time(nullptr));
		auto c = client(m);
		run(*c, [&] { c->prepareStatement("", "SELECT 1 AS " + alias, false); c->bindStatement("", "", {}, {}, false);
			c->executePortal("", 0, false); if (flush) c->sendFlush(); else c->sendSync(); });
		run(*c, [&] { c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, true); });
		return scalar(g_admin, "SELECT COALESCE(SUM(count_star),0) FROM stats_pgsql_query_digest WHERE digest_text LIKE '%" + alias + "%'");
	};
	const std::string with_sync = count(false), with_flush = count(true);
	ok(with_sync != "0" && with_flush == with_sync, "row 16 [%s]: P B E H + B E S counted as P B E S + B E S (Flush %s, Sync %s)",
		mode_name(m), with_flush.c_str(), with_sync.c_str());
}

// Review focus: every message in one TCP write.
static void case_one_write(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->beginBuffering(); c->prepareStatement("", uniq() + "SELECT $1::text AS x", false);
			c->describeStatement("", false); c->sendFlush(); c->bindStatement("", "", { { std::string("a"), 0 } }, {}, false);
			c->executePortal("", 0, true); c->endBuffering(); }),
		std::string("1 t T 2 D C(SELECT 1) Z(") + txn_z(txn) + ")", "one write: P D(S) H B E S", m, txn);
}

// Review focus: a result larger than threshold_resultset_size inside a Flush-ended segment.
static void case_large_result(Mode m, bool) {
	auto c = client(m);
	int d = 0; std::string last; bool z = false;
	try {
		c->prepareStatement("", uniq() + "SELECT g FROM generate_series(1,100000) g", false);
		c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush();
		for (const auto& msg : c->readUntilQuiet(1000)) {
			if (msg.first == 'D') d++;
			else if (msg.first == 'Z') z = true;
			else last = tokens(Msgs{ msg });
		}
	} catch (const PgException& e) { last = std::string("CLOSED:") + e.what(); }
	ok(d == 100000 && last == "C(SELECT 100000)" && !z, "large result [%s]: 100000 rows, CommandComplete, no ReadyForQuery (rows=%d, last='%s', Z=%d)",
		mode_name(m), d, last.c_str(), (int)z);
	check(run(*c, [&] { c->sendSync(); }), "Z(I)", "large result: S", m, false);
}

// Review focus: native mode switched on while a libpq connection holds a group.
static void case_mode_flip_mid_group(Mode m, bool) {
	if (m != Mode::LIBPQ) return;
	auto c = client(m);
	const std::string tag = tag_for("flip", m, false);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "INSERT INTO flush_t VALUES ('" + tag + "', 1)", false);
			c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush(); }),
		"1 2 C(INSERT 0 1)", "mode flip: P B E(INSERT) H on libpq", m, false);
	admin_set("pgsql-use_native_backend_protocol", "true");
	check(run(*c, [&] { c->sendSync(); }), "Z(I)", "mode flip: S after native mode was switched on", m, false);
	ok(rows(tag) == 1, "mode flip [libpq]: the group finished on its own connection (rows=%ld)", rows(tag));
	admin_set("pgsql-use_native_backend_protocol", "false");
}

// Review focus: a long cursor, one row per Execute + Flush (native only).
static void case_long_cursor(Mode m, bool) {
	if (m == Mode::LIBPQ) return;
	auto c = client(m);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT g FROM generate_series(1,1000) g", false);
			c->bindStatement("", "p1", {}, {}, false); c->describePortal("p1", false); c->sendFlush(); }),
		"1 2 T", "long cursor: P B(p1) D(P p1) H", m, false);
	int good = 0;
	try {
		for (int i = 0; i < 1000; i++) {
			c->executePortal("p1", 1, false); c->sendFlush();
			char t1 = 0, t2 = 0; std::vector<uint8_t> b;
			c->readMessage(t1, b); c->readMessage(t2, b);
			if (t1 == 'D' && t2 == 's') good++;
		}
	} catch (const PgException& e) { diag("long cursor [%s]: %s", mode_name(m), e.what()); }
	ok(good == 1000, "long cursor [%s]: 1000 x E(p1,1) H each gave D s (%d did)", mode_name(m), good);
	check(run(*c, [&] { c->closePortal("p1", false); c->sendSync(); }), "3 Z(I)", "long cursor: C(P p1) S", m, false);
}

// ===== Errors after a Flush: discard until the Sync (spec 4.6). =====

// Fails at Execute (no constant to fold at Bind), as in pgsql-extq_rule_error_stops_batch-t.
static const char* EXEC_ERR = "SELECT 1/(random()*0)::int";

static char txn_e(bool txn) { return txn ? 'E' : 'I'; }

static void insert_flush(PgConnection& c, const std::string& tag) {
	c.prepareStatement("", uniq() + "INSERT INTO flush_t VALUES ('" + tag + "', 1)", false);
	c.bindStatement("", "", {}, {}, false);
	c.executePortal("", 0, false);
	c.sendFlush();
}

// Rows 5c, 5d: an INSERT held by a Flush, then a part that fails. The group ends failed and the INSERT
// is rolled back.
static void case_row5cd(Mode m, bool txn) {
	for (int d = 0; d < 2; d++) {
		auto c = client(m);
		maybe_begin(*c, txn);
		const std::string tag = tag_for(d ? "row5d" : "row5c", m, txn);
		check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", d ? "row 5d: P B E(INSERT) H" : "row 5c: P B E(INSERT) H", m, txn);
		if (d == 0) {
			check(run(*c, [&] { c->prepareStatement("", uniq() + EXEC_ERR, false); c->bindStatement("", "", {}, {}, false);
					c->executePortal("", 0, false); c->sendSync(); }),
				std::string("1 2 E(22012) Z(") + txn_e(txn) + ")", "row 5c: P B E(error) S", m, txn);
		} else {
			check(run(*c, [&] { c->prepareStatement("", uniq() + "SELEC 1", false); c->sendFlush(); }), "E(42601)", "row 5d: P(syntax error) H", m, txn);
			check(run(*c, [&] { c->sendSync(); }), std::string("Z(") + txn_e(txn) + ")", "row 5d: S", m, txn);
		}
		if (txn) run(*c, [&] { c->sendQuery("ROLLBACK"); });
		ok(rows(tag) == 0, "row 5%c [%s%s]: the INSERT is rolled back (rows=%ld)", d ? 'd' : 'c', mode_name(m), txn ? ", in txn" : "", rows(tag));
	}
}

// Row 6: after an error everything up to the Sync is ignored, the simple Query too.
static void case_row6(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + EXEC_ERR, false); c->bindStatement("", "", {}, {}, false);
			c->executePortal("", 0, false); c->sendFlush(); }), "1 2 E(22012)", "row 6: P B E(error) H", m, txn);
	check(run(*c, [&] { c->sendFlush(); }), "", "row 6: H ignored", m, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT 1", false); c->describeStatement("", false); c->sendFlush(); }),
		"", "row 6: P D(S) H ignored", m, txn);
	check(run(*c, [&] { c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->closeStatement("", false);
			c->sendFlush(); }), "", "row 6: B E C(S) H ignored", m, txn);
	check(run(*c, [&] { c->sendQuery("SELECT 1"); }), "", "row 6: Q ignored", m, txn);
	check(run(*c, [&] { c->sendSync(); }), std::string("Z(") + txn_e(txn) + ")", "row 6: S", m, txn);
	if (txn) {
		check(run(*c, [&] { c->sendQuery("ROLLBACK"); }), "C(ROLLBACK) Z(I)", "row 6: ROLLBACK", m, txn);
	} else {
		check(run(*c, [&] { c->sendQuery("SELECT 1"); }), "T D C(SELECT 1) Z(I)", "row 6: the next query", m, txn);
	}
}

// Row 6b: a portal bound before the failing part dies with the group (native only: libpq mode refuses
// named portals).
static void case_row6b(Mode m, bool txn) {
	if (m == Mode::LIBPQ) return;
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "p1", {}, {}, false); c->sendFlush(); }),
		"1 2", "row 6b: P B(p1) H", m, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + EXEC_ERR, false); c->bindStatement("", "", {}, {}, false);
			c->executePortal("", 0, false); c->sendFlush(); }), "1 2 E(22012)", "row 6b: P B E(error) H", m, txn);
	check(run(*c, [&] { c->sendSync(); }), std::string("Z(") + txn_e(txn) + ")", "row 6b: S", m, txn);
	check(run(*c, [&] { c->executePortal("p1", 0, false); c->sendSync(); }), txn ? "E(25P02) Z(E)" : "E(34000) Z(I)",
		"row 6b: E(p1) S", m, txn);
}

// Row 7: ProxySQL's own errors for names it does not know, at once, with no ReadyForQuery.
static void case_row7_local(Mode m, bool txn) {
	struct Sub { const char* what; std::function<void(PgConnection&)> send; const char* err; };
	const Sub subs[] = {
		{ "B(missing statement) H", [](PgConnection& c) { c.bindStatement("flush_nope", "", {}, {}, false); }, "E(26000)" },
		{ "D(S missing) H", [](PgConnection& c) { c.describeStatement("flush_nope", false); }, "E(26000)" },
		{ "D(P unbound) H", [](PgConnection& c) { c.describePortal("", false); }, "E(34000)" },
		{ "E(unbound) H", [](PgConnection& c) { c.executePortal("", 0, false); }, "E(34000)" },
	};
	for (const Sub& sub : subs) {
		auto c = client(m);
		maybe_begin(*c, txn);
		const std::string what = std::string("row 7: ") + sub.what;
		check(run(*c, [&] { sub.send(*c); c->sendFlush(); }), sub.err, what.c_str(), m, txn);
		check(run(*c, [&] { c->sendSync(); }), std::string("Z(") + txn_e(txn) + ")", (what + ", then S").c_str(), m, txn);
	}
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->closeStatement("flush_nope", false); c->closePortal("", false); c->sendFlush(); }), "3 3",
		"row 7: C(S missing) C(P) H", m, txn);
	check(run(*c, [&] { c->sendSync(); }), std::string("Z(") + txn_z(txn) + ")", "row 7: C C H, then S", m, txn);
}

// Row 7, query rules: a rule's error_msg on a Parse, and on the Execute of a statement prepared before
// the rule. Each comes after an INSERT held by a Flush: the error at once, no ReadyForQuery, and the
// INSERT rolled back with the group. libpq mode checks error_msg on the Parse only, by design.
static void case_row7_rules(Mode m, bool txn) {
	const std::string blocked = "flush_rule_blocked_" + std::to_string((int)m) + (txn ? "t" : "a");
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->prepareStatement("flush_rb", "SELECT '" + blocked + "_exec'", false); c->sendSync(); }),
		std::string("1 Z(") + txn_z(txn) + ")", "row 7 rules: P(flush_rb) S before the rule", m, txn);
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9107");
	exec(g_admin, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (9107, 1, '" +
		blocked + "', 'blocked by flush test rule', 1)");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	for (int e = 0; e < (m == Mode::LIBPQ ? 1 : 2); e++) {
		const std::string tag = tag_for(e ? "rule_exec" : "rule_parse", m, txn);
		const char* what = e ? "row 7 rules: B(flush_rb) E H refused" : "row 7 rules: P(rule) H refused";
		check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "row 7 rules: P B E(INSERT) H", m, txn);
		const std::string got = run(*c, [&] {
			if (e) { c->bindStatement("flush_rb", "", {}, {}, false); c->executePortal("", 0, false); }
			else c->prepareStatement("", uniq() + "SELECT '" + blocked + "_parse'", false);
			c->sendFlush(); });
		// ProxySQL answers the unnamed Bind itself, so a refused Execute may follow its BindComplete.
		ok(got == "E(42501)" || (e && got == "2 E(42501)"), "%s [%s%s]: got '%s', expected 'E(42501)'", what, mode_name(m),
			txn ? ", in txn" : "", got.c_str());
		check(run(*c, [&] { c->sendSync(); }), std::string("Z(") + txn_e(txn) + ")", "row 7 rules: S", m, txn);
		if (txn) run(*c, [&] { c->sendQuery("ROLLBACK"); c->sendQuery("BEGIN"); });
		ok(rows(tag) == 0, "row 7 rules [%s%s]: the INSERT is rolled back (rows=%ld)", mode_name(m), txn ? ", in txn" : "", rows(tag));
	}
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9107");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
}

// Row 8: no connection for the group's first message. The error at once, one ReadyForQuery at the
// Sync, and the next query is clean. The unbatched client's startup option would lock the session on
// the dead hostgroup, so that mode uses a plain client: the path under test runs before any batching.
static void case_row8_connect(Mode m, bool) {
	const std::string timeout_before = scalar(g_admin, "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-connect_timeout_server_max'");
	exec(g_admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=9108");
	exec(g_admin, "INSERT INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (9108, '127.0.0.1', 1)");
	exec(g_admin, "LOAD PGSQL SERVERS TO RUNTIME");
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9108");
	exec(g_admin, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) "
		"VALUES (9108, 1, 'flush_dead_hg', 9108, 1)");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	admin_set("pgsql-connect_timeout_server_max", "1500");
	auto c = client(m == Mode::NATIVE_UNBATCHED ? Mode::NATIVE : m);
	const std::string got = run(*c, [&] { c->prepareStatement("", uniq() + "SELECT 'flush_dead_hg'", false);
		c->describeStatement("", false); c->sendFlush(); }, 4000);
	ok(got.compare(0, 2, "E(") == 0 && got.find(' ') == std::string::npos,
		"row 8 [%s]: P D(S) H to a dead hostgroup: one error at once, no ReadyForQuery (got '%s')", mode_name(m), got.c_str());
	check(run(*c, [&] { c->sendSync(); }), "Z(I)", "row 8: S", m, false);
	check(run(*c, [&] { c->sendQuery("SELECT 1"); }), "T D C(SELECT 1) Z(I)", "row 8: the next query", m, false);
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9108");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	exec(g_admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=9108");
	exec(g_admin, "LOAD PGSQL SERVERS TO RUNTIME");
	admin_set("pgsql-connect_timeout_server_max", timeout_before.empty() ? "10000" : timeout_before);
}

// ===== Releasing a part with no effects (decision 15, after PR #6526). =====

// Whether a backend is inside a transaction whose last statement carries marker, seen from a direct
// connection. Waits up to ms for the answer to become want: a backend that has just ended its
// transaction can linger in pg_stat_activity for a few ms.
static bool backend_txn_open_within(const std::string& marker, bool want, int ms = 1000) {
	for (int waited = 0; ; waited += 50) {
		const std::string n = scalar(g_be, "SELECT count(*) FROM pg_stat_activity WHERE xact_start IS NOT NULL "
			"AND pid <> pg_backend_pid() AND query LIKE '%" + marker + "%'");
		const bool open = !n.empty() && n != "0";
		if (open == want || waited >= ms) return open;
		usleep(50000);
	}
}

static void check_held(const std::string& marker, bool want, const char* what, Mode m) {
	const bool open = backend_txn_open_within(marker, want);
	ok(open == want, "%s [%s]: backend transaction %s (expected %s)", what, mode_name(m), open ? "held" : "not held",
		want ? "held" : "not held");
}

// What postgres.js sends: Parse and Describe of the statement, Flush, then Bind, Execute, Sync.
static void case_release_postgresjs(Mode m, bool) {
	auto c = client(m);
	const std::string mk = uniq();
	check(run(*c, [&] { c->prepareStatement("", mk + "SELECT $1::text AS x", false); c->describeStatement("", false); c->sendFlush(); }),
		"1 t T", "release postgres.js: P D(S) H", m, false);
	check_held(mk, false, "release postgres.js: after P D(S) H", m);
	check(run(*c, [&] { c->bindStatement("", "", { { std::string("a"), 0 } }, {}, false); c->executePortal("", 0, false); c->sendSync(); }),
		"2 D C(SELECT 1) Z(I)", "release postgres.js: B E S", m, false);
}

static void case_release_shapes(Mode m, bool) {
	auto c = client(m);
	std::string mk = uniq();
	check(run(*c, [&] { c->prepareStatement("", mk + "SELECT 1", false); c->sendFlush(); }), "1", "release shapes: P H", m, false);
	check_held(mk, false, "release shapes: after P H", m);
	run(*c, [&] { c->sendSync(); });
	mk = uniq();
	check(run(*c, [&] { c->prepareStatement("flush_rs", mk + "SELECT 2", false); c->sendSync(); }), "1 Z(I)", "release shapes: P(flush_rs) S", m, false);
	check(run(*c, [&] { c->describeStatement("flush_rs", false); c->sendFlush(); }), "t T", "release shapes: D(S existing) H", m, false);
	check_held(mk, false, "release shapes: after D(S existing) H", m);
	run(*c, [&] { c->sendSync(); });
	mk = uniq();
	check(run(*c, [&] { c->prepareStatement("", mk + "SELECT 3", false); c->closeStatement("", false); c->sendFlush(); }), "1 3",
		"release shapes: P C(S) H", m, false);
	check_held(mk, false, "release shapes: after P C(S) H", m);
	run(*c, [&] { c->sendSync(); });
}

// One backend connection for the hostgroup: a released part lets another client run, a held one
// makes it wait for the Sync. The unbatched mode's startup option keeps the connection with its session
// for good, so that mode uses plain native clients here.
static void case_release_pool_pressure(Mode mode, bool) {
	const Mode m = (mode == Mode::NATIVE_UNBATCHED) ? Mode::NATIVE : mode;
	const std::string max_before = scalar(g_admin, "SELECT max_connections FROM pgsql_servers WHERE hostgroup_id=" +
		std::to_string(HG) + " LIMIT 1");
	exec(g_admin, "UPDATE pgsql_servers SET max_connections=1 WHERE hostgroup_id=" + std::to_string(HG));
	exec(g_admin, "LOAD PGSQL SERVERS TO RUNTIME");
	reset_pool(g_admin);
	{
		auto a = client(m);
		auto b = client(m);
		check(run(*a, [&] { a->prepareStatement("", uniq() + "SELECT 1", false); a->describeStatement("", false); a->sendFlush(); }),
			"1 t T", "pool pressure: A P D(S) H", m, false);
		check(run(*b, [&] { b->sendQuery("SELECT 1"); }, 1500), "T D C(SELECT 1) Z(I)", "pool pressure: B runs while A's part is released", m, false);
		check(run(*a, [&] { a->bindStatement("", "", {}, {}, false); a->executePortal("", 0, false); a->sendSync(); }),
			"2 D C(SELECT 1) Z(I)", "pool pressure: A B E S", m, false);
		const std::string tag = tag_for("pressure", m, false);
		check(run(*a, [&] { insert_flush(*a, tag); }), "1 2 C(INSERT 0 1)", "pool pressure: A P B E(INSERT) H", m, false);
		check(run(*b, [&] { b->sendQuery("SELECT 1"); }, 1000), "", "pool pressure: B waits while A holds the connection", m, false);
		run(*a, [&] { a->sendSync(); });
		check(tokens(b->readUntilQuiet(QUIET_MS)), "T D C(SELECT 1) Z(I)", "pool pressure: B runs after A's Sync", m, false);
	}
	exec(g_admin, "UPDATE pgsql_servers SET max_connections=" + (max_before.empty() ? std::string("1000") : max_before) +
		" WHERE hostgroup_id=" + std::to_string(HG));
	exec(g_admin, "LOAD PGSQL SERVERS TO RUNTIME");
	reset_pool(g_admin);
}

// A released part gives its connection back: another client can take it and keep it in a transaction,
// and the group's next part then runs on a different connection. The pool starts empty, so the other
// client takes exactly the released one. Plain native clients here, as for pool pressure.
static void case_release_other_conn(Mode mode, bool) {
	const Mode m = (mode == Mode::NATIVE_UNBATCHED) ? Mode::NATIVE : mode;
	reset_pool(g_admin);
	auto a = client(m);
	auto b = client(m);
	check(run(*a, [&] { a->prepareStatement("", uniq() + "SELECT 1", false); a->describeStatement("", false); a->sendFlush(); }),
		"1 t T", "release other conn: A P D(S) H", m, false);
	check(run(*b, [&] { b->sendQuery("BEGIN"); b->sendQuery("SELECT 1"); }), "C(BEGIN) Z(T) T D C(SELECT 1) Z(T)",
		"release other conn: B takes the connection in a transaction", m, false);
	check(run(*a, [&] { a->bindStatement("", "", {}, {}, false); a->executePortal("", 0, false); a->sendSync(); }),
		"2 D C(SELECT 1) Z(I)", "release other conn: A B E S on another connection", m, false);
	check(run(*b, [&] { b->sendQuery("ROLLBACK"); }), "C(ROLLBACK) Z(I)", "release other conn: B ROLLBACK", m, false);
}

// The same with pgsql-connection_delay_multiplex_ms: a released part keeps its connection until the delay
// ends. Within it the next part runs there; once the connection is back in the pool, B can take it and
// the next part runs on another one.
static void case_release_delayed(Mode mode, bool) {
	const Mode m = (mode == Mode::NATIVE_UNBATCHED) ? Mode::NATIVE : mode;
	const std::string before = scalar(g_admin, "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-connection_delay_multiplex_ms'");
	admin_set("pgsql-connection_delay_multiplex_ms", "3000");
	reset_pool(g_admin);
	{
		auto a = client(m);
		auto b = client(m);
		const auto describe = [&] { a->prepareStatement("", uniq() + "SELECT 1", false); a->describeStatement("", false); a->sendFlush(); };
		const auto execute = [&] { a->bindStatement("", "", {}, {}, false); a->executePortal("", 0, false); a->sendSync(); };
		check(run(*a, describe), "1 t T", "release delayed: A P D(S) H", m, false);
		check(run(*a, execute), "2 D C(SELECT 1) Z(I)", "release delayed: A B E S within the delay", m, false);
		check(run(*a, describe), "1 t T", "release delayed: A P D(S) H again", m, false);
		usleep(6500000);  // past the delay and past a maintenance pass (pgsql-poll_timeout)
		check(run(*b, [&] { b->sendQuery("BEGIN"); b->sendQuery("SELECT 1"); }), "C(BEGIN) Z(T) T D C(SELECT 1) Z(T)",
			"release delayed: B takes the connection in a transaction", m, false);
		check(run(*a, execute), "2 D C(SELECT 1) Z(I)", "release delayed: A B E S on another connection", m, false);
		run(*b, [&] { b->sendQuery("ROLLBACK"); });
	}
	admin_set("pgsql-connection_delay_multiplex_ms", before.empty() ? "0" : before);
}

// The same while A keeps a connection in another hostgroup: a temporary table disables multiplexing on
// its hostgroup-0 connection, and a rule runs the group in hostgroup 9177.
static void case_release_other_hostgroup(Mode mode, bool) {
	const Mode m = (mode == Mode::NATIVE_UNBATCHED) ? Mode::NATIVE : mode;
	exec(g_admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=9177");
	exec(g_admin, "INSERT INTO pgsql_servers (hostgroup_id, hostname, port, use_ssl) SELECT 9177, hostname, port, use_ssl "
		"FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(HG) + " LIMIT 1");
	exec(g_admin, "LOAD PGSQL SERVERS TO RUNTIME");
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9177");
	exec(g_admin, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES "
		"(9177, 1, 'flush_other_hg', 9177, 1)");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	{
		auto a = client(m);
		auto b = client(m);
		check_initial(*a, DIAG_ST_RELEASE_CREATE, static_cast<int>(mode), static_cast<int>(m),
			[&] { a->sendQuery("CREATE TEMP TABLE flush_tmp (x int)"); },
			"C(CREATE TABLE) Z(I)", "release other hostgroup: A CREATE TEMP TABLE", m, false);
		check(run(*a, [&] { a->prepareStatement("", uniq() + "SELECT 'flush_other_hg'", false); a->describeStatement("", false);
				a->sendFlush(); }), "1 t T", "release other hostgroup: A P D(S) H", m, false);
		check(run(*b, [&] { b->sendQuery("BEGIN; SELECT 'flush_other_hg'"); }), "C(BEGIN) T D C(SELECT 1) Z(T)",
			"release other hostgroup: B takes the connection in a transaction", m, false);
		check(run(*a, [&] { a->bindStatement("", "", {}, {}, false); a->executePortal("", 0, false); a->sendSync(); }),
			"2 D C(SELECT 1) Z(I)", "release other hostgroup: A B E S on another connection", m, false);
		run(*b, [&] { b->sendQuery("ROLLBACK"); });
	}
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9177");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	exec(g_admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=9177");
	exec(g_admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

// A part that only parses or describes is still held when the group already holds something.
static void case_release_not(Mode m, bool) {
	const bool native = (m != Mode::LIBPQ);
	{	// in BEGIN
		auto c = client(m);
		maybe_begin(*c, true);
		const std::string mk = uniq();
		check(run(*c, [&] { c->prepareStatement("", mk + "SELECT 1", false); c->describeStatement("", false); c->sendFlush(); }),
			"1 t T", "release not, in BEGIN: P D(S) H", m, true);
		check_held(mk, true, "release not, in BEGIN", m);
		check(run(*c, [&] { c->sendSync(); }), "Z(T)", "release not, in BEGIN: S", m, true);
	}
	{	// after an INSERT held by a Flush
		auto c = client(m);
		const std::string tag = tag_for("notrel", m, false), mk = uniq();
		check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "release not, after INSERT: P B E H", m, false);
		check(run(*c, [&] { c->prepareStatement("", mk + "SELECT 1", false); c->describeStatement("", false); c->sendFlush(); }),
			"1 t T", "release not, after INSERT: P D(S) H", m, false);
		check_held(mk, true, "release not, after INSERT", m);
		ok(rows(tag) == 0, "release not, after INSERT [%s]: the INSERT is not visible before the Sync (rows=%ld)", mode_name(m), rows(tag));
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "release not, after INSERT: S", m, false);
		ok(rows(tag) == 1, "release not, after INSERT [%s]: committed by the Sync (rows=%ld)", mode_name(m), rows(tag));
	}
	if (native) {	// a named portal open
		auto c = client(m);
		const std::string mk = uniq();
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "p1", {}, {}, false); c->sendFlush(); }),
			"1 2", "release not, named portal: P B(p1) H", m, false);
		check(run(*c, [&] { c->prepareStatement("flush_np", mk + "SELECT 1", false); c->describeStatement("flush_np", false); c->sendFlush(); }),
			"1 t T", "release not, named portal: P D(S) H", m, false);
		check_held(mk, true, "release not, named portal", m);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "release not, named portal: S", m, false);
	}
	if (native) {	// a suspended unnamed portal
		auto c = client(m);
		const std::string mk = uniq();
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 2, false); c->sendFlush(); }), "1 2 D D s", "release not, suspended portal: P B E(2) H", m, false);
		check(run(*c, [&] { c->prepareStatement("flush_sp", mk + "SELECT 1", false); c->describeStatement("flush_sp", false); c->sendFlush(); }),
			"1 t T", "release not, suspended portal: P D(S) H", m, false);
		check_held(mk, true, "release not, suspended portal", m);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "release not, suspended portal: S", m, false);
	}
	if (native) {	// Describe of the portal
		auto c = client(m);
		const std::string mk = uniq();
		check(run(*c, [&] { c->prepareStatement("", mk + SER, false); c->bindStatement("", "", {}, {}, false); c->describePortal("", false);
				c->sendFlush(); }), "1 2 T", "release not, D(P): P B D(P) H", m, false);
		check_held(mk, true, "release not, D(P)", m);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "release not, D(P): S", m, false);
	}
	if (native) {	// a named Bind
		auto c = client(m);
		const std::string mk = uniq();
		check(run(*c, [&] { c->prepareStatement("", mk + SER, false); c->bindStatement("", "p2", {}, {}, false); c->sendFlush(); }),
			"1 2", "release not, named B: P B(p2) H", m, false);
		check_held(mk, true, "release not, named B", m);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "release not, named B: S", m, false);
	}
	if (native) {	// a named portal bound and closed in the same part: nothing left open, but the Bind ran
		auto c = client(m);
		const std::string mk = uniq();
		check(run(*c, [&] { c->prepareStatement("", mk + SER, false); c->bindStatement("", "p3", {}, {}, false); c->closePortal("p3", false);
				c->sendFlush(); }), "1 2 3", "release not, named C(P): P B(p3) C(P p3) H", m, false);
		check_held(mk, true, "release not, named C(P)", m);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "release not, named C(P): S", m, false);
	}
	{	// an Execute
		auto c = client(m);
		const std::string mk = uniq();
		check(run(*c, [&] { c->prepareStatement("", mk + "SELECT 1", false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 0, false); c->sendFlush(); }), "1 2 D C(SELECT 1)", "release not, E: P B E H", m, false);
		check_held(mk, true, "release not, E", m);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "release not, E: S", m, false);
	}
}

static void case_release_error(Mode m, bool) {
	auto c = client(m);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELEC 1", false); c->describeStatement("", false); c->sendFlush(); }),
		"E(42601)", "release error: P(syntax error) D(S) H", m, false);
	check(run(*c, [&] { c->sendSync(); }), "Z(I)", "release error: S", m, false);
}

// The session after a released part: the Sync, a simple Query, a failing Bind, a disconnect.
static void case_release_after(Mode m, bool) {
	{
		auto c = client(m);
		const std::string mk = uniq();
		check(run(*c, [&] { c->prepareStatement("", mk + "SELECT 1", false); c->describeStatement("", false); c->sendFlush(); }),
			"1 t T", "release after: P D(S) H", m, false);
		check_held(mk, false, "release after: P D(S) H", m);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "release after: S", m, false);
		check(run(*c, [&] { c->sendQuery("SELECT 1"); }), "T D C(SELECT 1) Z(I)", "release after: Q", m, false);
		check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT 1/0", false); c->describeStatement("", false); c->sendFlush(); }),
			"1 t T", "release after: P(1/0) D(S) H", m, false);
		check(run(*c, [&] { c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendSync(); }),
			"2 E(22012) Z(I)", "release after: B E S", m, false);
	}
	const std::string mk = uniq();
	{
		auto c = client(m);
		check(run(*c, [&] { c->prepareStatement("", mk + "SELECT 1", false); c->describeStatement("", false); c->sendFlush(); }),
			"1 t T", "release after: P D(S) H, then disconnect", m, false);
	}
	check_held(mk, false, "release after: disconnect", m);
}

// The part's last message is answered by ProxySQL: the backend work before it is still ended with a Sync.
static void case_release_trailing_local(Mode m, bool) {
	auto c = client(m);
	const std::string mk = uniq();
	check(run(*c, [&] { c->prepareStatement("", mk + "SELECT 1", false); c->describeStatement("", false);
			c->closeStatement("flush_x", false); c->sendFlush(); }), "1 t T 3", "release trailing local: P D(S) C(S x) H", m, false);
	check_held(mk, false, "release trailing local", m);
}

// ===== Teardown, idle limit, cache (spec 4.12). =====

// Row 5a: the client goes away with an INSERT held by a Flush. PostgreSQL rolls it back, so ProxySQL
// must drop that connection, not reset it for reuse (which would end the batch, committing it). The
// drop is the expected way out: no "refusing to reset" warning, which is kept for routes nobody expects.
static void case_row5a_disconnect(Mode m, bool) {
	std::fstream log;
	const bool have_log = open_file_and_seek_end(get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log", log) == EXIT_SUCCESS;
	const std::string tag = tag_for("row5a", m, false);
	{
		auto c = client(m);
		check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "row 5a: P B E(INSERT) H, then disconnect", m, false);
	}
	ok(backend_txn_open_within(tag, false, 2000) == false, "row 5a [%s]: the held transaction is gone after the disconnect", mode_name(m));
	ok(rows(tag) == 0, "row 5a [%s]: the INSERT is rolled back (rows=%ld)", mode_name(m), rows(tag));
	ok(scalar(g_admin, "SELECT 1") == "1", "row 5a [%s]: ProxySQL still answers", mode_name(m));
	ok(have_log && wait_for_log_match(log, "refusing to reset a backend left mid-batch", 500) == false,
		"row 5a [%s]: the drop logs no 'refusing to reset' warning (log %s)", mode_name(m), have_log ? "read" : "not found");
}

// The client goes away while the segment is still running on the backend. The statement runs for 10 s:
// the transaction must be gone well before that, so ProxySQL must kill it rather than leave it running.
// The client waits until the statement runs: gone before ProxySQL sent it, it proves nothing.
// A session with an untracked startup option never kills its running query on disconnect, a separate
// bug, so the unbatched mode uses a plain native client here.
static void case_disconnect_mid_segment(Mode mode, bool) {
	const Mode m = (mode == Mode::NATIVE_UNBATCHED) ? Mode::NATIVE : mode;
	const std::string tag = tag_for("midseg", m, false);
	bool started = false;
	{
		auto c = client(m);
		c->prepareStatement("", uniq() + "INSERT INTO flush_t SELECT '" + tag + "', 1 FROM pg_sleep(10)", false);
		c->bindStatement("", "", {}, {}, false);
		c->executePortal("", 0, false);
		c->sendFlush();
		started = backend_txn_open_within(tag, true, 3000);
	}
	ok(started && backend_txn_open_within(tag, false, 3000) == false, "disconnect mid segment [%s]: the running transaction is "
		"killed (started %d)", mode_name(m), (int)started);
	ok(rows(tag) == 0, "disconnect mid segment [%s]: the INSERT is rolled back (rows=%ld)", mode_name(m), rows(tag));
	ok(scalar(g_admin, "SELECT 1") == "1", "disconnect mid segment [%s]: ProxySQL still answers", mode_name(m));
}

// Row 14: a group held open by a Flush counts as a transaction for pgsql-max_transaction_idle_time.
// A group that holds nothing on a backend does not. The limit is checked once per pgsql-poll_timeout
// (5 s by default), so the client is gone at most that long after the 2 s limit.
static void case_row14_idle(Mode m, bool) {
	const std::string before = scalar(g_admin, "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-max_transaction_idle_time'");
	admin_set("pgsql-max_transaction_idle_time", "2000");
	const std::string tag = tag_for("idle", m, false);
	{
		auto c = client(m);
		check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "row 14: P B E(INSERT) H", m, false);
		std::string after;
		for (int waited = 0; waited < 9000 && after.rfind("CLOSED", 0) != 0; waited += 500) {
			after = run(*c, [] {}, 500);
		}
		ok(after.rfind("CLOSED", 0) == 0, "row 14 [%s]: the idle client was disconnected (got '%s')", mode_name(m), after.c_str());
	}
	ok(rows(tag) == 0, "row 14 [%s]: the INSERT is rolled back (rows=%ld)", mode_name(m), rows(tag));
	{
		auto c = client(m);
		const std::string q = uniq() + "SELECT 1";
		run(*c, [&] { c->prepareStatement("", q, false); c->sendSync(); });
		check(run(*c, [&] { c->prepareStatement("", q, false); c->sendFlush(); }), "1", "row 14: P(known) H", m, false);
		usleep(8000000);
		check(run(*c, [&] { c->sendSync(); }), "Z(I)", "row 14: still connected after the idle limit, S", m, false);
	}
	admin_set("pgsql-max_transaction_idle_time", before.empty() ? "14400000" : before);
}

static long long global_stat(const char* name) {
	return atoll(scalar(g_admin, std::string("SELECT Variable_Value FROM stats_pgsql_global WHERE Variable_Name='") + name + "'").c_str());
}

// Row 15: a group with a Flush in it is neither answered from nor stored in the extended query cache
// (a v3.1 feature). A session with an untracked startup option is never cached, so the unbatched mode
// uses a plain native client here.
static void case_row15_cache(Mode mode, bool) {
	const Mode m = (mode == Mode::NATIVE_UNBATCHED) ? Mode::NATIVE : mode;
	int major = 0, minor = 0;
	sscanf(scalar(g_admin, "SELECT variable_value FROM global_variables WHERE variable_name='admin-version'").c_str(), "%d.%d", &major, &minor);
	if (major < 3 || (major == 3 && minor < 1)) {
		skip(6, "row 15: no extended query cache before v3.1");
		return;
	}
	const std::string sql = "SELECT /*flush_cache_" + std::to_string((int)m) + "_" + std::to_string((long)time(nullptr)) + "*/ $1::text";
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9115");
	exec(g_admin, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, cache_ttl, apply) VALUES (9115, 1, 'flush_cache_', 60000, 1)");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	auto c = client(m);
	run(*c, [&] { c->prepareStatement("flush_cs", sql, false); c->sendSync(); });
	const long long get0 = global_stat("Query_Cache_count_GET"), set0 = global_stat("Query_Cache_count_SET");
	for (int i = 0; i < 2; i++) {
		run(*c, [&] { c->bindStatement("flush_cs", "", { { std::string("v"), 0 } }, {}, false); c->executePortal("", 0, false); c->sendFlush(); });
		run(*c, [&] { c->sendSync(); });
	}
	const long long get1 = global_stat("Query_Cache_count_GET"), set1 = global_stat("Query_Cache_count_SET");
	ok(get1 == get0 && set1 == set0, "row 15 [%s]: B E H, then S, twice: cache not read or written (GET %lld->%lld, SET %lld->%lld)",
		mode_name(m), get0, get1, set0, set1);
	run(*c, [&] { c->bindStatement("flush_cs", "", { { std::string("v"), 0 } }, {}, false); c->executePortal("", 0, false); c->sendSync(); });
	const long long set2 = global_stat("Query_Cache_count_SET");
	ok(set2 > set1, "row 15 [%s]: control, B E S stores the result (SET %lld->%lld)", mode_name(m), set1, set2);
	// A group a simple Query ends instead of a Sync must not keep the next group out of the cache: after a
	// client Flush with work held, then with nothing held, after a Query sent right behind the extended
	// messages (ProxySQL adds the Flush), and after a Query ProxySQL answers itself. That last one is a SET,
	// which changes the cache key, so it counts only the lookup.
	static const char* SHAPES[] = { "P B E(INSERT) H, Q SELECT 1", "P D(S) H, Q SELECT 1",
		"P B E(INSERT) Q(SELECT 1), no Flush", "P B E(INSERT) H, Q SET answered by ProxySQL" };
	for (int s = 0; s < 4; s++) {
		const std::string tag = tag_for("row15q", m, false);
		std::string q, want = "T D C(SELECT 1) Z(I)";
		if (s == 1) {
			run(*c, [&] { c->prepareStatement("", uniq() + "SELECT 1", false); c->describeStatement("", false); c->sendFlush(); });
		} else if (s != 2) {
			run(*c, [&] { insert_flush(*c, tag); });
		}
		const bool logged = (s == 3 && diag_enabled());
		DiagStageData local_set;
		if (s == 2) {
			q = run(*c, [&] { c->beginBuffering(); c->prepareStatement("", uniq() + "INSERT INTO flush_t VALUES ('" + tag + "', 1)", false);
				c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendQuery("SELECT 1"); c->endBuffering(); });
			want = "1 2 C(INSERT 0 1) " + want;
		} else if (s == 3) {
			if (logged) {
				local_set = read_stage(*c, DIAG_ST_ROW15_LOCAL_SET, static_cast<int>(mode), static_cast<int>(m),
					[&] { c->sendQuery("SET DateStyle = 'ISO'"); });
				q = local_set.got;
			} else {
				q = run(*c, [&] { c->sendQuery("SET DateStyle = 'ISO'"); });
			}
			want = "C(SET) Z(I)";
		} else {
			q = run(*c, [&] { c->sendQuery("SELECT 1"); });
		}
		const long long get3 = global_stat("Query_Cache_count_GET"), hit3 = global_stat("Query_Cache_count_GET_OK");
		DiagStageData cache_bes;
		if (logged) {
			cache_bes = read_stage(*c, DIAG_ST_ROW15_CACHE_BES, static_cast<int>(mode), static_cast<int>(m),
				[&] { c->bindStatement("flush_cs", "", { { std::string("v"), 0 } }, {}, false); c->executePortal("", 0, false); c->sendSync(); });
		} else {
			run(*c, [&] { c->bindStatement("flush_cs", "", { { std::string("v"), 0 } }, {}, false); c->executePortal("", 0, false); c->sendSync(); });
		}
		const long long get4 = global_stat("Query_Cache_count_GET"), hit4 = global_stat("Query_Cache_count_GET_OK");
		const bool passed = q == want && get4 == get3 + 1 && (s == 3 || hit4 == hit3 + 1);
		ok(passed,
			"row 15 [%s]: %s, then B E S %s (Q '%s', GET %lld->%lld, GET_OK %lld->%lld)", mode_name(m), SHAPES[s],
			s == 3 ? "looks in the cache" : "is answered from the cache", q.c_str(), get3, get4, hit3, hit4);
		if (logged) {
			diag_emit_stage(*c, DIAG_ST_ROW15_LOCAL_SET, DIAG_EV_STAGE,
				static_cast<int>(mode), static_cast<int>(m), local_set, DIAG_PH_NONE, local_set.closed);
			diag_emit_io_events(*c, DIAG_ST_ROW15_LOCAL_SET,
				static_cast<int>(mode), static_cast<int>(m), local_set, local_set.closed);
			diag_emit_stage(*c, DIAG_ST_ROW15_CACHE_BES, DIAG_EV_CACHE,
				static_cast<int>(mode), static_cast<int>(m), cache_bes, DIAG_PH_NONE, cache_bes.closed);
			diag_emit_io_events(*c, DIAG_ST_ROW15_CACHE_BES,
				static_cast<int>(mode), static_cast<int>(m), cache_bes, cache_bes.closed);
			const int phase = DIAG_PH_NONE;
			diag_emit_stage(*c, DIAG_ST_ROW15_ASSERT, DIAG_EV_ASSERT,
				static_cast<int>(mode), static_cast<int>(m), cache_bes, phase, cache_bes.closed,
				get3, get4, hit3, hit4);
			if (!passed && q.empty())
				diag_passive_peek(*c, DIAG_ST_ROW15_ASSERT, static_cast<int>(mode), static_cast<int>(m),
					local_set.send_end_us);
		}
	}
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9115");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	exec(g_admin, "PROXYSQL FLUSH PGSQL QUERY CACHE");
}

// ===== A simple Query inside the group's transaction (spec 4.7). =====

// Rows 11, 11-in-txn: the Query runs in the transaction the group opened and ends it, as in
// PostgreSQL. The named portal is native only (libpq mode refuses named portals).
static void case_row11(Mode m, bool txn) {
	const bool native = (m != Mode::LIBPQ);
	auto c = client(m);
	maybe_begin(*c, txn);
	const std::string tag = tag_for("row11", m, txn);
	check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "row 11: P B E(INSERT) H", m, txn);
	if (native) {
		check(run(*c, [&] { c->prepareStatement("flush_s1", uniq() + "SELECT 42 AS v", false); c->bindStatement("flush_s1", "p1", {}, {}, false);
				c->sendFlush(); }), "1 2", "row 11: P(s1) B(p1) H", m, txn);
	}
	check_initial(*c, DIAG_ST_ROW11_SELECT42, static_cast<int>(m), static_cast<int>(m),
		[&] { c->sendQuery("SELECT 42"); },
		std::string("T D C(SELECT 1) Z(") + txn_z(txn) + ")", "row 11: Q SELECT 42", m, txn);
	ok(rows(tag) == (txn ? 0 : 1), "row 11 [%s%s]: the INSERT is %s (rows=%ld)", mode_name(m), txn ? ", in txn" : "",
		txn ? "still in the open transaction" : "committed by the Query", rows(tag));
	if (native) {
		check_logged(*c, DIAG_ST_ROW11_NATIVE_PORTAL, DIAG_EV_PORTAL,
			static_cast<int>(m), static_cast<int>(m),
			[&] { c->executePortal("p1", 0, false); c->sendSync(); },
			txn ? "D C(SELECT 1) Z(T)" : "E(34000) Z(I)", "row 11: E(p1) S", m, txn);
	}
	if (txn) run(*c, [&] { c->sendQuery("ROLLBACK"); });
}

// Row 11b: the Query fails: the whole transaction, the INSERT with it, is rolled back.
static void case_row11b(Mode m, bool) {
	auto c = client(m);
	const std::string tag = tag_for("row11b", m, false);
	check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "row 11b: P B E(INSERT) H", m, false);
	check(run(*c, [&] { c->sendQuery("SELECT 1/0"); }), "E(22012) Z(I)", "row 11b: Q SELECT 1/0", m, false);
	ok(rows(tag) == 0, "row 11b [%s]: the INSERT is rolled back (rows=%ld)", mode_name(m), rows(tag));
}

// A Query ProxySQL answers itself (a tracked SET) ends the group as a successful Query would.
static void case_row11_local(Mode m, bool) {
	auto c = client(m);
	const std::string tag = tag_for("row11l", m, false);
	check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "row 11 local: P B E(INSERT) H", m, false);
	check(run(*c, [&] { c->sendQuery("SET DateStyle = 'ISO'"); }), "C(SET) Z(I)", "row 11 local: Q SET DateStyle", m, false);
	ok(rows(tag) == 1, "row 11 local [%s]: the INSERT is committed (rows=%ld)", mode_name(m), rows(tag));
}

// A Query ProxySQL refuses (a rule's error_msg) ends the group as a failed Query would.
static void case_row11_refused(Mode m, bool) {
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9111");
	exec(g_admin, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES "
		"(9111, 1, 'flush_q_refused', 'refused by flush test rule', 1)");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	auto c = client(m);
	const std::string tag = tag_for("row11r", m, false);
	check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "row 11 refused: P B E(INSERT) H", m, false);
	check(run(*c, [&] { c->sendQuery("SELECT 'flush_q_refused'"); }), "E(42501) Z(I)", "row 11 refused: Q refused by a rule", m, false);
	ok(rows(tag) == 0, "row 11 refused [%s]: the INSERT is rolled back (rows=%ld)", mode_name(m), rows(tag));
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9111");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
}

// A COPY as the Query.
static void case_row11_copy(Mode m, bool) {
	auto c = client(m);
	const std::string tag = tag_for("row11c", m, false);
	check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "row 11 copy: P B E(INSERT) H", m, false);
	check(run(*c, [&] { c->sendQuery("COPY (SELECT 7) TO STDOUT"); }), "H d c C(COPY 1) Z(I)", "row 11 copy: Q COPY TO STDOUT", m, false);
	ok(rows(tag) == 1, "row 11 copy [%s]: the INSERT is committed (rows=%ld)", mode_name(m), rows(tag));
}

// Rows 11d, 11e: the Query right behind the extended messages, in the same write, with no Flush. It
// runs in their transaction; after an error it is ignored until the Sync.
static void case_row11de(Mode m, bool) {
	auto c = client(m);
	const std::string tag = tag_for("row11d", m, false), tag2 = tag_for("row11ok", m, false);
	check(run(*c, [&] { c->beginBuffering(); c->prepareStatement("", uniq() + "INSERT INTO flush_t VALUES ('" + tag + "', 1)", false);
			c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendQuery("SELECT 1/0"); c->endBuffering(); }),
		"1 2 C(INSERT 0 1) E(22012) Z(I)", "row 11d: P B E(INSERT) Q(SELECT 1/0)", m, false);
	ok(rows(tag) == 0, "row 11d [%s]: the INSERT is rolled back with the failed Query (rows=%ld)", mode_name(m), rows(tag));
	check(run(*c, [&] { c->beginBuffering(); c->prepareStatement("", uniq() + EXEC_ERR, false); c->bindStatement("", "", {}, {}, false);
			c->executePortal("", 0, false); c->sendQuery("SELECT 42"); c->endBuffering(); }),
		"1 2 E(22012)", "row 11e: P B E(error) Q: the Query is ignored", m, false);
	check(run(*c, [&] { c->sendSync(); }), "Z(I)", "row 11e: S", m, false);
	check(run(*c, [&] { c->beginBuffering(); c->prepareStatement("", uniq() + "INSERT INTO flush_t VALUES ('" + tag2 + "', 1)", false);
			c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendQuery("SELECT 42"); c->endBuffering(); }),
		"1 2 C(INSERT 0 1) T D C(SELECT 1) Z(I)", "row 11: P B E(INSERT) Q(SELECT 42)", m, false);
	ok(rows(tag2) == 1, "row 11 [%s]: the INSERT is committed with the Query (rows=%ld)", mode_name(m), rows(tag2));
}

// A tracked SET as an extended statement inside the group, then a simple Query. The SET must not end
// the group's transaction on its way to the backend: the Query decides, committing everything or, when
// it fails, nothing.
static void case_row11_var(Mode m, bool) {
	auto c = client(m);
	for (int good = 0; good < 2; good++) {
		const std::string tag = tag_for(good ? "row11vok" : "row11v", m, false);
		check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "row 11 var: P B E(INSERT) H", m, false);
		const std::string set = run(*c, [&] { c->prepareStatement("", good ? "SET DateStyle = 'ISO, MDY'" : "SET DateStyle = 'SQL, DMY'", false);
			c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush(); });
		ok(set.size() >= 6 && set.compare(set.size() - 6, 6, "C(SET)") == 0, "row 11 var [%s]: P B E(SET DateStyle) H (got '%s')",
			mode_name(m), set.c_str());
		if (good) {
			check_initial(*c, DIAG_ST_ROW11_VAR_GOOD, static_cast<int>(m), static_cast<int>(m),
				[&] { c->sendQuery("SELECT 1"); }, "T D C(SELECT 1) Z(I)",
				"row 11 var: Q SELECT 1", m, false);
		} else {
			check(run(*c, [&] { c->sendQuery("SELECT 1/0"); }), "E(22012) Z(I)",
				"row 11 var: Q SELECT 1/0", m, false);
		}
		ok(rows(tag) == good, "row 11 var [%s]: the INSERT is %s (rows=%ld)", mode_name(m), good ? "committed" : "rolled back", rows(tag));
	}
}

// The held backend dies while the Query runs on it: the Query must not be run again alone on another
// connection, which would report success while the INSERT is gone. The backend is killed only once
// the Query runs there: killed while the client is idle, ProxySQL closes the client and no retry is
// ever considered. Retries are switched on, or none would happen either way. The reply is read until
// 8 s of quiet, longer than a retried 5 s sleep, so a retry's success cannot be missed.
static void case_retry_refused(Mode m, bool) {
	const std::string retries_before = scalar(g_admin, "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-query_retries_on_failure'");
	admin_set("pgsql-query_retries_on_failure", "1");
	auto c = client(m);
	const std::string tag = tag_for("retry", m, false);
	check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "retry refused: P B E(INSERT) H", m, false);
	const std::string mk = uniq();
	std::string got;
	bool running = false;
	try {
		c->sendQuery(mk + "SELECT pg_sleep(5)");
		for (int waited = 0; waited < 4000 && running == false; waited += 50) {
			running = scalar(g_be, "SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND pid <> pg_backend_pid() "
				"AND query LIKE '%" + mk + "%'") == "1";
			if (running == false) usleep(50000);
		}
		exec(g_be, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND query LIKE '%" + mk + "%'");
		got = tokens(c->readUntilQuiet(8000));
	} catch (const PgException& e) {
		got = std::string("CLOSED:") + e.what();
	}
	ok(running && got != "T D C(SELECT 1) Z(I)", "retry refused [%s]: the Query is not run again alone after its backend "
		"died under it (running %d, got '%s')", mode_name(m), (int)running, got.c_str());
	ok(rows(tag) == 0, "retry refused [%s]: the INSERT is gone (rows=%ld)", mode_name(m), rows(tag));
	admin_set("pgsql-query_retries_on_failure", retries_before.empty() ? "1" : retries_before);
}

// ===== A Flush in a poisoned session (spec 4.8, row 9). =====

// Poisons the session as pgsql-tx_poisoned_extended_query-t does: with
// pgsql-preserve_client_on_broken_backend_in_tx on, the backend of an open transaction is killed, and
// the client stays connected in a failed transaction that ProxySQL itself answers.
// A session locked to its hostgroup does not track BEGIN, so it is closed instead of poisoned: the
// unbatched mode's startup option locks it, so the row 9 cases use a plain native client there.
static std::unique_ptr<PgConnection> poison_client(Mode m) {
	return client(m == Mode::NATIVE_UNBATCHED ? Mode::NATIVE : m);
}
static void poison(PgConnection& c, Mode m) {
	const std::string before = scalar(g_admin, "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-preserve_client_on_broken_backend_in_tx'");
	admin_set("pgsql-preserve_client_on_broken_backend_in_tx", "true");
	const std::string mk = uniq();
	run(c, [&] { c.sendQuery("BEGIN"); });
	c.sendQuery(mk + "SELECT pg_sleep(3)");
	usleep(500000);
	exec(g_be, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND query LIKE '%" + mk + "%'");
	const std::string r = run(c, [] {}, 1000);
	ok(r == "E(25P02) Z(E)", "row 9 [%s]: the session is poisoned (got '%s')", mode_name(m), r.c_str());
	admin_set("pgsql-preserve_client_on_broken_backend_in_tx", before.empty() ? "false" : before);
}

// A frame that is not a transaction end: 25P02 at the Flush, no ReadyForQuery, discard until the Sync.
static void case_row9_refused(Mode m, bool) {
	auto c = poison_client(m);
	poison(*c, m);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT 1", false); c->describeStatement("", false); c->sendFlush(); }),
		"E(25P02)", "row 9 refused: P D(S) H", m, false);
	check(run(*c, [&] { c->sendSync(); }), "Z(E)", "row 9 refused: S", m, false);
	check(run(*c, [&] { c->sendQuery("ROLLBACK"); }), "C(ROLLBACK) Z(I)", "row 9 refused: ROLLBACK recovers", m, false);
}

// A ROLLBACK executed before the Flush ends the transaction there; the group goes on.
static void case_row9_rollback_exec(Mode m, bool) {
	auto c = poison_client(m);
	poison(*c, m);
	check(run(*c, [&] { c->prepareStatement("", "ROLLBACK", false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false);
			c->sendFlush(); }), "1 2 C(ROLLBACK)", "row 9 rollback: P(ROLLBACK) B E H", m, false);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT 1", false); c->bindStatement("", "", {}, {}, false);
			c->executePortal("", 0, false); c->sendFlush(); }), "1 2 D C(SELECT 1)", "row 9 rollback: P B E H after it", m, false);
	check(run(*c, [&] { c->sendSync(); }), "Z(I)", "row 9 rollback: S", m, false);
}

// A ROLLBACK parsed and described before the Flush, executed after it.
static void case_row9_rollback_describe(Mode m, bool) {
	auto c = poison_client(m);
	poison(*c, m);
	check(run(*c, [&] { c->prepareStatement("", "ROLLBACK", false); c->describeStatement("", false); c->sendFlush(); }), "1 t n",
		"row 9 describe: P(ROLLBACK) D(S) H", m, false);
	check(run(*c, [&] { c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendSync(); }),
		"2 C(ROLLBACK) Z(I)", "row 9 describe: B E S", m, false);
}

// A named ROLLBACK parsed at a Flush stays defined after a Sync with no Execute, as in PostgreSQL.
static void case_row9_named_kept(Mode m, bool) {
	auto c = poison_client(m);
	poison(*c, m);
	const std::string name = "flush_r1_" + std::to_string((long)time(nullptr));
	check(run(*c, [&] { c->prepareStatement(name, "ROLLBACK", false); c->sendFlush(); }), "1", "row 9 named: P(r1, ROLLBACK) H", m, false);
	check(run(*c, [&] { c->sendSync(); }), "Z(E)", "row 9 named: S", m, false);
	check(run(*c, [&] { c->bindStatement(name, "", {}, {}, false); c->executePortal("", 0, false); c->sendSync(); }),
		"2 C(ROLLBACK) Z(I)", "row 9 named: B(r1) E S", m, false);
}

// Every client reference to a prepared statement, summed over all statements.
static long stmt_client_refs() {
	return atol(scalar(g_admin, "SELECT IFNULL(SUM(ref_count_client),0) FROM stats_pgsql_prepared_statements_info").c_str());
}

// The unnamed statement, used before the backend died, Parsed again as ROLLBACK at a Flush: the ROLLBACK
// replaces it, as in PostgreSQL. It used to be counted but not stored, so the Execute ran the old
// statement and was refused, and the count was never given back.
static void case_row9_unnamed_reused(Mode m, bool) {
	// Sessions of earlier cases may still be closing: wait for the count to settle.
	long before = stmt_client_refs();
	for (int i = 0; i < 20; i++) {
		usleep(100000);
		const long now = stmt_client_refs();
		if (now == before) break;
		before = now;
	}
	{
		auto c = poison_client(m);
		check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT 65", false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 0, false); c->sendSync(); }), "1 2 D C(SELECT 1) Z(I)", "row 9 unnamed reused: P(\"\") B E S", m, false);
		poison(*c, m);
		check(run(*c, [&] { c->prepareStatement("", "ROLLBACK", false); c->sendFlush(); }), "1",
			"row 9 unnamed reused: P(\"\", ROLLBACK) H", m, false);
		check(run(*c, [&] { c->sendSync(); }), "Z(E)", "row 9 unnamed reused: S", m, false);
		check(run(*c, [&] { c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendSync(); }),
			"2 C(ROLLBACK) Z(I)", "row 9 unnamed reused: B E S", m, false);
	}
	long after = stmt_client_refs();
	for (int i = 0; i < 30 && after != before; i++) {
		usleep(100000);
		after = stmt_client_refs();
	}
	ok(after == before, "row 9 unnamed reused [%s]: the client's statement references are given back (before %ld, after %ld)",
		mode_name(m), before, after);
}

// ===== Simple Queries in a held group that ProxySQL used to answer itself (final review). =====

// COMMIT, ROLLBACK and ABORT end the group's transaction on the backend: PostgreSQL commits the held
// INSERT at COMMIT and rolls it back at ROLLBACK or ABORT (with a 25P01 notice, not shown here).
static void case_group_txn_end(Mode m, bool) {
	struct Sub { const char* q; const char* reply; long rows; };
	const Sub subs[] = { { "ROLLBACK", "C(ROLLBACK) Z(I)", 0 }, { "ABORT", "C(ROLLBACK) Z(I)", 0 }, { "COMMIT", "C(COMMIT) Z(I)", 1 } };
	for (const Sub& sub : subs) {
		auto c = client(m);
		const std::string tag = tag_for("txnend", m, false) + sub.q;
		check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "group txn end: P B E(INSERT) H", m, false);
		check(run(*c, [&] { c->sendQuery(sub.q); }), sub.reply, (std::string("group txn end: Q ") + sub.q).c_str(), m, false);
		ok(rows(tag) == sub.rows, "group txn end [%s]: after %s the INSERT is %s (rows=%ld)", mode_name(m), sub.q,
			sub.rows ? "committed" : "rolled back", rows(tag));
	}
}

// DISCARD ALL cannot run in the transaction the group opened: refused, the group rolled back.
static void case_group_discard_all(Mode m, bool) {
	auto c = client(m);
	const std::string tag = tag_for("discard", m, false);
	check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "group DISCARD ALL: P B E(INSERT) H", m, false);
	check(run(*c, [&] { c->sendQuery("DISCARD ALL"); }), "E(25001) Z(I)", "group DISCARD ALL: Q DISCARD ALL", m, false);
	ok(rows(tag) == 0, "group DISCARD ALL [%s]: the INSERT is rolled back (rows=%ld)", mode_name(m), rows(tag));
	check(run(*c, [&] { c->sendQuery("SELECT 1"); }), "T D C(SELECT 1) Z(I)", "group DISCARD ALL: the next Query", m, false);
}

// A tracked SET whose value differs from the backend's: answered by ProxySQL, the group committed, and
// the value reaches the backend before the next statement.
static void case_group_tracked_set(Mode m, bool) {
	auto c = client(m);
	const std::string tag = tag_for("tzset", m, false);
	check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "group SET: P B E(INSERT) H", m, false);
	check(run(*c, [&] { c->sendQuery("SET TimeZone = 'Asia/Tokyo'"); }), "C(SET) Z(I)", "group SET: Q SET TimeZone", m, false);
	ok(rows(tag) == 1, "group SET [%s]: the INSERT is committed (rows=%ld)", mode_name(m), rows(tag));
	std::string tz;
	try { c->sendQuery("SELECT current_setting('TimeZone')"); tz = first_value(c->readUntilQuiet(QUIET_MS)); }
	catch (const PgException& e) { tz = std::string("CLOSED:") + e.what(); }
	ok(tz == "Asia/Tokyo", "group SET [%s]: the backend runs the next statement with it (TimeZone '%s')", mode_name(m), tz.c_str());
}

// A Query that locks the session to a hostgroup (a multi-statement SET) and that a rule sends to
// another hostgroup. It belongs to the group's transaction, so it runs on the held connection and the
// rule's hostgroup does not apply. It used to be dropped, the INSERT committed by ProxySQL's own Sync;
// in a session already locked (the unbatched client's startup option locks it) it was refused, the
// INSERT rolled back.
static void case_group_lock_route(Mode m, bool) {
	exec(g_admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=9164");
	exec(g_admin, "INSERT INTO pgsql_servers (hostgroup_id, hostname, port, use_ssl) SELECT 9164, hostname, port, use_ssl "
		"FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(HG) + " LIMIT 1");
	exec(g_admin, "LOAD PGSQL SERVERS TO RUNTIME");
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9164");
	exec(g_admin, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES "
		"(9164, 1, 'flush_lock_route', 9164, 1)");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	auto c = client(m);
	const std::string tag = tag_for("lockroute", m, false);
	check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "group lock route: P B E(INSERT) H", m, false);
	check_initial(*c, DIAG_ST_GROUP_LOCK_ROUTE, static_cast<int>(m), static_cast<int>(m),
		[&] { c->sendQuery("SET application_name = 'flush_lock_route'; SELECT 64"); },
		"C(SET) T D C(SELECT 1) Z(I)", "group lock route: Q SET ...; SELECT 64", m, false);
	ok(rows(tag) == 1, "group lock route [%s]: the INSERT is committed with the Query (rows=%ld)", mode_name(m), rows(tag));
	exec(g_admin, "DELETE FROM pgsql_query_rules WHERE rule_id=9164");
	exec(g_admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	exec(g_admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=9164");
	exec(g_admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

// COPY FROM STDIN as the Query. Then, inside BEGIN, a statement ProxySQL answers itself must still
// get its ReadyForQuery: the connection must know the COPY's ReadyForQuery ended the held work.
static void case_group_copy_in(Mode m, bool) {
	for (int txn = 0; txn < 2; txn++) {
		auto c = client(m);
		maybe_begin(*c, txn);
		const std::string tag = tag_for("copyin", m, txn), tag2 = tag + "_copied";
		const std::string z = std::string("Z(") + txn_z(txn) + ")";
		check(run(*c, [&] { insert_flush(*c, tag); }), "1 2 C(INSERT 0 1)", "group COPY: P B E(INSERT) H", m, txn);
		check(run(*c, [&] { c->sendQuery("COPY flush_t FROM STDIN"); }), "G", "group COPY: Q COPY FROM STDIN", m, txn);
		const std::string line = tag2 + "\t1\n";
		check(run(*c, [&] { c->sendMessage('d', std::vector<uint8_t>(line.begin(), line.end())); c->sendMessage('c', {}); }),
			"C(COPY 1) " + z, "group COPY: CopyData CopyDone", m, txn);
		if (txn) {
			check(run(*c, [&] { c->sendQuery("SET DateStyle = 'SQL, DMY'"); }), "C(SET) Z(T)", "group COPY: a SET answered by ProxySQL", m, txn);
			check(run(*c, [&] { c->sendQuery("COMMIT"); }), "C(COMMIT) Z(I)", "group COPY: COMMIT", m, txn);
		}
		ok(rows(tag) == 1 && rows(tag2) == 1, "group COPY [%s%s]: the INSERT and the copied row are committed (rows %ld, %ld)",
			mode_name(m), txn ? ", in txn" : "", rows(tag), rows(tag2));
	}
}

// An error ProxySQL raises itself in a part ended with Flush leaves its ReadyForQuery to the client's
// Sync, so the Sync gets exactly one: a pg_cancel_backend() whose parameter is not a number, and a
// DISCARD ALL refused in a group already holding an INSERT.
static void case_local_error_one_ready(Mode m, bool) {
	struct Sub { const char* what; bool hold_insert; std::function<void(PgConnection&)> send; };
	const Sub subs[] = {
		{ "pg_cancel_backend('abc')", false, [](PgConnection& c) {
			c.prepareStatement("", uniq() + "SELECT pg_cancel_backend($1)", false);
			c.bindStatement("", "", { PgConnection::Param{ std::string("abc"), 0 } }, {}, false);
			c.executePortal("", 0, false); } },
		{ "DISCARD ALL after a held INSERT", true, [](PgConnection& c) {
			c.prepareStatement("", uniq() + "DISCARD ALL", false);
			c.bindStatement("", "", {}, {}, false);
			c.executePortal("", 0, false); } },
	};
	for (const Sub& sub : subs) {
		auto c = client(m);
		if (sub.hold_insert) run(*c, [&] { insert_flush(*c, tag_for("localready", m, false)); });
		const std::string flushed = run(*c, [&] { sub.send(*c); c->sendFlush(); });
		const std::string synced = run(*c, [&] { c->sendSync(); });
		const bool one = flushed.find("E(") != std::string::npos && flushed.find("Z(") == std::string::npos &&
			synced.size() == 4 && synced.rfind("Z(", 0) == 0;
		ok(one, "local error, then S: %s [%s]: the error at H without ReadyForQuery, one at S (H: '%s', S: '%s')",
			sub.what, mode_name(m), flushed.c_str(), synced.c_str());
	}
}

struct Case {
	const char* name;
	int checks;        // ok() calls per (mode, txn) run
	int checks_libpq;  // the same in libpq mode, where some behaviour is out of scope by design
	bool both_txn;     // also run inside BEGIN
	std::function<void(Mode, bool)> fn;
};

static const std::vector<Case> CASES = {
	{ "sync control",                2,  2, true,  case_sync_control },
	{ "row 1",                       2,  2, true,  case_row1 },
	{ "describe portal, no execute", 2,  1, true,  case_describe_portal_no_execute },
	{ "unnamed row limit",           10, 2, false, case_unnamed_row_limit },
	{ "unnamed exhausted",           24, 0, false, case_unnamed_exhausted },
	{ "row 2",                       2,  2, true,  case_row2 },
	{ "row 3a",                      4,  1, true,  case_row3a },
	{ "row 3b",                      4,  0, true,  case_row3b },
	{ "row 4",                       2,  0, true,  case_row4 },
	{ "row 10",                      4,  4, true,  case_row10 },
	{ "row 12",                      6,  6, false, case_row12 },
	{ "pin across delay multiplex",  4,  4, false, case_pin_delay_multiplex },
	{ "row 16 stats",                1,  1, false, case_row16_stats },
	{ "one write",                   1,  1, true,  case_one_write },
	{ "large result",                2,  2, false, case_large_result },
	{ "mode flip mid group",         0,  3, false, case_mode_flip_mid_group },
	{ "long cursor",                 3,  0, false, case_long_cursor },
	{ "row 5c/5d",                   7,  7, true,  case_row5cd },
	{ "row 6",                       7,  7, true,  case_row6 },
	{ "row 6b",                      4,  0, true,  case_row6b },
	{ "row 7 local",                 10, 10, true, case_row7_local },
	{ "row 7 rules",                 9,  5, true,  case_row7_rules },
	{ "row 8 connect",               3,  3, false, case_row8_connect },
	{ "release postgres.js",         3,  3, false, case_release_postgresjs },
	{ "release shapes",              7,  7, false, case_release_shapes },
	{ "release pool pressure",       6,  6, false, case_release_pool_pressure },
	{ "release other conn",          4,  4, false, case_release_other_conn },
	{ "release delayed",             5,  5, false, case_release_delayed },
	{ "release other hostgroup",     4,  4, false, case_release_other_hostgroup },
	{ "release not",                 29, 12, false, case_release_not },
	{ "release error",               2,  2, false, case_release_error },
	{ "release after",               8,  8, false, case_release_after },
	{ "release trailing local",      2,  2, false, case_release_trailing_local },
	{ "row 5a disconnect",           5,  5, false, case_row5a_disconnect },
	{ "disconnect mid segment",      3,  3, false, case_disconnect_mid_segment },
	{ "row 14 idle",                 5,  5, false, case_row14_idle },
	{ "row 15 cache",                6,  6, false, case_row15_cache },
	{ "row 11",                      5,  3, true,  case_row11 },
	{ "row 11b",                     3,  3, false, case_row11b },
	{ "row 11 local",                3,  3, false, case_row11_local },
	{ "row 11 refused",              3,  3, false, case_row11_refused },
	{ "row 11 copy",                 3,  3, false, case_row11_copy },
	{ "retry refused",               3,  3, false, case_retry_refused },
	{ "row 11d/11e",                 6,  6, false, case_row11de },
	{ "row 11 var",                  8,  8, false, case_row11_var },
	{ "row 9 refused",               4,  4, false, case_row9_refused },
	{ "row 9 rollback exec",         4,  4, false, case_row9_rollback_exec },
	{ "row 9 rollback describe",     3,  3, false, case_row9_rollback_describe },
	{ "row 9 named kept",            4,  4, false, case_row9_named_kept },
	{ "row 9 unnamed reused",        6,  6, false, case_row9_unnamed_reused },
	{ "group txn end",               9,  9, false, case_group_txn_end },
	{ "group DISCARD ALL",           4,  4, false, case_group_discard_all },
	{ "group tracked SET",           4,  4, false, case_group_tracked_set },
	{ "group lock route",            3,  3, false, case_group_lock_route },
	{ "group COPY FROM STDIN",       10, 10, false, case_group_copy_in },
	{ "local error one ready",        2,  2, false, case_local_error_one_ready },
};

static const Mode MODES[] = { Mode::LIBPQ, Mode::NATIVE, Mode::NATIVE_UNBATCHED };

int main(int, char**) {
	if (cl.getEnv()) return exit_status();

	// FLUSH_ONLY=<text> runs only the cases whose name contains it.
	const char* only = getenv("FLUSH_ONLY");
	auto selected = [only](const Case& k) { return only == nullptr || strstr(k.name, only) != nullptr; };
	int total = 0;
	for (const Mode m : MODES) {
		total += 1;  // the mode-switch check
		for (const Case& k : CASES) {
			if (selected(k)) total += (m == Mode::LIBPQ ? k.checks_libpq : k.checks) * (k.both_txn ? 2 : 1);
		}
	}
	plan(total);

	// Enabled only for an actual FLUSH_DIAG_PASSIVE=1 child; the start record carries the real budget.
	diag_start();

	auto admin = open_conn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");
	const std::string native_before = scalar(admin.get(), "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-use_native_backend_protocol'");

	auto be = backend();
	if (!be || PQstatus(be.get()) != CONNECTION_OK) BAIL_OUT("no direct backend connection");
	g_admin = admin.get();
	g_be = be.get();
	exec(g_be, "DROP TABLE IF EXISTS flush_t");
	if (!exec(g_be, "CREATE TABLE flush_t (tag text, v int)"))
		BAIL_OUT("could not create flush_t");
	exec(g_be, std::string("GRANT ALL ON flush_t TO ") + cl.pgsql_username);

	std::string prev_pid;
	for (const Mode m : MODES) {
		const bool switched = set_mode(admin.get(), m);
		std::string pid;
		{
			auto c = client(m);
			pid = proxy_pid(*c);
		}
		ok(switched && !pid.empty() && pid != prev_pid, "mode %s in effect on a new backend (pid %s, previous %s)",
			mode_name(m), pid.c_str(), prev_pid.empty() ? "-" : prev_pid.c_str());
		prev_pid = pid;
		for (const Case& k : CASES) {
			if (selected(k) == false) continue;
			for (int t = 0; t < (k.both_txn ? 2 : 1); t++) {
				try {
					k.fn(m, t == 1);
				} catch (const PgException& e) {
					diag("%s [%s]: %s", k.name, mode_name(m), e.what());
				}
			}
		}
	}

	exec(g_be, "DROP TABLE IF EXISTS flush_t");
	exec(admin.get(), "SET pgsql-use_native_backend_protocol='" + (native_before.empty() ? std::string("false") : native_before) + "'");
	exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	diag_finalize();
	return exit_status();
}
