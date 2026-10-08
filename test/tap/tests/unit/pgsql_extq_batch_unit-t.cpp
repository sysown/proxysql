/**
 * @file pgsql_extq_batch_unit-t.cpp
 * @brief Unit tests for PgSQL_Extq_Registry, which matches a native backend's replies to a
 *        batch of extended-query messages sent in one write.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Extq_Batch.h"

#include <string>
#include <vector>

static const std::string PARSE_OK("1\0\0\0\4", 5);
static const std::string CLOSE_OK("3\0\0\0\4", 5);

static Extq_Slot slot(Extq_Kind k, Extq_Reply r, uint32_t entry, const std::string& bytes = "") {
	return { k, r, entry, bytes };
}

// Feeds one backend message; payload is the message body.
static Extq_Verdict feed(PgSQL_Extq_Registry& reg, char type, const std::string& payload, std::string& out) {
	return reg.on_message(type, (const unsigned char*)payload.data(), (uint32_t)payload.size(), out);
}

static std::vector<Extq_Event> events(PgSQL_Extq_Registry& reg) {
	std::vector<Extq_Event> v;
	Extq_Event ev;
	while (reg.next_event(ev)) v.push_back(ev);
	return v;
}

// P(known, local) B E S: the local ParseComplete goes first, the rest is relayed, rows counted.
static void test_plain_unit() {
	PgSQL_Extq_Registry reg;
	reg.push(slot(Extq_Kind::PARSE, Extq_Reply::LOCAL, 0, PARSE_OK));
	reg.push(slot(Extq_Kind::BIND, Extq_Reply::RELAY, 1));
	reg.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 2));
	ok(reg.needs_backend(), "plain: needs the backend");
	std::string out;
	reg.start(out);
	ok(out == PARSE_OK, "plain: local ParseComplete due before any backend reply");
	reg.push(slot(Extq_Kind::SYNC, Extq_Reply::RELAY, 3));
	out.clear();
	ok(feed(reg, '2', "", out) == Extq_Verdict::RELAY, "plain: BindComplete relayed");
	ok(feed(reg, 'D', "x", out) == Extq_Verdict::RELAY && feed(reg, 'D', "y", out) == Extq_Verdict::RELAY,
		"plain: DataRows relayed");
	ok(feed(reg, 'C', std::string("SELECT 2\0", 9), out) == Extq_Verdict::RELAY, "plain: CommandComplete relayed");
	ok(reg.complete() == false, "plain: not complete before ReadyForQuery");
	ok(feed(reg, 'Z', "I", out) == Extq_Verdict::RELAY && reg.complete(), "plain: ReadyForQuery relayed, complete");
	auto ev = events(reg);
	ok(ev.size() == 3 && ev[2].kind == Extq_Kind::EXECUTE && ev[2].rows == 2 && ev[2].outcome == Extq_Outcome::OK,
		"plain: three events, Execute with 2 rows");
	ok(out.empty(), "plain: nothing local after the start");
}

// P1 B1 E1 P2(local) B2 E2 S: P2's ParseComplete waits for E1's CommandComplete.
static void test_local_reply_ordering() {
	PgSQL_Extq_Registry reg;
	reg.push(slot(Extq_Kind::PARSE, Extq_Reply::RELAY, 0));
	reg.push(slot(Extq_Kind::BIND, Extq_Reply::RELAY, 1));
	reg.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 2));
	reg.push(slot(Extq_Kind::PARSE, Extq_Reply::LOCAL, 3, PARSE_OK));
	reg.push(slot(Extq_Kind::BIND, Extq_Reply::RELAY, 4));
	reg.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 5));
	reg.push(slot(Extq_Kind::SYNC, Extq_Reply::RELAY, 6));
	std::string out;
	reg.start(out);
	ok(out.empty(), "ordering: nothing local before the first backend reply");
	feed(reg, '1', "", out);
	feed(reg, '2', "", out);
	ok(out.empty(), "ordering: local reply still waits after BindComplete");
	feed(reg, 'C', std::string("SELECT 0\0", 9), out);
	ok(out == PARSE_OK, "ordering: local ParseComplete comes right after E1's CommandComplete");
}

// An error at E1 skips everything up to the Sync, ProxySQL's own replies included.
static void test_error_skips_rest() {
	PgSQL_Extq_Registry reg;
	reg.push(slot(Extq_Kind::BIND, Extq_Reply::RELAY, 0));
	reg.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 1));
	reg.push(slot(Extq_Kind::PARSE, Extq_Reply::LOCAL, 2, PARSE_OK));
	reg.push(slot(Extq_Kind::BIND, Extq_Reply::RELAY, 3));
	reg.push(slot(Extq_Kind::SYNC, Extq_Reply::RELAY, 4));
	std::string out;
	reg.start(out);
	feed(reg, '2', "", out);
	ok(feed(reg, 'E', "err", out) == Extq_Verdict::RELAY, "error: ErrorResponse relayed");
	ok(feed(reg, 'D', "x", out) == Extq_Verdict::BAD, "error: only ReadyForQuery may follow an error");
	PgSQL_Extq_Registry reg2;
	reg2.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 0));
	reg2.push(slot(Extq_Kind::PARSE, Extq_Reply::LOCAL, 1, PARSE_OK));
	reg2.push(slot(Extq_Kind::SYNC, Extq_Reply::RELAY, 2));
	out.clear();
	reg2.start(out);
	feed(reg2, 'E', "err", out);
	ok(feed(reg2, 'Z', "I", out) == Extq_Verdict::RELAY && reg2.complete(), "error: ReadyForQuery ends the batch");
	ok(out.empty(), "error: the skipped local ParseComplete is never sent");
	auto ev = events(reg2);
	ok(ev.size() == 2 && ev[0].outcome == Extq_Outcome::ERROR && ev[1].outcome == Extq_Outcome::SKIPPED,
		"error: failed then skipped events");
}

// ProxySQL's own Parse: success dropped, error relayed and charged to the client message.
static void test_own_parse() {
	PgSQL_Extq_Registry reg;
	reg.push(slot(Extq_Kind::PARSE, Extq_Reply::DROP, 0));
	reg.push(slot(Extq_Kind::BIND, Extq_Reply::RELAY, 0));
	reg.push(slot(Extq_Kind::SYNC, Extq_Reply::RELAY, 1));
	std::string out;
	reg.start(out);
	ok(feed(reg, '1', "", out) == Extq_Verdict::DROP, "own parse: ParseComplete dropped");
	ok(feed(reg, '2', "", out) == Extq_Verdict::RELAY, "own parse: BindComplete relayed");
	auto ev = events(reg);
	ok(ev.size() == 2 && ev[0].reply == Extq_Reply::DROP && ev[0].outcome == Extq_Outcome::OK,
		"own parse: event reports the backend now holds the statement");

	PgSQL_Extq_Registry reg2;
	reg2.push(slot(Extq_Kind::PARSE, Extq_Reply::DROP, 0));
	reg2.push(slot(Extq_Kind::BIND, Extq_Reply::RELAY, 0));
	reg2.push(slot(Extq_Kind::SYNC, Extq_Reply::RELAY, 1));
	reg2.start(out);
	ok(feed(reg2, 'E', "relation does not exist", out) == Extq_Verdict::RELAY, "own parse: its error is relayed");
	ev = events(reg2);
	ok(ev.size() == 2 && ev[0].entry == 0 && ev[0].outcome == Extq_Outcome::ERROR &&
		ev[1].entry == 0 && ev[1].outcome == Extq_Outcome::SKIPPED,
		"own parse: the error belongs to the client's Bind entry");
}

// The Sync added before a simple Query: its ReadyForQuery is dropped unless the batch failed.
static void test_implicit_sync() {
	PgSQL_Extq_Registry reg;
	reg.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 0));
	reg.push(slot(Extq_Kind::SYNC, Extq_Reply::DROP, 1));
	std::string out;
	reg.start(out);
	feed(reg, 'C', std::string("INSERT 0 1\0", 11), out);
	ok(feed(reg, 'Z', "I", out) == Extq_Verdict::DROP, "implicit sync: ReadyForQuery dropped");
	auto ev = events(reg);
	ok(ev.size() == 1 && ev[0].affected_rows == 1, "implicit sync: affected rows from CommandComplete");

	PgSQL_Extq_Registry reg2;
	reg2.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 0));
	reg2.push(slot(Extq_Kind::SYNC, Extq_Reply::DROP, 1));
	reg2.start(out);
	feed(reg2, 'E', "err", out);
	ok(feed(reg2, 'Z', "I", out) == Extq_Verdict::RELAY, "implicit sync: ReadyForQuery relayed after an error");
}

// A batch sent without a Sync (cut short before a SET, or by a local error).
static void test_flush_ended() {
	PgSQL_Extq_Registry reg;
	reg.push(slot(Extq_Kind::BIND, Extq_Reply::RELAY, 0));
	reg.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 1));
	reg.push(slot(Extq_Kind::CLOSE, Extq_Reply::LOCAL, 2, CLOSE_OK));
	std::string out;
	reg.start(out);
	feed(reg, '2', "", out);
	feed(reg, 'C', std::string("SELECT 0\0", 9), out);
	ok(reg.complete() && out == CLOSE_OK, "flush-ended: complete with its last reply, trailing local reply sent");
	ok(reg.needs_sync() == false, "flush-ended: no Sync needed without an error");

	PgSQL_Extq_Registry reg2;
	reg2.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 0));
	reg2.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 1));
	out.clear();
	reg2.start(out);
	feed(reg2, 'E', "err", out);
	ok(reg2.needs_sync() && reg2.complete() == false, "flush-ended error: a Sync must be sent");
	ok(feed(reg2, 'Z', "I", out) == Extq_Verdict::BAD, "flush-ended error: ReadyForQuery before the Sync is wrong");
	PgSQL_Extq_Registry reg3;
	reg3.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 0));
	reg3.start(out);
	feed(reg3, 'E', "err", out);
	reg3.sync_sent();
	ok(feed(reg3, 'Z', "I", out) == Extq_Verdict::RELAY && reg3.complete(), "flush-ended error: the injected Sync's ReadyForQuery is relayed");
}

// ProxySQL's own error after buffered work: sent after the earlier replies, ends the batch.
static void test_local_error() {
	PgSQL_Extq_Registry reg;
	const std::string err("Eerr", 4);
	reg.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 0));
	reg.push(slot(Extq_Kind::BIND, Extq_Reply::LOCAL_ERROR, 1, err));
	std::string out;
	reg.start(out);
	ok(out.empty(), "local error: waits for earlier replies");
	feed(reg, 'C', std::string("UPDATE 1\0", 9), out);
	ok(out.empty() && reg.local_error_bytes() == err && reg.complete() && reg.ended_on_local_error(),
		"local error: due after the Execute, kept apart from the relayed bytes, batch complete");
	auto ev = events(reg);
	ok(ev.size() == 2 && ev[1].outcome == Extq_Outcome::ERROR && ev[1].reply == Extq_Reply::LOCAL_ERROR,
		"local error: reported as an error event");

	PgSQL_Extq_Registry reg2;
	reg2.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 0));
	reg2.push(slot(Extq_Kind::BIND, Extq_Reply::LOCAL_ERROR, 1, err));
	out.clear();
	reg2.start(out);
	feed(reg2, 'E', "backend err", out);
	ok(reg2.needs_sync() && reg2.ended_on_local_error() == false, "local error: skipped when an earlier backend error came first");
}

// Messages that answer nothing, and messages that fit no slot.
static void test_passthrough_and_bad() {
	PgSQL_Extq_Registry reg;
	reg.push(slot(Extq_Kind::DESCRIBE_S, Extq_Reply::RELAY, 0));
	reg.push(slot(Extq_Kind::SYNC, Extq_Reply::RELAY, 1));
	std::string out;
	reg.start(out);
	ok(feed(reg, 'N', "notice", out) == Extq_Verdict::RELAY, "notice relayed without consuming a slot");
	ok(feed(reg, 'T', "", out) == Extq_Verdict::BAD, "Describe('S') needs ParameterDescription before RowDescription");
	PgSQL_Extq_Registry reg2;
	reg2.push(slot(Extq_Kind::DESCRIBE_S, Extq_Reply::RELAY, 0));
	reg2.push(slot(Extq_Kind::SYNC, Extq_Reply::RELAY, 1));
	reg2.start(out);
	ok(feed(reg2, 't', "", out) == Extq_Verdict::RELAY && feed(reg2, 'n', "", out) == Extq_Verdict::RELAY,
		"Describe('S'): ParameterDescription then NoData");
	ok(feed(reg2, 'Z', "I", out) == Extq_Verdict::RELAY, "Describe('S'): then ReadyForQuery");
	ok(feed(reg2, 'Z', "I", out) == Extq_Verdict::BAD, "a second ReadyForQuery fits no slot");
}

// A batch of only ProxySQL's own replies never needs the backend.
static void test_all_local() {
	PgSQL_Extq_Registry reg;
	reg.push(slot(Extq_Kind::PARSE, Extq_Reply::LOCAL, 0, PARSE_OK));
	reg.push(slot(Extq_Kind::CLOSE, Extq_Reply::LOCAL, 1, CLOSE_OK));
	ok(reg.needs_backend() == false, "all local: no backend needed");
	std::string out;
	reg.start(out);
	ok(out == PARSE_OK + CLOSE_OK && reg.complete(), "all local: every reply out at start");
}

// B(p1) E(p1,1) E(p1,0) S: an Execute that stops at max_rows ends on PortalSuspended, and its
// event says so; one that runs to the end does not.
static void test_suspended_execute() {
	PgSQL_Extq_Registry reg;
	reg.push(slot(Extq_Kind::BIND, Extq_Reply::RELAY, 0));
	reg.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 1));
	reg.push(slot(Extq_Kind::EXECUTE, Extq_Reply::RELAY, 2));
	reg.push(slot(Extq_Kind::SYNC, Extq_Reply::RELAY, 3));
	std::string out;
	reg.start(out);
	feed(reg, '2', "", out);
	ok(feed(reg, 'D', "x", out) == Extq_Verdict::RELAY && feed(reg, 's', "", out) == Extq_Verdict::RELAY,
		"suspended: DataRow and PortalSuspended relayed");
	feed(reg, 'D', "y", out);
	feed(reg, 'C', std::string("SELECT 1\0", 9), out);
	ok(feed(reg, 'Z', "T", out) == Extq_Verdict::RELAY && reg.complete(), "suspended: complete at ReadyForQuery");
	auto ev = events(reg);
	ok(ev.size() == 3 && ev[1].rows == 1 && ev[1].suspended == true && ev[1].outcome == Extq_Outcome::OK,
		"suspended: first Execute reports PortalSuspended");
	ok(ev.size() == 3 && ev[2].rows == 1 && ev[2].suspended == false && ev[2].outcome == Extq_Outcome::OK,
		"suspended: second Execute ran to the end");
}

// P(relayed) then ProxySQL's own failing Parse in place of its own error, then Sync: the backend's
// error is swapped for ProxySQL's, the backend's ReadyForQuery reaches the client.
static void test_substitute() {
	PgSQL_Extq_Registry reg;
	const std::string own_error("E\0\0\0\x0bS26000\0\0", 12);
	reg.push(slot(Extq_Kind::PARSE, Extq_Reply::RELAY, 0));
	reg.push(slot(Extq_Kind::PARSE, Extq_Reply::SUBSTITUTE, 1, own_error));
	reg.push(slot(Extq_Kind::SYNC, Extq_Reply::RELAY, 2));
	ok(reg.needs_backend(), "substitute: needs the backend");
	std::string out;
	reg.start(out);
	ok(out.empty() && feed(reg, '1', "", out) == Extq_Verdict::RELAY, "substitute: the earlier ParseComplete is relayed");
	ok(feed(reg, 'E', "backend error", out) == Extq_Verdict::DROP && out == own_error,
		"substitute: the backend's error is dropped, ProxySQL's own goes out in its place");
	out.clear();
	ok(feed(reg, 'Z', "E", out) == Extq_Verdict::RELAY && reg.complete() && out.empty(),
		"substitute: the backend's ReadyForQuery is relayed and ends the batch");
	auto ev = events(reg);
	ok(ev.size() == 2 && ev[1].reply == Extq_Reply::SUBSTITUTE && ev[1].outcome == Extq_Outcome::ERROR,
		"substitute: its event is an error ProxySQL gave");
	PgSQL_Extq_Registry reg2;
	reg2.push(slot(Extq_Kind::PARSE, Extq_Reply::SUBSTITUTE, 0, own_error));
	reg2.start(out);
	ok(feed(reg2, '1', "", out) == Extq_Verdict::BAD, "substitute: a failing Parse that succeeds is a protocol violation");
}

int main() {
	plan(52);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");
	test_plain_unit();             // 9
	test_local_reply_ordering();   // 3
	test_error_skips_rest();       // 5
	test_own_parse();              // 5
	test_implicit_sync();          // 3
	test_flush_ended();            // 5
	test_local_error();            // 4
	test_passthrough_and_bad();    // 5
	test_all_local();              // 2
	test_suspended_execute();      // 4
	test_substitute();             // 6
	test_cleanup_minimal();
	return exit_status();
}
