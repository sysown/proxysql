/**
 * @file pgsql_native_affected_rows_unit-t.cpp
 * @brief The native backend path records a DML's affected rows even when a
 *        row-returning statement precedes it in the same batch (issue #6435).
 *
 * A native simple query feeds every statement of a multi-statement batch into one
 * PgSQL_Query_Result, up to ReadyForQuery. The "this CommandComplete belongs to a
 * row-returning statement" test used to read the result-wide TUPLE flag, so after
 * "SELECT 1" every later "UPDATE n" in the batch was skipped and affected_rows
 * stayed at its -1 sentinel. On libpq each statement gets its own result, so the
 * last DML count of the batch wins. These cases pin that parity without a server:
 *   - add_native_backend_message() fed synthetic messages directly;
 *   - native_fetch_result_cont() driven over a framed byte stream, for the simple
 *     query drain and for the extended EXECUTE drain, which swallows an unrequested
 *     RowDescription (a zero-row SELECT's "SELECT 0" is not an affected-row count).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Protocol.h"
#include "PgSQL_Session.h"

#include <fcntl.h>
#include <unistd.h>
#include <string>

static const unsigned long long NO_COUNT = static_cast<unsigned long long>(-1);

// ---------------------------------------------------------------------------
// Direct feed into a PgSQL_Query_Result with no connection (conn == NULL), so
// 'E' and 'Z' have no connection side effects.
// ---------------------------------------------------------------------------

struct Result {
	PgSQL_Query_Result r;
	Result() { r.clear(); }  // allocates the inline buffer, resets the counters

	void msg(char type, const std::string& payload) {
		r.add_native_backend_message(type, (const unsigned char*)payload.data(), (uint32_t)payload.size());
	}
	// RowDescription for one int4 column named "c".
	void T() {
		std::string p("\x00\x01", 2);
		p += std::string("c\0", 2);
		p += std::string(4, '\0');          // table oid
		p += std::string(2, '\0');          // column attnum
		p += std::string("\x00\x00\x00\x17", 4); // type oid 23 (int4)
		p += std::string("\x00\x04", 2);    // type len
		p += std::string("\xff\xff\xff\xff", 4); // typmod
		p += std::string(2, '\0');          // text format
		msg('T', p);
	}
	// DataRow with one column "1".
	void D() { msg('D', std::string("\x00\x01\x00\x00\x00\x01" "1", 7)); }
	void C(const char* tag) { msg('C', std::string(tag) + '\0'); }
	void I() { msg('I', std::string()); }
	void E() {
		std::string p;
		p += 'S'; p += "ERROR"; p += '\0';
		p += 'C'; p += "42P01"; p += '\0';
		p += 'M'; p += "boom"; p += '\0';
		p += '\0';
		msg('E', p);
	}
	void Z() { msg('Z', std::string("I", 1)); }
	unsigned long long affected() const { return r.get_affected_rows(); }
};

static void test_select_then_dml() {
	Result x;
	x.T(); x.D(); x.C("SELECT 1"); x.C("UPDATE 10"); x.Z();
	ok(x.affected() == 10,
	   "T D C(SELECT 1) C(UPDATE 10): the UPDATE count is recorded (got %lld)", (long long)x.affected());
	ok(x.r.get_num_rows() == 1,
	   "rows_sent accumulation over the batch is unchanged (num_rows=%llu)", x.r.get_num_rows());
}

static void test_last_dml_count_wins() {
	Result x;
	x.C("UPDATE 5"); x.T(); x.D(); x.C("SELECT 1"); x.C("UPDATE 3"); x.Z();
	ok(x.affected() == 3,
	   "C(UPDATE 5) T D C(SELECT 1) C(UPDATE 3): last DML count wins, not the first (got %lld)",
	   (long long)x.affected());
}

static void test_dml_then_select_control() {
	Result x;
	x.C("UPDATE 10"); x.T(); x.D(); x.C("SELECT 1"); x.Z();
	ok(x.affected() == 10,
	   "control: C(UPDATE 10) T D C(SELECT 1) keeps the UPDATE count (got %lld)", (long long)x.affected());
}

static void test_dml_only_batch() {
	Result x;
	x.C("UPDATE 5"); x.C("INSERT 0 3"); x.Z();
	ok(x.affected() == 3,
	   "control: C(UPDATE 5) C(INSERT 0 3): counts are not summed (got %lld)", (long long)x.affected());
}

static void test_row_returning_statement_alone() {
	Result s;
	s.T(); s.D(); s.C("SELECT 1"); s.Z();
	ok(s.affected() == NO_COUNT, "a lone SELECT records no affected rows");

	Result z;
	z.T(); z.C("SELECT 0"); z.Z();
	ok(z.affected() == NO_COUNT, "a zero-row SELECT with its RowDescription records no affected rows");

	Result r;
	r.T(); r.D(); r.D(); r.C("UPDATE 2"); r.Z();
	ok(r.affected() == NO_COUNT,
	   "UPDATE ... RETURNING: the tag counts returned rows, not recorded as affected rows");

	Result after;
	after.C("UPDATE 7"); after.T(); after.D(); after.C("UPDATE 1"); after.Z();
	ok(after.affected() == 7,
	   "C(UPDATE 7) then UPDATE ... RETURNING: the RETURNING tag does not overwrite the count (got %lld)",
	   (long long)after.affected());
}

static void test_error_and_empty_end_the_statement() {
	Result e;
	e.T(); e.D(); e.E(); e.C("UPDATE 4");
	ok(e.affected() == 4,
	   "T D E then C(UPDATE 4): a failed row-returning statement does not hide the next count (got %lld)",
	   (long long)e.affected());

	Result i;
	i.T(); i.I(); i.C("UPDATE 4");
	ok(i.affected() == 4,
	   "T I then C(UPDATE 4): an EmptyQueryResponse ends the statement (got %lld)", (long long)i.affected());
}

static void test_reset_at_ready_for_query() {
	// A row-returning statement cut off by ReadyForQuery (no 'C') must not leak
	// into the next query once get_resultset() resets the completed result.
	Result x;
	x.T(); x.D(); x.Z();
	PtrSizeArray out;
	const bool complete = x.r.get_resultset(&out);
	x.C("DELETE 6");
	ok(complete && x.affected() == 6,
	   "after a completed result is reset, the next query's count is recorded (got %lld)",
	   (long long)x.affected());
}

// ---------------------------------------------------------------------------
// Through the native drain (native_fetch_result_cont), fed a framed stream.
// ---------------------------------------------------------------------------

static std::string wire(char type, const std::string& payload) {
	std::string s(1, type);
	const uint32_t L = (uint32_t)(payload.size() + 4);
	s.push_back((char)((L >> 24) & 0xff));
	s.push_back((char)((L >> 16) & 0xff));
	s.push_back((char)((L >> 8) & 0xff));
	s.push_back((char)(L & 0xff));
	s += payload;
	return s;
}

static std::string wire_T() {
	std::string p("\x00\x01", 2);
	p += std::string("c\0", 2);
	p += std::string(4, '\0');
	p += std::string(2, '\0');
	p += std::string("\x00\x00\x00\x17", 4);
	p += std::string("\x00\x04", 2);
	p += std::string("\xff\xff\xff\xff", 4);
	p += std::string(2, '\0');
	return wire('T', p);
}
static std::string wire_D() { return wire('D', std::string("\x00\x01\x00\x00\x00\x01" "1", 7)); }
static std::string wire_C(const char* tag) { return wire('C', std::string(tag) + '\0'); }
static std::string wire_n() { return wire('n', std::string()); }
static std::string wire_Z() { return wire('Z', std::string("I", 1)); }

static PgSQL_Connection* make_conn() {
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = true;
	c->fd = ::open("/dev/null", O_RDONLY);
	c->native_st = PgSQL_Connection::PG_Native_Conn_St::DONE;
	c->native_connected = true;
	c->set_ready_for_query_status('I');
	c->query_result = new PgSQL_Query_Result();
	c->query_result->init(nullptr, nullptr, c);
	return c;
}

static void destroy(PgSQL_Connection* c) {
	if (c->fd >= 0) { ::close(c->fd); c->fd = -1; }
	c->native_connected = false;
	delete c; // also deletes query_result
}

// Drain the framed bytes. native_fetch_paused makes the drain read only what is
// already framed, so nothing touches the (dummy) socket.
static void drain(PgSQL_Connection* c, const std::string& bytes) {
	c->native_framer.feed((const unsigned char*)bytes.data(), bytes.size());
	c->native_fetch_paused = true;
	c->native_fetch_result_cont(0, nullptr);
}

static void test_simple_query_drain() {
	PgSQL_Connection* c = make_conn();
	drain(c, wire_T() + wire_D() + wire_C("SELECT 1") + wire_C("UPDATE 10") + wire_Z());
	ok(c->native_result_complete && c->processing_multi_statement && c->query_result->get_affected_rows() == 10,
	   "simple-query drain of SELECT 1; UPDATE t: complete, multi-statement, affected_rows=10 (got %lld)",
	   (long long)c->query_result->get_affected_rows());
	destroy(c);
}

// Reports the affected rows and the bytes forwarded towards the client.
static void drain_execute(uint8_t flags, const std::string& bytes, unsigned long long* affected, unsigned long long* fwd) {
	PgSQL_Connection* c = make_conn();
	PgSQL_Extended_Query_Info info {};
	info.flags = flags;
	c->query.extended_query_info = &info;
	c->native_stmt_step = PgSQL_Connection::PG_Native_Stmt_Step::EXECUTE;
	c->native_stmt_sync_terminated = false; // Flush-terminated: the step ends on 'C'
	drain(c, bytes);
	*affected = c->native_result_complete ? c->query_result->get_affected_rows() : 0;
	*fwd = c->query_result->get_resultset_size();
	c->query.extended_query_info = nullptr;
	destroy(c);
}

static void test_extended_execute_drain() {
	unsigned long long affected = 0, fwd = 0;
	const std::string sel0 = wire_C("SELECT 0");

	drain_execute(0, wire_T() + sel0, &affected, &fwd);
	ok(affected == NO_COUNT && fwd == sel0.size(),
	   "EXECUTE without Describe, zero-row SELECT: 'T' swallowed, \"SELECT 0\" is not an affected-row count "
	   "(affected=%lld fwd=%llu)", (long long)affected, fwd);

	drain_execute(PGSQL_EXTENDED_QUERY_FLAG_DESCRIBE_PORTAL, wire_T() + sel0, &affected, &fwd);
	ok(affected == NO_COUNT && fwd == wire_T().size() + sel0.size(),
	   "EXECUTE with Describe, zero-row SELECT: 'T' forwarded, no affected rows (affected=%lld fwd=%llu)",
	   (long long)affected, fwd);

	const std::string upd3 = wire_C("UPDATE 3");
	drain_execute(0, wire_n() + upd3, &affected, &fwd);
	ok(affected == 3 && fwd == upd3.size(),
	   "control: EXECUTE without Describe of a DML records its count (affected=%lld fwd=%llu)",
	   (long long)affected, fwd);
}

int main() {
	plan(16);
	test_init_minimal();

	test_select_then_dml();                     // 2
	test_last_dml_count_wins();                 // 1
	test_dml_then_select_control();             // 1
	test_dml_only_batch();                      // 1
	test_row_returning_statement_alone();       // 4
	test_error_and_empty_end_the_statement();   // 2
	test_reset_at_ready_for_query();            // 1
	test_simple_query_drain();                  // 1
	test_extended_execute_drain();              // 3

	test_cleanup_minimal();
	return exit_status();
}
