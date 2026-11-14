/**
 * @file pgsql_native_unread_reply_unit-t.cpp
 * @brief A native connection must not be reused while part of a backend reply is
 *        still unread, and an ordinary ErrorResponse must not end the result cycle
 *        (issue #6410).
 *
 * The native result drain could pause between an ErrorResponse and its
 * ReadyForQuery; the handler then ended the cycle on the recorded error. The
 * multi-statement variant returned that connection to the pool with the 'Z' still
 * framed and native_fetch_paused set, and the next client to get it was failed with
 * 08P01. The end-to-end cases live in pgsql-native_error_fetch_pause-t; this file
 * pins the two state rules behind them without a server:
 *   - is_connection_in_reusable_state() refuses a connection holding unread
 *     backend bytes or a paused fetch, except buffered bytes on a LISTEN-pinned
 *     connection, which are asynchronous notifications kept between queries, and
 *     a connection a protocol violation already finished and marked for
 *     destruction, whose client must still be told why;
 *   - native_result_aborted, which ends the handler's fetch early, is set by
 *     native_result_fatal() and native_result_protocol_violation() but NOT by an
 *     ordinary ErrorResponse -- an 'E' driven through the native result drain still
 *     reaches its ReadyForQuery. It is cleared at each query and step start, together
 *     with native_fetch_paused; async_free_result() clears native_fetch_paused only.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Protocol.h"

#include <fcntl.h>
#include <unistd.h>
#include <string>

static PgSQL_Connection* make_live_native_conn() {
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = true;
	c->fd = ::open("/dev/null", O_RDONLY);
	c->native_st = PgSQL_Connection::PG_Native_Conn_St::DONE;
	c->native_connected = true;
	c->set_ready_for_query_status('I');
	return c;
}

static void destroy(PgSQL_Connection* c) {
	if (c->fd >= 0) { ::close(c->fd); c->fd = -1; }
	c->native_connected = false;
	delete c;
}

// type(1) + be32 length (counts itself) + payload
static std::string backend_msg(char type, const std::string& payload) {
	std::string s(1, type);
	const uint32_t L = (uint32_t)(payload.size() + 4);
	s.push_back((char)((L >> 24) & 0xff));
	s.push_back((char)((L >> 16) & 0xff));
	s.push_back((char)((L >> 8) & 0xff));
	s.push_back((char)(L & 0xff));
	s += payload;
	return s;
}

static void feed(PgSQL_Connection* c, const std::string& bytes) {
	c->native_framer.feed((const unsigned char*)bytes.data(), bytes.size());
}

static void test_clean_conn_is_reusable() {
	PgSQL_Connection* c = make_live_native_conn();
	ok(c->native_framer.empty() && !c->native_fetch_paused && c->is_connection_in_reusable_state(),
	   "control: live native conn with nothing unread is reusable");
	destroy(c);
}

static void test_paused_fetch_is_not_reusable() {
	PgSQL_Connection* c = make_live_native_conn();
	// A paused fetch can sit on an empty framer: the rest of the reply, the 'Z'
	// included, may still be on the socket.
	c->native_fetch_paused = true;
	ok(c->native_framer.empty() && c->is_connection_in_reusable_state() == false,
	   "conn whose fetch is paused is not reusable, even with an empty framer");
	destroy(c);
}

static void test_unread_framer_is_not_reusable() {
	PgSQL_Connection* c = make_live_native_conn();
	feed(c, backend_msg('Z', "I"));   // the ReadyForQuery the issue left behind
	ok(!c->native_framer.empty() && c->is_connection_in_reusable_state() == false,
	   "conn holding an unread ReadyForQuery is not reusable -- the next query would "
	   "read it as its own answer and fail with 08P01");
	destroy(c);
}

static void test_listen_conn_keeps_buffered_notification() {
	PgSQL_Connection* c = make_live_native_conn();
	c->set_status(true, STATUS_PGSQL_CONNECTION_LISTEN);
	// NotificationResponse: be32 pid, channel\0, payload\0 (sizeof keeps the last NUL).
	static const char notify[] = "\0\0\0\x01" "chan\0" "payload";
	feed(c, backend_msg('A', std::string(notify, sizeof(notify))));
	ok(!c->native_framer.empty() && c->is_connection_in_reusable_state() == true,
	   "LISTEN-pinned conn buffering a notification between queries stays reusable");
	c->native_fetch_paused = true;
	ok(c->is_connection_in_reusable_state() == false,
	   "LISTEN-pinned conn with a paused fetch is still not reusable");
	destroy(c);
}

static void test_error_response_does_not_abort_the_cycle() {
	PgSQL_Connection* c = make_live_native_conn();
	// What add_native_backend_message() does for an 'E': fill error_info. The
	// backend still owes a ReadyForQuery, so this must not end the fetch.
	// Fields as (type byte, value\0); sizeof keeps the final NUL that ends the list.
	static const char e[] = "SERROR\0" "C22P02\0" "Minvalid input syntax for type integer\0";
	c->native_fill_error_from_E((const unsigned char*)e, (uint32_t)sizeof(e));
	ok(c->is_error_present() && c->native_result_aborted == false,
	   "an ordinary ErrorResponse records the error but does not mark the result aborted");
	destroy(c);
}

// The same through the drain itself: the 'E' is recorded and the drain goes on to the
// 'Z' that ends the cycle.
static void test_error_response_drains_to_ready_for_query() {
	PgSQL_Connection* c = make_live_native_conn();
	// The result is not tied to the connection: that would also count the error against the
	// connection's server, which a fabricated connection has none of. The error is recorded
	// on the connection the way the result would record it.
	c->query_result = new PgSQL_Query_Result();
	c->query_result->clear(); // the inline buffer, without init()'s ties to a connection
	static const char e[] = "SERROR\0" "C22P02\0" "Minvalid input syntax for type integer\0";
	c->native_fill_error_from_E((const unsigned char*)e, (uint32_t)sizeof(e));
	feed(c, backend_msg('E', std::string(e, sizeof(e))) + backend_msg('Z', "I"));
	// Only what is already framed is drained, so the (dummy) socket is never read.
	c->native_fetch_paused = true;
	c->native_fetch_result_cont(0, nullptr);
	ok(c->is_error_present() && c->native_result_aborted == false && c->native_result_complete &&
	   c->native_framer.empty(),
	   "an ErrorResponse in the native drain is recorded, and the drain reaches its ReadyForQuery "
	   "[error=%d aborted=%d complete=%d framer_empty=%d]", (int)c->is_error_present(),
	   (int)c->native_result_aborted, (int)c->native_result_complete, (int)c->native_framer.empty());
	destroy(c); // also deletes query_result
}

static void test_fatal_and_violation_abort_the_cycle() {
	PgSQL_Connection* c = make_live_native_conn();
	c->native_result_fatal("08006", "backend closed during result fetch");
	ok(c->native_result_aborted && c->is_error_present() && c->is_connection_in_reusable_state() == false,
	   "native_result_fatal() marks the result aborted and the connection unusable");
	destroy(c);

	c = make_live_native_conn();
	// The refused message, and whatever followed it, stays in the framer: the
	// violation stops reading on purpose.
	feed(c, backend_msg('R', std::string("\0\0\0\0", 4)));
	c->native_result_protocol_violation("illegal backend message type in result stream");
	ok(c->native_result_aborted && c->is_error_present() && c->reusable == false && c->healthy == false,
	   "native_result_protocol_violation() marks the result aborted and the connection for destruction");
	// The unread bytes must not turn this into a "broken connection": the session
	// would then drop the client without the error that says why.
	ok(!c->native_framer.empty() && c->is_connection_in_reusable_state() == true,
	   "after a protocol violation the unread-bytes rule stands aside, so the session "
	   "takes the branch that reports the refusal to the client");
	destroy(c);
}

static void test_flags_cleared_at_step_start_and_free() {
	PgSQL_Connection* c = make_live_native_conn();
	c->native_fetch_paused = true;
	c->native_result_aborted = true;
	c->native_stmt_reset_step();
	ok(c->native_fetch_paused == false && c->native_result_aborted == false,
	   "native_stmt_reset_step() clears native_fetch_paused and native_result_aborted");

	c->native_fetch_paused = true;
	c->async_free_result();
	ok(c->native_fetch_paused == false,
	   "async_free_result() clears native_fetch_paused");
	destroy(c);
}

int main() {
	plan(12);
	test_init_minimal();

	test_clean_conn_is_reusable();                  // 1
	test_paused_fetch_is_not_reusable();            // 1
	test_unread_framer_is_not_reusable();           // 1
	test_listen_conn_keeps_buffered_notification(); // 2
	test_error_response_does_not_abort_the_cycle(); // 1
	test_error_response_drains_to_ready_for_query(); // 1
	test_fatal_and_violation_abort_the_cycle();     // 3
	test_flags_cleared_at_step_start_and_free();    // 2

	test_cleanup_minimal();
	return exit_status();
}
