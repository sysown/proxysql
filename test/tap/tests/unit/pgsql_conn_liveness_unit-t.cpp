/**
 * @file pgsql_conn_liveness_unit-t.cpp
 * @brief A broken connection must never report itself as healthy.
 *
 * When a connection dies, the letter the backend last sent stays behind. The code
 * used to read that letter and conclude the connection was idle and fine, so a
 * dead connection went back into the pool and the next session got it. These
 * tests build connections directly, with no server and no Docker.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"

#include <fcntl.h>
#include <unistd.h>

// Use a real file so the destructor's close() cannot hit some other file.
static int open_dummy_fd() {
	int fd = ::open("/dev/null", O_RDONLY);
	return fd;
}

// A connection in the state a healthy pooled one is in: open socket, login done,
// backend last said it was idle.
static PgSQL_Connection* make_live_native_conn() {
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = true;
	c->fd = open_dummy_fd();
	c->native_st = PgSQL_Connection::PG_Native_Conn_St::DONE;
	// native_connected is what marks the connection usable; native_st is set to
	// match what a real completed login leaves behind.
	c->native_connected = true;
	c->set_ready_for_query_status('I');
	return c;
}

// Do what the real teardown does: close the socket and mark it not connected.
// It leaves the transaction letter behind, and so do we -- that is the point.
static void simulate_teardown(PgSQL_Connection* c) {
	if (c->fd >= 0) { ::close(c->fd); c->fd = -1; }
	c->native_connected = false;
}

static void test_live_native_conn_is_healthy() {
	PgSQL_Connection* c = make_live_native_conn();
	ok(c->is_connected() == true,
	   "live native conn: is_connected() true");
	ok(c->get_pg_transaction_status() == PQTRANS_IDLE,
	   "live native conn: transaction status IDLE (from the 'I' byte)");
	ok(c->is_connection_in_reusable_state() == true,
	   "live native conn: reusable");
	simulate_teardown(c);
	delete c;
}

static void test_dead_native_conn_reports_dead() {
	PgSQL_Connection* c = make_live_native_conn();
	simulate_teardown(c);

	ok(c->is_connected() == false,
	   "torn-down native conn: is_connected() false");
	ok(c->get_pg_connection_status() == CONNECTION_BAD,
	   "torn-down native conn: connection status BAD");
	ok(c->get_pg_transaction_status() == PQTRANS_UNKNOWN,
	   "torn-down native conn: transaction status UNKNOWN despite the stale 'I' byte "
	   "(F2/A1 regression -- reported PQTRANS_IDLE before the liveness gate)");
	ok(c->is_connection_in_reusable_state() == false,
	   "torn-down native conn: NOT reusable -- the pool must destroy it, not re-pool it");
	ok(c->IsKnownActiveTransaction() == false,
	   "torn-down native conn: holds no transaction (true here only because the "
	   "fixture's last ReadyForQuery byte is 'I' -- see "
	   "test_dead_conn_that_was_in_a_transaction_still_reports_one() for the 'T' case)");
	delete c;
}

static void test_protocol_answer_stays_unqualified() {
	PgSQL_Connection* c = make_live_native_conn();
	simulate_teardown(c);
	ok(c->last_ready_for_query_status() == 'I',
	   "last_ready_for_query_status() still reports the raw byte after teardown -- "
	   "question 1 is deliberately unqualified; its callers carry their own guard");
	delete c;
}

static void test_conn_that_died_after_handshake() {
	PgSQL_Connection* c = make_live_native_conn();
	// The usual way a connection dies: it worked, then the socket went away in the
	// middle of a result. Only the closed socket shows it, so that half of the
	// check has to be doing its job.
	if (c->fd >= 0) { ::close(c->fd); c->fd = -1; }
	ok(c->native_st == PgSQL_Connection::PG_Native_Conn_St::DONE &&
	   c->is_connection_in_reusable_state() == false,
	   "conn that died after a completed handshake (fd cleared, native_st still DONE) "
	   "is not reusable -- the fd half of the liveness gate is load-bearing");
	delete c;
}

static void test_healthy_conn_mid_partial_send_is_live() {
	PgSQL_Connection* c = make_live_native_conn();
	// A query too big to write in one go leaves the connection in a sending state.
	// Nothing is wrong with it, so it must still count as usable.
	c->native_st = PgSQL_Connection::PG_Native_Conn_St::SEND_STARTUP;
	c->native_st_after_send = PgSQL_Connection::PG_Native_Conn_St::DONE;
	ok(c->is_connected() == true && c->is_connection_in_reusable_state() == true,
	   "healthy conn parked at SEND_STARTUP by a partial send is still live and reusable");
	c->native_st = PgSQL_Connection::PG_Native_Conn_St::DONE;
	simulate_teardown(c);
	delete c;
}

static void test_dead_conn_that_was_in_a_transaction_still_reports_one() {
	PgSQL_Connection* c = make_live_native_conn();
	c->set_ready_for_query_status('T');          // backend last said "in transaction"
	simulate_teardown(c);
	// This connection died with a transaction open. If it claimed otherwise, the
	// statement would be run again on a fresh connection, on its own, outside the
	// transaction it belonged to.
	ok(c->IsKnownActiveTransaction() == true,
	   "native conn torn down while in a transaction still reports an active "
	   "transaction, so the statement is not silently retried outside it");
	delete c;
}

static void test_libpq_control() {
	// The gate must be a no-op for libpq: PQstatus(NULL) is already CONNECTION_BAD
	// and PQtransactionStatus(NULL) is already PQTRANS_UNKNOWN, so a dead libpq conn
	// gave these answers before the change too. Checking it here means a future edit
	// to the gate cannot quietly alter the shipped path.
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = false;
	// pgsql_conn stays NULL -- the constructor sets it so.
	ok(c->is_connected() == false && c->get_pg_connection_status() == CONNECTION_BAD &&
	   c->get_pg_transaction_status() == PQTRANS_UNKNOWN,
	   "libpq control: a dead libpq conn reports dead the same way it always did");
	// Record an error before asking the reusable question. libpq only reaches this
	// state through a failure that sets one, and the check inside that function
	// aborts a debug build if it ever sees a broken connection with no error -- a
	// live invariant on the libpq path that this change must not switch off.
	c->set_error("08006", "connection failure", true);
	ok(c->is_error_present() == true && c->is_connection_in_reusable_state() == false,
	   "libpq control: a dead libpq conn with its error recorded is not reusable, "
	   "and the no-error check behind it is still armed");
	delete c;
}

static void test_live_conn_in_failed_transaction_is_still_reusable() {
	PgSQL_Connection* c = make_live_native_conn();
	// A statement failed but the backend answered and is waiting for ROLLBACK. The
	// connection itself is fine, so a liveness check must not throw it away -- this
	// is the case an over-eager gate would break.
	c->set_ready_for_query_status('E');
	ok(c->get_pg_transaction_status() == PQTRANS_INERROR,
	   "live native conn in a failed transaction: status INERROR");
	ok(c->is_connection_in_reusable_state() == true,
	   "live native conn in a failed transaction is still reusable -- a query error "
	   "must not be mistaken for a broken connection");
	simulate_teardown(c);
	delete c;
}

static void test_conn_that_failed_login_is_not_live() {
	PgSQL_Connection* c = make_live_native_conn();
	// Login failed: the socket is still open but the handshake never finished. This
	// is the state an auth failure sits in before teardown runs, so the connected
	// half of the check has to catch it on its own.
	c->native_connected = false;
	ok(c->fd >= 0 && c->is_connected() == false,
	   "conn with an open socket that never finished login is not live -- the "
	   "native_connected half of the gate is load-bearing");
	ok(c->is_connection_in_reusable_state() == false,
	   "conn that never finished login is not reusable");
	simulate_teardown(c);
	delete c;
}

int main() {
	plan(18);
	test_init_minimal();

	test_live_native_conn_is_healthy();              // 3
	test_dead_native_conn_reports_dead();            // 5
	test_protocol_answer_stays_unqualified();        // 1
	test_conn_that_died_after_handshake();           // 1
	test_healthy_conn_mid_partial_send_is_live();    // 1
	test_dead_conn_that_was_in_a_transaction_still_reports_one(); // 1
	test_live_conn_in_failed_transaction_is_still_reusable();     // 2
	test_conn_that_failed_login_is_not_live();                    // 2
	test_libpq_control();                            // 2

	test_cleanup_minimal();
	return exit_status();
}
