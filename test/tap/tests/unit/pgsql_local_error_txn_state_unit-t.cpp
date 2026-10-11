/**
 * @file pgsql_local_error_txn_state_unit-t.cpp
 * @brief Regression test for #6424: the ReadyForQuery after an error ProxySQL raises itself.
 *
 * Some errors never reach the backend: ProxySQL answers them on its own (an Execute of a
 * portal that does not exist, a query rule's error_msg, a hostgroup-lock refusal, ...).
 * PostgreSQL aborts the transaction block on ANY error, so a client inside one must be
 * told ReadyForQuery('E'). ProxySQL used to hard-code 'I', so the client believed it was
 * idle while its transaction was still open on the pinned backend -- and a later COMMIT
 * committed it.
 *
 * PgSQL_Session::txn_state_for_local_error() is the decision every such path now asks,
 * and PgSQL_Protocol::generate_error_packet() is what carries its answer to the wire.
 * Both are driven directly here, on fabricated native connections:
 *
 *  - the status byte must follow the backend that holds the transaction, not the keyword
 *    tracker, which can still say BEGIN after the backend went idle;
 *  - a backend still at 'T' never saw the error, so the session must be poisoned -- the
 *    'E' alone would let a later COMMIT commit the work -- and the backend must be left
 *    attached, because callers may still be using it;
 *  - a backend already at 'E' agrees with the client and must NOT be poisoned, so its
 *    own ROLLBACK keeps working (including over the extended protocol), unless it is
 *    mid-batch or the caller is about to drop it;
 *  - when the backend is about to go (mid-batch, or dropped by the caller), the client's
 *    SET variables are put back to their BEGIN values while it is still attached.
 *
 * The libpq path shares the decision through IsKnownActiveTransaction() and
 * get_transaction_status_char(); a fabricated connection cannot own a PGconn, so the
 * end-to-end check of both protocols is pgsql-local_error_txn_state-t.
 */
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Backend.h"
#include "PgSQL_Thread.h"
#include "PgSQL_ExplicitTxnStateMgr.h"
#include "PgSQL_Variables.h"

// Stamp the tracked variables the transaction tracker asserts on when it records a BEGIN.
static void fill_tracked_variables(PgSQL_Connection* conn) {
	for (int idx = 0; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {
		const char* def_val = pgsql_tracked_variables[idx].default_value;
		conn->variables[idx].value = strdup(def_val);
		conn->var_hash[idx] = SpookyHash::Hash32(def_val, strlen(def_val), 10);
	}
}

struct Fixture {
	PgSQL_Session* sess = nullptr;
	PgSQL_Connection* conn = nullptr;   // the backend connection, nullptr when none
	PgSQL_Data_Stream* server_ds = nullptr;
};

static PgSQL_Thread* g_thread = nullptr;

// A session with a frontend and, unless txn_status is 0, one live native backend
// connection whose last ReadyForQuery carried `txn_status`. No socket is ever used:
// /dev/null only makes the connection read as live.
static Fixture build(char txn_status, bool mid_batch = false) {
	Fixture f;
	f.sess = new PgSQL_Session();
	f.sess->thread = g_thread;
	f.sess->connections_handler = true;   // keeps the session destructor away from PgHGM

	PgSQL_Data_Stream* client_ds = new PgSQL_Data_Stream();
	client_ds->myds_type = MYDS_FRONTEND;
	client_ds->myconn = new PgSQL_Connection(true);
	fill_tracked_variables(client_ds->myconn);
	f.sess->client_myds = client_ds;

	f.server_ds = new PgSQL_Data_Stream();
	PgSQL_Backend* be = new PgSQL_Backend();
	be->server_myds = f.server_ds;
	f.sess->mybe = be;
	f.sess->mybes->add(be);

	if (txn_status) {
		f.conn = new PgSQL_Connection(false);
		fill_tracked_variables(f.conn);
		f.conn->native_mode = true;
		f.conn->fd = ::open("/dev/null", O_RDONLY);
		f.conn->native_st = PgSQL_Connection::PG_Native_Conn_St::DONE;
		f.conn->native_connected = true;
		f.conn->set_ready_for_query_status(txn_status);
		f.conn->native_unsynced_work = mid_batch;
		f.server_ds->myconn = f.conn;
	}
	return f;
}

// Fabricated sessions never had a running thread; tearing them down is left to process
// exit, as the other session-level unit tests do.

static unsigned long long poisoned_total() {
	return g_thread->status_variables.tx_poisoned_total;
}

static void test_status_byte_follows_backend() {
	{
		Fixture f = build(0);
		ok(f.sess->txn_state_for_local_error() == 'I' && f.sess->tx_poisoned == false,
		   "no backend attached: 'I', session not poisoned");
	}
	{
		Fixture f = build('I');
		ok(f.sess->txn_state_for_local_error() == 'I' && f.sess->tx_poisoned == false,
		   "backend idle at 'I': 'I', session not poisoned");
	}
	{
		Fixture f = build('T');
		const unsigned long long before = poisoned_total();
		const char st = f.sess->txn_state_for_local_error();
		ok(st == 'E',
		   "backend in a transaction at 'T': 'E' -- PostgreSQL aborts the block on any error "
		   "[got '%c']", st);
		ok(f.sess->tx_poisoned == true && poisoned_total() == before + 1,
		   "and the session is poisoned (pgsql_tx_poisoned_total +1), so a later COMMIT "
		   "cannot commit the transaction the backend never saw fail");
		ok(f.server_ds->myconn == f.conn,
		   "and the backend is left attached: callers may still be using it, it is "
		   "discarded when the client ends the transaction");
	}
	{
		Fixture f = build('E');
		const unsigned long long before = poisoned_total();
		const char st = f.sess->txn_state_for_local_error();
		ok(st == 'E' && f.sess->tx_poisoned == false && poisoned_total() == before,
		   "backend already aborted at 'E': 'E' without poisoning, so the backend handles "
		   "the client's ROLLBACK itself [got '%c', poisoned=%d]", st, (int)f.sess->tx_poisoned);
	}
	{
		Fixture f = build('E', true);
		ok(f.sess->txn_state_for_local_error() == 'E' && f.sess->tx_poisoned == true,
		   "backend at 'E' but mid-batch: poisoned, the frame reset that follows drops it");
	}
	{
		Fixture f = build('E');
		ok(f.sess->txn_state_for_local_error(true) == 'E' && f.sess->tx_poisoned == true,
		   "backend at 'E' that the caller is about to drop: poisoned, nothing is left to "
		   "answer the ROLLBACK");
	}
	{
		Fixture f = build(0);
		f.sess->tx_poisoned = true;
		ok(f.sess->txn_state_for_local_error() == 'E',
		   "already poisoned session with no backend: still 'E'");
	}
}

// The keyword tracker is fed only on success and reads first words only, so it can
// still say BEGIN for a backend that is idle (#6417). Trusting it would poison idle
// sessions; the backend is what holds the transaction.
static void test_stale_tracker_is_not_trusted() {
	Fixture f = build('I');
	f.sess->transaction_state_manager->handle_transaction("BEGIN");
	if (f.sess->is_in_transaction() == false) {
		ok(false, "precondition: the tracker records BEGIN");
		return;
	}
	ok(f.sess->txn_state_for_local_error() == 'I' && f.sess->tx_poisoned == false,
	   "tracker says BEGIN but the backend is idle at 'I': 'I', session not poisoned");

	// The BEGIN snapshot is what puts the client's SET variables back when the poisoned
	// transaction ends. Recovery needs it, so poisoning with the backend kept leaves it.
	Fixture g = build('T');
	g.sess->transaction_state_manager->handle_transaction("BEGIN");
	ok(g.sess->txn_state_for_local_error() == 'E' && g.sess->tx_poisoned &&
	   g.sess->is_in_transaction() == true,
	   "poisoned with the backend kept: the BEGIN snapshot is kept for recovery");
}

// A caller about to drop the backend cannot leave the snapshot for recovery: rolling
// it back needs the backend attached. The client's SET variables go back to their
// values at BEGIN right away, as the ROLLBACK the backend will never see would do.
static void test_backend_lost_restores_variables() {
	Fixture f = build('T');
	const int idx = 0;
	const std::string at_begin = f.sess->client_myds->myconn->variables[idx].value;
	f.sess->transaction_state_manager->handle_transaction("BEGIN");
	const char* changed = "changed-inside-txn";
	const uint32_t changed_hash = SpookyHash::Hash32(changed, strlen(changed), 10);
	pgsql_variables.client_set_hash_and_value(f.sess, idx, changed, changed_hash);
	pgsql_variables.server_set_hash_and_value(f.sess, idx, changed, changed_hash);

	const char st = f.sess->txn_state_for_local_error(true);
	const char* now = f.sess->client_myds->myconn->variables[idx].value;
	ok(st == 'E' && f.sess->tx_poisoned && f.sess->is_in_transaction() == false &&
	   now && at_begin == now,
	   "backend about to be dropped: poisoned, and '%s' is back to its BEGIN value '%s' [now '%s']",
	   pgsql_tracked_variables[idx].set_variable_name, at_begin.c_str(), now ? now : "(null)");
}

// Same for a backend mid-batch: the frame reset that follows the error drops it, so by
// recovery time there is nothing attached to roll the snapshot back on and it could only
// be dropped -- leaving the SET variables changed inside the aborted transaction in place.
static void test_mid_batch_restores_variables() {
	Fixture f = build('T', true);
	const int idx = 0;
	const std::string at_begin = f.sess->client_myds->myconn->variables[idx].value;
	f.sess->transaction_state_manager->handle_transaction("BEGIN");
	const char* changed = "changed-inside-batch";
	const uint32_t changed_hash = SpookyHash::Hash32(changed, strlen(changed), 10);
	pgsql_variables.client_set_hash_and_value(f.sess, idx, changed, changed_hash);
	pgsql_variables.server_set_hash_and_value(f.sess, idx, changed, changed_hash);

	const char st = f.sess->txn_state_for_local_error();
	const char* now = f.sess->client_myds->myconn->variables[idx].value;
	ok(st == 'E' && f.sess->tx_poisoned && f.sess->is_in_transaction() == false &&
	   now && at_begin == now,
	   "backend mid-batch: poisoned, and '%s' is back to its BEGIN value '%s' before the frame "
	   "reset drops the backend [now '%s']",
	   pgsql_tracked_variables[idx].set_variable_name, at_begin.c_str(), now ? now : "(null)");
}

// generate_error_packet() used to write ReadyForQuery with the default 'I' whatever the
// caller knew; the status byte is now a parameter.
static void test_error_packet_carries_status() {
	PgSQL_Data_Stream* ds = new PgSQL_Data_Stream();
	for (char st : { 'I', 'E' }) {
		PtrSize_t pkt {};
		ds->myprot.generate_error_packet(false, true, "portal \"\" does not exist",
			PGSQL_ERROR_CODES::ERRCODE_UNDEFINED_CURSOR, false, false, &pkt, st);
		const unsigned char* b = (const unsigned char*)pkt.ptr;
		const bool tail_ok = pkt.size > 6 && b[0] == 'E' &&
			b[pkt.size - 6] == 'Z' && b[pkt.size - 5] == 0 && b[pkt.size - 4] == 0 &&
			b[pkt.size - 3] == 0 && b[pkt.size - 2] == 5 && b[pkt.size - 1] == (unsigned char)st;
		ok(tail_ok, "generate_error_packet(..., '%c'): ErrorResponse followed by ReadyForQuery('%c')",
		   st, st);
		free(pkt.ptr);
	}
	PtrSize_t pkt {};
	ds->myprot.generate_error_packet(false, true, "x", PGSQL_ERROR_CODES::ERRCODE_UNDEFINED_CURSOR,
		false, false, &pkt);
	ok(pkt.size > 6 && ((const unsigned char*)pkt.ptr)[pkt.size - 1] == 'I',
	   "generate_error_packet() without a status still reports 'I' (startup/auth callers)");
	free(pkt.ptr);
}

int main(int, char**) {
	plan(16);
	test_init_minimal();
	g_thread = new PgSQL_Thread();

	test_status_byte_follows_backend();
	test_stale_tracker_is_not_trusted();
	test_backend_lost_restores_variables();
	test_mid_batch_restores_variables();
	test_error_packet_carries_status();

	return exit_status();
}
