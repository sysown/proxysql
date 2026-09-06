/**
 * @file pgsql_txn_state_unit-t.cpp
 * @brief Unit tests for PgSQL_TxnCmdParser and PgSQL_ExplicitTxnStateMgr.
 *
 * Tests the pure parsing logic of PgSQL_TxnCmdParser::parse() which tokenizes
 * SQL transaction commands and returns a TxnCmd struct with .type and .savepoint.
 *
 * Also tests the PgSQL_ExplicitTxnStateMgr state machine, including
 * handle_transaction(), savepoint management, reset_state(), accessors,
 * and fill_internal_session() JSON serialization. These tests require
 * a minimal PgSQL_Session with a wired-up client_myds->myconn chain.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_ExplicitTxnStateMgr.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Backend.h"
#include "../deps/json/json.hpp"

#include <cstring>
#include <string>

// ============================================================
// BEGIN variants
// ============================================================

static void test_parser_begin() {
	PgSQL_TxnCmdParser parser;
	auto result = parser.parse("BEGIN");
	ok(result.type == TxnCmd::Type::BEGIN, "parser: BEGIN recognized");
}

static void test_parser_begin_variants() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("BEGIN TRANSACTION");
	ok(r1.type == TxnCmd::Type::BEGIN, "parser: BEGIN TRANSACTION recognized");

	auto r2 = parser.parse("START TRANSACTION");
	ok(r2.type == TxnCmd::Type::BEGIN, "parser: START TRANSACTION recognized");

	auto r3 = parser.parse("begin");
	ok(r3.type == TxnCmd::Type::BEGIN, "parser: case-insensitive begin");

	auto r4 = parser.parse("Begin");
	ok(r4.type == TxnCmd::Type::BEGIN, "parser: mixed-case Begin");

	// START without TRANSACTION should be UNKNOWN
	auto r5 = parser.parse("START");
	ok(r5.type == TxnCmd::Type::UNKNOWN, "parser: bare START is UNKNOWN (needs TRANSACTION)");

	// BEGIN WORK is not standard PgSQL but test parser behavior
	auto r6 = parser.parse("BEGIN WORK");
	ok(r6.type == TxnCmd::Type::BEGIN, "parser: BEGIN WORK recognized");
}

// ============================================================
// COMMIT variants
// ============================================================

static void test_parser_commit() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("COMMIT");
	ok(r1.type == TxnCmd::Type::COMMIT, "parser: COMMIT recognized");

	auto r2 = parser.parse("commit");
	ok(r2.type == TxnCmd::Type::COMMIT, "parser: case-insensitive commit");

	// END is a synonym for COMMIT in PostgreSQL
	auto r3 = parser.parse("END");
	ok(r3.type == TxnCmd::Type::COMMIT, "parser: END recognized as COMMIT synonym");

	auto r4 = parser.parse("end");
	ok(r4.type == TxnCmd::Type::COMMIT, "parser: case-insensitive end");
}

// ============================================================
// ROLLBACK variants
// ============================================================

static void test_parser_rollback() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("ROLLBACK");
	ok(r1.type == TxnCmd::Type::ROLLBACK, "parser: ROLLBACK recognized");

	auto r2 = parser.parse("rollback");
	ok(r2.type == TxnCmd::Type::ROLLBACK, "parser: case-insensitive rollback");

	// ABORT is a synonym for ROLLBACK in PostgreSQL
	auto r3 = parser.parse("ABORT");
	ok(r3.type == TxnCmd::Type::ROLLBACK, "parser: ABORT recognized as ROLLBACK synonym");

	auto r4 = parser.parse("abort");
	ok(r4.type == TxnCmd::Type::ROLLBACK, "parser: case-insensitive abort");

	// ROLLBACK WORK / ROLLBACK TRANSACTION
	auto r5 = parser.parse("ROLLBACK WORK");
	ok(r5.type == TxnCmd::Type::ROLLBACK, "parser: ROLLBACK WORK recognized");

	auto r6 = parser.parse("ROLLBACK TRANSACTION");
	ok(r6.type == TxnCmd::Type::ROLLBACK, "parser: ROLLBACK TRANSACTION recognized");
}

// ============================================================
// ROLLBACK AND CHAIN
// ============================================================

static void test_parser_rollback_and_chain() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("ROLLBACK AND CHAIN");
	ok(r1.type == TxnCmd::Type::ROLLBACK_AND_CHAIN, "parser: ROLLBACK AND CHAIN recognized");

	auto r2 = parser.parse("rollback and chain");
	ok(r2.type == TxnCmd::Type::ROLLBACK_AND_CHAIN, "parser: case-insensitive rollback and chain");

	// ABORT AND CHAIN should also work (ABORT is synonym)
	auto r3 = parser.parse("ABORT AND CHAIN");
	ok(r3.type == TxnCmd::Type::ROLLBACK_AND_CHAIN, "parser: ABORT AND CHAIN recognized");
}

// ============================================================
// SAVEPOINT
// ============================================================

static void test_parser_savepoint() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("SAVEPOINT sp1");
	ok(r1.type == TxnCmd::Type::SAVEPOINT, "parser: SAVEPOINT recognized");
	ok(r1.savepoint == "sp1", "parser: savepoint name 'sp1' extracted");

	auto r2 = parser.parse("SAVEPOINT my_save_point");
	ok(r2.type == TxnCmd::Type::SAVEPOINT, "parser: SAVEPOINT with underscore name");
	ok(r2.savepoint == "my_save_point", "parser: savepoint name 'my_save_point' extracted");

	auto r3 = parser.parse("savepoint SP1");
	ok(r3.type == TxnCmd::Type::SAVEPOINT, "parser: case-insensitive savepoint keyword");
	ok(r3.savepoint == "SP1", "parser: savepoint name preserves original case");
}

// ============================================================
// ROLLBACK TO SAVEPOINT
// ============================================================

static void test_parser_rollback_to_savepoint() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("ROLLBACK TO SAVEPOINT sp1");
	ok(r1.type == TxnCmd::Type::ROLLBACK_TO, "parser: ROLLBACK TO SAVEPOINT recognized");
	ok(r1.savepoint == "sp1", "parser: ROLLBACK TO SAVEPOINT extracts name");

	// Without SAVEPOINT keyword
	auto r2 = parser.parse("ROLLBACK TO sp1");
	ok(r2.type == TxnCmd::Type::ROLLBACK_TO, "parser: ROLLBACK TO sp1 (no SAVEPOINT keyword)");
	ok(r2.savepoint == "sp1", "parser: ROLLBACK TO extracts name without SAVEPOINT keyword");

	// Case insensitive
	auto r3 = parser.parse("rollback to savepoint SP2");
	ok(r3.type == TxnCmd::Type::ROLLBACK_TO, "parser: case-insensitive rollback to savepoint");
	ok(r3.savepoint == "SP2", "parser: savepoint name preserved in rollback to");
}

// ============================================================
// RELEASE SAVEPOINT
// ============================================================

static void test_parser_release_savepoint() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("RELEASE SAVEPOINT sp1");
	ok(r1.type == TxnCmd::Type::RELEASE, "parser: RELEASE SAVEPOINT recognized");
	ok(r1.savepoint == "sp1", "parser: RELEASE SAVEPOINT extracts name");

	// Without SAVEPOINT keyword
	auto r2 = parser.parse("RELEASE sp1");
	ok(r2.type == TxnCmd::Type::RELEASE, "parser: RELEASE sp1 (no SAVEPOINT keyword)");
	ok(r2.savepoint == "sp1", "parser: RELEASE extracts name without SAVEPOINT keyword");

	// Case insensitive
	auto r3 = parser.parse("release savepoint SP2");
	ok(r3.type == TxnCmd::Type::RELEASE, "parser: case-insensitive release savepoint");
	ok(r3.savepoint == "SP2", "parser: savepoint name preserved in release");
}

// ============================================================
// Non-transaction commands and edge cases
// ============================================================

static void test_parser_non_txn_commands() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("SELECT 1");
	ok(r1.type == TxnCmd::Type::UNKNOWN, "parser: SELECT is UNKNOWN");

	auto r2 = parser.parse("INSERT INTO t VALUES (1)");
	ok(r2.type == TxnCmd::Type::UNKNOWN, "parser: INSERT is UNKNOWN");

	auto r3 = parser.parse("SET search_path TO public");
	ok(r3.type == TxnCmd::Type::UNKNOWN, "parser: SET is UNKNOWN");
}

static void test_parser_empty_and_whitespace() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("");
	ok(r1.type == TxnCmd::Type::UNKNOWN, "parser: empty input = UNKNOWN");

	auto r2 = parser.parse("   ");
	ok(r2.type == TxnCmd::Type::UNKNOWN, "parser: whitespace-only = UNKNOWN");
}

static void test_parser_semicolons() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("BEGIN;");
	ok(r1.type == TxnCmd::Type::BEGIN, "parser: BEGIN with trailing semicolon");

	auto r2 = parser.parse("COMMIT;");
	ok(r2.type == TxnCmd::Type::COMMIT, "parser: COMMIT with trailing semicolon");

	auto r3 = parser.parse("ROLLBACK;");
	ok(r3.type == TxnCmd::Type::ROLLBACK, "parser: ROLLBACK with trailing semicolon");
}

static void test_parser_leading_whitespace() {
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("  BEGIN");
	ok(r1.type == TxnCmd::Type::BEGIN, "parser: leading whitespace before BEGIN");

	auto r2 = parser.parse("\tCOMMIT");
	ok(r2.type == TxnCmd::Type::COMMIT, "parser: leading tab before COMMIT");
}

static void test_parser_reuse() {
	// Verify parser can be reused for multiple parses
	PgSQL_TxnCmdParser parser;

	auto r1 = parser.parse("BEGIN");
	ok(r1.type == TxnCmd::Type::BEGIN, "parser reuse: first parse BEGIN");

	auto r2 = parser.parse("COMMIT");
	ok(r2.type == TxnCmd::Type::COMMIT, "parser reuse: second parse COMMIT");

	auto r3 = parser.parse("SAVEPOINT sp1");
	ok(r3.type == TxnCmd::Type::SAVEPOINT, "parser reuse: third parse SAVEPOINT");
	ok(r3.savepoint == "sp1", "parser reuse: savepoint name correct after reuse");

	auto r4 = parser.parse("ROLLBACK TO sp1");
	ok(r4.type == TxnCmd::Type::ROLLBACK_TO, "parser reuse: fourth parse ROLLBACK TO");
	ok(r4.savepoint == "sp1", "parser reuse: rollback to name correct after reuse");
}

// ============================================================
// PgSQL_ExplicitTxnStateMgr — State Machine Tests
// ============================================================

/**
 * @brief Helper: Create a minimal PgSQL_Session suitable for state manager testing.
 *
 * Allocates a PgSQL_Session, sets connections_handler=true to avoid
 * PgHGM dereference in destructor, creates a client data stream and
 * connection, and wires them together.
 *
 * @return Pointer to the newly created session. Caller must use
 *         destroy_test_session() to clean up.
 */
static PgSQL_Session* create_test_session() {
	PgSQL_Session* sess = new PgSQL_Session();
	// Prevent destructor from dereferencing PgHGM (which is nullptr in tests)
	sess->connections_handler = true;

	// Create client data stream and connection
	PgSQL_Data_Stream* ds = new PgSQL_Data_Stream();
	ds->myds_type = MYDS_FRONTEND;
	PgSQL_Connection* conn = new PgSQL_Connection(true);
	ds->myconn = conn;

	// Populate critical variables (indices 0..PGSQL_NAME_LAST_LOW_WM-1).
	// The state manager's start_transaction() asserts that these have
	// non-zero hashes. Use the default values from pgsql_tracked_variables[].
	for (int idx = 0; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {
		const char* def_val = pgsql_tracked_variables[idx].default_value;
		conn->variables[idx].value = strdup(def_val);
		conn->var_hash[idx] = SpookyHash::Hash32(def_val, strlen(def_val), 10);
	}

	sess->client_myds = ds;

	// Create a backend with server_myds->myconn for verify_server_variables()
	// and rollback(). In DEBUG builds, commit() and rollback() call
	// verify_server_variables() which dereferences session->mybe->server_myds->myconn.
	PgSQL_Backend* be = new PgSQL_Backend();
	PgSQL_Data_Stream* server_ds = new PgSQL_Data_Stream();
	PgSQL_Connection* server_conn = new PgSQL_Connection(false);
	// Populate server connection with same critical variables
	for (int idx = 0; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {
		const char* def_val = pgsql_tracked_variables[idx].default_value;
		server_conn->variables[idx].value = strdup(def_val);
		server_conn->var_hash[idx] = SpookyHash::Hash32(def_val, strlen(def_val), 10);
	}
	server_ds->myconn = server_conn;
	be->server_myds = server_ds;
	sess->mybe = be;

	return sess;
}

/**
 * @brief Helper: Safely destroy a test session created by create_test_session().
 *
 * Sets client_myds to nullptr before destruction to avoid the session
 * destructor calling myconn->reset() (which asserts on startup_parameters).
 * Manually cleans up the data stream and connection.
 */
static void destroy_test_session(PgSQL_Session* sess) {
	// Clean up backend before session destruction
	if (sess->mybe) {
		PgSQL_Backend* be = sess->mybe;
		if (be->server_myds) {
			PgSQL_Data_Stream* sds = be->server_myds;
			if (sds->myconn) {
				delete sds->myconn;
				sds->myconn = nullptr;
			}
			be->server_myds = nullptr;
			delete sds;
		}
		sess->mybe = nullptr;
		delete be;
	}
	if (sess->client_myds) {
		PgSQL_Data_Stream* ds = sess->client_myds;
		// Detach connection before data stream destruction to avoid
		// the data stream destructor also deleting it
		PgSQL_Connection* conn = ds->myconn;
		ds->myconn = nullptr;
		delete conn;
		sess->client_myds = nullptr;
		delete ds;
	}
	delete sess;
}

// ============================================================
// Accessors on empty state (nullptr session is safe)
// ============================================================

static void test_statemgr_initial_state() {
	PgSQL_ExplicitTxnStateMgr mgr(nullptr);
	ok(mgr.is_in_transaction() == false, "statemgr: initially not in transaction");
	ok(mgr.get_savepoint_count() == 0, "statemgr: initially zero savepoints");
}

static void test_statemgr_reset_empty() {
	PgSQL_ExplicitTxnStateMgr mgr(nullptr);
	// reset_state() on empty state should be a no-op (no crash)
	mgr.reset_state();
	ok(mgr.is_in_transaction() == false, "statemgr: still not in transaction after reset on empty");
	ok(mgr.get_savepoint_count() == 0, "statemgr: still zero savepoints after reset on empty");
}

static void test_statemgr_fill_internal_session_empty() {
	PgSQL_ExplicitTxnStateMgr mgr(nullptr);
	nlohmann::json j;
	mgr.fill_internal_session(j);
	// When not in a transaction, fill_internal_session should not add anything
	ok(j.empty(), "statemgr: fill_internal_session produces empty JSON when no transaction");
}

// ============================================================
// handle_transaction() — unknown command
// ============================================================

static void test_statemgr_handle_unknown() {
	PgSQL_ExplicitTxnStateMgr mgr(nullptr);
	bool result = mgr.handle_transaction("SELECT 1");
	ok(result == false, "statemgr: handle_transaction returns false for unknown command");
	ok(mgr.is_in_transaction() == false, "statemgr: not in transaction after unknown command");
}

// ============================================================
// BEGIN / COMMIT lifecycle
// ============================================================

static void test_statemgr_begin_commit() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	bool r1 = mgr->handle_transaction("BEGIN");
	ok(r1 == true, "statemgr: BEGIN returns true");
	ok(mgr->is_in_transaction() == true, "statemgr: in transaction after BEGIN");
	ok(mgr->get_savepoint_count() == 0, "statemgr: zero savepoints after BEGIN");

	bool r2 = mgr->handle_transaction("COMMIT");
	ok(r2 == true, "statemgr: COMMIT returns true");
	ok(mgr->is_in_transaction() == false, "statemgr: not in transaction after COMMIT");
	ok(mgr->get_savepoint_count() == 0, "statemgr: zero savepoints after COMMIT");

	destroy_test_session(sess);
}

// ============================================================
// BEGIN / ROLLBACK lifecycle
// ============================================================

static void test_statemgr_begin_rollback() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");
	ok(mgr->is_in_transaction() == true, "statemgr: in transaction after BEGIN (rollback test)");

	bool r1 = mgr->handle_transaction("ROLLBACK");
	ok(r1 == true, "statemgr: ROLLBACK returns true");
	ok(mgr->is_in_transaction() == false, "statemgr: not in transaction after ROLLBACK");

	destroy_test_session(sess);
}

// ============================================================
// BEGIN / ROLLBACK AND CHAIN lifecycle
// ============================================================

static void test_statemgr_rollback_and_chain() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");
	ok(mgr->is_in_transaction() == true, "statemgr: in transaction before ROLLBACK AND CHAIN");

	bool r1 = mgr->handle_transaction("ROLLBACK AND CHAIN");
	ok(r1 == true, "statemgr: ROLLBACK AND CHAIN returns true");
	// ROLLBACK AND CHAIN keeps the initial snapshot (stays in transaction)
	ok(mgr->is_in_transaction() == true, "statemgr: still in transaction after ROLLBACK AND CHAIN");
	ok(mgr->get_savepoint_count() == 0, "statemgr: savepoints cleared after ROLLBACK AND CHAIN");

	// Clean up by committing
	mgr->handle_transaction("COMMIT");
	ok(mgr->is_in_transaction() == false, "statemgr: not in transaction after final COMMIT");

	destroy_test_session(sess);
}

// ============================================================
// SAVEPOINT management
// ============================================================

static void test_statemgr_savepoint_add() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");

	bool r1 = mgr->handle_transaction("SAVEPOINT sp1");
	ok(r1 == true, "statemgr: SAVEPOINT sp1 returns true");
	ok(mgr->get_savepoint_count() == 1, "statemgr: one savepoint after SAVEPOINT sp1");

	bool r2 = mgr->handle_transaction("SAVEPOINT sp2");
	ok(r2 == true, "statemgr: SAVEPOINT sp2 returns true");
	ok(mgr->get_savepoint_count() == 2, "statemgr: two savepoints after SAVEPOINT sp2");

	// Duplicate savepoint name should fail
	bool r3 = mgr->handle_transaction("SAVEPOINT sp1");
	ok(r3 == false, "statemgr: duplicate SAVEPOINT sp1 returns false");
	ok(mgr->get_savepoint_count() == 2, "statemgr: still two savepoints after duplicate");

	mgr->handle_transaction("COMMIT");
	ok(mgr->get_savepoint_count() == 0, "statemgr: zero savepoints after COMMIT");

	destroy_test_session(sess);
}

// ============================================================
// RELEASE SAVEPOINT
// ============================================================

static void test_statemgr_release_savepoint() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");
	mgr->handle_transaction("SAVEPOINT sp1");
	mgr->handle_transaction("SAVEPOINT sp2");
	ok(mgr->get_savepoint_count() == 2, "statemgr: two savepoints before RELEASE");

	// Release sp1 — this should also remove sp2 (everything after sp1)
	bool r1 = mgr->handle_transaction("RELEASE SAVEPOINT sp1");
	ok(r1 == true, "statemgr: RELEASE SAVEPOINT sp1 returns true");
	ok(mgr->get_savepoint_count() == 0, "statemgr: zero savepoints after RELEASE sp1 (removes sp1 and later)");
	ok(mgr->is_in_transaction() == true, "statemgr: still in transaction after RELEASE");

	// Release non-existent savepoint should fail
	bool r2 = mgr->handle_transaction("RELEASE SAVEPOINT nonexistent");
	ok(r2 == false, "statemgr: RELEASE non-existent savepoint returns false");

	mgr->handle_transaction("COMMIT");
	destroy_test_session(sess);
}

// ============================================================
// ROLLBACK TO SAVEPOINT
// ============================================================

static void test_statemgr_rollback_to_savepoint() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");
	mgr->handle_transaction("SAVEPOINT sp1");
	mgr->handle_transaction("SAVEPOINT sp2");
	mgr->handle_transaction("SAVEPOINT sp3");
	ok(mgr->get_savepoint_count() == 3, "statemgr: three savepoints before ROLLBACK TO");

	// Rollback to sp2 — this should remove sp2 and sp3 state, keeping sp1
	bool r1 = mgr->handle_transaction("ROLLBACK TO SAVEPOINT sp2");
	ok(r1 == true, "statemgr: ROLLBACK TO sp2 returns true");
	ok(mgr->get_savepoint_count() == 1, "statemgr: one savepoint after ROLLBACK TO sp2");
	ok(mgr->is_in_transaction() == true, "statemgr: still in transaction after ROLLBACK TO");

	// Rollback to non-existent savepoint should fail
	bool r2 = mgr->handle_transaction("ROLLBACK TO SAVEPOINT nonexistent");
	ok(r2 == false, "statemgr: ROLLBACK TO non-existent savepoint returns false");

	mgr->handle_transaction("COMMIT");
	destroy_test_session(sess);
}

// ============================================================
// reset_state() with active transaction
// ============================================================

static void test_statemgr_reset_active_transaction() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");
	mgr->handle_transaction("SAVEPOINT sp1");
	ok(mgr->is_in_transaction() == true, "statemgr: in transaction before reset");
	ok(mgr->get_savepoint_count() == 1, "statemgr: one savepoint before reset");

	mgr->reset_state();
	ok(mgr->is_in_transaction() == false, "statemgr: not in transaction after reset_state");
	ok(mgr->get_savepoint_count() == 0, "statemgr: zero savepoints after reset_state");

	destroy_test_session(sess);
}

// ============================================================
// fill_internal_session() with active transaction
// ============================================================

static void test_statemgr_fill_internal_session_active() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");
	mgr->handle_transaction("SAVEPOINT sp1");

	nlohmann::json j;
	mgr->fill_internal_session(j);

	// Should have "initial_state" key
	ok(j.contains("initial_state"), "statemgr: JSON contains 'initial_state' after BEGIN");
	// Should have "savepoints" with "sp1" key
	ok(j.contains("savepoints"), "statemgr: JSON contains 'savepoints' after SAVEPOINT");
	ok(j["savepoints"].contains("sp1"), "statemgr: JSON savepoints contains 'sp1'");

	mgr->reset_state();
	destroy_test_session(sess);
}

// ============================================================
// fill_internal_session() — transaction without savepoints
// ============================================================

static void test_statemgr_fill_internal_session_no_savepoints() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");

	nlohmann::json j;
	mgr->fill_internal_session(j);

	ok(j.contains("initial_state"), "statemgr: JSON has 'initial_state' with no savepoints");
	ok(!j.contains("savepoints"), "statemgr: JSON has no 'savepoints' key when none exist");

	mgr->reset_state();
	destroy_test_session(sess);
}

// NOTE: Duplicate BEGIN (BEGIN while already in transaction) is not tested here
// because it requires NumActiveTransactions() > 0, which needs a fully wired
// backend connection with an active transaction — too complex for unit testing.

// ============================================================
// SAVEPOINT case-insensitive lookup
// ============================================================

static void test_statemgr_savepoint_case_insensitive() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");
	mgr->handle_transaction("SAVEPOINT MyPoint");
	ok(mgr->get_savepoint_count() == 1, "statemgr: one savepoint after SAVEPOINT MyPoint");

	// Duplicate with different case should fail (case-insensitive match)
	bool r = mgr->handle_transaction("SAVEPOINT mypoint");
	ok(r == false, "statemgr: duplicate savepoint with different case returns false");
	ok(mgr->get_savepoint_count() == 1, "statemgr: still one savepoint after case-insensitive dup");

	// Release with different case should succeed
	bool r2 = mgr->handle_transaction("RELEASE SAVEPOINT MYPOINT");
	ok(r2 == true, "statemgr: RELEASE with different case succeeds");
	ok(mgr->get_savepoint_count() == 0, "statemgr: zero savepoints after case-insensitive RELEASE");

	mgr->handle_transaction("COMMIT");
	destroy_test_session(sess);
}

// ============================================================
// END as COMMIT synonym through state manager
// ============================================================

static void test_statemgr_end_as_commit() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");
	ok(mgr->is_in_transaction() == true, "statemgr: in transaction before END");

	bool r = mgr->handle_transaction("END");
	ok(r == true, "statemgr: END returns true");
	ok(mgr->is_in_transaction() == false, "statemgr: not in transaction after END (COMMIT synonym)");

	destroy_test_session(sess);
}

// ============================================================
// ABORT as ROLLBACK synonym through state manager
// ============================================================

static void test_statemgr_abort_as_rollback() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_ExplicitTxnStateMgr* mgr = sess->transaction_state_manager;

	mgr->handle_transaction("BEGIN");
	ok(mgr->is_in_transaction() == true, "statemgr: in transaction before ABORT");

	bool r = mgr->handle_transaction("ABORT");
	ok(r == true, "statemgr: ABORT returns true");
	ok(mgr->is_in_transaction() == false, "statemgr: not in transaction after ABORT (ROLLBACK synonym)");

	destroy_test_session(sess);
}

// ============================================================
// Processlist query truncation
// ============================================================

static void test_current_query_short_truncation_limits() {
	PgSQL_Session* sess = create_test_session();
	std::string query = "SELECT 123456789";
	sess->CurrentQuery.QueryPointer =
		reinterpret_cast<unsigned char*>(query.data());
	sess->CurrentQuery.QueryLength = query.size();

	for (int max_length = 1; max_length <= 4; ++max_length) {
		char* current_query = sess->get_current_query(max_length);
		const std::string expected = max_length < 4
			? query.substr(0, max_length)
			: "S...";
		ok(current_query != nullptr && expected == current_query,
			"current query: max length %d is truncated safely", max_length);
		free(current_query);
	}

	char* current_query = sess->get_current_query();
	ok(current_query != nullptr && query == current_query,
		"current query: unlimited length preserves the complete query");
	free(current_query);

	destroy_test_session(sess);
}

int main() {
	plan(117);
	test_init_minimal();

	// --- Parser tests (54 tests) ---
	test_parser_begin();                            // 1
	test_parser_begin_variants();                   // 7
	test_parser_commit();                           // 4
	test_parser_rollback();                         // 6
	test_parser_rollback_and_chain();               // 3
	test_parser_savepoint();                        // 6
	test_parser_rollback_to_savepoint();            // 6
	test_parser_release_savepoint();                // 6
	test_parser_non_txn_commands();                 // 3
	test_parser_empty_and_whitespace();             // 2
	test_parser_semicolons();                       // 3
	test_parser_leading_whitespace();               // 2
	test_parser_reuse();                            // 6
	// Parser subtotal: 54

	// --- State Manager tests (58 tests) ---
	test_statemgr_initial_state();                  // 2
	test_statemgr_reset_empty();                    // 2
	test_statemgr_fill_internal_session_empty();    // 1
	test_statemgr_handle_unknown();                 // 2
	test_statemgr_begin_commit();                   // 6
	test_statemgr_begin_rollback();                 // 3
	test_statemgr_rollback_and_chain();             // 5
	test_statemgr_savepoint_add();                  // 7
	test_statemgr_release_savepoint();              // 5
	test_statemgr_rollback_to_savepoint();          // 5
	test_statemgr_reset_active_transaction();       // 4
	test_statemgr_fill_internal_session_active();   // 3
	test_statemgr_fill_internal_session_no_savepoints(); // 2
	test_statemgr_savepoint_case_insensitive();     // 5
	test_statemgr_end_as_commit();                  // 3
	test_statemgr_abort_as_rollback();              // 3
	// State manager subtotal: 58

	// --- Processlist query truncation (5 tests) ---
	test_current_query_short_truncation_limits();   // 5
	// Grand total: 54 + 58 + 5 = 117

	test_cleanup_minimal();
	return exit_status();
}
