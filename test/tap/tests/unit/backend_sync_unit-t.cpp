/**
 * @file backend_sync_unit-t.cpp
 * @brief Unit tests for backend variable sync decisions.
 *
 * @see Phase 3.6 (GitHub issue #5494)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "BackendSyncDecision.h"

static void test_no_sync_needed() {
	int a = determine_backend_sync_actions("user", "user", "db", "db", true, true);
	ok(a == SYNC_NONE, "no sync: all match");

	a = determine_backend_sync_actions("user", "user", "db", "db", false, false);
	ok(a == SYNC_NONE, "no sync: autocommit both false");
}

static void test_schema_mismatch() {
	int a = determine_backend_sync_actions("user", "user", "app_db", "other_db", true, true);
	ok((a & SYNC_SCHEMA) != 0, "schema mismatch: SYNC_SCHEMA set");
	ok((a & SYNC_USER) == 0, "schema mismatch: SYNC_USER not set");
}

static void test_user_mismatch() {
	int a = determine_backend_sync_actions("alice", "bob", "db", "db", true, true);
	ok((a & SYNC_USER) != 0, "user mismatch: SYNC_USER set");
	// Schema check skipped when user differs (CHANGE USER handles schema)
	ok((a & SYNC_SCHEMA) == 0, "user mismatch: SYNC_SCHEMA not set (handled by CHANGE USER)");
}

static void test_user_and_schema_mismatch() {
	int a = determine_backend_sync_actions("alice", "bob", "db1", "db2", true, true);
	ok((a & SYNC_USER) != 0, "user+schema: SYNC_USER set");
	ok((a & SYNC_SCHEMA) == 0, "user+schema: schema handled by user change");
}

static void test_autocommit_mismatch() {
	int a = determine_backend_sync_actions("user", "user", "db", "db", true, false);
	ok((a & SYNC_AUTOCOMMIT) != 0, "autocommit mismatch: SYNC_AUTOCOMMIT set");
	ok((a & SYNC_SCHEMA) == 0, "autocommit mismatch: no other sync");
}

static void test_multiple_mismatches() {
	int a = determine_backend_sync_actions("user", "user", "db1", "db2", true, false);
	ok((a & SYNC_SCHEMA) != 0, "multi: SYNC_SCHEMA set");
	ok((a & SYNC_AUTOCOMMIT) != 0, "multi: SYNC_AUTOCOMMIT set");
}

static void test_null_handling() {
	// null users — no crash
	int a = determine_backend_sync_actions(nullptr, "user", "db", "db", true, true);
	ok(a == SYNC_NONE || a >= 0, "null client_user: no crash");

	a = determine_backend_sync_actions("user", nullptr, "db", "db", true, true);
	ok(a == SYNC_NONE || a >= 0, "null backend_user: no crash");
}

int main() {
	plan(15);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_no_sync_needed();           // 2
	test_schema_mismatch();          // 2
	test_user_mismatch();            // 2
	test_user_and_schema_mismatch(); // 2
	test_autocommit_mismatch();      // 2
	test_multiple_mismatches();      // 2
	test_null_handling();            // 2
	// Total: 1+2+2+2+2+2+2+2 = 15

	test_cleanup_minimal();
	return exit_status();
}
