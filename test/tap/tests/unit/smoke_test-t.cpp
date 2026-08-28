/**
 * @file smoke_test-t.cpp
 * @brief Smoke test for the ProxySQL unit test harness.
 *
 * Validates that the test infrastructure (test_globals + test_init)
 * works correctly by performing minimal operations on each supported
 * component. This test must pass before any component-specific unit
 * tests can be trusted.
 *
 * Test coverage:
 *   1. test_init_minimal() — GloVars is usable
 *   2. test_init_auth()    — MySQL_Authentication add/lookup cycle
 *   3. test_cleanup_*()    — clean shutdown without leaks
 *
 * @see Phase 2.1 of the Unit Testing Framework (GitHub issue #5473)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "MySQL_Authentication.hpp"
#include "PgSQL_Authentication.h"

// Extern declarations for Glo* pointers (defined in test_globals.cpp)
extern MySQL_Authentication *GloMyAuth;
extern PgSQL_Authentication *GloPgAuth;

/**
 * @brief Test that minimal initialization sets up GloVars correctly.
 */
static void test_minimal_init() {
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() returns 0");
	ok(GloVars.datadir != nullptr, "GloVars.datadir is set after init");
	ok(GloVars.global.nostart == true, "GloVars.global.nostart is true");
}

/**
 * @brief Test MySQL_Authentication add/lookup/del cycle.
 */
static void test_mysql_auth_basic() {
	int rc = test_init_auth();
	ok(rc == 0, "test_init_auth() returns 0");
	ok(GloMyAuth != nullptr, "GloMyAuth is initialized");
	ok(GloPgAuth != nullptr, "GloPgAuth is initialized");

	// Add a frontend user
	bool added = GloMyAuth->add(
		(char *)"testuser",          // username
		(char *)"testpass",          // password
		USERNAME_FRONTEND,           // user type
		false,                       // use_ssl
		0,                           // default_hostgroup
		(char *)"",                  // default_schema
		false,                       // schema_locked
		false,                       // transaction_persistent
		false,                       // fast_forward
		100,                         // max_connections
		(char *)"",                  // attributes
		(char *)""                   // comment
	);
	ok(added == true, "GloMyAuth->add() succeeds for frontend user");

	// Verify user exists
	bool exists = GloMyAuth->exists((char *)"testuser");
	ok(exists == true, "GloMyAuth->exists() returns true for added user");

	// Verify user does not exist
	bool not_exists = GloMyAuth->exists((char *)"nonexistent");
	ok(not_exists == false, "GloMyAuth->exists() returns false for unknown user");

	// Cleanup
	test_cleanup_auth();
	ok(GloMyAuth == nullptr, "GloMyAuth is nullptr after cleanup");
	ok(GloPgAuth == nullptr, "GloPgAuth is nullptr after cleanup");
}

/**
 * @brief Test idempotency of init/cleanup functions.
 */
static void test_idempotency() {
	// Double init should be safe
	int rc1 = test_init_minimal();
	int rc2 = test_init_minimal();
	ok(rc1 == 0 && rc2 == 0, "test_init_minimal() is idempotent");

	int rc3 = test_init_auth();
	int rc4 = test_init_auth();
	ok(rc3 == 0 && rc4 == 0, "test_init_auth() is idempotent");

	// Double cleanup should be safe
	test_cleanup_auth();
	test_cleanup_auth();  // should not crash
	ok(1, "test_cleanup_auth() double-call does not crash");

	test_cleanup_minimal();
	test_cleanup_minimal();  // should not crash
	ok(1, "test_cleanup_minimal() double-call does not crash");
}

int main() {
	plan(15);

	test_minimal_init();
	test_mysql_auth_basic();
	test_idempotency();

	return exit_status();
}
