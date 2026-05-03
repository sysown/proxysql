#include "mysqlx_connection.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include <cstring>

static void test_connection_creation() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	ok(conn.get_state() == MysqlxConnection::CREATED, "initial state is CREATED");
	ok(conn.get_hostgroup() == -1, "no hostgroup initially");
	ok(!conn.is_reusable(), "not reusable before connect");
	conn.set_hostgroup(5);
	ok(conn.get_hostgroup() == 5, "hostgroup set to 5");
	conn.set_user("testuser");
	conn.set_schema("testdb");
	ok(strcmp(conn.get_user(), "testuser") == 0, "user set");
	ok(strcmp(conn.get_schema(), "testdb") == 0, "schema set");
}

static void test_connection_multiplexing() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_reusable(true);
	ok(conn.is_reusable(), "marked reusable");
	conn.set_has_prepared_statement(true);
	ok(!conn.is_reusable(), "prepared statement disables reuse");
	conn.set_has_prepared_statement(false);
	conn.set_reusable(true);
	ok(conn.is_reusable(), "re-enabled after prepared statement cleared");
	conn.set_in_transaction(true);
	ok(!conn.is_reusable(), "transaction disables reuse");
}

// Issue #5697: post-Session::Reset rehandshake flag invalidates the
// connection for pool reuse. Default-constructed connections have the
// flag clear; setting it forces is_reusable() to false even on an
// otherwise-reusable connection; reset() clears the flag defensively.
static void test_connection_post_reset_rehandshake_flag() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	ok(!conn.needs_post_reset_rehandshake(),
	   "default: needs_post_reset_rehandshake() == false");

	// Make the connection otherwise-reusable, then flip the flag.
	conn.set_reusable(true);
	ok(conn.is_reusable(), "pre-flag: is_reusable() == true");

	conn.set_needs_post_reset_rehandshake(true);
	ok(conn.needs_post_reset_rehandshake(),
	   "after set: needs_post_reset_rehandshake() == true");
	ok(!conn.is_reusable(),
	   "after set: is_reusable() == false (post-reset state forces drop)");

	// reset() defensively clears the flag — production path doesn't
	// rely on this (the cache deletes non-reusable conns instead of
	// resetting them), but the invariant matters for retry-on-error
	// or any other future code path that calls reset() directly.
	conn.reset();
	ok(!conn.needs_post_reset_rehandshake(),
	   "after reset(): needs_post_reset_rehandshake() == false (defensive clear)");
	ok(conn.is_reusable(),
	   "after reset(): is_reusable() == true (reset re-enables)");
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	// Plan derives from ok() count; new test_connection_post_reset_*
	// adds 6 ok() so total is 10 + 6 = 16. Switching to plan(0) so
	// further additions don't require re-counting.
	plan(0);
	diag("=== mysqlx_connection_unit-t starting ===");

	test_connection_creation();
	test_connection_multiplexing();
	test_connection_post_reset_rehandshake_flag();

	return exit_status();
}
