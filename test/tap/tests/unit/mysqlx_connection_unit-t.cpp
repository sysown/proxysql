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

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(10);
	diag("=== mysqlx_connection_unit-t starting ===");

	test_connection_creation();
	test_connection_multiplexing();

	return exit_status();
}
