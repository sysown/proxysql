/**
 * @file pgsql_command_complete_unit-t.cpp
 * @brief Unit tests for PostgreSQL CommandComplete tag parser.
 *
 * Tests parse_pgsql_command_complete() which extracts row counts
 * from PgSQL CommandComplete message tags.
 *
 * @see FFTO unit testing (GitHub issue #5499)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQLCommandComplete.h"

#include <cstring>

static PgSQLCommandResult parse(const char *tag) {
	return parse_pgsql_command_complete(
		(const unsigned char *)tag, strlen(tag));
}

static void test_dml_commands() {
	auto r = parse("INSERT 0 10");
	ok(r.rows == 10 && r.is_select == false, "INSERT 0 10 → rows=10");

	r = parse("UPDATE 3");
	ok(r.rows == 3 && r.is_select == false, "UPDATE 3 → rows=3");

	r = parse("DELETE 0");
	ok(r.rows == 0 && r.is_select == false, "DELETE 0 → rows=0");

	r = parse("COPY 100");
	ok(r.rows == 100 && r.is_select == false, "COPY 100 → rows=100");

	r = parse("MERGE 5");
	ok(r.rows == 5 && r.is_select == false, "MERGE 5 → rows=5");
}

static void test_select_commands() {
	auto r = parse("SELECT 50");
	ok(r.rows == 50 && r.is_select == true, "SELECT 50 → rows=50, is_select");

	r = parse("FETCH 10");
	ok(r.rows == 10 && r.is_select == true, "FETCH 10 → rows=10, is_select");

	r = parse("MOVE 7");
	ok(r.rows == 7 && r.is_select == true, "MOVE 7 → rows=7, is_select");
}

static void test_no_row_count() {
	auto r = parse("CREATE TABLE");
	ok(r.rows == 0, "CREATE TABLE → rows=0 (no row count)");

	r = parse("DROP INDEX");
	ok(r.rows == 0, "DROP INDEX → rows=0");

	r = parse("BEGIN");
	ok(r.rows == 0, "BEGIN → rows=0 (single token, no space)");
}

static void test_edge_cases() {
	// Empty payload
	auto r = parse_pgsql_command_complete(nullptr, 0);
	ok(r.rows == 0, "null payload → rows=0");

	r = parse("");
	ok(r.rows == 0, "empty string → rows=0");

	// Whitespace padding
	r = parse("  SELECT 42  ");
	ok(r.rows == 42, "whitespace padded SELECT → rows=42");

	// INSERT with OID (two numbers after command)
	r = parse("INSERT 0 1");
	ok(r.rows == 1, "INSERT 0 1 → rows=1 (last token)");

	// Large row count
	r = parse("SELECT 999999999");
	ok(r.rows == 999999999, "large row count parsed correctly");
}

int main() {
	plan(17);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_dml_commands();       // 5
	test_select_commands();    // 3
	test_no_row_count();       // 3
	test_edge_cases();         // 5
	// Total: 1+5+3+3+5 = 17

	test_cleanup_minimal();
	return exit_status();
}
