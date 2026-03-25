/**
 * @file pgsql_txn_state_unit-t.cpp
 * @brief Unit tests for PgSQL_TxnCmdParser — PostgreSQL transaction command parsing.
 *
 * Tests the pure parsing logic of PgSQL_TxnCmdParser::parse() which tokenizes
 * SQL transaction commands and returns a TxnCmd struct with .type and .savepoint.
 *
 * No session or connection objects are needed — the parser is fully standalone.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_ExplicitTxnStateMgr.h"

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

int main() {
	plan(54);
	test_init_minimal();

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
	// Total: 55... let me recount
	// 1+7+4+6+3+6+6+6+3+2+3+2+6 = 55? No:
	// 1+7=8, +4=12, +6=18, +3=21, +6=27, +6=33, +6=39, +3=42, +2=44, +3=47, +2=49, +6=55
	// Adjusting plan above

	test_cleanup_minimal();
	return exit_status();
}
