/**
 * @file sqlite3db_unit-t.cpp
 * @brief Unit tests for SQLite3DB — the foundational database wrapper.
 *
 * Tests cover: execute(), execute_statement(), return_one_int(),
 * check_table_structure(), build_table(), check_and_build_table(),
 * SQLite3_row::get_size(), and locking primitives.
 *
 * All tests use an in-memory SQLite3 database — no external deps.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "sqlite3db.h"

#include <climits>
#include <cstring>
#include <string>

// ============================================================
// SQLite3DB core operations
// ============================================================

static SQLite3DB *db = nullptr;

static void setup_db() {
    db = new SQLite3DB();
    db->open((char *)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
}

static void teardown_db() {
    delete db;
    db = nullptr;
}

static void test_open_and_execute() {
    bool rc = db->execute("CREATE TABLE test_t (id INTEGER PRIMARY KEY, name TEXT)");
    ok(rc == true, "execute: CREATE TABLE succeeds (returns true)");
}

static void test_execute_insert_select() {
    db->execute("INSERT INTO test_t (id, name) VALUES (1, 'alice')");
    db->execute("INSERT INTO test_t (id, name) VALUES (2, 'bob')");

    char *error = nullptr;
    SQLite3_result *result = db->execute_statement("SELECT COUNT(*) FROM test_t", &error);
    ok(result != nullptr, "execute_statement: returns result for SELECT");
    ok(result != nullptr && result->rows_count == 1, "execute_statement: COUNT(*) returns 1 row");
    if (result && result->rows_count > 0) {
        ok(strcmp(result->rows[0]->fields[0], "2") == 0,
           "execute_statement: COUNT(*) = 2");
    } else {
        ok(false, "execute_statement: COUNT(*) = 2 (no result)");
    }
    if (error) free(error);
    delete result;
}

// ============================================================
// return_one_int() — convenience wrapper
// ============================================================

static void test_return_one_int() {
    int val = db->return_one_int("SELECT 42");
    ok(val == 42, "return_one_int: SELECT 42 returns 42");
}

static void test_return_one_int_from_table() {
    int val = db->return_one_int("SELECT COUNT(*) FROM test_t");
    ok(val == 2, "return_one_int: COUNT(*) from test_t = 2");
}

static void test_return_one_int_no_rows() {
    int val = db->return_one_int("SELECT id FROM test_t WHERE id = 999");
    ok(val == 0, "return_one_int: no rows returns 0");
}

// ============================================================
// check_table_structure() — schema validation
// ============================================================

static void test_check_table_structure_match() {
    // The CREATE statement we used
    int match = db->check_table_structure(
        (char *)"test_t",
        (char *)"CREATE TABLE test_t (id INTEGER PRIMARY KEY, name TEXT)"
    );
    ok(match == 1, "check_table_structure: matching schema returns 1");
}

static void test_check_table_structure_mismatch() {
    int match = db->check_table_structure(
        (char *)"test_t",
        (char *)"CREATE TABLE test_t (id INTEGER, extra_col TEXT)"
    );
    ok(match == 0, "check_table_structure: mismatched schema returns 0");
}

static void test_check_table_structure_nonexistent() {
    int match = db->check_table_structure(
        (char *)"nonexistent_table",
        (char *)"CREATE TABLE nonexistent_table (id INT)"
    );
    ok(match == 0, "check_table_structure: nonexistent table returns 0");
}

// ============================================================
// build_table() / check_and_build_table()
// ============================================================

static void test_build_table() {
    bool rc = db->build_table(
        (char *)"new_table",
        (char *)"CREATE TABLE new_table (val TEXT)",
        false  // don't drop if exists
    );
    ok(rc == true, "build_table: creates new table successfully");

    // Verify it exists
    int count = db->return_one_int("SELECT COUNT(*) FROM new_table");
    ok(count == 0, "build_table: new table is empty");
}

static void test_build_table_drop_recreate() {
    // Insert data first
    db->execute("INSERT INTO new_table VALUES ('data')");
    int before = db->return_one_int("SELECT COUNT(*) FROM new_table");
    ok(before == 1, "build_table: table has 1 row before drop");

    bool rc = db->build_table(
        (char *)"new_table",
        (char *)"CREATE TABLE new_table (val TEXT)",
        true  // drop and recreate
    );
    ok(rc == true, "build_table: drop+recreate succeeds");

    int after = db->return_one_int("SELECT COUNT(*) FROM new_table");
    ok(after == 0, "build_table: table is empty after drop+recreate");
}

static void test_check_and_build_table_creates() {
    db->check_and_build_table(
        (char *)"auto_table",
        (char *)"CREATE TABLE auto_table (x INT)"
    );
    int count = db->return_one_int("SELECT COUNT(*) FROM auto_table");
    ok(count == 0, "check_and_build_table: creates table if not exists");
}

static void test_check_and_build_table_idempotent() {
    db->execute("INSERT INTO auto_table VALUES (1)");
    db->check_and_build_table(
        (char *)"auto_table",
        (char *)"CREATE TABLE auto_table (x INT)"
    );
    int count = db->return_one_int("SELECT COUNT(*) FROM auto_table");
    ok(count == 1, "check_and_build_table: idempotent -- data preserved");
}

// ============================================================
// SQLite3_row — row operations
// ============================================================

static void test_sqlite3_row_get_size() {
    char *error = nullptr;
    SQLite3_result *result = db->execute_statement("SELECT id, name FROM test_t WHERE id = 1", &error);
    ok(result != nullptr && result->rows_count == 1, "row_get_size: got 1 row");
    if (result && result->rows_count > 0) {
        unsigned long long sz = result->rows[0]->get_size();
        ok(sz > 0, "row_get_size: size is non-zero");
    } else {
        ok(false, "row_get_size: size is non-zero (no result)");
    }
    if (error) free(error);
    delete result;
}

static void test_sized_row_rejects_int_overflow() {
    char byte = 'x';
    char *fields[] = { &byte, &byte };
    const unsigned long oversized_field[] = {
        static_cast<unsigned long>(INT_MAX) + 1UL,
        0UL
    };
    const unsigned long oversized_row[] = {
        static_cast<unsigned long>(INT_MAX),
        1UL
    };

    SQLite3_result result(2);
    ok(result.add_row(fields, oversized_field) == SQLITE_TOOBIG &&
       result.rows_count == 0 && result.rows.empty(),
       "a sized field larger than INT_MAX is rejected without adding a row");
    ok(result.add_row(fields, oversized_row) == SQLITE_TOOBIG &&
       result.rows_count == 0 && result.rows.empty(),
       "a sized row larger than INT_MAX is rejected without adding a row");
}

// ============================================================
// Locking operations (basic sanity)
// ============================================================

static void test_rdlock_unlock() {
    // Just verify no crash/deadlock on lock+unlock
    db->rdlock();
    db->rdunlock();
    ok(true, "rdlock/rdunlock: no crash");
}

static void test_wrlock_unlock() {
    db->wrlock();
    db->wrunlock();
    ok(true, "wrlock/wrunlock: no crash");
}

int main() {
    plan(23);
    test_init_minimal();

    setup_db();

    test_open_and_execute();                // 1
    test_execute_insert_select();           // 3
    test_return_one_int();                  // 1
    test_return_one_int_from_table();       // 1
    test_return_one_int_no_rows();          // 1
    test_check_table_structure_match();     // 1
    test_check_table_structure_mismatch();  // 1
    test_check_table_structure_nonexistent(); // 1
    test_build_table();                     // 2
    test_build_table_drop_recreate();       // 3
    test_check_and_build_table_creates();   // 1
    test_check_and_build_table_idempotent();// 1
    test_sqlite3_row_get_size();            // 2
    test_sized_row_rejects_int_overflow();  // 2
    test_rdlock_unlock();                   // 1
    test_wrlock_unlock();                   // 1

    teardown_db();
    test_cleanup_minimal();
    return exit_status();
}
