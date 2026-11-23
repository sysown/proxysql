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

static void test_if_not_exists_preserves_rows() {
    const char* ddl = "CREATE TABLE IF NOT EXISTS guarded_table (id INTEGER PRIMARY KEY, value TEXT)";
    ok(db->check_and_build_table("guarded_table", ddl) &&
       db->execute("INSERT INTO guarded_table VALUES (1, 'persist')"),
       "IF NOT EXISTS: create and seed a persistent table");
    ok(db->check_table_structure("guarded_table", ddl) == 1,
       "IF NOT EXISTS: definition matches SQLite's stored CREATE TABLE form");
    ok(db->check_and_build_table("guarded_table", ddl) &&
       db->return_one_int("SELECT COUNT(*) FROM guarded_table WHERE value='persist'") == 1,
       "IF NOT EXISTS: repeated materialization preserves existing rows");
    ok(db->check_table_structure("guarded_table",
       "CREATE TABLE IF NOT EXISTS guarded_table (id TEXT, value TEXT)") == 0,
       "IF NOT EXISTS: a genuinely different schema still does not match");
}

static void test_create_table_prefix_variants_preserve_rows() {
    const char* prefixes[] = {
        "CREATE TABLE if not exists ",
        "create table IF NOT EXISTS ",
        "CrEaTe  TaBlE\tIf\nNoT\r\nExIsTs\t",
        "\n\t CREATE \r\nTABLE \t IF   NOT \f EXISTS    ",
        "CREATE\tTABLE\n",
        "create table "
    };
    for (const char* prefix : prefixes) {
        db->execute("DROP TABLE IF EXISTS prefix_guard");
        const std::string ddl = std::string(prefix) +
            "prefix_guard (id INTEGER PRIMARY KEY, value TEXT DEFAULT 'IF NOT EXISTS  Keep Case')";
        ok(db->check_and_build_table("prefix_guard", ddl.c_str()) &&
           db->execute("INSERT INTO prefix_guard (id) VALUES (1)"),
           "prefix variant: create and seed a persistent table");
        ok(db->check_table_structure("prefix_guard", ddl.c_str()) == 1,
           "prefix variant: definition matches SQLite's stored form");
        ok(db->check_table_structure("prefix_guard",
           "CREATE TABLE prefix_guard (id INTEGER PRIMARY KEY, value TEXT DEFAULT 'if not exists  Keep Case')") == 0,
           "prefix variant: literal case in the table body remains significant");
        ok(db->check_and_build_table("prefix_guard", ddl.c_str()) &&
           db->return_one_int("SELECT COUNT(*) FROM prefix_guard WHERE id=1 "
               "AND value='IF NOT EXISTS  Keep Case'") == 1,
           "prefix variant: repeated materialization preserves the seeded row and literal");
    }
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
        static_cast<unsigned long>(INT_MAX / 2),
        static_cast<unsigned long>(INT_MAX / 2)
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
// Native prepared statement proxy APIs
// ============================================================

static void test_native_prepared_proxy_apis() {
    sqlite3 *raw = db->get_db();
    sqlite3_stmt *stmt = nullptr;
    int rc = 0;

    // Parameter counts on real prepared statements.
    rc = (*proxy_sqlite3_prepare_v2)(raw, "SELECT ?1, ?2, ?3", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: SELECT with 3 parameters succeeds");
    ok((*proxy_sqlite3_bind_parameter_count)(stmt) == 3,
       "bind_parameter_count: reports 3 for three bound parameters");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;

    rc = (*proxy_sqlite3_prepare_v2)(raw, "SELECT 1", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: parameterless SELECT succeeds");
    ok((*proxy_sqlite3_bind_parameter_count)(stmt) == 0,
       "bind_parameter_count: reports 0 for parameterless statement");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;

    // Declared column metadata.
    db->execute("DROP TABLE IF EXISTS native_meta");
    db->execute("CREATE TABLE native_meta (a INTEGER, b TEXT, c BLOB)");
    rc = (*proxy_sqlite3_prepare_v2)(raw, "SELECT a, b, c FROM native_meta", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: SELECT from typed table succeeds");
    ok((*proxy_sqlite3_column_count)(stmt) == 3,
       "column_count: typed SELECT has 3 columns");
    ok((*proxy_sqlite3_column_decltype)(stmt, 0) != nullptr &&
       strcmp((*proxy_sqlite3_column_decltype)(stmt, 0), "INTEGER") == 0,
       "column_decltype: first column declared INTEGER");
    ok((*proxy_sqlite3_column_decltype)(stmt, 1) != nullptr &&
       strcmp((*proxy_sqlite3_column_decltype)(stmt, 1), "TEXT") == 0,
       "column_decltype: second column declared TEXT");
    ok((*proxy_sqlite3_column_decltype)(stmt, 2) != nullptr &&
       strcmp((*proxy_sqlite3_column_decltype)(stmt, 2), "BLOB") == 0,
       "column_decltype: third column declared BLOB");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;

    // Binary data, including embedded NUL bytes.
    db->execute("DROP TABLE IF EXISTS native_binary");
    db->execute("CREATE TABLE native_binary (payload BLOB)");
    rc = (*proxy_sqlite3_prepare_v2)(raw, "INSERT INTO native_binary (payload) VALUES (?1)", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: INSERT BLOB statement succeeds");
    char binary_data[] = {'A', '\0', 'B', '\0', 'C'};
    rc = (*proxy_sqlite3_bind_blob)(stmt, 1, binary_data, 5, SQLITE_TRANSIENT);
    ok(rc == SQLITE_OK, "bind_blob: binds 5 bytes including embedded NULs");
    rc = (*proxy_sqlite3_step)(stmt);
    ok(rc == SQLITE_DONE, "step: INSERT BLOB completes");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;

    rc = (*proxy_sqlite3_prepare_v2)(raw, "SELECT payload FROM native_binary", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: SELECT BLOB succeeds");
    rc = (*proxy_sqlite3_step)(stmt);
    ok(rc == SQLITE_ROW, "step: SELECT BLOB returns a row");
    ok((*proxy_sqlite3_column_type)(stmt, 0) == SQLITE_BLOB,
       "column_type: stored value is SQLITE_BLOB");
    ok((*proxy_sqlite3_column_bytes)(stmt, 0) == 5,
       "column_bytes: BLOB length is 5");
    const void *blob = (*proxy_sqlite3_column_blob)(stmt, 0);
    ok(blob != nullptr && memcmp(blob, binary_data, 5) == 0,
       "column_blob: bytes match, including embedded NULs");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;

    // Empty BLOB versus SQL NULL.
    db->execute("DROP TABLE IF EXISTS native_empty_blob");
    db->execute("CREATE TABLE native_empty_blob (payload BLOB)");
    rc = (*proxy_sqlite3_prepare_v2)(raw, "INSERT INTO native_empty_blob (payload) VALUES (?1)", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: INSERT empty BLOB statement succeeds");
    char non_null_dummy = 0;
    rc = (*proxy_sqlite3_bind_blob)(stmt, 1, &non_null_dummy, 0, SQLITE_TRANSIENT);
    ok(rc == SQLITE_OK, "bind_blob: empty BLOB uses non-null pointer with length 0");
    rc = (*proxy_sqlite3_step)(stmt);
    ok(rc == SQLITE_DONE, "step: INSERT empty BLOB completes");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;

    rc = (*proxy_sqlite3_prepare_v2)(raw, "SELECT payload FROM native_empty_blob", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: SELECT empty BLOB succeeds");
    rc = (*proxy_sqlite3_step)(stmt);
    ok(rc == SQLITE_ROW, "step: SELECT empty BLOB returns a row");
    ok((*proxy_sqlite3_column_type)(stmt, 0) == SQLITE_BLOB,
       "column_type: empty value is SQLITE_BLOB, not NULL");
    ok((*proxy_sqlite3_column_bytes)(stmt, 0) == 0,
       "column_bytes: empty BLOB length is 0");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;

    db->execute("DROP TABLE IF EXISTS native_sql_null");
    db->execute("CREATE TABLE native_sql_null (payload BLOB)");
    rc = (*proxy_sqlite3_prepare_v2)(raw, "INSERT INTO native_sql_null (payload) VALUES (?1)", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: INSERT NULL statement succeeds");
    rc = (*proxy_sqlite3_bind_null)(stmt, 1);
    ok(rc == SQLITE_OK, "bind_null: binds SQL NULL");
    rc = (*proxy_sqlite3_step)(stmt);
    ok(rc == SQLITE_DONE, "step: INSERT NULL completes");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;

    rc = (*proxy_sqlite3_prepare_v2)(raw, "SELECT payload FROM native_sql_null", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: SELECT NULL succeeds");
    rc = (*proxy_sqlite3_step)(stmt);
    ok(rc == SQLITE_ROW, "step: SELECT NULL returns a row");
    ok((*proxy_sqlite3_column_type)(stmt, 0) == SQLITE_NULL,
       "column_type: SQL NULL reports SQLITE_NULL");
    ok((*proxy_sqlite3_column_bytes)(stmt, 0) == 0,
       "column_bytes: SQL NULL length is 0");
    ok((*proxy_sqlite3_column_blob)(stmt, 0) == nullptr,
       "column_blob: SQL NULL returns null pointer");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;

    // Statement read-only classification without executing DML.
    rc = (*proxy_sqlite3_prepare_v2)(raw, "SELECT 1", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: readonly SELECT succeeds");
    ok((*proxy_sqlite3_stmt_readonly)(stmt) == 1,
       "stmt_readonly: SELECT statement is readonly");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;

    rc = (*proxy_sqlite3_prepare_v2)(raw, "INSERT INTO native_meta (a, b, c) VALUES (1, 'x', NULL)", -1, &stmt, nullptr);
    ok(rc == SQLITE_OK, "native prepare: non-readonly INSERT succeeds");
    ok((*proxy_sqlite3_stmt_readonly)(stmt) == 0,
       "stmt_readonly: INSERT statement is not readonly");
    (*proxy_sqlite3_finalize)(stmt);
    stmt = nullptr;
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
    plan(87);
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
    test_if_not_exists_preserves_rows();
    test_create_table_prefix_variants_preserve_rows();
    test_sqlite3_row_get_size();            // 2
    test_sized_row_rejects_int_overflow();  // 2
    test_native_prepared_proxy_apis();      // 36
    test_rdlock_unlock();                   // 1
    test_wrlock_unlock();                   // 1

    teardown_db();
    test_cleanup_minimal();
    return exit_status();
}
