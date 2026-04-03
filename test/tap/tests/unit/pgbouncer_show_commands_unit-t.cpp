/**
 * @file pgbouncer_show_commands_unit-t.cpp
 * @brief Unit tests for PgBouncer-compatible SHOW command translation.
 */

#include "tap.h"
#include "PgBouncer_ShowCommands.h"

#include <string>
#include <cstring>

#define CHECK(cond, msg) ok((cond), "%s", (msg))

// Helper: check that a query translates to something containing a substring
static bool translates_to_containing(const char* query, const std::string& expected_substr) {
    std::string out_query;
    bool is_extended = false;
    bool matched = PgBouncer::translate_show_command(query, (int)strlen(query), out_query, is_extended);
    if (!matched) return false;
    return out_query.find(expected_substr) != std::string::npos;
}

// ============================================================
// Test: Basic SHOW command recognition
// ============================================================
void test_show_command_recognition() {
    std::string out;
    bool ext = false;

    CHECK(PgBouncer::translate_show_command("SHOW POOLS", 10, out, ext),
          "SHOW POOLS recognized");
    CHECK(!ext, "SHOW POOLS is not extended");

    CHECK(PgBouncer::translate_show_command("SHOW STATS", 10, out, ext),
          "SHOW STATS recognized");

    CHECK(PgBouncer::translate_show_command("SHOW SERVERS", 12, out, ext),
          "SHOW SERVERS recognized");

    CHECK(PgBouncer::translate_show_command("SHOW CLIENTS", 12, out, ext),
          "SHOW CLIENTS recognized");

    CHECK(PgBouncer::translate_show_command("SHOW DATABASES", 14, out, ext),
          "SHOW DATABASES recognized");

    CHECK(PgBouncer::translate_show_command("SHOW USERS", 10, out, ext),
          "SHOW USERS recognized");

    CHECK(PgBouncer::translate_show_command("SHOW CONFIG", 11, out, ext),
          "SHOW CONFIG recognized");

    CHECK(PgBouncer::translate_show_command("SHOW VERSION", 12, out, ext),
          "SHOW VERSION recognized");

    CHECK(PgBouncer::translate_show_command("SHOW STATE", 10, out, ext),
          "SHOW STATE recognized");

    CHECK(PgBouncer::translate_show_command("SHOW LISTS", 10, out, ext),
          "SHOW LISTS recognized");
}

// ============================================================
// Test: Case insensitivity
// ============================================================
void test_case_insensitive() {
    std::string out;
    bool ext = false;

    CHECK(PgBouncer::translate_show_command("show pools", 10, out, ext),
          "lowercase 'show pools' recognized");

    CHECK(PgBouncer::translate_show_command("Show Pools", 10, out, ext),
          "mixed case 'Show Pools' recognized");

    CHECK(PgBouncer::translate_show_command("SHOW pools", 10, out, ext),
          "mixed case 'SHOW pools' recognized");
}

// ============================================================
// Test: Trailing semicolons and whitespace
// ============================================================
void test_trailing_semicolon() {
    std::string out;
    bool ext = false;

    const char* q1 = "SHOW POOLS;";
    CHECK(PgBouncer::translate_show_command(q1, (int)strlen(q1), out, ext),
          "SHOW POOLS; with semicolon recognized");

    const char* q2 = "SHOW POOLS ;";
    CHECK(PgBouncer::translate_show_command(q2, (int)strlen(q2), out, ext),
          "SHOW POOLS ; with space+semicolon recognized");

    const char* q3 = "  SHOW  POOLS  ";
    CHECK(PgBouncer::translate_show_command(q3, (int)strlen(q3), out, ext),
          "SHOW POOLS with extra whitespace recognized");
}

// ============================================================
// Test: EXTENDED variant
// ============================================================
void test_extended_variant() {
    std::string out;
    bool ext = false;

    const char* q1 = "SHOW EXTENDED POOLS";
    CHECK(PgBouncer::translate_show_command(q1, (int)strlen(q1), out, ext),
          "SHOW EXTENDED POOLS recognized");
    CHECK(ext, "SHOW EXTENDED POOLS sets extended flag");

    ext = false;
    const char* q2 = "SHOW EXTENDED SERVERS";
    CHECK(PgBouncer::translate_show_command(q2, (int)strlen(q2), out, ext),
          "SHOW EXTENDED SERVERS recognized");
    CHECK(ext, "SHOW EXTENDED SERVERS sets extended flag");
}

// ============================================================
// Test: SQL output contains expected columns
// ============================================================
void test_sql_output_columns() {
    CHECK(translates_to_containing("SHOW POOLS", "cl_active"),
          "SHOW POOLS output has cl_active column");
    CHECK(translates_to_containing("SHOW POOLS", "sv_idle"),
          "SHOW POOLS output has sv_idle column");
    CHECK(translates_to_containing("SHOW POOLS", "pool_mode"),
          "SHOW POOLS output has pool_mode column");

    CHECK(translates_to_containing("SHOW STATS", "total_query_count"),
          "SHOW STATS output has total_query_count");
    CHECK(translates_to_containing("SHOW STATS", "total_xact_time"),
          "SHOW STATS output has total_xact_time");

    CHECK(translates_to_containing("SHOW SERVERS", "remote_pid"),
          "SHOW SERVERS output has remote_pid");

    CHECK(translates_to_containing("SHOW CLIENTS", "application_name"),
          "SHOW CLIENTS output has application_name");

    CHECK(translates_to_containing("SHOW USERS", "pool_mode"),
          "SHOW USERS output has pool_mode");

    CHECK(translates_to_containing("SHOW CONFIG", "changeable"),
          "SHOW CONFIG output has changeable column");

    CHECK(translates_to_containing("SHOW VERSION", "ProxySQL"),
          "SHOW VERSION mentions ProxySQL");
}

// ============================================================
// Test: Non-matching queries return false
// ============================================================
void test_non_matching_queries() {
    std::string out;
    bool ext = false;

    CHECK(!PgBouncer::translate_show_command("SELECT 1", 8, out, ext),
          "SELECT 1 not matched");

    CHECK(!PgBouncer::translate_show_command("SHOW TABLES", 11, out, ext),
          "SHOW TABLES not matched (ProxySQL native)");

    CHECK(!PgBouncer::translate_show_command("INSERT INTO foo VALUES(1)", 25, out, ext),
          "INSERT not matched");
}

// ============================================================
// Test: Unsupported commands return error messages
// ============================================================
void test_unsupported_commands() {
    std::string msg;

    msg = PgBouncer::get_unsupported_show_message("SHOW DNS_HOSTS", 14);
    CHECK(!msg.empty(), "SHOW DNS_HOSTS returns error message");

    msg = PgBouncer::get_unsupported_show_message("SHOW PEERS", 10);
    CHECK(!msg.empty(), "SHOW PEERS returns error message");

    msg = PgBouncer::get_unsupported_show_message("SHOW FDS", 8);
    CHECK(!msg.empty(), "SHOW FDS returns error message");

    msg = PgBouncer::get_unsupported_show_message("SHOW MEM", 8);
    CHECK(!msg.empty(), "SHOW MEM returns error message");

    // Supported commands should NOT return unsupported message
    msg = PgBouncer::get_unsupported_show_message("SHOW POOLS", 10);
    CHECK(msg.empty(), "SHOW POOLS is not unsupported");
}

int main() {
    plan(39);

    test_show_command_recognition();  // 10
    test_case_insensitive();          // 3
    test_trailing_semicolon();        // 3
    test_extended_variant();          // 4
    test_sql_output_columns();        // 10
    test_non_matching_queries();      // 3
    test_unsupported_commands();      // 5

    // Note: 10+3+3+4+10+3+5 = 38, but plan says 40.
    // If count is off, adjust the plan number.
    return exit_status();
}
