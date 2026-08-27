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


// ============================================================
// Test: SHOW EXTENDED adds ProxySQL columns for every command
//
// Regression: only POOLS and SERVERS honoured `extended`; the other eight
// generators ignored the flag, so SHOW EXTENDED <cmd> returned the plain
// PgBouncer column set.
// ============================================================
static bool extended_differs_from_plain(const char* cmd) {
    std::string plain_q, ext_q;
    bool e1 = false, e2 = false;
    std::string plain = std::string("SHOW ") + cmd;
    std::string ext = std::string("SHOW EXTENDED ") + cmd;
    if (!PgBouncer::translate_show_command(plain.c_str(), (int)plain.size(), plain_q, e1))
        return false;
    if (!PgBouncer::translate_show_command(ext.c_str(), (int)ext.size(), ext_q, e2))
        return false;
    return e2 && !e1 && ext_q != plain_q && ext_q.size() > plain_q.size();
}

void test_extended_all_commands() {
    const char* cmds[] = {"POOLS", "STATS", "SERVERS", "CLIENTS", "DATABASES",
                          "USERS", "CONFIG", "VERSION", "STATE", "LISTS"};
    for (const char* c : cmds) {
        std::string msg = std::string("SHOW EXTENDED ") + c + " adds columns";
        CHECK(extended_differs_from_plain(c), msg.c_str());
    }
}

// ============================================================
// Test: translations only reference columns that actually exist
//
// Regression: SHOW CLIENTS selected `db` (the column is `database`), and
// SHOW DATABASES / SHOW EXTENDED SERVERS selected weight, max_connections and
// max_replication_lag from stats_pgsql_connection_pool, which has none of
// them. These are string-level guards; pgbouncer_show_commands-t executes the
// same queries against a live admin interface.
// ============================================================
void test_no_phantom_columns() {
    std::string q;
    bool ext = false;

    PgBouncer::translate_show_command("SHOW CLIENTS", 12, q, ext);
    CHECK(q.find("db AS database") == std::string::npos,
          "SHOW CLIENTS does not select the nonexistent `db` column");
    CHECK(q.find("database AS database") != std::string::npos,
          "SHOW CLIENTS selects `database`");

    PgBouncer::translate_show_command("SHOW DATABASES", 14, q, ext);
    CHECK(q.find("stats_pgsql_connection_pool") == std::string::npos,
          "SHOW DATABASES no longer reads max_connections from the stats table");
    CHECK(q.find("runtime_pgsql_servers") != std::string::npos,
          "SHOW DATABASES reads runtime_pgsql_servers");

    PgBouncer::translate_show_command("SHOW EXTENDED SERVERS", 21, q, ext);
    CHECK(q.find("runtime_pgsql_servers") != std::string::npos,
          "SHOW EXTENDED SERVERS joins runtime_pgsql_servers for weight/max_connections");
    CHECK(q.find("s.weight") != std::string::npos,
          "SHOW EXTENDED SERVERS takes weight from the servers table");
}

// ============================================================
// Test: trailing tokens are not a PgBouncer command
//
// "SHOW POOLS foo" used to translate as "SHOW POOLS", swallowing a query the
// admin interface should have handled (or rejected) itself.
// ============================================================
void test_trailing_tokens_rejected() {
    std::string q;
    bool ext = false;

    CHECK(!PgBouncer::translate_show_command("SHOW POOLS foo", 14, q, ext),
          "SHOW POOLS foo is not translated");
    CHECK(!PgBouncer::translate_show_command("SHOW EXTENDED SERVERS bar", 25, q, ext),
          "SHOW EXTENDED SERVERS bar is not translated");
    CHECK(PgBouncer::translate_show_command("SHOW POOLS", 10, q, ext),
          "SHOW POOLS alone still translates");
}

int main() {
    plan(58);

    test_show_command_recognition();
    test_case_insensitive();
    test_trailing_semicolon();
    test_extended_variant();
    test_sql_output_columns();
    test_non_matching_queries();
    test_unsupported_commands();
    test_extended_all_commands();
    test_no_phantom_columns();
    test_trailing_tokens_rejected();

    return exit_status();
}
