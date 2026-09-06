/**
 * @file pgsql-options_startup_params-t.cpp
 * @brief Comprehensive test for startup parameter handling in options
 *
 * Tests:
 * - All ProxySQL tracked variables with spaces (success/failure)
 * - Untracked parameters
 * - Edge cases (escaped spaces, multiple spaces, trailing spaces)
 * - Strict verification of error handling
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <vector>
#include <utility>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

struct TestCase {
    std::string name;
    std::string options;
    bool should_succeed;        // true = expect connection success
    std::string expected_error; // substring expected in error message (if should_fail)
    std::string description;
};

// Helper to create connection
PGConnPtr createConnection(const std::string& options, std::string& error_msg) {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port;
    ss << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password;
    ss << " sslmode=disable";
    if (!options.empty()) {
        ss << " options='" << options << "'";
    }

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        error_msg = PQerrorMessage(conn);
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    error_msg.clear();
    return PGConnPtr(conn, &PQfinish);
}

// Helper to get variable value
std::string getVar(PGconn* conn, const char* name) {
    PGresult* res = PQexec(conn, (std::string("SHOW ") + name).c_str());
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return "";
    }
    char* val = PQgetvalue(res, 0, 0);
    std::string result = val ? val : "";
    PQclear(res);
    return result;
}

int main(int argc, char** argv) {
    if (cl.getEnv()) return exit_status();

    // Build comprehensive test cases
    std::vector<TestCase> tests;

    // 0. client_encoding (has alias "names")
    tests.push_back({"client_encoding",
        "-c client_encoding=LATIN1",
        true, "", "client_encoding"});
    tests.push_back({"names_alias",
        "-c names=UTF8",
        true, "", "names alias for client_encoding"});

    // 1. DateStyle with escaped space
    // For escaped space: C++ "\\\\" becomes actual "\\" which libpq sees as "\ " (escaped space)
    tests.push_back({"datestyle_escaped",
        "-c DateStyle=SQL,\\\\ DMY",
        true, "", "DateStyle with escaped space"});
    tests.push_back({"datestyle_postgres",
        "-c DateStyle=Postgres,\\\\ DMY",
        true, "", "DateStyle Postgres format"});
    tests.push_back({"datestyle_iso_mdy",
        "-c DateStyle=ISO,\\\\ MDY",
        true, "", "DateStyle ISO MDY"});

    // 2. IntervalStyle
    tests.push_back({"intervalstyle_iso8601",
        "-c IntervalStyle=iso_8601",
        true, "", "IntervalStyle iso_8601"});
    tests.push_back({"intervalstyle_postgres",
        "-c IntervalStyle=postgres",
        true, "", "IntervalStyle postgres"});

    // 3. standard_conforming_strings
    tests.push_back({"standard_conforming_strings_off",
        "-c standard_conforming_strings=off",
        true, "", "standard_conforming_strings=off"});
    tests.push_back({"standard_conforming_strings_on",
        "-c standard_conforming_strings=on",
        true, "", "standard_conforming_strings=on"});

    // 4. TimeZone (has alias "TIME ZONE")
    tests.push_back({"timezone_pst",
        "-c TimeZone=PST8PDT",
        true, "", "TimeZone PST8PDT"});
    tests.push_back({"timezone_est",
        "-c TimeZone=EST5EDT",
        true, "", "TimeZone EST5EDT"});
    tests.push_back({"timezone_utc",
        "-c TimeZone=UTC",
        true, "", "TimeZone UTC"});
    tests.push_back({"time_zone_alias",
        "-c TimeZone=GMT",
        true, "", "TimeZone alias"});

    // Non-critical params (PGSQL_NAME_LAST_LOW_WM+1 to PGSQL_NAME_LAST_HIGH_WM-1)

    // 6. allow_in_place_tablespaces
    tests.push_back({"allow_in_place_tablespaces",
        "-c allow_in_place_tablespaces=on",
        true, "", "allow_in_place_tablespaces"});

    // 7. bytea_output
    tests.push_back({"bytea_output_escape",
        "-c bytea_output=escape",
        true, "", "bytea_output=escape"});
    tests.push_back({"bytea_output_hex",
        "-c bytea_output=hex",
        true, "", "bytea_output=hex"});

    // 8. client_min_messages
    tests.push_back({"client_min_messages",
        "-c client_min_messages=warning",
        true, "", "client_min_messages"});

    // 9-15. enable_* parameters
    tests.push_back({"enable_bitmapscan",
        "-c enable_bitmapscan=off",
        true, "", "enable_bitmapscan"});
    tests.push_back({"enable_hashjoin",
        "-c enable_hashjoin=off",
        true, "", "enable_hashjoin"});
    tests.push_back({"enable_indexscan",
        "-c enable_indexscan=off",
        true, "", "enable_indexscan"});
    tests.push_back({"enable_nestloop",
        "-c enable_nestloop=off",
        true, "", "enable_nestloop"});
    tests.push_back({"enable_seqscan",
        "-c enable_seqscan=off",
        true, "", "enable_seqscan"});
    tests.push_back({"enable_sort",
        "-c enable_sort=off",
        true, "", "enable_sort"});

    // 16. escape_string_warning
    tests.push_back({"escape_string_warning",
        "-c escape_string_warning=off",
        true, "", "escape_string_warning"});

    // 17. extra_float_digits
    tests.push_back({"extra_float_digits_2",
        "-c extra_float_digits=2",
        true, "", "extra_float_digits"});

    // 18. maintenance_work_mem (with space in value, must escape)
    tests.push_back({"maintenance_work_mem",
        "-c maintenance_work_mem=64MB",
        true, "", "maintenance_work_mem"});

    // 19. search_path (has NO_STRIP_VALUE flag, handles commas specially)
    tests.push_back({"searchpath_simple",
        "-c search_path=public",
        true, "", "search_path simple"});
    tests.push_back({"searchpath_escaped_space",
        "-c search_path=public,\\\\ private",
        true, "", "search_path with escaped space"});
    tests.push_back({"searchpath_quoted",
        "-c search_path=\"\\$user\",public",
        true, "", "search_path with quoted user"});

    // 20. synchronous_commit
    tests.push_back({"synchronous_commit",
        "-c synchronous_commit=off",
        true, "", "synchronous_commit"});

    // Multiple parameters with proper escaping
    tests.push_back({"multiple_critical",
        "-c DateStyle=SQL,\\\\ DMY -c TimeZone=PST8PDT -c client_encoding=UTF8",
        true, "", "Multiple critical params with escaped space"});
    tests.push_back({"multiple_all",
        "-c DateStyle=ISO,\\\\ MDY -c TimeZone=UTC -c client_encoding=UTF8 -c enable_seqscan=off -c bytea_output=escape",
        true, "", "Multiple params: critical + non-critical"});

    // ============================================================
    // FAILURE CASES: Unescaped spaces (should fail)
    // ============================================================

    // DateStyle with unescaped space (the main bug case)
    tests.push_back({"datestyle_unescaped",
        "-c DateStyle=SQL, DMY",
        false, "unescaped space", "DateStyle with unescaped space (should fail)"});

    // TimeZone with unescaped space
    tests.push_back({"timezone_unescaped",
        "-c TimeZone=New York",
        false, "unescaped space", "TimeZone with unescaped space"});

    // search_path with unescaped space
    tests.push_back({"searchpath_unescaped",
        "-c search_path=public, private",
        false, "unescaped space", "search_path with unescaped space"});

    // maintenance_work_mem with unescaped space
    tests.push_back({"maintenance_work_mem_unescaped",
        "-c maintenance_work_mem=128 MB",
        false, "unescaped space", "maintenance_work_mem with unescaped space"});

    // Trailing space after value
    tests.push_back({"trailing_space",
        "-c DateStyle=ISO, MDY ",
        false, "unescaped space", "Trailing space after value"});

    // Multiple spaces between options (one unescaped in value)
    tests.push_back({"multi_space_fail",
        "-c DateStyle=Postgres, DMY  -c TimeZone=PST",
        false, "unescaped space", "Multiple spaces with unescaped space in first value"});

    // bytea_output with unescaped space
    tests.push_back({"bytea_unescaped",
        "-c bytea_output=escape mode",
        false, "unescaped space", "bytea_output with unescaped space"});

    // client_min_messages with unescaped space
    tests.push_back({"client_min_messages_unescaped",
        "-c client_min_messages=log debug",
        false, "unescaped space", "client_min_messages with unescaped space"});

    // ============================================================
    // UNTRACKED PARAMETERS: Should work but lock hostgroup
    // ============================================================

    // Valid untracked parameter
    tests.push_back({"untracked_valid",
        "-c geqo=off",
        true, "", "Untracked parameter (geqo)"});
    tests.push_back({"untracked_join_collapse_limit",
        "-c join_collapse_limit=8",
        true, "", "Untracked parameter (join_collapse_limit)"});

    // ============================================================
    // EDGE CASES: Various escape scenarios
    // ============================================================

    // Multiple spaces needing escape
    tests.push_back({"multi_space_escape",
        "-c search_path=a,\\\\ b,\\\\ c",
        true, "", "Multiple escaped spaces"});

    // Space at start of value (escaped)
    tests.push_back({"space_at_start",
        "-c search_path=\\\\ public",
        true, "", "Escaped space at start of value"});

    // ============================================================
    // SPECIAL CASES: Empty and malformed
    // ============================================================

    // Empty options
    tests.push_back({"empty_options",
        "",
        true, "", "Empty options (no options)"});

    // Just spaces in options
    tests.push_back({"only_spaces",
        "   ",
        true, "", "Options with only spaces"});

    // No equals sign (malformed - should FAIL now)
    tests.push_back({"no_equals",
        "-c DateStyle",
        false, "missing '='", "Malformed option without ="});

    // Empty value after equals (valid - empty value)
    tests.push_back({"empty_value",
        "-c DateStyle=",
        true, "", "Empty value after equals"});

    // ============================================================
    // MALFORMED OPTIONS: Should be REJECTED (not skipped)
    // ============================================================

    // Token doesn't start with -c or --
    tests.push_back({"malformed_no_prefix",
        "foo=value",
        false, "token must start with", "Malformed: no -c or -- prefix"});

    // Space between key and =
    tests.push_back({"malformed_space_before_equals",
        "-c DateStyle =value",
        false, "missing '='", "Malformed: space before ="});

    // Empty key
    tests.push_back({"malformed_empty_key",
        "-c =value",
        false, "empty key", "Malformed: empty key before ="});

    // Multiple tokens without proper -c
    tests.push_back({"malformed_multiple_tokens",
        "-c foo -c bar=value",
        false, "missing '='", "Malformed: space in key"});

    // ============================================================
    // PROXY VALIDATION: Verify values are actually applied
    // ============================================================

    // Verify DateStyle is actually set
    // This will be verified separately after connection

    const int num_tests = tests.size() + 6; // +4 verification tests, +2 conninfo-quoting tests
    plan(num_tests);

    int pass_count = 0;
    int fail_count = 0;

    // Run all test cases
    for (const auto& tc : tests) {
        diag("\n=== Test: %s ===", tc.name.c_str());
        diag("Options: '%s'", tc.options.c_str());
        diag("Description: %s", tc.description.c_str());

        std::string error_msg;
        PGConnPtr conn = createConnection(tc.options, error_msg);
        bool connected = (conn != nullptr);

        bool test_passed;
        if (tc.should_succeed) {
            test_passed = connected;
            if (!test_passed) {
                diag("FAILED: Expected success but got error: %s", error_msg.c_str());
            }
        } else {
            test_passed = !connected;
            if (!test_passed) {
                diag("FAILED: Expected failure but connection succeeded");
            } else if (!tc.expected_error.empty()) {
                // Verify error message contains expected text
                if (error_msg.find(tc.expected_error) == std::string::npos) {
                    diag("WARNING: Error message doesn't contain '%s'", tc.expected_error.c_str());
                    diag("Actual error: %s", error_msg.c_str());
                }
            }
        }

        ok(test_passed, "%s", tc.description.c_str());

        if (test_passed) pass_count++;
        else fail_count++;
    }

    // Additional verification: Check that values are actually applied
    diag("\n=== Verification: Check values are actually applied ===");

    // Test 1: Verify escaped DateStyle is applied correctly
    {
        diag("\n--- Verifying DateStyle with escaped space is correct ---");
        std::string error;
        PGConnPtr conn = createConnection("-c DateStyle=SQL,\\\\ DMY", error);
        if (conn) {
            std::string val = getVar(conn.get(), "DateStyle");
            bool correct = (val.find("SQL") != std::string::npos && val.find("DMY") != std::string::npos);
            diag("Expected: SQL, DMY");
            diag("Got: %s", val.c_str());
            ok(correct, "DateStyle escaped space: value correctly applied");
        } else {
            diag("Connection failed: %s", error.c_str());
            ok(false, "DateStyle escaped space: value correctly applied");
        }
    }

    // Test 2: Verify partial value auto-completion works
    {
        diag("\n--- Verifying partial DateStyle (no escape needed) ---");
        std::string error;
        PGConnPtr conn = createConnection("-c DateStyle=MDY", error);
        if (conn) {
            std::string val = getVar(conn.get(), "DateStyle");
            // Should be completed to "ISO, MDY" (format from default, order from param)
            bool has_order = (val.find("MDY") != std::string::npos);
            diag("Got: %s (should contain MDY)", val.c_str());
            ok(has_order, "DateStyle partial value auto-completed");
        } else {
            diag("Connection failed: %s", error.c_str());
            ok(false, "DateStyle partial value auto-completed");
        }
    }

    // Test 3: Verify RESET reverts to startup value
    {
        diag("\n--- Verifying RESET reverts to startup value ---");
        std::string error;
        PGConnPtr conn = createConnection("-c DateStyle=SQL,\\\\ DMY", error);
        if (conn) {
            std::string startup_val = getVar(conn.get(), "DateStyle");
            diag("Startup value: %s", startup_val.c_str());

            // SET to different value
            PGresult* set_res = PQexec(conn.get(), "SET DateStyle = 'Postgres, MDY'");
            const bool set_ok = set_res && PQresultStatus(set_res) == PGRES_COMMAND_OK;
            if (!set_ok) {
                diag("SET failed: %s", set_res ? PQresultErrorMessage(set_res) : "null result");
            }
            PQclear(set_res);
            std::string set_val = getVar(conn.get(), "DateStyle");
            diag("After SET: %s", set_val.c_str());

            // Verify SET actually changed the value
            const bool set_changed = (set_val != startup_val);
            if (!set_changed) {
                diag("SET did not change value: startup='%s', after SET='%s'", startup_val.c_str(), set_val.c_str());
            }

            // RESET
            PGresult* reset_res = PQexec(conn.get(), "RESET DateStyle");
            const bool reset_ok = reset_res && PQresultStatus(reset_res) == PGRES_COMMAND_OK;
            if (!reset_ok) {
                diag("RESET failed: %s", reset_res ? PQresultErrorMessage(reset_res) : "null result");
            }
            PQclear(reset_res);
            std::string reset_val = getVar(conn.get(), "DateStyle");
            diag("After RESET: %s", reset_val.c_str());

            // Verify all conditions: SET worked, RESET worked, and value reverted
            bool reverted = set_ok && set_changed && reset_ok && (reset_val == startup_val);
            ok(reverted, "RESET reverts to startup value");
        } else {
            diag("Connection failed: %s", error.c_str());
            ok(false, "RESET reverts to startup value");
        }
    }

    // Test 4: Verify search_path with escaped space
    {
        diag("\n--- Verifying search_path with escaped space ---");
        std::string error;
        PGConnPtr conn = createConnection("-c search_path=public,\\\\ private", error);
        if (conn) {
            std::string val = getVar(conn.get(), "search_path");
            // search_path should contain both schemas
            bool has_public = (val.find("public") != std::string::npos);
            bool has_private = (val.find("private") != std::string::npos);
            diag("Expected: public, private");
            diag("Got: %s", val.c_str());
            ok(has_public && has_private, "search_path with escaped space applied");
        } else {
            diag("Connection failed: %s", error.c_str());
            ok(false, "search_path with escaped space applied");
        }
    }

    // Test 5: an option VALUE containing an apostrophe must survive to the backend.
    //
    // ProxySQL forwards client options by embedding them in a libpq conninfo as
    // options='<value>' (PgSQL_Connection.cpp). Values are escaped for the PostgreSQL
    // startup wire format (backslash before space/backslash) but NOT for the conninfo
    // quoting layer, so an apostrophe closes the quoted value early and everything after
    // it is parsed by libpq as further conninfo KEYWORDS. Round-tripping the literal is
    // the proof that the value stayed inside the options string.
    //
    // Escaping note: this test's own conninfo is also options='...', so the apostrophe is
    // written \' here; libpq strips that backslash and ProxySQL receives a bare "a'b".
    {
        diag("\n--- Verifying an apostrophe in an option value round-trips ---");
        std::string error;
        PGConnPtr conn = createConnection("-c myapp.tag=a\\'b", error);
        if (conn) {
            std::string val = getVar(conn.get(), "myapp.tag");
            diag("Expected: a'b");
            diag("Got: %s", val.c_str());
            ok(val == "a'b", "apostrophe in an option value reaches the backend intact");
        } else {
            diag("Connection failed: %s", error.c_str());
            ok(false, "apostrophe in an option value reaches the backend intact (connect failed)");
        }
    }

    // Test 6 (SECURITY): an apostrophe followed by what looks like a conninfo keyword must
    // NOT be interpreted as one. If the quoting is correct the whole thing arrives at the
    // backend as one literal GUC value; if it breaks out, libpq would parse host='127.0.0.99'
    // and the backend connection would go somewhere else (or fail outright).
    // The embedded space is wire-escaped (\\ ) so PostgreSQL's options parser keeps it as a
    // single token.
    {
        diag("\n--- Verifying no conninfo keyword injection via an option value ---");
        std::string error;
        PGConnPtr conn = createConnection("-c myapp.tag=x\\'\\\\ host=\\'127.0.0.99", error);
        if (conn) {
            std::string val = getVar(conn.get(), "myapp.tag");
            diag("Expected: x' host='127.0.0.99");
            diag("Got: %s", val.c_str());
            ok(val == "x' host='127.0.0.99",
               "quote+keyword in an option value stays a literal (no conninfo injection)");
        } else {
            diag("Connection failed: %s", error.c_str());
            ok(false, "quote+keyword in an option value stays a literal (connect failed)");
        }
    }

    // Summary
    diag("\n=== SUMMARY ===");
    diag("Passed: %d, Failed: %d", pass_count, fail_count);

    return exit_status();
}
