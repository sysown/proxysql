#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Variables_Validator.h"

#include <cstring>
#include <cstdlib>

// Helper: validate and check transformed value
static void assert_validates(const pgsql_variable_validator& v, const char* input,
                             bool expected, const char* expected_transformed, const char* msg) {
    char* transformed = nullptr;
    bool result = v.validate(input, &v.params, nullptr, &transformed);
    ok(result == expected, "%s: validate('%s') = %s", msg, input, expected ? "true" : "false");
    if (expected && expected_transformed && transformed) {
        ok(strcmp(transformed, expected_transformed) == 0,
           "%s: transformed('%s') = '%s' (got '%s')", msg, input, expected_transformed, transformed);
    }
    if (transformed) {
        free(transformed);
    }
}

// ============================================================
// Boolean validation tests
// ============================================================

static void test_bool_true_values() {
    assert_validates(pgsql_variable_validator_bool, "1", true, "on", "bool");
    assert_validates(pgsql_variable_validator_bool, "t", true, "on", "bool");
    assert_validates(pgsql_variable_validator_bool, "true", true, "on", "bool");
    assert_validates(pgsql_variable_validator_bool, "on", true, "on", "bool");
    assert_validates(pgsql_variable_validator_bool, "yes", true, "on", "bool");
    assert_validates(pgsql_variable_validator_bool, "TRUE", true, "on", "bool");  // case insensitive
}

static void test_bool_false_values() {
    assert_validates(pgsql_variable_validator_bool, "0", true, "off", "bool");
    assert_validates(pgsql_variable_validator_bool, "f", true, "off", "bool");
    assert_validates(pgsql_variable_validator_bool, "false", true, "off", "bool");
    assert_validates(pgsql_variable_validator_bool, "off", true, "off", "bool");
    assert_validates(pgsql_variable_validator_bool, "no", true, "off", "bool");
}

static void test_bool_invalid() {
    char* transformed = nullptr;
    bool r = pgsql_variable_validator_bool.validate("maybe", &pgsql_variable_validator_bool.params, nullptr, &transformed);
    ok(r == false, "bool: 'maybe' is invalid");
    ok(transformed == nullptr, "bool: invalid value gives null transformed");
    r = pgsql_variable_validator_bool.validate("2", &pgsql_variable_validator_bool.params, nullptr, &transformed);
    ok(r == false, "bool: '2' is invalid");
}

// ============================================================
// Float validation (extra_float_digits: range -15.0 to 3.0)
// ============================================================

static void test_float_valid() {
    assert_validates(pgsql_variable_validator_extra_float_digits, "0", true, nullptr, "float");
    assert_validates(pgsql_variable_validator_extra_float_digits, "3", true, nullptr, "float");
    assert_validates(pgsql_variable_validator_extra_float_digits, "-15", true, nullptr, "float");
    assert_validates(pgsql_variable_validator_extra_float_digits, "1.5", true, nullptr, "float");
}

static void test_float_out_of_range() {
    char* transformed = nullptr;
    bool r = pgsql_variable_validator_extra_float_digits.validate("4", &pgsql_variable_validator_extra_float_digits.params, nullptr, &transformed);
    ok(r == false, "float: 4 out of range (max 3.0)");
    r = pgsql_variable_validator_extra_float_digits.validate("-16", &pgsql_variable_validator_extra_float_digits.params, nullptr, &transformed);
    ok(r == false, "float: -16 out of range (min -15.0)");
}

static void test_float_invalid() {
    char* transformed = nullptr;
    bool r = pgsql_variable_validator_extra_float_digits.validate("abc", &pgsql_variable_validator_extra_float_digits.params, nullptr, &transformed);
    ok(r == false, "float: 'abc' is not a number");
    r = pgsql_variable_validator_extra_float_digits.validate("", &pgsql_variable_validator_extra_float_digits.params, nullptr, &transformed);
    ok(r == false, "float: empty string is invalid");
}

// ============================================================
// String validation (intervalstyle, synchronous_commit, etc.)
// ============================================================

static void test_string_intervalstyle() {
    assert_validates(pgsql_variable_validator_intervalstyle, "postgres", true, "postgres", "intervalstyle");
    assert_validates(pgsql_variable_validator_intervalstyle, "iso_8601", true, "iso_8601", "intervalstyle");
    assert_validates(pgsql_variable_validator_intervalstyle, "POSTGRES", true, "postgres", "intervalstyle");  // case insensitive
}

static void test_string_intervalstyle_invalid() {
    char* transformed = nullptr;
    bool r = pgsql_variable_validator_intervalstyle.validate("invalid_style", &pgsql_variable_validator_intervalstyle.params, nullptr, &transformed);
    ok(r == false, "intervalstyle: 'invalid_style' rejected");
}

static void test_string_synchronous_commit() {
    assert_validates(pgsql_variable_validator_synchronous_commit, "on", true, "on", "sync_commit");
    assert_validates(pgsql_variable_validator_synchronous_commit, "off", true, "off", "sync_commit");
    assert_validates(pgsql_variable_validator_synchronous_commit, "local", true, "local", "sync_commit");
    assert_validates(pgsql_variable_validator_synchronous_commit, "remote_apply", true, "remote_apply", "sync_commit");
}

static void test_string_bytea_output() {
    assert_validates(pgsql_variable_validator_bytea_output, "hex", true, "hex", "bytea");
    assert_validates(pgsql_variable_validator_bytea_output, "escape", true, "escape", "bytea");
}

// ============================================================
// Memory size validation (maintenance_work_mem via v3 validator)
// Range: 1024..2147483647 kB
// ============================================================

static void test_work_mem_basic_units() {
    assert_validates(pgsql_variable_validator_maintenance_work_mem, "1024", true, nullptr, "work_mem");  // default kB
    assert_validates(pgsql_variable_validator_maintenance_work_mem, "1GB", true, nullptr, "work_mem");
    assert_validates(pgsql_variable_validator_maintenance_work_mem, "512MB", true, nullptr, "work_mem");
    assert_validates(pgsql_variable_validator_maintenance_work_mem, "1048576kB", true, nullptr, "work_mem");
}

static void test_work_mem_case_insensitive() {
    assert_validates(pgsql_variable_validator_maintenance_work_mem, "1gb", true, nullptr, "work_mem_case");
    assert_validates(pgsql_variable_validator_maintenance_work_mem, "1Gb", true, nullptr, "work_mem_case");
}

static void test_work_mem_invalid() {
    char* transformed = nullptr;
    // Zero not allowed
    bool r = pgsql_variable_validator_maintenance_work_mem.validate("0", &pgsql_variable_validator_maintenance_work_mem.params, nullptr, &transformed);
    ok(r == false, "work_mem: 0 is invalid");
    // Invalid unit
    r = pgsql_variable_validator_maintenance_work_mem.validate("100XB", &pgsql_variable_validator_maintenance_work_mem.params, nullptr, &transformed);
    ok(r == false, "work_mem: invalid unit 'XB' rejected");
    // Not a number
    r = pgsql_variable_validator_maintenance_work_mem.validate("abc", &pgsql_variable_validator_maintenance_work_mem.params, nullptr, &transformed);
    ok(r == false, "work_mem: 'abc' rejected");
}

// ============================================================
// Search path validation
// ============================================================

static void test_search_path_valid() {
    assert_validates(pgsql_variable_validator_search_path, "public", true, "public", "search_path");
    assert_validates(pgsql_variable_validator_search_path, "public,pg_catalog", true, "public,pg_catalog", "search_path");
}

static void test_search_path_quoted() {
    assert_validates(pgsql_variable_validator_search_path, "\"my schema\"", true, "\"my schema\"", "search_path");
}

static void test_search_path_invalid() {
    char* transformed = nullptr;
    // Starts with digit (not valid identifier)
    bool r = pgsql_variable_validator_search_path.validate("123bad", &pgsql_variable_validator_search_path.params, nullptr, &transformed);
    ok(r == false, "search_path: identifier starting with digit rejected");
}

// ============================================================
// Client encoding validation
// ============================================================

static void test_client_encoding_valid() {
    assert_validates(pgsql_variable_validator_client_encoding, "UTF8", true, "UTF8", "encoding");
    assert_validates(pgsql_variable_validator_client_encoding, "utf8", true, "UTF8", "encoding");  // uppercased
    assert_validates(pgsql_variable_validator_client_encoding, "LATIN1", true, "LATIN1", "encoding");
}

static void test_client_encoding_invalid() {
    char* transformed = nullptr;
    bool r = pgsql_variable_validator_client_encoding.validate("NONEXISTENT_ENCODING", &pgsql_variable_validator_client_encoding.params, nullptr, &transformed);
    ok(r == false, "encoding: nonexistent encoding rejected");
}

int main() {
    plan(75);
    test_init_minimal();

    test_bool_true_values();                // 12 (6 inputs x 2 assertions each)
    test_bool_false_values();               // 10 (5 inputs x 2 assertions each)
    test_bool_invalid();                    // 3
    test_float_valid();                     // 4 (validate only, no transform check)
    test_float_out_of_range();              // 2
    test_float_invalid();                   // 2
    test_string_intervalstyle();            // 6 (3 inputs x 2)
    test_string_intervalstyle_invalid();    // 1
    test_string_synchronous_commit();       // 8 (4 inputs x 2)
    test_string_bytea_output();             // 4 (2 inputs x 2)
    test_work_mem_basic_units();            // 4 (validate only)
    test_work_mem_case_insensitive();       // 2 (validate only)
    test_work_mem_invalid();                // 3
    test_search_path_valid();               // 4 (2 inputs x 2)
    test_search_path_quoted();              // 2
    test_search_path_invalid();             // 1
    test_client_encoding_valid();           // 6 (3 inputs x 2)
    test_client_encoding_invalid();         // 1

    // Note: assert_validates calls ok() once for validate result,
    // and once more for transform comparison when expected_transformed != nullptr.
    // Adjust plan count after first run if assertions differ.

    test_cleanup_minimal();
    return exit_status();
}
