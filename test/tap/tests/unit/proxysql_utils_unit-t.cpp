#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "proxysql_utils.h"

#include <cstring>
#include <string>
#include <vector>

using std::string;
using std::vector;

// ============================================================
// hex() / unhex() — hex encoding/decoding
// ============================================================

static void test_hex_basic() {
    string result = hex("AB");
    ok(result == "4142", "hex: 'AB' encodes to '4142'");
}

static void test_hex_empty() {
    string result = hex("");
    ok(result.empty(), "hex: empty string encodes to empty");
}

static void test_hex_binary() {
    string input("\x00\xFF", 2);
    string result = hex(input);
    ok(result == "00FF" || result == "00ff", "hex: binary 0x00FF encodes correctly");
}

static void test_unhex_basic() {
    string result = unhex("4142");
    ok(result == "AB", "unhex: '4142' decodes to 'AB'");
}

static void test_unhex_empty() {
    string result = unhex("");
    ok(result.empty(), "unhex: empty string decodes to empty");
}

static void test_hex_roundtrip() {
    string original = "Hello, World!";
    string roundtrip = unhex(hex(original));
    ok(roundtrip == original, "hex/unhex roundtrip preserves data");
}

// ============================================================
// sql_escape() — SQLite single-quote escaping
// ============================================================

static void test_sql_escape_no_quotes() {
    string result = sql_escape("hello");
    ok(result == "hello", "sql_escape: no quotes unchanged");
}

static void test_sql_escape_with_quotes() {
    string result = sql_escape("it's");
    ok(result == "it''s", "sql_escape: single quote escaped");
}

static void test_sql_escape_empty() {
    string result = sql_escape("");
    ok(result.empty(), "sql_escape: empty string unchanged");
}

// ============================================================
// split_str() — string splitting
// ============================================================

static void test_split_str_basic() {
    vector<string> parts = split_str("a,b,c", ',');
    ok(parts.size() == 3, "split_str: 'a,b,c' splits into 3 parts");
    ok(parts[0] == "a" && parts[1] == "b" && parts[2] == "c", "split_str: values correct");
}

static void test_split_str_no_delim() {
    vector<string> parts = split_str("single", ',');
    ok(parts.size() == 1, "split_str: no delimiter gives 1 part");
    ok(parts[0] == "single", "split_str: single value correct");
}

static void test_split_str_empty() {
    vector<string> parts = split_str("", ',');
    ok(parts.empty(), "split_str: empty string gives 0 parts");
}

// ============================================================
// replace_str() — string replacement
// ============================================================

static void test_replace_str_basic() {
    string result = replace_str("hello world", "world", "there");
    ok(result == "hello there", "replace_str: basic replacement works");
}

static void test_replace_str_no_match() {
    string result = replace_str("hello", "xyz", "abc");
    ok(result == "hello", "replace_str: no match returns original");
}

static void test_replace_str_multiple() {
    string result = replace_str("aXbXc", "X", "Y");
    ok(result == "aYbYc", "replace_str: replaces all occurrences");
}

// ============================================================
// generate_multi_rows_query() — INSERT VALUES builder
// ============================================================

static void test_generate_multi_rows_query() {
    string result = generate_multi_rows_query(2, 3);
    // Should produce something like "(?,?,?),(?,?,?)"
    ok(result.find("?") != string::npos, "generate_multi_rows: contains placeholders");
    // Count question marks — should be rows * params = 6
    int qmarks = 0;
    for (char c : result) if (c == '?') qmarks++;
    ok(qmarks == 6, "generate_multi_rows: 2 rows x 3 params = 6 placeholders");
}

static void test_generate_multi_rows_single() {
    string result = generate_multi_rows_query(1, 1);
    ok(result.find("?") != string::npos, "generate_multi_rows: 1x1 has placeholder");
}

// ============================================================
// get_checksum_from_hash() — hash to checksum string
// ============================================================

static void test_checksum_from_hash_zero() {
    string result = get_checksum_from_hash(0);
    ok(!result.empty(), "get_checksum_from_hash: zero hash returns non-empty");
}

static void test_checksum_from_hash_deterministic() {
    string r1 = get_checksum_from_hash(12345);
    string r2 = get_checksum_from_hash(12345);
    ok(r1 == r2, "get_checksum_from_hash: deterministic for same input");
}

static void test_checksum_from_hash_different() {
    string r1 = get_checksum_from_hash(1);
    string r2 = get_checksum_from_hash(2);
    ok(r1 != r2, "get_checksum_from_hash: different hashes give different checksums");
}

int main() {
    plan(23);
    test_init_minimal();

    test_hex_basic();                   // 1
    test_hex_empty();                   // 1
    test_hex_binary();                  // 1
    test_unhex_basic();                 // 1
    test_unhex_empty();                 // 1
    test_hex_roundtrip();               // 1
    test_sql_escape_no_quotes();        // 1
    test_sql_escape_with_quotes();      // 1
    test_sql_escape_empty();            // 1
    test_split_str_basic();             // 2
    test_split_str_no_delim();          // 2
    test_split_str_empty();             // 1
    test_replace_str_basic();           // 1
    test_replace_str_no_match();        // 1
    test_replace_str_multiple();        // 1
    test_generate_multi_rows_query();   // 2
    test_generate_multi_rows_single();  // 1
    test_checksum_from_hash_zero();     // 1
    test_checksum_from_hash_deterministic(); // 1
    test_checksum_from_hash_different();// 1

    test_cleanup_minimal();
    return exit_status();
}
