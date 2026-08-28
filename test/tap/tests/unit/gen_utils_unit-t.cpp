#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "gen_utils.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>

// ============================================================
// mywildcmp() tests — SQL-style wildcard matching
// % matches any sequence, _ matches single char
// ============================================================

static void test_mywildcmp_exact_match() {
    ok(mywildcmp("hello", "hello") == true, "mywildcmp: exact match");
    ok(mywildcmp("hello", "world") == false, "mywildcmp: exact mismatch");
}

static void test_mywildcmp_percent() {
    ok(mywildcmp("%", "anything") == true, "mywildcmp: %% matches any string");
    ok(mywildcmp("%", "") == true, "mywildcmp: %% matches empty string");
    ok(mywildcmp("hel%", "hello") == true, "mywildcmp: prefix%%");
    ok(mywildcmp("%lo", "hello") == true, "mywildcmp: %%suffix");
    ok(mywildcmp("h%o", "hello") == true, "mywildcmp: h%%o matches hello");
    ok(mywildcmp("h%o", "ho") == true, "mywildcmp: h%%o matches ho (zero-length)");
    ok(mywildcmp("h%o", "hx") == false, "mywildcmp: h%%o rejects hx");
}

static void test_mywildcmp_underscore() {
    ok(mywildcmp("_", "x") == true, "mywildcmp: _ matches single char");
    ok(mywildcmp("_", "") == false, "mywildcmp: _ rejects empty");
    ok(mywildcmp("_", "ab") == false, "mywildcmp: _ rejects two chars");
    ok(mywildcmp("h_llo", "hello") == true, "mywildcmp: h_llo matches hello");
    ok(mywildcmp("h_llo", "hllo") == false, "mywildcmp: h_llo rejects hllo");
}

static void test_mywildcmp_combined() {
    ok(mywildcmp("%_", "a") == true, "mywildcmp: %%_ matches single char");
    ok(mywildcmp("%_", "") == false, "mywildcmp: %%_ rejects empty");
    ok(mywildcmp("_%", "a") == true, "mywildcmp: _%% matches single char");
    ok(mywildcmp("__%", "ab") == true, "mywildcmp: __%%  matches 2+ chars");
    ok(mywildcmp("__%", "a") == false, "mywildcmp: __%% rejects single char");
}

// ============================================================
// escape_string_single_quotes() — escape path (quotes present)
// Note: when no quotes are present, returns the SAME pointer
// ============================================================

static void test_escape_single_quotes_no_quotes() {
    char *input = strdup("hello world");
    char *result = escape_string_single_quotes(input, false);
    // When no quotes found, the function returns the original pointer
    ok(result == input, "escape_quotes: no quotes returns same pointer");
    ok(strcmp(result, "hello world") == 0, "escape_quotes: no quotes unchanged");
    free(input);
}

static void test_escape_single_quotes_with_quotes() {
    char *input = strdup("it's a test");
    char *result = escape_string_single_quotes(input, true);
    ok(strcmp(result, "it''s a test") == 0, "escape_quotes: single quote doubled");
    free(result);
}

static void test_escape_single_quotes_multiple() {
    char *input = strdup("a'b'c");
    char *result = escape_string_single_quotes(input, true);
    ok(strcmp(result, "a''b''c") == 0, "escape_quotes: multiple quotes doubled");
    free(result);
}

static void test_escape_single_quotes_only() {
    char *input = strdup("'''");
    char *result = escape_string_single_quotes(input, true);
    ok(strcmp(result, "''''''") == 0, "escape_quotes: all quotes doubled");
    free(result);
}

static void test_escape_single_quotes_no_free() {
    char *input = strdup("no'free");
    char *result = escape_string_single_quotes(input, false);
    ok(strcmp(result, "no''free") == 0, "escape_quotes: free_it=false works");
    free(input);  // caller must free since free_it=false
    free(result);
}

// ============================================================
// Proxy_file_regular() — file type checking
// ============================================================

static void test_proxy_file_regular() {
    // /etc/hosts should be a regular file on any Linux system
    ok(Proxy_file_regular("/etc/hosts") == true, "Proxy_file_regular: /etc/hosts is regular");
    ok(Proxy_file_regular("/tmp") == false, "Proxy_file_regular: /tmp is not regular (directory)");
    ok(Proxy_file_regular("/nonexistent_file_xyz") == false, "Proxy_file_regular: nonexistent returns false");
}

int main() {
    plan(28);
    test_init_minimal();

    test_mywildcmp_exact_match();           // 2
    test_mywildcmp_percent();               // 7
    test_mywildcmp_underscore();            // 5
    test_mywildcmp_combined();              // 5
    test_escape_single_quotes_no_quotes();  // 2
    test_escape_single_quotes_with_quotes();// 1
    test_escape_single_quotes_multiple();   // 1
    test_escape_single_quotes_only();       // 1
    test_escape_single_quotes_no_free();    // 1
    test_proxy_file_regular();              // 3 (note: Proxy_file_regular uses stat(), no special init needed)

    test_cleanup_minimal();
    return exit_status();
}
