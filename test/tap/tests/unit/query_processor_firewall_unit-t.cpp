/**
 * @file query_processor_firewall_unit-t.cpp
 * @brief Unit tests for Query_Processor firewall whitelist functions.
 *
 * Tests the firewall whitelist subsystem in isolation:
 *   - load_firewall_users() + find_firewall_whitelist_user()
 *   - load_firewall_rules() + find_firewall_whitelist_rule()
 *   - load_firewall_sqli_fingerprints() + whitelisted_sqli_fingerprint()
 *   - load_firewall() high-level loader
 *   - Memory accounting helpers
 *
 * Uses manually constructed SQLite3_result objects to populate the
 * internal firewall data structures, then verifies lookups.
 *
 * @see Phase 2.4 of the Unit Testing Framework (GitHub issue #5476)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"

#include <cstring>
#include <cstdlib>

// Extern declarations for Glo* pointers (defined in test_globals.cpp)
extern MySQL_Query_Processor *GloMyQPro;
extern PgSQL_Query_Processor *GloPgQPro;

// ============================================================================
// Helpers — build SQLite3_result objects that mimic admin table rows
// ============================================================================

/**
 * @brief Build a SQLite3_result for firewall_whitelist_users.
 *
 * Each row has 4 columns: active, username, client_address, mode.
 * Caller owns the returned pointer.
 */
static SQLite3_result *make_users_result(
	std::vector<std::tuple<const char*, const char*, const char*, const char*>> rows)
{
	SQLite3_result *res = new SQLite3_result(4);
	res->add_column_definition(SQLITE_TEXT, "active");
	res->add_column_definition(SQLITE_TEXT, "username");
	res->add_column_definition(SQLITE_TEXT, "client_address");
	res->add_column_definition(SQLITE_TEXT, "mode");
	for (auto &[active, user, client, mode] : rows) {
		const char *fields[] = { active, user, client, mode };
		res->add_row(fields);
	}
	return res;
}

/**
 * @brief Build a SQLite3_result for firewall_whitelist_rules.
 *
 * Each row has 6 columns: active, username, client_address, schemaname, flagIN, digest.
 */
static SQLite3_result *make_rules_result(
	std::vector<std::tuple<const char*, const char*, const char*, const char*, const char*, const char*>> rows)
{
	SQLite3_result *res = new SQLite3_result(6);
	res->add_column_definition(SQLITE_TEXT, "active");
	res->add_column_definition(SQLITE_TEXT, "username");
	res->add_column_definition(SQLITE_TEXT, "client_address");
	res->add_column_definition(SQLITE_TEXT, "schemaname");
	res->add_column_definition(SQLITE_TEXT, "flagIN");
	res->add_column_definition(SQLITE_TEXT, "digest");
	for (auto &[active, user, client, schema, flag, digest] : rows) {
		const char *fields[] = { active, user, client, schema, flag, digest };
		res->add_row(fields);
	}
	return res;
}

/**
 * @brief Build a SQLite3_result for firewall_whitelist_sqli_fingerprints.
 *
 * Each row has 2 columns: active, fingerprint.
 */
static SQLite3_result *make_sqli_result(
	std::vector<std::pair<const char*, const char*>> rows)
{
	SQLite3_result *res = new SQLite3_result(2);
	res->add_column_definition(SQLITE_TEXT, "active");
	res->add_column_definition(SQLITE_TEXT, "fingerprint");
	for (auto &[active, fp] : rows) {
		const char *fields[] = { active, fp };
		res->add_row(fields);
	}
	return res;
}

// ============================================================================
// 1. load_firewall_users + find_firewall_whitelist_user
// ============================================================================

/**
 * @brief Test loading users and looking them up by username+client.
 */
static void test_firewall_users_basic() {
	// Load users via load_firewall() which calls load_firewall_users internally.
	// We need three SQLite3_result* (users, rules, sqli) — rules and sqli can be empty.
	SQLite3_result *users = make_users_result({
		{"1", "admin",    "10.0.0.1", "PROTECTING"},
		{"1", "readonly", "10.0.0.2", "DETECTING"},
		{"1", "appuser",  "",         "OFF"},
	});
	SQLite3_result *rules = make_rules_result({});
	SQLite3_result *sqli  = make_sqli_result({});

	GloMyQPro->load_firewall(users, rules, sqli);

	// find_firewall_whitelist_user returns WUS_PROTECTING / WUS_DETECTING / WUS_OFF / WUS_NOT_FOUND
	// Note: find_firewall_whitelist_user is called under the mutex in production,
	// but it only reads internal maps. We call it directly here since we are
	// single-threaded and load_firewall already populated the maps.

	int status;

	status = GloMyQPro->find_firewall_whitelist_user((char*)"admin", (char*)"10.0.0.1");
	ok(status == WUS_PROTECTING,
		"Firewall users: admin@10.0.0.1 is PROTECTING (got %d)", status);

	status = GloMyQPro->find_firewall_whitelist_user((char*)"readonly", (char*)"10.0.0.2");
	ok(status == WUS_DETECTING,
		"Firewall users: readonly@10.0.0.2 is DETECTING (got %d)", status);

	status = GloMyQPro->find_firewall_whitelist_user((char*)"appuser", (char*)"");
	ok(status == WUS_OFF,
		"Firewall users: appuser@'' is OFF (got %d)", status);

	// Unknown user should return WUS_NOT_FOUND
	status = GloMyQPro->find_firewall_whitelist_user((char*)"unknown", (char*)"1.2.3.4");
	ok(status == WUS_NOT_FOUND,
		"Firewall users: unknown user returns WUS_NOT_FOUND (got %d)", status);

	// Known user but wrong client address
	status = GloMyQPro->find_firewall_whitelist_user((char*)"admin", (char*)"10.0.0.99");
	ok(status == WUS_NOT_FOUND,
		"Firewall users: admin@wrong_ip returns WUS_NOT_FOUND (got %d)", status);
}

/**
 * @brief Test that inactive users (active=0) are skipped during load.
 */
static void test_firewall_users_inactive() {
	SQLite3_result *users = make_users_result({
		{"0", "inactive_user", "10.0.0.5", "PROTECTING"},
		{"1", "active_user",   "10.0.0.6", "DETECTING"},
	});
	SQLite3_result *rules = make_rules_result({});
	SQLite3_result *sqli  = make_sqli_result({});

	GloMyQPro->load_firewall(users, rules, sqli);

	int status;

	status = GloMyQPro->find_firewall_whitelist_user((char*)"inactive_user", (char*)"10.0.0.5");
	ok(status == WUS_NOT_FOUND,
		"Firewall users: inactive user (active=0) not loaded (got %d)", status);

	status = GloMyQPro->find_firewall_whitelist_user((char*)"active_user", (char*)"10.0.0.6");
	ok(status == WUS_DETECTING,
		"Firewall users: active user (active=1) loaded correctly (got %d)", status);
}

/**
 * @brief Test that reloading users replaces old entries.
 */
static void test_firewall_users_reload() {
	// First load
	SQLite3_result *users1 = make_users_result({
		{"1", "testuser", "1.1.1.1", "PROTECTING"},
	});
	SQLite3_result *rules1 = make_rules_result({});
	SQLite3_result *sqli1  = make_sqli_result({});
	GloMyQPro->load_firewall(users1, rules1, sqli1);

	int status = GloMyQPro->find_firewall_whitelist_user((char*)"testuser", (char*)"1.1.1.1");
	ok(status == WUS_PROTECTING,
		"Firewall users reload: first load has testuser PROTECTING (got %d)", status);

	// Second load — different mode
	SQLite3_result *users2 = make_users_result({
		{"1", "testuser", "1.1.1.1", "DETECTING"},
	});
	SQLite3_result *rules2 = make_rules_result({});
	SQLite3_result *sqli2  = make_sqli_result({});
	GloMyQPro->load_firewall(users2, rules2, sqli2);

	status = GloMyQPro->find_firewall_whitelist_user((char*)"testuser", (char*)"1.1.1.1");
	ok(status == WUS_DETECTING,
		"Firewall users reload: second load updated to DETECTING (got %d)", status);
}

/**
 * @brief Test that entries removed from the result set are cleaned up.
 */
static void test_firewall_users_removal() {
	// First load with two users
	SQLite3_result *users1 = make_users_result({
		{"1", "user_a", "1.1.1.1", "PROTECTING"},
		{"1", "user_b", "2.2.2.2", "DETECTING"},
	});
	SQLite3_result *rules1 = make_rules_result({});
	SQLite3_result *sqli1  = make_sqli_result({});
	GloMyQPro->load_firewall(users1, rules1, sqli1);

	// Second load — only user_a
	SQLite3_result *users2 = make_users_result({
		{"1", "user_a", "1.1.1.1", "PROTECTING"},
	});
	SQLite3_result *rules2 = make_rules_result({});
	SQLite3_result *sqli2  = make_sqli_result({});
	GloMyQPro->load_firewall(users2, rules2, sqli2);

	int status;
	status = GloMyQPro->find_firewall_whitelist_user((char*)"user_a", (char*)"1.1.1.1");
	ok(status == WUS_PROTECTING,
		"Firewall users removal: user_a still present (got %d)", status);

	status = GloMyQPro->find_firewall_whitelist_user((char*)"user_b", (char*)"2.2.2.2");
	ok(status == WUS_NOT_FOUND,
		"Firewall users removal: user_b removed after reload (got %d)", status);
}

// ============================================================================
// 2. load_firewall_rules + find_firewall_whitelist_rule
// ============================================================================

/**
 * @brief Test loading rules and looking them up.
 */
static void test_firewall_rules_basic() {
	// The digest in the result is a hex string (strtoull with base 0).
	// We use "0x1234" which is 4660 decimal.
	SQLite3_result *users = make_users_result({
		{"1", "admin", "10.0.0.1", "PROTECTING"},
	});
	SQLite3_result *rules = make_rules_result({
		{"1", "admin", "10.0.0.1", "mydb", "0", "0x1234"},
		{"1", "admin", "10.0.0.1", "mydb", "0", "0xABCD"},
	});
	SQLite3_result *sqli = make_sqli_result({});

	GloMyQPro->load_firewall(users, rules, sqli);

	bool found;

	// Existing digest 0x1234 = 4660
	found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"admin", (char*)"10.0.0.1", (char*)"mydb", 0, 0x1234);
	ok(found == true,
		"Firewall rules: digest 0x1234 found for admin@10.0.0.1/mydb/flag0");

	// Existing digest 0xABCD = 43981
	found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"admin", (char*)"10.0.0.1", (char*)"mydb", 0, 0xABCD);
	ok(found == true,
		"Firewall rules: digest 0xABCD found for admin@10.0.0.1/mydb/flag0");

	// Non-existing digest
	found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"admin", (char*)"10.0.0.1", (char*)"mydb", 0, 0x9999);
	ok(found == false,
		"Firewall rules: unknown digest returns false");

	// Wrong username
	found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"nobody", (char*)"10.0.0.1", (char*)"mydb", 0, 0x1234);
	ok(found == false,
		"Firewall rules: wrong username returns false");

	// Wrong schema
	found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"admin", (char*)"10.0.0.1", (char*)"otherdb", 0, 0x1234);
	ok(found == false,
		"Firewall rules: wrong schema returns false");

	// Wrong flagIN
	found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"admin", (char*)"10.0.0.1", (char*)"mydb", 1, 0x1234);
	ok(found == false,
		"Firewall rules: wrong flagIN returns false");

	// Wrong client_address
	found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"admin", (char*)"10.0.0.99", (char*)"mydb", 0, 0x1234);
	ok(found == false,
		"Firewall rules: wrong client_address returns false");
}

/**
 * @brief Test that inactive rules (active=0) are skipped.
 */
static void test_firewall_rules_inactive() {
	SQLite3_result *users = make_users_result({
		{"1", "admin", "10.0.0.1", "PROTECTING"},
	});
	SQLite3_result *rules = make_rules_result({
		{"0", "admin", "10.0.0.1", "mydb", "0", "0x1111"},  // inactive
		{"1", "admin", "10.0.0.1", "mydb", "0", "0x2222"},  // active
	});
	SQLite3_result *sqli = make_sqli_result({});

	GloMyQPro->load_firewall(users, rules, sqli);

	bool found;

	found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"admin", (char*)"10.0.0.1", (char*)"mydb", 0, 0x1111);
	ok(found == false,
		"Firewall rules: inactive rule digest not loaded");

	found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"admin", (char*)"10.0.0.1", (char*)"mydb", 0, 0x2222);
	ok(found == true,
		"Firewall rules: active rule digest loaded");
}

/**
 * @brief Test empty rules result clears the rules map.
 */
static void test_firewall_rules_empty_clears() {
	// First, load some rules
	SQLite3_result *users1 = make_users_result({
		{"1", "admin", "10.0.0.1", "PROTECTING"},
	});
	SQLite3_result *rules1 = make_rules_result({
		{"1", "admin", "10.0.0.1", "mydb", "0", "0x5555"},
	});
	SQLite3_result *sqli1 = make_sqli_result({});
	GloMyQPro->load_firewall(users1, rules1, sqli1);

	bool found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"admin", (char*)"10.0.0.1", (char*)"mydb", 0, 0x5555);
	ok(found == true,
		"Firewall rules empty: rule exists before clearing");

	// Now load empty rules
	SQLite3_result *users2 = make_users_result({
		{"1", "admin", "10.0.0.1", "PROTECTING"},
	});
	SQLite3_result *rules2 = make_rules_result({});
	SQLite3_result *sqli2 = make_sqli_result({});
	GloMyQPro->load_firewall(users2, rules2, sqli2);

	found = GloMyQPro->find_firewall_whitelist_rule(
		(char*)"admin", (char*)"10.0.0.1", (char*)"mydb", 0, 0x5555);
	ok(found == false,
		"Firewall rules empty: rule cleared after empty reload");
}

// ============================================================================
// 3. load_firewall_sqli_fingerprints + whitelisted_sqli_fingerprint
// ============================================================================

/**
 * @brief Test loading sqli fingerprints and checking them.
 */
static void test_firewall_sqli_basic() {
	SQLite3_result *users = make_users_result({});
	SQLite3_result *rules = make_rules_result({});
	SQLite3_result *sqli  = make_sqli_result({
		{"1", "s&1"},
		{"1", "1UE"},
		{"0", "disabled_fp"},  // inactive
	});

	GloMyQPro->load_firewall(users, rules, sqli);

	bool found;

	found = GloMyQPro->whitelisted_sqli_fingerprint((char*)"s&1");
	ok(found == true,
		"Firewall sqli: 's&1' fingerprint found");

	found = GloMyQPro->whitelisted_sqli_fingerprint((char*)"1UE");
	ok(found == true,
		"Firewall sqli: '1UE' fingerprint found");

	found = GloMyQPro->whitelisted_sqli_fingerprint((char*)"disabled_fp");
	ok(found == false,
		"Firewall sqli: inactive fingerprint not loaded");

	found = GloMyQPro->whitelisted_sqli_fingerprint((char*)"unknown_fp");
	ok(found == false,
		"Firewall sqli: unknown fingerprint returns false");
}

/**
 * @brief Test that reloading sqli fingerprints replaces old ones.
 */
static void test_firewall_sqli_reload() {
	// First load
	SQLite3_result *users1 = make_users_result({});
	SQLite3_result *rules1 = make_rules_result({});
	SQLite3_result *sqli1  = make_sqli_result({
		{"1", "old_fp"},
	});
	GloMyQPro->load_firewall(users1, rules1, sqli1);

	ok(GloMyQPro->whitelisted_sqli_fingerprint((char*)"old_fp") == true,
		"Firewall sqli reload: old_fp present after first load");

	// Second load without old_fp
	SQLite3_result *users2 = make_users_result({});
	SQLite3_result *rules2 = make_rules_result({});
	SQLite3_result *sqli2  = make_sqli_result({
		{"1", "new_fp"},
	});
	GloMyQPro->load_firewall(users2, rules2, sqli2);

	ok(GloMyQPro->whitelisted_sqli_fingerprint((char*)"old_fp") == false,
		"Firewall sqli reload: old_fp gone after second load");
	ok(GloMyQPro->whitelisted_sqli_fingerprint((char*)"new_fp") == true,
		"Firewall sqli reload: new_fp present after second load");
}

// ============================================================================
// 4. Memory accounting
// ============================================================================

/**
 * @brief Test that memory accounting functions return sensible values.
 */
static void test_firewall_memory_accounting() {
	// Load some data so maps are non-empty
	SQLite3_result *users = make_users_result({
		{"1", "memuser", "10.0.0.1", "PROTECTING"},
	});
	SQLite3_result *rules = make_rules_result({
		{"1", "memuser", "10.0.0.1", "mydb", "0", "0xAAAA"},
	});
	SQLite3_result *sqli = make_sqli_result({
		{"1", "s&1"},
	});
	GloMyQPro->load_firewall(users, rules, sqli);

	unsigned long long users_table = GloMyQPro->get_firewall_memory_users_table();
	unsigned long long rules_table = GloMyQPro->get_firewall_memory_rules_table();

	ok(users_table > 0,
		"Firewall memory: users_table size > 0 (got %llu)", users_table);
	ok(rules_table > 0,
		"Firewall memory: rules_table size > 0 (got %llu)", rules_table);

	// After loading empty data, sizes should drop
	SQLite3_result *empty_users = make_users_result({});
	SQLite3_result *empty_rules = make_rules_result({});
	SQLite3_result *empty_sqli  = make_sqli_result({});
	GloMyQPro->load_firewall(empty_users, empty_rules, empty_sqli);

	unsigned long long users_table_empty = GloMyQPro->get_firewall_memory_users_table();
	unsigned long long rules_table_empty = GloMyQPro->get_firewall_memory_rules_table();

	ok(users_table_empty == 0,
		"Firewall memory: users_table size is 0 after clearing (got %llu)", users_table_empty);
	ok(rules_table_empty == 0,
		"Firewall memory: rules_table size is 0 after clearing (got %llu)", rules_table_empty);
}

// ============================================================================
// 5. get_current_firewall_whitelist retrieval
// ============================================================================

/**
 * @brief Test get_current_firewall_whitelist returns copies of loaded data.
 */
static void test_firewall_get_current() {
	SQLite3_result *users = make_users_result({
		{"1", "fetchuser", "10.0.0.1", "DETECTING"},
	});
	SQLite3_result *rules = make_rules_result({
		{"1", "fetchuser", "10.0.0.1", "testdb", "0", "0xBBBB"},
	});
	SQLite3_result *sqli = make_sqli_result({
		{"1", "fp1"},
	});
	GloMyQPro->load_firewall(users, rules, sqli);

	SQLite3_result *ret_users = nullptr;
	SQLite3_result *ret_rules = nullptr;
	SQLite3_result *ret_sqli  = nullptr;
	GloMyQPro->get_current_firewall_whitelist(&ret_users, &ret_rules, &ret_sqli);

	ok(ret_users != nullptr && ret_users->rows_count == 1,
		"Firewall get_current: users result has 1 row");
	ok(ret_rules != nullptr && ret_rules->rows_count == 1,
		"Firewall get_current: rules result has 1 row");
	ok(ret_sqli != nullptr && ret_sqli->rows_count == 1,
		"Firewall get_current: sqli result has 1 row");

	if (ret_users) {
		delete ret_users;
	}
	if (ret_rules) {
		delete ret_rules;
	}
	if (ret_sqli) {
		delete ret_sqli;
	}
}

// ============================================================================
// 6. PgSQL parity — basic smoke test
// ============================================================================

/**
 * @brief Verify PgSQL query processor also supports firewall whitelist.
 */
static void test_pgsql_firewall_basic() {
	SQLite3_result *users = make_users_result({
		{"1", "pguser", "10.0.0.1", "PROTECTING"},
	});
	SQLite3_result *rules = make_rules_result({
		{"1", "pguser", "10.0.0.1", "pgdb", "0", "0xFFFF"},
	});
	SQLite3_result *sqli = make_sqli_result({
		{"1", "pg_fp"},
	});

	GloPgQPro->load_firewall(users, rules, sqli);

	int status = GloPgQPro->find_firewall_whitelist_user((char*)"pguser", (char*)"10.0.0.1");
	ok(status == WUS_PROTECTING,
		"PgSQL firewall users: pguser@10.0.0.1 is PROTECTING (got %d)", status);

	bool found = GloPgQPro->find_firewall_whitelist_rule(
		(char*)"pguser", (char*)"10.0.0.1", (char*)"pgdb", 0, 0xFFFF);
	ok(found == true,
		"PgSQL firewall rules: digest 0xFFFF found");

	found = GloPgQPro->whitelisted_sqli_fingerprint((char*)"pg_fp");
	ok(found == true,
		"PgSQL firewall sqli: pg_fp fingerprint found");
}

// ============================================================================
// 7. Multiple digests for same key, sorted for bsearch
// ============================================================================

/**
 * @brief Test that multiple digests for the same user/schema/flag combo
 *        are all findable (tests internal sort + bsearch).
 */
static void test_firewall_rules_multiple_digests() {
	SQLite3_result *users = make_users_result({
		{"1", "multiuser", "10.0.0.1", "PROTECTING"},
	});
	// Add several digests for the same key, in non-sorted order
	SQLite3_result *rules = make_rules_result({
		{"1", "multiuser", "10.0.0.1", "mydb", "0", "0xFF00"},
		{"1", "multiuser", "10.0.0.1", "mydb", "0", "0x0001"},
		{"1", "multiuser", "10.0.0.1", "mydb", "0", "0x8000"},
		{"1", "multiuser", "10.0.0.1", "mydb", "0", "0x0100"},
	});
	SQLite3_result *sqli = make_sqli_result({});

	GloMyQPro->load_firewall(users, rules, sqli);

	// All four should be findable
	ok(GloMyQPro->find_firewall_whitelist_rule(
		(char*)"multiuser", (char*)"10.0.0.1", (char*)"mydb", 0, 0xFF00) == true,
		"Firewall multi-digest: 0xFF00 found");
	ok(GloMyQPro->find_firewall_whitelist_rule(
		(char*)"multiuser", (char*)"10.0.0.1", (char*)"mydb", 0, 0x0001) == true,
		"Firewall multi-digest: 0x0001 found");
	ok(GloMyQPro->find_firewall_whitelist_rule(
		(char*)"multiuser", (char*)"10.0.0.1", (char*)"mydb", 0, 0x8000) == true,
		"Firewall multi-digest: 0x8000 found");
	ok(GloMyQPro->find_firewall_whitelist_rule(
		(char*)"multiuser", (char*)"10.0.0.1", (char*)"mydb", 0, 0x0100) == true,
		"Firewall multi-digest: 0x0100 found");

	// One that does not exist
	ok(GloMyQPro->find_firewall_whitelist_rule(
		(char*)"multiuser", (char*)"10.0.0.1", (char*)"mydb", 0, 0xDEAD) == false,
		"Firewall multi-digest: 0xDEAD not found");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(44);

	test_init_minimal();
	test_init_query_processor();

	// MySQL firewall tests
	test_firewall_users_basic();              //  5 tests
	test_firewall_users_inactive();           //  2 tests
	test_firewall_users_reload();             //  2 tests
	test_firewall_users_removal();            //  2 tests
	test_firewall_rules_basic();              //  7 tests
	test_firewall_rules_inactive();           //  2 tests
	test_firewall_rules_empty_clears();       //  2 tests
	test_firewall_sqli_basic();               //  4 tests
	test_firewall_sqli_reload();              //  3 tests
	test_firewall_memory_accounting();        //  4 tests
	test_firewall_get_current();              //  3 tests

	// PgSQL parity
	test_pgsql_firewall_basic();              //  3 tests

	// Multi-digest bsearch
	test_firewall_rules_multiple_digests();   //  5 tests

	test_cleanup_query_processor();
	test_cleanup_minimal();

	return exit_status();
}
