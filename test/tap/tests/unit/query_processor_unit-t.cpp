/**
 * @file query_processor_unit-t.cpp
 * @brief Unit tests for MySQL_Query_Processor and PgSQL_Query_Processor.
 *
 * Tests the query processor rule management in isolation without a
 * running ProxySQL instance. Covers:
 *   - Rule creation via new_query_rule() factory method
 *   - Rule field storage and retrieval
 *   - Rule insertion, sorting by rule_id, and commit
 *   - Rule retrieval via get_current_query_rules() (SQLite3 result)
 *   - Regex modifier parsing (CASELESS, GLOBAL)
 *   - Active/inactive rule filtering
 *   - PgSQL rule parity
 *
 * @note Full process_query() testing requires a MySQL_Session with
 *       populated connection data (username, schema, client address),
 *       which is beyond the scope of isolated unit tests. Those
 *       scenarios are covered by the existing E2E TAP tests.
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

// Extern declarations for Glo* pointers (defined in test_globals.cpp)
extern MySQL_Query_Processor *GloMyQPro;
extern PgSQL_Query_Processor *GloPgQPro;

// ============================================================================
// Helpers
// ============================================================================

/**
 * @brief Create a simple MySQL query rule with common defaults.
 *
 * Most fields default to -1/NULL/false (no match / no action).
 * Only rule_id, active, and explicitly passed fields are set.
 */
static MySQL_Query_Processor_Rule_t *mysql_simple_rule(
	int rule_id, bool active,
	const char *match_pattern = nullptr,
	int destination_hostgroup = -1,
	bool apply = false,
	const char *username = nullptr,
	int flagIN = 0, int flagOUT = -1)
{
	return MySQL_Query_Processor::new_query_rule(
		rule_id, active,
		username,               // username
		nullptr,                // schemaname
		flagIN,                 // flagIN
		nullptr,                // client_addr
		nullptr,                // proxy_addr
		-1,                     // proxy_port
		nullptr,                // digest
		nullptr,                // match_digest
		match_pattern,          // match_pattern
		false,                  // negate_match_pattern
		nullptr,                // re_modifiers
		flagOUT,                // flagOUT
		nullptr,                // replace_pattern
		destination_hostgroup,  // destination_hostgroup
		-1,                     // cache_ttl
		-1,                     // cache_empty_result
		-1,                     // cache_timeout
		-1,                     // reconnect
		-1,                     // timeout
		-1,                     // retries
		-1,                     // delay
		-1,                     // next_query_flagIN
		-1,                     // mirror_flagOUT
		-1,                     // mirror_hostgroup
		nullptr,                // error_msg
		nullptr,                // OK_msg
		-1,                     // sticky_conn
		-1,                     // multiplex
		-1,                     // gtid_from_hostgroup
		-1,                     // log
		apply,                  // apply
		nullptr,                // attributes
		nullptr                 // comment
	);
}

/**
 * @brief Create a simple PgSQL query rule with common defaults.
 */
static PgSQL_Query_Processor_Rule_t *pgsql_simple_rule(
	int rule_id, bool active,
	const char *match_pattern = nullptr,
	int destination_hostgroup = -1,
	bool apply = false)
{
	return PgSQL_Query_Processor::new_query_rule(
		rule_id, active,
		nullptr, nullptr,       // username, schemaname
		0,                      // flagIN
		nullptr, nullptr, -1,   // client_addr, proxy_addr, proxy_port
		nullptr,                // digest
		nullptr,                // match_digest
		match_pattern,          // match_pattern
		false,                  // negate_match_pattern
		nullptr,                // re_modifiers
		-1,                     // flagOUT
		nullptr,                // replace_pattern
		destination_hostgroup,  // destination_hostgroup
		-1, -1, -1,            // cache_ttl, cache_empty_result, cache_timeout
		-1, -1, -1, -1,        // reconnect, timeout, retries, delay
		-1, -1, -1,            // next_query_flagIN, mirror_flagOUT, mirror_hostgroup
		nullptr, nullptr,       // error_msg, OK_msg
		-1, -1,                 // sticky_conn, multiplex
		-1,                     // log
		apply,                  // apply
		nullptr, nullptr        // attributes, comment
	);
}

// ============================================================================
// 1. Rule creation via new_query_rule()
// ============================================================================

/**
 * @brief Test that new_query_rule() allocates and populates a rule.
 */
static void test_mysql_rule_creation() {
	auto *rule = MySQL_Query_Processor::new_query_rule(
		100,                    // rule_id
		true,                   // active
		"testuser",             // username
		"testdb",               // schemaname
		0,                      // flagIN
		"192.168.1.%",          // client_addr
		nullptr,                // proxy_addr
		-1,                     // proxy_port
		nullptr,                // digest
		"^SELECT",              // match_digest
		"SELECT.*FROM users",   // match_pattern
		false,                  // negate_match_pattern
		"CASELESS",             // re_modifiers
		-1,                     // flagOUT
		nullptr,                // replace_pattern
		5,                      // destination_hostgroup
		3000,                   // cache_ttl
		1,                      // cache_empty_result
		-1,                     // cache_timeout
		-1,                     // reconnect
		5000,                   // timeout
		3,                      // retries
		-1,                     // delay
		-1,                     // next_query_flagIN
		-1,                     // mirror_flagOUT
		-1,                     // mirror_hostgroup
		nullptr,                // error_msg
		nullptr,                // OK_msg
		1,                      // sticky_conn
		0,                      // multiplex
		-1,                     // gtid_from_hostgroup
		1,                      // log
		true,                   // apply
		nullptr,                // attributes
		"route reads to HG 5"  // comment
	);

	ok(rule != nullptr, "MySQL QP: new_query_rule() returns non-null");
	ok(rule->rule_id == 100, "MySQL QP: rule_id is correct");
	ok(rule->active == true, "MySQL QP: active is correct");
	ok(rule->username != nullptr && strcmp(rule->username, "testuser") == 0,
		"MySQL QP: username is stored correctly");
	ok(rule->schemaname != nullptr && strcmp(rule->schemaname, "testdb") == 0,
		"MySQL QP: schemaname is stored correctly");
	ok(rule->match_digest != nullptr && strcmp(rule->match_digest, "^SELECT") == 0,
		"MySQL QP: match_digest is stored correctly");
	ok(rule->match_pattern != nullptr && strcmp(rule->match_pattern, "SELECT.*FROM users") == 0,
		"MySQL QP: match_pattern is stored correctly");
	ok(rule->destination_hostgroup == 5,
		"MySQL QP: destination_hostgroup is correct");
	ok(rule->cache_ttl == 3000,
		"MySQL QP: cache_ttl is correct");
	ok(rule->timeout == 5000,
		"MySQL QP: timeout is correct");
	ok(rule->retries == 3,
		"MySQL QP: retries is correct");
	ok(rule->sticky_conn == 1,
		"MySQL QP: sticky_conn is correct");
	ok(rule->multiplex == 0,
		"MySQL QP: multiplex is correct");
	ok(rule->apply == true,
		"MySQL QP: apply flag is correct");
	ok(rule->comment != nullptr && strcmp(rule->comment, "route reads to HG 5") == 0,
		"MySQL QP: comment is stored correctly");
	ok(rule->log == 1,
		"MySQL QP: log is correct");
	ok(rule->client_addr != nullptr && strcmp(rule->client_addr, "192.168.1.%") == 0,
		"MySQL QP: client_addr is stored correctly");

	// Verify re_modifiers parsed correctly
	ok(rule->re_modifiers & QP_RE_MOD_CASELESS,
		"MySQL QP: CASELESS re_modifier is set");

	// This rule is not inserted into the QP, so we free it manually.
	free(rule->username); free(rule->schemaname);
	free(rule->match_digest); free(rule->match_pattern);
	free(rule->client_addr); free(rule->comment);
	free(rule);
}

// ============================================================================
// 2. Rule insertion and retrieval via get_current_query_rules()
// ============================================================================

/**
 * @brief Test inserting rules and retrieving them via SQL result set.
 */
static void test_mysql_insert_and_retrieve() {
	// Create and insert rules
	auto *r1 = mysql_simple_rule(10, true, "^SELECT", 1, true);
	auto *r2 = mysql_simple_rule(20, true, "^INSERT", 2, true);
	auto *r3 = mysql_simple_rule(30, false, "^DELETE", 3, true);  // inactive

	GloMyQPro->insert((QP_rule_t *)r1);
	GloMyQPro->insert((QP_rule_t *)r2);
	GloMyQPro->insert((QP_rule_t *)r3);
	GloMyQPro->sort();
	GloMyQPro->commit();

	SQLite3_result *result = GloMyQPro->get_current_query_rules();
	ok(result != nullptr, "MySQL QP: get_current_query_rules() returns non-null");

	if (result != nullptr) {
		ok(result->rows_count == 3,
			"MySQL QP: get_current_query_rules() returns 3 rules");
		delete result;
	} else {
		ok(0, "MySQL QP: get_current_query_rules() returns 3 rules (skipped)");
	}
}

/**
 * @brief Test that rules are sorted by rule_id after sort().
 */
static void test_mysql_rule_sorting() {
	// Reset rules
	GloMyQPro->reset_all(true);

	// Insert in reverse order
	auto *r3 = mysql_simple_rule(300, true, nullptr, 3);
	auto *r1 = mysql_simple_rule(100, true, nullptr, 1);
	auto *r2 = mysql_simple_rule(200, true, nullptr, 2);

	GloMyQPro->insert((QP_rule_t *)r3);
	GloMyQPro->insert((QP_rule_t *)r1);
	GloMyQPro->insert((QP_rule_t *)r2);
	GloMyQPro->sort();
	GloMyQPro->commit();

	SQLite3_result *result = GloMyQPro->get_current_query_rules();
	ok(result != nullptr && result->rows_count == 3,
		"MySQL QP: 3 rules after insert in reverse order");

	if (result != nullptr && result->rows_count == 3) {
		// First row should be rule_id=100 (sorted ascending)
		auto it = result->rows.begin();
		ok(strcmp((*it)->fields[0], "100") == 0,
			"MySQL QP: first rule after sort has rule_id=100");
		++it;
		ok(strcmp((*it)->fields[0], "200") == 0,
			"MySQL QP: second rule after sort has rule_id=200");
		++it;
		ok(strcmp((*it)->fields[0], "300") == 0,
			"MySQL QP: third rule after sort has rule_id=300");
		delete result;
	} else {
		ok(0, "MySQL QP: first rule sorted (skipped)");
		ok(0, "MySQL QP: second rule sorted (skipped)");
		ok(0, "MySQL QP: third rule sorted (skipped)");
		if (result) {
			delete result;
		}
	}
}

// ============================================================================
// 3. Regex modifier parsing
// ============================================================================

/**
 * @brief Test re_modifiers parsing for CASELESS, GLOBAL, and combined.
 */
static void test_regex_modifiers() {
	auto *r1 = mysql_simple_rule(1, true);
	ok((r1->re_modifiers & QP_RE_MOD_CASELESS) == 0,
		"MySQL QP: no modifiers when re_modifiers is null");
	free(r1);

	// Create rule with CASELESS
	auto *r2 = MySQL_Query_Processor::new_query_rule(
		2, true, nullptr, nullptr, 0, nullptr, nullptr, -1,
		nullptr, nullptr, "test", false, "CASELESS",
		-1, nullptr, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		nullptr, nullptr, -1, -1, -1, -1, false, nullptr, nullptr);
	ok((r2->re_modifiers & QP_RE_MOD_CASELESS) != 0,
		"MySQL QP: CASELESS modifier parsed");
	ok((r2->re_modifiers & QP_RE_MOD_GLOBAL) == 0,
		"MySQL QP: GLOBAL not set when only CASELESS specified");
	free(r2->match_pattern);
	free(r2);

	// Create rule with CASELESS,GLOBAL
	auto *r3 = MySQL_Query_Processor::new_query_rule(
		3, true, nullptr, nullptr, 0, nullptr, nullptr, -1,
		nullptr, nullptr, "test", false, "CASELESS,GLOBAL",
		-1, nullptr, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		nullptr, nullptr, -1, -1, -1, -1, false, nullptr, nullptr);
	ok((r3->re_modifiers & QP_RE_MOD_CASELESS) != 0,
		"MySQL QP: CASELESS set in combined modifiers");
	ok((r3->re_modifiers & QP_RE_MOD_GLOBAL) != 0,
		"MySQL QP: GLOBAL set in combined modifiers");
	free(r3->match_pattern);
	free(r3);
}

// ============================================================================
// 4. Rule with all match fields populated
// ============================================================================

/**
 * @brief Test rule with error_msg, OK_msg, and replace_pattern.
 */
static void test_mysql_rule_special_fields() {
	auto *rule = MySQL_Query_Processor::new_query_rule(
		50, true,
		nullptr, nullptr,       // username, schemaname
		0,                      // flagIN
		nullptr, nullptr, -1,   // client_addr, proxy_addr, proxy_port
		nullptr,                // digest
		nullptr,                // match_digest
		"^BLOCKED",             // match_pattern
		false,                  // negate_match_pattern
		nullptr,                // re_modifiers
		-1,                     // flagOUT
		"REWRITTEN",            // replace_pattern
		-1,                     // destination_hostgroup
		-1, -1, -1,            // cache_ttl, cache_empty_result, cache_timeout
		-1, -1, -1, -1,        // reconnect, timeout, retries, delay
		-1, -1, -1,            // next_query_flagIN, mirror_flagOUT, mirror_hostgroup
		"Access denied",        // error_msg
		"Query OK",             // OK_msg
		-1, -1, -1, -1,        // sticky_conn, multiplex, gtid_from_hostgroup, log
		true, nullptr, nullptr  // apply, attributes, comment
	);

	ok(rule->error_msg != nullptr && strcmp(rule->error_msg, "Access denied") == 0,
		"MySQL QP: error_msg stored correctly");
	ok(rule->OK_msg != nullptr && strcmp(rule->OK_msg, "Query OK") == 0,
		"MySQL QP: OK_msg stored correctly");
	ok(rule->replace_pattern != nullptr && strcmp(rule->replace_pattern, "REWRITTEN") == 0,
		"MySQL QP: replace_pattern stored correctly");

	free(rule->match_pattern); free(rule->replace_pattern);
	free(rule->error_msg); free(rule->OK_msg);
	free(rule);
}

// ============================================================================
// 5. flagIN/flagOUT chaining
// ============================================================================

/**
 * @brief Test rule creation with flagIN/flagOUT for chain matching.
 */
static void test_mysql_flag_chaining() {
	GloMyQPro->reset_all(true);

	// Rule 1: flagIN=0, flagOUT=1 (passes to next stage)
	auto *r1 = mysql_simple_rule(10, true, nullptr, -1, false,
		nullptr, 0, 1);
	// Rule 2: flagIN=1, applies with destination
	auto *r2 = mysql_simple_rule(20, true, nullptr, 5, true,
		nullptr, 1, -1);

	GloMyQPro->insert((QP_rule_t *)r1);
	GloMyQPro->insert((QP_rule_t *)r2);
	GloMyQPro->sort();
	GloMyQPro->commit();

	SQLite3_result *result = GloMyQPro->get_current_query_rules();
	ok(result != nullptr && result->rows_count == 2,
		"MySQL QP: 2 chained rules inserted correctly");
	if (result) {
		delete result;
	}
}

// ============================================================================
// 6. Rule with username filter
// ============================================================================

/**
 * @brief Test rule creation with username filter.
 */
static void test_mysql_rule_with_username() {
	GloMyQPro->reset_all(true);

	auto *r1 = mysql_simple_rule(10, true, "^SELECT", 1, true, "admin");
	auto *r2 = mysql_simple_rule(20, true, "^SELECT", 2, true, "readonly");

	GloMyQPro->insert((QP_rule_t *)r1);
	GloMyQPro->insert((QP_rule_t *)r2);
	GloMyQPro->sort();
	GloMyQPro->commit();

	SQLite3_result *result = GloMyQPro->get_current_query_rules();
	ok(result != nullptr && result->rows_count == 2,
		"MySQL QP: 2 rules with username filters inserted");
	if (result) {
		delete result;
	}
}

// ============================================================================
// 7. Reset all rules
// ============================================================================

/**
 * @brief Test reset_all() clears all rules.
 */
static void test_mysql_reset_all() {
	GloMyQPro->reset_all(true);

	GloMyQPro->insert((QP_rule_t *)mysql_simple_rule(10, true));
	GloMyQPro->insert((QP_rule_t *)mysql_simple_rule(20, true));
	GloMyQPro->commit();

	GloMyQPro->reset_all(true);

	SQLite3_result *result = GloMyQPro->get_current_query_rules();
	ok(result != nullptr && result->rows_count == 0,
		"MySQL QP: no rules after reset_all()");
	if (result) {
		delete result;
	}
}

// ============================================================================
// 8. Stats commands counters
// ============================================================================

/**
 * @brief Test get_stats_commands_counters() returns a valid result.
 */
static void test_mysql_stats_counters() {
	SQLite3_result *result = GloMyQPro->get_stats_commands_counters();
	ok(result != nullptr,
		"MySQL QP: get_stats_commands_counters() returns non-null");
	if (result != nullptr) {
		ok(result->columns > 0,
			"MySQL QP: stats counters result has columns");
		delete result;
	} else {
		ok(0, "MySQL QP: stats counters result has columns (skipped)");
	}
}

// ============================================================================
// 9. PgSQL Query Processor: Basic operations
// ============================================================================

/**
 * @brief Test PgSQL rule creation and insertion.
 */
static void test_pgsql_rule_creation_and_insert() {
	auto *rule = pgsql_simple_rule(10, true, "^SELECT", 1, true);
	ok(rule != nullptr, "PgSQL QP: new_query_rule() returns non-null");
	ok(rule->rule_id == 10, "PgSQL QP: rule_id is correct");
	ok(rule->destination_hostgroup == 1,
		"PgSQL QP: destination_hostgroup is correct");

	GloPgQPro->insert((QP_rule_t *)rule);
	GloPgQPro->sort();
	GloPgQPro->commit();

	SQLite3_result *result = GloPgQPro->get_current_query_rules();
	ok(result != nullptr && result->rows_count >= 1,
		"PgSQL QP: rule appears in get_current_query_rules()");
	if (result) {
		delete result;
	}
}

/**
 * @brief Test PgSQL reset and stats.
 */
static void test_pgsql_reset_and_stats() {
	GloPgQPro->reset_all(true);
	SQLite3_result *result = GloPgQPro->get_current_query_rules();
	ok(result != nullptr && result->rows_count == 0,
		"PgSQL QP: no rules after reset_all()");
	if (result) {
		delete result;
	}
}

// ============================================================================
// 10. PgSQL: Comprehensive rule creation with all fields
// ============================================================================

/**
 * @brief Test PgSQL rule creation with all fields populated.
 *
 * Exercises PgSQL_Query_Processor::new_query_rule() with every
 * parameter set, verifying correct storage including PgSQL-specific
 * fields like log (which PgSQL exposes without gtid_from_hostgroup).
 */
static void test_pgsql_rule_creation_all_fields() {
	auto *rule = PgSQL_Query_Processor::new_query_rule(
		200,                    // rule_id
		true,                   // active
		"pguser",               // username
		"pgdb",                 // schemaname
		0,                      // flagIN
		"10.0.0.%",             // client_addr (wildcard)
		"127.0.0.1",            // proxy_addr
		6432,                   // proxy_port
		"0x1234ABCD00000000",   // digest
		"^SELECT",              // match_digest
		"SELECT.*FROM orders",  // match_pattern
		true,                   // negate_match_pattern
		"CASELESS,GLOBAL",      // re_modifiers
		5,                      // flagOUT
		"REWRITTEN",            // replace_pattern
		10,                     // destination_hostgroup
		5000,                   // cache_ttl
		1,                      // cache_empty_result
		2000,                   // cache_timeout
		1,                      // reconnect
		10000,                  // timeout
		5,                      // retries
		100,                    // delay
		3,                      // next_query_flagIN
		7,                      // mirror_flagOUT
		20,                     // mirror_hostgroup
		"blocked",              // error_msg
		"done",                 // OK_msg
		1,                      // sticky_conn
		2,                      // multiplex
		1,                      // log
		true,                   // apply
		nullptr,                // attributes
		"PgSQL routing rule"    // comment
	);

	ok(rule != nullptr, "PgSQL QP: all-fields rule is non-null");
	ok(rule->rule_id == 200, "PgSQL QP: rule_id stored correctly");
	ok(rule->active == true, "PgSQL QP: active stored correctly");
	ok(rule->username != nullptr && strcmp(rule->username, "pguser") == 0,
		"PgSQL QP: username stored correctly");
	ok(rule->schemaname != nullptr && strcmp(rule->schemaname, "pgdb") == 0,
		"PgSQL QP: schemaname stored correctly");
	ok(rule->flagIN == 0, "PgSQL QP: flagIN stored correctly");
	ok(rule->client_addr != nullptr && strcmp(rule->client_addr, "10.0.0.%") == 0,
		"PgSQL QP: client_addr stored correctly");
	ok(rule->client_addr_wildcard_position == 7,
		"PgSQL QP: client_addr wildcard position computed correctly");
	ok(rule->proxy_addr != nullptr && strcmp(rule->proxy_addr, "127.0.0.1") == 0,
		"PgSQL QP: proxy_addr stored correctly");
	ok(rule->proxy_port == 6432, "PgSQL QP: proxy_port stored correctly");
	ok(rule->digest != 0, "PgSQL QP: digest parsed from hex string");
	ok(rule->match_digest != nullptr && strcmp(rule->match_digest, "^SELECT") == 0,
		"PgSQL QP: match_digest stored correctly");
	ok(rule->match_pattern != nullptr && strcmp(rule->match_pattern, "SELECT.*FROM orders") == 0,
		"PgSQL QP: match_pattern stored correctly");
	ok(rule->negate_match_pattern == true,
		"PgSQL QP: negate_match_pattern stored correctly");
	ok((rule->re_modifiers & QP_RE_MOD_CASELESS) != 0,
		"PgSQL QP: CASELESS re_modifier set");
	ok((rule->re_modifiers & QP_RE_MOD_GLOBAL) != 0,
		"PgSQL QP: GLOBAL re_modifier set");
	ok(rule->flagOUT == 5, "PgSQL QP: flagOUT stored correctly");
	ok(rule->replace_pattern != nullptr && strcmp(rule->replace_pattern, "REWRITTEN") == 0,
		"PgSQL QP: replace_pattern stored correctly");
	ok(rule->destination_hostgroup == 10,
		"PgSQL QP: destination_hostgroup stored correctly");
	ok(rule->cache_ttl == 5000, "PgSQL QP: cache_ttl stored correctly");
	ok(rule->cache_empty_result == 1, "PgSQL QP: cache_empty_result stored correctly");
	ok(rule->cache_timeout == 2000, "PgSQL QP: cache_timeout stored correctly");
	ok(rule->timeout == 10000, "PgSQL QP: timeout stored correctly");
	ok(rule->retries == 5, "PgSQL QP: retries stored correctly");
	ok(rule->delay == 100, "PgSQL QP: delay stored correctly");
	ok(rule->next_query_flagIN == 3, "PgSQL QP: next_query_flagIN stored correctly");
	ok(rule->mirror_flagOUT == 7, "PgSQL QP: mirror_flagOUT stored correctly");
	ok(rule->mirror_hostgroup == 20, "PgSQL QP: mirror_hostgroup stored correctly");
	ok(rule->error_msg != nullptr && strcmp(rule->error_msg, "blocked") == 0,
		"PgSQL QP: error_msg stored correctly");
	ok(rule->OK_msg != nullptr && strcmp(rule->OK_msg, "done") == 0,
		"PgSQL QP: OK_msg stored correctly");
	ok(rule->sticky_conn == 1, "PgSQL QP: sticky_conn stored correctly");
	ok(rule->multiplex == 2, "PgSQL QP: multiplex stored correctly");
	ok(rule->log == 1, "PgSQL QP: log stored correctly");
	ok(rule->apply == true, "PgSQL QP: apply stored correctly");
	ok(rule->comment != nullptr && strcmp(rule->comment, "PgSQL routing rule") == 0,
		"PgSQL QP: comment stored correctly");
	ok(rule->hits == 0, "PgSQL QP: hits initialized to 0");

	// Free manually since not inserted into QP
	free(rule->username); free(rule->schemaname);
	free(rule->client_addr); free(rule->proxy_addr);
	free(rule->match_digest); free(rule->match_pattern);
	free(rule->replace_pattern); free(rule->error_msg);
	free(rule->OK_msg); free(rule->comment);
	free(rule);
}

// ============================================================================
// 11. PgSQL: client_addr wildcard at position 0 (catch-all '%')
// ============================================================================

/**
 * @brief Test client_addr wildcard position computation edge cases.
 */
static void test_pgsql_client_addr_wildcard() {
	// Catch-all: client_addr = "%"
	auto *r1 = PgSQL_Query_Processor::new_query_rule(
		1, true, nullptr, nullptr, 0,
		"%",                    // client_addr = catch-all
		nullptr, -1, nullptr, nullptr, nullptr, false, nullptr,
		-1, nullptr, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		nullptr, nullptr, -1, -1, -1, false, nullptr, nullptr);
	ok(r1->client_addr_wildcard_position == 0,
		"PgSQL QP: client_addr catch-all sets wildcard position to 0");
	free(r1->client_addr);
	free(r1);

	// No wildcard
	auto *r2 = PgSQL_Query_Processor::new_query_rule(
		2, true, nullptr, nullptr, 0,
		"192.168.1.1",          // no wildcard
		nullptr, -1, nullptr, nullptr, nullptr, false, nullptr,
		-1, nullptr, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		nullptr, nullptr, -1, -1, -1, false, nullptr, nullptr);
	ok(r2->client_addr_wildcard_position == -1,
		"PgSQL QP: client_addr without wildcard has position -1");
	free(r2->client_addr);
	free(r2);

	// No client_addr
	auto *r3 = PgSQL_Query_Processor::new_query_rule(
		3, true, nullptr, nullptr, 0,
		nullptr,                // no client_addr
		nullptr, -1, nullptr, nullptr, nullptr, false, nullptr,
		-1, nullptr, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		nullptr, nullptr, -1, -1, -1, false, nullptr, nullptr);
	ok(r3->client_addr == nullptr,
		"PgSQL QP: null client_addr is stored as null");
	ok(r3->client_addr_wildcard_position == -1,
		"PgSQL QP: null client_addr has wildcard position -1");
	free(r3);
}

// ============================================================================
// 12. PgSQL: Rule with JSON attributes (flagOUTs)
// ============================================================================

/**
 * @brief Test rule creation with flagOUTs in attributes JSON.
 *
 * Exercises the JSON attributes parsing path in new_query_rule(),
 * which populates flagOUT_ids, flagOUT_weights, and flagOUT_weights_total.
 */
static void test_pgsql_rule_attributes_flagouts() {
	const char *attrs = R"({"flagOUTs":[{"id":1,"weight":10},{"id":2,"weight":20}]})";

	auto *rule = PgSQL_Query_Processor::new_query_rule(
		50, true, nullptr, nullptr, 0,
		nullptr, nullptr, -1, nullptr, nullptr, nullptr, false, nullptr,
		-1, nullptr, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		nullptr, nullptr, -1, -1, -1, false, attrs, nullptr);

	ok(rule->flagOUT_ids != nullptr,
		"PgSQL QP: flagOUT_ids parsed from attributes");
	ok(rule->flagOUT_weights != nullptr,
		"PgSQL QP: flagOUT_weights parsed from attributes");
	if (rule->flagOUT_ids && rule->flagOUT_weights) {
		ok(rule->flagOUT_ids->size() == 2,
			"PgSQL QP: flagOUT_ids has 2 entries");
		ok(rule->flagOUT_weights->size() == 2,
			"PgSQL QP: flagOUT_weights has 2 entries");
		ok(rule->flagOUT_weights_total == 30,
			"PgSQL QP: flagOUT_weights_total is sum of weights (30)");
		ok((*rule->flagOUT_ids)[0] == 1 && (*rule->flagOUT_ids)[1] == 2,
			"PgSQL QP: flagOUT_ids values are correct");
		ok((*rule->flagOUT_weights)[0] == 10 && (*rule->flagOUT_weights)[1] == 20,
			"PgSQL QP: flagOUT_weights values are correct");
	} else {
		// Skip tests if parsing failed
		ok(0, "PgSQL QP: flagOUT_ids has 2 entries (skipped)");
		ok(0, "PgSQL QP: flagOUT_weights has 2 entries (skipped)");
		ok(0, "PgSQL QP: flagOUT_weights_total is sum of weights (skipped)");
		ok(0, "PgSQL QP: flagOUT_ids values are correct (skipped)");
		ok(0, "PgSQL QP: flagOUT_weights values are correct (skipped)");
	}

	if (rule->flagOUT_ids) {
		delete rule->flagOUT_ids;
	}
	if (rule->flagOUT_weights) {
		delete rule->flagOUT_weights;
	}
	free(rule->attributes);
	free(rule);
}

// ============================================================================
// 13. PgSQL: get_stats_commands_counters validation
// ============================================================================

/**
 * @brief Test PgSQL-specific command counters structure.
 *
 * Validates that get_stats_commands_counters() returns the expected
 * number of columns (15) and rows covering PgSQL-specific command types
 * (VACUUM, ANALYZE, LISTEN, NOTIFY, etc. up to PGSQL_QUERY__UNINITIALIZED).
 */
static void test_pgsql_stats_commands_counters() {
	SQLite3_result *result = GloPgQPro->get_stats_commands_counters();
	ok(result != nullptr,
		"PgSQL QP: get_stats_commands_counters() returns non-null");
	if (result != nullptr) {
		ok(result->columns == 15,
			"PgSQL QP: stats counters has 15 columns");
		// PGSQL_QUERY__UNINITIALIZED is the count of actual command types
		ok(result->rows_count == (unsigned int)PGSQL_QUERY__UNINITIALIZED,
			"PgSQL QP: stats counters row count matches PGSQL_QUERY__UNINITIALIZED");
		// Verify first row is "SELECT"
		if (result->rows_count > 0) {
			auto it = result->rows.begin();
			ok((*it)->fields[0] != nullptr && strcmp((*it)->fields[0], "SELECT") == 0,
				"PgSQL QP: first command counter is SELECT");
		} else {
			ok(0, "PgSQL QP: first command counter is SELECT (skipped)");
		}
		delete result;
	} else {
		ok(0, "PgSQL QP: stats counters has 15 columns (skipped)");
		ok(0, "PgSQL QP: stats counters row count matches (skipped)");
		ok(0, "PgSQL QP: first command counter is SELECT (skipped)");
	}
}

// ============================================================================
// 14. PgSQL: get_stats_query_rules
// ============================================================================

/**
 * @brief Test PgSQL stats query rules retrieval.
 */
static void test_pgsql_stats_query_rules() {
	GloPgQPro->reset_all(true);

	// Insert two active rules and one inactive
	auto *r1 = pgsql_simple_rule(10, true, "^SELECT", 1, true);
	auto *r2 = pgsql_simple_rule(20, true, "^INSERT", 2, true);
	auto *r3 = pgsql_simple_rule(30, false, "^DELETE", 3, true);

	GloPgQPro->insert((QP_rule_t *)r1);
	GloPgQPro->insert((QP_rule_t *)r2);
	GloPgQPro->insert((QP_rule_t *)r3);
	GloPgQPro->sort();
	GloPgQPro->commit();

	SQLite3_result *result = GloPgQPro->get_stats_query_rules();
	ok(result != nullptr,
		"PgSQL QP: get_stats_query_rules() returns non-null");
	if (result != nullptr) {
		// Only active rules appear in stats
		ok(result->rows_count == 2,
			"PgSQL QP: stats shows 2 active rules (inactive excluded)");
		ok(result->columns == 2,
			"PgSQL QP: stats has 2 columns (rule_id, hits)");
		delete result;
	} else {
		ok(0, "PgSQL QP: stats shows 2 active rules (skipped)");
		ok(0, "PgSQL QP: stats has 2 columns (skipped)");
	}
}

// ============================================================================
// 15. PgSQL: Rule field retrieval via get_current_query_rules() result
// ============================================================================

/**
 * @brief Verify that get_current_query_rules() result columns match PgSQL schema.
 *
 * PgSQL has 35 columns in its rule text (no gtid_from_hostgroup but
 * includes log). This test verifies the column count and names.
 */
static void test_pgsql_get_current_query_rules_columns() {
	GloPgQPro->reset_all(true);

	// Insert a rule with known values to verify result text serialization
	auto *rule = PgSQL_Query_Processor::new_query_rule(
		42, true, "testuser", "testdb", 0,
		nullptr, nullptr, -1, nullptr, nullptr, "^SELECT", false,
		"CASELESS,GLOBAL",
		-1, nullptr, 7, -1, -1, -1, -1, 3000, -1, -1, -1, -1, -1,
		nullptr, nullptr, -1, -1, 1, true, nullptr, "test comment");
	GloPgQPro->insert((QP_rule_t *)rule);
	GloPgQPro->sort();
	GloPgQPro->commit();

	SQLite3_result *result = GloPgQPro->get_current_query_rules();
	ok(result != nullptr, "PgSQL QP: get_current_query_rules returns non-null");
	if (result != nullptr) {
		ok(result->columns == 35,
			"PgSQL QP: result has 35 columns");
		ok(result->rows_count == 1,
			"PgSQL QP: result has 1 row");
		if (result->rows_count == 1) {
			auto it = result->rows.begin();
			char **fields = (*it)->fields;
			// Verify key field positions in PgSQL rule text:
			// [0]=rule_id, [1]=active, [2]=username, [3]=database
			ok(strcmp(fields[0], "42") == 0,
				"PgSQL QP: rule_id field is '42'");
			ok(strcmp(fields[1], "1") == 0,
				"PgSQL QP: active field is '1'");
			ok(fields[2] != nullptr && strcmp(fields[2], "testuser") == 0,
				"PgSQL QP: username field is 'testuser'");
			ok(fields[3] != nullptr && strcmp(fields[3], "testdb") == 0,
				"PgSQL QP: database field is 'testdb'");
			// [10]=match_pattern, [12]=re_modifiers
			ok(fields[10] != nullptr && strcmp(fields[10], "^SELECT") == 0,
				"PgSQL QP: match_pattern field is '^SELECT'");
			ok(fields[12] != nullptr && strcmp(fields[12], "CASELESS,GLOBAL") == 0,
				"PgSQL QP: re_modifiers field is 'CASELESS,GLOBAL'");
			// [15]=destination_hostgroup, [20]=timeout, [30]=log, [31]=apply
			ok(strcmp(fields[15], "7") == 0,
				"PgSQL QP: destination_hostgroup field is '7'");
			ok(strcmp(fields[20], "3000") == 0,
				"PgSQL QP: timeout field is '3000'");
			ok(strcmp(fields[30], "1") == 0,
				"PgSQL QP: log field is '1'");
			ok(strcmp(fields[31], "1") == 0,
				"PgSQL QP: apply field is '1'");
			ok(fields[33] != nullptr && strcmp(fields[33], "test comment") == 0,
				"PgSQL QP: comment field is 'test comment'");
		} else {
			for (int i = 0; i < 13; i++) {
				ok(0, "PgSQL QP: field check skipped (no rows)");
			}
		}
		delete result;
	} else {
		for (int i = 0; i < 15; i++) {
			ok(0, "PgSQL QP: get_current_query_rules column check (skipped)");
		}
	}
}

// ============================================================================
// 16. PgSQL: Sorting with reverse-ordered rules
// ============================================================================

/**
 * @brief Test PgSQL rule sorting by rule_id.
 */
static void test_pgsql_rule_sorting() {
	GloPgQPro->reset_all(true);

	auto *r3 = pgsql_simple_rule(300, true, nullptr, 3);
	auto *r1 = pgsql_simple_rule(100, true, nullptr, 1);
	auto *r2 = pgsql_simple_rule(200, true, nullptr, 2);

	GloPgQPro->insert((QP_rule_t *)r3);
	GloPgQPro->insert((QP_rule_t *)r1);
	GloPgQPro->insert((QP_rule_t *)r2);
	GloPgQPro->sort();
	GloPgQPro->commit();

	SQLite3_result *result = GloPgQPro->get_current_query_rules();
	ok(result != nullptr && result->rows_count == 3,
		"PgSQL QP: 3 rules after reverse-order insert");
	if (result != nullptr && result->rows_count == 3) {
		auto it = result->rows.begin();
		ok(strcmp((*it)->fields[0], "100") == 0,
			"PgSQL QP: first rule after sort has rule_id=100");
		++it;
		ok(strcmp((*it)->fields[0], "200") == 0,
			"PgSQL QP: second rule after sort has rule_id=200");
		++it;
		ok(strcmp((*it)->fields[0], "300") == 0,
			"PgSQL QP: third rule after sort has rule_id=300");
		delete result;
	} else {
		ok(0, "PgSQL QP: first rule sorted (skipped)");
		ok(0, "PgSQL QP: second rule sorted (skipped)");
		ok(0, "PgSQL QP: third rule sorted (skipped)");
		if (result) {
			delete result;
		}
	}
}

// ============================================================================
// 17. PgSQL: flagIN/flagOUT chaining
// ============================================================================

/**
 * @brief Test PgSQL rule chaining via flagIN/flagOUT.
 */
static void test_pgsql_flag_chaining() {
	GloPgQPro->reset_all(true);

	auto *r1 = PgSQL_Query_Processor::new_query_rule(
		10, true, nullptr, nullptr,
		0,                      // flagIN
		nullptr, nullptr, -1, nullptr, nullptr, nullptr, false, nullptr,
		1,                      // flagOUT
		nullptr, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		nullptr, nullptr, -1, -1, -1, false, nullptr, nullptr);
	auto *r2 = PgSQL_Query_Processor::new_query_rule(
		20, true, nullptr, nullptr,
		1,                      // flagIN = prev flagOUT
		nullptr, nullptr, -1, nullptr, nullptr, nullptr, false, nullptr,
		-1,                     // flagOUT (terminal)
		nullptr, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		nullptr, nullptr, -1, -1, -1, true, nullptr, nullptr);

	GloPgQPro->insert((QP_rule_t *)r1);
	GloPgQPro->insert((QP_rule_t *)r2);
	GloPgQPro->sort();
	GloPgQPro->commit();

	SQLite3_result *result = GloPgQPro->get_current_query_rules();
	ok(result != nullptr && result->rows_count == 2,
		"PgSQL QP: 2 chained rules inserted correctly");
	if (result) {
		delete result;
	}
}

// ============================================================================
// 18. PgSQL: query_parser_command_type — comprehensive command parsing
// ============================================================================

/**
 * @brief Helper: call query_parser_command_type with a SQL string.
 *
 * Sets up an SQP_par_t with query_prefix pointing to a strdup of
 * the input (since the function frees query_prefix).
 */
static enum PGSQL_QUERY_command pgsql_parse_cmd(const char *sql) {
	SQP_par_t qp;
	memset(&qp, 0, sizeof(qp));
	qp.digest_text = nullptr;
	qp.query_prefix = strdup(sql);
	return PgSQL_Query_Processor::query_parser_command_type(&qp);
}

/**
 * @brief Test PgSQL query_parser_command_type for all major command types.
 *
 * This is the largest uncovered area in PgSQL_Query_Processor.cpp:
 * the giant switch statement classifying PgSQL commands. Each sub-test
 * exercises a different branch.
 */
static void test_pgsql_query_parser_command_type() {
	// Basic DML
	ok(pgsql_parse_cmd("SELECT 1") == PGSQL_QUERY_SELECT,
		"PgSQL cmd: SELECT");
	ok(pgsql_parse_cmd("INSERT INTO t VALUES(1)") == PGSQL_QUERY_INSERT,
		"PgSQL cmd: INSERT");
	ok(pgsql_parse_cmd("UPDATE t SET x=1") == PGSQL_QUERY_UPDATE,
		"PgSQL cmd: UPDATE");
	ok(pgsql_parse_cmd("DELETE FROM t") == PGSQL_QUERY_DELETE,
		"PgSQL cmd: DELETE");
	ok(pgsql_parse_cmd("MERGE INTO t USING s ON t.id=s.id") == PGSQL_QUERY_MERGE,
		"PgSQL cmd: MERGE");
	ok(pgsql_parse_cmd("TRUNCATE TABLE t") == PGSQL_QUERY_TRUNCATE,
		"PgSQL cmd: TRUNCATE");
	ok(pgsql_parse_cmd("COPY t FROM '/tmp/data.csv'") == PGSQL_QUERY_COPY,
		"PgSQL cmd: COPY");

	// DDL: CREATE/ALTER/DROP TABLE
	ok(pgsql_parse_cmd("CREATE TABLE t (id int)") == PGSQL_QUERY_CREATE_TABLE,
		"PgSQL cmd: CREATE TABLE");
	ok(pgsql_parse_cmd("ALTER TABLE t ADD COLUMN x int") == PGSQL_QUERY_ALTER_TABLE,
		"PgSQL cmd: ALTER TABLE");
	ok(pgsql_parse_cmd("DROP TABLE t") == PGSQL_QUERY_DROP_TABLE,
		"PgSQL cmd: DROP TABLE");

	// INDEX
	ok(pgsql_parse_cmd("CREATE INDEX idx ON t(id)") == PGSQL_QUERY_CREATE_INDEX,
		"PgSQL cmd: CREATE INDEX");
	ok(pgsql_parse_cmd("ALTER INDEX idx RENAME") == PGSQL_QUERY_ALTER_INDEX,
		"PgSQL cmd: ALTER INDEX");
	ok(pgsql_parse_cmd("DROP INDEX idx") == PGSQL_QUERY_DROP_INDEX,
		"PgSQL cmd: DROP INDEX");

	// VIEW
	ok(pgsql_parse_cmd("CREATE VIEW v AS SELECT 1") == PGSQL_QUERY_CREATE_VIEW,
		"PgSQL cmd: CREATE VIEW");
	ok(pgsql_parse_cmd("ALTER VIEW v RENAME") == PGSQL_QUERY_ALTER_VIEW,
		"PgSQL cmd: ALTER VIEW");
	ok(pgsql_parse_cmd("DROP VIEW v") == PGSQL_QUERY_DROP_VIEW,
		"PgSQL cmd: DROP VIEW");

	// MATERIALIZED VIEW
	ok(pgsql_parse_cmd("CREATE MATERIALIZED VIEW mv AS SELECT 1") == PGSQL_QUERY_CREATE_MATERIALIZED_VIEW,
		"PgSQL cmd: CREATE MATERIALIZED VIEW");
	ok(pgsql_parse_cmd("ALTER MATERIALIZED VIEW mv RENAME") == PGSQL_QUERY_ALTER_MATERIALIZED_VIEW,
		"PgSQL cmd: ALTER MATERIALIZED VIEW");
	ok(pgsql_parse_cmd("DROP MATERIALIZED VIEW mv") == PGSQL_QUERY_DROP_MATERIALIZED_VIEW,
		"PgSQL cmd: DROP MATERIALIZED VIEW");
	ok(pgsql_parse_cmd("REFRESH MATERIALIZED VIEW mv") == PGSQL_QUERY_REFRESH_MATERIALIZED_VIEW,
		"PgSQL cmd: REFRESH MATERIALIZED VIEW");

	// SEQUENCE
	ok(pgsql_parse_cmd("CREATE SEQUENCE seq") == PGSQL_QUERY_CREATE_SEQUENCE,
		"PgSQL cmd: CREATE SEQUENCE");
	ok(pgsql_parse_cmd("ALTER SEQUENCE seq RESTART") == PGSQL_QUERY_ALTER_SEQUENCE,
		"PgSQL cmd: ALTER SEQUENCE");
	ok(pgsql_parse_cmd("DROP SEQUENCE seq") == PGSQL_QUERY_DROP_SEQUENCE,
		"PgSQL cmd: DROP SEQUENCE");

	// SCHEMA
	ok(pgsql_parse_cmd("CREATE SCHEMA myschema") == PGSQL_QUERY_CREATE_SCHEMA,
		"PgSQL cmd: CREATE SCHEMA");
	ok(pgsql_parse_cmd("ALTER SCHEMA myschema OWNER TO u") == PGSQL_QUERY_ALTER_SCHEMA,
		"PgSQL cmd: ALTER SCHEMA");
	ok(pgsql_parse_cmd("DROP SCHEMA myschema") == PGSQL_QUERY_DROP_SCHEMA,
		"PgSQL cmd: DROP SCHEMA");

	// FUNCTION / PROCEDURE
	ok(pgsql_parse_cmd("CREATE FUNCTION f() RETURNS void") == PGSQL_QUERY_CREATE_FUNCTION,
		"PgSQL cmd: CREATE FUNCTION");
	ok(pgsql_parse_cmd("ALTER FUNCTION f() OWNER TO u") == PGSQL_QUERY_ALTER_FUNCTION,
		"PgSQL cmd: ALTER FUNCTION");
	ok(pgsql_parse_cmd("DROP FUNCTION f()") == PGSQL_QUERY_DROP_FUNCTION,
		"PgSQL cmd: DROP FUNCTION");
	ok(pgsql_parse_cmd("CREATE PROCEDURE p() LANGUAGE plpgsql") == PGSQL_QUERY_CREATE_PROCEDURE,
		"PgSQL cmd: CREATE PROCEDURE");
	ok(pgsql_parse_cmd("ALTER PROCEDURE p() OWNER TO u") == PGSQL_QUERY_ALTER_PROCEDURE,
		"PgSQL cmd: ALTER PROCEDURE");
	ok(pgsql_parse_cmd("DROP PROCEDURE p()") == PGSQL_QUERY_DROP_PROCEDURE,
		"PgSQL cmd: DROP PROCEDURE");
	ok(pgsql_parse_cmd("CALL my_procedure()") == PGSQL_QUERY_CALL,
		"PgSQL cmd: CALL");

	// AGGREGATE / OPERATOR / TYPE / DOMAIN
	ok(pgsql_parse_cmd("CREATE AGGREGATE agg(int) (sfunc=f, stype=int)") == PGSQL_QUERY_CREATE_AGGREGATE,
		"PgSQL cmd: CREATE AGGREGATE");
	ok(pgsql_parse_cmd("DROP AGGREGATE agg(int)") == PGSQL_QUERY_DROP_AGGREGATE,
		"PgSQL cmd: DROP AGGREGATE");
	ok(pgsql_parse_cmd("CREATE OPERATOR +(int,int)") == PGSQL_QUERY_CREATE_OPERATOR,
		"PgSQL cmd: CREATE OPERATOR");
	ok(pgsql_parse_cmd("DROP OPERATOR +(int,int)") == PGSQL_QUERY_DROP_OPERATOR,
		"PgSQL cmd: DROP OPERATOR");
	ok(pgsql_parse_cmd("CREATE TYPE mytype AS (x int)") == PGSQL_QUERY_CREATE_TYPE,
		"PgSQL cmd: CREATE TYPE");
	ok(pgsql_parse_cmd("DROP TYPE mytype") == PGSQL_QUERY_DROP_TYPE,
		"PgSQL cmd: DROP TYPE");
	ok(pgsql_parse_cmd("CREATE DOMAIN mydomain AS int") == PGSQL_QUERY_CREATE_DOMAIN,
		"PgSQL cmd: CREATE DOMAIN");
	ok(pgsql_parse_cmd("DROP DOMAIN mydomain") == PGSQL_QUERY_DROP_DOMAIN,
		"PgSQL cmd: DROP DOMAIN");

	// TRIGGER / RULE / EXTENSION / POLICY
	ok(pgsql_parse_cmd("CREATE TRIGGER trig AFTER INSERT ON t") == PGSQL_QUERY_CREATE_TRIGGER,
		"PgSQL cmd: CREATE TRIGGER");
	ok(pgsql_parse_cmd("DROP TRIGGER trig ON t") == PGSQL_QUERY_DROP_TRIGGER,
		"PgSQL cmd: DROP TRIGGER");
	ok(pgsql_parse_cmd("CREATE RULE r AS ON INSERT TO t DO NOTHING") == PGSQL_QUERY_CREATE_RULE,
		"PgSQL cmd: CREATE RULE");
	ok(pgsql_parse_cmd("DROP RULE r ON t") == PGSQL_QUERY_DROP_RULE,
		"PgSQL cmd: DROP RULE");
	ok(pgsql_parse_cmd("CREATE EXTENSION hstore") == PGSQL_QUERY_CREATE_EXTENSION,
		"PgSQL cmd: CREATE EXTENSION");
	ok(pgsql_parse_cmd("DROP EXTENSION hstore") == PGSQL_QUERY_DROP_EXTENSION,
		"PgSQL cmd: DROP EXTENSION");
	ok(pgsql_parse_cmd("CREATE POLICY pol ON t") == PGSQL_QUERY_CREATE_POLICY,
		"PgSQL cmd: CREATE POLICY");
	ok(pgsql_parse_cmd("DROP POLICY pol ON t") == PGSQL_QUERY_DROP_POLICY,
		"PgSQL cmd: DROP POLICY");

	// ROLE / USER
	ok(pgsql_parse_cmd("CREATE ROLE myrole") == PGSQL_QUERY_CREATE_ROLE,
		"PgSQL cmd: CREATE ROLE");
	ok(pgsql_parse_cmd("ALTER ROLE myrole LOGIN") == PGSQL_QUERY_ALTER_ROLE,
		"PgSQL cmd: ALTER ROLE");
	ok(pgsql_parse_cmd("DROP ROLE myrole") == PGSQL_QUERY_DROP_ROLE,
		"PgSQL cmd: DROP ROLE");
	ok(pgsql_parse_cmd("CREATE USER myuser") == PGSQL_QUERY_CREATE_USER,
		"PgSQL cmd: CREATE USER");
	ok(pgsql_parse_cmd("ALTER USER myuser PASSWORD 'x'") == PGSQL_QUERY_ALTER_USER,
		"PgSQL cmd: ALTER USER");
	ok(pgsql_parse_cmd("DROP USER myuser") == PGSQL_QUERY_DROP_USER,
		"PgSQL cmd: DROP USER");

	// GRANT / REVOKE
	ok(pgsql_parse_cmd("GRANT SELECT ON t TO u") == PGSQL_QUERY_GRANT,
		"PgSQL cmd: GRANT");
	ok(pgsql_parse_cmd("REVOKE SELECT ON t FROM u") == PGSQL_QUERY_REVOKE,
		"PgSQL cmd: REVOKE");

	// Transaction control
	ok(pgsql_parse_cmd("BEGIN") == PGSQL_QUERY_BEGIN,
		"PgSQL cmd: BEGIN");
	ok(pgsql_parse_cmd("START TRANSACTION") == PGSQL_QUERY_BEGIN,
		"PgSQL cmd: START TRANSACTION -> BEGIN");
	ok(pgsql_parse_cmd("COMMIT") == PGSQL_QUERY_COMMIT,
		"PgSQL cmd: COMMIT");
	ok(pgsql_parse_cmd("ROLLBACK") == PGSQL_QUERY_ROLLBACK,
		"PgSQL cmd: ROLLBACK");
	ok(pgsql_parse_cmd("ABORT") == PGSQL_QUERY_ROLLBACK,
		"PgSQL cmd: ABORT -> ROLLBACK");
	ok(pgsql_parse_cmd("SAVEPOINT sp1") == PGSQL_QUERY_SAVEPOINT,
		"PgSQL cmd: SAVEPOINT");
	ok(pgsql_parse_cmd("ROLLBACK TO SAVEPOINT sp1") == PGSQL_QUERY_ROLLBACK_TO_SAVEPOINT,
		"PgSQL cmd: ROLLBACK TO SAVEPOINT");
	ok(pgsql_parse_cmd("RELEASE SAVEPOINT sp1") == PGSQL_QUERY_RELEASE_SAVEPOINT,
		"PgSQL cmd: RELEASE SAVEPOINT");

	// Session / utility
	ok(pgsql_parse_cmd("SET search_path TO public") == PGSQL_QUERY_SET,
		"PgSQL cmd: SET");
	ok(pgsql_parse_cmd("SHOW search_path") == PGSQL_QUERY_SHOW,
		"PgSQL cmd: SHOW");
	ok(pgsql_parse_cmd("RESET search_path") == PGSQL_QUERY_RESET,
		"PgSQL cmd: RESET");
	ok(pgsql_parse_cmd("DISCARD ALL") == PGSQL_QUERY_DISCARD,
		"PgSQL cmd: DISCARD");

	// PgSQL-specific
	ok(pgsql_parse_cmd("LISTEN channel1") == PGSQL_QUERY_LISTEN,
		"PgSQL cmd: LISTEN");
	ok(pgsql_parse_cmd("UNLISTEN channel1") == PGSQL_QUERY_UNLISTEN,
		"PgSQL cmd: UNLISTEN");
	ok(pgsql_parse_cmd("NOTIFY channel1") == PGSQL_QUERY_NOTIFY,
		"PgSQL cmd: NOTIFY");
	ok(pgsql_parse_cmd("COMMENT ON TABLE t IS 'desc'") == PGSQL_QUERY_COMMENT,
		"PgSQL cmd: COMMENT");
	ok(pgsql_parse_cmd("LOCK TABLE t") == PGSQL_QUERY_LOCK,
		"PgSQL cmd: LOCK");
	ok(pgsql_parse_cmd("CHECKPOINT") == PGSQL_QUERY_CHECKPOINT,
		"PgSQL cmd: CHECKPOINT");
	ok(pgsql_parse_cmd("REINDEX TABLE t") == PGSQL_QUERY_REINDEX,
		"PgSQL cmd: REINDEX");
	ok(pgsql_parse_cmd("VACUUM t") == PGSQL_QUERY_VACUUM,
		"PgSQL cmd: VACUUM");
	ok(pgsql_parse_cmd("ANALYZE t") == PGSQL_QUERY_ANALYZE,
		"PgSQL cmd: ANALYZE");
	ok(pgsql_parse_cmd("EXPLAIN SELECT 1") == PGSQL_QUERY_EXPLAIN,
		"PgSQL cmd: EXPLAIN");
	ok(pgsql_parse_cmd("EXECUTE stmt1") == PGSQL_QUERY_EXECUTE,
		"PgSQL cmd: EXECUTE");
	ok(pgsql_parse_cmd("PREPARE stmt1 AS SELECT 1") == PGSQL_QUERY_PREPARE,
		"PgSQL cmd: PREPARE");
	ok(pgsql_parse_cmd("DEALLOCATE stmt1") == PGSQL_QUERY_DEALLOCATE,
		"PgSQL cmd: DEALLOCATE");
	ok(pgsql_parse_cmd("FETCH NEXT FROM cursor1") == PGSQL_QUERY_FETCH,
		"PgSQL cmd: FETCH");
	ok(pgsql_parse_cmd("MOVE NEXT IN cursor1") == PGSQL_QUERY_MOVE,
		"PgSQL cmd: MOVE");
	ok(pgsql_parse_cmd("CLUSTER t") == PGSQL_QUERY_CLUSTER,
		"PgSQL cmd: CLUSTER");

	// DATABASE
	ok(pgsql_parse_cmd("CREATE DATABASE mydb") == PGSQL_QUERY_CREATE_DATABASE,
		"PgSQL cmd: CREATE DATABASE");
	ok(pgsql_parse_cmd("ALTER DATABASE mydb SET x=1") == PGSQL_QUERY_ALTER_DATABASE,
		"PgSQL cmd: ALTER DATABASE");
	ok(pgsql_parse_cmd("DROP DATABASE mydb") == PGSQL_QUERY_DROP_DATABASE,
		"PgSQL cmd: DROP DATABASE");

	// COLLATION
	ok(pgsql_parse_cmd("CREATE COLLATION mycoll (locale='en_US.utf8')") == PGSQL_QUERY_CREATE_COLLATION,
		"PgSQL cmd: CREATE COLLATION");
	ok(pgsql_parse_cmd("DROP COLLATION mycoll") == PGSQL_QUERY_DROP_COLLATION,
		"PgSQL cmd: DROP COLLATION");

	// TEXT SEARCH objects
	ok(pgsql_parse_cmd("CREATE TEXT SEARCH CONFIGURATION tsc (parser=p)") == PGSQL_QUERY_CREATE_TEXT_SEARCH_CONFIGURATION,
		"PgSQL cmd: CREATE TEXT SEARCH CONFIGURATION");
	ok(pgsql_parse_cmd("CREATE TEXT SEARCH DICTIONARY tsd (template=t)") == PGSQL_QUERY_CREATE_TEXT_SEARCH_DICTIONARY,
		"PgSQL cmd: CREATE TEXT SEARCH DICTIONARY");
	ok(pgsql_parse_cmd("CREATE TEXT SEARCH TEMPLATE tst (init=f)") == PGSQL_QUERY_CREATE_TEXT_SEARCH_TEMPLATE,
		"PgSQL cmd: CREATE TEXT SEARCH TEMPLATE");
	ok(pgsql_parse_cmd("CREATE TEXT SEARCH PARSER tsp (start=f)") == PGSQL_QUERY_CREATE_TEXT_SEARCH_PARSER,
		"PgSQL cmd: CREATE TEXT SEARCH PARSER");
	ok(pgsql_parse_cmd("DROP TEXT SEARCH CONFIGURATION tsc") == PGSQL_QUERY_DROP_TEXT_SEARCH_CONFIGURATION,
		"PgSQL cmd: DROP TEXT SEARCH CONFIGURATION");
	ok(pgsql_parse_cmd("DROP TEXT SEARCH DICTIONARY tsd") == PGSQL_QUERY_DROP_TEXT_SEARCH_DICTIONARY,
		"PgSQL cmd: DROP TEXT SEARCH DICTIONARY");

	// FOREIGN TABLE / SERVER / USER MAPPING
	ok(pgsql_parse_cmd("CREATE FOREIGN TABLE ft (id int) SERVER srv") == PGSQL_QUERY_CREATE_FOREIGN_TABLE,
		"PgSQL cmd: CREATE FOREIGN TABLE");
	ok(pgsql_parse_cmd("DROP FOREIGN TABLE ft") == PGSQL_QUERY_DROP_FOREIGN_TABLE,
		"PgSQL cmd: DROP FOREIGN TABLE");
	ok(pgsql_parse_cmd("CREATE SERVER srv FOREIGN DATA WRAPPER fdw") == PGSQL_QUERY_CREATE_SERVER,
		"PgSQL cmd: CREATE SERVER");
	ok(pgsql_parse_cmd("DROP SERVER srv") == PGSQL_QUERY_DROP_SERVER,
		"PgSQL cmd: DROP SERVER");
	ok(pgsql_parse_cmd("IMPORT FOREIGN SCHEMA public FROM SERVER srv INTO local") == PGSQL_QUERY_IMPORT_FOREIGN_SCHEMA,
		"PgSQL cmd: IMPORT FOREIGN SCHEMA");

	// PUBLICATION / SUBSCRIPTION
	ok(pgsql_parse_cmd("CREATE PUBLICATION pub FOR ALL TABLES") == PGSQL_QUERY_CREATE_PUBLICATION,
		"PgSQL cmd: CREATE PUBLICATION");
	ok(pgsql_parse_cmd("DROP PUBLICATION pub") == PGSQL_QUERY_DROP_PUBLICATION,
		"PgSQL cmd: DROP PUBLICATION");
	ok(pgsql_parse_cmd("CREATE SUBSCRIPTION sub CONNECTION '' PUBLICATION pub") == PGSQL_QUERY_CREATE_SUBSCRIPTION,
		"PgSQL cmd: CREATE SUBSCRIPTION");
	ok(pgsql_parse_cmd("DROP SUBSCRIPTION sub") == PGSQL_QUERY_DROP_SUBSCRIPTION,
		"PgSQL cmd: DROP SUBSCRIPTION");

	// EVENT TRIGGER / TRANSFORM / CAST
	ok(pgsql_parse_cmd("CREATE EVENT TRIGGER et ON ddl_command_start") == PGSQL_QUERY_CREATE_EVENT_TRIGGER,
		"PgSQL cmd: CREATE EVENT TRIGGER");
	ok(pgsql_parse_cmd("DROP EVENT TRIGGER et") == PGSQL_QUERY_DROP_EVENT_TRIGGER,
		"PgSQL cmd: DROP EVENT TRIGGER");
	ok(pgsql_parse_cmd("CREATE TRANSFORM FOR mytype LANGUAGE plpgsql") == PGSQL_QUERY_CREATE_TRANSFORM,
		"PgSQL cmd: CREATE TRANSFORM");
	ok(pgsql_parse_cmd("DROP TRANSFORM FOR mytype LANGUAGE plpgsql") == PGSQL_QUERY_DROP_TRANSFORM,
		"PgSQL cmd: DROP TRANSFORM");
	ok(pgsql_parse_cmd("CREATE CAST (int AS text) WITH FUNCTION f") == PGSQL_QUERY_CREATE_CAST,
		"PgSQL cmd: CREATE CAST");
	ok(pgsql_parse_cmd("DROP CAST (int AS text)") == PGSQL_QUERY_DROP_CAST,
		"PgSQL cmd: DROP CAST");

	// OPERATOR CLASS / FAMILY — Note: the parser's else-if chain matches
	// "OPERATOR" before reaching the "OPERATOR CLASS/FAMILY" branches,
	// so all OPERATOR variants return the base OPERATOR command type.
	ok(pgsql_parse_cmd("ALTER OPERATOR CLASS oc USING btree RENAME") == PGSQL_QUERY_ALTER_OPERATOR,
		"PgSQL cmd: ALTER OPERATOR CLASS returns ALTER_OPERATOR");
	ok(pgsql_parse_cmd("ALTER OPERATOR FAMILY ofam USING btree ADD") == PGSQL_QUERY_ALTER_OPERATOR,
		"PgSQL cmd: ALTER OPERATOR FAMILY returns ALTER_OPERATOR");
	ok(pgsql_parse_cmd("CREATE OPERATOR CLASS oc FOR TYPE int") == PGSQL_QUERY_CREATE_OPERATOR,
		"PgSQL cmd: CREATE OPERATOR CLASS returns CREATE_OPERATOR");
	ok(pgsql_parse_cmd("DROP OPERATOR CLASS oc USING btree") == PGSQL_QUERY_DROP_OPERATOR,
		"PgSQL cmd: DROP OPERATOR CLASS returns DROP_OPERATOR");

	// TABLESPACE
	ok(pgsql_parse_cmd("CREATE TABLESPACE ts LOCATION '/data'") == PGSQL_QUERY_CREATE_TABLESPACE,
		"PgSQL cmd: CREATE TABLESPACE");
	ok(pgsql_parse_cmd("DROP TABLESPACE ts") == PGSQL_QUERY_DROP_TABLESPACE,
		"PgSQL cmd: DROP TABLESPACE");

	// ACCESS METHOD
	ok(pgsql_parse_cmd("CREATE ACCESS METHOD am TYPE INDEX HANDLER f") == PGSQL_QUERY_CREATE_ACCESS_METHOD,
		"PgSQL cmd: CREATE ACCESS METHOD");
	ok(pgsql_parse_cmd("DROP ACCESS METHOD am") == PGSQL_QUERY_DROP_ACCESS_METHOD,
		"PgSQL cmd: DROP ACCESS METHOD");

	// pg_cancel_backend / pg_terminate_backend
	ok(pgsql_parse_cmd("SELECT pg_cancel_backend(1234)") == PGSQL_QUERY_CANCEL_BACKEND,
		"PgSQL cmd: SELECT pg_cancel_backend");
	ok(pgsql_parse_cmd("SELECT pg_terminate_backend(1234)") == PGSQL_QUERY_TERMINATE_BACKEND,
		"PgSQL cmd: SELECT pg_terminate_backend");

	// DECLARE CURSOR / CLOSE CURSOR
	ok(pgsql_parse_cmd("DECLARE CURSOR c FOR SELECT 1") == PGSQL_QUERY_DECLARE_CURSOR,
		"PgSQL cmd: DECLARE CURSOR");

	// Edge case: parenthesized subquery
	ok(pgsql_parse_cmd("(SELECT 1)") == PGSQL_QUERY_SELECT,
		"PgSQL cmd: (SELECT 1) parses as SELECT");

	// Unknown command
	ok(pgsql_parse_cmd("XYZZY") == PGSQL_QUERY_UNKNOWN,
		"PgSQL cmd: unknown command returns PGSQL_QUERY_UNKNOWN");

	// Case insensitivity
	ok(pgsql_parse_cmd("select 1") == PGSQL_QUERY_SELECT,
		"PgSQL cmd: lowercase 'select' recognized");
	ok(pgsql_parse_cmd("Vacuum t") == PGSQL_QUERY_VACUUM,
		"PgSQL cmd: mixed case 'Vacuum' recognized");
}

// ============================================================================
// 19. PgSQL: Fast routing hashmap
// ============================================================================

/**
 * @brief Test PgSQL fast routing hashmap creation and lookup.
 */
static void test_pgsql_fast_routing() {
	GloPgQPro->reset_all(true);

	// Build a resultset with 4 columns: username, schemaname, flagIN, dest_hg
	SQLite3_result *fr_resultset = new SQLite3_result(4);
	fr_resultset->add_column_definition(SQLITE_TEXT, "username");
	fr_resultset->add_column_definition(SQLITE_TEXT, "schemaname");
	fr_resultset->add_column_definition(SQLITE_TEXT, "flagIN");
	fr_resultset->add_column_definition(SQLITE_TEXT, "destination_hostgroup");
	{
		char *row1[] = { (char*)"user1", (char*)"db1", (char*)"0", (char*)"10" };
		fr_resultset->add_row(row1);
		char *row2[] = { (char*)"user2", (char*)"db2", (char*)"0", (char*)"20" };
		fr_resultset->add_row(row2);
		char *row3[] = { (char*)"user1", (char*)"db1", (char*)"1", (char*)"30" };
		fr_resultset->add_row(row3);
	}

	fast_routing_hashmap_t hm = GloPgQPro->create_fast_routing_hashmap(fr_resultset);
	ok(hm.rules_fast_routing != nullptr,
		"PgSQL QP: fast routing hashmap created successfully");

	GloPgQPro->wrlock();
	SQLite3_result *old = GloPgQPro->load_fast_routing(hm);
	GloPgQPro->wrunlock();

	// Test lookups
	int hg = GloPgQPro->testing___find_HG_in_mysql_query_rules_fast_routing(
		(char*)"user1", (char*)"db1", 0);
	ok(hg == 10, "PgSQL QP: fast routing finds user1/db1/flagIN=0 -> HG 10");

	hg = GloPgQPro->testing___find_HG_in_mysql_query_rules_fast_routing(
		(char*)"user2", (char*)"db2", 0);
	ok(hg == 20, "PgSQL QP: fast routing finds user2/db2/flagIN=0 -> HG 20");

	hg = GloPgQPro->testing___find_HG_in_mysql_query_rules_fast_routing(
		(char*)"user1", (char*)"db1", 1);
	ok(hg == 30, "PgSQL QP: fast routing finds user1/db1/flagIN=1 -> HG 30");

	// Miss
	hg = GloPgQPro->testing___find_HG_in_mysql_query_rules_fast_routing(
		(char*)"nouser", (char*)"nodb", 0);
	ok(hg == -1, "PgSQL QP: fast routing returns -1 for missing entry");

	// Verify count
	int count = GloPgQPro->get_current_query_rules_fast_routing_count();
	ok(count == 3, "PgSQL QP: fast routing count is 3");

	if (old) {
		delete old;
	}
}

// ============================================================================
// 20. PgSQL: Firewall whitelist
// ============================================================================

/**
 * @brief Test PgSQL firewall whitelist user/rule loading and lookup.
 */
static void test_pgsql_firewall_whitelist() {
	// Build user resultset: active, username, client_address, mode
	SQLite3_result *users = new SQLite3_result(4);
	users->add_column_definition(SQLITE_TEXT, "active");
	users->add_column_definition(SQLITE_TEXT, "username");
	users->add_column_definition(SQLITE_TEXT, "client_address");
	users->add_column_definition(SQLITE_TEXT, "mode");
	{
		char *row1[] = { (char*)"1", (char*)"pguser", (char*)"10.0.0.1", (char*)"PROTECTING" };
		users->add_row(row1);
		char *row2[] = { (char*)"1", (char*)"pgadmin", (char*)"10.0.0.2", (char*)"DETECTING" };
		users->add_row(row2);
		char *row3[] = { (char*)"0", (char*)"inactive", (char*)"10.0.0.3", (char*)"PROTECTING" };
		users->add_row(row3);
	}

	// Build rules resultset: active, username, client_address, schemaname, flagIN, digest
	SQLite3_result *rules = new SQLite3_result(6);
	rules->add_column_definition(SQLITE_TEXT, "active");
	rules->add_column_definition(SQLITE_TEXT, "username");
	rules->add_column_definition(SQLITE_TEXT, "client_address");
	rules->add_column_definition(SQLITE_TEXT, "schemaname");
	rules->add_column_definition(SQLITE_TEXT, "flagIN");
	rules->add_column_definition(SQLITE_TEXT, "digest");
	{
		char *row1[] = { (char*)"1", (char*)"pguser", (char*)"10.0.0.1", (char*)"public", (char*)"0", (char*)"0xABCD" };
		rules->add_row(row1);
	}

	// Empty sqli fingerprints
	SQLite3_result *sqli = new SQLite3_result(1);
	sqli->add_column_definition(SQLITE_TEXT, "fingerprint");

	GloPgQPro->load_firewall(users, rules, sqli);

	// Test user lookup
	int mode = GloPgQPro->find_firewall_whitelist_user((char*)"pguser", (char*)"10.0.0.1");
	ok(mode == WUS_PROTECTING,
		"PgSQL QP: firewall user pguser/10.0.0.1 found in PROTECTING mode");

	mode = GloPgQPro->find_firewall_whitelist_user((char*)"pgadmin", (char*)"10.0.0.2");
	ok(mode == WUS_DETECTING,
		"PgSQL QP: firewall user pgadmin/10.0.0.2 found in DETECTING mode");

	mode = GloPgQPro->find_firewall_whitelist_user((char*)"unknown", (char*)"10.0.0.99");
	ok(mode == WUS_NOT_FOUND,
		"PgSQL QP: firewall returns NOT_FOUND for unknown user");

	// Test rule lookup
	bool found = GloPgQPro->find_firewall_whitelist_rule(
		(char*)"pguser", (char*)"10.0.0.1", (char*)"public", 0, 0xABCD);
	ok(found == true,
		"PgSQL QP: firewall rule found for matching digest");

	found = GloPgQPro->find_firewall_whitelist_rule(
		(char*)"pguser", (char*)"10.0.0.1", (char*)"public", 0, 0x9999);
	ok(found == false,
		"PgSQL QP: firewall rule not found for non-matching digest");

	// Verify memory tracking
	unsigned long long mem_users = GloPgQPro->get_firewall_memory_users_table();
	ok(mem_users > 0, "PgSQL QP: firewall users memory tracked (> 0)");
	unsigned long long mem_rules = GloPgQPro->get_firewall_memory_rules_table();
	ok(mem_rules > 0, "PgSQL QP: firewall rules memory tracked (> 0)");
}

// ============================================================================
// 21. PgSQL: Query digests
// ============================================================================

/**
 * @brief Test PgSQL query digest operations.
 */
static void test_pgsql_query_digests() {
	// get_query_digests on empty state should return valid result
	SQLite3_result *result = GloPgQPro->get_query_digests();
	ok(result != nullptr, "PgSQL QP: get_query_digests returns non-null on empty state");
	if (result) {
		ok(result->rows_count == 0,
			"PgSQL QP: get_query_digests has 0 rows on empty state");
		delete result;
	} else {
		ok(0, "PgSQL QP: get_query_digests has 0 rows (skipped)");
	}

	// Test digest total size
	unsigned long long digest_size = GloPgQPro->get_query_digests_total_size();
	ok(digest_size == 0,
		"PgSQL QP: digest total size is 0 on empty state");

	// Test purge on empty state
	unsigned long long purged = GloPgQPro->purge_query_digests(false, false);
	ok(purged == 0, "PgSQL QP: purge_query_digests returns 0 on empty state");
}

// ============================================================================
// 22. PgSQL: Memory usage tracking
// ============================================================================

/**
 * @brief Test PgSQL memory usage tracking for rules.
 */
static void test_pgsql_memory_tracking() {
	GloPgQPro->reset_all(true);

	unsigned long long mem_empty = GloPgQPro->get_rules_mem_used();

	// Insert several rules
	for (int i = 1; i <= 5; i++) {
		auto *r = pgsql_simple_rule(i * 10, true, "^SELECT.*", i, true);
		GloPgQPro->insert((QP_rule_t *)r);
	}
	GloPgQPro->sort();
	GloPgQPro->commit();

	unsigned long long mem_with_rules = GloPgQPro->get_rules_mem_used();
	ok(mem_with_rules >= mem_empty,
		"PgSQL QP: rules memory usage increases after inserting rules");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(259);

	test_init_minimal();
	test_init_query_processor();

	// MySQL tests
	test_mysql_rule_creation();              // 18 tests
	test_mysql_insert_and_retrieve();        // 2 tests
	test_mysql_rule_sorting();               // 4 tests
	test_regex_modifiers();                  // 5 tests
	test_mysql_rule_special_fields();        // 3 tests
	test_mysql_flag_chaining();              // 1 test
	test_mysql_rule_with_username();         // 1 test
	test_mysql_reset_all();                  // 1 test
	test_mysql_stats_counters();             // 2 tests

	// PgSQL tests — existing
	test_pgsql_rule_creation_and_insert();   // 4 tests
	test_pgsql_reset_and_stats();            // 1 test

	// PgSQL tests — new
	test_pgsql_rule_creation_all_fields();   // 36 tests
	test_pgsql_client_addr_wildcard();       // 4 tests
	test_pgsql_rule_attributes_flagouts();   // 7 tests
	test_pgsql_stats_commands_counters();    // 4 tests
	test_pgsql_stats_query_rules();          // 3 tests
	test_pgsql_get_current_query_rules_columns(); // 14 tests
	test_pgsql_rule_sorting();               // 4 tests
	test_pgsql_flag_chaining();              // 1 test
	test_pgsql_query_parser_command_type();  // 126 tests (bulk coverage of switch)
	test_pgsql_fast_routing();               // 6 tests
	test_pgsql_firewall_whitelist();         // 7 tests
	test_pgsql_query_digests();              // 4 tests
	test_pgsql_memory_tracking();            // 1 test

	test_cleanup_query_processor();
	test_cleanup_minimal();

	return exit_status();
}
