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
#include "query_processor.h"
#include "QP_rule_text.h"

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

/**
 * @brief Create a bare query rule for rule_matches_query() predicate tests.
 */
static QP_rule_t simple_match_rule() {
	QP_rule_t rule {};
	rule.username = nullptr;
	rule.schemaname = nullptr;
	rule.client_addr = nullptr;
	rule.client_addr_wildcard_position = -1;
	rule.proxy_addr = nullptr;
	rule.flagIN = 0;
	rule.proxy_port = -1;
	rule.digest = 0;
	rule.match_digest = nullptr;
	rule.match_pattern = nullptr;
	rule.negate_match_pattern = false;
	rule.re_modifiers = 0;
	return rule;
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
		if (result) delete result;
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
	if (result) delete result;
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
	if (result) delete result;
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
	if (result) delete result;
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
	if (result) delete result;
}

/**
 * @brief Test PgSQL reset and stats.
 */
static void test_pgsql_reset_and_stats() {
	GloPgQPro->reset_all(true);
	SQLite3_result *result = GloPgQPro->get_current_query_rules();
	ok(result != nullptr && result->rows_count == 0,
		"PgSQL QP: no rules after reset_all()");
	if (result) delete result;
}

// ============================================================================
// 10. Extracted rule_matches_query() predicate
// ============================================================================

/**
 * @brief Test the extracted query rule matching predicate in isolation.
 */
static void test_rule_matches_query_predicate() {
	QP_rule_t username_rule = simple_match_rule();
	username_rule.username = const_cast<char *>("appuser");
	ok(
		rule_matches_query(&username_rule, 0, "appuser", "db1", "192.168.1.44", "127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"rule_matches_query(): username matches exactly"
	);

	QP_rule_t match_all_rule = simple_match_rule();
	ok(
		rule_matches_query(&match_all_rule, 0, "anyuser", "anydb", "10.0.0.1", "127.0.0.1", 6033, 42, "digest", "SELECT 1", nullptr, 2),
		"rule_matches_query(): rule with no criteria matches everything"
	);

	QP_rule_t schema_rule = simple_match_rule();
	schema_rule.schemaname = const_cast<char *>("analytics");
	ok(
		rule_matches_query(&schema_rule, 0, "appuser", "analytics", "10.0.0.1", "127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"rule_matches_query(): schemaname matches exactly"
	);

	QP_rule_t client_addr_rule = simple_match_rule();
	client_addr_rule.client_addr = const_cast<char *>("192.168.%");
	const char *client_addr_wildcard = std::strchr(client_addr_rule.client_addr, '%');
	ok(client_addr_wildcard != nullptr,
		"rule_matches_query(): client_addr test pattern contains wildcard");
	client_addr_rule.client_addr_wildcard_position =
		client_addr_wildcard - client_addr_rule.client_addr;
	ok(
		rule_matches_query(&client_addr_rule, 0, "appuser", "db1", "192.168.55.19", "127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"rule_matches_query(): client_addr wildcard matches"
	);

	QP_rule_t proxy_rule = simple_match_rule();
	proxy_rule.proxy_addr = const_cast<char *>("10.0.0.5");
	proxy_rule.proxy_port = 6033;
	ok(
		rule_matches_query(&proxy_rule, 0, "appuser", "db1", "192.168.1.1", "10.0.0.5", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"rule_matches_query(): proxy_addr and proxy_port both match"
	);

	QP_rule_t digest_rule = simple_match_rule();
	digest_rule.digest = 123456789ULL;
	ok(
		rule_matches_query(&digest_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033, 123456789ULL, nullptr, "SELECT 1", nullptr, 2),
		"rule_matches_query(): digest matches"
	);

	QP_rule_t match_digest_re2_rule = simple_match_rule();
	match_digest_re2_rule.match_digest = const_cast<char *>("^SELECT .* FROM users$");
	ok(
		rule_matches_query(
			&match_digest_re2_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, "SELECT name FROM users", "SELECT name FROM users WHERE id=1", nullptr, 2
		),
		"rule_matches_query(): match_digest regex matches with RE2"
	);

	QP_rule_t match_digest_pcre_rule = simple_match_rule();
	match_digest_pcre_rule.match_digest = const_cast<char *>("^SELECT .* FROM users$");
	ok(
		rule_matches_query(
			&match_digest_pcre_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, "SELECT email FROM users", "SELECT email FROM users WHERE id=1", nullptr, 1
		),
		"rule_matches_query(): match_digest regex matches with PCRE"
	);

	QP_rule_t match_pattern_rule = simple_match_rule();
	match_pattern_rule.match_pattern = const_cast<char *>("SELECT .* FROM orders");
	ok(
		rule_matches_query(
			&match_pattern_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, nullptr, "SELECT id FROM orders WHERE id=10", nullptr, 2
		),
		"rule_matches_query(): match_pattern regex matches query text"
	);

	QP_rule_t negate_pattern_rule = simple_match_rule();
	negate_pattern_rule.match_pattern = const_cast<char *>("DELETE");
	negate_pattern_rule.negate_match_pattern = true;
	ok(
		rule_matches_query(
			&negate_pattern_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, nullptr, "SELECT 1", nullptr, 2
		),
		"rule_matches_query(): negate_match_pattern inverts match_pattern result"
	);

	QP_rule_t flag_rule = simple_match_rule();
	flag_rule.flagIN = 3;
	ok(
		rule_matches_query(&flag_rule, 3, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"rule_matches_query(): flagIN must match current flag"
	);

	QP_rule_t combined_rule = simple_match_rule();
	combined_rule.username = const_cast<char *>("appuser");
	combined_rule.schemaname = const_cast<char *>("analytics");
	combined_rule.proxy_addr = const_cast<char *>("10.0.0.9");
	combined_rule.proxy_port = 6033;
	combined_rule.match_pattern = const_cast<char *>("SELECT");
	ok(
		rule_matches_query(
			&combined_rule, 0, "appuser", "analytics", "10.0.0.1", "10.0.0.9", 6033,
			0, nullptr, "SELECT 1", nullptr, 2
		),
		"rule_matches_query(): multiple criteria use AND logic"
	);

	QP_rule_t caseless_rule = simple_match_rule();
	caseless_rule.match_pattern = const_cast<char *>("select .* from inventory");
	caseless_rule.re_modifiers = QP_RE_MOD_CASELESS;
	ok(
		rule_matches_query(
			&caseless_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, nullptr, "SELECT SKU FROM INVENTORY", nullptr, 2
		),
		"rule_matches_query(): CASELESS modifier makes regex matching case-insensitive"
	);

	QP_rule_t rewritten_query_rule = simple_match_rule();
	rewritten_query_rule.match_pattern = const_cast<char *>("SELECT .* FROM rewritten_table");
	ok(
		rule_matches_query(
			&rewritten_query_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, nullptr, "SELECT * FROM original_table", "SELECT * FROM rewritten_table", 2
		),
		"rule_matches_query(): rewritten query is used for match_pattern when present"
	);
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(57);

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

	// PgSQL tests
	test_pgsql_rule_creation_and_insert();   // 4 tests
	test_pgsql_reset_and_stats();            // 1 test
	test_rule_matches_query_predicate();     // 15 tests

	test_cleanup_query_processor();
	test_cleanup_minimal();

	return exit_status();
}
