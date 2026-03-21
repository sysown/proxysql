/**
 * @file test_rule_matches_query-t.cpp
 * @brief TAP unit tests for extracted query rule matching logic.
 */

#include <cstring>

#include "tap.h"
#include "query_processor.h"
#include "QP_rule_text.h"

static QP_rule_t make_rule() {
	QP_rule_t rule {};
	rule.flagIN = 0;
	rule.proxy_port = -1;
	return rule;
}

int main() {
	plan(14);

	QP_rule_t username_rule = make_rule();
	username_rule.username = const_cast<char *>("appuser");
	ok(
		rule_matches_query(&username_rule, 0, "appuser", "db1", "192.168.1.44", "127.0.0.1", 6033, 0, NULL, "SELECT 1", NULL, 2),
		"username matches exactly"
	);

	QP_rule_t match_all_rule = make_rule();
	ok(
		rule_matches_query(&match_all_rule, 0, "anyuser", "anydb", "10.0.0.1", "127.0.0.1", 6033, 42, "digest", "SELECT 1", NULL, 2),
		"rule with no criteria matches everything"
	);

	QP_rule_t schema_rule = make_rule();
	schema_rule.schemaname = const_cast<char *>("analytics");
	ok(
		rule_matches_query(&schema_rule, 0, "appuser", "analytics", "10.0.0.1", "127.0.0.1", 6033, 0, NULL, "SELECT 1", NULL, 2),
		"schemaname matches exactly"
	);

	QP_rule_t client_addr_rule = make_rule();
	client_addr_rule.client_addr = const_cast<char *>("192.168.%");
	client_addr_rule.client_addr_wildcard_position = std::strlen(client_addr_rule.client_addr) - 1;
	ok(
		rule_matches_query(&client_addr_rule, 0, "appuser", "db1", "192.168.55.19", "127.0.0.1", 6033, 0, NULL, "SELECT 1", NULL, 2),
		"client_addr wildcard matches"
	);

	QP_rule_t proxy_rule = make_rule();
	proxy_rule.proxy_addr = const_cast<char *>("10.0.0.5");
	proxy_rule.proxy_port = 6033;
	ok(
		rule_matches_query(&proxy_rule, 0, "appuser", "db1", "192.168.1.1", "10.0.0.5", 6033, 0, NULL, "SELECT 1", NULL, 2),
		"proxy_addr and proxy_port both match"
	);

	QP_rule_t digest_rule = make_rule();
	digest_rule.digest = 123456789ULL;
	ok(
		rule_matches_query(&digest_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033, 123456789ULL, NULL, "SELECT 1", NULL, 2),
		"digest matches"
	);

	QP_rule_t match_digest_re2_rule = make_rule();
	match_digest_re2_rule.match_digest = const_cast<char *>("^SELECT .* FROM users$");
	ok(
		rule_matches_query(
			&match_digest_re2_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, "SELECT name FROM users", "SELECT name FROM users WHERE id=1", NULL, 2
		),
		"match_digest regex matches with RE2"
	);

	QP_rule_t match_digest_pcre_rule = make_rule();
	match_digest_pcre_rule.match_digest = const_cast<char *>("^SELECT .* FROM users$");
	ok(
		rule_matches_query(
			&match_digest_pcre_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, "SELECT email FROM users", "SELECT email FROM users WHERE id=1", NULL, 1
		),
		"match_digest regex matches with PCRE"
	);

	QP_rule_t match_pattern_rule = make_rule();
	match_pattern_rule.match_pattern = const_cast<char *>("SELECT .* FROM orders");
	ok(
		rule_matches_query(
			&match_pattern_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, NULL, "SELECT id FROM orders WHERE id=10", NULL, 2
		),
		"match_pattern regex matches query text"
	);

	QP_rule_t negate_pattern_rule = make_rule();
	negate_pattern_rule.match_pattern = const_cast<char *>("DELETE");
	negate_pattern_rule.negate_match_pattern = true;
	ok(
		rule_matches_query(
			&negate_pattern_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, NULL, "SELECT 1", NULL, 2
		),
		"negate_match_pattern inverts match_pattern result"
	);

	QP_rule_t flag_rule = make_rule();
	flag_rule.flagIN = 3;
	ok(
		rule_matches_query(&flag_rule, 3, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033, 0, NULL, "SELECT 1", NULL, 2),
		"flagIN must match current flag"
	);

	QP_rule_t combined_rule = make_rule();
	combined_rule.username = const_cast<char *>("appuser");
	combined_rule.schemaname = const_cast<char *>("analytics");
	combined_rule.proxy_addr = const_cast<char *>("10.0.0.9");
	combined_rule.proxy_port = 6033;
	combined_rule.match_pattern = const_cast<char *>("SELECT");
	ok(
		rule_matches_query(
			&combined_rule, 0, "appuser", "analytics", "10.0.0.1", "10.0.0.9", 6033,
			0, NULL, "SELECT 1", NULL, 2
		),
		"multiple criteria use AND logic"
	);

	QP_rule_t caseless_rule = make_rule();
	caseless_rule.match_pattern = const_cast<char *>("select .* from inventory");
	caseless_rule.re_modifiers = QP_RE_MOD_CASELESS;
	ok(
		rule_matches_query(
			&caseless_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, NULL, "SELECT SKU FROM INVENTORY", NULL, 2
		),
		"CASELESS modifier makes regex matching case-insensitive"
	);

	QP_rule_t rewritten_query_rule = make_rule();
	rewritten_query_rule.match_pattern = const_cast<char *>("SELECT .* FROM rewritten_table");
	ok(
		rule_matches_query(
			&rewritten_query_rule, 0, "appuser", "db1", "10.0.0.1", "127.0.0.1", 6033,
			0, NULL, "SELECT * FROM original_table", "SELECT * FROM rewritten_table", 2
		),
		"rewritten query is used for match_pattern when present"
	);

	return exit_status();
}
