/**
 * @file rule_matching_unit-t.cpp
 * @brief Unit tests for the extracted rule_matches_query() function.
 *
 * Tests the query rule matching predicate extracted from process_query()
 * in lib/Query_Processor.cpp. The function takes all inputs as parameters
 * (no session dependency) and supports both RE2 and PCRE regex engines.
 *
 * @see Phase 3.2 (GitHub issue #5490)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "query_processor.h"
#include "QP_rule_text.h"

#include <cstring>

#ifdef DEBUG
// Debug-only seam implemented in Query_Processor.cpp. It keeps the adapter and
// all PCRE2 types private while exercising the real substitution path.
extern bool pcre2_query_rule_replace_for_test(
	const char* pattern,
	const char* subject,
	const char* legacy_rewrite,
	bool global,
	std::string* rewritten
);
#endif

/**
 * @brief Create a zeroed QP_rule_t with safe defaults.
 */
static QP_rule_t make_rule() {
	QP_rule_t rule {};
	rule.flagIN = 0;
	rule.proxy_port = -1;
	qp_addr_predicate_init(&rule.client_addr_pred, NULL, QP_ADDR_FIELD_CLIENT);
	qp_addr_predicate_init(&rule.proxy_addr_pred, NULL, QP_ADDR_FIELD_PROXY);
	return rule;
}

/**
 * @brief Build a sockaddr from a literal address, for the CIDR criteria.
 *
 * Deliberately not an ok() assertion: the addresses are fixed literals in this
 * file, so a bad one is a bug in the test rather than a finding, and keeping
 * it out of the assertion stream keeps plan() equal to the ok() call count.
 */
static struct sockaddr_storage make_sa(const char *addr) {
	struct sockaddr_storage ss {};
	memset(&ss, 0, sizeof(ss));
	int rc;
	if (strchr(addr, ':') != NULL) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		sin6->sin6_family = AF_INET6;
		rc = inet_pton(AF_INET6, addr, &sin6->sin6_addr);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		rc = inet_pton(AF_INET, addr, &sin->sin_addr);
	}
	if (rc != 1) {
		fprintf(stderr, "Bail out! test fixture address is not a valid literal: %s\n", addr);
		exit(1);
	}
	return ss;
}

/**
 * @brief Run the address criteria of @p r against a client address.
 *
 * @param client_addr The address as ProxySQL renders it, via inet_ntop().
 * @param client_sa   The same address in parsed form, or NULL to omit it.
 */
static bool match_client_addr(const QP_rule_t *r, const char *client_addr,
	const struct sockaddr *client_sa) {
	return rule_matches_query(r, 0, "u", "d", client_addr, client_sa,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2);
}

// ============================================================================
// 1. Basic matching criteria
// ============================================================================

static void test_match_all() {
	QP_rule_t r = make_rule();
	ok(rule_matches_query(&r, 0, "anyuser", "anydb", "10.0.0.1",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 42, "digest", "SELECT 1", nullptr, 2),
		"rule with no criteria matches everything");
}

static void test_flagIN() {
	QP_rule_t r = make_rule();
	r.flagIN = 3;
	ok(rule_matches_query(&r, 3, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"flagIN=3 matches current_flagIN=3");
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"flagIN=3 does not match current_flagIN=0");
}

static void test_username() {
	QP_rule_t r = make_rule();
	r.username = const_cast<char *>("appuser");
	ok(rule_matches_query(&r, 0, "appuser", "db", "10.0.0.1",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"username matches exactly");
	ok(!rule_matches_query(&r, 0, "other", "db", "10.0.0.1",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"username mismatch rejects");
	ok(!rule_matches_query(&r, 0, nullptr, "db", "10.0.0.1",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"username rule rejects null session username");
}

static void test_schemaname() {
	QP_rule_t r = make_rule();
	r.schemaname = const_cast<char *>("analytics");
	ok(rule_matches_query(&r, 0, "u", "analytics", "10.0.0.1",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"schemaname matches");
	ok(!rule_matches_query(&r, 0, "u", "other_db", "10.0.0.1",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"schemaname mismatch rejects");
}

static void test_client_addr_wildcard() {
	QP_rule_t r = make_rule();
	r.client_addr = const_cast<char *>("192.168.%");
	ok(qp_addr_predicate_init(&r.client_addr_pred, r.client_addr, QP_ADDR_FIELD_CLIENT), "wildcard predicate resolves");
	ok(r.client_addr_pred.match == QP_ADDR_MATCH_WILDCARD, "trailing % selects wildcard mode");
	ok(rule_matches_query(&r, 0, "u", "d", "192.168.55.19",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"client_addr wildcard matches");
	ok(!rule_matches_query(&r, 0, "u", "d", "10.0.0.1",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"client_addr wildcard rejects non-match");
}

// ============================================================================
// 3b. client_addr as a CIDR prefix
// ============================================================================

// Acceptance criterion 1: a /20 covers exactly its own range.
static void test_cidr_ipv4_boundaries() {
	QP_rule_t r = make_rule();
	r.client_addr = const_cast<char *>("10.0.128.0/20");
	ok(qp_addr_predicate_init(&r.client_addr_pred, r.client_addr, QP_ADDR_FIELD_CLIENT), "/20 predicate resolves");
	ok(r.client_addr_pred.match == QP_ADDR_MATCH_CIDR, "'/' selects CIDR mode");
	ok(r.client_addr_pred.cidr_count == 1, "single prefix parsed");

	struct sockaddr_storage lo = make_sa("10.0.128.0");
	struct sockaddr_storage lo1 = make_sa("10.0.128.1");
	struct sockaddr_storage hi = make_sa("10.0.143.255");
	struct sockaddr_storage below = make_sa("10.0.127.255");
	struct sockaddr_storage above = make_sa("10.0.144.0");
	struct sockaddr_storage mid = make_sa("10.0.135.7");

	ok(match_client_addr(&r, "10.0.128.0", (struct sockaddr *)&lo), "10.0.128.0/20 matches first address");
	ok(match_client_addr(&r, "10.0.128.1", (struct sockaddr *)&lo1), "10.0.128.0/20 matches first host");
	ok(match_client_addr(&r, "10.0.143.255", (struct sockaddr *)&hi), "10.0.128.0/20 matches last address");
	ok(match_client_addr(&r, "10.0.135.7", (struct sockaddr *)&mid), "10.0.128.0/20 matches a middle address");
	ok(!match_client_addr(&r, "10.0.127.255", (struct sockaddr *)&below), "10.0.128.0/20 rejects one below range");
	ok(!match_client_addr(&r, "10.0.144.0", (struct sockaddr *)&above), "10.0.128.0/20 rejects one above range");
}

// Acceptance criterion 2: /0, /8 and non-byte-aligned prefix lengths.
static void test_cidr_ipv4_prefix_lengths() {
	QP_rule_t r = make_rule();
	r.client_addr = const_cast<char *>("0.0.0.0/0");
	ok(qp_addr_predicate_init(&r.client_addr_pred, r.client_addr, QP_ADDR_FIELD_CLIENT), "/0 predicate resolves");
	struct sockaddr_storage any = make_sa("203.0.113.9");
	struct sockaddr_storage lo = make_sa("0.0.0.0");
	struct sockaddr_storage bcast = make_sa("255.255.255.255");
	ok(match_client_addr(&r, "203.0.113.9", (struct sockaddr *)&any), "0.0.0.0/0 matches any IPv4 address");
	ok(match_client_addr(&r, "0.0.0.0", (struct sockaddr *)&lo), "0.0.0.0/0 matches 0.0.0.0");
	ok(match_client_addr(&r, "255.255.255.255", (struct sockaddr *)&bcast), "0.0.0.0/0 matches the broadcast address");

	// 10.0.0.0/8 leaves a partial byte, exercising the remaining-bits path.
	QP_rule_t r8 = make_rule();
	r8.client_addr = const_cast<char *>("10.0.0.0/8");
	ok(qp_addr_predicate_init(&r8.client_addr_pred, r8.client_addr, QP_ADDR_FIELD_CLIENT), "/8 predicate resolves");
	struct sockaddr_storage in8 = make_sa("10.255.255.255");
	struct sockaddr_storage out8 = make_sa("11.0.0.0");
	ok(match_client_addr(&r8, "10.255.255.255", (struct sockaddr *)&in8), "10.0.0.0/8 matches 10.255.255.255");
	ok(!match_client_addr(&r8, "11.0.0.0", (struct sockaddr *)&out8), "10.0.0.0/8 rejects 11.0.0.0");

	// 192.168.4.0/22 straddles a nibble, so it needs the partial-byte compare.
	QP_rule_t r22 = make_rule();
	r22.client_addr = const_cast<char *>("192.168.4.0/22");
	ok(qp_addr_predicate_init(&r22.client_addr_pred, r22.client_addr, QP_ADDR_FIELD_CLIENT), "/22 predicate resolves");
	struct sockaddr_storage in22 = make_sa("192.168.7.255");
	struct sockaddr_storage out22 = make_sa("192.168.8.0");
	ok(match_client_addr(&r22, "192.168.7.255", (struct sockaddr *)&in22), "192.168.4.0/22 matches 192.168.7.255");
	ok(!match_client_addr(&r22, "192.168.8.0", (struct sockaddr *)&out22), "192.168.4.0/22 rejects 192.168.8.0");

	// A /32 is an exact address; a /31 admits only the even host bit.
	QP_rule_t r32 = make_rule();
	r32.client_addr = const_cast<char *>("10.0.0.7/32");
	ok(qp_addr_predicate_init(&r32.client_addr_pred, r32.client_addr, QP_ADDR_FIELD_CLIENT), "/32 predicate resolves");
	struct sockaddr_storage exact = make_sa("10.0.0.7");
	struct sockaddr_storage near = make_sa("10.0.0.8");
	ok(match_client_addr(&r32, "10.0.0.7", (struct sockaddr *)&exact), "/32 matches its own address");
	ok(!match_client_addr(&r32, "10.0.0.8", (struct sockaddr *)&near), "/32 rejects a neighbour");

	QP_rule_t r31 = make_rule();
	r31.client_addr = const_cast<char *>("10.0.0.6/31");
	ok(qp_addr_predicate_init(&r31.client_addr_pred, r31.client_addr, QP_ADDR_FIELD_CLIENT), "/31 predicate resolves");
	struct sockaddr_storage even = make_sa("10.0.0.6");
	struct sockaddr_storage odd = make_sa("10.0.0.7");
	ok(match_client_addr(&r31, "10.0.0.6", (struct sockaddr *)&even), "/31 matches the even address");
	ok(match_client_addr(&r31, "10.0.0.7", (struct sockaddr *)&odd), "/31 matches the odd address");
	struct sockaddr_storage next = make_sa("10.0.0.8");
	ok(!match_client_addr(&r31, "10.0.0.8", (struct sockaddr *)&next), "/31 rejects the next pair");
}

// Host bits set by the operator are masked off, not treated as an error.
static void test_cidr_host_bits_are_masked() {
	QP_rule_t r = make_rule();
	r.client_addr = const_cast<char *>("10.0.128.5/20");
	ok(qp_addr_predicate_init(&r.client_addr_pred, r.client_addr, QP_ADDR_FIELD_CLIENT), "host bits still resolve");
	struct sockaddr_storage in = make_sa("10.0.130.1");
	struct sockaddr_storage out = make_sa("10.0.150.1");
	ok(match_client_addr(&r, "10.0.130.1", (struct sockaddr *)&in), "10.0.128.5/20 is treated as 10.0.128.0/20");
	ok(!match_client_addr(&r, "10.0.150.1", (struct sockaddr *)&out), "masked /20 rejects outside its range");
}

// Acceptance criterion 3: an IPv6 prefix is compared numerically, so the
// spelling of the client address (:: compression or expanded) is irrelevant.
static void test_cidr_ipv6() {
	QP_rule_t r = make_rule();
	r.client_addr = const_cast<char *>("2001:db8::/32");
	ok(qp_addr_predicate_init(&r.client_addr_pred, r.client_addr, QP_ADDR_FIELD_CLIENT), "IPv6 /32 predicate resolves");
	ok(r.client_addr_pred.match == QP_ADDR_MATCH_CIDR, "IPv6 prefix selects CIDR mode");

	struct sockaddr_storage compressed = make_sa("2001:db8::1");
	struct sockaddr_storage expanded = make_sa("2001:0db8:0000:0000:0000:0000:0000:0001");
	struct sockaddr_storage other = make_sa("2001:db9::1");

	ok(match_client_addr(&r, "2001:db8::1", (struct sockaddr *)&compressed), "/32 matches the compressed spelling");
	// The same address written out in full must match identically: a textual
	// comparison could not do this, which is the reason CIDR is needed for IPv6.
	ok(match_client_addr(&r, "2001:0db8:0000:0000:0000:0000:0000:0001", (struct sockaddr *)&expanded),
		"/32 matches regardless of :: compression");
	ok(!match_client_addr(&r, "2001:db9::1", (struct sockaddr *)&other), "/32 rejects a different prefix");

	// A /64 leaves six whole bytes plus a partial one.
	QP_rule_t r64 = make_rule();
	r64.client_addr = const_cast<char *>("2001:db8:0:1::/64");
	ok(qp_addr_predicate_init(&r64.client_addr_pred, r64.client_addr, QP_ADDR_FIELD_CLIENT), "IPv6 /64 predicate resolves");
	struct sockaddr_storage in64 = make_sa("2001:db8:0:1:ffff::1");
	struct sockaddr_storage out64 = make_sa("2001:db8:0:2::1");
	ok(match_client_addr(&r64, "2001:db8:0:1:ffff::1", (struct sockaddr *)&in64), "/64 matches inside the subnet");
	ok(!match_client_addr(&r64, "2001:db8:0:2::1", (struct sockaddr *)&out64), "/64 rejects the adjacent subnet");

	// ::/0 must match every IPv6 client.
	QP_rule_t r0 = make_rule();
	r0.client_addr = const_cast<char *>("::/0");
	ok(qp_addr_predicate_init(&r0.client_addr_pred, r0.client_addr, QP_ADDR_FIELD_CLIENT), "::/0 predicate resolves");
	struct sockaddr_storage any6 = make_sa("fe80::1234");
	ok(match_client_addr(&r0, "fe80::1234", (struct sockaddr *)&any6), "::/0 matches any IPv6 address");

	// A /128 is a single address.
	QP_rule_t r128 = make_rule();
	r128.client_addr = const_cast<char *>("2001:db8::1/128");
	ok(qp_addr_predicate_init(&r128.client_addr_pred, r128.client_addr, QP_ADDR_FIELD_CLIENT), "IPv6 /128 predicate resolves");
	struct sockaddr_storage one = make_sa("2001:db8::1");
	struct sockaddr_storage two = make_sa("2001:db8::2");
	ok(match_client_addr(&r128, "2001:db8::1", (struct sockaddr *)&one), "/128 matches its own address");
	ok(!match_client_addr(&r128, "2001:db8::2", (struct sockaddr *)&two), "/128 rejects a neighbour");
}

// Acceptance criterion 4: the two families never match each other, and a mixed
// list matches whichever family the client belongs to.
static void test_cidr_mixed_families() {
	QP_rule_t r = make_rule();
	r.client_addr = const_cast<char *>("10.0.0.0/8,2001:db8::/32");
	ok(qp_addr_predicate_init(&r.client_addr_pred, r.client_addr, QP_ADDR_FIELD_CLIENT), "mixed list resolves");
	ok(r.client_addr_pred.cidr_count == 2, "both prefixes parsed");

	struct sockaddr_storage v4in = make_sa("10.1.2.3");
	struct sockaddr_storage v4out = make_sa("11.1.2.3");
	struct sockaddr_storage v6in = make_sa("2001:db8::99");
	struct sockaddr_storage v6out = make_sa("2001:db9::99");

	ok(match_client_addr(&r, "10.1.2.3", (struct sockaddr *)&v4in), "mixed list matches its IPv4 entry");
	ok(!match_client_addr(&r, "11.1.2.3", (struct sockaddr *)&v4out), "mixed list rejects an IPv4 address outside it");
	ok(match_client_addr(&r, "2001:db8::99", (struct sockaddr *)&v6in), "mixed list matches its IPv6 entry");
	ok(!match_client_addr(&r, "2001:db9::99", (struct sockaddr *)&v6out), "mixed list rejects an IPv6 address outside it");

	// An IPv4-only rule must ignore an IPv6 client, and the reverse.
	QP_rule_t r4 = make_rule();
	r4.client_addr = const_cast<char *>("0.0.0.0/0");
	ok(qp_addr_predicate_init(&r4.client_addr_pred, r4.client_addr, QP_ADDR_FIELD_CLIENT), "IPv4 /0 resolves");
	ok(!match_client_addr(&r4, "2001:db8::1", (struct sockaddr *)&v6in), "IPv4 /0 does not match an IPv6 client");

	QP_rule_t r6 = make_rule();
	r6.client_addr = const_cast<char *>("::/0");
	ok(qp_addr_predicate_init(&r6.client_addr_pred, r6.client_addr, QP_ADDR_FIELD_CLIENT), "IPv6 /0 resolves");
	ok(!match_client_addr(&r6, "10.1.2.3", (struct sockaddr *)&v4in), "IPv6 /0 does not match an IPv4 client");
}

// A CIDR criterion cannot be satisfied without a parsed address, so it must
// fail closed rather than accidentally matching everything.
static void test_cidr_requires_parsed_address() {
	QP_rule_t r = make_rule();
	r.client_addr = const_cast<char *>("0.0.0.0/0");
	ok(qp_addr_predicate_init(&r.client_addr_pred, r.client_addr, QP_ADDR_FIELD_CLIENT), "/0 resolves");
	ok(!match_client_addr(&r, "10.1.2.3", nullptr), "CIDR criterion rejects a null sockaddr");
}

// Acceptance criterion 6: the pre-existing forms keep their behaviour, and a
// bare '_' now reaches mywildcmp() instead of being compared literally.
static void test_addr_predicate_mode_selection() {
	qp_addr_predicate_t pred;

	ok(qp_addr_predicate_init(&pred, NULL, QP_ADDR_FIELD_CLIENT), "NULL value resolves");
	ok(pred.match == QP_ADDR_MATCH_NONE, "NULL selects no criterion");

	ok(qp_addr_predicate_init(&pred, "", QP_ADDR_FIELD_CLIENT), "empty value resolves");
	ok(pred.match == QP_ADDR_MATCH_NONE, "empty string selects no criterion");

	ok(qp_addr_predicate_init(&pred, "10.0.0.1", QP_ADDR_FIELD_CLIENT), "literal resolves");
	ok(pred.match == QP_ADDR_MATCH_EXACT, "literal selects exact mode");

	ok(qp_addr_predicate_init(&pred, "10.0.0.1", QP_ADDR_FIELD_PROXY), "literal resolves for proxy_addr");
	ok(pred.match == QP_ADDR_MATCH_EXACT, "proxy_addr literal stays exact");

	ok(qp_addr_predicate_init(&pred, "%", QP_ADDR_FIELD_CLIENT), "catch-all resolves");
	ok(pred.match == QP_ADDR_MATCH_WILDCARD, "'%' selects wildcard mode");

	ok(qp_addr_predicate_init(&pred, "10.0.128.%", QP_ADDR_FIELD_CLIENT), "suffix wildcard resolves");
	ok(pred.match == QP_ADDR_MATCH_WILDCARD, "trailing % selects wildcard mode");

	ok(qp_addr_predicate_init(&pred, "10.0.13_", QP_ADDR_FIELD_CLIENT), "single-char wildcard resolves");
	ok(pred.match == QP_ADDR_MATCH_WILDCARD, "bare '_' selects wildcard mode, not exact");

	// proxy_addr has never supported wildcards and must keep its strcmp.
	ok(qp_addr_predicate_init(&pred, "10.0.0.%", QP_ADDR_FIELD_PROXY), "proxy_addr wildcard-shaped value resolves");
	ok(pred.match == QP_ADDR_MATCH_EXACT, "proxy_addr stays exact even with a % in the value");
	// The same value on client_addr does select wildcard matching.
	ok(qp_addr_predicate_init(&pred, "10.0.0.%", QP_ADDR_FIELD_CLIENT), "client_addr wildcard-shaped value resolves");
	ok(pred.match == QP_ADDR_MATCH_WILDCARD, "client_addr selects wildcard for the same value");

	// A Unix socket path is how a socket listener spells itself in proxy_addr,
	// so a leading '/' must not be read as the start of a malformed prefix.
	ok(ip_cidr_spec_looks_like_prefix("/tmp/proxysql.sock") == false,
		"a leading '/' is a path, not a prefix");
	ok(ip_cidr_spec_looks_like_prefix("10.0.0.0/8") == true, "addr/len is a prefix");
	ok(ip_cidr_spec_looks_like_prefix("2001:db8::/32") == true, "IPv6 addr/len is a prefix");
	ok(ip_cidr_spec_looks_like_prefix("10.0.0.1") == false, "a bare address is not a prefix");
	ok(ip_cidr_spec_looks_like_prefix("") == false, "an empty value is not a prefix");
	ok(ip_cidr_spec_looks_like_prefix(NULL) == false, "a null value is not a prefix");

	// The path exception is reserved for proxy_addr, which is the field a Unix
	// listener writes its socket path into.
	ok(qp_addr_predicate_init(&pred, "/tmp/proxysql.sock", QP_ADDR_FIELD_PROXY), "Unix socket path resolves on proxy_addr");
	ok(pred.match == QP_ADDR_MATCH_EXACT, "Unix socket path stays on the exact-match path");
	ok(qp_addr_predicate_init(&pred, "/tmp/proxysql.sock", QP_ADDR_FIELD_CLIENT) == false,
		"a socket path is refused on client_addr");

	// A listener path is not a rendered address, so neither the length cap nor
	// the '%'-position rule may be applied to it.
	ok(qp_addr_predicate_init(&pred, "/tmp/a-very-long-socket-path-that-exceeds-inet6-addrstrlen-by-a-way.sock",
		QP_ADDR_FIELD_PROXY), "an over-long socket path is accepted on proxy_addr");
	ok(pred.match == QP_ADDR_MATCH_EXACT, "an over-long socket path stays exact");
	ok(qp_addr_predicate_init(&pred, "/tmp/a%b.sock", QP_ADDR_FIELD_PROXY),
		"a socket path containing '%' is accepted on proxy_addr");
	ok(pred.match == QP_ADDR_MATCH_EXACT, "a socket path containing '%' stays exact");
}

// An IPv6 literal may embed a dotted quad, which makes the longest legal token
// 49 bytes -- address plus "/128" -- past INET6_ADDRSTRLEN. Such a prefix is
// valid and must be accepted.
static void test_cidr_ipv6_embedded_dotted_quad() {
	qp_addr_predicate_t pred;
	ok(qp_addr_predicate_init(&pred, "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128", QP_ADDR_FIELD_CLIENT),
		"an IPv6 literal embedding a dotted quad is accepted");
	ok(pred.match == QP_ADDR_MATCH_CIDR, "it selects CIDR mode");
	ok(pred.cidr_count == 1, "one prefix parsed");
	ok(ip_cidr_list_is_valid("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128"),
		"the validator accepts it too");

	// The limit has to be applied to the trimmed token, since ip_cidr_parse()
	// tolerates padding. A 49-byte prefix plus one trailing space must still
	// load rather than tripping the raw-slice length check.
	ok(ip_cidr_list_is_valid("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128 "),
		"a padded maximum-length token is accepted");
	ok(ip_cidr_list_is_valid(" ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128 "),
		"a maximum-length token padded on both sides is accepted");
	ok(ip_cidr_list_is_valid("10.0.0.0/8 , 192.168.0.0/16 "),
		"a padded list is accepted");
	ok(ip_cidr_list_is_valid("10.0.0.0/8, ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128"),
		"a padded maximum-length entry inside a list is accepted");
	ok(ip_cidr_list_is_valid("10.0.0.0/8,10.0.0.0/8,10.0.0.0/8,10.0.0.0/8,10.0.0.0/8,"
	                         "10.0.0.0/8,10.0.0.0/8,10.0.0.0/8 ,  ") == false,
		"a list of empty trailing tokens is still rejected");

	QP_rule_t r = make_rule();
	r.client_addr = const_cast<char *>("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128");
	ok(qp_addr_predicate_init(&r.client_addr_pred, r.client_addr, QP_ADDR_FIELD_CLIENT), "rule predicate resolves");
	// The embedded dotted quad is the last 32 bits, so this prefix is the
	// all-ones address -- not ::ffff:255.255.255.255, which has ten leading
	// zero bytes and is a different 128-bit value.
	struct sockaddr_storage lo = make_sa("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
	struct sockaddr_storage other = make_sa("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe");
	ok(match_client_addr(&r, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", (struct sockaddr *)&lo),
		"the /128 matches its own address");
	ok(!match_client_addr(&r, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", (struct sockaddr *)&other),
		"the /128 rejects a neighbour");
	// The IPv4-mapped address is genuinely outside this prefix.
	struct sockaddr_storage mapped = make_sa("::ffff:255.255.255.255");
	ok(!match_client_addr(&r, "::ffff:255.255.255.255", (struct sockaddr *)&mapped),
		"the all-ones /128 does not match the IPv4-mapped address");
}

// A bare '_' used to be compared literally and so could never match. Now that
// it selects wildcard mode it must actually reach mywildcmp().
//
// '_' stands for exactly one character, so it only lines up when the rest of
// the pattern is as long as the rest of the address. Absorbing a variable tail
// still needs a trailing '%'.
static void test_bare_underscore_wildcard_matches() {
	QP_rule_t r = make_rule();
	r.client_addr = const_cast<char *>("10.0.1_.5");
	ok(qp_addr_predicate_init(&r.client_addr_pred, r.client_addr, QP_ADDR_FIELD_CLIENT), "bare '_' resolves");
	ok(r.client_addr_pred.match == QP_ADDR_MATCH_WILDCARD, "bare '_' selects wildcard mode");
	ok(rule_matches_query(&r, 0, "u", "d", "10.0.13.5",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"bare '_' substitutes the single character it stands for");
	ok(!rule_matches_query(&r, 0, "u", "d", "10.0.23.5",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"bare '_' wildcard rejects a non-match");

	// '_' consumes one character, so it cannot stand in for a variable tail.
	QP_rule_t rs = make_rule();
	rs.client_addr = const_cast<char *>("10.0.13_");
	ok(qp_addr_predicate_init(&rs.client_addr_pred, rs.client_addr, QP_ADDR_FIELD_CLIENT), "trailing bare '_' resolves");
	ok(!rule_matches_query(&rs, 0, "u", "d", "10.0.130.1",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"'_' matches exactly one character, not a variable tail");

	// The documented form pairs '_' with a trailing '%' to absorb the tail.
	QP_rule_t rp = make_rule();
	rp.client_addr = const_cast<char *>("10.0.13_.%");
	ok(qp_addr_predicate_init(&rp.client_addr_pred, rp.client_addr, QP_ADDR_FIELD_CLIENT), "'_.' with trailing % resolves");
	ok(rule_matches_query(&rp, 0, "u", "d", "10.0.135.7",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"'10.0.13_.%' matches 10.0.135.7");
	ok(!rule_matches_query(&rp, 0, "u", "d", "10.0.145.7",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"'10.0.13_.%' rejects 10.0.145.7");
}

// Acceptance criterion 5: malformed values are rejected by the parser rather
// than being loaded in a state where they can never match.
static void test_cidr_rejects_malformed() {
	qp_addr_predicate_t pred;
	IP_CIDR_t scratch {};

	ok(qp_addr_predicate_init(&pred, "10.0.0.0/33", QP_ADDR_FIELD_CLIENT) == false, "IPv4 /33 rejected");
	ok(pred.match == QP_ADDR_MATCH_NONE, "rejected value leaves no criterion");
	ok(qp_addr_predicate_init(&pred, "10.0.0.0/99", QP_ADDR_FIELD_CLIENT) == false, "IPv4 /99 rejected");
	ok(qp_addr_predicate_init(&pred, "10.0.0.0/not_a_mask", QP_ADDR_FIELD_CLIENT) == false, "non-numeric prefix rejected");
	ok(qp_addr_predicate_init(&pred, "10.0.0.0/-1", QP_ADDR_FIELD_CLIENT) == false, "negative prefix rejected");
	ok(qp_addr_predicate_init(&pred, "10.0.0.0/8x", QP_ADDR_FIELD_CLIENT) == false, "trailing junk after prefix rejected");
	ok(qp_addr_predicate_init(&pred, "10.0.0.0/8/8", QP_ADDR_FIELD_CLIENT) == false, "second '/' rejected");
	// A leading '/' is a filesystem path. Only proxy_addr can hold one -- a
	// Unix listener's socket path -- so on client_addr it is a mistake and is
	// rejected rather than becoming a criterion that could never match.
	ok(qp_addr_predicate_init(&pred, "/8", QP_ADDR_FIELD_CLIENT) == false,
		"a leading '/' is rejected on client_addr");
	ok(qp_addr_predicate_init(&pred, "/tmp/proxysql.sock", QP_ADDR_FIELD_CLIENT) == false,
		"a socket path is rejected on client_addr");
	ok(qp_addr_predicate_init(&pred, "/8", QP_ADDR_FIELD_PROXY) == true,
		"a leading '/' is accepted on proxy_addr");
	ok(pred.match == QP_ADDR_MATCH_EXACT, "'/8' is compared literally on proxy_addr");
	ok(ip_cidr_parse("/8", &scratch) == false, "but /8 is still not a parseable prefix");
	ok(qp_addr_predicate_init(&pred, "10.0.0.0/", QP_ADDR_FIELD_CLIENT) == false, "missing prefix length rejected");
	ok(qp_addr_predicate_init(&pred, "not_an_address/24", QP_ADDR_FIELD_CLIENT) == false, "invalid address rejected");
	ok(qp_addr_predicate_init(&pred, "10.0.256.0/24", QP_ADDR_FIELD_CLIENT) == false, "out-of-range octet rejected");
	ok(qp_addr_predicate_init(&pred, "10.0.0.0.1/24", QP_ADDR_FIELD_CLIENT) == false, "five octets rejected");
	ok(qp_addr_predicate_init(&pred, "10.0.0.0/24,", QP_ADDR_FIELD_CLIENT) == false, "trailing empty token rejected");
	ok(qp_addr_predicate_init(&pred, "10.0.0.0/24,,10.0.0.0/8", QP_ADDR_FIELD_CLIENT) == false, "empty middle token rejected");
	ok(qp_addr_predicate_init(&pred, "2001:db8::/129", QP_ADDR_FIELD_CLIENT) == false, "IPv6 /129 rejected");
	ok(qp_addr_predicate_init(&pred, "10.0.0.0/8,10.0.0.0/33", QP_ADDR_FIELD_CLIENT) == false, "one bad token fails the whole list");
	ok(ip_cidr_list_is_valid("10.0.0.0/24,10.0.0.0/33") == false, "validator rejects a list with one bad token");

	// A list longer than a rule can hold must fail rather than be truncated.
	std::string too_many;
	for (int i = 0; i <= MAX_CIDR_PREFIXES_PER_RULE; i++) {
		if (i > 0) {
			too_many += ",";
		}
		too_many += "10.0.0.0/8";
	}
	ok(qp_addr_predicate_init(&pred, too_many.c_str(), QP_ADDR_FIELD_CLIENT) == false, "list longer than the cap rejected");
	ok(ip_cidr_list_is_valid(too_many.c_str()) == false, "validator rejects an over-long list");
}

// proxy_addr takes the same CIDR form, and the address arrives as text only.
static void test_proxy_addr_cidr() {
	QP_rule_t r = make_rule();
	r.proxy_addr = const_cast<char *>("10.0.128.0/20");
	ok(qp_addr_predicate_init(&r.proxy_addr_pred, r.proxy_addr, QP_ADDR_FIELD_PROXY), "proxy_addr CIDR resolves");
	ok(r.proxy_addr_pred.match == QP_ADDR_MATCH_CIDR, "proxy_addr accepts a CIDR prefix");

	// process_query() converts the proxy address once and hands the sockaddr in,
	// so the test supplies the same parsed form for each candidate.
	struct sockaddr_storage in = make_sa("10.0.135.7");
	struct sockaddr_storage out = make_sa("10.0.150.7");
	struct sockaddr_storage v6 = make_sa("2001:db8::1");

	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"10.0.135.7",
		(struct sockaddr *)&in, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"proxy_addr CIDR matches inside the prefix");
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"10.0.150.7",
		(struct sockaddr *)&out, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"proxy_addr CIDR rejects outside the prefix");
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"2001:db8::1",
		(struct sockaddr *)&v6, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"proxy_addr IPv4 CIDR does not match an IPv6 proxy");
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"10.0.135.7",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"proxy_addr CIDR fails closed without a parsed proxy address");

	// An exact proxy_addr is unaffected and does not need a sockaddr.
	QP_rule_t rex = make_rule();
	rex.proxy_addr = const_cast<char *>("10.0.0.5");
	ok(qp_addr_predicate_init(&rex.proxy_addr_pred, rex.proxy_addr, QP_ADDR_FIELD_PROXY), "exact proxy_addr resolves");
	ok(rule_matches_query(&rex, 0, "u", "d", "1.2.3.4",
		nullptr,
		"10.0.0.5",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"exact proxy_addr still matches");
	ok(!rule_matches_query(&rex, 0, "u", "d", "1.2.3.4",
		nullptr,
		"10.0.0.6",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"exact proxy_addr still rejects a mismatch");
}

// The parse helpers are the unit the rest of the feature rests on, so pin the
// network-byte-order and masking behaviour directly.
static void test_cidr_parse_primitives() {
	IP_CIDR_t cidr {};

	ok(ip_cidr_parse("192.168.1.0/24", &cidr), "parse 192.168.1.0/24");
	ok(cidr.family == AF_INET, "IPv4 family recorded");
	ok(cidr.prefix_len == 24, "prefix length recorded");
	ok(cidr.addr[0] == 192 && cidr.addr[1] == 168 && cidr.addr[2] == 1 && cidr.addr[3] == 0,
		"network address kept in network byte order");

	ok(ip_cidr_parse("192.168.1.130/24", &cidr), "parse with host bits set");
	ok(cidr.addr[2] == 1 && cidr.addr[3] == 0, "host bits masked off");

	ok(ip_cidr_parse(" 10.0.0.0/8 ", &cidr), "surrounding spaces tolerated");
	ok(cidr.prefix_len == 8, "prefix length parsed with spaces");

	ok(ip_cidr_parse("10.0.0.0/0", &cidr), "parse /0");
	ok(cidr.addr[0] == 0 && cidr.addr[1] == 0 && cidr.addr[2] == 0 && cidr.addr[3] == 0,
		"/0 masks the whole address");

	ok(ip_cidr_parse("2001:db8::/32", &cidr), "parse IPv6");
	ok(cidr.family == AF_INET6, "IPv6 family recorded");
	ok(cidr.prefix_len == 32, "IPv6 prefix length recorded");

	ok(ip_cidr_parse(NULL, &cidr) == false, "NULL token rejected");
	ok(ip_cidr_parse("", &cidr) == false, "empty token rejected");

	IP_CIDR_t list[MAX_CIDR_PREFIXES_PER_RULE];
	int count = 0;
	ok(ip_cidr_parse_list("10.0.0.0/8,192.168.0.0/16", list, MAX_CIDR_PREFIXES_PER_RULE, &count),
		"parse a two-entry list");
	ok(count == 2, "list length reported");
	ok(list[0].prefix_len == 8 && list[1].prefix_len == 16, "list entries kept in order");

	ok(ip_cidr_list_is_valid("") == false, "an empty list is not valid");
	ok(ip_cidr_list_is_valid(NULL) == false, "a null list is not valid");
	ok(ip_cidr_list_is_valid("10.0.0.0/8"), "a single valid prefix is valid");
	ok(ip_cidr_list_is_valid(" 10.0.0.0/8 , 192.168.0.0/16 "), "a padded list is valid");

	ok(ip_cidr_contains(NULL, NULL) == false, "null prefix never matches");
	ok(ip_cidr_contains(&cidr, NULL) == false, "null address never matches");
}

static void test_proxy_addr_port() {
	QP_rule_t r = make_rule();
	r.proxy_addr = const_cast<char *>("10.0.0.5");
	r.proxy_port = 6033;
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"10.0.0.5",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"proxy_addr + proxy_port match");
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"10.0.0.5",
		nullptr, 6034, 0, nullptr, "SELECT 1", nullptr, 2),
		"proxy_port mismatch rejects");
}

static void test_digest() {
	QP_rule_t r = make_rule();
	r.digest = 123456789ULL;
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 123456789ULL, nullptr, "SELECT 1", nullptr, 2),
		"digest matches");
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 999ULL, nullptr, "SELECT 1", nullptr, 2),
		"digest mismatch rejects");
}

// ============================================================================
// 2. Regex matching
// ============================================================================

static void test_match_digest_re2() {
	QP_rule_t r = make_rule();
	r.match_digest = const_cast<char *>("^SELECT .* FROM users$");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, "SELECT name FROM users",
		"SELECT name FROM users WHERE id=1", nullptr, 2),
		"match_digest regex matches with RE2");
}

static void test_match_digest_pcre() {
	QP_rule_t r = make_rule();
	r.match_digest = const_cast<char *>("^SELECT .* FROM users$");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, "SELECT email FROM users",
		"SELECT email FROM users WHERE id=1", nullptr, 1),
		"match_digest regex matches with PCRE");
}

static void test_match_digest_pcre2() {
	QP_rule_t r = make_rule();
	r.match_digest = const_cast<char *>("(?<=A{1,2})B");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, "AAB", "SELECT 1", nullptr, 1),
		"PCRE-compatible mode accepts PCRE2 variable-length lookbehind");
}

static void test_match_digest_pcre2_lookaround_reset_start() {
	QP_rule_t r = make_rule();
	r.match_digest = const_cast<char *>("(?=a\\K)a");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, "a", "SELECT 1", nullptr, 1),
		"PCRE-compatible mode accepts legacy \\K inside positive lookahead");
}

static void test_invalid_pcre2_pattern() {
	QP_rule_t r = make_rule();
	r.match_pattern = const_cast<char *>("(");
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 1),
		"invalid PCRE2 pattern safely returns no match");
}

static void test_invalid_negated_pcre2_pattern() {
	QP_rule_t r = make_rule();
	r.match_pattern = const_cast<char *>("(");
	r.negate_match_pattern = true;
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 1),
		"invalid PCRE2 pattern does not match a negated rule");
}

static void test_match_pattern() {
	QP_rule_t r = make_rule();
	r.match_pattern = const_cast<char *>("SELECT .* FROM orders");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr,
		"SELECT id FROM orders WHERE id=10", nullptr, 2),
		"match_pattern regex matches query text");
}

static void test_negate_match_pattern() {
	QP_rule_t r = make_rule();
	r.match_pattern = const_cast<char *>("DELETE");
	r.negate_match_pattern = true;
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"negate_match_pattern inverts result");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 1),
		"PCRE-compatible negate_match_pattern inverts result");
}

static void test_caseless_modifier() {
	QP_rule_t r = make_rule();
	r.match_pattern = const_cast<char *>("select .* from inventory");
	r.re_modifiers = QP_RE_MOD_CASELESS;
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr,
		"SELECT SKU FROM INVENTORY", nullptr, 2),
		"CASELESS modifier makes regex case-insensitive");
}

static void test_rewritten_query() {
	QP_rule_t r = make_rule();
	r.match_pattern = const_cast<char *>("SELECT .* FROM rewritten_table");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr,
		"SELECT * FROM original_table",
		"SELECT * FROM rewritten_table", 2),
		"rewritten query used for match_pattern when present");
}

#ifdef DEBUG
static void test_pcre2_rewrites() {
	std::string rewritten;

	bool rc = pcre2_query_rule_replace_for_test(
		"(x)", "x x", "$1:${name}:$&", false, &rewritten
	);
	ok(rc && rewritten == "$1:${name}:$& x",
		"PCRE rewrite preserves dollar forms as literal text");

	rc = pcre2_query_rule_replace_for_test(
		"(ab)", "ab ab", "\\0:\\1", false, &rewritten
	);
	ok(rc && rewritten == "ab:ab ab",
		"PCRE rewrite expands legacy whole-match and capture references once");

	rc = pcre2_query_rule_replace_for_test(
		"(ab)", "ab ab", "\\0:\\1", true, &rewritten
	);
	ok(rc && rewritten == "ab:ab ab:ab",
		"PCRE global rewrite expands legacy captures for every match");

	rc = pcre2_query_rule_replace_for_test(
		"x", "x x", "\\\\", false, &rewritten
	);
	ok(rc && rewritten == "\\ x",
		"PCRE rewrite emits one legacy literal backslash once");

	rc = pcre2_query_rule_replace_for_test(
		"x", "x x", "\\\\", true, &rewritten
	);
	ok(rc && rewritten == "\\ \\",
		"PCRE global rewrite emits a legacy literal backslash for every match");

	rc = pcre2_query_rule_replace_for_test(
		"(a)?(b)", "b b", "X\\1Y", false, &rewritten
	);
	ok(rc && rewritten == "XY b",
		"PCRE rewrite expands an unset optional capture as empty once");

	rc = pcre2_query_rule_replace_for_test(
		"(a)?(b)", "b b", "X\\1Y", true, &rewritten
	);
	ok(rc && rewritten == "XY XY",
		"PCRE global rewrite expands unset optional captures as empty");
}
#endif

// ============================================================================
// 3. Combined criteria (AND logic)
// ============================================================================

static void test_combined_criteria() {
	QP_rule_t r = make_rule();
	r.username = const_cast<char *>("appuser");
	r.schemaname = const_cast<char *>("analytics");
	r.proxy_addr = const_cast<char *>("10.0.0.9");
	r.proxy_port = 6033;
	r.match_pattern = const_cast<char *>("SELECT");
	ok(rule_matches_query(&r, 0, "appuser", "analytics", "1.2.3.4",
		nullptr,
		"10.0.0.9",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"multiple criteria use AND logic — all match");
	ok(!rule_matches_query(&r, 0, "other", "analytics", "1.2.3.4",
		nullptr,
		"10.0.0.9",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"multiple criteria AND logic — username mismatch rejects");
}

// ============================================================================
// 4. Edge cases
// ============================================================================

static void test_null_rule() {
	ok(!rule_matches_query(nullptr, 0, "u", "d", "1.2.3.4",
		nullptr,
		"127.0.0.1",
		nullptr, 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"null rule returns false");
}

// ============================================================================
// Main
// ============================================================================

int main() {
#ifdef DEBUG
	plan(200);
#else
	plan(193);
#endif

	test_init_minimal();

	test_match_all();
	test_flagIN();
	test_username();
	test_schemaname();
	test_client_addr_wildcard();
	test_cidr_ipv4_boundaries();
	test_cidr_ipv4_prefix_lengths();
	test_cidr_host_bits_are_masked();
	test_cidr_ipv6();
	test_cidr_mixed_families();
	test_cidr_requires_parsed_address();
	test_addr_predicate_mode_selection();
	test_cidr_ipv6_embedded_dotted_quad();
	test_bare_underscore_wildcard_matches();
	test_cidr_rejects_malformed();
	test_proxy_addr_cidr();
	test_cidr_parse_primitives();
	test_proxy_addr_port();
	test_digest();
	test_match_digest_re2();
	test_match_digest_pcre();
	test_match_digest_pcre2();
	test_match_digest_pcre2_lookaround_reset_start();
	test_invalid_pcre2_pattern();
	test_invalid_negated_pcre2_pattern();
	test_match_pattern();
	test_negate_match_pattern();
	test_caseless_modifier();
	test_rewritten_query();
#ifdef DEBUG
	test_pcre2_rewrites();
#endif
	test_combined_criteria();
	test_null_rule();

	test_cleanup_minimal();
	return exit_status();
}
