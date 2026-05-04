/**
 * @file listen_validator_unit-t.cpp
 * @brief Unit tests for proxysql_listen_validator.h
 *
 * Tests the following functions from the proxysql_listen_validator namespace:
 * - trim_copy(): whitespace trimming
 * - split_listener_list(): semicolon-separated list parsing
 * - is_ipv4_wildcard() / is_ipv6_wildcard(): wildcard detection
 * - parse_listener(): listener string parsing (IPv4, IPv6, Unix socket, invalid)
 * - sets_intersect(): set intersection check
 * - listeners_conflict(): conflict detection between parsed listeners
 * - validate_module_listener_conflicts(): top-level cross-module validation
 *
 * This header is pure inline functions with no external ProxySQL dependencies
 * beyond standard libraries, making it ideal for isolated unit testing.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql_listen_validator.h"

#include <string>
#include <vector>
#include <set>

using namespace proxysql_listen_validator;


// ============================================================
// trim_copy()
// ============================================================

static void test_trim_copy() {
	ok(trim_copy("") == "",
		"trim_copy: empty string unchanged");
	ok(trim_copy("hello") == "hello",
		"trim_copy: no-whitespace string unchanged");
	ok(trim_copy("  hello  ") == "hello",
		"trim_copy: leading and trailing spaces removed");
	ok(trim_copy("\t\n hello \r\n\t") == "hello",
		"trim_copy: tabs/newlines/carriage returns removed");
	ok(trim_copy("   ") == "",
		"trim_copy: all-whitespace string becomes empty");
	ok(trim_copy("hello world") == "hello world",
		"trim_copy: interior whitespace preserved");
	ok(trim_copy(" a ") == "a",
		"trim_copy: single char with spaces");
}


// ============================================================
// split_listener_list()
// ============================================================

static void test_split_listener_list() {
	// nullptr
	{
		std::vector<std::string> result = split_listener_list(nullptr);
		ok(result.empty(),
			"split_listener_list: nullptr returns empty vector");
	}
	// empty string
	{
		std::vector<std::string> result = split_listener_list("");
		ok(result.empty(),
			"split_listener_list: empty string returns empty vector");
	}
	// single listener
	{
		std::vector<std::string> result = split_listener_list("0.0.0.0:6033");
		ok(result.size() == 1,
			"split_listener_list: single listener returns one element");
		ok(result[0] == "0.0.0.0:6033",
			"split_listener_list: single listener value correct");
	}
	// multiple listeners
	{
		std::vector<std::string> result = split_listener_list("0.0.0.0:6033;0.0.0.0:6034");
		ok(result.size() == 2,
			"split_listener_list: two listeners separated by semicolon");
		ok(result[0] == "0.0.0.0:6033",
			"split_listener_list: first listener correct");
		ok(result[1] == "0.0.0.0:6034",
			"split_listener_list: second listener correct");
	}
	// whitespace around entries
	{
		std::vector<std::string> result = split_listener_list("  0.0.0.0:6033 ; 0.0.0.0:6034  ");
		ok(result.size() == 2,
			"split_listener_list: whitespace trimmed, two entries");
		ok(result[0] == "0.0.0.0:6033",
			"split_listener_list: first entry trimmed");
		ok(result[1] == "0.0.0.0:6034",
			"split_listener_list: second entry trimmed");
	}
	// trailing semicolon
	{
		std::vector<std::string> result = split_listener_list("0.0.0.0:6033;");
		ok(result.size() == 1,
			"split_listener_list: trailing semicolon does not add empty entry");
	}
	// multiple semicolons (empty segments)
	{
		std::vector<std::string> result = split_listener_list("0.0.0.0:6033;;;0.0.0.0:6034");
		ok(result.size() == 2,
			"split_listener_list: empty segments between semicolons skipped");
	}
	// only semicolons
	{
		std::vector<std::string> result = split_listener_list(";;;");
		ok(result.empty(),
			"split_listener_list: only semicolons returns empty vector");
	}
}


// ============================================================
// is_ipv4_wildcard() / is_ipv6_wildcard()
// ============================================================

static void test_wildcard_detection() {
	// IPv4 wildcards
	ok(is_ipv4_wildcard("") == true,
		"is_ipv4_wildcard: empty string is wildcard");
	ok(is_ipv4_wildcard("0.0.0.0") == true,
		"is_ipv4_wildcard: 0.0.0.0 is wildcard");
	ok(is_ipv4_wildcard("*") == true,
		"is_ipv4_wildcard: asterisk is wildcard");
	ok(is_ipv4_wildcard("127.0.0.1") == false,
		"is_ipv4_wildcard: 127.0.0.1 is not wildcard");
	ok(is_ipv4_wildcard("192.168.1.1") == false,
		"is_ipv4_wildcard: specific IP is not wildcard");

	// IPv6 wildcards
	ok(is_ipv6_wildcard("::") == true,
		"is_ipv6_wildcard: :: is wildcard");
	ok(is_ipv6_wildcard("") == false,
		"is_ipv6_wildcard: empty string is NOT ipv6 wildcard");
	ok(is_ipv6_wildcard("::1") == false,
		"is_ipv6_wildcard: ::1 is not wildcard");
	ok(is_ipv6_wildcard("0.0.0.0") == false,
		"is_ipv6_wildcard: 0.0.0.0 is not ipv6 wildcard");
}


// ============================================================
// parse_listener() — valid IPv4:port
// ============================================================

static void test_parse_valid_ipv4() {
	// 0.0.0.0:6033 — wildcard
	{
		parsed_listener p = parse_listener("MySQL", "0.0.0.0:6033");
		ok(p.valid == true,
			"parse_listener: 0.0.0.0:6033 is valid");
		ok(p.kind == listener_kind::tcp,
			"parse_listener: 0.0.0.0:6033 is TCP");
		ok(p.port == 6033,
			"parse_listener: 0.0.0.0:6033 port is 6033");
		ok(p.wildcard_v4 == true,
			"parse_listener: 0.0.0.0:6033 sets wildcard_v4");
		ok(p.module_name == "MySQL",
			"parse_listener: 0.0.0.0:6033 module_name is MySQL");
		ok(p.listener == "0.0.0.0:6033",
			"parse_listener: 0.0.0.0:6033 listener string preserved");
	}
	// 127.0.0.1:3306 — specific address
	{
		parsed_listener p = parse_listener("MySQL", "127.0.0.1:3306");
		ok(p.valid == true,
			"parse_listener: 127.0.0.1:3306 is valid");
		ok(p.kind == listener_kind::tcp,
			"parse_listener: 127.0.0.1:3306 is TCP");
		ok(p.port == 3306,
			"parse_listener: 127.0.0.1:3306 port is 3306");
		ok(p.wildcard_v4 == false,
			"parse_listener: 127.0.0.1:3306 is not wildcard");
		ok(p.ipv4_addrs.count("127.0.0.1") == 1,
			"parse_listener: 127.0.0.1:3306 resolves to 127.0.0.1");
	}
	// *:6033 — star wildcard
	{
		parsed_listener p = parse_listener("MySQL", "*:6033");
		ok(p.valid == true,
			"parse_listener: *:6033 is valid");
		ok(p.wildcard_v4 == true,
			"parse_listener: *:6033 sets wildcard_v4");
		ok(p.port == 6033,
			"parse_listener: *:6033 port is 6033");
	}
	// empty host (implicit wildcard) :6033
	{
		parsed_listener p = parse_listener("MySQL", ":6033");
		ok(p.valid == true,
			"parse_listener: :6033 (empty host) is valid");
		ok(p.wildcard_v4 == true,
			"parse_listener: :6033 (empty host) sets wildcard_v4");
		ok(p.port == 6033,
			"parse_listener: :6033 port is 6033");
	}
}


// ============================================================
// parse_listener() — valid IPv6:port
// ============================================================

static void test_parse_valid_ipv6() {
	// [::]:6033 — wildcard
	{
		parsed_listener p = parse_listener("MySQL", "[::]:6033");
		ok(p.valid == true,
			"parse_listener: [::]:6033 is valid");
		ok(p.kind == listener_kind::tcp,
			"parse_listener: [::]:6033 is TCP");
		ok(p.port == 6033,
			"parse_listener: [::]:6033 port is 6033");
		ok(p.wildcard_v6 == true,
			"parse_listener: [::]:6033 sets wildcard_v6");
	}
	// [::1]:3306 — loopback
	{
		parsed_listener p = parse_listener("PgSQL", "[::1]:3306");
		ok(p.valid == true,
			"parse_listener: [::1]:3306 is valid");
		ok(p.port == 3306,
			"parse_listener: [::1]:3306 port is 3306");
		ok(p.wildcard_v6 == false,
			"parse_listener: [::1]:3306 is not wildcard");
		ok(p.ipv6_addrs.count("::1") == 1,
			"parse_listener: [::1]:3306 resolves to ::1");
		ok(p.module_name == "PgSQL",
			"parse_listener: [::1]:3306 module_name is PgSQL");
	}
}


// ============================================================
// parse_listener() — Unix socket paths
// ============================================================

static void test_parse_unix_socket() {
	// Standard socket path
	{
		parsed_listener p = parse_listener("MySQL", "/var/run/proxysql.sock");
		ok(p.valid == true,
			"parse_listener: Unix socket path is valid");
		ok(p.kind == listener_kind::unix_socket,
			"parse_listener: Unix socket path detected as unix_socket");
		ok(p.listener == "/var/run/proxysql.sock",
			"parse_listener: Unix socket listener string preserved");
	}
	// Another socket path
	{
		parsed_listener p = parse_listener("MySQL", "/tmp/proxysql.sock");
		ok(p.valid == true,
			"parse_listener: /tmp/proxysql.sock is valid");
		ok(p.kind == listener_kind::unix_socket,
			"parse_listener: /tmp/proxysql.sock is unix_socket");
	}
	// Socket path with no extension
	{
		parsed_listener p = parse_listener("MySQL", "/var/lib/mysql/mysql");
		ok(p.valid == true,
			"parse_listener: socket path without extension is valid");
		ok(p.kind == listener_kind::unix_socket,
			"parse_listener: socket path without extension is unix_socket");
	}
}


// ============================================================
// parse_listener() — invalid inputs
// ============================================================

static void test_parse_invalid() {
	// Empty string — no colon, treated as unix socket
	{
		parsed_listener p = parse_listener("MySQL", "");
		// empty string has no colon, so it's treated as unix_socket
		ok(p.kind == listener_kind::unix_socket,
			"parse_listener: empty string treated as unix_socket (no colon)");
	}
	// Missing closing bracket
	{
		parsed_listener p = parse_listener("MySQL", "[::1:6033");
		ok(p.valid == false,
			"parse_listener: missing closing bracket is invalid");
	}
	// Bracket but no port
	{
		parsed_listener p = parse_listener("MySQL", "[::1]");
		ok(p.valid == false,
			"parse_listener: [::1] without port is invalid");
	}
	// Port is zero
	{
		parsed_listener p = parse_listener("MySQL", "0.0.0.0:0");
		ok(p.valid == false,
			"parse_listener: port 0 is invalid");
	}
	// Port is 65536 (out of range)
	{
		parsed_listener p = parse_listener("MySQL", "0.0.0.0:65536");
		ok(p.valid == false,
			"parse_listener: port 65536 is invalid (out of range)");
	}
	// Port is negative
	{
		parsed_listener p = parse_listener("MySQL", "0.0.0.0:-1");
		ok(p.valid == false,
			"parse_listener: negative port is invalid");
	}
	// Port is non-numeric
	{
		parsed_listener p = parse_listener("MySQL", "0.0.0.0:abc");
		ok(p.valid == false,
			"parse_listener: non-numeric port is invalid");
	}
	// Port is very large number
	{
		parsed_listener p = parse_listener("MySQL", "0.0.0.0:999999");
		ok(p.valid == false,
			"parse_listener: port 999999 is invalid");
	}
	// IPv6 bracket with no port separator
	{
		parsed_listener p = parse_listener("MySQL", "[::1]6033");
		ok(p.valid == false,
			"parse_listener: [::1]6033 (missing colon after bracket) is invalid");
	}
	// Port with trailing garbage
	{
		parsed_listener p = parse_listener("MySQL", "0.0.0.0:6033x");
		ok(p.valid == false,
			"parse_listener: port with trailing chars is invalid");
	}
}


// ============================================================
// parse_listener() — edge cases
// ============================================================

static void test_parse_edge_cases() {
	// Port 1 (minimum valid)
	{
		parsed_listener p = parse_listener("MySQL", "0.0.0.0:1");
		ok(p.valid == true,
			"parse_listener: port 1 is valid");
		ok(p.port == 1,
			"parse_listener: port 1 value correct");
	}
	// Port 65535 (maximum valid)
	{
		parsed_listener p = parse_listener("MySQL", "0.0.0.0:65535");
		ok(p.valid == true,
			"parse_listener: port 65535 is valid");
		ok(p.port == 65535,
			"parse_listener: port 65535 value correct");
	}
	// Very long garbage string (no colon => unix_socket)
	{
		std::string long_str(1000, 'x');
		parsed_listener p = parse_listener("MySQL", long_str);
		ok(p.kind == listener_kind::unix_socket,
			"parse_listener: very long string without colon is unix_socket");
	}
	// localhost resolves to both 127.0.0.1 and ::1
	{
		parsed_listener p = parse_listener("MySQL", "localhost:3306");
		ok(p.valid == true,
			"parse_listener: localhost:3306 is valid");
		ok(p.ipv4_addrs.count("127.0.0.1") == 1,
			"parse_listener: localhost resolves to 127.0.0.1");
		ok(p.ipv6_addrs.count("::1") == 1,
			"parse_listener: localhost resolves to ::1");
	}
	// LOCALHOST (case insensitive)
	{
		parsed_listener p = parse_listener("MySQL", "LOCALHOST:3306");
		ok(p.valid == true,
			"parse_listener: LOCALHOST:3306 is valid (case insensitive)");
		ok(p.ipv4_addrs.count("127.0.0.1") == 1,
			"parse_listener: LOCALHOST resolves to 127.0.0.1");
	}
}


// ============================================================
// sets_intersect()
// ============================================================

static void test_sets_intersect() {
	// Both empty
	{
		std::set<std::string> a, b;
		ok(sets_intersect(a, b) == false,
			"sets_intersect: two empty sets do not intersect");
	}
	// One empty
	{
		std::set<std::string> a = {"x"};
		std::set<std::string> b;
		ok(sets_intersect(a, b) == false,
			"sets_intersect: one empty set => no intersection");
	}
	// Disjoint
	{
		std::set<std::string> a = {"a", "b"};
		std::set<std::string> b = {"c", "d"};
		ok(sets_intersect(a, b) == false,
			"sets_intersect: disjoint sets do not intersect");
	}
	// Overlapping
	{
		std::set<std::string> a = {"a", "b"};
		std::set<std::string> b = {"b", "c"};
		ok(sets_intersect(a, b) == true,
			"sets_intersect: overlapping sets intersect");
	}
	// Identical
	{
		std::set<std::string> a = {"x"};
		std::set<std::string> b = {"x"};
		ok(sets_intersect(a, b) == true,
			"sets_intersect: identical single-element sets intersect");
	}
}


// ============================================================
// listeners_conflict()
// ============================================================

static void test_listeners_conflict() {
	// Same unix socket path => conflict
	{
		parsed_listener a = parse_listener("MySQL", "/tmp/proxysql.sock");
		parsed_listener b = parse_listener("PgSQL", "/tmp/proxysql.sock");
		ok(listeners_conflict(a, b) == true,
			"listeners_conflict: same unix socket path conflicts");
	}
	// Different unix socket paths => no conflict
	{
		parsed_listener a = parse_listener("MySQL", "/tmp/mysql.sock");
		parsed_listener b = parse_listener("PgSQL", "/tmp/pgsql.sock");
		ok(listeners_conflict(a, b) == false,
			"listeners_conflict: different unix socket paths do not conflict");
	}
	// Unix socket vs TCP => no conflict
	{
		parsed_listener a = parse_listener("MySQL", "/tmp/proxysql.sock");
		parsed_listener b = parse_listener("PgSQL", "0.0.0.0:6033");
		ok(listeners_conflict(a, b) == false,
			"listeners_conflict: unix socket vs TCP do not conflict");
	}
	// Same wildcard IPv4, same port => conflict
	{
		parsed_listener a = parse_listener("MySQL", "0.0.0.0:6033");
		parsed_listener b = parse_listener("PgSQL", "0.0.0.0:6033");
		ok(listeners_conflict(a, b) == true,
			"listeners_conflict: same wildcard IPv4 same port conflicts");
	}
	// Same wildcard IPv4, different port => no conflict
	{
		parsed_listener a = parse_listener("MySQL", "0.0.0.0:6033");
		parsed_listener b = parse_listener("PgSQL", "0.0.0.0:6034");
		ok(listeners_conflict(a, b) == false,
			"listeners_conflict: same wildcard IPv4 different port no conflict");
	}
	// Wildcard IPv4 vs specific IPv4 on same port => conflict
	{
		parsed_listener a = parse_listener("MySQL", "0.0.0.0:6033");
		parsed_listener b = parse_listener("PgSQL", "127.0.0.1:6033");
		ok(listeners_conflict(a, b) == true,
			"listeners_conflict: wildcard v4 vs specific v4 same port conflicts");
	}
	// Same wildcard IPv6, same port => conflict
	{
		parsed_listener a = parse_listener("MySQL", "[::]:6033");
		parsed_listener b = parse_listener("PgSQL", "[::]:6033");
		ok(listeners_conflict(a, b) == true,
			"listeners_conflict: same wildcard IPv6 same port conflicts");
	}
	// Wildcard IPv6 vs specific IPv6 on same port => conflict
	{
		parsed_listener a = parse_listener("MySQL", "[::]:6033");
		parsed_listener b = parse_listener("PgSQL", "[::1]:6033");
		ok(listeners_conflict(a, b) == true,
			"listeners_conflict: wildcard v6 vs specific v6 same port conflicts");
	}
	// Same specific IP, same port => conflict
	{
		parsed_listener a = parse_listener("MySQL", "127.0.0.1:6033");
		parsed_listener b = parse_listener("PgSQL", "127.0.0.1:6033");
		ok(listeners_conflict(a, b) == true,
			"listeners_conflict: same specific IP same port conflicts");
	}
	// Different specific IPs, same port => no conflict
	{
		parsed_listener a = parse_listener("MySQL", "127.0.0.1:6033");
		parsed_listener b = parse_listener("PgSQL", "192.168.1.1:6033");
		ok(listeners_conflict(a, b) == false,
			"listeners_conflict: different specific IPs same port no conflict");
	}
}


// ============================================================
// validate_module_listener_conflicts()
// ============================================================

static void test_validate_no_conflicts() {
	std::string error;
	std::vector<module_listener_config> modules = {
		{"MySQL",     "0.0.0.0:6033"},
		{"PostgreSQL", "0.0.0.0:6034"},
	};
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == true,
		"validate_module_listener_conflicts: different ports no conflict");
	ok(error.empty(),
		"validate_module_listener_conflicts: no error on success");
}

static void test_validate_cross_module_conflict() {
	std::string error;
	std::vector<module_listener_config> modules = {
		{"MySQL",     "0.0.0.0:6033"},
		{"PostgreSQL", "0.0.0.0:6033"},
	};
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == false,
		"validate_module_listener_conflicts: same port same addr conflicts");
	ok(error.find("conflict") != std::string::npos || error.find("overlap") != std::string::npos,
		"validate_module_listener_conflicts: error message describes conflict");
	ok(error.find("MySQL") != std::string::npos,
		"validate_module_listener_conflicts: error mentions MySQL");
	ok(error.find("PostgreSQL") != std::string::npos,
		"validate_module_listener_conflicts: error mentions PostgreSQL");
}

static void test_validate_same_module_no_conflict() {
	// Same module with overlapping listeners should NOT be flagged
	// (conflict detection is cross-module only)
	std::string error;
	std::vector<module_listener_config> modules = {
		{"MySQL", "0.0.0.0:6033;0.0.0.0:6033"},
	};
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == true,
		"validate_module_listener_conflicts: same module overlap is allowed");
}

static void test_validate_null_listeners() {
	std::string error;
	std::vector<module_listener_config> modules = {
		{"MySQL", nullptr},
		{"PostgreSQL", "0.0.0.0:6034"},
	};
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == true,
		"validate_module_listener_conflicts: null listeners skipped");
}

static void test_validate_empty_listeners() {
	std::string error;
	std::vector<module_listener_config> modules = {
		{"MySQL", ""},
		{"PostgreSQL", "0.0.0.0:6034"},
	};
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == true,
		"validate_module_listener_conflicts: empty listeners skipped");
}

static void test_validate_null_string_literal() {
	std::string error;
	std::vector<module_listener_config> modules = {
		{"MySQL", "(null)"},
		{"PostgreSQL", "0.0.0.0:6034"},
	};
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == true,
		"validate_module_listener_conflicts: '(null)' string skipped");
}

static void test_validate_invalid_listeners_skipped() {
	// Invalid listeners (bad port) should be skipped, not cause conflict
	std::string error;
	std::vector<module_listener_config> modules = {
		{"MySQL",     "0.0.0.0:0"},
		{"PostgreSQL", "0.0.0.0:0"},
	};
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == true,
		"validate_module_listener_conflicts: invalid listeners are skipped");
}

static void test_validate_multiple_listeners_per_module() {
	std::string error;
	std::vector<module_listener_config> modules = {
		{"MySQL",     "0.0.0.0:6033;0.0.0.0:6034"},
		{"PostgreSQL", "0.0.0.0:6035;0.0.0.0:6036"},
	};
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == true,
		"validate_module_listener_conflicts: multiple non-conflicting listeners pass");
}

static void test_validate_multiple_listeners_with_conflict() {
	std::string error;
	std::vector<module_listener_config> modules = {
		{"MySQL",     "0.0.0.0:6033;0.0.0.0:6034"},
		{"PostgreSQL", "0.0.0.0:6035;0.0.0.0:6034"},
	};
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == false,
		"validate_module_listener_conflicts: conflict on second listener detected");
}

static void test_validate_unix_socket_conflict() {
	std::string error;
	std::vector<module_listener_config> modules = {
		{"MySQL",     "/tmp/proxysql.sock"},
		{"PostgreSQL", "/tmp/proxysql.sock"},
	};
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == false,
		"validate_module_listener_conflicts: same unix socket cross-module conflicts");
}

static void test_validate_empty_modules() {
	std::string error;
	std::vector<module_listener_config> modules;
	bool result = validate_module_listener_conflicts(modules, error);
	ok(result == true,
		"validate_module_listener_conflicts: empty module list passes");
}


// ============================================================
// main
// ============================================================

int main() {
	plan(
		7    // trim_copy
		+ 13 // split_listener_list
		+ 9  // wildcard detection
		+ 17 // parse valid IPv4
		+ 9  // parse valid IPv6
		+ 7  // parse unix socket
		+ 11 // parse invalid
		+ 10 // parse edge cases
		+ 5  // sets_intersect
		+ 10 // listeners_conflict
		+ 14 // validate_module_listener_conflicts
	);

	test_init_minimal();

	test_trim_copy();
	test_split_listener_list();
	test_wildcard_detection();
	test_parse_valid_ipv4();
	test_parse_valid_ipv6();
	test_parse_unix_socket();
	test_parse_invalid();
	test_parse_edge_cases();
	test_sets_intersect();
	test_listeners_conflict();

	test_validate_no_conflicts();
	test_validate_cross_module_conflict();
	test_validate_same_module_no_conflict();
	test_validate_null_listeners();
	test_validate_empty_listeners();
	test_validate_null_string_literal();
	test_validate_invalid_listeners_skipped();
	test_validate_multiple_listeners_per_module();
	test_validate_multiple_listeners_with_conflict();
	test_validate_unix_socket_conflict();
	test_validate_empty_modules();

	test_cleanup_minimal();
	return exit_status();
}
