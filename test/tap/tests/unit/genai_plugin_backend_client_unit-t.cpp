/**
 * @file genai_plugin_backend_client_unit-t.cpp
 * @brief Unit tests for the genai plugin's backend_client helper
 *        (Step 4.B of the carve-out plan).
 *
 * Coverage focus:
 *   - `parse_interfaces_first_tcp` — the parser is the logic-heavy
 *     component (handles IPv4, IPv6 literals, wildcard rewriting,
 *     Unix-socket skipping, port range checks, multi-listener
 *     iteration).  Exercised exhaustively here.
 *   - Null-admindb guards on the public dial / resolve entry points.
 *   - Invalid host/port guards on the direct-dial entry points.
 *
 * Out of scope:
 *   - Full MySQL handshake.  `dial_mysql` -> `mysql_real_connect`
 *     would need a fake handshake server; deferred to the integration
 *     coverage that lands with Step 4.D once Query_Tool_Handler is
 *     wired through this helper end-to-end.
 *
 * Build trick: same as genai_plugin_anomaly_unit-t — compiles the
 * plugin's own translation units directly into the test binary so we
 * exercise the same code that ships in the .so without dlopening it.
 * See the rule in this directory's Makefile.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "backend_client.h"

#include <string>

// ---------------------------------------------------------------------------
// parse_interfaces_first_tcp
// ---------------------------------------------------------------------------

static void test_parse_empty() {
	LocalProxyEndpoint ep = parse_interfaces_first_tcp("");
	ok(!ep.valid(), "parse: empty value -> invalid endpoint");
}

static void test_parse_basic_ipv4() {
	LocalProxyEndpoint ep = parse_interfaces_first_tcp("127.0.0.1:6033");
	ok(ep.valid(), "parse: 127.0.0.1:6033 -> valid");
	ok(ep.host == "127.0.0.1", "parse: host preserved (got '%s')", ep.host.c_str());
	ok(ep.port == 6033, "parse: port preserved (got %d)", ep.port);
}

static void test_parse_wildcard_v4_rewritten_to_loopback() {
	LocalProxyEndpoint ep = parse_interfaces_first_tcp("0.0.0.0:6033");
	ok(ep.valid(), "parse: wildcard 0.0.0.0:6033 -> valid");
	ok(ep.host == "127.0.0.1",
	   "parse: 0.0.0.0 rewritten to 127.0.0.1 (got '%s')", ep.host.c_str());
	ok(ep.port == 6033, "parse: wildcard port preserved");
}

static void test_parse_ipv6_literal() {
	LocalProxyEndpoint ep = parse_interfaces_first_tcp("[fe80::1]:6033");
	ok(ep.valid(), "parse: [fe80::1]:6033 -> valid");
	ok(ep.host == "fe80::1",
	   "parse: IPv6 brackets stripped (got '%s')", ep.host.c_str());
	ok(ep.port == 6033, "parse: IPv6 port preserved");
}

static void test_parse_ipv6_wildcard_rewritten() {
	LocalProxyEndpoint ep = parse_interfaces_first_tcp("[::]:6033");
	ok(ep.valid(), "parse: [::]:6033 -> valid");
	ok(ep.host == "::1",
	   "parse: IPv6 wildcard :: rewritten to ::1 (got '%s')", ep.host.c_str());
}

static void test_parse_picks_first_of_many() {
	LocalProxyEndpoint ep = parse_interfaces_first_tcp(
		"127.0.0.1:6033;0.0.0.0:6034;[::]:6035");
	ok(ep.valid(), "parse: multi-listener -> valid");
	ok(ep.host == "127.0.0.1" && ep.port == 6033,
	   "parse: picks first listener (got '%s:%d')", ep.host.c_str(), ep.port);
}

static void test_parse_skips_unix_socket_first() {
	// First token is a Unix-socket path (no :port suffix); parser
	// must skip it and pick the second TCP listener.
	LocalProxyEndpoint ep = parse_interfaces_first_tcp(
		"/tmp/proxysql.sock;127.0.0.1:6033");
	ok(ep.valid(), "parse: skips Unix socket, picks next TCP");
	ok(ep.host == "127.0.0.1" && ep.port == 6033,
	   "parse: returned the TCP token (got '%s:%d')", ep.host.c_str(), ep.port);
}

static void test_parse_only_unix_socket() {
	LocalProxyEndpoint ep = parse_interfaces_first_tcp("/tmp/proxysql.sock");
	ok(!ep.valid(), "parse: only Unix socket -> invalid");
}

static void test_parse_invalid_port_zero() {
	LocalProxyEndpoint ep = parse_interfaces_first_tcp("127.0.0.1:0");
	ok(!ep.valid(), "parse: port 0 -> invalid (rejected as Unix-socket-style)");
}

static void test_parse_invalid_port_out_of_range() {
	LocalProxyEndpoint ep = parse_interfaces_first_tcp("127.0.0.1:99999");
	ok(!ep.valid(), "parse: port > 65535 -> invalid");
}

static void test_parse_handles_whitespace() {
	LocalProxyEndpoint ep = parse_interfaces_first_tcp("  127.0.0.1:6033  ");
	ok(ep.valid() && ep.host == "127.0.0.1" && ep.port == 6033,
	   "parse: leading/trailing whitespace trimmed");
}

// ---------------------------------------------------------------------------
// null-admindb guards
// ---------------------------------------------------------------------------

static void test_resolve_mysql_null_admindb() {
	LocalProxyEndpoint ep = resolve_mysql_endpoint(nullptr);
	ok(!ep.valid(), "resolve_mysql_endpoint(nullptr) -> invalid");
}

static void test_resolve_pgsql_null_admindb() {
	LocalProxyEndpoint ep = resolve_pgsql_endpoint(nullptr);
	ok(!ep.valid(), "resolve_pgsql_endpoint(nullptr) -> invalid");
}

static void test_dial_mysql_local_null_admindb() {
	BackendTarget t {"u", "p", "", 5};
	MySQLDialResult r = dial_mysql_local(nullptr, t);
	ok(r.conn == nullptr && !r.error.empty(),
	   "dial_mysql_local(nullptr) -> error path");
}

static void test_dial_pgsql_local_null_admindb() {
	BackendTarget t {"u", "p", "", 5};
	PgSQLDialResult r = dial_pgsql_local(nullptr, t);
	ok(r.conn == nullptr && !r.error.empty(),
	   "dial_pgsql_local(nullptr) -> error path");
}

// ---------------------------------------------------------------------------
// dial: invalid-parameter guards
// ---------------------------------------------------------------------------

static void test_dial_mysql_empty_host() {
	BackendTarget t {"u", "p", "", 5};
	MySQLDialResult r = dial_mysql("", 6033, t);
	ok(r.conn == nullptr && !r.error.empty(),
	   "dial_mysql with empty host -> error");
}

static void test_dial_mysql_zero_port() {
	BackendTarget t {"u", "p", "", 5};
	MySQLDialResult r = dial_mysql("127.0.0.1", 0, t);
	ok(r.conn == nullptr && !r.error.empty(),
	   "dial_mysql with port=0 -> error");
}

static void test_dial_pgsql_empty_host() {
	BackendTarget t {"u", "p", "", 5};
	PgSQLDialResult r = dial_pgsql("", 6133, t);
	ok(r.conn == nullptr && !r.error.empty(),
	   "dial_pgsql with empty host -> error");
}

// ---------------------------------------------------------------------------

int main() {
	plan(27);

	test_init_minimal();

	test_parse_empty();
	test_parse_basic_ipv4();
	test_parse_wildcard_v4_rewritten_to_loopback();
	test_parse_ipv6_literal();
	test_parse_ipv6_wildcard_rewritten();
	test_parse_picks_first_of_many();
	test_parse_skips_unix_socket_first();
	test_parse_only_unix_socket();
	test_parse_invalid_port_zero();
	test_parse_invalid_port_out_of_range();
	test_parse_handles_whitespace();

	test_resolve_mysql_null_admindb();
	test_resolve_pgsql_null_admindb();
	test_dial_mysql_local_null_admindb();
	test_dial_pgsql_local_null_admindb();

	test_dial_mysql_empty_host();
	test_dial_mysql_zero_port();
	test_dial_pgsql_empty_host();

	test_cleanup_minimal();
	return exit_status();
}
