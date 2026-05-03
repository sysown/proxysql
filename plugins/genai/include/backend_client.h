/**
 * @file backend_client.h
 * @brief Helper for opening MySQL / PgSQL client connections to the local
 *        ProxySQL data ports from inside the genai plugin.
 *
 * Step 4.B introduces this helper as a no-caller standalone module.
 * Step 4.D rewires `Query_Tool_Handler` and `MySQL_Tool_Handler` to use
 * it; later sub-steps reroute additional tool handlers through the same
 * code path.
 *
 * Design (per docs/superpowers/plans/2026-04-19-step4-mcp-subsystem-move.md
 * sub-step 4.B):
 *
 *   - Tool handlers historically dialled `target.host:target.port`
 *     (the backend MySQL/PgSQL servers) directly.  After Step 4.D they
 *     dial `127.0.0.1:<local-proxy-port>` and let ProxySQL itself route,
 *     pool, and ACL-check.  This module is the unified entry point for
 *     that pattern.
 *
 *   - The local proxy endpoint is discovered by reading the
 *     `mysql-interfaces` / `pgsql-interfaces` global_variables rows from
 *     the admin DB at dial time.  No new config knob.  See
 *     local_proxy_endpoint.cpp for the parser.
 *
 *   - Authentication uses credentials supplied by the caller in
 *     BackendTarget.  Per Q-svcuser of the spec, those credentials come
 *     from the existing `mcp_auth_profiles` table; the operator is
 *     responsible for ensuring the user is provisioned in
 *     `mysql_users` / `pgsql_users`.
 *
 * Lifetime: dial functions return a raw handle (MYSQL* / PGconn*) that
 * the caller owns.  Caller MUST `mysql_close()` / `PQfinish()` on
 * success.  On failure the handle is null and the error string is
 * populated.
 */

#ifndef PROXYSQL_GENAI_BACKEND_CLIENT_H
#define PROXYSQL_GENAI_BACKEND_CLIENT_H

#include <cstdint>
#include <string>

// Forward declarations to keep this header light.  Implementation TUs
// (backend_client.cpp / local_proxy_endpoint.cpp) include the real
// MariaDB / libpq / SQLite3 headers.
struct st_mysql;          // MariaDB connector typedef target
struct pg_conn;           // libpq typedef target
class SQLite3DB;

/**
 * @brief Per-call connection parameters supplied by the caller.
 *
 * Maps to one row of `runtime_mcp_target_profiles` joined with
 * `runtime_mcp_auth_profiles` in production callers (added in 4.D).
 * The unit test populates the struct directly.
 */
struct BackendTarget {
	/// MySQL/PgSQL user the plugin authenticates as.  Must be
	/// provisioned in proxysql's `mysql_users` / `pgsql_users` table.
	std::string user;

	/// Cleartext password.  Borrowed from the auth-profile row at dial
	/// time; not retained beyond the dial.
	std::string password;

	/// Default schema (database name).  Empty = no schema selected.
	std::string default_schema;

	/// Connect / read / write timeout in seconds.  Applied uniformly
	/// to MySQL handle options and to the libpq `connect_timeout`
	/// keyword.  Caller default: 5.
	unsigned int connect_timeout_s = 5;
};

/**
 * @brief Result of a MySQL dial.  POD-ish; caller owns `conn`.
 *
 * On success: `conn != nullptr`, `error.empty()`.  Caller MUST
 * `mysql_close(conn)` when done.
 *
 * On failure: `conn == nullptr`, `error` populated with a human-readable
 * message (suitable for proxy_error()).
 */
struct MySQLDialResult {
	st_mysql* conn = nullptr;
	std::string error;
};

/// PgSQL counterpart.  Same lifetime contract; caller MUST `PQfinish`.
struct PgSQLDialResult {
	pg_conn* conn = nullptr;
	std::string error;
};

/**
 * @brief Direct dial — caller-supplied host/port.
 *
 * This is the test-facing entry point: the unit test stands up a fake
 * listener on `127.0.0.1:0` and passes the bound port in.  Production
 * callers should prefer `dial_mysql_local` so the local proxy endpoint
 * is discovered consistently.
 *
 * @param host  IPv4/IPv6 literal or hostname.  No SRV/DNS smarts.
 * @param port  TCP port; must be > 0.
 * @param target Credentials + schema + timeout.
 * @return MySQLDialResult; check `.conn` for success.
 */
MySQLDialResult dial_mysql(const std::string& host, int port, const BackendTarget& target);

/// PgSQL counterpart of `dial_mysql`.  Same parameter semantics.
PgSQLDialResult dial_pgsql(const std::string& host, int port, const BackendTarget& target);

/**
 * @brief Dial the local ProxySQL MySQL listener.
 *
 * Reads `mysql-interfaces` from `global_variables` via `admindb`,
 * picks the first usable TCP listener, rewrites `0.0.0.0` /
 * `::` to the loopback equivalent, then calls `dial_mysql` with the
 * resolved host/port.
 *
 * @param admindb  Borrowed; must be non-null.  In the plugin lifecycle
 *                 this comes from `services->get_admindb()` and is only
 *                 valid after `start()` runs.
 * @param target   Credentials + schema + timeout.
 * @return On success, a connected handle; on failure, an empty handle
 *         and a populated error string.  Possible failure modes:
 *           - admindb is null
 *           - mysql-interfaces row absent / empty
 *           - no usable TCP listener (only Unix sockets, etc.)
 *           - auth / network error from `dial_mysql`
 */
MySQLDialResult dial_mysql_local(SQLite3DB* admindb, const BackendTarget& target);

/// PgSQL counterpart; reads `pgsql-interfaces` instead.
PgSQLDialResult dial_pgsql_local(SQLite3DB* admindb, const BackendTarget& target);

/**
 * @brief One resolved listener (host + port).
 *
 * `host` is canonicalised: `0.0.0.0` becomes `127.0.0.1`, `::` becomes
 * `::1`.  IPv6 literals are returned without surrounding brackets — the
 * dial functions add them back for libpq if needed.
 *
 * `port == 0` means "no usable TCP listener" (e.g. only Unix sockets in
 * the interfaces var); callers treat as failure.
 */
struct LocalProxyEndpoint {
	std::string host;
	int port = 0;
	bool valid() const { return port > 0 && !host.empty(); }
};

/**
 * @brief Parse an `interfaces`-style value into the first usable TCP
 *        endpoint.
 *
 * Format mirrors `mysql-interfaces` / `pgsql-interfaces`:
 * semicolon-separated `host:port` tokens, IPv6 literals as
 * `[addr]:port`, Unix sockets as a bare path with port 0.
 * `0.0.0.0` and `::` get rewritten to `127.0.0.1` / `::1`.
 *
 * Exposed in the header (separate from `resolve_*_endpoint`) so unit
 * tests can exercise the parser without standing up an admin DB.
 *
 * @param interfaces_value  Raw value of the `*-interfaces` var.
 * @return First usable endpoint; check `.valid()`.
 */
LocalProxyEndpoint parse_interfaces_first_tcp(const std::string& interfaces_value);

/**
 * @brief Look up `mysql-interfaces` from `global_variables` and pick
 *        the first usable TCP listener.
 *
 * No caching today — every call re-reads admindb.  When 4.D wires real
 * callers we may add a per-process cache invalidated on
 * `LOAD MYSQL VARIABLES TO RUNTIME`.
 *
 * @param admindb  Borrowed; must be non-null.
 * @return Endpoint; check `.valid()`.
 */
LocalProxyEndpoint resolve_mysql_endpoint(SQLite3DB* admindb);

/// PgSQL counterpart.
LocalProxyEndpoint resolve_pgsql_endpoint(SQLite3DB* admindb);

#endif /* PROXYSQL_GENAI_BACKEND_CLIENT_H */
