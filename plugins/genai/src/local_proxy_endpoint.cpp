/**
 * @file local_proxy_endpoint.cpp
 * @brief Resolve the local ProxySQL listener (host, port) from admindb.
 *
 * Reads `mysql-interfaces` / `pgsql-interfaces` from `global_variables`
 * and parses out the first usable TCP listener.  The format mirrors
 * what `MySQL_Thread::listener_add` parses (see lib/MySQL_Thread.cpp
 * around L240 for the canonical parser): semicolon-separated tokens,
 * each `host:port` (IPv6 wrapped in `[…]`).  A bare path with no
 * trailing `:port` is a Unix socket and is skipped here — tool handlers
 * over a Unix socket would need a different code path.
 *
 * No caching today.  Every call hits sqlite3.  This is fine for 4.B
 * (zero callers) and 4.C/4.D's first cut (low call volume — endpoint is
 * read once per connection-pool init).  Caching can be added later.
 */

#include "backend_client.h"
#include "sqlite3db.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

/// Semicolon-tokenise; trim leading/trailing whitespace from each token.
std::vector<std::string> split_semi(const std::string& s) {
	std::vector<std::string> out;
	std::size_t start = 0;
	while (start <= s.size()) {
		std::size_t pos = s.find(';', start);
		std::string tok = (pos == std::string::npos)
			? s.substr(start)
			: s.substr(start, pos - start);
		// trim
		std::size_t a = tok.find_first_not_of(" \t");
		std::size_t b = tok.find_last_not_of(" \t");
		if (a != std::string::npos) {
			out.emplace_back(tok.substr(a, b - a + 1));
		}
		if (pos == std::string::npos) break;
		start = pos + 1;
	}
	return out;
}

/**
 * Parse one `host:port` token (or `[ipv6]:port`).  Returns a usable
 * LocalProxyEndpoint, or `{}` if the token isn't a TCP listener.
 *
 * Canonicalises wildcard hosts to loopback so the result is dial-able
 * from this process: `0.0.0.0` → `127.0.0.1`, `::` → `::1`.
 */
LocalProxyEndpoint parse_token(const std::string& tok) {
	if (tok.empty()) return {};

	std::string host;
	std::string port_s;

	if (tok.front() == '[') {
		// IPv6 literal: [addr]:port
		std::size_t close = tok.find(']');
		if (close == std::string::npos) return {};
		host = tok.substr(1, close - 1);
		if (close + 1 >= tok.size() || tok[close + 1] != ':') return {};
		port_s = tok.substr(close + 2);
	} else {
		std::size_t colon = tok.rfind(':');
		if (colon == std::string::npos) return {};  // Unix socket path; skip.
		host = tok.substr(0, colon);
		port_s = tok.substr(colon + 1);
	}

	if (host.empty() || port_s.empty()) return {};
	int port = std::atoi(port_s.c_str());
	if (port <= 0 || port > 65535) return {};

	if (host == "0.0.0.0") host = "127.0.0.1";
	else if (host == "::" || host == "::0") host = "::1";

	LocalProxyEndpoint ep;
	ep.host = std::move(host);
	ep.port = port;
	return ep;
}

/**
 * Read `variable_value` from `global_variables` for the given variable
 * name.  Returns the value as a std::string; empty if the row is
 * missing, the value is NULL, or the query errors out (a logged error
 * message would be visible to the operator via the proxy log; here we
 * silently return empty so the caller treats the situation uniformly).
 *
 * `var_name` is bound as a parameter rather than concatenated into the
 * SQL.  Today the only callers pass hardcoded `mysql-interfaces` /
 * `pgsql-interfaces`, so the SQL injection surface is zero — but a
 * future caller passing operator-controlled input shouldn't have to
 * audit this helper to stay safe.
 */
std::string read_global_variable(SQLite3DB* admindb, const char* var_name) {
	if (admindb == nullptr || var_name == nullptr) return {};

	auto [prep_rc, stmt] = admindb->prepare_v2(
		"SELECT variable_value FROM main.global_variables WHERE variable_name = ?1"
	);
	if (prep_rc != SQLITE_OK) return {};

	sqlite3_stmt* st = stmt.get();
	(*proxy_sqlite3_bind_text)(st, 1, var_name, -1, SQLITE_TRANSIENT);

	std::string value;
	const int step_rc = (*proxy_sqlite3_step)(st);
	if (step_rc == SQLITE_ROW) {
		const unsigned char* col = (*proxy_sqlite3_column_text)(st, 0);
		if (col != nullptr) value.assign(reinterpret_cast<const char*>(col));
	}
	// SQLITE_DONE on no match, anything else (BUSY/ERROR) → return empty
	// string with no logging — same semantics as the previous body.
	return value;
}

} // namespace

LocalProxyEndpoint parse_interfaces_first_tcp(const std::string& interfaces_value) {
	if (interfaces_value.empty()) return {};
	for (const auto& tok : split_semi(interfaces_value)) {
		LocalProxyEndpoint ep = parse_token(tok);
		if (ep.valid()) return ep;
	}
	return {};
}

LocalProxyEndpoint resolve_mysql_endpoint(SQLite3DB* admindb) {
	return parse_interfaces_first_tcp(read_global_variable(admindb, "mysql-interfaces"));
}

LocalProxyEndpoint resolve_pgsql_endpoint(SQLite3DB* admindb) {
	return parse_interfaces_first_tcp(read_global_variable(admindb, "pgsql-interfaces"));
}
