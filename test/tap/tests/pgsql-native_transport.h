/**
 * @file pgsql-native_transport.h
 * @brief Runs a native-vs-libpq differential corpus once per transport (plain, TLS).
 *
 * WHY
 * ---
 * The differential corpora (query, transactions, COPY, prepared, portals,
 * streaming) used to connect with sslmode=disable towards ProxySQL and with
 * use_ssl=0 towards PostgreSQL, so none of the native path's TLS code was
 * reached by them: the buffered TLS writes, partial-send recovery, the
 * WANT_READ/WANT_WRITE edges, and large results streamed through SSL_read
 * (issue #5905). Instead of a second test group, each test loops over
 * NATIVE_TRANSPORTS in the same run.
 *
 * USAGE
 * -----
 *   plan(NATIVE_TRANSPORT_COUNT * (per_transport_assertions + NATIVE_TRANSPORT_CHECKS));
 *   for (size_t t = 0; t < NATIVE_TRANSPORT_COUNT; t++) {
 *       native_transport_select(t);
 *       // client conninfo uses native_client_sslmode();
 *       // the pgsql_servers INSERT uses native_backend_use_ssl();
 *       ok_native_transport(admin, hg, [&]{ ... native mode on, pool flushed ... }, open_client, true);
 *       ... existing corpus ...
 *   }
 *   native_transport_select(0);   // restore the plain transport before the final pool flush
 *
 * The TLS row encrypts BOTH legs. Mixed combinations are covered by
 * pgsql-native_ssl_pool_reuse-t, and COPY with only the backend leg encrypted by
 * pgsql-native_copy_tls_differential-t.
 */
#ifndef PGSQL_NATIVE_TRANSPORT_H
#define PGSQL_NATIVE_TRANSPORT_H

#include <string>
#include <sstream>
#include <unistd.h>

#include "libpq-fe.h"
#include "tap.h"

struct NativeTransport {
	const char* name;
	int backend_use_ssl;  // pgsql_servers.use_ssl: ProxySQL -> PostgreSQL leg
	bool client_tls;      // sslmode=require: client -> ProxySQL leg
};

static const NativeTransport NATIVE_TRANSPORTS[] = {
	{ "plain", 0, false },
	{ "tls",   1, true  },
};
static const size_t NATIVE_TRANSPORT_COUNT = sizeof(NATIVE_TRANSPORTS) / sizeof(NATIVE_TRANSPORTS[0]);

// Assertions emitted by ok_native_transport() per transport.
static const int NATIVE_TRANSPORT_CHECKS = 1;

static const NativeTransport* g_native_transport = &NATIVE_TRANSPORTS[0];

inline void native_transport_select(size_t i) {
	g_native_transport = &NATIVE_TRANSPORTS[i];
	diag("======== transport '%s': backend use_ssl=%d, client sslmode=%s ========",
	     g_native_transport->name, g_native_transport->backend_use_ssl,
	     g_native_transport->client_tls ? "require" : "disable");
}

inline const char* native_transport_name() { return g_native_transport->name; }
inline const char* native_client_sslmode() { return g_native_transport->client_tls ? "require" : "disable"; }
inline int native_backend_use_ssl() { return g_native_transport->backend_use_ssl; }

// "[tls] label", so the TAP lines of the two passes stay distinguishable.
inline std::string native_transport_label(const std::string& label) {
	return std::string("[") + g_native_transport->name + "] " + label;
}

inline std::string native_transport_scalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string out;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0)) {
		out = PQgetvalue(r, 0, 0);
	}
	PQclear(r);
	return out;
}

// Asks PostgreSQL whether the backend connection running this query is
// encrypted. ProxySQL intercepts pg_backend_pid(), so the backend session is
// found through a marker in the query text instead, as in
// pgsql-native_copy_tls_differential-t. Returns "t", "f" or "" (not found).
inline std::string native_backend_leg_ssl(PGconn* client) {
	return native_transport_scalar(client,
		"SELECT s.ssl FROM pg_stat_ssl s JOIN pg_stat_activity a ON s.pid = a.pid"
		" WHERE a.state = 'active' AND a.query LIKE '%native_transport_self_marker%' LIMIT 1");
}

// Every free connection in hostgroup `hg` must report native_mode=true. A silent
// fallback to libpq would make the TLS pass meaningless, and the log-based
// fallback check is not sufficient on its own (the capability-gap warning is
// logged once per worker thread). Polls, because returning a connection to the
// pool is asynchronous. Returns "" on success, otherwise a diagnostic.
inline std::string native_pool_mode_problem(PGconn* admin, int hg) {
	const std::string q = "SELECT pgsql_info FROM stats_pgsql_free_connections WHERE hostgroup="
		+ std::to_string(hg);
	for (int waited = 0; waited <= 5000; waited += 100) {
		PGresult* r = PQexec(admin, q.c_str());
		const int n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
		if (n > 0) {
			int native = 0, other = 0;
			for (int i = 0; i < n; i++) {
				const std::string info = PQgetvalue(r, i, 0);
				if (info.find("\"native_mode\":true") != std::string::npos) native++;
				else other++;
			}
			PQclear(r);
			if (other == 0) return "";
			std::stringstream ss;
			ss << "pool has " << other << " non-native connection(s) and " << native << " native";
			return ss.str();
		}
		PQclear(r);
		usleep(100000);
	}
	return "no free connection appeared in the pool";
}

/**
 * One assertion that the current transport is really in effect on the native path.
 *
 * @param prepare      puts ProxySQL in native mode and recreates the server rows
 *                     (so no connection built under the previous transport survives).
 * @param open_client  returns a smart pointer to a libpq client connection to ProxySQL.
 * @param check_client whether the client leg is expected to follow client_tls; false for
 *                     tests whose corpus uses a raw client that cannot speak TLS.
 */
template <typename PrepareFn, typename OpenFn>
void ok_native_transport(PGconn* admin, int hg, PrepareFn prepare, OpenFn open_client, bool check_client) {
	const NativeTransport& t = *g_native_transport;
	std::string problem;
	if (!prepare()) {
		problem = "could not enable native mode / recreate the server rows";
	} else {
		auto client = open_client();
		if (!client || PQstatus(client.get()) != CONNECTION_OK) {
			problem = std::string("client connection failed: ") + (client ? PQerrorMessage(client.get()) : "null");
		} else {
			const bool client_tls = PQsslInUse(client.get()) == 1;
			const std::string backend_ssl = native_backend_leg_ssl(client.get());
			const std::string want_ssl = t.backend_use_ssl ? "t" : "f";
			if (check_client && client_tls != t.client_tls) {
				problem = std::string("client leg TLS=") + (client_tls ? "on" : "off");
			} else if (backend_ssl != want_ssl) {
				problem = "backend leg pg_stat_ssl.ssl='" + backend_ssl + "', expected '" + want_ssl + "'";
			}
			client.reset();
			if (problem.empty()) problem = native_pool_mode_problem(admin, hg);
		}
	}
	ok(problem.empty(), "[%s] transport in effect on the native path (backend use_ssl=%d%s)%s%s",
	   t.name, t.backend_use_ssl,
	   check_client ? (t.client_tls ? ", client TLS" : ", client plain") : ", client leg not checked",
	   problem.empty() ? "" : " -- ", problem.c_str());
}

#endif // PGSQL_NATIVE_TRANSPORT_H
