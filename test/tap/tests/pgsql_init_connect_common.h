/**
 * @file pgsql_init_connect_common.h
 * @brief Helpers shared by the pgsql-init_connect TAP tests.
 *
 * Every client query goes through ic_wait() with a deadline: an init_connect
 * that stalls a session must fail the test, not hang the run.
 */
#ifndef PGSQL_INIT_CONNECT_COMMON_H
#define PGSQL_INIT_CONNECT_COMMON_H

#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <poll.h>
#include <cstdio>
#include <memory>
#include <sstream>
#include <string>

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// Forces a new backend connection, so each step runs the current init_connect.
static const char* const IC_MARKER = "SELECT /* create_new_connection=1 */ current_setting('ic.marker', true)";

static PGConnPtr ic_connect(const char* host, int port, const char* user, const char* pass) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass
	   << " sslmode=disable connect_timeout=10";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK)
		diag("connect to %s:%d failed: %s", host, port, PQerrorMessage(c));
	return PGConnPtr(c, &PQfinish);
}

static PGConnPtr ic_connect_admin(const CommandLine& cl) {
	return ic_connect(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password);
}

static PGConnPtr ic_connect_client(const CommandLine& cl) {
	return ic_connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password);
}

static bool ic_admin(PGconn* admin, const std::string& sql) {
	PGresult* r = PQexec(admin, sql.c_str());
	const ExecStatusType st = PQresultStatus(r);
	const bool ok_ = st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK;
	if (!ok_) diag("admin query failed: %s -- %s", sql.c_str(), PQresultErrorMessage(r));
	PQclear(r);
	return ok_;
}

static std::string ic_admin_value(PGconn* admin, const std::string& sql) {
	PGresult* r = PQexec(admin, sql.c_str());
	std::string v;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		v = PQgetvalue(r, 0, 0);
	PQclear(r);
	return v;
}

// The server's tier, not the TAP build's: init_connect works from v3.1.
static bool ic_is_v31(PGconn* admin) {
	const std::string v = ic_admin_value(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='admin-version'");
	int major = 0, minor = 0;
	if (sscanf(v.c_str(), "%d.%d", &major, &minor) != 2)
		BAIL_OUT("Cannot determine ProxySQL build tier from admin-version '%s'", v.c_str());
	return major > 3 || (major == 3 && minor >= 1);
}

static std::string ic_literal(const std::string& v) {
	std::string out = "'";
	for (char ch : v) {
		if (ch == '\'') out += '\'';
		out += ch;
	}
	return out + "'";
}

static bool ic_set_global(PGconn* admin, const std::string& value) {
	return ic_admin(admin, "UPDATE global_variables SET variable_value=" + ic_literal(value) +
		" WHERE variable_name='pgsql-init_connect'") &&
		ic_admin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

struct IcResult {
	bool timed_out = false;
	bool ok = false;               // no error result and the command was sent
	std::string sqlstate;          // SQLSTATE of the first error
	std::string value;             // first cell of the last tuples result
	unsigned long long elapsed_ms = 0;
};

// Collects every result of the command already sent on `c`, up to `timeout_ms`
// after `start_us` (monotonic_time()).
static IcResult ic_wait(PGconn* c, int timeout_ms, unsigned long long start_us) {
	IcResult res;
	bool error = false;
	const unsigned long long deadline = start_us + (unsigned long long)timeout_ms * 1000;
	while (true) {
		while (PQisBusy(c)) {
			const unsigned long long now = monotonic_time();
			if (now >= deadline) {
				res.timed_out = true;
				res.elapsed_ms = (now - start_us) / 1000;
				diag("query timed out after %llu ms", res.elapsed_ms);
				return res;
			}
			struct pollfd pfd = { PQsocket(c), POLLIN, 0 };
			poll(&pfd, 1, (int)((deadline - now) / 1000) + 1);
			if (PQconsumeInput(c) == 0) break;   // connection closed: PQgetResult reports it
		}
		PGresult* r = PQgetResult(c);
		if (r == NULL) break;
		const ExecStatusType st = PQresultStatus(r);
		if (st == PGRES_FATAL_ERROR || st == PGRES_NONFATAL_ERROR) {
			if (!error) {
				const char* s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
				res.sqlstate = s ? s : "";
				diag("query error: %s", PQresultErrorMessage(r));
			}
			error = true;
		} else if (st == PGRES_TUPLES_OK && PQntuples(r) > 0) {
			res.value = PQgetisnull(r, 0, 0) ? "" : PQgetvalue(r, 0, 0);
		}
		PQclear(r);
		if (PQstatus(c) == CONNECTION_BAD) { error = true; break; }
	}
	res.ok = !error;
	res.elapsed_ms = (monotonic_time() - start_us) / 1000;
	return res;
}

static IcResult ic_query(PGconn* c, const std::string& sql, int timeout_ms = 10000) {
	const unsigned long long start = monotonic_time();
	if (!PQsendQuery(c, sql.c_str())) {
		diag("PQsendQuery failed: %s", PQerrorMessage(c));
		return IcResult();
	}
	return ic_wait(c, timeout_ms, start);
}

// Unnamed statement over the extended protocol (Parse/Bind/Describe/Execute/Sync).
static IcResult ic_query_extended(PGconn* c, const std::string& sql, int timeout_ms = 10000) {
	const unsigned long long start = monotonic_time();
	if (!PQsendQueryParams(c, sql.c_str(), 0, NULL, NULL, NULL, NULL, 0)) {
		diag("PQsendQueryParams failed: %s", PQerrorMessage(c));
		return IcResult();
	}
	return ic_wait(c, timeout_ms, start);
}

#endif // PGSQL_INIT_CONNECT_COMMON_H
