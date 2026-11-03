/**
 * @file pgsql-reg_test_6569_timezone_validation-t.cpp
 * @brief Regression #6569: TimeZone values were not checked.
 *
 * ProxySQL accepted any TimeZone value: at login, in options, with SET and in
 * pgsql-default_timezone. A value PostgreSQL refuses, such as a quoted 'UTC' or
 * 'America/New York', only failed when ProxySQL applied it to a backend connection, and
 * then every later query of the session failed. ProxySQL now refuses what can never be a
 * time zone where the client sends it. Whether a well-formed name exists is still the
 * backend's decision.
 *
 * Every value is also sent to PostgreSQL directly, and both must accept it or both must
 * refuse it. The one expected difference is a number of hours with a leading or trailing
 * space, which PostgreSQL accepts and ProxySQL refuses. Values that ProxySQL accepts and
 * PostgreSQL refuses (Invalid/Zone, PST) are not sent: the backend still catches those
 * only on a later query.
 *
 * An INTERVAL time zone cannot be applied again on another backend connection. A SET with
 * one goes to the backend as written and the client keeps that connection; at login and
 * in pgsql-default_timezone it is refused. SET TIME ZONE LOCAL is handled as DEFAULT.
 */

#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "libpq-fe.h"
#include "mysql.h"
#include "command_line.h"
#include "tap.h"

CommandLine cl;

using PGConn = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using PGResult = std::unique_ptr<PGresult, decltype(&PQclear)>;

static const char* REFUSED = "invalid value for parameter \"TimeZone\"";

static PGConn connect_to(const char* host, int port, const char* user, const char* pass, const std::string& extra,
	std::string* error = nullptr) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass
	   << " sslmode=disable connect_timeout=10 " << extra;
	PGConn conn(PQconnectdb(ss.str().c_str()), &PQfinish);
	if (PQstatus(conn.get()) != CONNECTION_OK) {
		if (error) *error = PQerrorMessage(conn.get());
		else diag("Connection to %s:%d with '%s' failed: %s", host, port, extra.c_str(), PQerrorMessage(conn.get()));
		conn.reset();
	}
	return conn;
}

static PGConn connect_proxy(const std::string& extra, std::string* error = nullptr) {
	return connect_to(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, extra, error);
}

static PGConn connect_backend(const std::string& extra, std::string* error = nullptr) {
	return connect_to(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username,
		cl.pgsql_server_password, "dbname=postgres " + extra, error);
}

// Runs a statement; on failure, stores the error text in *error.
static bool exec_ok(PGconn* conn, const std::string& sql, std::string* error = nullptr) {
	if (!conn) return false;
	PGResult res(PQexec(conn, sql.c_str()), &PQclear);
	const ExecStatusType st = PQresultStatus(res.get());
	if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
		if (error) *error = PQerrorMessage(conn);
		return false;
	}
	return true;
}

static std::string shown_timezone(PGconn* conn) {
	if (!conn) return "";
	PGResult res(PQexec(conn, "SHOW TimeZone"), &PQclear);
	if (PQresultStatus(res.get()) != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
		diag("SHOW TimeZone failed: %s", PQerrorMessage(conn));
		return "";
	}
	return PQgetvalue(res.get(), 0, 0);
}

static std::string set_statement(const std::string& value) {
	std::string sql = "SET TimeZone = '";
	for (char c : value) {
		if (c == '\'') sql += '\'';
		sql += c;
	}
	return sql + "'";
}

static std::string printable(const std::string& value) {
	std::string out;
	for (char c : value) out += (c == '\t') ? std::string("\\t") : std::string(1, c);
	return out.size() > 40 ? out.substr(0, 20) + "...(" + std::to_string(value.size()) + " chars)" : out;
}

// Every zone name the backend knows must be accepted, applied to the backend connection,
// and shown as PostgreSQL shows it. Read from the backend, so the list follows its version.
static void check_every_zone_name() {
	PGConn direct = connect_backend("");
	PGConn proxy = connect_proxy("");
	std::vector<std::string> names;
	if (direct) {
		PGResult res(PQexec(direct.get(), "SELECT name FROM pg_timezone_names ORDER BY name"), &PQclear);
		for (int i = 0; PQresultStatus(res.get()) == PGRES_TUPLES_OK && i < PQntuples(res.get()); i++) {
			names.emplace_back(PQgetvalue(res.get(), i, 0));
		}
	}

	int checked = 0;
	int failed = 0;
	for (const std::string& name : names) {
		const std::string set = set_statement(name);
		// A name PostgreSQL itself refuses is not sent: ProxySQL would accept it and only
		// the backend would catch it, on a later query.
		if (!exec_ok(direct.get(), set)) continue;
		const std::string expected = shown_timezone(direct.get());
		std::string error;
		const bool set_ok = exec_ok(proxy.get(), set, &error);
		const std::string got = set_ok ? shown_timezone(proxy.get()) : "";
		checked++;
		// shown_timezone() gives "" when SHOW fails, so an empty value is a failure, never a match.
		if (expected.empty() || got != expected) {
			failed++;
			diag("'%s': ProxySQL %s, PostgreSQL shows '%s'", name.c_str(),
				set_ok ? ("shows '" + got + "'").c_str() : ("refused it: " + error).c_str(), expected.c_str());
			// A value the backend refused on this session makes every later query fail.
			if (set_ok) break;
		}
	}
	ok(proxy && checked > 0 && failed == 0,
		"All %d zone names in pg_timezone_names are accepted and shown as PostgreSQL shows them (%zu listed, %d failed)",
		checked, names.size(), failed);
}

// Values of each form, sent with SET to PostgreSQL and to ProxySQL: both must accept or both
// must refuse, and after a refusal the session must keep working. Zone names are only ones every
// tzdata release has: old names such as EST or US/Eastern are missing on newer systems.
static void check_samples() {
	const std::vector<std::string> accepted = {
		// zone names, in any case, with the optional leading ':'
		"UTC", "utc", "Etc/UTC", "Europe/Berlin", "EUROPE/BERLIN", "America/Argentina/Buenos_Aires",
		"America/Port-au-Prince", "Etc/GMT+3", "Etc/GMT-14", ":UTC",
		// POSIX rules
		"PST8PDT", "EST5EDT,M3.2.0,M11.1.0", "EST5EDT,M3.2.0/2,M11.1.0/2:00:00", "CET-1CEST,M3.5.0,M10.5.0/3",
		"EST5EDT,J60,J300", "UTC+3", "UTC+03:30", "<-03>3", "<+0330>-3:30", "<+03>3<+04>,M3.2.0,M11.1.0",
		// hours, up to just under 168
		"0", "-7", "+7", "5.5", "-3.5", ".5", "1e1", "0x5", "167", "-167.99",
		// intervals, which go to the backend as written
		"INTERVAL '+02:30'", "INTERVAL '2 hours'", "INTERVAL'1'", "INTERVAL '@ 2 hours'",
	};
	const std::vector<std::string> refused = {
		"'UTC'", "\"UTC\"", "America/New York", "UTC\t", " UTC", "UTC ", "UTC;", "UTC$", "Europe/Z\xC3\xBCrich",
		std::string(256, 'A'),
		// hours PostgreSQL refuses
		"168", "-168", "inf", "nan", "1e400",
		// paths that can never name a zone file
		"/etc/localtime", ":/etc/localtime", "Europe//Rome", "../UTC", "Europe/../Europe/Rome", ":", "::UTC",
		// a POSIX abbreviation opened with '<' and never closed
		"<+03", "<+03>3<+04", "UTC<",
		// intervals, refused by the backend they are sent to
		"INTERVAL '-08:00' HOUR TO MINUTE", "INTERVAL '1''2'", "INTERVAL+3",
	};
	// PostgreSQL reads these as a number of hours; ProxySQL refuses them.
	const std::vector<std::string> refused_by_proxysql_only = { " 5", "5 ", "\t5" };

	PGConn direct = connect_backend("");
	auto run = [&](const std::string& value, bool pg_accepts, bool proxysql_accepts) {
		const std::string set = set_statement(value);
		const bool pg_ok = exec_ok(direct.get(), set);
		const std::string expected = pg_ok ? shown_timezone(direct.get()) : "";

		PGConn proxy = connect_proxy("");
		std::string error;
		const bool proxy_ok = exec_ok(proxy.get(), set, &error);
		// Without the direct connection pg_ok is false, which would match every refusal.
		bool good = direct && pg_ok == pg_accepts && proxy_ok == proxysql_accepts;
		if (proxy_ok) {
			good = good && !expected.empty() && shown_timezone(proxy.get()) == expected;
		} else {
			good = good && error.find(REFUSED) != std::string::npos && exec_ok(proxy.get(), "SELECT 1");
		}
		if (!good) {
			diag("'%s': PostgreSQL %s, ProxySQL %s %s", printable(value).c_str(), pg_ok ? "accepted" : "refused",
				proxy_ok ? "accepted" : "refused", error.c_str());
		}
		ok(good, "SET TimeZone = '%s': PostgreSQL %s, ProxySQL %s%s", printable(value).c_str(),
			pg_accepts ? "accepts" : "refuses", proxysql_accepts ? "accepts" : "refuses",
			proxysql_accepts ? "" : " and the session keeps working");
	};
	for (const std::string& v : accepted) run(v, true, true);
	for (const std::string& v : refused) run(v, false, false);
	for (const std::string& v : refused_by_proxysql_only) run(v, true, false);
}

// A quoted login value is refused at login, as PostgreSQL does, both as a startup
// parameter (PGTZ) and in options.
static void check_login_refused() {
	setenv("PGTZ", "'UTC'", 1);
	std::string pg_error, proxy_error;
	const bool pg_refused = !connect_backend("", &pg_error);
	const bool proxy_refused = !connect_proxy("", &proxy_error);
	unsetenv("PGTZ");
	// PostgreSQL's own error is checked too: a login that failed for another reason, such as
	// PostgreSQL being unreachable, would otherwise count as refused.
	ok(pg_refused && pg_error.find(REFUSED) != std::string::npos && proxy_refused && proxy_error.find(REFUSED) != std::string::npos,
		"Login with PGTZ='UTC' (quoted) is refused at login, as by PostgreSQL (%s)", proxy_error.c_str());

	const std::string options = "options='-c TimeZone=\\'UTC\\''";
	const bool pg_refused2 = !connect_backend(options, &pg_error);
	const bool proxy_refused2 = !connect_proxy(options, &proxy_error);
	ok(pg_refused2 && pg_error.find(REFUSED) != std::string::npos && proxy_refused2 && proxy_error.find(REFUSED) != std::string::npos,
		"Login with options -c TimeZone='UTC' (quoted) is refused at login, as by PostgreSQL (%s)", proxy_error.c_str());
}

// Login values, as a startup parameter (PGTZ) and in options. An accepted one must leave the
// value PostgreSQL leaves; a refused one must be refused at login, not on the first query.
static void check_login_values() {
	const std::vector<std::pair<std::string, bool>> values = {
		{ "Europe/Berlin", true }, { "utc", true }, { "-7", true }, { "EST5EDT,M3.2.0,M11.1.0", true },
		{ "<+0330>-3:30", true }, { "0x5", true }, { "168", false }, { "/etc/localtime", false }, { "LOCAL", false },
	};
	for (const auto& [value, accepted] : values) {
		for (const bool as_option : { false, true }) {
			const std::string extra = as_option ? "options='-c TimeZone=" + value + "'" : "";
			if (!as_option) setenv("PGTZ", value.c_str(), 1);
			std::string pg_error, proxy_error;
			PGConn direct = connect_backend(extra, &pg_error);
			PGConn proxy = connect_proxy(extra, &proxy_error);
			unsetenv("PGTZ");
			const std::string expected = shown_timezone(direct.get());
			const std::string got = shown_timezone(proxy.get());
			const bool good = accepted
				? direct && proxy && !expected.empty() && got == expected
				: !direct && pg_error.find(REFUSED) != std::string::npos && !proxy && proxy_error.find(REFUSED) != std::string::npos;
			if (!good) {
				diag("'%s': PostgreSQL %s, ProxySQL %s", value.c_str(), direct ? ("shows '" + expected + "'").c_str() : pg_error.c_str(),
					proxy ? ("shows '" + got + "'").c_str() : proxy_error.c_str());
			}
			ok(good, "Login with %s TimeZone=%s: %s", as_option ? "options -c" : "PGTZ", value.c_str(),
				accepted ? "applied as by PostgreSQL" : "refused at login, as by PostgreSQL");
		}
	}
}

// An INTERVAL login value is refused at login, as a startup parameter and in options. PostgreSQL
// accepts it, but ProxySQL could not apply it again on the next backend connection.
static void check_login_interval_refused() {
	for (const bool as_option : { false, true }) {
		if (as_option) setenv("PGOPTIONS", "-c TimeZone=INTERVAL\\ \\'+02:30\\'", 1);
		else setenv("PGTZ", "INTERVAL '+02:30'", 1);
		std::string pg_error, proxy_error;
		PGConn direct = connect_backend("", &pg_error);
		PGConn proxy = connect_proxy("", &proxy_error);
		unsetenv("PGTZ");
		unsetenv("PGOPTIONS");
		const std::string shown = shown_timezone(direct.get());
		const bool good = direct && shown == "<+02:30>-02:30" && !proxy && proxy_error.find(REFUSED) != std::string::npos;
		if (!good) {
			diag("PostgreSQL %s, ProxySQL %s", direct ? ("shows '" + shown + "'").c_str() : pg_error.c_str(),
				proxy ? "accepted it" : proxy_error.c_str());
		}
		ok(good, "Login with %s TimeZone=INTERVAL '+02:30': PostgreSQL accepts, ProxySQL refuses at login",
			as_option ? "options -c" : "PGTZ");
	}
}

// The statement forms of SET, on PostgreSQL and through ProxySQL. An accepted one must leave the
// same value on both. DEFAULT, RESET and LOCAL must bring back the value the session started with, which
// through ProxySQL is pgsql-default_timezone. A refused one must leave the session and its value.
static void check_statements() {
	struct Case { const char* sql; bool accepted; bool resets; };
	const std::vector<Case> cases = {
		{ "SET TIME ZONE 'Europe/Berlin'", true, false },
		{ "set time zone 'Europe/Berlin'", true, false },
		{ "SET timezone TO 'Europe/Berlin'", true, false },
		{ "SET TimeZone = \"Europe/Berlin\"", true, false },
		{ "SET TimeZone = 'Europe/Berlin';", true, false },
		{ "SET /* note */ TimeZone = 'Europe/Berlin'", true, false },
		{ "SET TIME ZONE UTC", true, false },
		{ "SET TimeZone = utc", true, false },
		{ "SET TIME ZONE -7", true, false },
		{ "SET TIME ZONE +5.5", true, false },
		{ "SET TimeZone TO 5.5", true, false },
		{ "SET TIME ZONE DEFAULT", true, true },
		{ "SET TimeZone TO DEFAULT", true, true },
		{ "RESET TimeZone", true, true },
		{ "RESET TIME ZONE", true, true },
		// SET TIME ZONE LOCAL means DEFAULT; LOCAL as a value is refused
		{ "SET TIME ZONE LOCAL", true, true },
		{ "SET TIME ZONE LOCAL;", true, true },
		{ "SET TimeZone = LOCAL", false, false },
		{ "SET TimeZone = 'LOCAL'", false, false },
		{ "SET TIME ZONE '168'", false, false },
		{ "SET TimeZone = 'Europe/Berlin', 'UTC'", false, false },
	};
	for (const Case& c : cases) {
		PGConn direct = connect_backend("");
		PGConn proxy = connect_proxy("");
		const std::string direct_start = shown_timezone(direct.get());
		const std::string proxy_start = shown_timezone(proxy.get());
		// DEFAULT, RESET and LOCAL are sent after a change, so they have something to undo.
		bool changed = true;
		if (c.resets) {
			changed = exec_ok(direct.get(), "SET TimeZone = 'America/Port-au-Prince'")
				&& exec_ok(proxy.get(), "SET TimeZone = 'America/Port-au-Prince'")
				&& shown_timezone(proxy.get()) != proxy_start;
		}
		std::string error;
		const bool pg_ok = exec_ok(direct.get(), c.sql);
		const bool proxy_ok = exec_ok(proxy.get(), c.sql, &error);
		const std::string pg_value = shown_timezone(direct.get());
		const std::string proxy_value = shown_timezone(proxy.get());
		bool good = changed && !direct_start.empty() && !proxy_start.empty() && pg_ok == c.accepted && proxy_ok == c.accepted;
		if (c.resets) {
			good = good && pg_value == direct_start && proxy_value == proxy_start;
		} else if (c.accepted) {
			good = good && !pg_value.empty() && proxy_value == pg_value;
		} else {
			good = good && proxy_value == proxy_start;
		}
		if (!good) {
			diag("%s: PostgreSQL %s ('%s'), ProxySQL %s ('%s', started '%s') %s", c.sql, pg_ok ? "accepted" : "refused",
				pg_value.c_str(), proxy_ok ? "accepted" : "refused", proxy_value.c_str(), proxy_start.c_str(), error.c_str());
		}
		ok(good, "%s: %s", c.sql, c.resets ? "both go back to the session's starting value"
			: (c.accepted ? "both accept it and show the same value" : "both refuse it and the session keeps its value"));
	}
}

// SET TIME ZONE LOCAL, DEFAULT and RESET go back to the client's own default, here its startup
// TimeZone. The pooled backend connection was usually opened for another client, so a reset left
// to the backend would land on that client's default instead.
static void check_reset_to_client_default() {
	const char* startup = "America/Port-au-Prince";
	int checked = 0, wrong = 0;
	for (const char* reset : { "SET TIME ZONE LOCAL", "SET TIME ZONE DEFAULT", "RESET TimeZone" }) {
		setenv("PGTZ", startup, 1);
		PGConn direct = connect_backend("");
		PGConn proxy = connect_proxy("");
		unsetenv("PGTZ");
		const std::string start = shown_timezone(direct.get());
		for (PGconn* c : { direct.get(), proxy.get() }) {
			const bool sent = exec_ok(c, "SET TimeZone = 'Europe/Berlin'") && exec_ok(c, reset);
			const std::string got = shown_timezone(c);
			checked++;
			if (!sent || start.empty() || got != start) {
				wrong++;
				diag("%s on %s: expected '%s', got '%s'", reset, c == direct.get() ? "PostgreSQL" : "ProxySQL",
					start.c_str(), got.c_str());
			}
		}
	}
	ok(checked == 6 && wrong == 0, "LOCAL, DEFAULT and RESET go back to the client's startup TimeZone, as on PostgreSQL (%d wrong)",
		wrong);
}

// Clients with different time zones share the pooled backend connections, so ProxySQL has to
// apply each client's value before each of its queries. Every query must see its own client's.
static void check_clients_keep_their_value() {
	const std::vector<std::string> zones = { "Europe/Berlin", "America/Port-au-Prince", "-7" };
	PGConn direct = connect_backend("");
	std::vector<PGConn> clients;
	std::vector<std::string> expected;
	for (const std::string& zone : zones) {
		expected.push_back(exec_ok(direct.get(), set_statement(zone)) ? shown_timezone(direct.get()) : "");
		clients.push_back(connect_proxy(""));
		exec_ok(clients.back().get(), set_statement(zone));
	}
	int checked = 0, wrong = 0;
	for (int round = 0; round < 10; round++) {
		for (size_t i = 0; i < clients.size(); i++) {
			const std::string got = shown_timezone(clients[i].get());
			checked++;
			if (expected[i].empty() || got != expected[i]) {
				wrong++;
				diag("Client %zu: expected '%s', got '%s'", i, expected[i].c_str(), got.c_str());
			}
		}
	}
	ok(checked == 30 && wrong == 0, "Three clients with different time zones each keep their own over 10 rounds (%d checked, %d wrong)",
		checked, wrong);
}

static MYSQL* admin = nullptr;

static bool admin_exec(const std::string& sql) {
	if (mysql_query(admin, sql.c_str())) {
		diag("Admin query failed: %s; SQL: %s", mysql_error(admin), sql.c_str());
		return false;
	}
	return true;
}

static std::string admin_value(const std::string& sql) {
	std::string ret;
	if (!admin_exec(sql)) return ret;
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	if (row && row[0]) ret = row[0];
	mysql_free_result(res);
	return ret;
}

// Backend connections in use, over the whole pool.
static std::string conn_used() {
	return admin_value("SELECT IFNULL(SUM(ConnUsed),0) FROM stats_pgsql_connection_pool");
}

// INTERVAL time zones, as statements and as strings, on PostgreSQL and through ProxySQL. An
// accepted one must show PostgreSQL's value on every later query and never reach another
// client, which only holds if the client kept its backend connection. A refused one gets the
// backend's error, and the session keeps working with its value. Either way the client keeps
// its backend connection while idle, which the pool's in-use count shows directly.
static void check_interval_forwarded() {
	const std::vector<std::pair<std::string, bool>> statements = {
		{ "SET TIME ZONE INTERVAL '+02:30' HOUR TO MINUTE", true },
		{ "SET TIME ZONE INTERVAL '+02:30' HOUR", true },
		{ "SET TIME ZONE INTERVAL '+02:30' MINUTE", true },
		{ "SET TIME ZONE INTERVAL '2' HOUR", true },
		{ "SET TIME ZONE INTERVAL '30' MINUTE", true },
		{ "SET TIME ZONE INTERVAL '2 hours'", true },
		{ "SET TIME ZONE INTERVAL(2) '+02:30'", true },
		{ "set session time zone interval '-08:00' hour to minute", true },
		{ "SET TimeZone = 'INTERVAL ''+02:30'''", true },
		{ "SET TIME ZONE 'interval ''1 hour 30 minutes'''", true },
		{ "SET TIME ZONE INTERVAL '+02:30' DAY", false },
		{ "SET TIME ZONE INTERVAL '+02:30' FOO", false },
		{ "SET TIME ZONE INTERVAL '1' HOUR TO SECOND", false },
		{ "SET TIME ZONE INTERVAL '1 day'", false },
		{ "SET TimeZone = 'INTERVAL ''1 day'''", false },
	};
	for (const auto& [sql, pg_accepts] : statements) {
		// The previous case's connections are released once ProxySQL has seen its clients go.
		for (int i = 0; i < 50 && conn_used() != "0"; i++) usleep(100000);
		PGConn direct = connect_backend("");
		PGConn proxy = connect_proxy("");
		PGConn other = connect_proxy("");
		const std::string proxy_start = shown_timezone(proxy.get());
		const std::string other_start = shown_timezone(other.get());
		const bool pg_ok = exec_ok(direct.get(), sql);
		std::string error;
		const bool proxy_ok = exec_ok(proxy.get(), sql, &error);
		const std::string expected = pg_ok ? shown_timezone(direct.get()) : proxy_start;
		// Each round also runs a query for the other client, so pooled connections change hands.
		int wrong = 0;
		for (int round = 0; round < 5; round++) {
			if (shown_timezone(proxy.get()) != expected) wrong++;
			if (shown_timezone(other.get()) != other_start) wrong++;
		}
		// Both clients are idle now, and the other one's connection went back to the pool after each
		// query: a connection still in use is this client's, kept by the hostgroup lock.
		const std::string used = conn_used();
		const bool good = direct && proxy && other && !proxy_start.empty() && !other_start.empty() && !expected.empty()
			&& pg_ok == pg_accepts && proxy_ok == pg_accepts && wrong == 0 && used == "1";
		if (!good) {
			diag("%s: PostgreSQL %s ('%s'), ProxySQL %s %s, %d wrong values, %s connections in use", sql.c_str(),
				pg_ok ? "accepted" : "refused", expected.c_str(), proxy_ok ? "accepted" : "refused", error.c_str(), wrong,
				used.c_str());
		}
		ok(good, "%s: %s, and the client keeps its backend connection", sql.c_str(), pg_accepts
			? "both accept it, the value stays on later queries and does not reach another client"
			: "both refuse it and the session keeps its value");
	}
}

// A bad pgsql-default_timezone is refused, and the runtime value stays as it was.
static void check_default_variable() {
	const char* where = " WHERE variable_name='pgsql-default_timezone'";
	const std::string original = admin_value(std::string("SELECT variable_value FROM global_variables") + where);
	const std::string runtime_before = admin_value(std::string("SELECT variable_value FROM runtime_global_variables") + where);
	if (original.empty() || runtime_before.empty()) {
		BAIL_OUT("Could not read pgsql-default_timezone");
	}

	// The admin tables are SQLite: an apostrophe in a literal is doubled, a backslash is plain text.
	auto set_table = [&](const std::string& value) {
		std::string quoted;
		for (char c : value) {
			if (c == '\'') quoted += '\'';
			quoted += c;
		}
		return admin_exec("UPDATE global_variables SET variable_value='" + quoted + "'" + where);
	};
	for (const std::string bad : { "'UTC'", "INTERVAL '+02:30'", "LOCAL" }) {
		// If the UPDATE or the LOAD failed, an unchanged runtime value would prove nothing. The
		// table is read before the LOAD, which writes the runtime value back into it.
		const bool applied = set_table(bad)
			&& admin_value(std::string("SELECT variable_value FROM global_variables") + where) == bad
			&& admin_exec("LOAD PGSQL VARIABLES TO RUNTIME");
		const std::string runtime = admin_value(std::string("SELECT variable_value FROM runtime_global_variables") + where);
		ok(applied && runtime == runtime_before, "pgsql-default_timezone=%s is refused: runtime value stays '%s' (got '%s')",
			bad.c_str(), runtime_before.c_str(), runtime.c_str());
	}
	// The runtime value is loaded back first and the table value is put back after, without a
	// LOAD: if the two differed before the test, loading the table value would change runtime.
	const bool restored = set_table(runtime_before) && admin_exec("LOAD PGSQL VARIABLES TO RUNTIME")
		&& set_table(original);
	ok(restored, "pgsql-default_timezone restored: runtime '%s', table '%s'", runtime_before.c_str(), original.c_str());
}

int main() {
	if (cl.getEnv()) return exit_status();

	// libpq sends these as startup parameters; the cases choose their own.
	unsetenv("PGTZ");
	unsetenv("PGOPTIONS");

	plan(1 + 65 + 2 + 18 + 2 + 21 + 1 + 1 + 15 + 4);
	alarm(300);

	admin = mysql_init(nullptr);
	if (!admin || !mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
		nullptr, cl.admin_port, nullptr, 0)) {
		BAIL_OUT("Admin connection failed: %s", admin ? mysql_error(admin) : "mysql_init failed");
	}

	check_every_zone_name();
	check_samples();
	check_login_refused();
	check_login_values();
	check_login_interval_refused();
	check_statements();
	check_reset_to_client_default();
	check_clients_keep_their_value();
	check_interval_forwarded();
	check_default_variable();

	mysql_close(admin);
	return exit_status();
}
