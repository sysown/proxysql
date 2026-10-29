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
// must refuse, and after a refusal the session must keep working.
static void check_samples() {
	const std::vector<std::string> accepted = {
		"UTC", "utc", "EST", "Europe/Berlin", "America/Argentina/Buenos_Aires", "America/Port-au-Prince", "Etc/GMT+3",
		"PST8PDT", "EST5EDT,M3.2.0,M11.1.0", "UTC+3", "<-03>3", "<+0330>-3:30",
		"-7", "5.5", "1e1",
		"INTERVAL '+02:30'", "INTERVAL '2 hours'", "INTERVAL'1'",
	};
	const std::vector<std::string> refused = {
		"'UTC'", "America/New York", "UTC\t", "UTC;", std::string(256, 'A'),
		"INTERVAL '-08:00' HOUR TO MINUTE", "INTERVAL '1''2'", "INTERVAL+3",
	};
	// PostgreSQL reads these as a number of hours; ProxySQL refuses them.
	const std::vector<std::string> refused_by_proxysql_only = { " 5", "5 " };

	PGConn direct = connect_backend("");
	auto run = [&](const std::string& value, bool pg_accepts, bool proxysql_accepts) {
		const std::string set = set_statement(value);
		const bool pg_ok = exec_ok(direct.get(), set);
		const std::string expected = pg_ok ? shown_timezone(direct.get()) : "";

		PGConn proxy = connect_proxy("");
		std::string error;
		const bool proxy_ok = exec_ok(proxy.get(), set, &error);
		bool good = pg_ok == pg_accepts && proxy_ok == proxysql_accepts;
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
	ok(pg_refused && proxy_refused && proxy_error.find(REFUSED) != std::string::npos,
		"Login with PGTZ='UTC' (quoted) is refused at login, as by PostgreSQL (%s)", proxy_error.c_str());

	const std::string options = "options='-c TimeZone=\\'UTC\\''";
	const bool pg_refused2 = !connect_backend(options, &pg_error);
	const bool proxy_refused2 = !connect_proxy(options, &proxy_error);
	ok(pg_refused2 && proxy_refused2 && proxy_error.find(REFUSED) != std::string::npos,
		"Login with options -c TimeZone='UTC' (quoted) is refused at login, as by PostgreSQL (%s)", proxy_error.c_str());
}

// The SET TIME ZONE INTERVAL statement form, on PostgreSQL and through ProxySQL: both must
// accept or both must refuse. The grammar allows only HOUR, MINUTE or HOUR TO MINUTE after
// the interval. After an accepted one the connection is closed without another query: with
// the default SET parser the value cannot yet be applied to a backend connection.
static void check_interval_statements() {
	const std::vector<std::pair<std::string, bool>> statements = {
		{ "SET TIME ZONE INTERVAL '+02:30' HOUR TO MINUTE", true },
		{ "SET TIME ZONE INTERVAL '+02:30' HOUR", true },
		{ "SET TIME ZONE INTERVAL '+02:30' MINUTE", true },
		{ "SET TIME ZONE INTERVAL '2 hours'", true },
		{ "SET TIME ZONE INTERVAL(2) '+02:30'", true },
		{ "SET TIME ZONE INTERVAL '+02:30' DAY", false },
		{ "SET TIME ZONE INTERVAL '+02:30' FOO", false },
		{ "SET TIME ZONE INTERVAL '1' HOUR TO SECOND", false },
	};
	for (const auto& [sql, pg_accepts] : statements) {
		PGConn direct = connect_backend("");
		const bool pg_ok = exec_ok(direct.get(), sql);
		PGConn proxy = connect_proxy("");
		std::string error;
		const bool proxy_ok = exec_ok(proxy.get(), sql, &error);
		bool good = proxy && pg_ok == pg_accepts && proxy_ok == pg_accepts;
		if (!proxy_ok) good = good && exec_ok(proxy.get(), "SELECT 1");
		if (!good) {
			diag("%s: PostgreSQL %s, ProxySQL %s %s", sql.c_str(), pg_ok ? "accepted" : "refused",
				proxy_ok ? "accepted" : "refused", error.c_str());
		}
		ok(good, "%s: PostgreSQL and ProxySQL both %s", sql.c_str(), pg_accepts ? "accept it" : "refuse it");
	}
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

// A bad pgsql-default_timezone is refused, and the runtime value stays as it was.
static void check_default_variable() {
	const char* where = " WHERE variable_name='pgsql-default_timezone'";
	const std::string original = admin_value(std::string("SELECT variable_value FROM global_variables") + where);
	const std::string runtime_before = admin_value(std::string("SELECT variable_value FROM runtime_global_variables") + where);
	if (original.empty() || runtime_before.empty()) {
		BAIL_OUT("Could not read pgsql-default_timezone");
	}

	// If the UPDATE or the LOAD failed, an unchanged runtime value would prove nothing. The
	// table is read before the LOAD, which writes the runtime value back into it.
	const bool applied = admin_exec(std::string("UPDATE global_variables SET variable_value='''UTC'''") + where)
		&& admin_value(std::string("SELECT variable_value FROM global_variables") + where) == "'UTC'"
		&& admin_exec("LOAD PGSQL VARIABLES TO RUNTIME");
	const std::string runtime = admin_value(std::string("SELECT variable_value FROM runtime_global_variables") + where);
	ok(applied && runtime == runtime_before,
		"pgsql-default_timezone='UTC' (quoted) is refused: runtime value stays '%s' (got '%s')",
		runtime_before.c_str(), runtime.c_str());

	std::string escaped(original.size() * 2 + 1, '\0');
	escaped.resize(mysql_real_escape_string(admin, &escaped[0], original.c_str(), original.size()));
	const bool restored = admin_exec("UPDATE global_variables SET variable_value='" + escaped + "'" + where)
		&& admin_exec("LOAD PGSQL VARIABLES TO RUNTIME");
	ok(restored, "pgsql-default_timezone restored to '%s'", original.c_str());
}

int main() {
	if (cl.getEnv()) return exit_status();

	// libpq sends these as startup parameters; the cases choose their own.
	unsetenv("PGTZ");
	unsetenv("PGOPTIONS");

	plan(1 + 28 + 2 + 8 + 2);
	alarm(180);

	admin = mysql_init(nullptr);
	if (!admin || !mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
		nullptr, cl.admin_port, nullptr, 0)) {
		BAIL_OUT("Admin connection failed: %s", admin ? mysql_error(admin) : "mysql_init failed");
	}

	check_every_zone_name();
	check_samples();
	check_login_refused();
	check_interval_statements();
	check_default_variable();

	mysql_close(admin);
	return exit_status();
}
