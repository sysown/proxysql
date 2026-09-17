/**
 * @file pgsql-pgbouncer_compat-t.cpp
 * @brief Integration tests for the PgBouncer compatibility layer.
 *
 * The unit tests under test/tap/tests/unit/ compare generated strings. That is
 * not enough: every SHOW translation and every converter INSERT is SQL that the
 * admin interface has to execute, and a wrong column name is invisible to a
 * string comparison. Three such defects shipped in the original branch
 * (pgsql_query_rules.schemaname, stats_pgsql_processlist.db, and reading
 * weight/max_connections from stats_pgsql_connection_pool).
 *
 * This test therefore executes, against a live PgSQL admin port:
 *   - every PgBouncer SHOW command, plain and EXTENDED
 *   - every SQL statement the converter emits for a representative config
 * so that a schema drift or a typo fails here rather than in production.
 *
 * It also imports a userlist.txt holding an md5 hash and a SCRAM-SHA-256
 * verifier (#6134) and logs in through ProxySQL with both users, which is the
 * only check that proves hashed credentials work end to end.
 */

#include <string>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <fstream>
#include <unistd.h>
#include <libpq-fe.h>

#include "command_line.h"
#include "tap.h"
#include "utils.h"

#include "PgBouncer_Config.h"
#include "PgBouncer_ConfigConverter.h"

// Every command PgBouncer's SHOW interface exposes and we claim to support.
static const char* SUPPORTED_SHOW[] = {
	"POOLS", "STATS", "SERVERS", "CLIENTS", "DATABASES",
	"USERS", "CONFIG", "VERSION", "STATE", "LISTS"
};
static const int NUM_SUPPORTED = sizeof(SUPPORTED_SHOW) / sizeof(SUPPORTED_SHOW[0]);

// Commands we deliberately reject with an explanatory message.
static const char* UNSUPPORTED_SHOW[] = {
	"DNS_HOSTS", "DNS_ZONES", "FDS", "PEERS", "PEER_POOLS",
	"MEM", "ACTIVE_SOCKETS", "SOCKETS"
};
static const int NUM_UNSUPPORTED = sizeof(UNSUPPORTED_SHOW) / sizeof(UNSUPPORTED_SHOW[0]);

static PGconn* connect_admin(const CommandLine& cl) {
	std::stringstream cs;
	cs << "host=" << cl.pgsql_admin_host
	   << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username
	   << " password=" << cl.admin_password
	   << " dbname=postgres";
	return PQconnectdb(cs.str().c_str());
}

// Run a statement, reporting the server's own error text on failure so a
// failing assertion names the offending column instead of just "failed".
static bool exec_ok(PGconn* c, const std::string& q, const std::string& what) {
	PGresult* res = PQexec(c, q.c_str());
	ExecStatusType st = PQresultStatus(res);
	bool passed = (st == PGRES_TUPLES_OK || st == PGRES_COMMAND_OK);
	if (!passed) {
		diag("%s failed: %s", what.c_str(), PQerrorMessage(c));
		diag("  statement: %s", q.c_str());
	}
	PQclear(res);
	return passed;
}

// ---------------------------------------------------------------------------
// SHOW command execution
// ---------------------------------------------------------------------------
static void test_show_commands(PGconn* admin) {
	for (int i = 0; i < NUM_SUPPORTED; i++) {
		std::string q = std::string("SHOW ") + SUPPORTED_SHOW[i];
		ok(exec_ok(admin, q, q), "%s executes", q.c_str());
	}
	for (int i = 0; i < NUM_SUPPORTED; i++) {
		std::string q = std::string("SHOW EXTENDED ") + SUPPORTED_SHOW[i];
		ok(exec_ok(admin, q, q), "%s executes", q.c_str());
	}
}

// SHOW EXTENDED must return at least as many columns as the plain form, and
// strictly more for the commands that have ProxySQL-specific data to add.
static void test_extended_adds_columns(PGconn* admin) {
	for (int i = 0; i < NUM_SUPPORTED; i++) {
		std::string plain = std::string("SHOW ") + SUPPORTED_SHOW[i];
		std::string ext = std::string("SHOW EXTENDED ") + SUPPORTED_SHOW[i];

		PGresult* r1 = PQexec(admin, plain.c_str());
		PGresult* r2 = PQexec(admin, ext.c_str());
		int n1 = (PQresultStatus(r1) == PGRES_TUPLES_OK) ? PQnfields(r1) : -1;
		int n2 = (PQresultStatus(r2) == PGRES_TUPLES_OK) ? PQnfields(r2) : -1;
		PQclear(r1);
		PQclear(r2);

		ok(n1 > 0 && n2 > n1,
		   "SHOW EXTENDED %s returns more columns than SHOW %s (%d > %d)",
		   SUPPORTED_SHOW[i], SUPPORTED_SHOW[i], n2, n1);
	}
}

static void test_unsupported_commands(PGconn* admin) {
	for (int i = 0; i < NUM_UNSUPPORTED; i++) {
		std::string q = std::string("SHOW ") + UNSUPPORTED_SHOW[i];
		PGresult* res = PQexec(admin, q.c_str());
		bool errored = (PQresultStatus(res) == PGRES_FATAL_ERROR);
		std::string msg = PQerrorMessage(admin);
		PQclear(res);
		ok(errored && msg.find("not supported") != std::string::npos,
		   "%s is rejected with an explanatory message", q.c_str());
	}
}

// A SHOW that is not part of the PgBouncer set must still reach ProxySQL's own
// handling rather than being swallowed by the translation layer.
static void test_native_show_still_works(PGconn* admin) {
	ok(exec_ok(admin, "SHOW TABLES", "SHOW TABLES"),
	   "native SHOW TABLES is unaffected by the PgBouncer layer");
	ok(exec_ok(admin, "SHOW PGSQL VARIABLES", "SHOW PGSQL VARIABLES"),
	   "native SHOW PGSQL VARIABLES is unaffected by the PgBouncer layer");

	// Trailing tokens are not a PgBouncer command; this must not translate.
	PGresult* res = PQexec(admin, "SHOW POOLS bogus_trailing_token");
	bool rejected = (PQresultStatus(res) == PGRES_FATAL_ERROR);
	PQclear(res);
	ok(rejected, "SHOW POOLS <trailing token> is not treated as SHOW POOLS");
}

// ---------------------------------------------------------------------------
// Hashed userlist.txt import (#6134)
// ---------------------------------------------------------------------------
static const int HASHED_USERLIST_TESTS = 5;

static PGconn* connect_pg(const char* host, int port, const char* user,
                          const char* pass, const char* db) {
	std::stringstream cs;
	cs << "host=" << host << " port=" << port << " user=" << user
	   << " password=" << pass << " dbname=" << db << " sslmode=disable";
	return PQconnectdb(cs.str().c_str());
}

static std::string exec_scalar(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	std::string v;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0)) {
		v = PQgetvalue(res, 0, 0);
	}
	PQclear(res);
	return v;
}

// Log in through ProxySQL and require a query to reach the backend, which needs
// both the frontend and the backend leg to authenticate with the stored hash.
static bool select_through_proxysql(const CommandLine& cl, const char* user, const char* pass) {
	PGconn* c = connect_pg(cl.pgsql_host, cl.pgsql_port, user, pass, "postgres");
	bool passed = false;
	if (PQstatus(c) != CONNECTION_OK) {
		diag("login through ProxySQL failed for '%s': %s", user, PQerrorMessage(c));
	} else {
		passed = exec_scalar(c, "SELECT 1") == "1";
		if (!passed) diag("SELECT 1 through ProxySQL failed for '%s': %s", user, PQerrorMessage(c));
	}
	PQfinish(c);
	return passed;
}

/**
 * Import a userlist.txt with an md5 hash (infra role 'md5user', which the
 * backend authenticates with md5) and a SCRAM-SHA-256 verifier copied from the
 * backend, then log in through ProxySQL as both users.
 *
 * Must run before the other converter tests: the representative config enables
 * the firewall whitelist and rewrites pgsql_servers, and this test reads the
 * backend address from the current runtime servers.
 */
static void test_hashed_userlist_authenticates(PGconn* admin, const CommandLine& cl) {
	const char* MD5_USER = "md5user";  // infra role: password_encryption=md5, pg_hba md5
	const char* MD5_PASS = "md5user";  // NOSONAR(cpp:S2068): infra test credential.
	const char* SCRAM_USER = "pgbouncer_scram_user";
	const char* SCRAM_PASS = "pgbouncer_scram_pw"; // NOSONAR(cpp:S2068): synthetic test credential.

	std::string be_host = exec_scalar(admin,
		"SELECT hostname FROM runtime_pgsql_servers ORDER BY hostgroup_id LIMIT 1");
	std::string be_port = exec_scalar(admin,
		"SELECT port FROM runtime_pgsql_servers ORDER BY hostgroup_id LIMIT 1");

	PGconn* be = connect_pg(cl.pgsql_server_host, cl.pgsql_server_port,
		cl.pgsql_server_username, cl.pgsql_server_password, "postgres");
	if (PQstatus(be) != CONNECTION_OK || be_host.empty() || be_port.empty()) {
		diag("backend connection: %s; runtime server '%s:%s'",
			PQerrorMessage(be), be_host.c_str(), be_port.c_str());
		skip(HASHED_USERLIST_TESTS, "no backend connection or no runtime pgsql server");
		PQfinish(be);
		return;
	}

	// The md5 user must be usable directly against the backend.
	std::string md5_hash = exec_scalar(be,
		std::string("SELECT rolpassword FROM pg_authid WHERE rolname='") + MD5_USER + "'");
	bool md5_backend_ok = false;
	if (md5_hash.rfind("md5", 0) == 0) {
		PGconn* probe = connect_pg(cl.pgsql_server_host, cl.pgsql_server_port,
			MD5_USER, MD5_PASS, "postgres");
		md5_backend_ok = PQstatus(probe) == CONNECTION_OK;
		PQfinish(probe);
	}

	bool scram_ok =
		exec_ok(be, "SET password_encryption TO 'scram-sha-256'", "set password_encryption") &&
		exec_ok(be, std::string("DROP ROLE IF EXISTS ") + SCRAM_USER, "drop scram role") &&
		exec_ok(be, std::string("CREATE ROLE ") + SCRAM_USER + " LOGIN PASSWORD '" + SCRAM_PASS + "'",
			"create scram role");
	std::string verifier = scram_ok ? exec_scalar(be,
		std::string("SELECT rolpassword FROM pg_authid WHERE rolname='") + SCRAM_USER + "'") : "";

	if (!md5_backend_ok || verifier.rfind("SCRAM-SHA-256$", 0) != 0) {
		skip(HASHED_USERLIST_TESTS,
			"backend lacks an md5-authenticated '%s' or a SCRAM role (md5 %s, verifier '%.14s')",
			MD5_USER, md5_backend_ok ? "ok" : "unusable", verifier.c_str());
		exec_ok(be, std::string("DROP ROLE IF EXISTS ") + SCRAM_USER, "drop scram role");
		PQfinish(be);
		return;
	}

	// PgBouncer accepts uppercase md5 hex, ProxySQL only lowercase: the import
	// must normalise it.
	std::string md5_upper = md5_hash;
	for (size_t i = 3; i < md5_upper.size(); i++) {
		md5_upper[i] = std::toupper(static_cast<unsigned char>(md5_upper[i]));
	}

	char dir_template[] = "/tmp/pgbouncer_hashed_XXXXXX";
	const char* dir = mkdtemp(dir_template);
	std::string ini_path = std::string(dir ? dir : "/tmp") + "/pgbouncer.ini";
	std::string userlist_path = std::string(dir ? dir : "/tmp") + "/userlist.txt";
	{
		std::ofstream ini(ini_path);
		ini << "[databases]\n"
		    << "* = host=" << be_host << " port=" << be_port << "\n"
		    << "[pgbouncer]\n"
		    << "auth_type = md5\n"
		    << "auth_file = " << userlist_path << "\n"
		    << "pool_mode = transaction\n";
		std::ofstream userlist(userlist_path);
		userlist << "\"" << MD5_USER << "\" \"" << md5_upper << "\"\n"
		         << "\"" << SCRAM_USER << "\" \"" << verifier << "\"\n";
	}

	PgBouncer::Config config;
	bool parsed = PgBouncer::parse_config_file(ini_path, config);
	for (const auto& e : config.errors) diag("parse error: %s:%d: %s", e.file.c_str(), e.line, e.message.c_str());
	ok(parsed && config.auth_entries.size() == 2,
	   "hashed userlist.txt parses (%zu auth entries)", config.auth_entries.size());

	PgBouncer::ConfigConverter converter;
	PgBouncer::ConversionResult result = converter.convert(config, true);
	for (const auto& e : result.errors) diag("conversion error: %s", e.message.c_str());
	for (const auto& n : result.notes) diag("conversion note: %s", n.message.c_str());
	ok(result.success, "hashed userlist.txt converts in strict mode");

	int failed = 0;
	for (const auto& e : result.entries) {
		if (e.sql.empty() || strncasecmp(e.sql.c_str(), "SAVE ", 5) == 0) continue;
		if (!exec_ok(admin, e.sql, "converter statement")) failed++;
	}
	ok(failed == 0, "every statement of the hashed userlist import executed (%d failed)", failed);

	ok(select_through_proxysql(cl, MD5_USER, MD5_PASS),
	   "md5-stored user '%s' imported from userlist.txt logs in and reaches the backend", MD5_USER);
	ok(select_through_proxysql(cl, SCRAM_USER, SCRAM_PASS),
	   "SCRAM-verifier-stored user '%s' imported from userlist.txt logs in and reaches the backend",
	   SCRAM_USER);

	// The backend role is dropped by main() once pooled connections are gone.
	unlink(userlist_path.c_str());
	unlink(ini_path.c_str());
	if (dir) rmdir(dir);
	PQfinish(be);
}

// ---------------------------------------------------------------------------
// Converter output must be executable SQL
// ---------------------------------------------------------------------------
static PgBouncer::Config build_representative_config() {
	PgBouncer::Config config;
	config.global.listen_port = 6432;
	config.global.auth_type = "md5";
	config.global.pool_mode = "transaction";
	config.global.max_client_conn = 500;
	config.global.default_pool_size = 25;

	PgBouncer::Database db;
	db.name = "appdb";
	db.host = "127.0.0.1";
	db.port = 5432;
	db.pool_size = 30;
	config.databases.push_back(db);

	PgBouncer::Database wild;
	wild.name = "*";
	wild.host = "127.0.0.1";
	wild.port = 5432;
	config.databases.push_back(wild);

	PgBouncer::User user;
	user.name = "appuser";
	user.pool_mode = "transaction";
	config.users.push_back(user);

	PgBouncer::AuthFileEntry auth;
	auth.username = "appuser";
	auth.password = "appsecret"; // NOSONAR(cpp:S2068): synthetic fixture value for an in-memory PgBouncer::Config; never reaches a real credential store.
	auth.type = PgBouncer::AuthType::PLAIN;
	config.auth_entries.push_back(auth);

	PgBouncer::HBARule rule;
	rule.conn_type = "host";
	rule.database = "all";
	rule.user = "all";
	rule.address = "10.0.0.0/8";
	rule.method = "md5";
	config.hba_rules.push_back(rule);

	return config;
}

static void test_converter_sql_executes(PGconn* admin) {
	PgBouncer::Config config = build_representative_config();
	PgBouncer::ConfigConverter converter;
	PgBouncer::ConversionResult result = converter.convert(config, false);

	ok(!result.entries.empty(), "converter produced SQL for the sample config");

	int executed = 0;
	int failed = 0;
	int skipped_persist = 0;
	for (const auto& e : result.entries) {
		// Comment-only entries carry no statement to run.
		if (e.sql.empty() || e.sql.compare(0, 2, "--") == 0) continue;

		// Never execute the converter's "SAVE ... TO DISK" statements. They
		// would overwrite this instance's on-disk configuration permanently,
		// which no LOAD ... FROM DISK could then undo -- it would restore the
		// clobbered copy. Every other statement touches memory/runtime only,
		// so the restore at the end of main() puts things back. The SAVE
		// statements are plain, fixed SQL with no generated identifiers, so
		// skipping them costs no coverage of the mapping logic.
		if (strncasecmp(e.sql.c_str(), "SAVE ", 5) == 0) {
			skipped_persist++;
			continue;
		}

		executed++;
		PGresult* res = PQexec(admin, e.sql.c_str());
		ExecStatusType st = PQresultStatus(res);
		if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
			failed++;
			diag("converter SQL failed: %s", e.sql.c_str());
			diag("  server said: %s", PQerrorMessage(admin));
		}
		PQclear(res);
	}

	ok(executed > 0, "converter SQL contained executable statements (%d)", executed);
	ok(failed == 0, "every converter statement executed cleanly (%d failed of %d)",
	   failed, executed);
	ok(skipped_persist > 0,
	   "converter emits SAVE ... TO DISK statements (%d, deliberately not executed here)",
	   skipped_persist);
}

// After the import the tables it targets must actually hold the imported rows.
static void test_converter_populated_tables(PGconn* admin) {
	struct { const char* table; const char* what; } checks[] = {
		{ "pgsql_servers",      "servers" },
		{ "pgsql_users",        "users" },
		{ "pgsql_query_rules",  "query rules" },
	};
	for (const auto& c : checks) {
		std::string q = std::string("SELECT COUNT(*) FROM ") + c.table;
		PGresult* res = PQexec(admin, q.c_str());
		bool has_rows = false;
		if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
			has_rows = atoi(PQgetvalue(res, 0, 0)) > 0;
		}
		PQclear(res);
		ok(has_rows, "%s were imported into %s", c.what, c.table);
	}
}

// IMPORT with a path that does not exist must fail cleanly, not crash or hang.
static void test_import_missing_file(PGconn* admin) {
	PGresult* res = PQexec(admin,
		"IMPORT PGBOUNCER CONFIG FROM '/nonexistent/pgbouncer.ini' DRY RUN");
	bool errored = (PQresultStatus(res) == PGRES_FATAL_ERROR);
	PQclear(res);
	ok(errored, "IMPORT PGBOUNCER CONFIG from a missing file reports an error");

	// The connection must still be usable afterwards.
	ok(exec_ok(admin, "SELECT 1", "SELECT 1"),
	   "admin connection survives a failed IMPORT");
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// 10 plain SHOW + 10 EXTENDED SHOW + 10 column-count + 8 unsupported
	// + 3 native SHOW + hashed userlist import + 4 converter SQL
	// + 3 populated tables + 2 import
	plan(NUM_SUPPORTED * 3 + NUM_UNSUPPORTED + 3 + HASHED_USERLIST_TESTS + 4 + 3 + 2);

	PGconn* admin = connect_admin(cl);
	if (PQstatus(admin) != CONNECTION_OK) {
		diag("Failed to connect to the PgSQL admin interface: %s", PQerrorMessage(admin));
		PQfinish(admin);
		return exit_status();
	}

	test_show_commands(admin);
	test_extended_adds_columns(admin);
	test_unsupported_commands(admin);
	test_native_show_still_works(admin);

	test_hashed_userlist_authenticates(admin, cl);
	test_converter_sql_executes(admin);
	test_converter_populated_tables(admin);
	test_import_missing_file(admin);

	// Put the configuration back the way we found it. The converter statements
	// above rewrote pgsql_servers / pgsql_users / pgsql_query_rules / the
	// firewall whitelist and set pgsql-* variables, all in memory only -- the
	// SAVE ... TO DISK statements were deliberately skipped, so the on-disk
	// copy is still the one this instance was configured with and is a valid
	// source to restore from. Other tests share this instance; leaving it
	// holding a PgBouncer import would break them.
	static const char* RESTORE[] = {
		"LOAD PGSQL SERVERS FROM DISK",
		"LOAD PGSQL USERS FROM DISK",
		"LOAD PGSQL QUERY RULES FROM DISK",
		"LOAD PGSQL VARIABLES FROM DISK",
		"LOAD PGSQL FIREWALL FROM DISK",
		"LOAD PGSQL SERVERS TO RUNTIME",
		"LOAD PGSQL USERS TO RUNTIME",
		"LOAD PGSQL QUERY RULES TO RUNTIME",
		"LOAD PGSQL VARIABLES TO RUNTIME",
		"LOAD PGSQL FIREWALL TO RUNTIME",
	};
	for (const char* stmt : RESTORE) {
		PGresult* res = PQexec(admin, stmt);
		ExecStatusType st = PQresultStatus(res);
		if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
			// Not an assertion (the plan is fixed), but it must be visible:
			// a failed restore leaves the shared instance misconfigured.
			diag("RESTORE FAILED: %s -> %s", stmt, PQerrorMessage(admin));
		}
		PQclear(res);
	}

	// Drop the SCRAM role created by test_hashed_userlist_authenticates. The
	// restore above removed the user from ProxySQL; pooled backend connections
	// may still hold it, so terminate them first.
	PGconn* be = connect_pg(cl.pgsql_server_host, cl.pgsql_server_port,
		cl.pgsql_server_username, cl.pgsql_server_password, "postgres");
	if (PQstatus(be) == CONNECTION_OK) {
		exec_ok(be, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
			"WHERE usename='pgbouncer_scram_user'", "terminate scram role sessions");
		exec_ok(be, "DROP ROLE IF EXISTS pgbouncer_scram_user", "drop scram role");
	}
	PQfinish(be);

	PQfinish(admin);
	return exit_status();
}
