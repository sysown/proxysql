/**
 * @file pgsql-set_transaction_forward-t.cpp
 * @brief 'SET [LOCAL|SESSION] TRANSACTION ...' is forwarded without locking the hostgroup.
 *
 * In PostgreSQL, SET TRANSACTION only changes the transaction already open. It must come
 * after BEGIN, and the session takes its backend at BEGIN; outside a transaction it is a
 * no-op that returns a WARNING. Nothing outlives the transaction, so ProxySQL forwards it
 * without tracking it, without locking the hostgroup and without logging
 * "Unable to parse unknown SET query". The session-wide
 * 'SET SESSION CHARACTERISTICS AS TRANSACTION ...' and 'SET default_transaction_*' still
 * lock.
 *
 * Before, the lock also broke read/write split: a later query that a rule sends to another
 * hostgroup failed with "trying to reach HG 1 while locked on HG 0" (issue #6446). A
 * temporary rule routes a marker SELECT to a second hostgroup to check that too.
 *
 * Every check runs with pgsql-query_processor_parser=0 and =1: the two digest engines
 * produce different digests for these statements (ParserSQL 1.1.0 drops the scope and
 * digests SESSION CHARACTERISTICS as 'SET TRANSACTION ...').
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <vector>
#include <fstream>
#include "libpq-fe.h"
#include "mysql.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "json.hpp"

using nlohmann::json;

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static const char* WARN_REGEX = ".*\\[WARNING\\] Unable to parse unknown SET query.*";

static std::fstream f_proxysql_log {};
static MYSQL* admin = nullptr;

static PGConnPtr connectBackend() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_root_username << " password=" << cl.pgsql_root_password
	   << " sslmode=disable";
	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection failed: %s", PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

static bool exec_ok(PGconn* conn, const std::string& q) {
	PGresult* res = PQexec(conn, q.c_str());
	const ExecStatusType st = PQresultStatus(res);
	const bool ok_ = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!ok_) diag("'%s' failed: %s", q.c_str(), PQerrorMessage(conn));
	PQclear(res);
	return ok_;
}

static std::string scalar(PGconn* conn, const std::string& q) {
	PGresult* res = PQexec(conn, q.c_str());
	std::string v = "<error>";
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
		v = PQgetisnull(res, 0, 0) ? "<null>" : PQgetvalue(res, 0, 0);
	} else {
		diag("'%s' failed: %s", q.c_str(), PQerrorMessage(conn));
	}
	PQclear(res);
	return v;
}

static int lockedOnHostgroup(PGconn* conn) {
	PGresult* res = PQexec(conn, "PROXYSQL INTERNAL SESSION");
	int hg = -2;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
		try {
			const json j = json::parse(PQgetvalue(res, 0, 0));
			hg = j.at("locked_on_hostgroup").get<int>();
		} catch (const std::exception& e) {
			diag("cannot parse PROXYSQL INTERNAL SESSION: %s", e.what());
		}
	} else {
		diag("PROXYSQL INTERNAL SESSION failed: %s", PQerrorMessage(conn));
	}
	PQclear(res);
	return hg;
}

static bool admin_exec(const std::string& q) {
	if (mysql_query(admin, q.c_str())) {
		diag("Admin query failed: '%s': %s", q.c_str(), mysql_error(admin));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (r) mysql_free_result(r);
	return true;
}

static std::string admin_scalar(const std::string& q) {
	std::string v;
	if (mysql_query(admin, q.c_str())) {
		diag("Admin query failed: '%s': %s", q.c_str(), mysql_error(admin));
		return v;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (r) {
		MYSQL_ROW row = mysql_fetch_row(r);
		if (row && row[0]) v = row[0];
		mysql_free_result(r);
	}
	return v;
}

// Skips everything logged so far.
static void log_mark() {
	admin_exec("PROXYSQL FLUSH LOGS");
	f_proxysql_log.clear(f_proxysql_log.rdstate() & ~std::ios_base::eofbit & ~std::ios_base::failbit);
	f_proxysql_log.seekg(0, std::ios_base::end);
}

// True when the warning was logged since the last log_mark().
static bool log_has_warning() {
	admin_exec("PROXYSQL FLUSH LOGS");
	f_proxysql_log.clear(f_proxysql_log.rdstate() & ~std::ios_base::eofbit & ~std::ios_base::failbit);
	const auto& [_, lines] = get_matching_lines(f_proxysql_log, WARN_REGEX);
	return !lines.empty();
}

static bool set_parser(int v) {
	return admin_exec("SET pgsql-query_processor_parser=" + std::to_string(v)) &&
		admin_exec("LOAD PGSQL VARIABLES TO RUNTIME");
}

static void dump_digests() {
	if (mysql_query(admin, "SELECT digest_text FROM stats_pgsql_query_digest WHERE digest_text LIKE 'SET%TRANSACTION%' "
		"OR digest_text LIKE 'set%transaction%' OR digest_text LIKE 'SET%CHARACTERISTICS%' OR digest_text LIKE 'SET%default_transaction%'")) {
		return;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (!r) return;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(r))) diag("  digest: %s", row[0] ? row[0] : "NULL");
	mysql_free_result(r);
}

struct InTxnCase {
	const char* set;
	const char* show;
	const char* expected;
};

static const std::vector<InTxnCase> in_txn_cases = {
	{ "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", "SHOW transaction_isolation", "serializable" },
	{ "SET LOCAL TRANSACTION READ ONLY", "SHOW transaction_read_only", "on" },
	{ "SET SESSION TRANSACTION READ ONLY", "SHOW transaction_read_only", "on" },
	{ "set transaction isolation level repeatable read, read only, deferrable", "SHOW transaction_isolation", "repeatable read" },
	{ "SET /* c */ SESSION  TRANSACTION\n ISOLATION LEVEL READ UNCOMMITTED", "SHOW transaction_isolation", "read uncommitted" },
};
static const int IN_TXN_TESTS = 6;

static const std::vector<const char*> out_of_txn_cases = {
	"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
	"SET LOCAL TRANSACTION READ ONLY",
	"SET SESSION TRANSACTION READ WRITE",
};
static const int OUT_OF_TXN_TESTS = 3;

static const int SNAPSHOT_TESTS = 4;

static const std::vector<const char*> locking_cases = {
	"SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE",
	"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
	"SET default_transaction_isolation = 'serializable'",
};
static const int LOCKING_TESTS = 2;

static const int ROUTING_TESTS = 3;

static int tests_per_mode() {
	return in_txn_cases.size() * IN_TXN_TESTS + out_of_txn_cases.size() * OUT_OF_TXN_TESTS +
		SNAPSHOT_TESTS + locking_cases.size() * LOCKING_TESTS + ROUTING_TESTS;
}

// Routing (issue #6446): a rule sends ROUTED_QUERY to a hostgroup other than the user's
// default one. A session locked on the default hostgroup can no longer run it.
static const int ROUTE_RULE_ID = 6446;
static const char* ROUTED_QUERY = "SELECT 'settx_route_6446'";
static int route_hg = -1;

static bool setup_route_rule() {
	const std::string def_hg = admin_scalar("SELECT default_hostgroup FROM runtime_pgsql_users WHERE username='" +
		std::string(cl.pgsql_root_username) + "' LIMIT 1");
	if (def_hg.empty()) return false;
	const std::string other = admin_scalar("SELECT hostgroup_id FROM runtime_pgsql_servers WHERE status='ONLINE' "
		"AND hostgroup_id<>" + def_hg + " ORDER BY hostgroup_id LIMIT 1");
	if (other.empty()) return false;
	route_hg = std::stoi(other);
	diag("routing rule %d sends \"%s\" to hostgroup %d (default hostgroup %s)", ROUTE_RULE_ID, ROUTED_QUERY, route_hg, def_hg.c_str());
	return admin_exec("DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(ROUTE_RULE_ID)) &&
		admin_exec("INSERT INTO pgsql_query_rules (rule_id,active,match_pattern,destination_hostgroup,apply) VALUES (" +
			std::to_string(ROUTE_RULE_ID) + ",1,'^SELECT ''settx_route_6446''$'," + other + ",1)") &&
		admin_exec("LOAD PGSQL QUERY RULES TO RUNTIME");
}

static void cleanup_route_rule() {
	admin_exec("DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(ROUTE_RULE_ID));
	admin_exec("LOAD PGSQL QUERY RULES TO RUNTIME");
}

static void run_routing() {
	if (route_hg < 0) {
		skip(ROUTING_TESTS, "no second hostgroup to route to");
		return;
	}
	{
		PGConnPtr conn = connectBackend();
		const bool r = conn && exec_ok(conn.get(), "BEGIN") && exec_ok(conn.get(), "SET TRANSACTION READ ONLY") &&
			exec_ok(conn.get(), "COMMIT") && exec_ok(conn.get(), ROUTED_QUERY);
		ok(r, "after BEGIN; SET TRANSACTION READ ONLY; COMMIT a query routed to hostgroup %d succeeds", route_hg);
	}
	{
		PGConnPtr conn = connectBackend();
		const bool r = conn && exec_ok(conn.get(), "SET SESSION TRANSACTION READ ONLY") && exec_ok(conn.get(), ROUTED_QUERY);
		ok(r, "after an out-of-transaction SET SESSION TRANSACTION READ ONLY a query routed to hostgroup %d succeeds", route_hg);
	}
	{
		PGConnPtr conn = connectBackend();
		bool rejected = false;
		if (conn && exec_ok(conn.get(), "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")) {
			PGresult* res = PQexec(conn.get(), ROUTED_QUERY);
			rejected = PQresultStatus(res) == PGRES_FATAL_ERROR;
			diag("control: %s", rejected ? PQerrorMessage(conn.get()) : "query was not rejected");
			PQclear(res);
		}
		ok(rejected, "control: after SET SESSION CHARACTERISTICS the session is locked and the routed query is rejected");
	}
}

static void run_in_txn(const InTxnCase& c) {
	PGConnPtr conn = connectBackend();
	if (!conn) {
		skip(IN_TXN_TESTS, "no connection");
		return;
	}
	PGconn* pc = conn.get();
	log_mark();
	ok(exec_ok(pc, "BEGIN") && exec_ok(pc, c.set), "inside BEGIN: '%s' succeeds", c.set);
	const std::string v = scalar(pc, c.show);
	ok(v == c.expected, "inside BEGIN: '%s' took effect: %s = '%s' (expected '%s')", c.set, c.show, v.c_str(), c.expected);
	ok(exec_ok(pc, "COMMIT"), "COMMIT after '%s' succeeds", c.set);
	const int hg = lockedOnHostgroup(pc);
	ok(hg == -1, "after COMMIT the session is not locked on a hostgroup (locked_on_hostgroup=%d)", hg);
	ok(!log_has_warning(), "no 'Unable to parse unknown SET query' for '%s'", c.set);
	// The next transaction starts again from the defaults: nothing leaked.
	const std::string after = scalar(pc, c.show);
	ok(after != c.expected,
		"the setting did not outlive the transaction: %s = '%s'", c.show, after.c_str());
}

static void run_out_of_txn(const char* set) {
	PGConnPtr conn = connectBackend();
	if (!conn) {
		skip(OUT_OF_TXN_TESTS, "no connection");
		return;
	}
	PGconn* pc = conn.get();
	log_mark();
	ok(exec_ok(pc, set), "outside a transaction: '%s' succeeds (PostgreSQL only warns)", set);
	const int hg = lockedOnHostgroup(pc);
	ok(hg == -1, "outside a transaction: '%s' does not lock (locked_on_hostgroup=%d)", set, hg);
	ok(!log_has_warning(), "no 'Unable to parse unknown SET query' for '%s'", set);
}

static void run_snapshot() {
	PGConnPtr exporter = connectBackend();
	PGConnPtr importer = connectBackend();
	if (!exporter || !importer) {
		skip(SNAPSHOT_TESTS, "no connection");
		return;
	}
	std::string snap = "<error>";
	if (exec_ok(exporter.get(), "BEGIN ISOLATION LEVEL REPEATABLE READ")) {
		snap = scalar(exporter.get(), "SELECT pg_catalog.pg_export_snapshot()");
	}
	log_mark();
	const std::string set = "SET TRANSACTION SNAPSHOT '" + snap + "'";
	ok(exec_ok(importer.get(), "BEGIN ISOLATION LEVEL REPEATABLE READ") && exec_ok(importer.get(), set),
		"inside BEGIN: '%s' succeeds", set.c_str());
	ok(exec_ok(importer.get(), "COMMIT"), "COMMIT after SET TRANSACTION SNAPSHOT succeeds");
	exec_ok(exporter.get(), "COMMIT");
	const int hg = lockedOnHostgroup(importer.get());
	ok(hg == -1, "after SET TRANSACTION SNAPSHOT the session is not locked (locked_on_hostgroup=%d)", hg);
	ok(!log_has_warning(), "no 'Unable to parse unknown SET query' for SET TRANSACTION SNAPSHOT");
}

static void run_locking(const char* set) {
	PGConnPtr conn = connectBackend();
	if (!conn) {
		skip(LOCKING_TESTS, "no connection");
		return;
	}
	PGconn* pc = conn.get();
	ok(exec_ok(pc, set), "'%s' succeeds", set);
	const int hg = lockedOnHostgroup(pc);
	ok(hg >= 0, "'%s' still locks the session on a hostgroup (locked_on_hostgroup=%d)", set, hg);
}

int main(int, char**) {
	if (cl.getEnv()) return exit_status();

	const std::vector<int> modes = { 0, 1 };
	plan(tests_per_mode() * modes.size());

	admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connection failed: %s", mysql_error(admin));
		return exit_status();
	}

	const std::string f_path { get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };
	if (open_file_and_seek_end(f_path, f_proxysql_log) != EXIT_SUCCESS) {
		return exit_status();
	}

	const std::string orig_parser = admin_scalar(
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-query_processor_parser'");
	diag("pgsql-query_processor_parser was '%s'", orig_parser.c_str());

	const bool have_route = setup_route_rule();
	if (!have_route) route_hg = -1;

	for (int mode : modes) {
		diag("=== pgsql-query_processor_parser=%d ===", mode);
		if (!set_parser(mode)) {
			skip(tests_per_mode(), "cannot set pgsql-query_processor_parser=%d", mode);
			continue;
		}
		admin_exec("SELECT 1 FROM stats_pgsql_query_digest_reset LIMIT 1");
		usleep(100000);

		for (const auto& c : in_txn_cases) run_in_txn(c);
		for (const auto* s : out_of_txn_cases) run_out_of_txn(s);
		run_snapshot();
		for (const auto* s : locking_cases) run_locking(s);
		run_routing();

		dump_digests();
	}

	if (have_route) cleanup_route_rule();
	if (!orig_parser.empty()) {
		admin_exec("SET pgsql-query_processor_parser=" + orig_parser);
		admin_exec("LOAD PGSQL VARIABLES TO RUNTIME");
	}
	mysql_close(admin);
	return exit_status();
}
