/**
 * @file test_gtid_from_ok_mariadb-t.cpp
 * @brief End-to-end check of ProxySQL's own MariaDB GTID tracking (issue #6331).
 *
 * MariaDB has no SESSION_TRACK_GTIDS: the GTID of a session's own transaction
 * is reported as the tracked system variable 'last_gtid'. With
 * 'mysql-default_session_track_gtids=OWN_GTID' ProxySQL adds 'last_gtid' to
 * each backend connection's 'session_track_system_variables'
 * (MySQL_Session::handler_again___status_SETTING_SESSION_TRACK_GTIDS). The
 * mariadb10-binlog servers run with stock defaults, so this test fails if
 * ProxySQL's own SET is missing or wrong.
 *
 * It checks, through ProxySQL and against the writer:
 *  1. the backend connection tracks 'last_gtid' (set by ProxySQL, not the server);
 *  2. GTIDs are collected from the OK packets of writes;
 *  3. the collected GTID has the MariaDB 'domain-server-seq' form;
 *  4. with 'mysql-update_gtid_from_ok=true' the writer's executed set learns the
 *     server id, which only the OK-packet path provides (the binlog reader
 *     sends none): 'stats_mysql_gtid_executed' shows the native
 *     'domain-server-seq' form, covering the session's last GTID.
 *
 * Assumes the writer's GTIDs in domain 0 start at sequence 1, as on a freshly
 * deployed sandbox, so that its executed set is one contiguous interval.
 */

#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

#include "mysql.h"
#include "re2/re2.h"

#include "command_line.h"
#include "json.hpp"
#include "tap.h"
#include "utils.h"

using nlohmann::json;

CommandLine cl;

static const int NUM_WRITES = 5;

static bool admin_exec(MYSQL* admin, const std::string& q) {
	if (mysql_query(admin, q.c_str())) {
		diag("Admin query failed: '%s' : %s", q.c_str(), mysql_error(admin));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (r) mysql_free_result(r);
	return true;
}

static std::string single_value(MYSQL* conn, const std::string& q) {
	std::string v {};
	if (mysql_query(conn, q.c_str())) {
		diag("Query failed: '%s' : %s", q.c_str(), mysql_error(conn));
		return v;
	}
	MYSQL_RES* r = mysql_store_result(conn);
	if (r) {
		MYSQL_ROW row = mysql_fetch_row(r);
		if (row && row[0]) v = row[0];
		mysql_free_result(r);
	}
	return v;
}

static std::string global_var(MYSQL* admin, const char* name) {
	return single_value(admin,
		std::string("SELECT variable_value FROM global_variables WHERE variable_name='") + name + "'");
}

static long long gtid_session_collected(MYSQL* admin) {
	const std::string v = single_value(admin,
		"SELECT variable_value FROM stats_mysql_global WHERE variable_name='GTID_session_collected'");
	return v.empty() ? -1 : strtoll(v.c_str(), NULL, 10);
}

static bool set_vars(MYSQL* admin, const std::string& track_gtids, const std::string& from_ok) {
	bool ret = true;
	ret &= admin_exec(admin, "SET mysql-default_session_track_gtids='" + track_gtids + "'");
	ret &= admin_exec(admin, "SET mysql-update_gtid_from_ok='" + from_ok + "'");
	ret &= admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	// Let the worker threads pick up the new thread-local values.
	usleep(500 * 1000);
	return ret;
}

static std::string backend_gtid_from_internal_session(MYSQL* proxy) {
	const std::string out = single_value(proxy, "PROXYSQL INTERNAL SESSION");
	std::string gtid {};
	try {
		const json j = json::parse(out);
		if (j.contains("backends") && j["backends"].is_array()) {
			for (const auto& be : j["backends"]) {
				if (be.contains("gtid") && be["gtid"].is_string() && !be["gtid"].get<std::string>().empty()) {
					gtid = be["gtid"].get<std::string>();
					break;
				}
			}
		}
	} catch (const std::exception& e) {
		diag("Failed to parse PROXYSQL INTERNAL SESSION output: %s", e.what());
	}
	return gtid;
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(6);

	const char* whg_env = getenv("BINLOG_WHG");
	const std::string whg = whg_env ? whg_env : "1500";

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connect failed: %s", mysql_error(admin));
		return exit_status();
	}

	const std::string orig_track_gtids = global_var(admin, "mysql-default_session_track_gtids");
	const std::string orig_from_ok = global_var(admin, "mysql-update_gtid_from_ok");
	diag("Original values: mysql-default_session_track_gtids='%s' mysql-update_gtid_from_ok='%s'",
		orig_track_gtids.c_str(), orig_from_ok.c_str());

	ok(set_vars(admin, "OWN_GTID", "true"),
		"Set mysql-default_session_track_gtids=OWN_GTID and mysql-update_gtid_from_ok=true");

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Client connect failed: %s", mysql_error(proxy));
		set_vars(admin, orig_track_gtids, orig_from_ok);
		mysql_close(admin);
		return exit_status();
	}

	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_T(proxy, "CREATE TABLE IF NOT EXISTS test.gtid_from_ok_mariadb (id INT NOT NULL)");

	// 1. The writer's backend connection reports last_gtid because ProxySQL
	// asked for it. BEGIN keeps the SELECT on that same backend connection.
	MYSQL_QUERY_T(proxy, "BEGIN");
	const std::string tracked = single_value(proxy, "SELECT @@session.session_track_system_variables");
	MYSQL_QUERY_T(proxy, "COMMIT");
	diag("Backend session_track_system_variables='%s'", tracked.c_str());
	ok(tracked == "*" || RE2::PartialMatch(tracked, "(^|,)last_gtid(,|$)"),
		"ProxySQL enables last_gtid tracking on the backend connection: '%s'", tracked.c_str());

	const long long collected_before = gtid_session_collected(admin);
	for (int i = 0; i < NUM_WRITES; i++) {
		const std::string q = "INSERT INTO test.gtid_from_ok_mariadb VALUES (" + std::to_string(i) + ")";
		MYSQL_QUERY_T(proxy, q.c_str());
	}
	const long long collected_after = gtid_session_collected(admin);
	ok(collected_before >= 0 && collected_after >= collected_before + NUM_WRITES,
		"GTIDs are collected from the OK packets: before=%lld after=%lld (expected >= +%d)",
		collected_before, collected_after, NUM_WRITES);

	// 3. The collected GTID is the session's own MariaDB GTID.
	const std::string session_gtid = backend_gtid_from_internal_session(proxy);
	std::string domain {}, server_id {}, seq {};
	const bool mariadb_form = RE2::FullMatch(session_gtid, "(\\d+)-(\\d+)-(\\d+)", &domain, &server_id, &seq);
	ok(mariadb_form, "The collected GTID has the MariaDB domain-server-seq form: '%s'", session_gtid.c_str());

	// 4. The writer's executed set learnt the server id from the OK packets.
	const std::string writer_host = single_value(admin,
		"SELECT hostname FROM runtime_mysql_servers WHERE hostgroup_id=" + whg + " LIMIT 1");
	const std::string writer_port = single_value(admin,
		"SELECT port FROM runtime_mysql_servers WHERE hostgroup_id=" + whg + " LIMIT 1");
	const std::string executed = single_value(admin,
		"SELECT gtid_executed FROM stats_mysql_gtid_executed WHERE hostname='" + writer_host
		+ "' AND port=" + writer_port);
	diag("stats_mysql_gtid_executed for %s:%s = '%s'", writer_host.c_str(), writer_port.c_str(), executed.c_str());
	std::string ex_domain {}, ex_server_id {}, ex_seq {};
	const bool native = RE2::FullMatch(executed, "(\\d+)-(\\d+)-(\\d+)", &ex_domain, &ex_server_id, &ex_seq);
	ok(mariadb_form && native && ex_domain == domain && ex_server_id == server_id
		&& strtoull(ex_seq.c_str(), NULL, 10) >= strtoull(seq.c_str(), NULL, 10),
		"update_gtid_from_ok records the writer's server id and covers the session GTID: executed='%s' session='%s'",
		executed.c_str(), session_gtid.c_str());

	MYSQL_QUERY_T(proxy, "DROP TABLE IF EXISTS test.gtid_from_ok_mariadb");
	mysql_close(proxy);

	ok(set_vars(admin, orig_track_gtids, orig_from_ok), "Restored the original variable values");
	mysql_close(admin);

	return exit_status();
}
