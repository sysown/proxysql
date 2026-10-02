/**
 * @file mysql-reg_test_6328_gtid_collected_without_forwarding-t.cpp
 * @brief Regression test for issue #6328.
 *
 * ProxySQL collects the GTID that a backend returns in the OK packet
 * (SESSION_TRACK_GTIDS) and stores it in the session's MySQL_Backend. That
 * per-backend GTID is what query rules with 'gtid_from_hostgroup' read to
 * route a following read causally (MySQL_Session.cpp, the
 * '_gtid_from_backend->gtid_uuid' lookup).
 *
 * The collection must not depend on the two settings that only control what
 * ProxySQL does *with* the GTID afterwards:
 *  - 'mysql-client_session_track_gtid' : forward the GTID to the client;
 *  - 'mysql-update_gtid_from_ok'       : feed the GTID into the per-server
 *                                        executed-GTID set.
 *
 * Issue #6328: a guard in MySQL_Connection::get_gtid() returned early when
 * both settings were false, so no GTID was collected at all and
 * 'gtid_from_hostgroup' routing silently fell back to non-causal routing.
 *
 * The test disables both settings, makes the client request OWN_GTID
 * tracking, runs writes, and checks:
 *  1. 'GTID_session_collected' increases (one per collected GTID);
 *  2. 'PROXYSQL INTERNAL SESSION' shows a non-empty GTID for the backend;
 *  3. the GTID is still NOT forwarded to the client (forwarding is off).
 */

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <unistd.h>

#include "mysql.h"

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

static std::string admin_single_value(MYSQL* admin, const std::string& q) {
	std::string v {};
	if (mysql_query(admin, q.c_str())) {
		diag("Admin query failed: '%s' : %s", q.c_str(), mysql_error(admin));
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

static std::string global_var(MYSQL* admin, const char* name) {
	return admin_single_value(admin,
		std::string("SELECT variable_value FROM global_variables WHERE variable_name='") + name + "'");
}

static long long gtid_session_collected(MYSQL* admin) {
	const std::string v = admin_single_value(admin,
		"SELECT variable_value FROM stats_mysql_global WHERE variable_name='GTID_session_collected'");
	return v.empty() ? -1 : strtoll(v.c_str(), NULL, 10);
}

static bool set_gtid_vars(MYSQL* admin, const std::string& track_gtid, const std::string& from_ok) {
	bool result = admin_exec(admin, "SET mysql-client_session_track_gtid='" + track_gtid + "'");
	result = admin_exec(admin, "SET mysql-update_gtid_from_ok='" + from_ok + "'") && result;
	return admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME") && result;
}

struct RestoreGtidVars {
	MYSQL* admin;
	std::string track_gtid;
	std::string from_ok;
	bool active = true;

	bool restore() {
		if (!active) return true;
		if (!set_gtid_vars(admin, track_gtid, from_ok)) return false;
		active = false;
		return true;
	}

	~RestoreGtidVars() {
		if (!restore()) diag("Failed to restore the original GTID settings during cleanup");
	}
};

/**
 * @brief Returns the GTID stored for the first backend in 'PROXYSQL INTERNAL SESSION'
 *  that has one, or an empty string.
 */
static std::string backend_gtid_from_internal_session(MYSQL* proxy) {
	if (mysql_query(proxy, "PROXYSQL INTERNAL SESSION")) {
		diag("PROXYSQL INTERNAL SESSION failed: %s", mysql_error(proxy));
		return "";
	}
	MYSQL_RES* r = mysql_store_result(proxy);
	if (r == NULL) return "";
	std::string gtid {};
	MYSQL_ROW row = mysql_fetch_row(r);
	if (row && row[0]) {
		try {
			const json j = json::parse(row[0]);
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
	}
	mysql_free_result(r);
	return gtid;
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(5);

	std::unique_ptr<MYSQL, decltype(&mysql_close)> admin_owner(mysql_init(NULL), mysql_close);
	MYSQL* admin = admin_owner.get();
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connect failed: %s", mysql_error(admin));
		return exit_status();
	}

	const std::string orig_track_gtid = global_var(admin, "mysql-client_session_track_gtid");
	const std::string orig_from_ok = global_var(admin, "mysql-update_gtid_from_ok");
	if (orig_track_gtid.empty() || orig_from_ok.empty()) {
		diag("Cannot save the original GTID settings; leaving configuration unchanged");
		return EXIT_FAILURE;
	}
	diag("Original values: mysql-client_session_track_gtid='%s' mysql-update_gtid_from_ok='%s'",
		orig_track_gtid.c_str(), orig_from_ok.c_str());
	// Declared after the Admin owner so cleanup also covers macro returns,
	// and always runs before the Admin connection is closed.
	RestoreGtidVars restore_gtid_vars { admin, orig_track_gtid, orig_from_ok };

	// Both settings that only control what is done *with* a collected GTID are off.
	const bool configured = set_gtid_vars(admin, "false", "false");
	ok(configured,
		"Disabled mysql-client_session_track_gtid and mysql-update_gtid_from_ok");
	if (!configured) {
		skip(3, "Cannot exercise GTID collection without configuring both variables");
		ok(restore_gtid_vars.restore(), "Restored the original GTID settings");
		return exit_status();
	}
	// Let the worker threads pick up the new thread-local values.
	usleep(500 * 1000);

	std::unique_ptr<MYSQL, decltype(&mysql_close)> proxy_owner(mysql_init(NULL), mysql_close);
	MYSQL* proxy = proxy_owner.get();
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Client connect failed: %s", mysql_error(proxy));
		return exit_status();
	}

	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_T(proxy, "CREATE TABLE IF NOT EXISTS test.reg_test_6328 (id INT NOT NULL)");
	// The backend only reports the GTID of the session's own transactions when
	// OWN_GTID tracking is requested; ProxySQL propagates this to the backend.
	MYSQL_QUERY_T(proxy, "SET SESSION_TRACK_GTIDS=OWN_GTID");

	const long long collected_before = gtid_session_collected(admin);
	diag("GTID_session_collected before writes: %lld", collected_before);

	bool client_received_gtid = false;
	for (int i = 0; i < NUM_WRITES; i++) {
		const std::string q = "INSERT INTO test.reg_test_6328 VALUES (" + std::to_string(i) + ")";
		MYSQL_QUERY_T(proxy, q.c_str());
		if (proxy->server_status & SERVER_SESSION_STATE_CHANGED) {
			const char* data = NULL;
			size_t length = 0;
			if (mysql_session_track_get_first(proxy, SESSION_TRACK_GTIDS, &data, &length) == 0 && length > 0) {
				diag("Client received GTID '%.*s' on write %d", (int)length, data, i);
				client_received_gtid = true;
			}
		}
	}

	const long long collected_after = gtid_session_collected(admin);
	diag("GTID_session_collected after %d writes: %lld", NUM_WRITES, collected_after);

	ok(collected_before >= 0 && collected_after >= collected_before + NUM_WRITES,
		"GTIDs are collected with both GTID settings disabled: before=%lld after=%lld (expected >= +%d)",
		collected_before, collected_after, NUM_WRITES);

	const std::string backend_gtid = backend_gtid_from_internal_session(proxy);
	ok(!backend_gtid.empty(),
		"The session backend keeps the collected GTID used by gtid_from_hostgroup: '%s'",
		backend_gtid.c_str());

	ok(client_received_gtid == false,
		"The GTID is not forwarded to the client while mysql-client_session_track_gtid=false");

	MYSQL_QUERY_T(proxy, "DROP TABLE IF EXISTS test.reg_test_6328");
	proxy_owner.reset();

	ok(restore_gtid_vars.restore(), "Restored the original GTID settings");

	return exit_status();
}
