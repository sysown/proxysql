/**
 * @file test_client_connect_attrs-t.cpp
 * @brief Verify frontend client connection attributes are visible in processlist extended info.
 */

#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "json.hpp"

using nlohmann::json;

static bool run_admin_query(MYSQL* admin, const char* query) {
	if (mysql_query(admin, query) != 0) {
		diag("Query failed: %s; error: %s", query, mysql_error(admin));
		return false;
	}
	MYSQL_RES* result = mysql_store_result(admin);
	if (result) {
		mysql_free_result(result);
	}
	return true;
}

static bool fetch_extended_info(MYSQL* admin, unsigned long session_id, json& extended_info) {
	const std::string query =
		"SELECT extended_info FROM stats_mysql_processlist WHERE SessionID=" + std::to_string(session_id);
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("Query failed: %s; error: %s", query.c_str(), mysql_error(admin));
		return false;
	}

	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) {
		diag("mysql_store_result failed for query: %s; error: %s", query.c_str(), mysql_error(admin));
		return false;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	if (!row || !row[0]) {
		mysql_free_result(result);
		diag("No extended_info found for session %lu", session_id);
		return false;
	}

	try {
		extended_info = json::parse(row[0]);
	} catch (const std::exception& error) {
		diag("Unable to parse extended_info for session %lu: %s", session_id, error.what());
		mysql_free_result(result);
		return false;
	}

	mysql_free_result(result);
	return true;
}

int main(int argc, char** argv) {
	CommandLine cl;
	plan(5);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(nullptr);
	if (!admin) {
		diag("mysql_init failed for admin connection");
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	const bool configured =
		run_admin_query(admin, "SET mysql-show_processlist_extended=1") &&
		run_admin_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	if (!configured) {
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	MYSQL* frontend = mysql_init(nullptr);
	if (!frontend) {
		diag("mysql_init failed for frontend connection");
		run_admin_query(admin, "SET mysql-show_processlist_extended=0");
		run_admin_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	const int program_name_rc = mysql_options4(
		frontend, MYSQL_OPT_CONNECT_ATTR_ADD, "program_name", "proxysql-client-connect-attrs-test"
	);
	const int issue_rc = mysql_options4(frontend, MYSQL_OPT_CONNECT_ATTR_ADD, "proxysql_issue", "670");
	ok(program_name_rc == 0 && issue_rc == 0, "Client connection attributes are configured before connect");

	MYSQL* connected = mysql_real_connect(frontend, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0);
	ok(connected != nullptr, "Frontend client connects to ProxySQL with connection attributes");
	if (!connected) {
		diag("Failed to connect to ProxySQL frontend: %s", mysql_error(frontend));
		mysql_close(frontend);
		run_admin_query(admin, "SET mysql-show_processlist_extended=0");
		run_admin_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		mysql_close(admin);
		return exit_status();
	}

	const unsigned long session_id = mysql_thread_id(frontend);
	json extended_info;
	const bool has_extended_info = fetch_extended_info(admin, session_id, extended_info);
	ok(has_extended_info, "Processlist exposes extended_info for frontend session %lu", session_id);

	bool attrs_visible = false;
	if (has_extended_info
		&& extended_info.contains("client")
		&& extended_info["client"].contains("connect_attrs")
		&& extended_info["client"]["connect_attrs"].is_object()) {
		const json& attrs = extended_info["client"]["connect_attrs"];
		attrs_visible = attrs.value("program_name", "") == "proxysql-client-connect-attrs-test"
			&& attrs.value("proxysql_issue", "") == "670";
	}
	ok(attrs_visible, "Processlist extended_info contains frontend client connection attributes");
	if (!attrs_visible && has_extended_info) {
		diag("Processlist extended_info: %s", extended_info.dump().c_str());
	}

	mysql_close(frontend);
	const bool restored =
		run_admin_query(admin, "SET mysql-show_processlist_extended=0") &&
		run_admin_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(restored, "Restored mysql-show_processlist_extended");
	mysql_close(admin);

	return exit_status();
}
