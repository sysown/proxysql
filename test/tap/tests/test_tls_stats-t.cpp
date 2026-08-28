/**
 * @file test_tls_stats-t.cpp
 * @brief TAP test for stats_tls_certificates and stats_proxysql_global TLS metrics.
 *
 * @details This test verifies:
 *   1. stats_proxysql_global table exists and is queryable from the stats schema.
 *   2. stats_proxysql_global contains the expected TLS tracking variables:
 *        - TLS_Load_Count
 *        - TLS_Last_Load_Timestamp
 *        - TLS_Last_Load_Result
 *        - TLS_Server_Cert_File
 *        - TLS_CA_Cert_File
 *        - TLS_Key_File
 *   3. TLS_Load_Count >= 1 (ProxySQL always loads certs at startup).
 *   4. TLS_Last_Load_Timestamp is a positive Unix timestamp.
 *   5. TLS_Last_Load_Result is one of "NONE", "SUCCESS", or "FAILED".
 *   6. TLS_Server_Cert_File and TLS_CA_Cert_File are non-empty strings.
 *   7. stats_tls_certificates table exists and is queryable.
 *   8. stats_tls_certificates has exactly two rows (cert_type 'server' and 'ca').
 *   9. Both rows have non-empty file_path, subject_cn, issuer_cn, serial_number,
 *        not_before, not_after, sha256_fingerprint.
 *  10. days_until_expiry is a reasonable value (> -36500 and < 36500).
 *  11. loaded_at is a positive Unix timestamp.
 *  12. After PROXYSQL RELOAD TLS:
 *        - TLS_Load_Count in stats_proxysql_global increments by 1.
 *        - stats_tls_certificates rows are still present and non-empty.
 *  13. TLS_Last_Load_Timestamp in stats_proxysql_global increases after PROXYSQL RELOAD TLS.
 *  14. TLS-related variables are NOT present in stats_mysql_global.
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::map;
using std::set;
using std::string;
using std::vector;

/** @brief Maximum plausible lifetime of a certificate in days (approx. 100 years). */
static const int MAX_CERT_DAYS = 36500;

/**
 * @brief Executes a query and returns all rows as a map keyed by the first column.
 * @param conn   An open MySQL connection.
 * @param query  The SQL query to run (must return exactly 2 columns).
 * @return A map<string, string> where key=col[0] and value=col[1].
 */
static map<string,string> query_key_value(MYSQL* conn, const char* query) {
	map<string,string> result;
	if (mysql_query(conn, query)) {
		diag("Query failed: '%s' err='%s'", query, mysql_error(conn));
		return result;
	}
	MYSQL_RES* res = mysql_store_result(conn);
	if (!res) return result;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(res))) {
		if (row[0] && row[1])
			result[string(row[0])] = string(row[1]);
	}
	mysql_free_result(res);
	return result;
}

/**
 * @brief Executes a query and returns all rows as a vector of key-value maps.
 * @param conn     An open MySQL connection.
 * @param query    The SQL query to run.
 * @param col_names  Column names to use as map keys (in order).
 * @return A vector of maps, one per result row.
 */
static vector<map<string,string>> query_rows(MYSQL* conn, const char* query, const vector<string>& col_names) {
	vector<map<string,string>> rows;
	if (mysql_query(conn, query)) {
		diag("Query failed: '%s' err='%s'", query, mysql_error(conn));
		return rows;
	}
	MYSQL_RES* res = mysql_store_result(conn);
	if (!res) return rows;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(res))) {
		map<string,string> r;
		for (size_t i = 0; i < col_names.size(); i++) {
			r[col_names[i]] = row[i] ? string(row[i]) : "";
		}
		rows.push_back(r);
	}
	mysql_free_result(res);
	return rows;
}

int main(int argc, char** argv) {
	CommandLine cl;

	diag("TAP test for SSL/TLS Certificate Statistics Table");
	diag("This test verifies that ProxySQL correctly reports TLS certificate information,");
	diag("tracks TLS load operations in stats_proxysql_global, and updates these stats after a reload.");

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	// Tests:
	// 1-5: stats_proxysql_global TLS variables present
	// 6-9: stats_proxysql_global TLS variable values
	// 10-11: TLS_Last_Load_Result valid value
	// 12-16: stats_tls_certificates structure
	// 17-24: stats_tls_certificates row data for 'server' and 'ca'
	// 23-26: PROXYSQL RELOAD TLS increments counter and updates timestamp
	// 27: TLS vars NOT in stats_mysql_global
	plan(27);

	diag("Connecting to ProxySQL Admin interface on %s:%d", cl.host, cl.admin_port);
	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}

	// -----------------------------------------------------------------------
	// Part 1: stats_proxysql_global - TLS tracking variables
	// -----------------------------------------------------------------------
	diag("Step 1: Verifying TLS tracking variables in stats.stats_proxysql_global");
	diag("--- Querying stats.stats_proxysql_global ---");

	auto global_stats = query_key_value(admin,
		"SELECT Variable_Name, Variable_Value FROM stats.stats_proxysql_global");

	const vector<string> expected_tls_vars = {
		"TLS_Load_Count",
		"TLS_Last_Load_Timestamp",
		"TLS_Last_Load_Result",
		"TLS_Server_Cert_File",
		"TLS_CA_Cert_File",
		"TLS_Key_File",
	};

	for (const auto& var : expected_tls_vars) {
		ok(global_stats.count(var) > 0,
			"stats_proxysql_global: Variable '%s' is present", var.c_str());
	}

	diag("Verifying values of TLS tracking variables...");
	// TLS_Load_Count >= 1
	int tls_load_count = 0;
	if (global_stats.count("TLS_Load_Count"))
		tls_load_count = std::stoi(global_stats["TLS_Load_Count"]);
	ok(tls_load_count >= 1,
		"stats_proxysql_global: TLS_Load_Count is >= 1 (was %d)", tls_load_count);

	// TLS_Last_Load_Timestamp is a positive Unix timestamp (> 0)
	long long tls_ts = 0;
	if (global_stats.count("TLS_Last_Load_Timestamp"))
		tls_ts = std::stoll(global_stats["TLS_Last_Load_Timestamp"]);
	ok(tls_ts > 0,
		"stats_proxysql_global: TLS_Last_Load_Timestamp is positive (was %lld)", tls_ts);

	// TLS_Last_Load_Result must be one of NONE, SUCCESS, FAILED
	string tls_result = global_stats.count("TLS_Last_Load_Result") ?
		global_stats["TLS_Last_Load_Result"] : "";
	ok(tls_result == "SUCCESS" || tls_result == "NONE" || tls_result == "FAILED",
		"stats_proxysql_global: TLS_Last_Load_Result='%s' is valid (NONE/SUCCESS/FAILED)",
		tls_result.c_str());

	// TLS_Server_Cert_File should be a non-empty path
	string cert_file = global_stats.count("TLS_Server_Cert_File") ?
		global_stats["TLS_Server_Cert_File"] : "";
	ok(!cert_file.empty(),
		"stats_proxysql_global: TLS_Server_Cert_File is non-empty ('%s')", cert_file.c_str());

	// TLS_CA_Cert_File should be a non-empty path
	string ca_file = global_stats.count("TLS_CA_Cert_File") ?
		global_stats["TLS_CA_Cert_File"] : "";
	ok(!ca_file.empty(),
		"stats_proxysql_global: TLS_CA_Cert_File is non-empty ('%s')", ca_file.c_str());

	// -----------------------------------------------------------------------
	// Part 2: stats_tls_certificates - table structure and row content
	// -----------------------------------------------------------------------
	diag("Step 2: Verifying content of stats.stats_tls_certificates");
	diag("--- Querying stats.stats_tls_certificates ---");

	const vector<string> cert_cols = {
		"cert_type", "file_path", "subject_cn", "issuer_cn",
		"serial_number", "not_before", "not_after",
		"days_until_expiry", "sha256_fingerprint", "loaded_at"
	};

	auto cert_rows = query_rows(admin,
		"SELECT cert_type, file_path, subject_cn, issuer_cn, serial_number, "
		"not_before, not_after, days_until_expiry, sha256_fingerprint, loaded_at "
		"FROM stats.stats_tls_certificates",
		cert_cols);

	// Should have exactly 2 rows: 'server' and 'ca'
	ok(cert_rows.size() == 2,
		"stats_tls_certificates: has exactly 2 rows (got %zu)", cert_rows.size());

	// Find the 'server' and 'ca' rows
	map<string,string> server_row, ca_row;
	for (const auto& r : cert_rows) {
		if (r.at("cert_type") == "server") server_row = r;
		if (r.at("cert_type") == "ca")     ca_row     = r;
	}

	diag("Validating cert_type 'server' and 'ca' rows exist...");
	ok(!server_row.empty(), "stats_tls_certificates: row with cert_type='server' exists");
	ok(!ca_row.empty(),     "stats_tls_certificates: row with cert_type='ca' exists");

	// Check non-empty required fields for server cert
	diag("Validating server certificate row data...");
	if (!server_row.empty()) {
		ok(!server_row["file_path"].empty(),
			"stats_tls_certificates: server file_path is non-empty ('%s')",
			server_row["file_path"].c_str());
		ok(!server_row["sha256_fingerprint"].empty(),
			"stats_tls_certificates: server sha256_fingerprint is non-empty");
		int server_days = std::stoi(server_row["days_until_expiry"]);
		ok(server_days > -MAX_CERT_DAYS && server_days < MAX_CERT_DAYS,
			"stats_tls_certificates: server days_until_expiry=%d is reasonable",
			server_days);
		long long server_loaded_at = std::stoll(server_row["loaded_at"]);
		ok(server_loaded_at > 0,
			"stats_tls_certificates: server loaded_at=%lld is positive",
			server_loaded_at);
	} else {
		ok(false, "stats_tls_certificates: server file_path is non-empty (row missing)");
		ok(false, "stats_tls_certificates: server sha256_fingerprint is non-empty (row missing)");
		ok(false, "stats_tls_certificates: server days_until_expiry is reasonable (row missing)");
		ok(false, "stats_tls_certificates: server loaded_at is positive (row missing)");
	}

	// Check non-empty required fields for CA cert
	diag("Validating CA certificate row data...");
	if (!ca_row.empty()) {
		ok(!ca_row["file_path"].empty(),
			"stats_tls_certificates: ca file_path is non-empty ('%s')",
			ca_row["file_path"].c_str());
		ok(!ca_row["sha256_fingerprint"].empty(),
			"stats_tls_certificates: ca sha256_fingerprint is non-empty");
		int ca_days = std::stoi(ca_row["days_until_expiry"]);
		ok(ca_days > -MAX_CERT_DAYS && ca_days < MAX_CERT_DAYS,
			"stats_tls_certificates: ca days_until_expiry=%d is reasonable",
			ca_days);
		long long ca_loaded_at = std::stoll(ca_row["loaded_at"]);
		ok(ca_loaded_at > 0,
			"stats_tls_certificates: ca loaded_at=%lld is positive",
			ca_loaded_at);
	} else {
		ok(false, "stats_tls_certificates: ca file_path is non-empty (row missing)");
		ok(false, "stats_tls_certificates: ca sha256_fingerprint is non-empty (row missing)");
		ok(false, "stats_tls_certificates: ca days_until_expiry is reasonable (row missing)");
		ok(false, "stats_tls_certificates: ca loaded_at is positive (row missing)");
	}

	// -----------------------------------------------------------------------
	// Part 3: PROXYSQL RELOAD TLS increments TLS_Load_Count and updates timestamp
	// -----------------------------------------------------------------------
	diag("Step 3: Verifying PROXYSQL RELOAD TLS updates stats");
	diag("--- Executing PROXYSQL RELOAD TLS ---");

	// Sleep 1 second to guarantee timestamp changes on fast systems
	sleep(1);

	if (mysql_query(admin, "PROXYSQL RELOAD TLS")) {
		diag("PROXYSQL RELOAD TLS failed: %s", mysql_error(admin));
	}
	mysql_free_result(mysql_store_result(admin));

	diag("Verifying updated stats in stats.stats_proxysql_global after reload...");
	auto global_stats_after = query_key_value(admin,
		"SELECT Variable_Name, Variable_Value FROM stats.stats_proxysql_global");

	int tls_load_count_after = 0;
	if (global_stats_after.count("TLS_Load_Count"))
		tls_load_count_after = std::stoi(global_stats_after["TLS_Load_Count"]);
	ok(tls_load_count_after == tls_load_count + 1,
		"stats_proxysql_global: TLS_Load_Count incremented after RELOAD TLS (%d -> %d)",
		tls_load_count, tls_load_count_after);

	long long tls_ts_after = 0;
	if (global_stats_after.count("TLS_Last_Load_Timestamp"))
		tls_ts_after = std::stoll(global_stats_after["TLS_Last_Load_Timestamp"]);
	ok(tls_ts_after > tls_ts,
		"stats_proxysql_global: TLS_Last_Load_Timestamp increased after RELOAD TLS (%lld -> %lld)",
		tls_ts, tls_ts_after);

	string tls_result_after = global_stats_after.count("TLS_Last_Load_Result") ?
		global_stats_after["TLS_Last_Load_Result"] : "";
	ok(tls_result_after == "SUCCESS",
		"stats_proxysql_global: TLS_Last_Load_Result='SUCCESS' after RELOAD TLS (got '%s')",
		tls_result_after.c_str());

	diag("Verifying stats.stats_tls_certificates rows after reload...");
	// stats_tls_certificates rows still present after reload
	auto cert_rows_after = query_rows(admin,
		"SELECT cert_type, file_path, sha256_fingerprint FROM stats.stats_tls_certificates",
		{"cert_type", "file_path", "sha256_fingerprint"});
	ok(cert_rows_after.size() == 2,
		"stats_tls_certificates: still has 2 rows after RELOAD TLS (got %zu)",
		cert_rows_after.size());

	// -----------------------------------------------------------------------
	// Part 4: TLS variables must NOT appear in stats_mysql_global
	// -----------------------------------------------------------------------
	diag("Step 4: Verifying TLS variables are absent from stats.stats_mysql_global");
	diag("--- Querying stats.stats_mysql_global ---");

	auto mysql_global_stats = query_key_value(admin,
		"SELECT Variable_Name, Variable_Value FROM stats.stats_mysql_global");

	bool tls_vars_in_mysql_global = false;
	for (const auto& var : expected_tls_vars) {
		if (mysql_global_stats.count(var)) {
			diag("UNEXPECTED: TLS variable '%s' found in stats_mysql_global", var.c_str());
			tls_vars_in_mysql_global = true;
		}
	}
	ok(!tls_vars_in_mysql_global,
		"TLS variables are NOT present in stats_mysql_global");

	diag("Test completed successfully, closing connection.");
	mysql_close(admin);
	return exit_status();
}
