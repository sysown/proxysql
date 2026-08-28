/**
 * @file test_prometheus_metrics-t.cpp
 * @brief Integration tests for ProxySQL Prometheus metrics.
 * 
 * This test suite verifies that various Prometheus metrics are correctly 
 * incremented or updated when specific events occur within ProxySQL.
 * It covers hostgroup-specific metrics, access denied errors, transaction 
 * rollbacks, and connection pool statistics.
 * 
 * Each test follows a Setup -> Record -> Trigger -> Record -> Verify flow.
 * 
 * @date 2021-03-01
 */

#include <cmath>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <utility>
#include <set>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "json.hpp"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::function;
using std::map;
using std::vector;
using std::pair;
using std::string;
using std::tuple;

/**
 * @brief Global command line options for the test.
 */
CommandLine cl;

// Writer hostgroup: read from TAP_MYSQL8_BACKEND_HG, fallback to 0 for legacy
static const int WRITER_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 0);
static const string WRITER_HG_S = std::to_string(WRITER_HG);

/**
 * @brief Helper function to execute a MySQL query and log it to diagnostics.
 * 
 * @param mysql The MySQL connection handle.
 * @param query The SQL query string to execute.
 * @return int The result of mysql_query().
 */
int mysql_query_d(MYSQL* mysql, const char* query) {
	diag("Query: Issuing query '%s' to ('%s':%d)", query, mysql->host, mysql->port);
	return mysql_query(mysql, query);
}

/**
 * @brief Fetches the current Prometheus metrics from ProxySQL Admin.
 * 
 * Issues 'SHOW PROMETHEUS METRICS' to the admin interface and parses the result
 * into a map of metric names (including labels) to their current double values.
 * 
 * @param admin The MySQL connection handle to ProxySQL Admin.
 * @param[out] metrics_vals Map to store the parsed metrics.
 * @return int EXIT_SUCCESS on success, or an error code.
 */
int get_cur_metrics(MYSQL* admin, map<string,double>& metrics_vals) {
	MYSQL_QUERY(admin, "SHOW PROMETHEUS METRICS\\G");
	MYSQL_RES* p_resulset = mysql_store_result(admin);
	MYSQL_ROW data_row = mysql_fetch_row(p_resulset);

	std::string row_value {};
	if (data_row && data_row[0]) {
		row_value = data_row[0];
	} else {
		row_value = "NULL";
	}

	mysql_free_result(p_resulset);
	metrics_vals = parse_prometheus_metrics(row_value);

	return EXIT_SUCCESS;
}

/**
 * @brief Triggers the increment of 'proxysql_myhgm_auto_increment_multiplex_total'.
 * 
 * Creates a temporary table and inserts a row to trigger the auto-increment 
 * multiplexing logic.
 * 
 * @param proxy Opened MYSQL handler to ProxySQL.
 * @return bool True if the action was successful, false otherwise.
 */
bool trigger_auto_increment_delay_multiplex_metric(MYSQL* proxy, MYSQL*, const CommandLine&) {
	int inc_query_res =
		mysql_query(
			proxy,
			"CREATE TEMPORARY TABLE test.auto_inc_test_table("
			" id MEDIUMINT NOT NULL AUTO_INCREMENT, text VARCHAR(50) NOT NULL, PRIMARY KEY (id))"
		);
	if (inc_query_res) {
		diag("Failed to create temporary table to perform query.");
		return false;
	}

	const char* inc_query = "INSERT INTO test.auto_inc_test_table (text) VALUES ('sample_val')";
	inc_query_res = mysql_query(proxy, inc_query);
	if (inc_query_res) {
		diag("Failed to execute the query '%s'.", inc_query);
		return false;
	}

	return true;
}

/**
 * @brief Verifies that 'proxysql_myhgm_auto_increment_multiplex_total' incremented.
 * 
 * Uses prefix matching to handle potential labels and allows for missing 
 * previous metric value (defaults to 0).
 * 
 * @param prev_metrics Metrics values before the trigger.
 * @param after_metrics Metrics values after the trigger.
 */
void check_auto_increment_delay_multiplex_metric(
	const std::map<std::string, double>& prev_metrics,
	const std::map<std::string, double>& after_metrics
) {
	auto prev_metric_key = prev_metrics.end();
	auto after_metric_key = after_metrics.end();

	for (auto it = prev_metrics.begin(); it != prev_metrics.end(); ++it) {
		if (it->first.rfind("proxysql_myhgm_auto_increment_multiplex_total", 0) == 0) {
			prev_metric_key = it;
			break;
		}
	}
	for (auto it = after_metrics.begin(); it != after_metrics.end(); ++it) {
		if (it->first.rfind("proxysql_myhgm_auto_increment_multiplex_total", 0) == 0) {
			after_metric_key = it;
			break;
		}
	}

	bool metric_found = after_metric_key != after_metrics.end();

	ok(metric_found, "Metric was present in output from 'SHOW PROMETHEUS METRICS'");
	if (metric_found) {
		double prev_metric_val = 0;
		if (prev_metric_key != prev_metrics.end()) {
			prev_metric_val = prev_metric_key->second;
		}
		double after_metric_val = after_metric_key->second;

		bool is_updated =
			fabs(prev_metric_val + 1 - after_metric_val) < 0.1;
		ok(is_updated, "Metric has a properly updated value.");
	} else {
		ok(false, "Metric has a properly updated value.");
	}
}

/**
 * @brief Triggers 'proxysql_access_denied_wrong_password_total' by failing login.
 * 
 * Attempts a connection with an invalid username/password combination.
 * 
 * @param cl Command line arguments containing host and port.
 * @return bool True if the access denied error was correctly received.
 */
bool trigger_access_denied_wrong_password_total(MYSQL*, MYSQL*, const CommandLine& cl) {
	// Initialize ProxySQL connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	// Connect to ProxySQL with invalid credentials
	bool access_denied_error = false;
	void* connect_res = mysql_real_connect(proxysql, cl.host, "invalid_username", "invalid_password", NULL, cl.port, NULL, 0);
	int access_errno = mysql_errno(proxysql);

	if (!connect_res && access_errno == ER_ACCESS_DENIED_ERROR) {
		access_denied_error = true;
	} else {
		diag("Connections should have failed due to access denied. ErrCode: %d", access_errno);
		access_denied_error = false;
	}

	mysql_close(proxysql);

	return access_denied_error;
}

/**
 * @brief Verifies that 'proxysql_access_denied_wrong_password_total' incremented.
 * 
 * Uses prefix matching because this metric includes a {protocol=\"mysql\"} label.
 * 
 * @param prev_metrics Metrics values before the trigger.
 * @param after_metrics Metrics values after the trigger.
 */
void check_access_denied_wrong_password_total(
	const std::map<std::string, double>& prev_metrics,
	const std::map<std::string, double>& after_metrics
) {
	auto prev_metric_key = prev_metrics.end();
	auto after_metric_key = after_metrics.end();

	for (auto it = prev_metrics.begin(); it != prev_metrics.end(); ++it) {
		if (it->first.rfind("proxysql_access_denied_wrong_password_total", 0) == 0) {
			prev_metric_key = it;
			break;
		}
	}
	for (auto it = after_metrics.begin(); it != after_metrics.end(); ++it) {
		if (it->first.rfind("proxysql_access_denied_wrong_password_total", 0) == 0) {
			after_metric_key = it;
			break;
		}
	}

	bool metric_found = after_metric_key != after_metrics.end();

	ok(metric_found, "Metric was present in output from 'SHOW PROMETHEUS METRICS'");
	if (metric_found) {
		double prev_metric_val = 0;
		if (prev_metric_key != prev_metrics.end()) {
			prev_metric_val = prev_metric_key->second;
		}
		double after_metric_val = after_metric_key->second;

		bool is_updated =
			fabs(prev_metric_val + 1 - after_metric_val) < 0.1;
		ok(is_updated, "Metric has a properly updated value.");
	} else {
		ok(false, "Metric has a properly updated value.");
	}
}

/**
 * @brief Triggers 'proxysql_com_rollback_total' by rolling back a transaction.
 * 
 * @param proxysql Opened MYSQL handler to ProxySQL.
 * @return bool True if ROLLBACK command was successful.
 */
bool trigger_transaction_rollback_total(MYSQL* proxysql, MYSQL*, const CommandLine&) {
	int st_err = mysql_query(proxysql, "BEGIN");
	bool res = false;

	if (!st_err) {
		int rl_err = mysql_query(proxysql, "ROLLBACK");

		if (!rl_err) {
			res = true;
		}
	}

	return res;
}

/**
 * @brief Verifies that 'proxysql_com_rollback_total' incremented.
 * 
 * Uses prefix matching to handle potential labels.
 * 
 * @param prev_metrics Metrics values before the trigger.
 * @param after_metrics Metrics values after the trigger.
 */
void check_transaction_rollback_total(
	const std::map<std::string, double>& prev_metrics,
	const std::map<std::string, double>& after_metrics
){
	auto prev_metric_key = prev_metrics.end();
	auto after_metric_key = after_metrics.end();

	for (auto it = prev_metrics.begin(); it != prev_metrics.end(); ++it) {
		if (it->first.rfind("proxysql_com_rollback_total", 0) == 0) {
			prev_metric_key = it;
			break;
		}
	}
	for (auto it = after_metrics.begin(); it != after_metrics.end(); ++it) {
		if (it->first.rfind("proxysql_com_rollback_total", 0) == 0) {
			after_metric_key = it;
			break;
		}
	}

	bool metric_found = after_metric_key != after_metrics.end();

	ok(metric_found, "Metric was present in output from 'SHOW PROMETHEUS METRICS'");
	if (metric_found) {
		double prev_metric_val = 0;
		if (prev_metric_key != prev_metrics.end()) {
			prev_metric_val = prev_metric_key->second;
		}
		double after_metric_val = after_metric_key->second;

		bool is_updated =
			fabs(prev_metric_val + 1 - after_metric_val) < 0.1;
		ok(is_updated, "Metric has a properly updated value.");
	} else {
		ok(false, "Metric has a properly updated value.");
	}
}

/**
 * @brief Global storage for the ProxySQL version string fetched during tests.
 */
string PROXYSQL_VERSION {};

/**
 * @brief Fetches the current ProxySQL version via 'SELECT @@version'.
 * 
 * @param admin Opened MYSQL handler to ProxySQL Admin.
 * @return bool True if version was successfully fetched.
 */
bool get_proxysql_version_info(MYSQL*, MYSQL* admin, const CommandLine&) {
	int v_err = mysql_query(admin, "SELECT @@version");
	if (v_err) {
		diag(
			"'mysql_query' failed for 'SELECT @@version' with {Line: %d, Err: '%s'}",
			__LINE__, mysql_error(admin)
		);
		return false;
	}

	MYSQL_RES* v_res = mysql_store_result(admin);
	vector<mysql_res_row> res_rows = extract_mysql_rows(v_res);
	mysql_free_result(v_res);

	if (res_rows.size() != 1 && res_rows[0].size() != 1) {
		diag("Invalid resulset received for 'SELECT @@version' at Line: %d", __LINE__);
		return false;
	} else {
		PROXYSQL_VERSION = res_rows[0][0];
		return true;
	}
}

/**
 * @brief Verifies that 'proxysql_version_info' metric contains the correct version label.
 * 
 * This metric is a gauge with value 1.0 and labels containing the version information.
 * 
 * @param after_metrics Metrics values after the trigger.
 */
void check_proxysql_version_info(const map<string, double>& prev_metrics, const map<string, double>& after_metrics) {
	map<string,double>::const_iterator after_metric_it { after_metrics.end() };

	for (auto metric_key = after_metrics.begin(); metric_key != after_metrics.end(); metric_key++) {
		if (metric_key->first.rfind("proxysql_version_info") == 0) {
			after_metric_it = metric_key;
		}
	}

	bool metric_found = after_metric_it != after_metrics.end();
	ok(metric_found, "Metric was present in output from 'SHOW PROMETHEUS METRICS'");

	if (metric_found) {
		string after_metric_key = after_metric_it->first;
		double after_metric_val = after_metric_it->second;

		size_t v_id_len = strlen("version=\"");
		size_t v_pos_st = after_metric_key.find("version=\"", 0);
		size_t v_id_pos_st = v_pos_st + v_id_len;
		size_t v_id_pos_end = after_metric_key.find_first_of("\"", v_id_pos_st);

		string v_proxysql_metric = after_metric_key.substr(v_id_pos_st, v_id_pos_end - v_id_pos_st);

		ok(
			v_proxysql_metric == PROXYSQL_VERSION,
			"Metric expected key and value match: {act_key:'%s', exp_key:'%s', act_val:'%lf', exp_val:'%lf'}",
			v_proxysql_metric.c_str(), PROXYSQL_VERSION.c_str(), after_metric_val, 1.0
		);
	} else {
		ok(false, "Metric has a properly updated value.");
	}
}

/**
 * @brief Internal helper to extract the next label-value pair from a metric string.
 * 
 * @param metric_id The metric identifier string containing labels.
 * @param st_pos Starting position for extraction.
 * @return pair<pair<string,string>,string::size_type> The extracted {key, value} pair and the next position.
 */
pair<pair<string,string>,string::size_type> extract_next_tag(const string metric_id, string::size_type st_pos) {
	string::size_type tag_eq_pos = metric_id.find("=\"", st_pos);
	if (tag_eq_pos == string::npos) {
		return { {}, string::npos };
	}

	string key { metric_id.substr(st_pos, tag_eq_pos - st_pos) };
	string::size_type tag_val_st = tag_eq_pos + 2;
	string::size_type tag_val_end = metric_id.find_first_of("\"", tag_val_st);
	string val { metric_id.substr(tag_val_st, tag_val_end - tag_val_st) };

	return { { key, val }, tag_val_end + 2 };
}

/**
 * @brief Parses labels from a Prometheus metric identifier.
 * 
 * Example: 'metric_name{label1="val1",label2="val2"}' -> map {label1: val1, label2: val2}
 * 
 * @param metric_id The full metric identifier string.
 * @return map<string,string> Map of label names to label values.
 */
map<string,string> extract_metric_tags(const string metric_id) {
	string::size_type tags_init_pos = metric_id.find('{');
	if (tags_init_pos == std::string::npos) {
		return {};
	}

	string::size_type tags_final_pos = metric_id.find_first_of('}', tags_init_pos);
	if (tags_final_pos == std::string::npos) {
		return {};
	}

	string metric_tags = metric_id.substr(tags_init_pos + 1, tags_final_pos - tags_init_pos - 1);
	auto next_tag { extract_next_tag(metric_tags, 0) };
	map<string,string> result {};

	while (next_tag.second != string::npos) {
		result.insert(next_tag.first);
		next_tag = extract_next_tag(metric_tags, next_tag.second);
	}

	return result;
}

/**
 * @brief Triggers 'proxysql_message_count_total' increment via a parse failure.
 * 
 * Issues an incomplete/invalid query 'SET NAMES' without arguments to 
 * force a parse error.
 * 
 * @param cl Command line arguments.
 * @return bool True if the query failed as expected.
 */
bool trigger_message_count_parse_failure(MYSQL*, MYSQL*, const CommandLine& cl) {
	// Initialize ProxySQL connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return false;
	}
	// Connect to ProxySQL
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return false;
	}

	int res = false;

	int rc = mysql_query(proxysql, "SET NAMES");
	if (rc != EXIT_FAILURE) {
		diag(
			"Invalid query 'SET NAMES' should have failed - ErrCode: %d, ErrMsg: %s",
			mysql_errno(proxysql), mysql_error(proxysql)
		);
		res = false;
	} else {
		res = true;
	}

	mysql_close(proxysql);

	return res;
}

/**
 * @brief Hostgroup ID used for backend connection tests.
 */
int NEW_SRV_HG = get_env_int("TAP_PROMETHEUS_METRICS__NEW_SRV_HG", 1724090);

/**
 * @brief String representation of NEW_SRV_HG.
 */
string NEW_SRV_HG_STR { std::to_string(NEW_SRV_HG) };

/**
 * @brief Target MySQL port as string.
 */
string MY_PORT_STR {};

/**
 * @brief Target MySQL host as string.
 */
string MY_HOST_STR {};

/**
 * @brief Finds a hostgroup ID that is not currently in use.
 * 
 * @param nums Vector of currently used hostgroup IDs.
 * @param offset Initial hostgroup ID to check.
 * @return int A free hostgroup ID.
 */
int find_free_slot(const std::vector<int>& nums, int offset) {
    std::set<int> num_set(nums.begin(), nums.end());

	if (num_set.find(offset) != num_set.end()) {
		auto it = num_set.end();
		return *num_set.rbegin() + 1;
	} else {
		return offset;
	}
}

/**
 * @brief Updates the target hostgroup ID by finding an unused one.
 * 
 * Scans existing metrics for used hostgroups to avoid collisions.
 * 
 * @param admin Opened MYSQL handler to ProxySQL Admin.
 * @return int EXIT_SUCCESS on success.
 */
int upd_tg_metric_hg(MYSQL* admin) {
	// Forces a metrics refresh; all hostgroups from current servers should be present
	map<string,double> cur_metrics {};
	int m_res = get_cur_metrics(admin, cur_metrics);
	if (m_res) {
		diag("Failed to fetch current metrics   rc=%d", m_res);
		return EXIT_FAILURE;
	}

	vector<string> str_hgs {};

	// Build a map with the current hostgroups used
	for (const pair<string,double>& p_metric_val : cur_metrics) {
		if (p_metric_val.first.rfind("proxysql_connpool_conns") == 0) {
			const map<string,string> metric_tags { extract_metric_tags(p_metric_val.first) };
			str_hgs.push_back(metric_tags.at("hostgroup"));
		}
	}

	vector<int> hgs {};
	std::transform(str_hgs.begin(), str_hgs.end(), std::back_inserter(hgs),
		[] (const string& s) -> int {
			return std::atoi(s.c_str());
		}
	);

	// Get a new hostgroup currently not present in the map
	NEW_SRV_HG = find_free_slot(hgs, NEW_SRV_HG);
	NEW_SRV_HG_STR = std::to_string(NEW_SRV_HG);

	return EXIT_SUCCESS;
}

/**
 * @brief Creates a new hostgroup and a connection to it.
 * 
 * This triggers the creation of connection pool metrics for a new hostgroup.
 * 
 * @param proxy Opened MYSQL handler to ProxySQL.
 * @param admin Opened MYSQL handler to ProxySQL Admin.
 * @param cl Command line arguments.
 * @return bool True if setup and connection were successful.
 */
bool trigger_conn_in_new_backend_hg(MYSQL* proxy, MYSQL* admin, const CommandLine& cl) {
	MY_HOST_STR = cl.mysql_host;
	MY_PORT_STR = std::to_string(cl.mysql_port);

	// Update the target hostgroup
	int m_res = upd_tg_metric_hg(admin);
	if (m_res) {
		diag("Failed to update target conn hostgroup   rc=%d", m_res);
		return false;
	}

	// Destroy the previous hostgroup stats
	MYSQL_QUERY(admin, ("DELETE FROM mysql_servers WHERE hostgroup_id=" + NEW_SRV_HG_STR).c_str());
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Re-create the server
	MYSQL_QUERY(admin,
		("INSERT INTO mysql_servers (hostgroup_id,hostname,port) VALUES ("
			+ NEW_SRV_HG_STR + ",'" + MY_HOST_STR + "'," + MY_PORT_STR + ")").c_str()
	);
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Create backend connection; we keep the connection open intentionally (gauge)
	MYSQL_QUERY(proxy, ("/* hostgroup=" + NEW_SRV_HG_STR + " */ BEGIN").c_str());

	return true;
}

/**
 * @brief Triggers an update to an existing backend connection metric.
 * 
 * @param proxy Opened MYSQL handler to ProxySQL.
 * @return bool True if query was successful.
 */
bool trigger_conn_in_prev_backend_hg(MYSQL* proxy, MYSQL* admin, const CommandLine& cl) {
	// Create backend connection; we keep the connection open intentionally (gauge)
	MYSQL_QUERY(proxy, ("/* hostgroup=" + NEW_SRV_HG_STR + ";create_new_connection=1 */ BEGIN").c_str());
	return true;
}

/**
 * @brief Validates that metrics were created after an action.
 * 
 * @return bool True if metrics were absent before and present after.
 */
bool check_metric_creation(
	map<string,double>::const_iterator prev_metric_it_free,
	map<string,double>::const_iterator prev_metric_it_used,
	map<string,double>::const_iterator after_metric_it_free,
	map<string,double>::const_iterator after_metric_it_used,
	const map<string, double>& prev_metrics,
	const map<string, double>& after_metrics
) {
	bool metric_found =
		prev_metric_it_free == prev_metrics.end() &&
		prev_metric_it_used == prev_metrics.end() &&
		after_metric_it_free != after_metrics.end() &&
		after_metric_it_used != after_metrics.end();

	ok(metric_found, "Metric was present ONLY after the action in 'SHOW PROMETHEUS METRICS'");

	return metric_found;
}

/**
 * @brief Validates that metrics existed before and after an action.
 * 
 * @return bool True if metrics were present in both states.
 */
bool check_metric_update(
	map<string,double>::const_iterator prev_metric_it_free,
	map<string,double>::const_iterator prev_metric_it_used,
	map<string,double>::const_iterator after_metric_it_free,
	map<string,double>::const_iterator after_metric_it_used,
	const map<string, double>& prev_metrics,
	const map<string, double>& after_metrics
) {
	bool metric_found =
		prev_metric_it_free != prev_metrics.end() &&
		prev_metric_it_used != prev_metrics.end() &&
		after_metric_it_free != after_metrics.end() &&
		after_metric_it_used != after_metrics.end();

	ok(metric_found, "Metric was present ONLY after the action in 'SHOW PROMETHEUS METRICS'");

	return metric_found;
}

/**
 * @brief Function pointer for dynamic metric presence checking.
 */
bool (*check_metric_presence)(
	map<string,double>::const_iterator prev_metric_it_free,
	map<string,double>::const_iterator prev_metric_it_used,
	map<string,double>::const_iterator after_metric_it_free,
	map<string,double>::const_iterator after_metric_it_used,
	const map<string, double>& prev_metrics,
	const map<string, double>& after_metrics
) = check_metric_creation;

/**
 * @brief Checks if a metric identifier matches a set of label/value expectations.
 * 
 * @param metric_key Iterator to the metric entry.
 * @param tags_chcks Map of label names to validation functions.
 * @return pair<bool,map<string,string>> Success status and the actual tags.
 */
pair<bool,map<string,string>> check_matching_tags(
	map<string,double>::const_iterator metric_key,
	map<string,function<bool(string)>> tags_chcks
) {
	map<string,string> metric_tags = extract_metric_tags(metric_key->first);

	// Find the matching metrics by key and using the check function for values
	for (const auto& [tag, check] : tags_chcks) {
		auto it = metric_tags.find(tag);
		if (it == metric_tags.end() || !check(it->second)) {
			return { false, {} };
		}
	}

	return { true, metric_tags };
}

/**
 * @brief Verifies increment of 'proxysql_connpool_conns' gauge for 'used' connections.
 * 
 * @param prev_metrics Metrics values before the trigger.
 * @param after_metrics Metrics values after the trigger.
 */
void check_conn_used_incr_on_hg(
	const map<string, double>& prev_metrics, const map<string, double>& after_metrics
) {
	map<string,double>::const_iterator after_metric_it_free { after_metrics.end() };
	map<string,double>::const_iterator after_metric_it_used { after_metrics.end() };
	map<string,double>::const_iterator prev_metric_it_free { prev_metrics.end() };
	map<string,double>::const_iterator prev_metric_it_used { prev_metrics.end() };

	map<string,string> metric_tags_used {};
	map<string,string> metric_tags_free {};

	const map<string,function<bool(string)>> tags_chcks {
		{ "endpoint", [&] (const string& s) { return s == MY_HOST_STR + ":" + MY_PORT_STR; } },
		{ "hostgroup", [&] (const string& s) { return s == NEW_SRV_HG_STR; } },
		{ "status", [&] (const string& s) { return s == "free" || s == "used"; } },
	};

	for (auto metric_key = after_metrics.begin(); metric_key != after_metrics.end(); metric_key++) {
		if (metric_key->first.rfind("proxysql_connpool_conns") == 0) {
			pair<bool,map<string,string>> match_res { check_matching_tags(metric_key, tags_chcks) };

			if (match_res.first) {
				if (match_res.second["status"] == "free") {
					metric_tags_free = match_res.second;
					after_metric_it_free = metric_key;
				} else if (match_res.second["status"] == "used") {
					metric_tags_used = match_res.second;
					after_metric_it_used = metric_key;
				}
				if (
					after_metric_it_free != after_metrics.end()
					&& after_metric_it_used != after_metrics.end()
				) {
					break;
				}
			}
		}
	}
	for (auto metric_key = prev_metrics.begin(); metric_key != prev_metrics.end(); metric_key++) {
		if (metric_key->first.rfind("proxysql_connpool_conns") == 0) {
			pair<bool,map<string,string>> match_res { check_matching_tags(metric_key, tags_chcks) };

			if (match_res.first) {
				if (match_res.second["status"] == "free") {
					metric_tags_free = match_res.second;
					prev_metric_it_free = metric_key;
				} else if (match_res.second["status"] == "used") {
					metric_tags_used = match_res.second;
					prev_metric_it_used = metric_key;
				}
				if (
					prev_metric_it_free != prev_metrics.end()
					&& prev_metric_it_used != prev_metrics.end()
				) {
					break;
				}
			}
		}
	}

	// Check the metric presence - origin vs update
	bool metric_found = check_metric_presence(
		prev_metric_it_free,
		prev_metric_it_used,
		after_metric_it_free,
		after_metric_it_used,
		prev_metrics,
		after_metrics
	);

	if (metric_found) {
		// Fallback to zero in case of first time being triggered
		double prev_metric_val = 0;
		if (prev_metric_it_used != prev_metrics.end()) {
			prev_metric_val = prev_metric_it_used->second;
		}

		double after_metric_val = after_metric_it_used->second;
		bool is_updated = fabs(prev_metric_val + 1 - after_metric_val) < 0.1;
		const string tags_used { nlohmann::json(metric_tags_used).dump() };

		ok(
			metric_found && is_updated,
			"Metric has a correct tags and updated value: { old_val: '%lf', new_val: '%lf', tags: '%s' }",
			prev_metric_val, after_metric_val, tags_used.c_str()
		);
	} else {
		ok(false, "Metric has a properly updated value");
	}
}

/**
 * @brief Helper to find a specific metric with matching tags in a metrics map.
 * 
 * @param metrics The metrics map to search.
 * @param key The metric name prefix to search for.
 * @param tags_chcks Map of label validations.
 * @return pair Iterator to the found entry and its parsed tags.
 */
pair<map<string,double>::const_iterator,map<string,string>> get_metric(
	const map<string, double>& metrics,
	const string& key,
	const map<string,function<bool(string)>> tags_chcks
) {
	for (auto metric_key = metrics.begin(); metric_key != metrics.end(); metric_key++) {
		if (metric_key->first.rfind(key) == 0) {
			pair<bool,map<string,string>> match_res { check_matching_tags(metric_key, tags_chcks) };

			if (match_res.first) {
				return { metric_key, match_res.second };
			}
		}
	}

	return { metrics.end(), {} };
}

/**
 * @brief Verifies increment of 'proxysql_connpool_conns_total' counter.
 * 
 * @param prev_metrics Metrics values before the trigger.
 * @param after_metrics Metrics values after the trigger.
 */
void check_conn_total_incr_on_hg(
	const map<string, double>& prev_metrics, const map<string, double>& after_metrics
) {

	const map<string,function<bool(string)>> tags_chcks {
		{ "endpoint", [&] (const string& s) { return s == MY_HOST_STR + ":" + MY_PORT_STR; } },
		{ "hostgroup", [&] (const string& s) { return s == NEW_SRV_HG_STR; } },
		{ "status", [&] (const string& s) { return s == "ok"; } },
	};

	const auto& p_prev_metric_tags { get_metric(prev_metrics, "proxysql_connpool_conns", tags_chcks) };
	const auto& p_after_metric_tags { get_metric(after_metrics, "proxysql_connpool_conns", tags_chcks) };

	// Check the metric presence - origin vs update
	bool metric_found = check_metric_presence(
		p_prev_metric_tags.first,
		p_prev_metric_tags.first,
		p_after_metric_tags.first,
		p_after_metric_tags.first,
		prev_metrics,
		after_metrics
	);

	if (metric_found) {
		// Fallback to zero in case of first time being triggered
		double prev_metric_val = 0;
		if (p_prev_metric_tags.first != prev_metrics.end()) {
			prev_metric_val = p_prev_metric_tags.first->second;
		}

		double after_metric_val = p_after_metric_tags.first->second;
		bool is_updated = fabs(prev_metric_val + 1 - after_metric_val) < 0.1;
		const string tags { nlohmann::json(p_after_metric_tags.second).dump() };

		ok(
			metric_found && is_updated,
			"Metric has a correct tags and updated value: { old_val: '%lf', new_val: '%lf', tags: '%s' }",
			prev_metric_val, after_metric_val, tags.c_str()
		);
	} else {
		ok(false, "Metric has a properly updated value");
	}
}

/**
 * @brief Verifies 'proxysql_message_count_total' with specific code location labels.
 * 
 * These metrics include filename, func, and line labels where the error occurred.
 * 
 * @param prev_metrics Metrics values before the trigger.
 * @param after_metrics Metrics values after the trigger.
 */
void check_message_count_parse_failure(const map<string, double>& prev_metrics, const map<string, double>& after_metrics) {
	map<string,double>::const_iterator after_metric_it { after_metrics.end() };
	map<string,double>::const_iterator prev_metric_it { prev_metrics.end() };

	map<string,string> metric_tags {};

	const auto match_exp_tags = [](map<string,double>::const_iterator metric_key) -> pair<map<string,string>,bool> {
		// Find the right metric using the proper tags for 'proxysql_message_count_total'
		map<string,string> metric_tags = extract_metric_tags(metric_key->first);
		auto message_id_it = metric_tags.find("message_id");
		auto filename_it = metric_tags.find("filename");
		auto line_it = metric_tags.find("line");
		auto func_it = metric_tags.find("func");

		bool all_tags_present =
			message_id_it != metric_tags.end() && filename_it != metric_tags.end() &&
			line_it != metric_tags.end() && func_it != metric_tags.end();
		bool correct_tag_values = false;

		if (all_tags_present == true) {
			correct_tag_values =
				message_id_it->second == string {"10002"} && line_it->second != "0" &&
				filename_it->second == "MySQL_Session.cpp" &&
				func_it->second == "handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo";
		}

		return { metric_tags, correct_tag_values };
	};

	for (auto metric_key = after_metrics.begin(); metric_key != after_metrics.end(); metric_key++) {
		if (metric_key->first.rfind("proxysql_message_count_total") == 0) {
			pair<map<string,string>,bool> match_res { match_exp_tags(metric_key) };

			if (match_res.second) {
				metric_tags = match_res.first;
				after_metric_it = metric_key;
				break;
			}
		}
	}
	for (auto metric_key = prev_metrics.begin(); metric_key != prev_metrics.end(); metric_key++) {
		if (metric_key->first.rfind("proxysql_message_count_total") == 0) {
			pair<map<string,string>,bool> match_res { match_exp_tags(metric_key) };

			if (match_res.second) {
				prev_metric_it = metric_key;
				break;
			}
		}
	}

	// NOTE: Because this metric is dynamic, we can only be sure that is present after the operation.
	bool metric_found = after_metric_it != after_metrics.end();
	ok(metric_found, "Metric was present in output from 'SHOW PROMETHEUS METRICS'");

	if (metric_found) {
		// NOTE: Fallback to zero in case of first time being triggered
		double prev_metric_val = 0;
		if (prev_metric_it != prev_metrics.end()) {
			prev_metric_val = prev_metric_it->second;
		}
		double after_metric_val = after_metric_it->second;
		bool is_updated = fabs(prev_metric_val + 1 - after_metric_val) < 0.1;

		ok(
			metric_found && is_updated,
			"Metric has a proper tag values and updated value: { old_value: '%lf', new_value: '%lf', tags: '%s' }",
			prev_metric_val, after_metric_val, nlohmann::json(metric_tags).dump().c_str()
		);
	} else {
		ok(false, "Metric has a properly updated value.");
	}
}

/**
 * @brief Retrieves multiple target metrics from a metrics map.
 * 
 * @param metrics_map The source metrics map.
 * @param metrics_ids List of full metric identifiers to find.
 * @param[out] tg_metrics Map to store the found metrics.
 * @return int EXIT_SUCCESS if all metrics were found.
 */
int get_target_metrics(
	const map<string,double>& metrics_map, const vector<string>& metrics_ids, map<string,double>& tg_metrics
) {
	map<string,double> metrics_vals {};

	for (const string& metric_id : metrics_ids) {
		const auto& metric_it = metrics_map.find(metric_id);
		if (metric_it == metrics_map.end()) {
			diag("%s: Unable to find target metric '%s'", __func__, metric_id.c_str());
			return EXIT_FAILURE;
		} else {
			metrics_vals.insert({metric_id, metric_it->second});
		}
	}

	tg_metrics = metrics_vals;

	return EXIT_SUCCESS;
}

/**
 * @brief Prepares the writer hostgroup by issuing initial traffic.
 */
bool rm_add_server_connpool_setup(MYSQL* proxy, MYSQL* admin, const CommandLine& cl) {
	// Exercise some load on the writer hostgroup
	const string q_load = "/* hostgroup=" + WRITER_HG_S + " */ SELECT 1";
	for (size_t i = 0; i < 10; i++) {
		int rc = mysql_query_d(proxy, q_load.c_str());
		if (rc != EXIT_SUCCESS) { return EXIT_FAILURE; }
		mysql_free_result(mysql_store_result(proxy));
	}

	// check metric value has been updated
	return EXIT_SUCCESS;
}

/**
 * @brief Triggers connection pool counters by removing and re-adding a server.
 * 
 * @return bool True if operations were successful.
 */
bool rm_add_server_connpool_counters(MYSQL* proxy, MYSQL* admin, const CommandLine& cl) {
	// Delete server and add it again to hostgroup
	const string del_q = "DELETE FROM mysql_servers WHERE hostgroup_id=" + WRITER_HG_S;
	diag("Removing current 'mysql_servers' for target hostgroup '%s'", WRITER_HG_S.c_str());
	mysql_query_d(admin, del_q.c_str());
	mysql_query_d(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	diag("Recover original servers for target hostgroup '%s'", WRITER_HG_S.c_str());
	mysql_query_d(admin, "LOAD MYSQL SERVERS FROM DISK");
	mysql_query_d(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Exercise some load on the writer hostgroup
	const string query = "/* hostgroup=" + WRITER_HG_S + ",create_new_connection=1 */ SELECT 1";
	int rc = mysql_query_d(proxy, query.c_str());
	if (rc != EXIT_SUCCESS) {
		diag("Failed to execute query '%s' with error '%s'", query.c_str(), mysql_error(proxy));
		return false;
	}
	mysql_free_result(mysql_store_result(proxy));

	return true;
}

/**
 * @brief Verifies data transmission and connection counters for a specific server.
 * 
 * Checks 'proxysql_connpool_data_bytes_total', 'proxysql_connpool_conns_total', 
 * and 'proxysql_connpool_conns_queries_total'.
 * 
 * @param prev_metrics Metrics before the server flap.
 * @param after_metrics Metrics after the server flap.
 */
void check_server_data_recv(const map<string,double>& prev_metrics, const map<string,double>& after_metrics) {
	// Endpoint we are going to target
	const string endpoint_hg { "endpoint=\"" + std::string(cl.mysql_host) + ":" + std::to_string(cl.mysql_port) + "\",hostgroup=\"" + WRITER_HG_S + "\",protocol=\"mysql\"" };

	// Metrics identifiers
	const vector<string> metrics_ids {
		{ "proxysql_connpool_data_bytes_total{" + endpoint_hg + ",traffic_flow=\"sent\"}" },
		{ "proxysql_connpool_data_bytes_total{" + endpoint_hg + ",traffic_flow=\"recv\"}" },
		{ "proxysql_connpool_conns_total{" + endpoint_hg + ",status=\"ok\"}" },
		{ "proxysql_connpool_conns_queries_total{" + endpoint_hg + "}" }
	};


	// Get metrics prior to issue some traffic
	diag("Obtaining metrics prior to issuing traffic to server");
	bool found_prev_metrics = false;
	map<string,double> prev_tg_metrics {};
	int prev_metrics_rc = get_target_metrics(prev_metrics, metrics_ids, prev_tg_metrics);
	if (prev_metrics_rc == EXIT_SUCCESS) {
		found_prev_metrics = true;
	} else {
		diag("Failed to find metrics prior to sending traffic to server");
	}

	diag("Obtaining metrics after to issuing traffic to server");
	bool found_after_metrics = false;
	map<string,double> after_tg_metrics {};
	int after_metrics_rc = get_target_metrics(after_metrics, metrics_ids, after_tg_metrics);
	if (after_metrics_rc == EXIT_SUCCESS) {
		found_after_metrics = true;
	} else {
		diag("Failed to find metrics after sending traffic to server");
	}

	ok(found_prev_metrics && found_after_metrics, "Metric was present in output from 'SHOW PROMETHEUS METRICS'");

	// Check that all metrics increased from the previous values as expected
	diag("Checking values have increased after the issued traffic");
	vector<string> failed_metrics {};

	for (const string& m_id : metrics_ids) {
		const double pre_val = prev_tg_metrics[m_id];
		const double post_val = after_tg_metrics[m_id];

		if (pre_val >= post_val) {
			failed_metrics.push_back(m_id);
			diag("Error: Metric '%s' failed to be incremented [%lf, %lf]", m_id.c_str(), pre_val, post_val);
		}
	}

	ok(failed_metrics.empty(), "All metric values were properly incremented after server rm/add from hostgroup");
}

/**
 * @brief Test function signatures.
 */
using setup = function<bool(MYSQL*, MYSQL*, const CommandLine&)>;
using metric_trigger = function<bool(MYSQL*, MYSQL*, const CommandLine&)>;
using metric_check = function<void(const map<string, double>&, const map<string, double>&)>;

/**
 * @brief Indexing for metric_tests tuples.
 */
struct CHECK {
	enum funcs { SETUP, TRIGGER, CHECKER, _END };
};

/**
 * @brief Default setup function that does nothing.
 */
bool placeholder_setup(MYSQL*, MYSQL*, const CommandLine&) { return true; }

/**
 * @brief Configures the checker to expect metric creation.
 */
bool setup_metric_creation_check(MYSQL*, MYSQL*, const CommandLine&) {
	check_metric_presence = check_metric_creation;
	return true;
}

/**
 * @brief Configures the checker to expect metric update.
 */
bool setup_metric_update_check(MYSQL*, MYSQL*, const CommandLine&) {
	check_metric_presence = check_metric_update;
	return true;
}

/**
 * @brief Registry of all metrics tests.
 * 
 * Each entry consists of:
 * - Test Name
 * - Tuple containing {Setup Function, Trigger Function, Check Function}
 */
const vector<pair<string, tuple<setup, metric_trigger, metric_check>>> metric_tests {
	{
		"proxysql_myhgm_auto_increment_multiplex_total",
		{ placeholder_setup, trigger_auto_increment_delay_multiplex_metric, check_auto_increment_delay_multiplex_metric }
	},
	{
		"proxysql_access_denied_wrong_password_total",
		{ placeholder_setup, trigger_access_denied_wrong_password_total, check_access_denied_wrong_password_total }
	},
	{
		"proxysql_com_rollback_total",
		{ placeholder_setup, trigger_transaction_rollback_total, check_transaction_rollback_total } },
	{
		"proxysql_version_info",
		{ placeholder_setup, get_proxysql_version_info, check_proxysql_version_info }
	},
	{
		"rm_add_server_connpool_counters",
		{ placeholder_setup, rm_add_server_connpool_counters, { check_server_data_recv } },
	},
	// Checks metric creation and initial value
	{
		"proxysql_message_count_parse_failure_init",
		{ placeholder_setup, trigger_message_count_parse_failure, check_message_count_parse_failure } },
	// Checks metric increment
	{
		"proxysql_message_count_parse_failure_inc",
		{ placeholder_setup, trigger_message_count_parse_failure, check_message_count_parse_failure }
	},
	// Create a connection to a NEW backend server - proxysql_connpool_conns gauge
	{
		"proxysql_connpool_conns{endpoint/hostgroup/status} - Creation",
		{ setup_metric_creation_check, trigger_conn_in_new_backend_hg, check_conn_used_incr_on_hg }
	},
	// Create a connection to the SAME (previous) backend server - proxysql_connpool_conns gauge
	{
		"proxysql_connpool_conns{endpoint/hostgroup/status} - Update",
		{ setup_metric_update_check, trigger_conn_in_prev_backend_hg, check_conn_used_incr_on_hg }
	},
	// Create a connection to a NEW backend server - proxysql_connpool_conns_total counter
	{
		"proxysql_connpool_conns_total{endpoint/hostgroup/status} - Creation",
		{ setup_metric_creation_check, trigger_conn_in_new_backend_hg, check_conn_total_incr_on_hg }
	},
	// Create a connection to a NEW backend server - proxysql_connpool_conns_total counter
	{
		"proxysql_connpool_conns_total{endpoint/hostgroup/status} - Update",
		{ setup_metric_update_check, trigger_conn_in_prev_backend_hg, check_conn_total_incr_on_hg }
	},
};

/**
 * @brief Main entry point for the TAP test suite.
 */
int main(int argc, char** argv) {

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(metric_tests.size() * 4);

	for (const auto& metric_test : metric_tests) {
		// Initialize Admin connection
		MYSQL* proxysql_admin = mysql_init(NULL);
		if (!proxysql_admin) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return EXIT_FAILURE;
		}
		// Connnect to ProxySQL Admin
		if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return EXIT_FAILURE;
		}
		// Initialize ProxySQL connection
		MYSQL* proxysql = mysql_init(NULL);
		if (!proxysql) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			return EXIT_FAILURE;
		}
		// Connect to ProxySQL
		if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		    fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			return EXIT_FAILURE;
		}

		// Log test start for metric
		diag("Started test for metric '%s'", metric_test.first.c_str());

		// Execute the action triggering the metric update
		const auto& metric_setup = std::get<CHECK::SETUP>(metric_test.second);
		bool action_res = metric_setup(proxysql, proxysql_admin, cl);
		ok(action_res, "Setup action to prepare the env was successful.");

		// Get the current metrics values
		std::map<string, double> prev_metrics {};
		int rc = get_cur_metrics(proxysql_admin, prev_metrics);
		if (rc != EXIT_SUCCESS) { return EXIT_FAILURE; }

		// Execute the action triggering the metric update
		const auto& metric_trigger = std::get<CHECK::TRIGGER>(metric_test.second);
		bool trigger_res = metric_trigger(proxysql, proxysql_admin, cl);
		ok(trigger_res, "Action to update the metric was executed properly.");

		// Get the new updated metrics values
		std::map<string, double> after_metrics {};
		rc = get_cur_metrics(proxysql_admin, after_metrics);
		if (rc != EXIT_SUCCESS) { return EXIT_FAILURE; }

		// Check that the new metrics values matches the expected
		const auto& metric_checker = std::get<CHECK::CHECKER>(metric_test.second);
		metric_checker(prev_metrics, after_metrics);

		// Close the connections used for this test
		mysql_close(proxysql);
		mysql_close(proxysql_admin);
	}

	return exit_status();
}
