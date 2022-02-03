/**
 * @file test_prometheus_metrics-t.cpp
 * @brief This test should be used to verify that added prometheus metrics are working properly.
 * @date 2021-03-01
 */

#include <algorithm>
#include <cmath>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <sstream>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::function;
using std::map;
using std::vector;
using std::pair;
using std::string;

std::vector<std::string> split(const std::string& s, char delimiter) {
	std::vector<std::string> tokens {};
	std::string token {};
	std::istringstream tokenStream(s);

	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(token);
	}

	return tokens;
}

/**
 * @brief Extract the metrics values from the output of the admin command
 *   'SHOW PROMETHEUS METRICS'.
 * @param metrics_output The output of the command 'SHOW PROMETHEUS METRICS'.
 * @return A map holding the metrics identifier and its current value.
 */
std::map<std::string, double> get_metric_values(std::string metrics_output) {
	std::vector<std::string> output_lines { split(metrics_output, '\n') };
	std::map<std::string, double> metrics_map {};

	for (const std::string line : output_lines) {
		const std::vector<std::string> line_values { split(line, ' ') };

		if (line.empty() == false && line[0] != '#') {
			if (line_values.size() > 2) {
				size_t delim_pos_st = line.rfind("} ");
				string metric_key = line.substr(0, delim_pos_st);
				string metric_val = line.substr(delim_pos_st + 2);

				metrics_map.insert({metric_key, std::stod(metric_val)});
			} else {
				metrics_map.insert({line_values.front(), std::stod(line_values.back())});
			}
		}
	}

	return metrics_map;
}

/**
 * @brief Triggers the increment of 'auto_increment_delay_multiplex_metric'.
 * @param proxy Oppened MYSQL handler to ProxySQL.
 * @param proxy MYSQL Oppened MYSQL handler to ProxySQL Admin.
 * @return True if the action was able to be performed correctly, false otherwise.
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
 * @brief Checks if the increment of 'auto_increment_delay_multiplex_metric' has been
 *   performed correctly.
 * @param prev_metrics Metrics values previous to executing the triggering action.
 * @param after_metrics Metrics values after executing the triggering action.
 */
void check_auto_increment_delay_multiplex_metric(
	const std::map<std::string, double>& prev_metrics,
	const std::map<std::string, double>& after_metrics
) {
	auto prev_metric_key = prev_metrics.find("proxysql_myhgm_auto_increment_multiplex_total");
	auto after_metric_key = after_metrics.find("proxysql_myhgm_auto_increment_multiplex_total");

	bool metric_found =
		prev_metric_key != prev_metrics.end() &&
		after_metric_key != after_metrics.end();

	ok(metric_found, "Metric was present in output from 'SHOW PROMETHEUS METRICS'");
	if (metric_found) {
		double prev_metric_val = prev_metric_key->second;
		double after_metric_val = after_metric_key->second;

		bool is_updated =
			fabs(prev_metric_val + 1 - after_metric_val) < 0.1;
		ok(is_updated, "Metric has a properly updated value.");
	} else {
		ok(false, "Metric has a properly updated value.");
	}
}

bool trigger_access_denied_wrong_password_total(MYSQL*, MYSQL*, const CommandLine& cl) {
	// Initialize ProxySQL connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	// Connect to ProxySQL
	bool access_denied_error = false;
	void* connect_res = mysql_real_connect(proxysql, cl.host, "invalid_username", "invalid_password", NULL, cl.port, NULL, 0);
	int access_errno = mysql_errno(proxysql);

	if (!connect_res && access_errno == ER_ACCESS_DENIED_ERROR) {
		access_denied_error = true;
	} else {
		diag("Connections should have failed due to access denied. ErrCode: %d", access_errno);
		access_denied_error = false;
	}

	return access_denied_error;
}

void check_access_denied_wrong_password_total(
	const std::map<std::string, double>& prev_metrics,
	const std::map<std::string, double>& after_metrics
) {
	auto prev_metric_key = prev_metrics.find("proxysql_access_denied_wrong_password_total");
	auto after_metric_key = after_metrics.find("proxysql_access_denied_wrong_password_total");

	bool metric_found =
		prev_metric_key != prev_metrics.end() &&
		after_metric_key != after_metrics.end();

	ok(metric_found, "Metric was present in output from 'SHOW PROMETHEUS METRICS'");
	if (metric_found) {
		double prev_metric_val = prev_metric_key->second;
		double after_metric_val = after_metric_key->second;

		bool is_updated =
			fabs(prev_metric_val + 1 - after_metric_val) < 0.1;
		ok(is_updated, "Metric has a properly updated value.");
	} else {
		ok(false, "Metric has a properly updated value.");
	}
}

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

void check_transaction_rollback_total(
	const std::map<std::string, double>& prev_metrics,
	const std::map<std::string, double>& after_metrics
){
	auto prev_metric_key = prev_metrics.find("proxysql_com_rollback_total");
	auto after_metric_key = after_metrics.find("proxysql_com_rollback_total");

	bool metric_found =
		prev_metric_key != prev_metrics.end() &&
		after_metric_key != after_metrics.end();

	ok(metric_found, "Metric was present in output from 'SHOW PROMETHEUS METRICS'");
	if (metric_found) {
		double prev_metric_val = prev_metric_key->second;
		double after_metric_val = after_metric_key->second;

		bool is_updated =
			fabs(prev_metric_val + 1 - after_metric_val) < 0.1;
		ok(is_updated, "Metric has a properly updated value.");
	} else {
		ok(false, "Metric has a properly updated value.");
	}
}

string PROXYSQL_VERSION {};

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

	if (res_rows.size() != 1 && res_rows[0].size() != 1) {
		diag("Invalid resulset received for 'SELECT @@version' at Line: %d", __LINE__);
		return false;
	} else {
		PROXYSQL_VERSION = res_rows[0][0];
		return true;
	}
}

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
 * @brief Map of test identifier and pair functions holding the metrics tests:
 *   - First function of the pair uses an open connection to ProxySQL and to ProxySQL Admin to perform
 *   the actions that should trigger the metric increment.
 *   - Second function performs the check to verify that the metric have been incremented properly.
 *     This function should execute **one** 'ok(...)' inside when the values have been properly checked.
 */
const map<
	string,
	pair<
		function<bool(MYSQL*, MYSQL*, const CommandLine&)>,
		function<void(const map<string, double>&, const map<string, double>&)>
	>
> metric_tests {
	{ "proxysql_myhgm_auto_increment_multiplex_total", { trigger_auto_increment_delay_multiplex_metric, check_auto_increment_delay_multiplex_metric } },
	{ "proxysql_access_denied_wrong_password_total", { trigger_access_denied_wrong_password_total, check_access_denied_wrong_password_total } },
	{ "proxysql_com_rollback_total", { trigger_transaction_rollback_total, check_transaction_rollback_total } },
	{ "proxysql_version_info", { get_proxysql_version_info, check_proxysql_version_info } }
};

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(metric_tests.size() * 3);

	for (const auto& metric_checker : metric_tests) {
		// Initialize Admin connection
		MYSQL* proxysql_admin = mysql_init(NULL);
		if (!proxysql_admin) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		}
		// Connnect to ProxySQL Admin
		if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		}

		// Initialize ProxySQL connection
		MYSQL* proxysql = mysql_init(NULL);
		if (!proxysql) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			return -1;
		}
		// Connect to ProxySQL
		if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		    fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			return exit_status();
		}

		// Log test start for metric
		diag("Started test for metric '%s'", metric_checker.first.c_str());

		// Get the current metrics values
		MYSQL_QUERY(proxysql_admin, "SHOW PROMETHEUS METRICS\\G");
		MYSQL_RES* p_resulset = mysql_store_result(proxysql_admin);
		MYSQL_ROW data_row = mysql_fetch_row(p_resulset);
		std::string row_value {};
		if (data_row[0]) {
			row_value = data_row[0];
		} else {
			row_value = "NULL";
		}
		mysql_free_result(p_resulset);
		const std::map<string, double> prev_metrics { get_metric_values(row_value) };

		// Execute the action triggering the metric update
		bool action_res = metric_checker.second.first(proxysql, proxysql_admin, cl);
		ok(action_res, "Action to update the metric was executed properly.");

		// Get the new updated metrics values
		MYSQL_QUERY(proxysql_admin, "SHOW PROMETHEUS METRICS\\G");
		p_resulset = mysql_store_result(proxysql_admin);
		data_row = mysql_fetch_row(p_resulset);
		if (data_row[0]) {
			row_value = data_row[0];
		} else {
			row_value = "NULL";
		}
		mysql_free_result(p_resulset);
		const std::map<string, double> after_metrics { get_metric_values(row_value) };

		// Check that the new metrics values matches the expected
		metric_checker.second.second(prev_metrics, after_metrics);

		// Close the connections used for this test
		mysql_close(proxysql);
		mysql_close(proxysql_admin);
	}

	return exit_status();
}
