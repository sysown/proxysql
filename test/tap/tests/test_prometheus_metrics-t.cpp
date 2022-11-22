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

#include "json.hpp"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::function;
using std::map;
using std::vector;
using std::pair;
using std::string;

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

#include <iostream>

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
 * @brief Map of test identifier and pair functions holding the metrics tests:
 *   - First function of the pair uses an open connection to ProxySQL and to ProxySQL Admin to perform
 *   the actions that should trigger the metric increment.
 *   - Second function performs the check to verify that the metric have been incremented properly.
 *     This function should execute **one** 'ok(...)' inside when the values have been properly checked.
 */
const vector<pair<
	string,
	pair<
		function<bool(MYSQL*, MYSQL*, const CommandLine&)>,
		function<void(const map<string, double>&, const map<string, double>&)>
	>
>> metric_tests {
	{ "proxysql_myhgm_auto_increment_multiplex_total", { trigger_auto_increment_delay_multiplex_metric, check_auto_increment_delay_multiplex_metric } },
	{ "proxysql_access_denied_wrong_password_total", { trigger_access_denied_wrong_password_total, check_access_denied_wrong_password_total } },
	{ "proxysql_com_rollback_total", { trigger_transaction_rollback_total, check_transaction_rollback_total } },
	{ "proxysql_version_info", { get_proxysql_version_info, check_proxysql_version_info } },
	// Checks metric creation and initial value
	{ "proxysql_message_count_parse_failure_init", { trigger_message_count_parse_failure, check_message_count_parse_failure } },
	// Checks metric increment
	{ "proxysql_message_count_parse_failure_inc", { trigger_message_count_parse_failure, check_message_count_parse_failure } },
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
		const std::map<string, double> prev_metrics { get_prometheus_metric_values(row_value) };

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
		const std::map<string, double> after_metrics { get_prometheus_metric_values(row_value) };

		// Check that the new metrics values matches the expected
		metric_checker.second.second(prev_metrics, after_metrics);

		// Close the connections used for this test
		mysql_close(proxysql);
		mysql_close(proxysql_admin);
	}

	return exit_status();
}
