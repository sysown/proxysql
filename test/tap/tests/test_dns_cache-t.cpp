/**
 * @file test_dns_cache-t.cpp
 * @brief This test will verify dns cache is working properly.
 */

#include <stdio.h>
#include <unistd.h>

#include <string>
#include <algorithm>
#include <functional>
#include <map>
#include <vector>
#include <chrono>
#include <thread>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

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
std::map<std::string, double> get_metric_values(const std::string& metrics_output) {
	std::vector<std::string> output_lines { split(metrics_output, '\n') };
	std::map<std::string, double> metrics_map {};

	for (const std::string line : output_lines) {
		const std::vector<std::string> line_values { split(line, ' ') };

		if (line.empty() == false && line[0] != '#') {
			if (line_values.size() > 2) {
				size_t delim_pos_st = line.rfind("} ");
				std::string metric_key = line.substr(0, delim_pos_st);
				std::string metric_val = line.substr(delim_pos_st + 2);

				metrics_map.insert({metric_key, std::stod(metric_val)});
			} else {
				metrics_map.insert({line_values.front(), std::stod(line_values.back())});
			}
		}
	}

	return metrics_map;
}

bool get_prometheus_metrics(MYSQL* proxysql_admin, std::map<std::string, double>& matric_val) {
	matric_val.clear();

	if (mysql_query(proxysql_admin, "SHOW PROMETHEUS METRICS\\G")) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin)); 
		return false;
	} 

	MYSQL_RES* p_resulset = mysql_store_result(proxysql_admin);
	MYSQL_ROW data_row = mysql_fetch_row(p_resulset);
	std::string row_value{};
	if (data_row[0]) {
		row_value = data_row[0];
	}
	else {
		row_value = "NULL";
	}
	mysql_free_result(p_resulset);

	matric_val = get_metric_values(row_value);

	return true;
}



#define STEP_START {
#define STEP_END }

#define DECLARE_PREV_AFTER_METRICS() std::map<std::string, double> prev_metrics, after_metrics
#define EXECUTE_QUERY(QUERY,MYSQL_CONNECTION,IGNORE_RESULT)	[&MYSQL_CONNECTION]() -> bool { if (mysql_query(std::ref(MYSQL_CONNECTION), QUERY) && !IGNORE_RESULT) { \
																					fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(std::ref(MYSQL_CONNECTION))); \
																					return false; } return true; } 
#define DELAY_SEC(SECONDS)	[]() -> bool { std::this_thread::sleep_for(std::chrono::seconds(SECONDS)); return true; }
#define UPDATE_PREV_METRICS(PROXYSQL_ADMIN) std::bind(get_prometheus_metrics, std::ref(PROXYSQL_ADMIN), std::ref(prev_metrics))
#define UPDATE_AFTER_METRICS(PROXYSQL_ADMIN) std::bind(get_prometheus_metrics, std::ref(PROXYSQL_ADMIN), std::ref(after_metrics))
#define CHECK_RESULT(a,b)	std::bind(check_result<a>, b, std::ref(prev_metrics), std::ref(after_metrics))
#define LOOP_FUNC(FUNC,TIMES)	[&]() -> bool { for(int i=0; i < TIMES; i++) { \
											if (FUNC() == false) return false; } \
											return true;}

template<typename COMPARE>
bool check_result(const std::string& key, const std::map<std::string, double>& prev_metrics, std::map<std::string, double>& after_metrics) {
	auto prev_metric_key = prev_metrics.find(key);
	auto after_metric_key = after_metrics.find(key);

	bool metric_found = prev_metric_key != prev_metrics.end() && after_metric_key != after_metrics.end();

	ok(metric_found, "'%s' metric was present in output from 'SHOW PROMETHEUS METRICS'", key.c_str());

	if (metric_found) {
		const double prev_metric_val = prev_metric_key->second;
		const double after_metric_val = after_metric_key->second;

		diag("Started test for metric '%s'", key.c_str());

		COMPARE fn;
		bool res = fn(after_metric_val, prev_metric_val);

		ok(res, "'%s' metric result success.",key.c_str());
	}

	return true;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

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

	MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_servers WHERE hostgroup_id=999"); // just in case
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	MYSQL_QUERY(proxysql_admin, "UPDATE mysql_users SET default_hostgroup=999");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL USERS TO RUNTIME");

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

	DECLARE_PREV_AFTER_METRICS();

	std::vector<std::vector<std::function<bool()>>> dns_cache_check_steps = {
	STEP_START
			EXECUTE_QUERY("SET mysql-monitor_enabled='false'", proxysql_admin, false),
			EXECUTE_QUERY("SET mysql-monitor_local_dns_cache_refresh_interval=1000", proxysql_admin, false),
			EXECUTE_QUERY("SET mysql-monitor_local_dns_cache_ttl=5000", proxysql_admin, false),
			EXECUTE_QUERY("LOAD MYSQL VARIABLES TO RUNTIME", proxysql_admin, false),
			DELAY_SEC(2)
	STEP_END,
	STEP_START
			UPDATE_PREV_METRICS(proxysql_admin),
			EXECUTE_QUERY("INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (999,'0.0.0.0',7861,0,1000,'dummy mysql server')", proxysql_admin, false),
			EXECUTE_QUERY("LOAD MYSQL SERVERS TO RUNTIME", proxysql_admin, false),
			DELAY_SEC(2),
			UPDATE_AFTER_METRICS(proxysql_admin),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_record_updated"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_lookup_success"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_queried")
	STEP_END,
	STEP_START
			UPDATE_PREV_METRICS(proxysql_admin),
			LOOP_FUNC(EXECUTE_QUERY("DO 1", proxysql, true), 2),
			DELAY_SEC(2),
			UPDATE_AFTER_METRICS(proxysql_admin),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_record_updated"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_lookup_success"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_queried")
	STEP_END,
	STEP_START
			UPDATE_PREV_METRICS(proxysql_admin),
			LOOP_FUNC(EXECUTE_QUERY("DO 1", proxysql, true), 2),
			DELAY_SEC(2),
			UPDATE_AFTER_METRICS(proxysql_admin),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_record_updated"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_lookup_success"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_queried")
	STEP_END,
	STEP_START
			UPDATE_PREV_METRICS(proxysql_admin),
			EXECUTE_QUERY("INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (999,'google.com',7861,0,1000,'dummy mysql server')", proxysql_admin, false),
			EXECUTE_QUERY("LOAD MYSQL SERVERS TO RUNTIME", proxysql_admin, false),
			DELAY_SEC(2),
			LOOP_FUNC(EXECUTE_QUERY("DO 1", proxysql, true), 2),
			DELAY_SEC(2),
			UPDATE_AFTER_METRICS(proxysql_admin),
			CHECK_RESULT(std::greater<double>, "proxysql_mysql_monitor_dns_cache_record_updated"),
			CHECK_RESULT(std::greater<double>, "proxysql_mysql_monitor_dns_cache_lookup_success"),
			CHECK_RESULT(std::greater<double>, "proxysql_mysql_monitor_dns_cache_queried")
	STEP_END,
	STEP_START
			UPDATE_PREV_METRICS(proxysql_admin),
			EXECUTE_QUERY("INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (999,' yahoo.com ',7861,0,1000,'dummy mysql server')", proxysql_admin, false),
			EXECUTE_QUERY("LOAD MYSQL SERVERS TO RUNTIME", proxysql_admin, false),
			DELAY_SEC(2),
			LOOP_FUNC(EXECUTE_QUERY("DO 1", proxysql, true), 2),
			DELAY_SEC(2),
			UPDATE_AFTER_METRICS(proxysql_admin),
			CHECK_RESULT(std::greater<double>, "proxysql_mysql_monitor_dns_cache_record_updated"),
			CHECK_RESULT(std::greater<double>, "proxysql_mysql_monitor_dns_cache_lookup_success"),
			CHECK_RESULT(std::greater<double>, "proxysql_mysql_monitor_dns_cache_queried")
	STEP_END,
	STEP_START
			UPDATE_PREV_METRICS(proxysql_admin),
			EXECUTE_QUERY("DELETE FROM mysql_servers WHERE hostgroup_id=999", proxysql_admin, false),
			EXECUTE_QUERY("LOAD MYSQL SERVERS TO RUNTIME", proxysql_admin, false),
			DELAY_SEC(2),
			UPDATE_AFTER_METRICS(proxysql_admin),
			CHECK_RESULT(std::greater<double>, "proxysql_mysql_monitor_dns_cache_record_updated"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_lookup_success"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_queried")
	STEP_END,
	STEP_START
			UPDATE_PREV_METRICS(proxysql_admin),
			EXECUTE_QUERY("INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (999,'INVALID_DOMAIN',7861,0,1000,'dummy mysql server')", proxysql_admin, false),
			EXECUTE_QUERY("LOAD MYSQL SERVERS TO RUNTIME", proxysql_admin, false),
			DELAY_SEC(2),
			LOOP_FUNC(EXECUTE_QUERY("DO 1", proxysql, true), 2),
			DELAY_SEC(2),
			UPDATE_AFTER_METRICS(proxysql_admin),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_record_updated"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_lookup_success"),
			CHECK_RESULT(std::greater<double>, "proxysql_mysql_monitor_dns_cache_queried")
	STEP_END,
	STEP_START
			//disable dns cache
			EXECUTE_QUERY("SET mysql-monitor_local_dns_cache_refresh_interval=0", proxysql_admin, false),
			EXECUTE_QUERY("LOAD MYSQL VARIABLES TO RUNTIME", proxysql_admin, false),
			DELAY_SEC(2),
			UPDATE_PREV_METRICS(proxysql_admin),
			LOOP_FUNC(EXECUTE_QUERY("DO 1", proxysql, true), 2),
			DELAY_SEC(2),
			UPDATE_AFTER_METRICS(proxysql_admin),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_record_updated"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_lookup_success"),
			CHECK_RESULT(std::equal_to<double>, "proxysql_mysql_monitor_dns_cache_queried")
	STEP_END
	};

	plan((dns_cache_check_steps.size() -1) * 3 * 2);

	for (size_t i = 0; i < dns_cache_check_steps.size(); i++) {
		diag("Starting Step:'%ld'", i);
		for (const auto fn : dns_cache_check_steps[i])
			if (fn() == false)
				goto __cleanup;
		diag("Ending Step:'%ld'\n", i);
	}

__cleanup:
	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
