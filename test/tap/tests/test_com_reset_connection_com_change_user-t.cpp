/**
 * @file test_com_reset_connection_com_change_user-t.cpp
 * @brief This test checks session cleanup for 'COM_RESET_CONNECTION' and 'COM_CHANGE_USER'.
 * @details The test is going to verify that both 'COM_RESET_CONNECTION' and 'COM_CHANGE_USER':
 *   - Rollbacks active transactions.
 *   - Closes active prepared statements
 *   - Clears user variables.
 *   - Variables tracked by ProxySQL are reset.
 *   - Sessions others than 'PROXYSQL_SESSION_MYSQL' and 'PROXYSQL_SESSION_SQLITE' report '1047'
 *     error when 'COM_RESET_CONNECTION' is received.
 *   - Relevant session variables are recovered.
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <tuple>
#include <iostream>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "command_line.h"
#include "proxysql_utils.h"
#include "json.hpp"
#include "tap.h"
#include "utils.h"

using nlohmann::json;
using var_val = std::pair<std::string, std::string>;

const std::vector<std::string> tracked_variables {
	"sql_log_bin", "sql_mode", "time_zone", "sql_auto_is_null",  "sql_safe_updates", "session_track_gtids",
	//"max_join_size", "net_write_timeout", "sql_select_limit",  "sql_select_limit", "character_set_results",
	"max_join_size", "sql_select_limit",  "sql_select_limit", "character_set_results",
	"transaction_isolation", "transaction_read_only", "sql_auto_is_null", "collation_connection",
	"character_set_connection", "character_set_client", /*"character_set_database",*/ "group_concat_max_len",
	"wsrep_sync_wait"
};

void variable_rows_to_json(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j[row[0]] = row[1];
	}
}

int get_tracked_mysql_vars(MYSQL* proxysql, std::vector<var_val>& vars) {
	int err = 0;
	std::string query {
		"SELECT /*+ ;hostgroup=0 */ LOWER(variable_name), variable_value FROM performance_schema.session_variables WHERE variable_name IN ("
	};

	for (const auto& varname : tracked_variables) {
		query += "'" + varname + "'";

		if (&varname != &tracked_variables.back()) {
			query += ",";
		}
	}

	query += ")";
	err = mysql_query(proxysql, query.c_str());
	if (err != EXIT_SUCCESS) {
		return mysql_errno(proxysql);
	}

	MYSQL_RES* result = mysql_store_result(proxysql);
	// Extract all rows into variables
	{
		MYSQL_ROW row = NULL;

		while ((row = mysql_fetch_row(result))) {
			var_val var_value {
				row[0] == NULL ? "NULL" : row[0],
				row[1] == NULL ? "NULL" : row[1]
			};
			vars.push_back(var_value);
		}
	}
	mysql_free_result(result);

	return EXIT_SUCCESS;
}

using track_variable_spec = std::tuple<std::string, std::string, std::string, std::string>;

std::vector<track_variable_spec> tracked_vars {
//  TODO: This variable shouldn't be tracked or updated in our side, because of this, we don't care of it's value.
//  { "SQL_CHARACTER_SET_DATABASE",   "character_set_database",   "CHARACTER_SET_DATABASE",              "'latin2'" },

	{ "SQL_SAFE_UPDATES",             "sql_safe_updates",         "SQL_SAFE_UPDATES",                    "'ON'" },
	{ "SQL_SELECT_LIMIT",             "sql_select_limit",         "SQL_SELECT_LIMIT",                    "2020" },
	{ "SQL_SQL_MODE",                 "sql_mode",                 "SQL_MODE",                            "'PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'" },
	{ "SQL_TIME_ZONE",                "time_zone",                "TIME_ZONE",                           "'-03:00'"},
	{ "SQL_CHARACTER_SET_RESULTS",    "character_set_results",    "CHARACTER_SET_RESULTS",               "binary" },
	{ "SQL_CHARACTER_SET_CONNECTION", "character_set_connection", "CHARACTER_SET_CONNECTION",            "'latin1'" },
	{ "SQL_CHARACTER_SET_CLIENT",     "character_set_client",     "CHARACTER_SET_CLIENT",                "'latin7'" },
	{ "SQL_ISOLATION_LEVEL",          "transaction_isolation",    "SESSION TRANSACTION ISOLATION LEVEL", "READ COMMITTED"},
	{ "SQL_TRANSACTION_READ",         "transaction_read_only",    "SESSION TRANSACTION READ",            "ONLY"},
	{ "SQL_SQL_AUTO_IS_NULL",         "sql_auto_is_null",         "SQL_AUTO_IS_NULL",                    "'ON'"},
	{ "SQL_COLLATION_CONNECTION",     "collation_connection",     "COLLATION_CONNECTION",                "'latin5_turkish_ci'" },
//	{ "SQL_NET_WRITE_TIMEOUT",        "net_write_timeout",        "NET_WRITE_TIMEOUT",                   "60" },
	{ "SQL_MAX_JOIN_SIZE",            "max_join_size",            "MAX_JOIN_SIZE",                       "10000" },
	{ "SQL_LOG_BIN",                  "sql_log_bin",              "SQL_LOG_BIN",                         "0" },
	{ "SQL_GROUP_CONCAT_MAX_LEN",     "group_concat_max_len",     "GROUP_CONCAT_MAX_LEN",                "4096" },
	{ "SET_SESSION_TRACK_GTIDS",      "session_track_gtids",      "SESSION_TRACK_GTIDS",                 "OWN_GTID" },
};

std::vector<std::string> special_syntax_ids {
	"SQL_CHARACTER_SET", "SQL_SET_NAMES", "SQL_ISOLATION_LEVEL", "SQL_TRANSACTION_READ"
};

int set_tracked_variables(MYSQL* proxysql) {
	for (const auto tracked_var_spec : tracked_vars) {
		std::string set_command { "SET " };

		const std::string var_id = std::get<0>(tracked_var_spec);
		const std::string var_command = std::get<2>(tracked_var_spec);
		const std::string var_val = std::get<3>(tracked_var_spec);

		if (std::find(special_syntax_ids.begin(), special_syntax_ids.end(), var_id) == special_syntax_ids.end()) {
			set_command += var_command + "=" + var_val;
		} else {
			set_command += var_command + " " + var_val;
		}

		MYSQL_QUERY(proxysql, set_command.c_str());
	}

	return EXIT_SUCCESS;
}

void parse_internal_session_result(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row = NULL;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

/**
 * TODO: Almost identical to 'set_testing-t.cpp', needs a refactor.
 */
int query_internal_session(MYSQL *mysql, nlohmann::json& j) {
	char *query = (char*)"PROXYSQL INTERNAL SESSION";
	MYSQL_QUERY(mysql, query);

	MYSQL_RES *result = mysql_store_result(mysql);
	parse_internal_session_result(result, j);
	mysql_free_result(result);

	// value types in mysql and in proxysql are different
	// we should convert proxysql values to mysql format to compare
	for (auto& el : j.items()) {
		if (el.key() == "conn") {
			std::string sql_log_bin_value;

//			diag("DUMP 1:\n%s: ", j["conn"].dump(1).c_str());
			// sql_log_bin {0|1}
			if (el.value()["sql_log_bin"] == 1) {
				el.value().erase("sql_log_bin");
				j["conn"]["sql_log_bin"] = "ON";
			}
			else if (el.value()["sql_log_bin"] == 0) {
				el.value().erase("sql_log_bin");
				j["conn"]["sql_log_bin"] = "OFF";
			}

			// sql_auto_is_null {true|false}
			if (!el.value()["sql_auto_is_null"].dump().compare("ON") ||
				!el.value()["sql_auto_is_null"].dump().compare("1") ||
				!el.value()["sql_auto_is_null"].dump().compare("on") ||
				el.value()["sql_auto_is_null"] == 1
			) {
				el.value().erase("sql_auto_is_null");
				j["conn"]["sql_auto_is_null"] = "ON";
			}
			else if (!el.value()["sql_auto_is_null"].dump().compare("OFF") ||
					!el.value()["sql_auto_is_null"].dump().compare("0") ||
					!el.value()["sql_auto_is_null"].dump().compare("off") ||
					el.value()["sql_auto_is_null"] == 0) {
				el.value().erase("sql_auto_is_null");
				j["conn"]["sql_auto_is_null"] = "OFF";
			}

			// sql_safe_updates
			if (!el.value()["sql_safe_updates"].dump().compare("\"ON\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"1\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"on\"") ||
					el.value()["sql_safe_updates"] == 1) {
				el.value().erase("sql_safe_updates");
				j["conn"]["sql_safe_updates"] = "ON";
			} else if (!el.value()["sql_safe_updates"].dump().compare("\"OFF\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"0\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"off\"") ||
					el.value()["sql_safe_updates"] == 0) {
				el.value().erase("sql_safe_updates");
				j["conn"]["sql_safe_updates"] = "OFF";
			}

			// sql_select_limit
			if (!el.value()["sql_select_limit"].dump().compare("\"DEFAULT\"")) {
				el.value().erase("sql_select_limit");
				std::stringstream ss {};
				ss << 0xFFFFFFFFFFFFFFFF;
				j["conn"]["sql_select_limit"] = ss.str();
			}

			{
				// transaction_isolation (level)
				if (!el.value()["isolation_level"].dump().compare("\"REPEATABLE READ\"")) {
					el.value().erase("isolation_level");
					j["conn"]["transaction_isolation"] = "REPEATABLE-READ";
				}
				else if (!el.value()["isolation_level"].dump().compare("\"READ COMMITTED\"")) {
					el.value().erase("isolation_level");
					j["conn"]["transaction_isolation"] = "READ-COMMITTED";
				}
				else if (!el.value()["isolation_level"].dump().compare("\"READ UNCOMMITTED\"")) {
					el.value().erase("isolation_level");
					j["conn"]["transaction_isolation"] = "READ-UNCOMMITTED";
				}
				else if (!el.value()["isolation_level"].dump().compare("\"SERIALIZABLE\"")) {
					el.value().erase("isolation_level");
					j["conn"]["transaction_isolation"] = "SERIALIZABLE";
				} else {
					el.value().erase("isolation_level");
					j["conn"]["transaction_isolation"] = "";
				}
			}

			{
				// transaction_read (write|only)
				if (!el.value()["transaction_read"].dump().compare("\"ONLY\"")) {
					el.value().erase("transaction_read");
					j["conn"]["transaction_read_only"] = "ON";
				}
				else if (!el.value()["transaction_read"].dump().compare("\"WRITE\"")) {
					el.value().erase("transaction_read");
					j["conn"]["transaction_read_only"] = "OFF";
				} else {
					el.value().erase("transaction_read");
					j["conn"]["transaction_read_only"] = "";
				}
			}

			{
				// session_track_gtids
				if (!el.value()["session_track_gtids"].dump().compare("\"OFF\"")) {
					el.value().erase("session_track_gtids");
					j["conn"]["session_track_gtids"] = "OFF";
				}
				else if (!el.value()["session_track_gtids"].dump().compare("\"OWN_GTID\"")) {
					el.value().erase("session_track_gtids");
					j["conn"]["session_track_gtids"] = "OWN_GTID";
				}
				else if (!el.value()["session_track_gtids"].dump().compare("\"ALL_GTIDS\"")) {
					el.value().erase("session_track_gtids");
					j["conn"]["session_track_gtids"] = "ALL_GTIDS";
				}
			}
//			diag("DUMP 2:\n%s: ", j["conn"].dump(1).c_str());
		}
	}

	return EXIT_SUCCESS;
}

using session_var = std::pair<std::string, std::string>;

const std::vector<std::pair<std::string, std::string>> dummy_session_variables {
	{ "@session_var0", "'foobar0'" },
	{ "@session_var1", "'foobar1'" },
	{ "@session_var2", "'foobar2'" },
	{ "@session_var3", "'foobar3'" },
};

int set_session_variables(MYSQL* proxysql) {
	for (const auto sess_var : dummy_session_variables) {
		const std::string set_command { "SET " + sess_var.first + "=" + sess_var.second };
		MYSQL_QUERY(proxysql, set_command.c_str());
	}

	return EXIT_SUCCESS;
}

int get_session_variables(MYSQL* proxysql, std::vector<session_var>& sess_vars) {
	std::string select_query { "SELECT /*+ ;hostgroup=0 */ " };

	for (const auto& sess_var : dummy_session_variables) {
		select_query += sess_var.first;

		if (&sess_var != &dummy_session_variables.back()) {
			select_query += ",";
		}
	}

	MYSQL_QUERY(proxysql, select_query.c_str());

	// Extract the values for the variables
	std::vector<session_var> tmp_sess_vars {};
	MYSQL_RES* my_res = mysql_store_result(proxysql);
	int var_num = mysql_num_fields(my_res);
	MYSQL_ROW row = mysql_fetch_row(my_res);

	if (row != NULL) {
		for (int i = 0; i < var_num; i++) {
			tmp_sess_vars.push_back({ dummy_session_variables[i].first, row[i] == NULL ? "NULL" : row[i] });
		}
	}

	mysql_free_result(my_res);
	sess_vars = tmp_sess_vars;

	return EXIT_SUCCESS;
}

int get_tracked_proxy_vars(MYSQL* proxysql, const std::vector<std::string>& vars_names, std::vector<var_val>& vars_vals) {
	nlohmann::json internal_status_json {};
	int status_err = query_internal_session(proxysql, internal_status_json);
	if (status_err != EXIT_SUCCESS) {
		diag("'query_internal_session' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, status_err);
		return status_err;
	}

	for (const auto& var_id : vars_names) {
		const auto conn_object = internal_status_json["conn"];
		std::string lower_var_id {};
		std::transform(
			std::begin(var_id), std::end(var_id), std::back_inserter(lower_var_id),
			[] (unsigned char c) { return std::tolower(c); }
		);

		//diag("%s: ", conn_object.dump(1).c_str());
		const auto var_key = conn_object.find(lower_var_id);
		if (var_key == conn_object.end()) {
			diag("Failed to find key '%s' in the keys reported by 'PROXYSQL INTERNAL SESSION'", lower_var_id.c_str());
			vars_vals.push_back({ lower_var_id, "null" });
		} else {
			std::string vs;
			auto v = var_key.value();
			if (v.is_null() == false) {
				vs = std::string(v);
			} else {
				vs = "null";
			}
			diag("%s: %s", lower_var_id.c_str(), vs.c_str());
			vars_vals.push_back({ var_id, vs });
		}
	}

	return EXIT_SUCCESS;
}

int get_default_trx_isolation_attr(const std::string& user_attributes, std::string& trx_isolation) {
	try {
		if (user_attributes.empty() == false) {
			nlohmann::json j_user_attributes = nlohmann::json::parse(user_attributes);
			std::string tmp_trx_isolation = j_user_attributes["default-transaction_isolation"];
			if (tmp_trx_isolation == "REPEATABLE READ") {
				tmp_trx_isolation = "REPEATABLE-READ";
			} else if (tmp_trx_isolation == "READ COMMITTED") {
				tmp_trx_isolation = "READ-COMMITTED";
			} else if (tmp_trx_isolation == "READ UNCOMMITTED") {
				tmp_trx_isolation = "READ-UNCOMMITTED";
			} else {
				tmp_trx_isolation = "";
			}

			trx_isolation = tmp_trx_isolation;
		} else {
			return EXIT_SUCCESS;
		}
	} catch(const std::exception& ex) {
		diag(
			"Parsing JSON in 'user_attributes' resulted in exception '%s' at ('%s':'%d')",
			ex.what(), __FILE__, __LINE__
		);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int test_simple_select_after_reset(MYSQL* proxysql, const CommandLine&, const std::vector<user_config>& user_configs, bool com_reset=true) {
	// Do an initial reset
	if (com_reset) {
		int err_code = mysql_reset_connection(proxysql);
		if (err_code != EXIT_SUCCESS) {
			diag(
				"'mysql_reset_connection' failed with error: (%d,'%s') at ('%s':'%d')",
				mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
			);
			return EXIT_FAILURE;
		}
	} else {
		if (user_configs.size() == 0) {
			diag("Supplied empty 'users_config' parameter ('%s':'%d')", __FILE__, __LINE__);
			return EXIT_FAILURE;
		} else {
			std::string username = std::get<0>(user_configs[0]);
			std::string password = std::get<1>(user_configs[0]);

			int err_code = mysql_change_user(proxysql, username.c_str(), password.c_str(), NULL);
			if (err_code != EXIT_SUCCESS) {
				diag(
					"'mysql_change_user' failed with error: (%d,'%s') at ('%s':'%d')",
					mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
				);
				return EXIT_FAILURE;
			}
		}
	}

	MYSQL_QUERY(proxysql, "DO 1");

	// Check that a simple select works
	int err_code = mysql_query(proxysql, "SELECT /*+ ;hostgroup=0 */ 1");
	if (err_code != EXIT_SUCCESS) {
		diag("Simple 'SELECT 1' query failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	MYSQL_RES* select_res = mysql_store_result(proxysql);
	mysql_free_result(select_res);

	return EXIT_SUCCESS;
}

int test_simple_reset_admin(MYSQL*, const CommandLine& cl, const std::vector<user_config>&, bool) {
	MYSQL* admin = mysql_init(NULL);
	int res = EXIT_FAILURE;

	if (
		!mysql_real_connect(
			admin, "127.0.0.1", cl.admin_username, cl.admin_password, "information_schema", cl.admin_port, NULL, 0
		)
	) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// FIXME: 'COM_CHANGE_USER' doesn't return proper error right now for unsupported sessions types.
	mysql_reset_connection(admin);

	if (mysql_errno(admin) == 1047) {
		res = EXIT_SUCCESS;
	} else {
		diag(
			"'mysql_reset_connection' should fail for 'PROXYSQL_ADMIN' session: (exp_err: '1047', err: '%d', err_msg: '%s')",
			mysql_errno(admin), mysql_error(admin)
		);
	}

	mysql_close(admin);
	return res;
}

int test_transaction_rollback(MYSQL* proxysql, const CommandLine&, const std::vector<user_config>& user_configs, bool com_reset=true) {
	MYSQL_QUERY(proxysql, "DROP TABLE IF EXISTS test.com_reset_connection_trx");
	MYSQL_QUERY(
		proxysql,
		"CREATE TABLE test.com_reset_connection_trx ("
		" `id` int(10) unsigned NOT NULL AUTO_INCREMENT, `k` int(10) unsigned NOT NULL DEFAULT '0',"
		" `c` char(120) NOT NULL DEFAULT '', `pad` char(60) NOT NULL DEFAULT '', PRIMARY KEY (`id`), KEY `k_1` (`k`)"
		")"
	);

	MYSQL_QUERY(proxysql, "BEGIN");
	MYSQL_QUERY(proxysql, "INSERT INTO test.com_reset_connection_trx (k, c, pad) VALUES (5, 'k_value', 'value_pad')");

	if (com_reset) {
		int err_code = mysql_reset_connection(proxysql);
		if (err_code != EXIT_SUCCESS) {
			diag(
				"'mysql_reset_connection' failed with error: (%d,'%s') at ('%s':'%d')",
				mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
			);
			return EXIT_FAILURE;
		}
	} else {
		if (user_configs.size() == 0) {
			diag("Supplied empty 'users_config' parameter ('%s':'%d')", __FILE__, __LINE__);
			return EXIT_FAILURE;
		} else {
			std::string username = std::get<0>(user_configs[0]);
			std::string password = std::get<1>(user_configs[0]);

			int err_code = mysql_change_user(proxysql, username.c_str(), password.c_str(), NULL);
			if (err_code != EXIT_SUCCESS) {
				diag(
					"'mysql_change_user' failed with error: (%d,'%s') at ('%s':'%d')",
					mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
				);
				return EXIT_FAILURE;
			}
		}
	}

	MYSQL_QUERY(proxysql, "SELECT /*+ ;hostgroup=0 */ * FROM test.com_reset_connection_trx");
	MYSQL_RES* select_res = mysql_store_result(proxysql);
	int row_count = mysql_num_rows(select_res);
	if (row_count != 0) {
		diag(
			"Transaction should have been 'ROLLBACK', no rows should be returned: (row_count:'%d')", row_count
		);
		return EXIT_FAILURE;
	}
	mysql_free_result(select_res);

	return EXIT_SUCCESS;
}

int test_tracked_variables_cleanup(MYSQL* proxysql, const CommandLine&, const std::vector<user_config>& user_configs, bool com_reset=true) {
	// Get the initial values for the tracked variables
	std::vector<std::string> var_names {};
	std::transform(
		tracked_vars.begin(), tracked_vars.end(), std::back_inserter(var_names),
		[] (const track_variable_spec& var_spec) -> std::string {
			return std::get<1>(var_spec);
		}
	);

	MYSQL_QUERY(proxysql, "DO 1");

	std::vector<var_val> bef_vars_vals {};
	int err_num = get_tracked_proxy_vars(proxysql, var_names, bef_vars_vals);
	if (err_num) {
		diag("'get_tracked_vars_proxy_vals' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_num);
		return EXIT_FAILURE;
	}

	// Do an initial reset
	if (com_reset) {
		int err_code = mysql_reset_connection(proxysql);
		if (err_code != EXIT_SUCCESS) {
			diag(
				"'mysql_reset_connection' failed with error: (%d,'%s') at ('%s':'%d')",
				mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
			);
			return EXIT_FAILURE;
		}
	} else {
		if (user_configs.size() == 0) {
			diag("Supplied empty 'users_config' parameter ('%s':'%d')", __FILE__, __LINE__);
			return EXIT_FAILURE;
		} else {
			std::string username = std::get<0>(user_configs[0]);
			std::string password = std::get<1>(user_configs[0]);

			int err_code = mysql_change_user(proxysql, username.c_str(), password.c_str(), NULL);
			if (err_code != EXIT_SUCCESS) {
				diag(
					"'mysql_change_user' failed with error: (%d,'%s') at ('%s':'%d')",
					mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
				);
				return EXIT_FAILURE;
			}
		}
	}

	std::vector<var_val> init_proxy_vars {};
	int err_code = get_tracked_proxy_vars(proxysql, var_names, init_proxy_vars);
	if (err_code) {
		diag("'get_tracked_vars_proxy_vals' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	std::vector<var_val> init_mysql_vars {};
	err_code = get_tracked_mysql_vars(proxysql, init_mysql_vars);
	if (err_code) {
		diag("'query_tracked_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	// Set new values for the tracked variables
	err_code = set_tracked_variables(proxysql);
	if (err_code != EXIT_SUCCESS) {
		diag("'set_tracked_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return err_code;
	}

	std::vector<var_val> upd_proxy_vars {};
	err_code = get_tracked_proxy_vars(proxysql, var_names, upd_proxy_vars);
	if (err_code) {
		diag("'get_tracked_vars_proxy_vals' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	std::vector<var_val> upd_mysql_vars {};
	err_code = get_tracked_mysql_vars(proxysql, upd_mysql_vars);
	if (err_code) {
		diag("'query_tracked_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	// Sort the vectors with the values
	std::sort(upd_proxy_vars.begin(), upd_proxy_vars.end());
	std::sort(upd_mysql_vars.begin(), upd_mysql_vars.end());

	bool upd_vars_match =
		std::equal(std::begin(upd_proxy_vars), std::end(upd_proxy_vars), std::begin(upd_mysql_vars));
	if (upd_vars_match == false) {
		diag(
			"Updated variable values differ from ProxySQL and MySQL: \nProxySQL: %s, \nMySQL: %s",
			nlohmann::json(upd_proxy_vars).dump().c_str(), nlohmann::json(upd_mysql_vars).dump().c_str()
		);
		return EXIT_FAILURE;
	}

	// Do a second reset and get the new values
	if (com_reset) {
		int err_code = mysql_reset_connection(proxysql);
		if (err_code != EXIT_SUCCESS) {
			diag(
				"'mysql_reset_connection' failed with error: (%d,'%s') at ('%s':'%d')",
				mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
			);
			return EXIT_FAILURE;
		}
	} else {
		if (user_configs.size() != 2) {
			diag("Supplied 'users_config' parameters should be of size '2': ('%s':'%d')", __FILE__, __LINE__);
			return EXIT_FAILURE;
		} else {
			std::string username = std::get<0>(user_configs[1]);
			std::string password = std::get<1>(user_configs[1]);

			int err_code = mysql_change_user(proxysql, username.c_str(), password.c_str(), NULL);
			if (err_code != EXIT_SUCCESS) {
				diag(
					"'mysql_change_user' failed with error: (%d,'%s') at ('%s':'%d')",
					mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
				);
				return EXIT_FAILURE;
			}
		}
	}

	std::vector<var_val> reset_proxy_vars {};
	err_code = get_tracked_proxy_vars(proxysql, var_names, reset_proxy_vars);
	if (err_code) {
		diag("'get_tracked_vars_proxy_vals' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	std::vector<var_val> reset_mysql_vars {};
	err_code = get_tracked_mysql_vars(proxysql, reset_mysql_vars);
	if (err_code) {
		diag("'query_tracked_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	// Sort the vectors with the values
	std::sort(init_proxy_vars.begin(), init_proxy_vars.end());
	std::sort(reset_proxy_vars.begin(), reset_proxy_vars.end());
	std::sort(reset_mysql_vars.begin(), reset_mysql_vars.end());

	// Check that **ANY** of the reset values matched the updated values
	bool preserved_values = std::any_of(std::begin(upd_proxy_vars), std::end(upd_proxy_vars),
		[&] (const var_val& var_1) -> bool {
			for (const auto& var_2 : reset_proxy_vars) {
				if (var_1 == var_2) return true;
			}

			return false;
		}
	);

	const auto vars_eq_check =
		[&com_reset](const var_val& var_1, const var_val& var_2) -> bool {
			if (var_1.first == "transaction_isolation" && com_reset == false) {
				return var_1.second == "REPEATABLE-READ" && var_2.second == "READ-UNCOMMITTED";
			} else {
				return var_1 == var_2;
			}
		};

	bool equal_proxy_vars =
		std::equal(std::begin(init_proxy_vars), std::end(init_proxy_vars), std::begin(reset_proxy_vars), vars_eq_check);
	bool equal_mysql_vars =
		std::equal(std::begin(init_mysql_vars), std::end(init_mysql_vars), std::begin(reset_mysql_vars), vars_eq_check);
	bool reset_values_match = equal_proxy_vars && equal_mysql_vars && (preserved_values == false);

	diag(
		"Reset variables values are the same as the ones after initial reset ('%d', '%d', '%d'):"
		" \nBEFORE: %s,\nPROXY_INIT: %s,\nBACKEND_INIT: %s,\nPROXY_UPD: %s,\nPROXY_RESET: %s, \nBACKEND_RESET: %s",
		equal_proxy_vars, equal_mysql_vars, preserved_values, json(bef_vars_vals).dump().c_str(),
		json(init_proxy_vars).dump().c_str(), json(init_mysql_vars).dump().c_str(), json(upd_proxy_vars).dump().c_str(),
		json(reset_proxy_vars).dump().c_str(),  json(reset_mysql_vars).dump().c_str()
	);

	return reset_values_match ? 0 : 1;
}

int test_user_defined_variables_cleanup(MYSQL* proxysql, const CommandLine&, const std::vector<user_config>& user_configs, bool com_reset=true) {
	// Do an initial reset
	if (com_reset) {
		int err_code = mysql_reset_connection(proxysql);
		if (err_code != EXIT_SUCCESS) {
			diag(
				"'mysql_reset_connection' failed with error: (%d,'%s') at ('%s':'%d')",
				mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
			);
			return EXIT_FAILURE;
		}
	} else {
		if (user_configs.size() == 0) {
			diag("Supplied empty 'users_config' parameter ('%s':'%d')", __FILE__, __LINE__);
			return EXIT_FAILURE;
		} else {
			std::string username = std::get<0>(user_configs[0]);
			std::string password = std::get<1>(user_configs[0]);

			int err_code = mysql_change_user(proxysql, username.c_str(), password.c_str(), NULL);
			if (err_code != EXIT_SUCCESS) {
				diag(
					"'mysql_change_user' failed with error: (%d,'%s') at ('%s':'%d')",
					mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
				);
				return EXIT_FAILURE;
			}
		}
	}

	// Session variables should be now NULL now
	std::vector<session_var> ini_sess_vars {};
	int err_code = get_session_variables(proxysql, ini_sess_vars);
	if (err_code) {
		diag("'get_session_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return err_code;
	}

	bool non_null_val = std::any_of(
		std::begin(ini_sess_vars), std::end(ini_sess_vars),
		[](const session_var& sess_var) { return sess_var.second != "NULL"; }
	);
	if (non_null_val) {
		diag(
			"Session variable values failed to be NULL after initial reset at ('%s':'%d')",
			__FILE__, __LINE__
		);
		return EXIT_FAILURE;
	}

	err_code = set_session_variables(proxysql);
	if (err_code) {
		diag("'set_session_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return err_code;
	}

	std::vector<session_var> set_sess_vars {};
	err_code = get_session_variables(proxysql, set_sess_vars);
	if (err_code) {
		diag("'get_session_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return err_code;
	}

	bool equal_sess_values = std::equal(
		std::begin(dummy_session_variables), std::end(dummy_session_variables), std::begin(set_sess_vars),
		[] (const session_var& exp_var, const session_var& act_var) {
			return exp_var.first == act_var.first && exp_var.second == "'" + act_var.second + "'";
		}
	);
	if (equal_sess_values == false) {
		diag(
			"Session values failed to be equal to expected set values: \nExp: %s,\nAct: %s",
			 nlohmann::json(dummy_session_variables).dump().c_str(), nlohmann::json(set_sess_vars).dump().c_str()
		);
		return EXIT_FAILURE;
	}

	// Do a final reset and check that the variables are NULL again
	if (com_reset) {
		int err_code = mysql_reset_connection(proxysql);
		if (err_code != EXIT_SUCCESS) {
			diag(
				"'mysql_reset_connection' failed with error: (%d,'%s') at ('%s':'%d')",
				mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
			);
			return EXIT_FAILURE;
		}
	} else {
		if (user_configs.size() != 2) {
			diag("Supplied 'users_config' parameters should be of size '2': ('%s':'%d')", __FILE__, __LINE__);
			return EXIT_FAILURE;
		} else {
			std::string username = std::get<0>(user_configs[1]);
			std::string password = std::get<1>(user_configs[1]);

			int err_code = mysql_change_user(proxysql, username.c_str(), password.c_str(), NULL);
			if (err_code != EXIT_SUCCESS) {
				diag(
					"'mysql_change_user' failed with error: (%d,'%s') at ('%s':'%d')",
					mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
				);
				return EXIT_FAILURE;
			}
		}
	}

	std::vector<session_var> reset_sess_vars {};
	err_code = get_session_variables(proxysql, reset_sess_vars);
	if (err_code) {
		diag("'get_session_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return err_code;
	}

	non_null_val = std::any_of(
		std::begin(ini_sess_vars), std::end(ini_sess_vars),
		[](const session_var& sess_var) { return sess_var.second != "NULL"; }
	);
	if (non_null_val) {
		diag(
			"Session variable values failed to be NULL after initial reset at ('%s':'%d')",
			__FILE__, __LINE__
		);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int test_recover_session_values(MYSQL* proxysql, const CommandLine& cl, const std::vector<user_config>& user_configs, bool com_reset=true) {
	std::string username = std::get<0>(user_configs[0]);
	std::string password = std::get<1>(user_configs[0]);

	int err_code = mysql_change_user(proxysql, username.c_str(), password.c_str(), NULL);
	if (err_code != EXIT_SUCCESS) {
		diag(
			"'mysql_change_user' executed with error: (%d,'%s') at ('%s':'%d')",
			mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
		);
		return EXIT_FAILURE;
	}

	// Get the current session values
	nlohmann::json internal_status_json {};
	err_code = query_internal_session(proxysql, internal_status_json);
	if (err_code != EXIT_SUCCESS) {
		diag("'query_internal_session' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return err_code;
	}

	int init_current_hostgroup = internal_status_json["current_hostgroup"].get<int>();
	bool init_transaction_persistent = internal_status_json["transaction_persistent"].get<bool>();
	std::string user_attributes = internal_status_json["user_attributes"].get<std::string>();

	std::string init_trx_isolation_attr {};
	err_code = get_default_trx_isolation_attr(user_attributes, init_trx_isolation_attr);
	if (err_code != EXIT_SUCCESS) {
		diag("'get_default_trx_isolation_attr' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return err_code;
	}

	nlohmann::json j_init_trx_isolation_json = internal_status_json["conn"]["transaction_isolation"];
	std::string init_trx_isolation_session { j_init_trx_isolation_json.empty() ? "" : j_init_trx_isolation_json };

	if (init_trx_isolation_attr != init_trx_isolation_session) {
		diag(
			"Found invalid session 'trx_isolation' not matching 'user_attributes' (Exp:'%s', Act:'%s') at ('%s':'%d')",
			init_trx_isolation_attr.c_str(), init_trx_isolation_session.c_str(), __FILE__, __LINE__
		);
		return EXIT_FAILURE;
	}

	// Reset the connection
	if (com_reset) {
		int err_code = mysql_reset_connection(proxysql);
		if (err_code != EXIT_SUCCESS) {
			diag(
				"'mysql_reset_connection' failed with error: (%d,'%s') at ('%s':'%d')",
				mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
			);
			return EXIT_FAILURE;
		}
	} else {
		if (user_configs.size() == 0) {
			diag("Supplied empty 'users_config' parameter ('%s':'%d')", __FILE__, __LINE__);
			return EXIT_FAILURE;
		} else {
			std::string username = std::get<0>(user_configs[1]);
			std::string password = std::get<1>(user_configs[1]);

			int err_code = mysql_change_user(proxysql, username.c_str(), password.c_str(), NULL);
			if (err_code != EXIT_SUCCESS) {
				diag(
					"'mysql_change_user' executed with error: (%d,'%s') at ('%s':'%d')",
					mysql_errno(proxysql), mysql_error(proxysql), __FILE__, __LINE__
				);
				return EXIT_FAILURE;
			}
		}
	}

	err_code = query_internal_session(proxysql, internal_status_json);
	if (err_code != EXIT_SUCCESS) {
		diag("'query_internal_session' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return err_code;
	}

	// Update the session values
	init_current_hostgroup = internal_status_json["current_hostgroup"].get<int>();
	init_transaction_persistent = internal_status_json["transaction_persistent"].get<bool>();
	user_attributes = internal_status_json["user_attributes"].get<std::string>();

	std::string upd_trx_isolation_attr {};
	err_code = get_default_trx_isolation_attr(user_attributes, upd_trx_isolation_attr);
	if (err_code != EXIT_SUCCESS) {
		diag("'get_default_trx_isolation_attr' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return err_code;
	}

	nlohmann::json j_upd_trx_isolation_json = internal_status_json["conn"]["transaction_isolation"];
	std::string upd_trx_isolation_session { j_upd_trx_isolation_json.empty() ? "" : j_upd_trx_isolation_json };

	if (upd_trx_isolation_attr != upd_trx_isolation_session) {
		diag(
			"Found invalid session 'trx_isolation' not matching 'user_attributes' (Exp:'%s', Act:'%s') at ('%s':'%d')",
			upd_trx_isolation_attr.c_str(), upd_trx_isolation_session.c_str(), __FILE__, __LINE__
		);
		return EXIT_FAILURE;
	}

	int upd_current_hostgroup = internal_status_json["current_hostgroup"].get<int>();
	bool upd_transaction_persistent = internal_status_json["transaction_persistent"].get<bool>();
	bool matching_trx_isolations = false;

	if (com_reset == true) {
		matching_trx_isolations =
			init_trx_isolation_session == "REPEATABLE-READ" &&
			upd_trx_isolation_session == "REPEATABLE-READ";
	} else {
		matching_trx_isolations =
			init_trx_isolation_session == "REPEATABLE-READ" &&
			upd_trx_isolation_session == "READ-UNCOMMITTED";
	}

	if (
		init_current_hostgroup != upd_current_hostgroup &&
		init_transaction_persistent != upd_transaction_persistent &&
		matching_trx_isolations
	) {
		diag(
			"Values for 'INTERNAL SESSION' variables failed to match expected ones:"
			" 'current_hostgroup'= (Exp:'%d', Act:'%d'), 'transaction_persistent': (Exp: '%d', Act: '%d')),"
			" 'isolation_level'= (Exp:'%s', Act:'%s')",
			init_current_hostgroup, upd_current_hostgroup, init_transaction_persistent, upd_transaction_persistent,
			init_trx_isolation_session.c_str(), upd_trx_isolation_session.c_str()
		);
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}

int test_mysql_server_variables(MYSQL*, const CommandLine& cl, const std::vector<user_config>& user_configs, bool com_reset=true) {
	// Do an initial reset
	MYSQL* mysql = mysql_init(NULL);

	// Use a known default charset for the connection
	MARIADB_CHARSET_INFO* latin2_charset = proxysql_find_charset_collate("latin2_general_ci");
	mysql->charset = latin2_charset;

	if (!mysql_real_connect(mysql, cl.host, "root", "root", NULL, 13306, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return EXIT_FAILURE;
	}

	std::vector<var_val> bef_vars_vals {};
	int err_num = get_tracked_mysql_vars(mysql, bef_vars_vals);
	if (err_num) {
		diag("'get_tracked_vars_proxy_vals' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_num);
		return EXIT_FAILURE;
	}

	if (com_reset) {
		int err_code = mysql_reset_connection(mysql);
		if (err_code != EXIT_SUCCESS) {
			diag(
				"'mysql_reset_connection' failed with error: (%d,'%s') at ('%s':'%d')",
				mysql_errno(mysql), mysql_error(mysql), __FILE__, __LINE__
			);
			return EXIT_FAILURE;
		}
	} else {
		if (user_configs.size() == 0) {
			diag("Supplied empty 'users_config' parameter ('%s':'%d')", __FILE__, __LINE__);
			return EXIT_FAILURE;
		} else {
			std::string username = std::get<0>(user_configs[0]);
			std::string password = std::get<1>(user_configs[0]);

			int err_code = mysql_change_user(mysql, username.c_str(), password.c_str(), NULL);
			if (err_code != EXIT_SUCCESS) {
				diag(
					"'mysql_change_user' failed with error: (%d,'%s') at ('%s':'%d')",
					mysql_errno(mysql), mysql_error(mysql), __FILE__, __LINE__
				);
				return EXIT_FAILURE;
			}
		}
	}

	std::vector<std::string> var_names {};
	std::transform(
		tracked_vars.begin(), tracked_vars.end(), std::back_inserter(var_names),
		[] (const track_variable_spec& var_spec) -> std::string {
			return std::get<1>(var_spec);
		}
	);

	// Get the initial values for the tracked variables
	std::vector<var_val> ini_vars_vals {};
	std::vector<var_val> initial_mysql_vars {};
	int err_code = get_tracked_mysql_vars(mysql, initial_mysql_vars);
	if (err_code) {
		diag("'query_tracked_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	// Set new values for the tracked variables
	err_code = set_tracked_variables(mysql);
	if (err_code != EXIT_SUCCESS) {
		diag("'set_tracked_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return err_code;
	}

	std::vector<var_val> upd_mysql_vars {};
	err_code = get_tracked_mysql_vars(mysql, upd_mysql_vars);
	if (err_code) {
		diag("'query_tracked_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	// Sort the vectors with the values
	std::sort(upd_mysql_vars.begin(), upd_mysql_vars.end());

	// Do a second reset and get the new values
	if (com_reset) {
		int err_code = mysql_reset_connection(mysql);
		if (err_code != EXIT_SUCCESS) {
			diag(
				"'mysql_reset_connection' failed with error: (%d,'%s') at ('%s':'%d')",
				mysql_errno(mysql), mysql_error(mysql), __FILE__, __LINE__
			);
			return EXIT_FAILURE;
		}
	} else {
		if (user_configs.size() != 2) {
			diag("Supplied 'users_config' parameters should be of size '2': ('%s':'%d')", __FILE__, __LINE__);
			return EXIT_FAILURE;
		} else {
			std::string username = std::get<0>(user_configs[1]);
			std::string password = std::get<1>(user_configs[1]);

			MARIADB_CHARSET_INFO* charset = proxysql_find_charset_collate("latin2_general_ci");
			mysql->charset = charset;

			int err_code = mysql_change_user(mysql, username.c_str(), password.c_str(), NULL);
			if (err_code != EXIT_SUCCESS) {
				diag(
					"'mysql_change_user' failed with error: (%d,'%s') at ('%s':'%d')",
					mysql_errno(mysql), mysql_error(mysql), __FILE__, __LINE__
				);
				return EXIT_FAILURE;
			}
		}
	}

	std::vector<var_val> reset_mysql_vars {};
	err_code = get_tracked_mysql_vars(mysql, reset_mysql_vars);
	if (err_code) {
		diag("'query_tracked_variables' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	// Sort the vectors with the values
	std::sort(ini_vars_vals.begin(), ini_vars_vals.end());
	std::sort(reset_mysql_vars.begin(), reset_mysql_vars.end());

	bool reset_values_match =
		std::equal(std::begin(reset_mysql_vars), std::end(reset_mysql_vars), std::begin(initial_mysql_vars));
	diag(
		"Reset variables values are the same as the ones after initial reset:"
		" \nBACKEND_INIT: %s\nBACKEND_UPD: %s\nBACKEND_RESET: %s",
		nlohmann::json(initial_mysql_vars).dump().c_str(), nlohmann::json(upd_mysql_vars).dump().c_str(),
		nlohmann::json(reset_mysql_vars).dump().c_str()
	);

	mysql_close(mysql);

	return reset_values_match ? 0 : 1;
}

using test_function = std::function<int(MYSQL*,const CommandLine&,const std::vector<user_config>&,bool)>;

std::vector<std::pair<std::string, test_function>> tests_fns {
	{ "test_simple_select_after_reset", test_simple_select_after_reset },
	{ "test_transaction_rollback", test_transaction_rollback },
	{ "test_tracked_variables_cleanup", test_tracked_variables_cleanup },
	{ "test_user_defined_variables_cleanup", test_user_defined_variables_cleanup },
	{ "test_simple_reset_admin", test_simple_reset_admin },
	{ "test_recover_session_values", test_recover_session_values },
	// NOTE: This is not a proper test for ProxySQL, was used during development to verify that the
	// same behavior tested by 'test_tracked_variables_cleanup' holds against a MySQL instance.
	// { "test_mysql_server_variables", test_mysql_server_variables }
};

int main(int argc, char** argv) {
	CommandLine cl;

	// One 'reset_connection' and 'change_user_test'
	plan(tests_fns.size() * 2);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxysql = mysql_init(NULL);

	// Use a known default charset for the connection
	MARIADB_CHARSET_INFO* latin2_charset = proxysql_find_charset_collate("latin2_general_ci");
	proxysql->charset = latin2_charset;

	if (
		!mysql_real_connect(
			proxysql, "127.0.0.1", cl.username, cl.password, "information_schema", cl.port, NULL, 0
		)
	) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	if (
		!mysql_real_connect(
			admin, "127.0.0.1", cl.admin_username, cl.admin_password, "information_schema", cl.admin_port, NULL, 0
		)
	) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Set the number of backend connections to '1' for making sure all the operations are performed in the same
	// backend connection.
	std::string t_update_servers_query {
		"UPDATE mysql_servers SET max_connections=1 WHERE hostgroup_id=%d"
	};
	std::string update_servers_query {};
	string_format(t_update_servers_query, update_servers_query, 0);

	MYSQL_QUERY(admin, update_servers_query.c_str());
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	usleep(50*1000);

	const std::vector<user_config> extra_users {
		std::make_tuple(
			"sbtest_reset_conn_1",
			"sbtest_reset_conn_1",
			"{\"default-transaction_isolation\":\"REPEATABLE READ\"}"
		),
		std::make_tuple(
			"sbtest_reset_conn_2",
			"sbtest_reset_conn_2",
			"{\"default-transaction_isolation\":\"READ UNCOMMITTED\"}"
		)
	};

	MYSQL* mysql_server = mysql_init(NULL);
	if (!mysql_real_connect(mysql_server, cl.host, "root", "root", NULL, 13306, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql_server));
		return EXIT_FAILURE;
	}

	int err_code = create_extra_users(admin, mysql_server, extra_users);
	if (err_code) {
		diag("'create_extra_users' failed at ('%s':'%d') with error '%d'", __FILE__, __LINE__, err_code);
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

	for (const auto& test_fn : tests_fns) {
		int test_res = EXIT_FAILURE;

		// Test the 'reset_connection' first
		try {
			test_res = test_fn.second(proxysql, cl, extra_users, true);
		} catch (const std::exception& ex) {
			diag("Exception while executing test '%s', exception msg: '%s'", test_fn.first.c_str(), ex.what());
		}
		ok(
			test_res == EXIT_SUCCESS,
			"'COM_RESET_CONNECTION' test '%s' completed with error code '%d'", test_fn.first.c_str(), test_res
		);

		// Test the 'change_user' later
		try {
			test_res = test_fn.second(proxysql, cl, extra_users, false);
		} catch (const std::exception& ex) {
			diag("Exception while executing test '%s', exception msg: '%s'", test_fn.first.c_str(), ex.what());
		}
		ok(
			test_res == EXIT_SUCCESS,
			"'COM_CHANGE_USER' test '%s' completed with error code '%d'", test_fn.first.c_str(), test_res
		);
	}

	mysql_close(proxysql);
	mysql_close(mysql_server);
	mysql_close(admin);

	return exit_status();
}
