/**
 * @file test_keep_multiplexing_variables-t.cpp
 * @brief This test checks that selecting on '@@session.*' and '@@*' variables disables multiplexing when
 *   target variables are not specified by 'mysql-keep_multiplexing_variables'.
 * @date 2021-09-30
 */

#include <vector>
#include <string>
#include <stdio.h>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using std::string;
using namespace nlohmann;

CommandLine cl;

std::vector<std::string> select_queries {
	"select @@session.autocommit,         @@session.big_tables, @@autocommit,@@bulk_insert_buffer_size,     @@character_set_database,@@transaction_isolation,    @@version,@@session.transaction_isolation",
	"select  @@autocommit, @@sql_mode,        @@big_tables,    @@autocommit,@@bulk_insert_buffer_size,     @@character_set_database,@@session.transaction_isolation,    @@version,@@transaction_isolation",
	"select  @@autocommit, @@sql_mode,        @@big_tables,    @@autocommit,@@bulk_insert_buffer_size,     @@character_set_database,@@session.transaction_isolation,    @@version,@@transaction_isolation",
	"select @@autocommit, @@sql_mode,        @@big_tables,    @@autocommit,@@session.bulk_insert_buffer_size,     @@character_set_database,@@session.transaction_isolation,    @@version,@@transaction_isolation",
	"select  @@sql_mode, @@autocommit,    @@big_tables,    @@autocommit,    @@character_set_database,@@transaction_isolation,    @@version,@@session.transaction_isolation",
	"select  @@sql_mode, @@autocommit,    @@big_tables,    @@autocommit,@@bulk_insert_buffer_size,     @@transaction_isolation,    @@version,@@session.transaction_isolation",
	"select  @@sql_mode, @@autocommit,    @@big_tables,    @@autocommit,@@bulk_insert_buffer_size,     @@character_set_database,@@transaction_isolation,    @@version,@@session.transaction_isolation",
	"select @@session.autocommit, @@big_tables, @@autocommit,@@bulk_insert_buffer_size,     @@character_set_database,@@transaction_isolation,    @@version,@@session.transaction_isolation",
	"select  @@big_tables, @@session.autocommit, @@autocommit,@@bulk_insert_buffer_size,     @@character_set_database,@@transaction_isolation,    @@version,@@session.transaction_isolation",
	"select  @@session.autocommit, @@big_tables, @@autocommit,@@bulk_insert_buffer_size,     @@character_set_database,  @@version,@@session.transaction_isolation",
	"select  @@session.autocommit, @@big_tables, @@autocommit,@@bulk_insert_buffer_size,     @@character_set_database,@@transaction_isolation,    @@version,@@session.transaction_isolation",
};

int check_multiplexing_disabled(const std::string query, bool& multiplex_disabled) {

	MYSQL* proxysql_mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_mysql->net.compress, "Compression: (%d)", proxysql_mysql->net.compress);
	}

	MYSQL_QUERY(proxysql_mysql, query.c_str());
	MYSQL_RES* dummy_res = mysql_store_result(proxysql_mysql);
	mysql_free_result(dummy_res);

	json j_status = fetch_internal_session(proxysql_mysql);

	if (j_status.contains("backends")) {
		for (auto& backend : j_status["backends"]) {
			if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
				multiplex_disabled = backend["conn"]["MultiplexDisabled"];
			}
		}
	}

	mysql_close(proxysql_mysql);

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {

	plan(2+2*4+2*2*select_queries.size() + 26);

	MYSQL* proxysql_admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_admin->net.compress, "Compression: (%d)", proxysql_admin->net.compress);
	}

	// Clean the 'keep_multiplexing_variables'
	MYSQL_QUERY(proxysql_admin, "SET mysql-keep_multiplexing_variables='version'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	diag("Cleaning 'mysql-keep_multiplexing_variables' to check multiplexing disabling.");

	// Check that any query will disable multiplexing
	{
		bool disabled_multiplexing = false;
		int check_multiplexing_err = check_multiplexing_disabled("SELECT @@sql_mode", disabled_multiplexing);
		ok (disabled_multiplexing == true, "Simple 'SELECT @@*' should disable multiplexing.");
	}

	{
		bool disabled_multiplexing = false;
		int check_multiplexing_err = check_multiplexing_disabled("SELECT @@SESSION.sql_mode", disabled_multiplexing);
		ok (disabled_multiplexing == true, "Simple 'SELECT @@SESSION.*' should disable multiplexing.");
	}

	// Adding the variable to 'keep_multiplexing_variables' should keep multiplexing enabled
	MYSQL_QUERY(proxysql_admin, "SET mysql-keep_multiplexing_variables='version,sql_mode'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	diag("Setting 'mysql-keep_multiplexing_variables' to keep multiplexing enabled.");

	// Check that any query will disable multiplexing
	{
		bool disabled_multiplexing = false;
		int check_multiplexing_err = check_multiplexing_disabled("SELECT @@sql_mode", disabled_multiplexing);
		ok (disabled_multiplexing == false, "Simple 'SELECT @@*' should keep multiplexing enabled.");
	}

	{
		bool disabled_multiplexing = false;
		int check_multiplexing_err = check_multiplexing_disabled("SELECT @@SESSION.sql_mode", disabled_multiplexing);
		ok (disabled_multiplexing == false, "Simple 'SELECT @@SESSION.*' should keep multiplexing enabled.");
	}

	// Clean the 'keep_multiplexing_variables'
	MYSQL_QUERY(proxysql_admin, "SET mysql-keep_multiplexing_variables='version'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	diag("Cleaning 'mysql-keep_multiplexing_variables' to check multiplexing disabling.");

	{
		for (const std::string& query : select_queries) {
			bool disabled_multiplexing = true;
			int check_multiplexing_err = check_multiplexing_disabled(query, disabled_multiplexing);
			ok (disabled_multiplexing == true, "Complex 'SELECT @@SESSION.*, @@*' should disable multiplexing.");
		}
	}

	// Adding multiple variables to 'keep_multiplexing_variables' should keep multiplexing enabled
	MYSQL_QUERY(proxysql_admin, "SET mysql-keep_multiplexing_variables='version,sql_mode,autocommit,big_tables,bulk_insert_buffer_size,character_set_database,transaction_isolation'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	diag("Setting 'mysql-keep_multiplexing_variables' to keep multiplexing enabled.");

	{
		for (const std::string& query : select_queries) {
			bool disabled_multiplexing = false;
			int check_multiplexing_err = check_multiplexing_disabled(query, disabled_multiplexing);
			ok (disabled_multiplexing == false, "Complex 'SELECT @@SESSION.*, @@*' queries should keep multiplexing enabled.");
		}
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
