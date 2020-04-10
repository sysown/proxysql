#include <mysql.h>

#include "tap.h"
#include "utils.h"

int show_variable(MYSQL *mysql, const std::string& var_name, std::string& var_value) {
	char query[128];

	snprintf(query, sizeof(query),"show variables like '%s'", var_name.c_str());
	if (mysql_query(mysql, query)) {
		fprintf(stderr, "Failed to execute query [%s] : no %d, %s\n",
				query, mysql_errno(mysql), mysql_error(mysql));
		return exit_status();
	}

	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);

	int num_fields = mysql_num_fields(result);

	row = mysql_fetch_row(result);
	var_value = row[1];
	mysql_free_result(result);
	return 0;
}

int select_config_file(MYSQL* mysql, std::string& resultset) {
	if (mysql_query(mysql, "select config file")) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);
	if (result) {
		row = mysql_fetch_row(result);
		resultset = row[0];
		mysql_free_result(result);
	} else {
		fprintf(stderr, "error\n");
	}

	return 0;
}

int show_admin_global_variable(MYSQL *mysql, const std::string& var_name, std::string& var_value) {
	char query[128];

	snprintf(query, sizeof(query),"select variable_value from global_variables where variable_name='%s'", var_name.c_str());
	if (mysql_query(mysql, query)) {
		fprintf(stderr, "Failed to execute SHOW VARIABLES LIKE : no %d, %s\n",
				mysql_errno(mysql), mysql_error(mysql));
		return exit_status();
	}

	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);

	int num_fields = mysql_num_fields(result);

	row = mysql_fetch_row(result);
	var_value = row[0];
	mysql_free_result(result);
	return 0;
}

int set_admin_global_variable(MYSQL *mysql, const std::string& var_name, const std::string& var_value) {
	char query[128];

	snprintf(query, sizeof(query),"update global_variables set variable_value = '%s' where variable_name='%s'", var_value.c_str(), var_name.c_str());
	if (mysql_query(mysql, query)) {
		fprintf(stderr, "Failed to execute SHOW VARIABLES LIKE : no %d, %s\n",
				mysql_errno(mysql), mysql_error(mysql));
		return exit_status();
	}
	return 0;
}


int get_server_version(MYSQL *mysql, std::string& version) {
	char query[128];

	if (mysql_query(mysql, "select @@version")) {
		fprintf(stderr, "Error %d, %s\n",
				mysql_errno(mysql), mysql_error(mysql));
		return exit_status();
	}

	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);

	int num_fields = mysql_num_fields(result);

	row = mysql_fetch_row(result);
	version = row[0];
	mysql_free_result(result);

	return 0;
}
