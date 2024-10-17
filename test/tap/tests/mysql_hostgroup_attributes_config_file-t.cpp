/**
 * @file mysql_hostgroup_attributes_config_file-t.cpp
 * @brief Reading and saving 'mysql_hostgroup_attributes' table from configuration file:
 *   1. Correct values should be inserted into 'mysql_hostgroup_attributes' table.
 *   2. Correct saving of mysql_hostgroup_attributes into config file.
 *   3. Delete all the values from 'mysql_hostgroup_attributes' table
 *   4. Correct load of 'mysql_hostgroup_attributes' table values from config file
 */

#include <cstring>
#include <string>
#include <fstream>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "json.hpp"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using nlohmann::json;
using std::string;
using std::fstream;

int save_and_read_mysql_hostgroup_attributes_from_config(MYSQL* admin) {
	json j_servers_defaults { { "weight", 100 }, { "max_connections", 10000 }, { "use_ssl", 1}, };

	// To run this test locally copy a ProxySQL config file into this path.
	string save_config_query = {"SAVE CONFIG TO FILE /var/lib/jenkins//scripts/"
								"docker-mysql-proxysql/conf/proxysql/proxysql.cnf"};

	const string INSERT_QUERY {
		"INSERT INTO mysql_hostgroup_attributes (hostgroup_id, servers_defaults, comment)"
			" VALUES (0, '" + j_servers_defaults.dump() + "', 'read config test')"
	};

	MYSQL_QUERY_T(admin, "DELETE FROM mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, INSERT_QUERY.c_str());
	MYSQL_QUERY_T(admin, save_config_query.c_str());
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS FROM CONFIG;");

	diag("Checking that config saved value matches INSERTED");
	MYSQL_QUERY_T(admin, "SELECT servers_defaults FROM mysql_hostgroup_attributes WHERE hostgroup_id=0");

	const auto extract_json_result = [] (MYSQL* admin) {
		json j_result {};
		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[0]) {
			try {
				j_result = json::parse(myrow[0]);
			} catch (const std::exception& e) {
				diag("ERROR: Failed to parse retrieved 'servers_defaults' - '%s'", e.what());
			}
		}

		mysql_free_result(myres);

		return j_result;
	};

	json j_config_servers_defaults = extract_json_result(admin);

	ok(
		j_servers_defaults == j_config_servers_defaults,
		"INSERTED 'servers_defaults' should match config value - Exp: `%s`, Act: `%s`",
		j_servers_defaults.dump().c_str(), j_config_servers_defaults.dump().c_str()
	);

	MYSQL_QUERY_T(admin, "DELETE FROM mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, save_config_query.c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS FROM CONFIG;");		
	diag("Checking that config saved value matches INSERTED");
	MYSQL_QUERY_T(admin, "SELECT servers_defaults FROM mysql_hostgroup_attributes WHERE hostgroup_id=0");

	j_config_servers_defaults = extract_json_result(admin);
	json j_empty = {};

	ok(
		j_empty == j_config_servers_defaults,
		"mysql_hostgroup_attributes should be empty. j_config_servers_defaults: `%s`",
		j_config_servers_defaults.dump().c_str()
	);

	return EXIT_SUCCESS;
}

int main(int, char**) {
	plan(2);

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Cleanup
	MYSQL_QUERY_T(admin, "DROP TABLE IF EXISTS mysql_hostgroup_attributes_0508");
	MYSQL_QUERY_T(admin, "CREATE TABLE mysql_hostgroup_attributes_0508 AS SELECT * FROM mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_hostgroup_attributes");

	save_and_read_mysql_hostgroup_attributes_from_config(admin);

cleanup:

	MYSQL_QUERY_T(admin, "DELETE FROM mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, "INSERT INTO mysql_hostgroup_attributes SELECT * FROM mysql_hostgroup_attributes_0508");
	mysql_close(admin);
	return exit_status();
}