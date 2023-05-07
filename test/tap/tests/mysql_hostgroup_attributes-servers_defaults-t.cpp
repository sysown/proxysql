/**
 * @file mysql_hostgroup_attributes-servers_defaults-t.cpp
 * @brief Simple test checking that 'servers_defaults' values are correctly LOAD TO RUNTIME for
 *  'mysql_hostgroup_attributes'.
 */

#include <cstring>
#include <string>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "json.hpp"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using nlohmann::json;
using std::string;

int update_and_check_servers_defaults(MYSQL* admin, const json& j_servers_defaults) {
	const string INSERT_QUERY {
		"INSERT INTO mysql_hostgroup_attributes (hostgroup_id, servers_defaults)"
			" VALUES (0, '" + j_servers_defaults.dump() + "')"
	};

	// Since the value we are updating in a single field, we can just DELETE each time
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, INSERT_QUERY.c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	diag("Checking that RUNTIME value matches INSERTED");
	MYSQL_QUERY_T(admin, "SELECT servers_defaults FROM mysql_hostgroup_attributes WHERE hostgroup_id=0");
	MYSQL_RES* myres = mysql_store_result(admin);
	MYSQL_ROW myrow = mysql_fetch_row(myres);
	json j_runtime_servers_defaults {};

	if (myrow && myrow[0]) {
		try {
			j_runtime_servers_defaults = json::parse(myrow[0]);
		} catch (const std::exception& e) {
			diag("ERROR: Failed to parse retrieved 'servers_defaults' - '%s'", e.what());
		}
	}

	mysql_free_result(myres);

	ok(
		j_servers_defaults == j_runtime_servers_defaults,
		"INSERTED 'servers_defaults' should match RUNTIME value - Exp: `%s`, Act: `%s`",
		j_servers_defaults.dump().c_str(), j_runtime_servers_defaults.dump().c_str()
	);

	return EXIT_SUCCESS;
}

int main(int, char**) {
	plan(3);

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
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// 1. Set multiple valid values, and check it's properly set.
	json j_multiple_vals { { "weight", 100 }, { "max_connections", 10000 }, { "use_ssl", 1}, };
	update_and_check_servers_defaults(admin, j_multiple_vals);

	// 2. Set single valid value, and see others values have been reset.
	json j_single_val { { "weight", 100 } };
	update_and_check_servers_defaults(admin, j_single_val);

	// 3. NOTE: Setting only valid keys isn't enforced right now. In the future, we could at least report a
	// sensible error via error log to more easily detect typos.
	json j_inv_val { { "weiht", 100 } };
	update_and_check_servers_defaults(admin, j_inv_val);

cleanup:

	mysql_close(admin);

	return exit_status();
}
