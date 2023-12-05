/**
 * @file mysql_hostgroup_attributes-servers_defaults-t.cpp
 * @brief Simple test doing several checks for 'servers_defaults':
 *   1. Correct values can be inserted and check on 'mysql_hostgroup_attributes'.
 *   2. Correct LOAD TO RUNTIME.
 *   3. Correct SAVE TO DISK.
 *   4. Runtime values reset when a single new value is set. This doesn't reflect the internal memory values.
 *   5. Non-supported key fields in the JSON are allowed. This is by design.
 *   6. Invalid values can be inserted, but is reported in the error log.
 *   7. Invalid type values can be inserted, but is reported in the error log.
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
	MYSQL_QUERY_T(admin, "SELECT servers_defaults FROM runtime_mysql_hostgroup_attributes WHERE hostgroup_id=0");

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

	json j_runtime_servers_defaults = extract_json_result(admin);

	ok(
		j_servers_defaults == j_runtime_servers_defaults,
		"INSERTED 'servers_defaults' should match RUNTIME value - Exp: `%s`, Act: `%s`",
		j_servers_defaults.dump().c_str(), j_runtime_servers_defaults.dump().c_str()
	);

	MYSQL_QUERY_T(admin, "SAVE MYSQL SERVERS TO DISK");
	diag("Checking that DISK value matches INSERTED");
	MYSQL_QUERY_T(admin, "SELECT servers_defaults FROM disk.mysql_hostgroup_attributes WHERE hostgroup_id=0");
	json j_disk_servers_defaults = extract_json_result(admin);

	ok(
		j_servers_defaults == j_disk_servers_defaults,
		"INSERTED 'servers_defaults' should match RUNTIME value - Exp: `%s`, Act: `%s`",
		j_servers_defaults.dump().c_str(), j_disk_servers_defaults.dump().c_str()
	);

	return EXIT_SUCCESS;
}

void check_matching_logline(fstream& f_log, string regex) {
	// Minimal wait for the error log to be written
	usleep(500 * 1000);

	std::vector<line_match_t> matching_lines { get_matching_lines(f_log, regex) };
	for (const line_match_t& line_match : matching_lines) {
		diag(
			"Found matching logline - pos: %ld, line: `%s`",
			static_cast<int64_t>(std::get<LINE_MATCH_T::POS>(line_match)),
			std::get<LINE_MATCH_T::LINE>(line_match).c_str()
		);
	}

	ok(
		matching_lines.size() == 1,
		"Expected to find an invalid value logline matching regex - found_lines: %ld",
		matching_lines.size()
	);

	// Set the file to the end of stream
	f_log.seekg(0, std::ios::end);
}

int main(int, char**) {
	plan(12);

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	// Open the error log and fetch the final position
	const string f_path { get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };
	fstream f_log {};

	int of_err = open_file_and_seek_end(f_path, f_log);
	if (of_err) {
		diag("Failed to open ProxySQL log file. Aborting further testing...");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Cleanup
	MYSQL_QUERY_T(admin, "DROP TABLE IF EXISTS mysql_hostgroup_attributes_0508");
	MYSQL_QUERY_T(admin, "CREATE TABLE mysql_hostgroup_attributes_0508 AS SELECT * FROM disk.mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// 1. Set multiple valid values, and check it's properly set.
	json j_multiple_vals { { "weight", 100 }, { "max_connections", 10000 }, { "use_ssl", 1}, };
	update_and_check_servers_defaults(admin, j_multiple_vals);

	// 2. Set single valid value, and see others values have been reset.
	json j_single_val { { "weight", 100 } };
	update_and_check_servers_defaults(admin, j_single_val);

	// 3. NOTE: Setting only valid keys isn't enforced right now. This is by design.
	json j_inv_key { { "weiht", 100 } };
	update_and_check_servers_defaults(admin, j_inv_key);

	// 4. NOTE: Setting invalid value is allowed, error log should reflect the update error.
	json j_inv_val { { "weight", -100 } };
	update_and_check_servers_defaults(admin, j_inv_val);

	const string inv_val_regex {
		"\\[ERROR\\] Invalid value .+\\d supplied for 'mysql_hostgroup_attributes\\.servers_defaults\\.weight'"
			" for hostgroup +\\d\\. Value NOT UPDATED\\."
	};
	check_matching_logline(f_log, inv_val_regex);

	// 5. NOTE: Setting invalid type is allowed, error log should reflect the update error.
	json j_inv_val_type { { "weight", "100" } };
	update_and_check_servers_defaults(admin, j_inv_val_type);

	const string inv_type_regex {
		"\\[ERROR\\] Invalid type .*\\(\\d\\) supplied for 'mysql_hostgroup_attributes\\.servers_defaults\\.weight'"
			" for hostgroup +\\d\\. Value NOT UPDATED\\."
	};
	check_matching_logline(f_log, inv_type_regex);

cleanup:

	MYSQL_QUERY_T(admin, "DELETE FROM disk.mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, "INSERT INTO disk.mysql_hostgroup_attributes SELECT * FROM mysql_hostgroup_attributes_0508");
	mysql_close(admin);

	return exit_status();
}
