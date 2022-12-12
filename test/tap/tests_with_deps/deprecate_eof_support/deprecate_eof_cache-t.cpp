#include <algorithm>
#include <unistd.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <iostream>
#include <random>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include <proxysql_utils.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include "json.hpp"

using std::vector;
using std::string;
using std::pair;

/**
 * @brief Creates the tables required for the test.
 * @param mysql_server The initialized connection to the server.
 * @return The 'mysql_errno' code after creating the tables.
 */
int create_testing_tables(MYSQL* mysql_server) {
	// Create the testing database
	int res = mysql_query(mysql_server, "CREATE DATABASE IF NOT EXISTS test");
	if (res != 0) { return mysql_errno(mysql_server); }
	res = mysql_query(mysql_server, "DROP TABLE IF EXISTS test.ok_packet_cache_test");
	if (res != 0) { return mysql_errno(mysql_server); }

	mysql_query(
		mysql_server,
		"CREATE TABLE IF NOT EXISTS test.ok_packet_cache_test ("
		"  id INTEGER NOT NULL AUTO_INCREMENT,"
		"  c varchar(255),"
		"  pad CHAR(60),"
		"  PRIMARY KEY (id)"
		")"
	);
	return mysql_errno(mysql_server);
}

std::vector<std::string> queries {
	"SELECT * FROM test.ok_packet_cache_test WHERE id=%d",
	"INSERT INTO test.ok_packet_cache_test (c, pad) VALUES ('%s', '%s')",
	"UPDATE test.ok_packet_cache_test SET c='%s', pad='%s' WHERE id=%d"
};

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* proxy_mysql = mysql_init(NULL);
	MYSQL* proxy_admin = mysql_init(NULL);

	if (!proxy_mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		return -1;
	}
	if (!proxy_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return -1;
	}

	if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		return -1;
	}
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return -1;
	}

	// Create the testing tables
	int c_err = create_testing_tables(proxy_mysql);
	ok(c_err == 0, "Table creation should succeed. ErrCode: %d", c_err);
	if (tests_failed()) {
		std::string error = mysql_error(proxy_mysql);
		diag("MySQL Error: '%s'", error.c_str());

		return exit_status();
	}

	uint32_t c_operations = 50;
	vector<pair<string, string>> stored_pairs {};

	// INSERT the required data for exercising the cache
	for (auto i = 0; i < c_operations; i++) {
		std::string rnd_c = random_string(rand() % 80);
		std::string rnd_pad = random_string(rand() % 15);
		const std::string& t_insert_query = queries[1];
		std::string insert_query {};

		// Store the random generated strings
		stored_pairs.push_back(pair<string, string>{rnd_c, rnd_pad});

		// Execute the INSERT queries
		string_format(t_insert_query, insert_query, rnd_c.c_str(), rnd_pad.c_str());
		int i_res = mysql_query(proxy_mysql, insert_query.c_str());
		uint64_t i_err = mysql_errno(proxy_mysql);

		ok(i_err == 0, "Insert queries should be executed correctly. ErrCode: %ld", i_err);
		if (tests_failed()) {
			std::string error = mysql_error(proxy_mysql);
			diag("MySQL Error: '%s'", error.c_str());

			return exit_status();
		}
	}

	// Delete previous mysql_query_rules matching target digest
	MYSQL_QUERY(
		proxy_admin,
		"DELETE FROM mysql_query_rules WHERE "
		"match_digest='SELECT \\* FROM test\\.ok_packet_cache_test WHERE id=?'"
	);

	// Disable current ^SELECT query rule
	MYSQL_QUERY(proxy_admin, "UPDATE mysql_query_rules SET active=0 WHERE rule_id=2");

	// Add a new query rule with caching TTL for targgeting the cache
	std::string query_digest { "SELECT \\* FROM test\\.ok_packet_cache_test WHERE id=?" };
	std::string t_query_rule {
		"INSERT INTO mysql_query_rules "
		" (active,username,match_digest,destination_hostgroup,apply,cache_ttl)"
		" VALUES (1,'%s','%s',%d,%d,%d);"
	};
	std::string query_rule {};
	string_format(t_query_rule, query_rule, cl.username, query_digest.c_str(), 0, 1, 100);
	MYSQL_QUERY(proxy_admin, query_rule.c_str());

	// Load query rules to runtime
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	for (auto i = 0; i < c_operations; i++) {
		int rnd_op = rand() % c_operations;

		const auto id = i + 1;
		const std::string& t_select_query = queries[0];
		std::string select_query {};
		string_format(t_select_query, select_query, id);

		to_opts_t opts { 10000*1000, 100*1000, 500*1000, 2000*1000 };

		// Query *without* support for EOF deprecation
		auto eof_query = [&] (std::string& query_res, std::string& eof_query_err) -> int {
			int exec_res = wexecvp(
				std::string(cl.workdir) + "fwd_eof_query",
				{ select_query.c_str() },
				opts,
				query_res,
				eof_query_err
			);

			return exec_res;
		};

		// Query *with* support for EOF deprecation
		auto ok_query = [&] (std::string& query_res, std::string& ok_query_err) -> int {
			int exec_res = wexecvp(
				std::string(cl.workdir) + "fwd_eof_ok_query",
				{ select_query.c_str() },
				opts,
				query_res,
				ok_query_err
			);

			return exec_res;
		};

		// First check that the conversion from EOF to OK packet is working
		std::string eof_query_res {};
		std::string eof_query_err {};
		int exec_res = eof_query(eof_query_res, eof_query_err);
		ok(exec_res == 0, "'fwd_eof_query' should succeed - ErrCode: '%d', ErrMsg: '%s'", exec_res, eof_query_err.c_str());
		if (exec_res) {
			return exit_status();
		}

		std::string ok_query_res {};
		std::string ok_query_err {};
		exec_res = ok_query(ok_query_res, ok_query_err);
		ok(exec_res == 0, "'fwd_eof_ok_query' should succeed - ErrCode: '%d', ErrMsg: '%s'", exec_res, ok_query_err.c_str());
		if (exec_res) {
			return exit_status();
		}

		nlohmann::json eof_query_res_json = nlohmann::json::parse(eof_query_res);
		nlohmann::json ok_query_res_json = nlohmann::json::parse(ok_query_res);

		const std::string ok_res_id = ok_query_res_json["Result"][0]["id"];
		ok(
			ok_res_id == std::to_string(id),
			"EOF to OK -> inserted id: %d // received id: %s",
			id,
			ok_res_id.c_str()
		);

		const std::string ok_res_c = ok_query_res_json["Result"][0]["c"];
		ok(
			ok_res_c == stored_pairs[i].first,
			"EOF to OK -> inserted c: %s // received c: %s",
			stored_pairs[i].first.c_str(),
			ok_res_c.c_str()
		);

		const std::string ok_res_pad = ok_query_res_json["Result"][0]["pad"];
		ok(
			ok_res_pad == stored_pairs[i].second,
			"EOF to OK -> inserted pad: %s // received pad: %s",
			stored_pairs[i].second.c_str(),
			ok_res_pad.c_str()
		);

		uint32_t eof_res_status = eof_query_res_json["Status"];
		uint32_t ok_res_status = ok_query_res_json["Status"];
		ok(
			eof_res_status == ok_res_status,
			"EOF to OK -> EOF received status: %d // OK received status: %d",
			eof_res_status,
			ok_res_status
		);

		uint32_t eof_res_warnings = eof_query_res_json["Warnings"];
		uint32_t ok_res_warnings = ok_query_res_json["Warnings"];
		ok(
			eof_res_warnings == ok_res_warnings,
			"EOF to OK -> EOF received warnings: %d // OK received warnings: %d",
			eof_res_warnings,
			ok_res_warnings
		);

		// Wait for invalidation of query_cache
		usleep(110*1000);

		// Now check that the conversion from OK to EOF packet is working
		exec_res = ok_query(ok_query_res, ok_query_err);

		if (exec_res) {
			ok(false, "Error: fwd_eof_ok_query failed - ErrCode: '%d', ErrMsg: '%s'", exec_res, ok_query_err.c_str());
			return exit_status();
		}

		exec_res = eof_query(eof_query_res, eof_query_err);

		if (exec_res) {
			ok(false, "Error: fwd_eof_query failed - ErrCode: '%d', ErrMsg: '%s'", exec_res, eof_query_err.c_str());
			return exit_status();
		}

		ok_query_res_json = nlohmann::json::parse(ok_query_res);
		eof_query_res_json = nlohmann::json::parse(eof_query_res);

		const std::string eof_res_id = eof_query_res_json["Result"][0]["id"];
		ok(
			eof_res_id == std::to_string(id),
			"OK to EOF -> inserted id: %d // received id: %s",
			id,
			eof_res_id.c_str()
		);

		const std::string eof_res_c = eof_query_res_json["Result"][0]["c"];
		ok(
			eof_res_c == stored_pairs[i].first,
			"OK to EOF -> inserted c: %s // received c: %s",
			stored_pairs[i].first.c_str(),
			eof_res_c.c_str()
		);

		const std::string eof_res_pad = eof_query_res_json["Result"][0]["pad"];
		ok(
			eof_res_pad == stored_pairs[i].second,
			"OK to EOF -> inserted pad: %s // received pad: %s",
			stored_pairs[i].second.c_str(),
			eof_res_pad.c_str()
		);

		ok_res_status = ok_query_res_json["Status"];
		eof_res_status = eof_query_res_json["Status"];
		ok(
			ok_res_status == eof_res_status,
			"OK to EOF -> OK received status: %d // EOF received status: %d",
			ok_res_status,
			eof_res_status
		);

		ok_res_warnings = ok_query_res_json["Warnings"];
		eof_res_warnings = eof_query_res_json["Warnings"];
		ok(
			ok_res_warnings == eof_res_warnings,
			"OK to EOF -> OK received warnings: %d // EOF received warnings: %d",
			ok_res_warnings,
			eof_res_warnings
		);
	}

	// Delete new query cache rule
	MYSQL_QUERY(
		proxy_admin,
		"DELETE FROM mysql_query_rules WHERE "
		"match_digest='SELECT \\* FROM test\\.ok_packet_cache_test WHERE id=?'"
	);

	// Enable old ^SELECT query rule
	MYSQL_QUERY(proxy_admin, "UPDATE mysql_query_rules SET active=1 WHERE rule_id=2");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	mysql_close(proxy_admin);
	mysql_close(proxy_mysql);

	return exit_status();
}
