#include <unistd.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <stdlib.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "proxysql_utils.h"

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
	// Insert with an explicit id (first %d) so the value the SELECT loop
	// looks up below matches deterministically on every backend, including
	// multi-master ones (Galera, Group Replication) where
	// auto_increment_increment != 1. See issue #5781.
	"INSERT INTO test.ok_packet_cache_test (id, c, pad) VALUES (%d, '%s', '%s')",
	"UPDATE test.ok_packet_cache_test SET c='%s', pad='%s' WHERE id=%d"
};

long long query_cache_counter(MYSQL* proxy_admin, const char* counter_name) {
	std::string query {
		"SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='" +
		std::string(counter_name) + "'"
	};
	if (mysql_query(proxy_admin, query.c_str())) {
		diag("Failed to read query-cache counter '%s': %s", counter_name, mysql_error(proxy_admin));
		return -1;
	}

	MYSQL_RES* result = mysql_store_result(proxy_admin);
	if (!result) {
		diag("No result while reading query-cache counter '%s': %s", counter_name, mysql_error(proxy_admin));
		return -1;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	long long value = row && row[0] ? strtoll(row[0], nullptr, 10) : -1;
	if (value < 0) {
		diag("Query-cache counter '%s' was not available", counter_name);
	}
	mysql_free_result(result);
	return value;
}

class ProxyStateRestore {
public:
	explicit ProxyStateRestore(MYSQL* proxy_admin, bool restore_variables)
		: proxy_admin_(proxy_admin), restore_variables_(restore_variables) {}
	~ProxyStateRestore() { restore(); }

	void restore() {
		if (proxy_admin_) {
			mysql_query(proxy_admin_, "LOAD MYSQL QUERY RULES FROM DISK");
			mysql_query(proxy_admin_, "LOAD MYSQL QUERY RULES TO RUNTIME");
			if (restore_variables_) {
				mysql_query(proxy_admin_, "LOAD MYSQL VARIABLES FROM DISK");
				mysql_query(proxy_admin_, "LOAD MYSQL VARIABLES TO RUNTIME");
			}
			proxy_admin_ = nullptr;
		}
	}

private:
	MYSQL* proxy_admin_;
	bool restore_variables_;
};

int main(int argc, char** argv) {
	CommandLine cl;

	const bool mixed_capabilities = argc == 2 && std::string(argv[1]) == "--mixed-capabilities";
	if (argc != 1 && !mixed_capabilities) {
		diag("Unsupported argument. Expected --mixed-capabilities.");
		return -1;
	}

	uint32_t c_operations = mixed_capabilities ? 2 : 50;
	to_opts_t opts { 10000*1000, 100*1000, 500*1000, 2000*1000 };

	unsigned int p = 1; // create table
	p += c_operations; // inserts
	p += c_operations * (mixed_capabilities ? 26 : 22);
	plan(p);

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
	ProxyStateRestore proxy_state_restore(proxy_admin, mixed_capabilities);
	auto set_client_deprecate_eof = [&] (bool enabled) -> bool {
		const std::string value = std::to_string(enabled ? 1 : 0);
		if (mysql_query(proxy_admin, ("SET mysql-enable_client_deprecate_eof=" + value).c_str())) {
			diag("Failed to set mysql-enable_client_deprecate_eof=%s: %s", value.c_str(), mysql_error(proxy_admin));
			return false;
		}
		if (mysql_query(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
			diag("Failed to load MySQL variables to runtime: %s", mysql_error(proxy_admin));
			return false;
		}
		return true;
	};

	vector<pair<string, string>> stored_pairs {};

	// INSERT the required data for exercising the cache
	for (auto i = 0; i < c_operations; i++) {
		std::string rnd_c = random_string(rand() % 80);
		std::string rnd_pad = random_string(rand() % 15);
		const std::string& t_insert_query = queries[1];
		std::string insert_query {};

		// Store the random generated strings
		stored_pairs.push_back(pair<string, string>{rnd_c, rnd_pad});

		// Execute the INSERT queries with an explicit id of i+1 so the
		// downstream SELECT WHERE id=i+1 always matches (see issue #5781).
		string_format(t_insert_query, insert_query, i + 1, rnd_c.c_str(), rnd_pad.c_str());
		int i_res = mysql_query(proxy_mysql, insert_query.c_str());
		uint64_t i_err = mysql_errno(proxy_mysql);

		ok(i_err == 0, "Insert queries should be executed correctly. ErrCode: %ld", i_err);
		if (tests_failed()) {
			std::string error = mysql_error(proxy_mysql);
			diag("MySQL Error: '%s'", error.c_str());

			return exit_status();
		}
	}

	// Delete previous mysql_query_rules
	MYSQL_QUERY(proxy_admin, "DELETE FROM mysql_query_rules");

	// Add a new query rule with caching TTL for targgeting the cache
	std::string query_digest { "SELECT \\* FROM test\\.ok_packet_cache_test WHERE id=?" };
	std::string t_query_rule {
		"INSERT INTO mysql_query_rules "
		" (active,username,match_digest,destination_hostgroup,apply,cache_ttl)"
		" VALUES (1,'%s','%s',%d,%d,%d);"
	};
	std::string query_rule {};
	string_format(t_query_rule, query_rule, cl.username, query_digest.c_str(), 0, 1, 10000);
	MYSQL_QUERY(proxy_admin, query_rule.c_str());

	// Load query rules to runtime
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	for (auto i = 0; i < c_operations; i++) {
		const auto id = i + 1;
		const std::string& t_select_query = queries[0];
		std::string select_query {};
		string_format(t_select_query, select_query, id);


		std::string binary = "";
		// Query *without* support for EOF deprecation
		binary = "fwd_eof_query";
		diag("Calling %s%s with query: %s", cl.workdir, binary.c_str(), select_query.c_str());
		auto eof_query = [&] (std::string& query_res, std::string& eof_query_err) -> int {
			int exec_res = wexecvp(
				std::string(cl.workdir) + binary,
				{ select_query.c_str() },
				opts,
				query_res,
				eof_query_err
			);

			return exec_res;
		};

		// Query *with* support for EOF deprecation
		binary = "fwd_eof_ok_query";
		diag("Calling %s%s with query: %s", cl.workdir, binary.c_str(), select_query.c_str());
		auto ok_query = [&] (std::string& query_res, std::string& ok_query_err) -> int {
			int exec_res = wexecvp(
				std::string(cl.workdir) + binary,
				{ select_query.c_str() },
				opts,
				query_res,
				ok_query_err
			);

			return exec_res;
		};

		// Start each direction from a known empty cache. The first real client fills
		// the entry and the incompatible real client must read it, exercising the
		// EOF-to-OK conversion in the query cache.
		MYSQL_QUERY(proxy_admin, "PROXYSQL FLUSH MYSQL QUERY CACHE");
		const long long eof_to_ok_get_ok_before = query_cache_counter(proxy_admin, "Query_Cache_count_GET_OK");
		const long long eof_to_ok_set_before = query_cache_counter(proxy_admin, "Query_Cache_count_SET");

		// First check that the conversion from EOF to OK packet is working
		if (mixed_capabilities && !set_client_deprecate_eof(false)) return exit_status();
		std::string eof_query_res {};
		std::string eof_query_err {};
		int exec_res = eof_query(eof_query_res, eof_query_err);
		ok(exec_res == 0, "'fwd_eof_query' should succeed - ErrCode: '%d', ErrMsg: '%s'", exec_res, eof_query_err.c_str());
		if (exec_res) {
			return exit_status();
		}
		ok(
			query_cache_counter(proxy_admin, "Query_Cache_count_SET") == eof_to_ok_set_before + 1,
			"EOF to OK -> EOF client stores exactly one cache entry"
		);
		ok(
			query_cache_counter(proxy_admin, "Query_Cache_count_GET_OK") == eof_to_ok_get_ok_before,
			"EOF to OK -> EOF client does not read a cache entry"
		);

		std::string ok_query_res {};
		std::string ok_query_err {};
		if (mixed_capabilities && !set_client_deprecate_eof(true)) return exit_status();
		exec_res = ok_query(ok_query_res, ok_query_err);
		ok(exec_res == 0, "'fwd_eof_ok_query' should succeed - ErrCode: '%d', ErrMsg: '%s'", exec_res, ok_query_err.c_str());
		if (exec_res) {
			return exit_status();
		}
		ok(
			query_cache_counter(proxy_admin, "Query_Cache_count_SET") == eof_to_ok_set_before + 1,
			"EOF to OK -> EOF-deprecation client does not store a second cache entry"
		);
		ok(
			query_cache_counter(proxy_admin, "Query_Cache_count_GET_OK") == eof_to_ok_get_ok_before + 1,
			"EOF to OK -> EOF-deprecation client reads the cached entry"
		);

		nlohmann::json eof_query_res_json = nlohmann::json::parse(eof_query_res);
		nlohmann::json ok_query_res_json = nlohmann::json::parse(ok_query_res);
		if (mixed_capabilities) {
			ok(
				eof_query_res_json.value("FrontendDeprecateEOF", -1) == 0,
				"EOF to OK -> first client negotiated EOF packets"
			);
			ok(
				ok_query_res_json.value("FrontendDeprecateEOF", -1) == 1,
				"EOF to OK -> second client negotiated OK packets"
			);
		}

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

		// Expire no entries by time. Flush explicitly so the reverse direction also
		// has a guaranteed fill followed by a cache hit.
		MYSQL_QUERY(proxy_admin, "PROXYSQL FLUSH MYSQL QUERY CACHE");
		const long long ok_to_eof_get_ok_before = query_cache_counter(proxy_admin, "Query_Cache_count_GET_OK");
		const long long ok_to_eof_set_before = query_cache_counter(proxy_admin, "Query_Cache_count_SET");

		// Now check that the conversion from OK to EOF packet is working
		exec_res = ok_query(ok_query_res, ok_query_err);

		ok(exec_res == 0, "'fwd_eof_ok_query' should succeed - ErrCode: '%d', ErrMsg: '%s'", exec_res, ok_query_err.c_str());
		if (exec_res) {
			return exit_status();
		}
		ok(
			query_cache_counter(proxy_admin, "Query_Cache_count_SET") == ok_to_eof_set_before + 1,
			"OK to EOF -> EOF-deprecation client stores exactly one cache entry"
		);
		ok(
			query_cache_counter(proxy_admin, "Query_Cache_count_GET_OK") == ok_to_eof_get_ok_before,
			"OK to EOF -> EOF-deprecation client does not read a cache entry"
		);

		if (mixed_capabilities && !set_client_deprecate_eof(false)) return exit_status();
		exec_res = eof_query(eof_query_res, eof_query_err);

		ok(exec_res == 0, "'fwd_eof_query' should succeed - ErrCode: '%d', ErrMsg: '%s'", exec_res, eof_query_err.c_str());
		if (exec_res) {
			return exit_status();
		}
		ok(
			query_cache_counter(proxy_admin, "Query_Cache_count_SET") == ok_to_eof_set_before + 1,
			"OK to EOF -> EOF client does not store a second cache entry"
		);
		ok(
			query_cache_counter(proxy_admin, "Query_Cache_count_GET_OK") == ok_to_eof_get_ok_before + 1,
			"OK to EOF -> EOF client reads the cached entry"
		);

		ok_query_res_json = nlohmann::json::parse(ok_query_res);
		eof_query_res_json = nlohmann::json::parse(eof_query_res);
		if (mixed_capabilities) {
			ok(
				ok_query_res_json.value("FrontendDeprecateEOF", -1) == 1,
				"OK to EOF -> first client negotiated OK packets"
			);
			ok(
				eof_query_res_json.value("FrontendDeprecateEOF", -1) == 0,
				"OK to EOF -> second client negotiated EOF packets"
			);
		}

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

	proxy_state_restore.restore();
	mysql_close(proxy_admin);
	mysql_close(proxy_mysql);

	return exit_status();
}
