/**
 * @file reg_test_compression_split_packets-t.cpp
 * @brief This test performs INSERTs and SELECTs of big compressed packets.
 * @details Lengths used in the test must ensure that the packets are split, and we must check that the integrity of the
 *   inserted data is preserved when retrieving it through ProxySQL. We perform the same checks for with and without
 *   compression enabled in the backend servers.
 */

#include <cstring>
#include <fstream>
#include <string>
#include <stdio.h>
#include <vector>

#include <sys/stat.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;
using std::size_t;

/**
 * @brief Generate random string of only letters of the supplied size, we do this to ensure no-escaped sequences.
 * @param size Target size of the string to generate.
 * @return A randomly generated string of the supplied size.
 */
string gen_binary_payload(size_t size) {
	string binary_str(size, 'p');

	for (size_t i = 0; i < size; i++) {
		binary_str[i] = (char)(65 + rand() % 26);
	}

	return binary_str;
}

void print_query(const string& query, MYSQL* mysql) {
	diag("Query: Issuing query '%s' to ('%s':%d)", query.c_str(), mysql->host, mysql->port);
}

int mysql_query_p(MYSQL* mysql, const char* query) {
	diag("Query: Issuing query '%s' to ('%s':%d)", query, mysql->host, mysql->port);
	return mysql_query(mysql, query);
}

#define MYSQL_QUERY_P(mysql, query) \
	do { \
		diag("Query: Issuing query '%s' to ('%s':%d)", query, mysql->host, mysql->port); \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			return EXIT_FAILURE; \
		} \
	} while(0)

int test_compress_split_packets(const CommandLine& cl, const vector<size_t> test_payload_sizes) {
	diag("Create new conn to ProxySQL and ensure new backend conn is used for serving this queries");
	MYSQL* proxy = mysql_init(NULL);

	int rc = mysql_options(proxy, MYSQL_OPT_COMPRESS, NULL);
	if (rc != 0) {
		diag("Failed to set 'MYSQL_OPT_COMPRESS' for connection, aborting test. Error: '%s'", mysql_error(proxy));
	}

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_P(proxy, "/* create_new_connection=1 */ BEGIN");

	// 1. Test table creation
	const char* CREATE_TABLE_QUERY =
		"CREATE TABLE IF NOT EXISTS test.compress_split_packet (id INT PRIMARY KEY AUTO_INCREMENT, binarydata LONGBLOB)";

	MYSQL_QUERY_P(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_P(proxy, "DROP TABLE IF EXISTS test.compress_split_packet");
	MYSQL_QUERY_P(proxy, CREATE_TABLE_QUERY);

	// 2. Data insertion/retrieval
	int test_num = 1;

	for (const size_t test_size : test_payload_sizes) {
		const string bin_data { gen_binary_payload(test_size) };
		const string INSERT_QUERY {
			"INSERT INTO test.compress_split_packet (binarydata) VALUES ('" + bin_data + "')"
		};
		const string INSERT_QUERY_DIGEST {
			"INSERT INTO test.compress_split_packet (binarydata) VALUES ('?')"
		};
		const string SELECT_QUERY {
			"/* hostgroup=0 */ SELECT binarydata FROM test.compress_split_packet WHERE id=" + std::to_string(test_num)
		};

		print_query(INSERT_QUERY_DIGEST, proxy);
		int rc = mysql_query(proxy, INSERT_QUERY.c_str());
		ok(rc == 0, "INSERT query of size '%ld' should be successful. Error: '%s'", test_size, mysql_error(proxy));

		if (rc) {
			break;
		}

		rc = mysql_query_p(proxy, SELECT_QUERY.c_str());
		ok(rc == 0, "SELECT query of size '%ld' should be successful. Error: '%s'", test_size, mysql_error(proxy));

		if (rc) {
			break;
		}

		MYSQL_RES* myres = mysql_store_result(proxy);
		ok(
			myres != NULL, "'mysql_store_result' should retrieve a result for query '%s'. Error: '%s'",
			SELECT_QUERY.c_str(), mysql_error(proxy)
		);

		MYSQL_ROW myrow = mysql_fetch_row(myres);
		if (myres == NULL || (myrow == NULL || myrow[0] == NULL)) {
			diag("Unexpected empty 'resulset' from 'mysql_store_result', test failed to complete");
			break;
		}

		std::string res_bin_data { myrow[0] };
		mysql_free_result(myres);

		bool data_matches = res_bin_data == bin_data;

		ok(data_matches, "Received binary data should match sent binary data");

		if (!data_matches) {
			const string datadir_path { string { cl.workdir } + "reg_test_compression_split_packets_datadir" };
			diag("Saving payloads from failed test in: '%s'", datadir_path.c_str());

			int rc = mkdir(datadir_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
			if (rc && errno != EEXIST) {
				diag("Failed to create directory for payload saving: '%s'", strerror(errno));
			} else {
				try {
					const string insert_fpath { datadir_path + "/insert_data_" + std::to_string(test_size) + ".txt" };
					const string resdata_fpath { datadir_path + "/proxy_resdata_" + std::to_string(test_size) + ".txt" };

					std::ofstream insert_data_file { insert_fpath, std::ios::out };
					insert_data_file << bin_data;

					std::ofstream resdata_file { resdata_fpath, std::ios::out };
					resdata_file << res_bin_data;
				} catch (const std::exception& ex) {
					diag("Failed to save payload into target file: '%s'", ex.what());
				}
			}
			break;
		}

		test_num += 1;
	}

	mysql_close(proxy);

	return (test_num - 1) != test_payload_sizes.size();
}

/**
 * @brief Sizes of the payloads to test.
 */
const vector<size_t> test_payload_sizes {
	1024 * 1024 * 16 - 5,
	1024 * 1024 * 16 - 4,
	1024 * 1024 * 16 - 3,
	1024 * 1024 * 16 - 2,
	1024 * 1024 * 16 - 1,
	1024 * 1024 * 16,
	1024 * 1024 * 16 + 1,
	1024 * 1024 * 16 + 2,
	1024 * 1024 * 16 + 20,
	1024 * 1024 * 32,
	1024 * 1024 * 32 + 1024*1024,
	1024 * 1024 * 32 + 1024*1024*3
};

int main(int argc, char** argv) {
	CommandLine cl;

	// '4' tests per payload, times '2' due to compression/non-compression on backend servers
	plan(test_payload_sizes.size() * 4 * 2);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	diag("Preparing server for queries to be performed");
	MYSQL_QUERY_P(proxy, "/* hostgroup=0 */ SET GLOBAL max_allowed_packet=41943040");
	mysql_close(proxy);

	diag("Prepare ProxySQL servers with 'compression=0' for first test");
	MYSQL_QUERY_P(admin, "UPDATE mysql_servers SET compression=0 WHERE port=13306");
	MYSQL_QUERY_P(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	diag("TEST: Check compressed split packets through ProxySQL with backend conns with 'compression=0'");
	int rc = test_compress_split_packets(cl, test_payload_sizes);
	if (rc != EXIT_SUCCESS) {
		diag("Failed tests for 'compression=0' aborting further testing");
		goto cleanup;
	}

	diag("Prepare ProxySQL servers with 'compression=1' for second test");
	MYSQL_QUERY_P(admin, "UPDATE mysql_servers SET compression=1 WHERE port=13306");
	MYSQL_QUERY_P(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	diag("TEST: Check compressed split packets through ProxySQL with backend conns with 'compression=1'");
	test_compress_split_packets(cl, test_payload_sizes);

cleanup:
	mysql_close(admin);

	return exit_status();
}
