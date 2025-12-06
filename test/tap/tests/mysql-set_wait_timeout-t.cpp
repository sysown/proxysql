/**
 * @file mysql-set_wait_timeout-t.cpp
 * @brief This TAP test validates if session 'wait_timeout' is working correctly.
 */

#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using namespace nlohmann;

MYSQL* init_mysql_conn(char* host, char* user, char* pass, int port) {
	diag("Creating MySQL conn host=\"%s\" port=\"%d\" user=\"%s\"", host, port, user);

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		return nullptr;
	}

	if (!mysql_real_connect(mysql, host, user, pass, NULL, port, NULL, 0)) {
		return nullptr;
	}

	return mysql;
}

int run_q(MYSQL *mysql, const char *q) {
	MYSQL_QUERY_T(mysql,q);
	return 0;
}

// Helper function to extract wait_timeout from JSON
int extract_wait_timeout_from_json(const json& j_session, unsigned long long &wait_timeout_value) {
	try {
		if (j_session.is_array() && !j_session.empty()) {
			// If it's an array, get the first element
			json session_data = j_session[0];
			if (session_data.contains("wait_timeout") && session_data["wait_timeout"].is_number_unsigned()) {
				wait_timeout_value = session_data["wait_timeout"].get<unsigned long long>();
				return 1;
			}
		} else if (j_session.contains("wait_timeout") && j_session["wait_timeout"].is_number_unsigned()) {
			// If it's a single object
			wait_timeout_value = j_session["wait_timeout"].get<unsigned long long>();
			return 1;
		}
	} catch (const std::exception& e) {
		diag("Error accessing wait_timeout from JSON: %s", e.what());
	}
	return 0;
}

int test_session_timeout(CommandLine *cl, MYSQL *admin) {
	diag("Test: %s", __func__);

	diag("Setting mysql-wait_timeout=50000");
	MYSQL_QUERY_T(admin, "SET mysql-wait_timeout=50000");
	diag("Setting mysql-poll_timeout=500 , required for more precise timeout");
	MYSQL_QUERY_T(admin, "SET mysql-poll_timeout=500");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = init_mysql_conn(cl->host, cl->username, cl->password, cl->port);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(proxy, "SET wait_timeout=10");

	int rc = run_q(proxy, "SET sql_mode=''");
	ok(rc == 0, (rc == 0 ? "Connection alive" : "Connection killed"));

	sleep(13);

	rc = run_q(proxy, "SET sql_mode=''");
	ok(rc != 0, (rc == 0 ? "Connection alive" : "Connection killed"));

	mysql_close(proxy);
	return EXIT_SUCCESS;
}


int test_session_timeout_exceed_global_timeout(CommandLine *cl, MYSQL *admin) {
	diag("Test: %s", __func__);

	diag("Setting mysql-wait_timeout=10000");
	MYSQL_QUERY_T(admin, "SET mysql-wait_timeout=10000");
	diag("Setting mysql-poll_timeout=500 , required for more precise timeout");
	MYSQL_QUERY_T(admin, "SET mysql-poll_timeout=500");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL*proxy = init_mysql_conn(cl->host, cl->username, cl->password, cl->port);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(proxy, "SET wait_timeout=20");

	int rc = run_q(proxy, "SET sql_mode=''");
	ok(rc == 0, (rc == 0 ? "Connection alive" : "Connection killed"));

	sleep(13);

	rc = run_q(proxy, "SET sql_mode=''");
	ok(rc != 0, (rc == 0 ? "Connection alive" : "Connection killed"));

	mysql_close(proxy);
	return EXIT_SUCCESS;
}

int test_wait_timeout_json_values(CommandLine *cl, MYSQL *admin) {
	diag("Test: %s - Testing various wait_timeout values and JSON validation", __func__);

	MYSQL_QUERY_T(admin, "SET mysql-wait_timeout=60000"); // 60 seconds global timeout
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = init_mysql_conn(cl->host, cl->username, cl->password, cl->port);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	struct TestCase {
		const char* set_query;
		unsigned long long expected_ms;
		const char* description;
	};

	TestCase test_cases[] = {
		{"SET wait_timeout=0", 1000, "Zero value should be clamped to 1 second"},
		{"SET wait_timeout=1", 1000, "1 second should be accepted"},
		{"SET wait_timeout=10", 10000, "10 seconds should be accepted"},
		{"SET wait_timeout=300", 300000, "5 minutes should be accepted"},
		{"SET wait_timeout=3600", 3600000, "1 hour should be accepted"},
		{"SET wait_timeout=86400", 86400000, "24 hours should be accepted"},
		{"SET wait_timeout=1728000", 1728000000, "20 days should be accepted"},
		{"SET wait_timeout=1728001", 1728000000, "Value exceeding 20 days should be clamped"}
	};

	int test_count = sizeof(test_cases) / sizeof(test_cases[0]);

	for (int i = 0; i < test_count; i++) {
		diag("Testing: %s", test_cases[i].description);

		// Set the wait_timeout value
		MYSQL_QUERY_T(proxy, test_cases[i].set_query);

		// Query PROXYSQL INTERNAL SESSION using the utility function
		json j_session = fetch_internal_session(proxy, false);
		if (j_session.empty()) {
			ok(false, "Failed to fetch PROXYSQL INTERNAL SESSION");
			mysql_close(proxy);
			return EXIT_FAILURE;
		}

		unsigned long long actual_wait_timeout;
		int json_result = extract_wait_timeout_from_json(j_session, actual_wait_timeout);

		if (json_result) {
			ok(actual_wait_timeout == test_cases[i].expected_ms,
			   "wait_timeout JSON value matches expected: %llu ms == %llu ms",
			   actual_wait_timeout, test_cases[i].expected_ms);
			diag("Expected: %llu ms, Got: %llu ms", test_cases[i].expected_ms, actual_wait_timeout);
		} else {
			ok(false, "Failed to extract wait_timeout from JSON");
		}

		// Small delay between tests
		usleep(10000);
	}

	mysql_close(proxy);
	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	plan(12); // 4 + 8 tests for new JSON validation function

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_username, cl.admin_password, cl.admin_port);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}

	int rc = test_session_timeout(&cl, admin);
	if (rc != EXIT_SUCCESS) {
		return exit_status();
	}

	rc = test_session_timeout_exceed_global_timeout(&cl, admin);
	if (rc != EXIT_SUCCESS) {
		return exit_status();
	}

	rc = test_wait_timeout_json_values(&cl, admin);
	if (rc != EXIT_SUCCESS) {
		return exit_status();
	}

	mysql_close(admin);
	return exit_status();
}
