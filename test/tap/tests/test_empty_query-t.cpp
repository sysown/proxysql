/**
 * @file test_empty_query-t.cpp
 * @brief Simple test checking that empty queries are properly handled by ProxySQL.
 */

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

static constexpr unsigned int EXECUTIONS = 100U;

int main(int argc, char** argv) {
	plan(1);

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxy = mysql_init(nullptr);

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	const unsigned int exp_myerr = 1065U;
	unsigned int act_myerr = 0U;

	for (uint32_t i = 0; i < EXECUTIONS; i++) {
		mysql_query(proxy, "");
		act_myerr = mysql_errno(proxy);

		if (exp_myerr != act_myerr) {
			break;
		}
	}

	ok(
		exp_myerr == act_myerr, "MySQL error equals expected - exp_err: '%d', act_err: '%d' error: `%s`",
		exp_myerr, act_myerr, mysql_error(proxy)
	);

	mysql_close(proxy);

	return exit_status();
}
