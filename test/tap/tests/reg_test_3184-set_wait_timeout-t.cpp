/**
 * @file reg_test_3184-set_wait_timeout-t.cpp
 * @brief This test is a regression test for issue #3184.
 * @details The test performs all the valid supported combinations of
 *   'SET @@wait_timeout' queries that ProxySQL should ignore, returning
 *   an okay packet. The check is performed via 'PROXYSQL INTERNAL SESSION',
 *   checking that multiplexing hasn't been disable due to an unknown
 *   'SET' statement.
 *
 * @date 2021-03-26
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

/**
 * @brief Valid variations of 'SET wait_timeout' supported
 *  by ProxySQL to be ignored.
 */
std::vector<std::string> valids_set_wait_timeout {
	"SET @@wait_timeout = 2147483",
	"SET @@wait_timeout=2147483",
	"SET @@SESSION.wait_timeout = 2147483",
	"SET @@SESSION.wait_timeout=2147483",
	"SET wait_timeout = 2147483",
	"SET wait_timeout=2147483",
	"SET SESSION wait_timeout = 2147483",
	"SET SESSION wait_timeout=2147483",

	"SET @@net_read_timeout = 2147483",
	"SET @@net_read_timeout=2147483",
	"SET @@SESSION.net_read_timeout = 2147483",
	"SET @@SESSION.net_read_timeout=2147483",
	"SET net_read_timeout = 2147483",
	"SET net_read_timeout=2147483",
	"SET SESSION net_read_timeout = 2147483",
	"SET SESSION net_read_timeout=2147483",

	"SET @@interactive_timeout = 2147483",
	"SET @@interactive_timeout=2147483",
	"SET @@SESSION.interactive_timeout = 2147483",
	"SET @@SESSION.interactive_timeout=2147483",
	"SET interactive_timeout = 2147483",
	"SET interactive_timeout=2147483",
	"SET SESSION interactive_timeout = 2147483",
	"SET SESSION interactive_timeout=2147483"

};

int main(int argc, char** argv) {

	plan(2 * valids_set_wait_timeout.size());

	MYSQL* proxysql_mysql = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}

	for (const auto& set_wait_timeout : valids_set_wait_timeout) {
		int query_err = mysql_query(proxysql_mysql, set_wait_timeout.c_str());
		ok (query_err == 0, "Query '%s' should be properly executed.", set_wait_timeout.c_str());

		json j_status = fetch_internal_session(proxysql_mysql);
		bool found_backends = j_status.contains("backends");
		ok(found_backends == false, "No backends should be found for the current connection.");
	}

	mysql_close(proxysql_mysql);

	return exit_status();
}
