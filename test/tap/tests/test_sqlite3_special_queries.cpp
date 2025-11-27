/**
 * @file test_sqlite3_special_queries.cpp
 * @brief Execute all the special queries intercepted by SQLite3 sessions.
 * @details The test should be compiled against 'libmariadb' and 'libmysql' to ensure compatibility in the
 *   response of the intercepted queries.
 */

#include <vector>
#include <string>

#include "mysql.h"

#include "command_line.h"
#include "utils.h"
#include "tap.h"

using std::string;
using std::vector;

struct test_opts_t {
	unsigned long cflags;
	enum enum_mysql_set_option set_opt;
};

string to_string(const test_opts_t& opts) {
	return string { "{" }
		+ "cflags:" + std::to_string(opts.cflags) + ", "
		+ "set_opt:" + std::to_string(opts.set_opt)
	+ "}";
}

test_opts_t get_opt(vector<bool> bin_vec) {
	return test_opts_t {
		bin_vec[0] ? CLIENT_DEPRECATE_EOF : 0,
		bin_vec[1] ? MYSQL_OPTION_MULTI_STATEMENTS_ON : MYSQL_OPTION_MULTI_STATEMENTS_OFF
	};
}

vector<test_opts_t> gen_tests() {
	vector<test_opts_t> tests {};
	const auto opts { get_all_bin_vec(2) };

	std::transform(opts.begin(), opts.end(), std::back_inserter(tests), get_opt);

	return tests;
}

const vector<string> set_queries {
	"SET character_set_results='latin1'",
	"SET SQL_AUTO_IS_NULL=1",
	"SET NAMES 'utf8'",
	"/*!40100 SET @@SQL_MODE='' */",
	"/*!40103 SET TIME_ZONE='UTC' */",
	"/*!80000 SET SESSION transaction_isolation = 'READ-COMMITTED' */",
	"SET SESSION transaction_isolation = 'READ-COMMITTED'",
	"SET wait_timeout=86400"
};

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const vector<test_opts_t> tests { gen_tests() };
	plan(tests.size()*(3 + set_queries.size()));

	for (const test_opts_t& opts : tests) {
		diag("Executing test   test_opts=%s", to_string(opts).c_str());
		MYSQL* proxy = mysql_init(NULL);
		mysql_options(proxy, MYSQL_DEFAULT_AUTH, "mysql_native_password");

		int cflags = opts.cflags;

#ifdef LIBMYSQL_HELPER8
		{
			enum mysql_ssl_mode ssl_mode = SSL_MODE_DISABLED;
			mysql_options(proxy, MYSQL_OPT_SSL_MODE, &ssl_mode);
		}
#endif

		if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, cflags)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		}

		int set_rc = mysql_set_server_option(proxy, opts.set_opt);

		ok(
			set_rc == 0,
			"Setting server option should succeed   rc=%d test_opts=%s",
			set_rc, to_string(opts).c_str()
		);

		int ping_rc = mysql_ping(proxy);
		ok(ping_rc == 0, "Pinging the server succeed   rc=%d", ping_rc);

		int initdb_rc = mysql_select_db(proxy, "information_schema");
		ok(initdb_rc == 0, "COM_INIT_DB should succeed   rc=%d", initdb_rc);

		for (const auto& q : set_queries) {
			diag("Executing 'special SET' query   q='%s'", q.c_str());
			int rc = mysql_query(proxy, q.c_str());
			ok(rc == 0, "Query should execute without error   q='%s'", q.c_str());
		}

		mysql_close(proxy);
	}

	return exit_status();
}
