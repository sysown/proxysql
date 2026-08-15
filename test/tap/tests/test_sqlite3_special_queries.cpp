/**
 * @file test_sqlite3_special_queries.cpp
 * @brief Execute all the special queries intercepted by SQLite3 sessions.
 * @details The test should be compiled against 'libmariadb' and 'libmysql' to ensure compatibility in the
 *   response of the intercepted queries.
 */

#include <cstdlib>
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

constexpr int SQLITE3_SERVER_PORT { 6030 };

static bool set_client_deprecate_eof(MYSQL* admin, bool enabled) {
	const string query {
		"SET mysql-enable_client_deprecate_eof=" + std::to_string(enabled ? 1 : 0)
	};
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("Failed to set mysql-enable_client_deprecate_eof: %s", mysql_error(admin));
		return false;
	}
	if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") != 0) {
		diag("Failed to load mysql variables to runtime: %s", mysql_error(admin));
		return false;
	}
	return true;
}

static bool get_client_deprecate_eof(MYSQL* admin, bool& enabled) {
	const char* query {
		"SELECT variable_value FROM global_variables "
		"WHERE variable_name='mysql-enable_client_deprecate_eof'"
	};
	if (mysql_query(admin, query) != 0) {
		diag("Failed to read mysql-enable_client_deprecate_eof: %s", mysql_error(admin));
		return false;
	}

	MYSQL_RES* result = mysql_store_result(admin);
	MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
	const char* value = row ? row[0] : nullptr;
	const bool valid_value = value &&
		(!strcmp(value, "0") || !strcmp(value, "1") ||
		 !strcmp(value, "false") || !strcmp(value, "true"));
	if (valid_value) {
		enabled = !strcmp(value, "1") || !strcmp(value, "true");
	} else {
		diag("Unexpected mysql-enable_client_deprecate_eof value: %s", value ? value : "(null)");
	}
	if (result) {
		mysql_free_result(result);
	}
	return valid_value;
}

class restore_client_deprecate_eof {
	MYSQL* admin;
	bool enabled;

public:
	restore_client_deprecate_eof(MYSQL* admin, bool enabled) : admin { admin }, enabled { enabled } {}
	~restore_client_deprecate_eof() {
		if (!set_client_deprecate_eof(admin, enabled)) {
			diag("Failed to restore mysql-enable_client_deprecate_eof");
		}
	}
};

static void test_direct_deprecate_eof_matrix(const CommandLine& cl, MYSQL* admin) {
	bool original_enabled = false;
	if (!get_client_deprecate_eof(admin, original_enabled)) {
		ok(false, "SQLite3 advertised CLIENT_DEPRECATE_EOF as configured");
		ok(false, "SELECT CONNECTION_ID() parses with the negotiated backend EOF mode");
		ok(false, "SQLite3 advertised CLIENT_DEPRECATE_EOF as configured");
		ok(false, "SELECT CONNECTION_ID() parses with the negotiated backend EOF mode");
		return;
	}
	restore_client_deprecate_eof restore { admin, original_enabled };

	for (const bool expected_server_capability : { false, true }) {
		if (!set_client_deprecate_eof(admin, expected_server_capability)) {
			ok(false, "SQLite3 advertised CLIENT_DEPRECATE_EOF as configured");
			ok(false, "SELECT CONNECTION_ID() parses with the negotiated backend EOF mode");
			continue;
		}

		MYSQL* proxy = mysql_init(NULL);
		const bool connected = proxy && mysql_real_connect(
			proxy, cl.host, cl.username, cl.password, NULL, SQLITE3_SERVER_PORT, NULL,
			CLIENT_DEPRECATE_EOF
		);
		const bool server_supports_deprecate_eof = connected &&
			(proxy->server_capabilities & CLIENT_DEPRECATE_EOF);
		ok(server_supports_deprecate_eof == expected_server_capability,
			"SQLite3 advertised CLIENT_DEPRECATE_EOF as configured");

		int connection_id_rc = connected ? mysql_query(proxy, "SELECT CONNECTION_ID()") : -1;
		MYSQL_RES* connection_id_result = connection_id_rc == 0 ? mysql_store_result(proxy) : nullptr;
		MYSQL_ROW connection_id_row = connection_id_result ? mysql_fetch_row(connection_id_result) : nullptr;
		char* parse_end = nullptr;
		const unsigned long long connection_id = connection_id_row && connection_id_row[0]
			? std::strtoull(connection_id_row[0], &parse_end, 10)
			: 0;
		const bool valid_connection_id = connection_id_row && connection_id_row[0]
			&& parse_end && *parse_end == '\0' && connection_id > 0;
		const unsigned long long expected_connection_id = connected
			? static_cast<unsigned long long>(mysql_thread_id(proxy))
			: 0;
		if (connection_id_result) {
			mysql_free_result(connection_id_result);
		}
		ok(connection_id_rc == 0 && valid_connection_id && connection_id == expected_connection_id,
			"SELECT CONNECTION_ID() parses with the negotiated backend EOF mode");

		if (proxy) {
			mysql_close(proxy);
		}
	}
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const vector<test_opts_t> tests { gen_tests() };
	plan(4 + tests.size()*(4 + set_queries.size()));

	MYSQL* admin = mysql_init(NULL);
	if (!admin || !mysql_real_connect(
		admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0
	)) {
		diag("Failed to connect to the admin interface: %s", admin ? mysql_error(admin) : "mysql_init failed");
		if (admin) {
			mysql_close(admin);
		}
		return EXIT_FAILURE;
	}
	test_direct_deprecate_eof_matrix(cl, admin);
	mysql_close(admin);

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

		if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, SQLITE3_SERVER_PORT, NULL, cflags)) {
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

		int connection_id_rc = mysql_query(proxy, "SELECT CONNECTION_ID()");
		MYSQL_RES* connection_id_result = connection_id_rc == 0 ? mysql_store_result(proxy) : nullptr;
		MYSQL_ROW connection_id_row = connection_id_result ? mysql_fetch_row(connection_id_result) : nullptr;
		char* parse_end = nullptr;
		const unsigned long long connection_id = connection_id_row && connection_id_row[0]
			? std::strtoull(connection_id_row[0], &parse_end, 10)
			: 0;
		const bool valid_connection_id = connection_id_row && connection_id_row[0]
			&& parse_end && *parse_end == '\0' && connection_id > 0;
		const unsigned long long expected_connection_id =
			static_cast<unsigned long long>(mysql_thread_id(proxy));
		if (connection_id_result) {
			mysql_free_result(connection_id_result);
		}
		ok(
			connection_id_rc == 0 && valid_connection_id && connection_id == expected_connection_id,
			"SELECT CONNECTION_ID() should return this session ID   rc=%d",
			connection_id_rc
		);

		for (const auto& q : set_queries) {
			diag("Executing 'special SET' query   q='%s'", q.c_str());
			int rc = mysql_query(proxy, q.c_str());
			ok(rc == 0, "Query should execute without error   q='%s'", q.c_str());
		}

		mysql_close(proxy);
	}

	return exit_status();
}
