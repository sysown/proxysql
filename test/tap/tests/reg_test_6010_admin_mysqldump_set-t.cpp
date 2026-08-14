#include <cstdlib>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

static long long count_timeout_rows(MYSQL* admin) {
	const char* query =
		"SELECT COUNT(*) FROM global_variables "
		"WHERE variable_name IN ('net_read_timeout', 'net_write_timeout')";
	if (mysql_query_t(admin, query) != 0) return -1;
	MYSQL_RES* result = mysql_store_result(admin);
	MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
	const long long count = row ? atoll(row[0]) : -1;
	if (result) mysql_free_result(result);
	return count;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port,
		cl.admin_username, cl.admin_password, false, false);
	if (!admin) return EXIT_FAILURE;

	plan(5);
	const long long before = count_timeout_rows(admin);
	ok(before == 0, "timeout variables are not Admin global variables before SET");

	const int dump_set_rc = mysql_query_t(admin,
		"SET SESSION NET_READ_TIMEOUT=86400, SESSION NET_WRITE_TIMEOUT=86400");
	ok(dump_set_rc == 0, "mysqldump timeout SET succeeds");

	const long long after = count_timeout_rows(admin);
	ok(after == before, "mysqldump timeout SET has no persistent Admin side effect");

	const int single_set_rc = mysql_query_t(admin,
		"SET SESSION net_read_timeout=86400");
	ok(single_set_rc == 0, "a scoped ignored timeout SET succeeds alone");

	const int unknown_set_rc = mysql_query_t(admin,
		"SET SESSION issue_6010_unknown_variable=1");
	ok(unknown_set_rc != 0, "unknown scoped SET remains an error");

	mysql_close(admin);
	return exit_status();
}
