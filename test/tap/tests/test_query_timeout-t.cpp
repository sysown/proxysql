#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

CommandLine cl;

inline unsigned long long monotonic_time() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

int main(int argc, char** argv) {

	plan(2+2 + 1);

	MYSQL* mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
	}

	MYSQL* admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to Admin: Error: %s\n", mysql_error(admin));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == admin->net.compress, "Compression: (%d)", admin->net.compress);
	}

	const string poll_query { "SELECT variable_value FROM global_variables WHERE variable_name='mysql-poll_timeout'" };
	MYSQL_RES* res = nullptr;
	MYSQL_ROW row = nullptr;
	int poll_timeout = 0;

	int q_res = mysql_query(admin, poll_query.c_str());
	if (q_res) {
	    fprintf(stderr, "Query '%s' failed with error '%s'\n", poll_query.c_str(), mysql_error(admin));
		goto cleanup;
	}

	res = mysql_store_result(admin);
	row = mysql_fetch_row(res);

	if (row == nullptr || row[0] == nullptr) {
	    fprintf(stderr, "Query '%s' failed to retrive 'mysql-poll_timeout' value. Empty row received.\n", poll_query.c_str());
		goto cleanup;
	}

	poll_timeout = std::strtol(row[0], NULL, 10);

	{

	const char *q = "SELECT /* query_timeout=3300 */ SLEEP(20)";
	diag("Running query; %s", q);
	unsigned long long begin = monotonic_time();
	MYSQL_QUERY(mysql, q);
	MYSQL_RES * res = mysql_store_result(mysql);
	mysql_free_result(res);
	unsigned long long end = monotonic_time();

	unsigned long time_diff_ms = (end-begin)/1000;
	// NOTE: We give a grace period of 150 extra ms. This value could be much lower.
	unsigned long max_poll_to_ms = (3300 + poll_timeout + 150);

	ok(
		time_diff_ms > 3100 && time_diff_ms < max_poll_to_ms,
		"Query should be interrupted at around 3300ms with a failure timeout at '%lu'ms. Exact time: %lums",
		max_poll_to_ms, time_diff_ms
	);

	}

cleanup:

	mysql_close(admin);
	mysql_close(mysql);

	return exit_status();
}

