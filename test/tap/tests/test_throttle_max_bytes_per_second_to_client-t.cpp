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

CommandLine cl;

inline unsigned long long monotonic_time() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

int main(int argc, char** argv) {

	plan(2+2 + 1);

	MYSQL* mysqladmin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysqladmin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysqladmin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysqladmin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysqladmin->net.compress, "Compression: (%d)", mysqladmin->net.compress);
	}

	diag("Setting mysql-throttle_max_bytes_per_second_to_client=150000");
	diag("Client will read from ProxySQL at no more than 150KB/s");
	MYSQL_QUERY(mysqladmin, "SET mysql-throttle_max_bytes_per_second_to_client=150000");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

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

	MYSQL_RES *res;
	if (create_table_test_sbtest1(100,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}
	diag("Waiting few seconds for replication...");
	sleep(2);
	MYSQL_QUERY(mysql, "USE test");

	const char *q = "SELECT a.*, b.* FROM sbtest1 a JOIN sbtest1 b";
	diag("Running query; %s", q);
	unsigned long long begin = monotonic_time();
	MYSQL_QUERY(mysql, q);
	res = mysql_store_result(mysql);
	mysql_free_result(res);
	unsigned long long end = monotonic_time();

	unsigned long time_diff_ms = (end-begin)/1000;

	if (cl.compression) {
		ok(time_diff_ms>5000, "Total query execution time should be more than 5 seconds : %lums", time_diff_ms);
	} else {
		ok(time_diff_ms>20000, "Total query execution time should be more than 20 seconds : %lums", time_diff_ms);
	}

	MYSQL_QUERY(mysqladmin, "SET mysql-throttle_max_bytes_per_second_to_client=0");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");
	mysql_close(mysql);
	mysql_close(mysqladmin);

	return exit_status();
}

