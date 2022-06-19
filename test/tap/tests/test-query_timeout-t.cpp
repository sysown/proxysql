#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

inline unsigned long long monotonic_time() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}


int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(1);

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}

	const char *q = "SELECT /* query_timeout=3300 */ SLEEP(10)";
	diag("Running query; %s", q);
	unsigned long long begin = monotonic_time();
	MYSQL_QUERY(mysql, q);
	MYSQL_RES * res = mysql_store_result(mysql);
	mysql_free_result(res);
	unsigned long long end = monotonic_time();

	unsigned long time_diff_ms = (end-begin)/1000;

	ok(time_diff_ms>3100 && time_diff_ms<3500 , "Query should be interrupted at around 3300ms . Exact time: %llums", time_diff_ms);

	mysql_close(mysql);

	return exit_status();
}

