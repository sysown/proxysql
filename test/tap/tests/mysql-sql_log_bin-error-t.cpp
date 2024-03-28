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

int main(int argc, char** argv) {

	plan(2 + 1);

	MYSQL* mysql = mysql_init(NULL);
	diag("Connecting: username='%s' cl.use_ssl=%d cl.compression=%d", "sbtest1", cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
	}

	diag("Running 'SET sql_log_bin=0' for a not privileged user: sbtest1");
	MYSQL_QUERY(mysql, "SET sql_log_bin=0");


	int query_res = mysql_query(mysql, "SELECT 1");
	ok(query_res!=0, "Query \"SELECT 1\" should fail. Error: %s", (query_res == 0 ? "None" : mysql_error(mysql))); 


	mysql_close(mysql);

	return exit_status();
}

