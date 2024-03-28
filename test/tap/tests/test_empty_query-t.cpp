/**
 * @file test_empty_query-t.cpp
 * @brief Simple test checking that empty queries are properly handled by ProxySQL.
 */

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

uint32_t EXECUTIONS = 100;

int main(int argc, char** argv) {

	plan(2 + 1);

	MYSQL* proxy = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxy, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxy);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxy->net.compress, "Compression: (%d)", proxy->net.compress);
	}

	int exp_myerr = 1065;
	int act_myerr = 0;

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
