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

std::string queries[4] = {
	"SELECT LAST_INSERT_ID() LIMIT 1",
	"SELECT LAST_INSERT_ID()",
	"SELECT @@IDENTITY LIMIT 1",
	"SELECT @@IDENTITY"
};

inline unsigned long long monotonic_time() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

int main(int argc, char** argv) {

	plan(2 + 8);

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

	if (create_table_test_sbtest1(500,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}
	diag("Waiting few seconds for replication...");
	sleep(2);
	MYSQL_QUERY(mysql, "USE test");
	MYSQL_QUERY(mysql, "INSERT INTO sbtest1 (id) VALUES (NULL)");


	MYSQL_RES *res;
	for (int i=0; i<4; i++) {
		diag("Running query: %s", queries[i].c_str());
		MYSQL_QUERY(mysql, queries[i].c_str());
		res = mysql_store_result(mysql);
		MYSQL_ROW row;
		unsigned long long num_rows = mysql_num_rows(res);
		ok(num_rows == 1, "mysql_num_rows() , expected: 1 , actual: %llu", num_rows);
		while ((row = mysql_fetch_row(res))) {
				ok(strcmp(row[0],"501")==0, "row: expected: \"501\" , actual: \"%s\"", row[0]);
		}	
		mysql_free_result(res);
	}

	mysql_close(mysql);

	return exit_status();
}

