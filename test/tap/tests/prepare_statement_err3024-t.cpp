#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

const int NUM_EXECUTIONS = 5;

std::string select_query[3] = {
	"SELECT /*+ MAX_EXECUTION_TIME(10) */ COUNT(*) FROM test.sbtest1 a JOIN test.sbtest1 b WHERE (a.id+b.id)%2" ,
	"SELECT COUNT(*) FROM (SELECT a.* FROM test.sbtest1 a JOIN test.sbtest1 b WHERE (a.id+b.id)%2 LIMIT 1000) t" ,
	"SELECT a.* FROM test.sbtest1 a JOIN test.sbtest1 b WHERE (a.id+b.id)%2 LIMIT 10000"
};

int main(int argc, char** argv) {
	CommandLine cl;

	plan(3+NUM_EXECUTIONS*3); // 3 prepare + 3*execution

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (create_table_test_sbtest1(1000,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}

	MYSQL_STMT* stmt[3];
	for (int i=0; i<3; i++) {
		// Initialize and prepare the statement
		stmt[i]= mysql_stmt_init(mysql);
		if (!stmt[i]) {
			diag("mysql_stmt_init(), out of memory\n");
			return exit_status();
		}
		if (mysql_stmt_prepare(stmt[i], select_query[i].c_str(), strlen(select_query[i].c_str()))) {
			diag("select_query: %s", select_query[i].c_str());
			ok(false, "mysql_stmt_prepare at line %d failed: %s", __LINE__ , mysql_error(mysql));
			mysql_close(mysql);
			mysql_library_end();
			return exit_status();
		} else {
			ok(true, "Prepare succeeded: %s", select_query[i].c_str());
		}
	}
	int rc = 0;

	for (int j = 0; j < NUM_EXECUTIONS; j++) {
		for (int i=0; i<3; i++) {
			// we run 3 queries:
			// the 1st should fail
			// the others should succeed
			diag("Executing: %s", select_query[i].c_str());
			rc = mysql_stmt_execute(stmt[i]);
			if (i==0) { // this should fail
				unsigned int sterrno = mysql_stmt_errno(stmt[i]); // we expect error 3024
				ok(rc==1 && sterrno==3024, "mysql_stmt_execute at line %d should fail with code 3024. Received code: %u, error: %s", __LINE__ , sterrno, mysql_stmt_error(stmt[i]));
			} else {
				ok(rc==0, "mysql_stmt_execute should succeed");
			}
			rc = mysql_stmt_store_result(stmt[i]);
			mysql_stmt_free_result(stmt[i]);
		}
	}
	for (int i=0; i<3; i++) {
		if (mysql_stmt_close(stmt[i])) {
			ok(false, "mysql_stmt_close at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
		}
	}
	mysql_close(mysql);

	return exit_status();
}
