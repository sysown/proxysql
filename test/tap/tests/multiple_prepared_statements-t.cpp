/*
This test creates a large number of prepared statements in multiple connections.
It stresses how proxysql managers prepared statements, specifically:
* when the same PS is prepared multiple times in the same connection
* when the same PS is prepared in the multiple connections
* behavior when PS are closed
* behavior when connections are closed
* purging of PS cache
*/

#include <algorithm>
#include <cstring>
#include <cmath>
#include <chrono>
#include <climits>
#include <numeric>
#include <memory>
#include <string>
#include <stdio.h>
#include <vector>
#include <tuple>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "command_line.h"
#include "proxysql_utils.h"
#include "tap.h"
//#include "utils.h"

int g_seed = 0;

inline int fastrand() {
	g_seed = (214013*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}

inline unsigned long long monotonic_time() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

#define NCONNS 6
#define NPREP 15000
#define PROGRESS 2000
MYSQL* conns[NCONNS];
int ids[NCONNS*NPREP];
MYSQL_STMT * stmts[NCONNS*NPREP];
MYSQL_BIND bind[NCONNS*NPREP];

int int_data=1;

int get_Stmt_Cached(MYSQL *admin) {
	std::string ret = "";
	const char * query = (const char *)"SELECT Variable_Value FROM stats_mysql_global WHERE variable_name='Stmt_Cached'";
	diag("Running query: %s", query);
	int rc = mysql_query(admin, query);
	ok(rc==0,"Query: %s . Error: %s", query, (rc == 0 ? "None" : mysql_error(admin)));
	if (rc == 0 ) {
		MYSQL_RES* res = mysql_store_result(admin);
		int num_rows = mysql_num_rows(res);
		ok(num_rows==1,"1 row expected when querying Stmt_Cached. Returned: %d", num_rows);
		if (num_rows == 0) {
			diag("Fatal error in line %d: No result", __LINE__);
		} else if (num_rows > 1) {
			diag("Fatal error in line %d: returned rows more than 1: %d", __LINE__, num_rows);
		} else {
			MYSQL_ROW row = nullptr;
			while (( row = mysql_fetch_row(res) )) {
				ret = std::string(row[0]);
			}
		}
		mysql_free_result(res);
	}
	return atoi(ret.c_str());
}

int prepare_stmt(int idx, int i) {
	stmts[idx] = mysql_stmt_init(conns[i]);
	if (stmts[idx] == NULL) {
		diag("Failed initialized stmt %d", idx);
		return EXIT_FAILURE;
	}

	std::string query = "SELECT " + std::to_string(ids[idx]) + " + ?";
	int rc = mysql_stmt_prepare(stmts[idx], query.c_str(), strlen(query.c_str()));
	if (rc) {
		diag("Failed preparing stmt %d", idx);
		return EXIT_FAILURE;
	}
	return 0;
}

int execute_stmt(int idx) {
	int rc;
	bind[idx].buffer_type= MYSQL_TYPE_LONG;
	bind[idx].buffer= (char *)&int_data;
	bind[idx].is_null= 0;
	bind[idx].length= 0;
	rc = mysql_stmt_bind_param(stmts[idx], bind+idx);
	if (rc) {
		diag("Failed binding stmt %d", idx);
		return EXIT_FAILURE;
	}
	rc = mysql_stmt_execute(stmts[idx]);
	if (rc) {
		diag("Failed executing stmt %d", idx);
		return EXIT_FAILURE;
	}
	MYSQL_RES * prepare_meta_result;
	prepare_meta_result = mysql_stmt_result_metadata(stmts[idx]);
	if (rc) {
		diag("Failed storing metadata for stmt %d", idx);
		return EXIT_FAILURE;
	}
	rc = mysql_stmt_store_result(stmts[idx]);
	if (rc) {
		diag("Failed storing result for stmt %d", idx);
		return EXIT_FAILURE;
	}
	mysql_free_result(prepare_meta_result);
	mysql_stmt_free_result(stmts[idx]);
	return 0;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(6);

	MYSQL* proxysql_admin = mysql_init(NULL);
	memset(bind, 0, sizeof(bind));

	diag("Creating connections");
	for (int i=0; i<NCONNS; i++) {
		conns[i] = mysql_init(NULL);
		if (!mysql_real_connect(conns[i], cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conns[i]));
			return EXIT_FAILURE;
		}
	}

	// ceating "random" ids in within a range 0..NPREP
	diag("Creating IDs");
	for (int i=0; i<NCONNS*NPREP; i++) {
		ids[i] = fastrand()%NPREP;
	}
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	diag("Preparing statements");
	for (int i=0; i<NCONNS; i++) {
		for (int j=0; j<NPREP; j++) {
			int idx=i*NPREP+j;
			if (idx%PROGRESS==(PROGRESS-1)) diag("Preparing statements. Progress: %d", idx+1);
			if (prepare_stmt(idx,i)) return EXIT_FAILURE;
			// excute every 7 stmt
			if (idx%7==0) {
				if (execute_stmt(idx)) return EXIT_FAILURE;
			}
		}
	}

	{
		int Stmt_Cached = get_Stmt_Cached(proxysql_admin);
		ok(Stmt_Cached > (NPREP*80/100), "Stmt_Cached should be a value close to %d . Value: %d", NPREP, Stmt_Cached);
	}

	// excute statements in order
	diag("Executing statements in order");
	for (int i=0; i<NCONNS; i++) {
		for (int j=0; j<NPREP; j++) {
			int idx=i*NPREP+j;
			if (idx%PROGRESS==(PROGRESS-1)) diag("Executing statements in order 1. Progress: %d", idx+1);
			if (execute_stmt(idx)) return EXIT_FAILURE;
		}
	}

	// excute statements in different order
	diag("Executing statements in different order");
	int p=0; // we need a new counter because of the out of order
	for (int j=0; j<NPREP; j++) {
		for (int i=0; i<NCONNS; i++) {
			int idx=i*NPREP+j;
			if (p%PROGRESS==(PROGRESS-1)) diag("Executing statements in order 2. Progress: %d", p+1);
			if (execute_stmt(idx)) return EXIT_FAILURE;
			p++;
		}
	}

	// close 1 of 4 prepared statements, execute the rest
	for (int i=0; i<NCONNS*NPREP; i++) {
		if (i%PROGRESS==(PROGRESS-1)) diag("Closing or executing statements, loop 1. Progress: %d", i+1);
		if (i%4==3) {
			int rc = mysql_stmt_close(stmts[i]);
			if (rc) {
				diag("Failed to close stmt %d", i);
				return EXIT_FAILURE;
			}
			stmts[i] = NULL;
		} else {
			if (execute_stmt(i)) return EXIT_FAILURE;
		}
	}

	// close 1 of 4 prepared statements, skip 1 in 4, execute the rest
	for (int i=0; i<NCONNS*NPREP; i++) {
		if (i%PROGRESS==(PROGRESS-1)) diag("Closing or executing statements, loop 2. Progress: %d", i+1);
		if (i%4==3) {
			// skip, already closed
		} else if (i%4==2) {
			int rc = mysql_stmt_close(stmts[i]);
			if (rc) {
				diag("Failed to close stmt %d", i);
				return EXIT_FAILURE;
			}
			stmts[i] = NULL;
		} else {
			if (execute_stmt(i)) return EXIT_FAILURE;
		}
	}

	// close half the connections without closing the prepared statements
	for (int i=0; i<NCONNS; i+=2) {
		diag("Closing connection %d", i);
		mysql_close(conns[i]);
		for (int j=0; j<NPREP; j++) {
			int idx=i*NPREP+j;
			stmts[idx]=NULL;
		}
	}

	// execute and close the prepared statements left, loop 1
	for (int i=0; i<NCONNS*NPREP; i++) {
		if (stmts[i] != NULL) {
			if (i%2==1) {
				if (execute_stmt(i)) return EXIT_FAILURE;
				int rc = mysql_stmt_close(stmts[i]);
				if (rc) {
					diag("Failed to close stmt %d", i);
					return EXIT_FAILURE;
				}
				stmts[i] = NULL;
			}
		}
	}

	// execute and close the prepared statements left, loop 2
	for (int i=0; i<NCONNS*NPREP; i++) {
		if (stmts[i] != NULL) {
			if (i%2==0) {
				if (execute_stmt(i)) return EXIT_FAILURE;
				int rc = mysql_stmt_close(stmts[i]);
				if (rc) {
					diag("Failed to close stmt %d", i);
					return EXIT_FAILURE;
				}
				stmts[i] = NULL;
			}
		}
	}

	// Half of the connections were freed earlier. We only iterate the other
	// half that has not been freed.
	for (int i=1; i<NCONNS; i+=2) {
		mysql_close(conns[i]);
	}

	{
		int Stmt_Cached = get_Stmt_Cached(proxysql_admin);
		ok(Stmt_Cached < 10000, "Stmt_Cached should be less than 10000 . Value: %d", Stmt_Cached);
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
