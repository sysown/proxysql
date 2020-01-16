#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <time.h>
#include <semaphore.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/wait.h>


#include <fstream>
#include <sstream>

#include <string>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"

#define MYSQL_QUERY(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			return exit_status(); \
		} \
	} while(0)


int select_config_file(MYSQL* mysql, std::string& resultset) {
	if (mysql_query(mysql, "select config file")) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);
	if (result) {
		row = mysql_fetch_row(result);
		resultset = row[0];
		mysql_free_result(result);
	} else {
		fprintf(stderr, "error\n");
	}

}

int query_memory(MYSQL* mysql) {
	if (mysql_query(mysql, "select * from stats_memory_metrics")) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	int allocated = 0;
	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);
	while((row = mysql_fetch_row(result))) {
		if (strncmp("jemalloc_allocated", row[0], 18) == 0)
			allocated = atoi(row[1]);
	}
	mysql_free_result(result);

	return allocated;
}

#define STRING_SIZE 120

bool prepared_statement(MYSQL *mysqla, const std::string& query) {
	MYSQL_STMT * stmt = mysql_stmt_init(mysqla);
	if (mysql_stmt_prepare(stmt,query.c_str(), query.size()))
		return false;

	MYSQL_BIND bind1[1];
	int           int_data;
	int           int_data1;
	int           int_data2;
	char 		  str_data1[120];
	char 		  str_data2[120];
	my_bool       is_null[4];
	my_bool       error[4];
	unsigned long length[4];
	int			  row_count;
	memset(bind1, 0, sizeof(bind1));

	int_data = 1;
	/* INTEGER COLUMN */
	bind1[0].buffer_type= MYSQL_TYPE_LONG;
	bind1[0].buffer= (char *)&int_data;
	bind1[0].is_null= &is_null[0];
	bind1[0].length= &length[0];
	bind1[0].error= &error[0];

	if (mysql_stmt_bind_param(stmt, bind1))
		return false;

	if (mysql_stmt_execute(stmt))
		return false;

	/* Bind the result buffers for all columns before fetching them */

	MYSQL_BIND bind[3];
	memset(bind, 0, sizeof(bind));

	/* INTEGER COLUMN */
	bind[0].buffer_type= MYSQL_TYPE_LONG;
	bind[0].buffer= (char *)&int_data1;
	bind[0].is_null= &is_null[0];
	bind[0].length= &length[0];
	bind[0].error= &error[0];

	/* INTEGER COLUMN */
	bind[1].buffer_type= MYSQL_TYPE_LONG;
	bind[1].buffer= (char *)&int_data2;
	bind[1].is_null= &is_null[1];
	bind[1].length= &length[1];
	bind[1].error= &error[1];

	/* STRING COLUMN */
	bind[2].buffer_type= MYSQL_TYPE_STRING;
	bind[2].buffer= (char *)str_data1;
	bind[2].buffer_length= STRING_SIZE;
	bind[2].is_null= &is_null[2];
	bind[2].length= &length[2];
	bind[2].error= &error[2];

	/* Bind the result buffers */
	if (mysql_stmt_bind_result(stmt, bind))
		return false;

	/* Now buffer all results to client (optional step) */
	if (mysql_stmt_store_result(stmt))
		return false;

	/* Fetch all rows */
	row_count= 0;
	while (!mysql_stmt_fetch(stmt)) ;


	/* Close the statement */
	if (mysql_stmt_close(stmt))
		return false;

	return true;
}

int simulate_deadlock(const char* host, const char* username, const char* password, int port ) {

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();
	
	if (!mysql_real_connect(mysql, host, username, password, "test", port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	MYSQL_QUERY(mysql, "INSERT INTO t (i) VALUES(1)");
	MYSQL_QUERY(mysql, "START TRANSACTION");
	MYSQL_QUERY(mysql, "SELECT * FROM t WHERE i = 1 FOR SHARE");

	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);
	if (result) {
		row = mysql_fetch_row(result);
		mysql_free_result(result);
	} else {
		ok(false, "Error getting query results\n");
		return exit_status();
	}

	std::stringstream ss;
	ss << "SELECT " << rand() << ", id, c FROM sbtest1 WHERE id= ?";
	if (!prepared_statement(mysql, ss.str())) {
		ok(false, "Error in prepared statement\n");
		return exit_status();
	}

	sem_t* sp = sem_open("mysync", O_CREAT, S_IRUSR | S_IWUSR, 0);
	if (sp == SEM_FAILED)
		fprintf(stderr, "cannot create semaphor\n");

	auto pid = fork();
	if (pid == 0) {
		MYSQL* mysqla = mysql_init(NULL);
		if (!mysqla)
			return exit_status();

		if (!mysql_real_connect(mysqla, host, username, password, "test", port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n",
					__FILE__, __LINE__, mysql_error(mysql));
			return exit_status();
		}

		std::stringstream ss;
		ss << "SELECT " << rand() << ", id, c FROM sbtest_no_test1 WHERE id= ?";
		prepared_statement(mysqla, ss.str());

		sem_t* sp1 = sem_open("mysync", 0);
		if (sp1 == SEM_FAILED)
			fprintf(stderr, "Error opening sem\n");
		MYSQL_QUERY(mysqla, "START TRANSACTION");
		if (sem_post(sp1))
			fprintf(stderr, "error semaphor post\n");
		if (mysql_query(mysqla, "DELETE FROM t WHERE i = 1")) {
			exit(0);
		}

		sem_close(sp1);
		mysql_close(mysqla);
		exit(0);
	}
	else {

		sem_wait(sp);
		std::stringstream ss;
		ss << "SELECT " << rand() << ", id, c FROM sbtest_no_test1 WHERE id= ?";
		prepared_statement(mysql, ss.str());

		MYSQL_QUERY(mysql, "DELETE FROM t WHERE i = 1");
		sem_unlink("mysync");
		sem_close(sp);
		mysql_close(mysql);

		int status;
		waitpid(pid, &status, 0);
	}
}


int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	srand(time(NULL));

	plan(101);
	diag("Testing prepared statements");

	/* configuring proxysql for testing (setup) */
	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();
	
	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}
	
	MYSQL_QUERY(mysqladmin, "set mysql-max_stmts_per_connection=5");
	MYSQL_QUERY(mysqladmin, "SET mysql-max_stmts_cache=1024");
	MYSQL_QUERY(mysqladmin, "LOAD MYSQL VARIABLES TO RUNTIME");

	/* configuring database for testing (setup) */
	MYSQL* mysql = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	MYSQL_QUERY(mysql, "create database if not exists test");
	MYSQL_QUERY(mysql, "create table if not exists test.t (i int)");
	MYSQL_QUERY(mysql, "CREATE TABLE if not exists test.sbtest1 (`id` int(10) unsigned NOT NULL AUTO_INCREMENT, `k` int(10) unsigned NOT NULL DEFAULT '0', `c` char(120) NOT NULL DEFAULT '', `pad` char(60) NOT NULL DEFAULT '',  PRIMARY KEY (`id`), KEY `k_1` (`k`))");
	mysql_close(mysql);

	auto mem_before = query_memory(mysqladmin);

	/* simulating deadloc */
	for (int i = 0 ; i < 100; i++) {
		simulate_deadlock(cl.host, cl.username, cl.password, cl.port);
		ok(true, "Iteration");
	}

	auto mem_after = query_memory(mysqladmin);
	mysql_close(mysqladmin);

	fprintf(stderr, "mem before %d, me after %d, diff %d\n", mem_before, mem_after, mem_after - mem_before);

	ok(mem_after - mem_before < 500000, "Everything is ok");
	return exit_status();
}

