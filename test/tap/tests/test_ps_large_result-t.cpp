#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <random>

#include <fstream>
#include <sstream>

#include <string>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

const int NUM_ROWS=10000;

int restore_admin(MYSQL* mysqladmin) {
	MYSQL_QUERY(mysqladmin, "load mysql query rules from disk");
	MYSQL_QUERY(mysqladmin, "load mysql query rules to runtime");
	MYSQL_QUERY(mysqladmin, "load mysql servers from disk");
	MYSQL_QUERY(mysqladmin, "load mysql servers to runtime");

	return 0;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(9);
	diag("Testing PS large resultset");

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();
	
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	MYSQL_QUERY(mysqladmin, "delete from mysql_query_rules");
	MYSQL_QUERY(mysqladmin, "load mysql query rules to runtime");

	MYSQL_QUERY(mysqladmin, "delete from mysql_servers where hostgroup_id=1");
	MYSQL_QUERY(mysqladmin, "load mysql servers to runtime");

	MYSQL_QUERY(mysql, "drop database if exists test");
	MYSQL_QUERY(mysql, "create database if not exists test");

	if (create_table_test_sbtest1(NUM_ROWS,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}

	MYSQL_QUERY(mysql, "create table if not exists test.t (i int)");

	MYSQL_STMT *stmt1 = mysql_stmt_init(mysql);
	if (!stmt1)
	{
		ok(false, " mysql_stmt_init(), out of memory\n");
		return restore_admin(mysqladmin);
	}

	std::string query = "SELECT id FROM test.sbtest1 LIMIT 100";
	if (mysql_stmt_prepare(stmt1,query.c_str(), query.size())) {
		fprintf(stderr, "Query error %s\n", mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return restore_admin(mysqladmin);
	}

	if (mysql_stmt_execute(stmt1))
	{
		fprintf(stderr, " mysql_stmt_execute(), failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt1));
		return restore_admin(mysqladmin);
	}
	ok(true, "100 rows result stored");

	MYSQL_BIND bind1[1];
	int int_data0;
	my_bool is_null1[1];
	long unsigned int length1[1];
	my_bool error1[1];
	int row_count1=0;
	memset(bind1, 0, sizeof(bind1));

	bind1[0].buffer_type= MYSQL_TYPE_LONG;
	bind1[0].buffer= (char *)&int_data0;
	bind1[0].is_null= &is_null1[0];
	bind1[0].length= &length1[0];
	bind1[0].error= &error1[0];

	if (mysql_stmt_bind_result(stmt1, bind1))
	{
		fprintf(stderr, " mysql_stmt_bind_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt1));
		return restore_admin(mysqladmin);
	}

	if (mysql_stmt_store_result(stmt1))
	{
		fprintf(stderr, " mysql_stmt_store_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt1));
		return restore_admin(mysqladmin);
	}

	while (!mysql_stmt_fetch(stmt1))
	{
		row_count1++;
	}
	ok(row_count1==100, "Fetched 100 rows");
	if (mysql_stmt_close(stmt1))
	{
		fprintf(stderr, " failed while closing the statement\n");
		ok(false, " %s\n", mysql_error(mysql));
		return restore_admin(mysqladmin);
	}

	MYSQL_STMT *stmt2 = mysql_stmt_init(mysql);
	if (!stmt2)
	{
		ok(false, " mysql_stmt_init(), out of memory\n");
		return restore_admin(mysqladmin);
	}
	query = "SELECT t1.id id1, t1.k k1, t1.c c1, t1.pad pad1, t2.id id2, t2.k k2, t2.c c2, t2.pad pad2 FROM test.sbtest1 t1 JOIN test.sbtest1 t2 LIMIT 10000000";
	if (mysql_stmt_prepare(stmt2,query.c_str(), query.size())) {
		fprintf(stderr, "Query error %s\n", mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return restore_admin(mysqladmin);
	}
	if (mysql_stmt_execute(stmt2))
	{
		fprintf(stderr, " mysql_stmt_execute(), failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt2));
		return restore_admin(mysqladmin);
	}
	ok(true, "4GB resultset stored");

	#define STRING_SIZE 4096

	MYSQL_BIND bind2[8];
	int int_data1;
	int int_data2;
	int int_data3;
	int int_data4;
	char str_data1[STRING_SIZE];
	char str_data2[STRING_SIZE];
	char str_data3[STRING_SIZE];
	char str_data4[STRING_SIZE];
	my_bool is_null2[8];
	long unsigned int length2[8];
	my_bool error2[8];
	int row_count2=0;
	memset(bind2, 0, sizeof(bind2));

	bind2[0].buffer_type= MYSQL_TYPE_LONG;
	bind2[0].buffer= (char *)&int_data1;
	bind2[0].is_null= &is_null2[0];
	bind2[0].length= &length2[0];
	bind2[0].error= &error2[0];

	bind2[1].buffer_type= MYSQL_TYPE_LONG;
	bind2[1].buffer= (char *)&int_data2;
	bind2[1].is_null= &is_null2[1];
	bind2[1].length= &length2[1];
	bind2[1].error= &error2[1];

	bind2[2].buffer_type= MYSQL_TYPE_STRING;
	bind2[2].buffer= (char *)&str_data1;
	bind2[2].buffer_length= STRING_SIZE;
	bind2[2].is_null= &is_null2[2];
	bind2[2].length= &length2[2];
	bind2[2].error= &error2[2];

	bind2[3].buffer_type= MYSQL_TYPE_STRING;
	bind2[3].buffer= (char *)&str_data2;
	bind2[3].buffer_length= STRING_SIZE;
	bind2[3].is_null= &is_null2[3];
	bind2[3].length= &length2[3];
	bind2[3].error= &error2[3];

	bind2[4].buffer_type= MYSQL_TYPE_LONG;
	bind2[4].buffer= (char *)&int_data3;
	bind2[4].is_null= &is_null2[4];
	bind2[4].length= &length2[4];
	bind2[4].error= &error2[4];

	bind2[5].buffer_type= MYSQL_TYPE_LONG;
	bind2[5].buffer= (char *)&int_data4;
	bind2[5].is_null= &is_null2[5];
	bind2[5].length= &length2[5];
	bind2[5].error= &error2[5];

	bind2[6].buffer_type= MYSQL_TYPE_STRING;
	bind2[6].buffer= (char *)&str_data3;
	bind2[6].buffer_length= STRING_SIZE;
	bind2[6].is_null= &is_null2[6];
	bind2[6].length= &length2[6];
	bind2[6].error= &error2[6];

	bind2[7].buffer_type= MYSQL_TYPE_STRING;
	bind2[7].buffer= (char *)&str_data4;
	bind2[7].buffer_length= STRING_SIZE;
	bind2[7].is_null= &is_null2[7];
	bind2[7].length= &length2[7];
	bind2[7].error= &error2[7];

	if (mysql_stmt_bind_result(stmt2, bind2))
	{
		fprintf(stderr, " mysql_stmt_bind_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt2));
		return restore_admin(mysqladmin);
	}

	if (mysql_stmt_store_result(stmt2))
	{
		fprintf(stderr, " mysql_stmt_store_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt2));
		return restore_admin(mysqladmin);
	}

	while (!mysql_stmt_fetch(stmt2))
	{
		row_count2++;
	}
	ok(row_count2==10000000, "Fetched 10000000 rows");
	ok(true, "Fetched 4GB");

	
	if (mysql_stmt_close(stmt2))
	{
		fprintf(stderr, " failed while closing the statement\n");
		ok(false, " %s\n", mysql_error(mysql));
		return restore_admin(mysqladmin);
	}


	/* Prepare a SELECT query to fetch data from test_table */
	MYSQL_STMT *stmt3 = mysql_stmt_init(mysql);
	if (!stmt3)
	{
		ok(false, " mysql_stmt_init(), out of memory\n");
		return restore_admin(mysqladmin);
	}

	/* Test case #3. */
	#define LARGE_STRING_SIZE 30000000 
	std::string query1 = "SELECT id, k, REPEAT(c,100+ROUND(RAND()*200000)) cc FROM test.sbtest1 LIMIT 10";
	if (mysql_stmt_prepare(stmt3, query1.c_str(), query1.size())) {
		fprintf(stderr, "Query error %s\n", mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return restore_admin(mysqladmin);
	}

	/* Execute the SELECT query */
	if (mysql_stmt_execute(stmt3))
	{
		fprintf(stderr, " mysql_stmt_execute(), failed\n");
		fprintf(stderr, " %s\n", mysql_stmt_error(stmt3));
		exit(0);
	}
	ok(true, "16MB row query is executed");

	MYSQL_BIND bind3[3];
	int int_data31;
	int int_data32;
	char* str_data31 = (char*)malloc(LARGE_STRING_SIZE);

	my_bool is_null3[3];
	long unsigned int length3[3];
	my_bool error3[3];
	int row_count3=0;
	memset(bind3, 0, sizeof(bind3));

	char* str_data32 = (char*)malloc(LARGE_STRING_SIZE);
	if (!str_data32)
		fprintf(stderr, "MEMORY ERROR\n");

	/* INTEGER COLUMN */
	bind3[0].buffer_type= MYSQL_TYPE_LONG;
	bind3[0].buffer= (char *)&int_data31;
	bind3[0].is_null= &is_null3[0];
	bind3[0].length= &length3[0];
	bind3[0].error= &error3[0];

	bind3[1].buffer_type= MYSQL_TYPE_LONG;
	bind3[1].buffer= (char *)&int_data32;
	bind3[1].is_null= &is_null3[1];
	bind3[1].length= &length3[1];
	bind3[1].error= &error3[1];

	bind3[2].buffer_type= MYSQL_TYPE_STRING;
	bind3[2].buffer= (char *)str_data32;
	bind3[2].buffer_length= LARGE_STRING_SIZE;
	bind3[2].is_null= &is_null3[2];
	bind3[2].length= &length3[2];
	bind3[2].error= &error3[2];

	/* Bind the result buffers */
	if (mysql_stmt_bind_result(stmt3, bind3))
	{
		fprintf(stderr, " mysql_stmt_bind_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt3));
		exit(0);
	}
	ok(true, "16MB result binded");

	/* Now buffer all results to client (optional step) */
	if (mysql_stmt_store_result(stmt3))
	{
		fprintf(stderr, " mysql_stmt_store_re/ult() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt3));
		exit(0);
	}
	ok(true, "16MB result stored");

	int status;

	while (1)
	{
		status = mysql_stmt_fetch(stmt3);

		if (status == 1 || status == MYSQL_NO_DATA) {
			break;
		}
		if (status == MYSQL_DATA_TRUNCATED)
			ok(false, "Data truncated\n");
		row_count3++;

		/* handle current row here */
	}

	ok(row_count3==10, "Fetched 10 rows. Some of them are 16MB long");

	/* Close the statement */
	if (mysql_stmt_close(stmt3))
	{
		fprintf(stderr, " failed while closing the statement\n");
		ok(false, " %s\n", mysql_error(mysql));
		return restore_admin(mysqladmin);
	}

	if (str_data31)
		free(str_data31);

	if (str_data32)
		free(str_data32);

	return restore_admin(mysqladmin);

	mysql_close(mysql);
	mysql_library_end();

	return exit_status();
}

