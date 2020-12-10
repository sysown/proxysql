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

const int NUM_ROWS=5;

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

int restore_admin(MYSQL* mysqladmin) {
	MYSQL_QUERY(mysqladmin, "load mysql query rules from disk");
	MYSQL_QUERY(mysqladmin, "load mysql query rules to runtime");
	MYSQL_QUERY(mysqladmin, "load mysql servers from disk");
	MYSQL_QUERY(mysqladmin, "load mysql servers to runtime");
}

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(4);
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
	MYSQL_QUERY(mysql, "create table if not exists test.t (i int)");
	MYSQL_QUERY(mysql, "CREATE TABLE if not exists test.sbtest1 (`id` int(10) unsigned NOT NULL AUTO_INCREMENT, `k` int(10) unsigned NOT NULL DEFAULT '0', `c` char(120) NOT NULL DEFAULT '', `pad` char(60) NOT NULL DEFAULT '',  PRIMARY KEY (`id`), KEY `k_1` (`k`))");

	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<int> dist(0.0, 9.0);

	std::stringstream q;
	q << "INSERT INTO test.sbtest1 (k, c, pad) values ";
	bool put_comma = false;
	for (int i=0; i<NUM_ROWS; ++i) {
		int k = dist(mt);
		std::stringstream c;
		for (int j=0; j<10; j++) {
			for (int k=0; k<11; k++) {
				c << dist(mt);
			}
			if (j<9)
				c << "-";
		}
		std::stringstream pad;
		for (int j=0; j<5; j++) {
			for (int k=0; k<11; k++) {
				pad << dist(mt);
			}
			if (j<4)
				pad << "-";
		}
		if (put_comma) q << ",";
		if (!put_comma) put_comma=true;
		q << "(" << k << ",'" << c.str() << "','" << pad.str() << "')";
	}
	MYSQL_QUERY(mysql, q.str().c_str());
	ok(true, "%d row inserted.", NUM_ROWS);

	std::string query = "";

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

	for (int loops=0; loops<3; loops++) {
	MYSQL_STMT *stmt2a = mysql_stmt_init(mysql);
	if (!stmt2a)
	{
		ok(false, " mysql_stmt_init(), out of memory\n");
		restore_admin(mysqladmin);
		return exit_status();
	}
	query = "SELECT t1.id id1, t2.id id2 FROM test.sbtest1 t1 JOIN test.sbtest1 t2 LIMIT 20";
	if (mysql_stmt_prepare(stmt2a,query.c_str(), query.size())) {
		fprintf(stderr, "Query error %s\n", mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		restore_admin(mysqladmin);
		return exit_status();
	}

	if (mysql_stmt_execute(stmt2a))
	{
		fprintf(stderr, " mysql_stmt_execute(), failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt2a));
		restore_admin(mysqladmin);
		return exit_status();
	}

	#define STRING_SIZE 4096

	MYSQL_BIND bind2a[8];
	my_bool is_null2a[8];
	long unsigned int length2a[8];
	my_bool error2a[8];
	int row_count2a=0;
	memset(bind2a, 0, sizeof(bind2a));

	bind2a[0].buffer_type= MYSQL_TYPE_LONG;
	bind2a[0].buffer= (char *)&int_data1;
	bind2a[0].buffer_length= 8;

	bind2a[1].buffer_type= MYSQL_TYPE_LONG;
	bind2a[1].buffer= (char *)&int_data2;
	bind2a[1].buffer_length= 8;

	MYSQL_RES     * prepare_meta_result = mysql_stmt_result_metadata(stmt2a);
	if (mysql_stmt_bind_result(stmt2a, bind2a))
	{
		fprintf(stderr, " mysql_stmt_bind_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt2a));
		restore_admin(mysqladmin);
		return exit_status();
	}

/*
	// WE INTENTIONALLY SKIP THIS
	if (mysql_stmt_store_result(stmt2a))
	{
		fprintf(stderr, " mysql_stmt_store_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt2a));
		restore_admin(mysqladmin);
		return exit_status();
	}
*/

	int stmt2aRC = 0;
	while (!(stmt2aRC = mysql_stmt_fetch(stmt2a)))
	{
		 fprintf(stderr, "Row %d : %d , %d\n", row_count2a, int_data1, int_data2);
		row_count2a++;
	}
	ok(row_count2a==20, "Fetched %d rows. To fetch 20 rows", row_count2a);

	if (prepare_meta_result) {
		mysql_free_result(prepare_meta_result);
	}
	
	if (mysql_stmt_close(stmt2a))
	{
		fprintf(stderr, " failed while closing the statement\n");
		ok(false, " %s\n", mysql_error(mysql));
		restore_admin(mysqladmin);
		return exit_status();
	}
	}

	restore_admin(mysqladmin);

	mysql_close(mysql);
	mysql_library_end();

	return exit_status();
}

