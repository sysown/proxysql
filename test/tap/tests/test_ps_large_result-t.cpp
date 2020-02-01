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


int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(9);
	diag("Testing SELECT CONFIG FILE");

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();
	
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

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
	ok(true, "%d row inserted", NUM_ROWS);

	/* Test case #1. */
	if (mysql_query(mysql, "SELECT id FROM test.sbtest1 LIMIT 100")) {
		fprintf(stderr, "Query error %s\n", mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	}
	MYSQL_RES* result = mysql_store_result(mysql);
	ok(true, "100 rows result stored");

	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result)))
	{
		unsigned long *lengths;
		lengths = mysql_fetch_lengths(result);
	}
	mysql_free_result(result);
	ok(true, "Fetched 100 rows");

	/* Test case #2. */
	if (mysql_query(mysql, "SELECT t1.id id1, t1.k k1, t1.c c1, t1.pad pad1, t2.id id2, t2.k k2, t2.c c2, t2.pad pad2 FROM test.sbtest1 t1 JOIN test.sbtest1 t2 LIMIT 10000000")) {
		fprintf(stderr, "Query error %s\n", mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	}
	result = mysql_store_result(mysql);
	ok(true, "4GB Result stored");

	int num_rows = mysql_num_rows(result);
	ok(num_rows==10000000, "Fetch 10000000 rows");

	while ((row = mysql_fetch_row(result)))
	{
		unsigned long *lengths;
		lengths = mysql_fetch_lengths(result);
	}
	mysql_free_result(result);
	ok(true, "Fetched 4GB");

	/* Test case #3. */
	if (mysql_query(mysql, "SELECT id, k, REPEAT(c,100+ROUND(RAND()*200000)) FROM test.sbtest1 LIMIT 10")) {
		fprintf(stderr, "Query error %s\n", mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	}
	result = mysql_store_result(mysql);
	ok(true, "4GB Result stored");

	num_rows = mysql_num_rows(result);
	ok(num_rows==10, "Fetch 10 rows");

	while ((row = mysql_fetch_row(result)))
	{
		unsigned long *lengths;
		lengths = mysql_fetch_lengths(result);
	}
	mysql_free_result(result);
	ok(true, "Fetched large rows");
	mysql_close(mysql);
	mysql_library_end();

	return exit_status();
}

