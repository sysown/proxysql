#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <time.h>
#include <iostream>

#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

const int STRING_SIZE=32;

int g_seed = 0;

inline int fastrand() {
	g_seed = (214013*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}

void gen_random_str(char *s, const int len) {
	g_seed = time(NULL) ^ getpid() ^ pthread_self();
	static const char alphanum[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[fastrand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

int insert_and_check(MYSQL_STMT *stmti, MYSQL_STMT *stmts, int id, char *name1, MYSQL_TIME *ts1, int *i1, char *name2, MYSQL_TIME *ts2, int *i2) {
	int rc;
	MYSQL_BIND bindi[7];
	MYSQL_BIND bindsi[1];
	MYSQL_BIND binds[7];
	my_bool is_null_on = 1;
	long unsigned int name1l = 0;
	long unsigned int name2l = 0;
	memset(bindi, 0, sizeof(bindi));
	memset(bindsi, 0, sizeof(bindsi));
	memset(binds, 0, sizeof(binds));

	int copyid = id;
	// for INSERT
	bindi[0].buffer_type= MYSQL_TYPE_LONG;
	bindi[0].buffer= (char *)&copyid;
	bindi[0].is_null= 0;
	bindi[0].length= 0;

	bindi[1].buffer_type= MYSQL_TYPE_STRING;
	bindi[1].buffer= name1;
	if (name1) {
		name1l = strlen(name1);
		bindi[1].buffer_length= name1l;
		bindi[1].is_null= 0;
		bindi[1].length= &name1l;
	} else {
		bindi[1].is_null= &is_null_on;
	}

	bindi[2].buffer_type= MYSQL_TYPE_TIME;
	bindi[2].buffer= (char *)ts1;
	if (ts1) {
		bindi[2].is_null= 0;
	} else {
		bindi[2].is_null= &is_null_on;
	}	
	bindi[2].length= 0;

	bindi[3].buffer_type= MYSQL_TYPE_LONG;
	bindi[3].buffer= (char *)i1;
	if (i1) {
		bindi[3].is_null= 0;
	} else {
		bindi[3].is_null= &is_null_on;
	}
	bindi[3].length= 0;

	bindi[4].buffer_type= MYSQL_TYPE_STRING;
	bindi[4].buffer= name2;
	if (name2) {
		name2l = strlen(name2);
		bindi[4].buffer_length= name2l;
		bindi[4].is_null= 0;
		bindi[4].length= &name2l;
	} else {
		bindi[4].is_null= &is_null_on;
	}

	bindi[5].buffer_type= MYSQL_TYPE_TIME;
	bindi[5].buffer= (char *)ts2;
	if (ts2) {
		bindi[5].is_null= 0;
	} else {
		bindi[5].is_null= &is_null_on;
	}	
	bindi[5].length= 0;
	
	bindi[6].buffer_type= MYSQL_TYPE_LONG;
	bindi[6].buffer= (char *)i2;
	if (i2) {
		bindi[6].is_null= 0;
	} else {
		bindi[6].is_null= &is_null_on;
	}
	bindi[6].length= 0;

	rc = mysql_stmt_bind_param(stmti, bindi);
	if (rc) {
		diag("mysql_stmt_bind_param() failed for INSERT with id %d\n", id);
		return exit_status();	
	}

	rc = mysql_stmt_execute(stmti);
	if (rc) {
		diag("mysql_stmt_execute() failed for INSERT with id %d : %s\n", id, mysql_stmt_error(stmti));
		return exit_status();	
	}

	copyid+=100;
	rc = mysql_stmt_execute(stmti);
	if (rc) {
		diag("mysql_stmt_execute() failed for INSERT with id %d : %s\n", id, mysql_stmt_error(stmti));
		return exit_status();	
	}

	// for SELECT input
	bindsi[0].buffer_type= MYSQL_TYPE_LONG;
	bindsi[0].buffer= (char *)&copyid;
	bindsi[0].is_null= 0;
	bindsi[0].length= 0;

	rc = mysql_stmt_bind_param(stmts, bindsi);
	if (rc) {
		diag("mysql_stmt_bind_param() failed for SELECT with id %d\n", id);
		return exit_status();	
	}
	char namebuf1[256];
	char namebuf2[256];
	MYSQL_TIME ts_res1;
	MYSQL_TIME ts_res2;
	memset(&ts_res1, 0, sizeof(ts_res1));
	memset(&ts_res2, 0, sizeof(ts_res2));
	unsigned long length[7];
	my_bool is_null[7];
	my_bool error[7];
	memset(&length, 0, sizeof(length));
	memset(&is_null, 0, sizeof(is_null));
	memset(&error, 0, sizeof(error));
	int id_res, i1_res, i2_res;

	// for SELECT result
	binds[0].buffer_type= MYSQL_TYPE_LONG;
	binds[0].buffer= (char *)&id_res;
	binds[0].is_null= &is_null[0];
	binds[0].length= &length[0];
	binds[0].error= &error[0];

	binds[1].buffer_type= MYSQL_TYPE_STRING;
	binds[1].buffer= (char *)namebuf1;
	binds[1].buffer_length= sizeof(namebuf1);
	binds[1].is_null= &is_null[1];
	binds[1].length= &length[1];
	binds[1].error= &error[1];

	binds[2].buffer_type= MYSQL_TYPE_TIME;
	binds[2].buffer= (char *)&ts_res1;
	binds[2].is_null= &is_null[2];
	binds[2].length= &length[2];
	binds[2].error= &error[2];

	binds[3].buffer_type= MYSQL_TYPE_LONG;
	binds[3].buffer= (char *)&i1_res;
	binds[3].is_null= &is_null[3];
	binds[3].length= &length[3];
	binds[3].error= &error[3];

	binds[4].buffer_type= MYSQL_TYPE_STRING;
	binds[4].buffer= (char *)namebuf2;
	binds[4].buffer_length= sizeof(namebuf2);
	binds[4].is_null= &is_null[4];
	binds[4].length= &length[4];
	binds[4].error= &error[4];

	binds[5].buffer_type= MYSQL_TYPE_TIME;
	binds[5].buffer= (char *)&ts_res2;
	binds[5].is_null= &is_null[5];
	binds[5].length= &length[5];
	binds[5].error= &error[5];

	binds[6].buffer_type= MYSQL_TYPE_LONG;
	binds[6].buffer= (char *)&i2_res;
	binds[6].is_null= &is_null[6];
	binds[6].length= &length[6];
	binds[6].error= &error[6];

	rc = mysql_stmt_execute(stmts);
	if (rc) {
		diag("mysql_stmt_execute() failed for SELECT with id %d : %s", id, mysql_stmt_error(stmts));
		return exit_status();
	}

	rc = mysql_stmt_bind_result(stmts, binds);
	if (rc) {
  		diag("mysql_stmt_bind_result() failed: %s", mysql_stmt_error(stmts));
		return exit_status();	
	}
	MYSQL_RES *prepare_meta_result;
	prepare_meta_result = mysql_stmt_result_metadata(stmts);
	if (prepare_meta_result == NULL) {
 		diag("mysql_stmt_result_metadata() failed: %s", mysql_stmt_error(stmts));
		return exit_status();	
	}

	rc = mysql_stmt_store_result(stmts);
	if (rc) {
  		diag("mysql_stmt_store_result() failed: %s", mysql_stmt_error(stmts));
		return exit_status();	
	}

	unsigned long long rows_count= mysql_stmt_num_rows(stmts);
	ok(rows_count == 1 , "Rows expected: 1 , retrieved: %llu", rows_count);
	if (rows_count != 1) {
		return 1;
	}
	rc = mysql_stmt_fetch(stmts);
	if (rc) {
  		diag("mysql_stmt_fetch() failed: %d %s", rc , mysql_stmt_error(stmts));
	} else {
		int matches = 0;
		diag("id expected/retrieved: %d , %d", copyid, is_null[0] ? 0 : id_res);
		if (copyid == (is_null[0] ? 0 : id_res))
			matches++;
		diag("name1 expected/retrieved: %s , %s", name1 ? name1 : "NULL" , is_null[1] ? "NULL" : (char *)binds[1].buffer);
		if (name1 == NULL && is_null[1]) {
			matches++;
		} else {
			if (name1 && !is_null[1] && strcmp(name1,(char *)binds[1].buffer)==0)
			matches++;
		}
		char buf1[256], buf2[256];
		if (ts1) {
			sprintf(buf1,"%d:%d:%d", ts1->hour, ts1->minute, ts1->second);
		} else {
			sprintf(buf1,"NULL");
		}
		if (is_null[2]) {
			sprintf(buf2,"NULL");
		} else {
			sprintf(buf2,"%d:%d:%d", ts_res1.hour, ts_res1.minute, ts_res1.second);
		}
		if (strcmp(buf1,buf2)==0)
			matches++;
		diag("time1 expected/retrieved: %s , %s", buf1, buf2);
		sprintf(buf1,"NULL");
		sprintf(buf2,"NULL");
		if (i1)
			sprintf(buf1, "%d", *i1);
		if (!is_null[3])
			sprintf(buf2, "%d", i1_res);
		diag("i1 expected/retrieved: %s , %s", buf1, buf2);
		if (strcmp(buf1,buf2)==0)
			matches++;
		diag("name2 expected/retrieved: %s , %s", name2 ? name2 : "NULL" , is_null[4] ? "NULL" : (char *)binds[4].buffer);
		if (name2 == NULL && is_null[4]) {
			matches++;
		} else {
			if (name2 && !is_null[4] && strcmp(name2,(char *)binds[4].buffer)==0)
			matches++;
		}
		if (ts2) {
			sprintf(buf1,"%d:%d:%d", ts2->hour, ts2->minute, ts2->second);
		} else {
			sprintf(buf1,"NULL");
		}
		if (is_null[5]) {
			sprintf(buf2,"NULL");
		} else {
			sprintf(buf2,"%d:%d:%d", ts_res2.hour, ts_res2.minute, ts_res2.second);
		}
		if (strcmp(buf1,buf2)==0)
			matches++;
		diag("time2 expected/retrieved: %s , %s", buf1, buf2);
		sprintf(buf1,"NULL");
		sprintf(buf2,"NULL");
		if (i2)
			sprintf(buf1, "%d", *i2);
		if (!is_null[6])
			sprintf(buf2, "%d", i2_res);
		diag("i2 expected/retrieved: %s , %s", buf1, buf2);
		if (strcmp(buf1,buf2)==0)
			matches++;
		ok(matches == 7, "Matching columns for ID %d/%d: %d (expected 7)\n", id, copyid, matches);
		mysql_stmt_free_result(stmts);
		mysql_free_result(prepare_meta_result);
	}
	return 0;

}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	int np = 4; // init + prepare
	np += 25*2; // number of INSERT+SELECT
	plan(np);

	MYSQL* proxysql_mysql = mysql_init(NULL);
	if (!proxysql_mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return exit_status();
	}

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return exit_status();
	}

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	MYSQL_QUERY(proxysql_mysql, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(proxysql_mysql, "DROP TABLE IF EXISTS test.reg_test_3585");
	MYSQL_QUERY(proxysql_mysql, "CREATE TABLE IF NOT EXISTS test.reg_test_3585 (`id` int(11) NOT NULL, `name1` varchar(255) DEFAULT NULL, `time1` time DEFAULT NULL, i1 INT DEFAULT NULL, `name2` varchar(255) DEFAULT NULL, `time2` time DEFAULT NULL, i2 INT DEFAULT NULL, PRIMARY KEY (id)) ENGINE=InnoDB");


	int rc;
	std::string query_i = "INSERT INTO test.reg_test_3585 VALUES (? , ? , ? , ? , ? , ? , ?)";
	// Force the 'hostgroup' for the 'SELECT' query to avoid replication issues
	std::string query_s = "SELECT /* ;hostgroup=0 */ * FROM test.reg_test_3585 WHERE id=?";

	// init and prepare INSERT
	MYSQL_STMT *stmti = mysql_stmt_init(proxysql_mysql);
	ok(stmti != NULL, "mysql_stmt_init() %s",  stmti != NULL ? "succeeded" : "failed");
	if (!stmti) {
		return exit_status();
	}
	rc = mysql_stmt_prepare(stmti, query_i.c_str(), strlen(query_i.c_str()));
	ok(rc==0, "mysql_stmt_prepare() for INSERT %s%s" , rc == 0 ? "succeeded" : "failed: " , rc == 0 ? "" : mysql_error(proxysql_mysql));
	if (rc) {
		return exit_status();
	}
	

	// init and prepare SELECT
	MYSQL_STMT *stmts = mysql_stmt_init(proxysql_mysql);
	ok(stmts != NULL, "mysql_stmt_init() %s",  stmts != NULL ? "succeeded" : "failed");
	if (!stmts) {
		return exit_status();
	}
	rc = mysql_stmt_prepare(stmts, query_s.c_str(), strlen(query_s.c_str()));
	ok(rc==0, "mysql_stmt_prepare() for SELECT %s%s" , rc == 0 ? "succeeded" : "failed: " , rc == 0 ? "" : mysql_error(proxysql_mysql));
	if (rc) {
		return exit_status();
	}

	diag("%s","");
	MYSQL_TIME ts1;
	MYSQL_TIME ts2;
	int i1, i2;
	memset(&ts1, 0, sizeof(ts1));
	memset(&ts2, 0, sizeof(ts2));
	ts1.time_type=MYSQL_TIMESTAMP_TIME;
	ts1.hour = 4; ts1.minute = 14; ts1.second=24;
	ts2.hour = 10; ts2.minute = 20; ts2.second=30;
	insert_and_check(stmti, stmts, 1, (char *)"hello1", NULL, NULL, (char *)"world1", NULL, NULL);
	i1 = 12; i2 = 33;
	insert_and_check(stmti, stmts, 2, (char *)"hello2", &ts1, &i1,  (char *)"world2", NULL, NULL);
	insert_and_check(stmti, stmts, 3, NULL,             &ts1, NULL, (char *)"world3", NULL, &i2);
	i1 = 42; i2 = 53;
	insert_and_check(stmti, stmts, 4, NULL,             &ts1, &i1,  NULL,             NULL, NULL);
	insert_and_check(stmti, stmts, 5, NULL,             &ts1, NULL, NULL,             &ts2, &i2);
	insert_and_check(stmti, stmts, 6, NULL,             NULL, NULL, NULL,             &ts2, NULL);
	insert_and_check(stmti, stmts, 7, (char *)"hello7", NULL, NULL, NULL,             &ts2, NULL);
	insert_and_check(stmti, stmts, 8, (char *)"hello8", NULL, &i1,  NULL,             NULL, &i2);
	insert_and_check(stmti, stmts, 9, NULL,             NULL, NULL, (char *)"world9", NULL, &i2);
	i1 = 17; i2 = 192;
	ts1.hour = 1; ts1.minute = 2; ts1.second=3;
	ts2.hour = 11; ts2.minute = 21; ts2.second=31;
	insert_and_check(stmti, stmts, 10, NULL,              &ts1, NULL, (char *)"world10", &ts2, NULL);
	insert_and_check(stmti, stmts, 11, (char *)"hello11", NULL, NULL, (char *)"world11", &ts2, NULL);
	insert_and_check(stmti, stmts, 12, (char *)"hello12", NULL, &i1,  NULL,              NULL, &i2);
	insert_and_check(stmti, stmts, 13, NULL,              NULL, NULL, (char *)"world13", &ts2, &i2);
	i1 = 24; i2 = 47;
	ts1.hour = 7; ts1.minute = 10; ts1.second=15;
	ts2.hour = 9; ts2.minute = 16; ts2.second=41;
	insert_and_check(stmti, stmts, 14, NULL,              NULL, &i1, (char *)"world14", &ts2, NULL);
	insert_and_check(stmti, stmts, 15, (char *)"hello15", NULL, &i1, (char *)"world15", &ts2, NULL);
	insert_and_check(stmti, stmts, 16, NULL,              NULL, &i1, (char *)"world16", &ts2, &i2);
	insert_and_check(stmti, stmts, 17, (char *)"hello17", NULL, &i1, (char *)"world17", &ts2, &i2);
	i1 = 123; i2 = 456;
	insert_and_check(stmti, stmts, 18, NULL,              NULL, NULL, NULL,             NULL, NULL);
	insert_and_check(stmti, stmts, 19, NULL,              NULL, NULL, NULL,             NULL, &i2);
	insert_and_check(stmti, stmts, 20, NULL,              NULL, &i1,  NULL,             NULL, &i2);
	insert_and_check(stmti, stmts, 21, NULL,              &ts1, &i1,  NULL,             NULL, &i2);
	ts1.hour = 0; ts1.minute = 0; ts1.second=0;
	ts2.hour = 0; ts2.minute = 0; ts2.second=0;
	insert_and_check(stmti, stmts, 22, NULL,              &ts1, NULL, (char *)"world22", &ts2, NULL);
	insert_and_check(stmti, stmts, 23, (char *)"hello23", NULL, NULL, (char *)"world23", &ts2, NULL);
	insert_and_check(stmti, stmts, 24, (char *)"hello24", NULL, &i1,  NULL,              NULL, &i2);
	insert_and_check(stmti, stmts, 25, NULL,              NULL, NULL, (char *)"world25", &ts2, &i2);
	mysql_close(proxysql_mysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
