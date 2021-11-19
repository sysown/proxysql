/**
 * @file reg_test_3603-stmt_metadata-t.cpp
 * @brief This test is a regression test for issue #3603. It performs several
 *   prepared statements using NULL values to check that these values are correctly
 *   preserved/forgotten when new values are received.
 * @details For being able to trigger the issue, the test needs to execute the
 *   statements using 'MYSQL_TYPE_NULL' for supplied 'buffer_types'. Since the
 *   issue consists in the invalid preservation of the 'NULL' values in
 *   subsequent executions of the same prepared stmt. This tests performs two
 *   sequences of actions:
 *
 *   1. Sets all the values to 'NULL' in a particular stmt, for later updating
 *   those values in the subsequent execution of the stmt. If the issue is
 *   present, reported values should be 'NULL' due to the issue.
 *   2. Sets all the values of the same stmt to other values than NULL. Because
 *   of the issue, this stmt needs to be executed twice to if the values were
 *   'nullified' previously. Later executes an statement making this values to
 *   NULL, followed by one with values other than NULL. This creates the
 *   required conditions to provoque a 'heap-buffer-overflow'.
 *
 * @date 2020-09-07
 */

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

int update_and_check(
	MYSQL_STMT *stmti, MYSQL_STMT *stmts, int64_t id, char *cll_num, char *dst_num,
	int64_t* dur, MYSQL_TIME *end_time, char *lst_msg, char *lst_st, int *mapping_id,
	char *prov, char *prov_id, MYSQL_TIME *st_time, char* trck_num
) {
	int rc;
	MYSQL_BIND bindu[13];
	MYSQL_BIND bindsi[1];
	MYSQL_BIND binds[13];
	my_bool is_null_on = 1;

	long unsigned int cll_l = 0;
	long unsigned int dst_l = 0;
	long unsigned int lst_msg_l = 0;
	long unsigned int lst_st_l = 0;
	long unsigned int prov_l = 0;
	long unsigned int prov_id_l = 0;
	long unsigned int trck_num_l = 0;

	int64_t copyid = id;

	memset(bindu, 0, sizeof(bindu));
	memset(bindsi, 0, sizeof(bindsi));
	memset(binds, 0, sizeof(binds));

	bindu[0].buffer_type= MYSQL_TYPE_VAR_STRING;
	bindu[0].buffer= cll_num;
	if (cll_num) {
		cll_l = strlen(cll_num);
		bindu[0].buffer_length= cll_l;
		bindu[0].is_null= 0;
		bindu[0].length= &cll_l;
	} else {
		bindu[0].is_null= &is_null_on;
		bindu[0].buffer_type= MYSQL_TYPE_NULL;
	}

	bindu[1].buffer_type= MYSQL_TYPE_VAR_STRING;
	bindu[1].buffer= dst_num;
	if (dst_num) {
		dst_l = strlen(dst_num);
		bindu[1].buffer_length= dst_l;
		bindu[1].is_null= 0;
		bindu[1].length= &dst_l;
	} else {
		bindu[1].is_null= &is_null_on;
		bindu[1].buffer_type= MYSQL_TYPE_NULL;
	}

	bindu[2].buffer_type= MYSQL_TYPE_LONG;
	bindu[2].buffer= (char *)dur;
	if (dur) {
		bindu[2].is_null= 0;
	} else {
		bindu[2].is_null= &is_null_on;
		bindu[2].buffer_type= MYSQL_TYPE_NULL;
	}
	bindu[2].length= 0;

	bindu[3].buffer_type= MYSQL_TYPE_DATETIME;
	bindu[3].buffer= (char *)end_time;
	if (end_time) {
		bindu[3].is_null= 0;
	} else {
		bindu[3].is_null= &is_null_on;
		bindu[3].buffer_type= MYSQL_TYPE_NULL;
	}
	bindu[3].length= 0;

	bindu[4].buffer_type= MYSQL_TYPE_VAR_STRING;
	bindu[4].buffer= lst_msg;
	if (lst_msg) {
		lst_msg_l = strlen(lst_msg);
		bindu[4].buffer_length= lst_msg_l;
		bindu[4].is_null= 0;
		bindu[4].length= &lst_msg_l;
	} else {
		bindu[4].is_null= &is_null_on;
		bindu[4].buffer_type= MYSQL_TYPE_NULL;
	}

	bindu[5].buffer_type= MYSQL_TYPE_VAR_STRING;
	bindu[5].buffer= lst_st;
	if (lst_st) {
		lst_st_l = strlen(lst_st);
		bindu[5].buffer_length= lst_st_l;
		bindu[5].is_null= 0;
		bindu[5].length= &lst_st_l;
	} else {
		bindu[5].is_null= &is_null_on;
		bindu[5].buffer_type= MYSQL_TYPE_NULL;
	}

	bindu[6].buffer_type= MYSQL_TYPE_LONG;
	bindu[6].buffer= (char *)mapping_id;
	if (mapping_id) {
		bindu[6].is_null= 0;
	} else {
		bindu[6].is_null= &is_null_on;
		bindu[6].buffer_type= MYSQL_TYPE_NULL;
	}
	bindu[6].length= 0;

	bindu[7].buffer_type= MYSQL_TYPE_VAR_STRING;
	bindu[7].buffer= prov;
	if (prov) {
		prov_l = strlen(prov);
		bindu[7].buffer_length= prov_l;
		bindu[7].is_null= 0;
		bindu[7].length= &prov_l;
	} else {
		bindu[7].is_null= &is_null_on;
		bindu[7].buffer_type= MYSQL_TYPE_NULL;
	}

	bindu[8].buffer_type= MYSQL_TYPE_VAR_STRING;
	bindu[8].buffer= prov_id;
	if (prov_id) {
		prov_id_l = strlen(prov_id);
		bindu[8].buffer_length= prov_id_l;
		bindu[8].is_null= 0;
		bindu[8].length= &prov_id_l;
	} else {
		bindu[8].is_null= &is_null_on;
		bindu[8].buffer_type= MYSQL_TYPE_NULL;
	}

	bindu[9].buffer_type= MYSQL_TYPE_DATETIME;
	bindu[9].buffer= (char *)st_time;
	if (st_time) {
		bindu[9].is_null= 0;
	} else {
		bindu[9].is_null= &is_null_on;
		bindu[9].buffer_type= MYSQL_TYPE_NULL;
	}	
	bindu[9].length= 0;

	bindu[10].buffer_type= MYSQL_TYPE_VAR_STRING;
	bindu[10].buffer= trck_num;
	if (trck_num) {
		trck_num_l = strlen(trck_num);
		bindu[10].buffer_length= trck_num_l;
		bindu[10].is_null= 0;
		bindu[10].length= &trck_num_l;
	} else {
		bindu[10].is_null= &is_null_on;
		bindu[10].buffer_type= MYSQL_TYPE_NULL;
	}

	bindu[11].buffer_type= MYSQL_TYPE_LONGLONG;
	bindu[11].buffer= (char *)&copyid;
	if (copyid) {
		bindu[11].is_null= 0;
	} else {
		bindu[11].is_null= &is_null_on;
		bindu[11].buffer_type= MYSQL_TYPE_NULL;
	}
	bindu[11].length= 0;

	rc = mysql_stmt_bind_param(stmti, bindu);
	if (rc) {
		diag("mysql_stmt_bind_param() failed for INSERT with id %ld\n", id);
		return exit_status();
	}

	rc = mysql_stmt_execute(stmti);
	if (rc) {
		diag("mysql_stmt_execute() failed for INSERT with id %ld : %s\n", id, mysql_stmt_error(stmti));
		return exit_status();
	}

	// for SELECT input
	bindsi[0].buffer_type= MYSQL_TYPE_LONG;
	bindsi[0].buffer= (char *)&copyid;
	bindsi[0].is_null= 0;
	bindsi[0].length= 0;

	rc = mysql_stmt_bind_param(stmts, bindsi);
	if (rc) {
		diag("mysql_stmt_bind_param() failed for SELECT with id %ld\n", id);
		return exit_status();
	}

	char cll_buf[256];
	char dst_buf[256];
	char lst_msg_buf[256];
	char lst_st_buf[256];
	char prov_buf[256];
	char prov_id_buf[256];
	char trck_num_buf[256];

	MYSQL_TIME ts_end_time;
	MYSQL_TIME ts_st_time;
	memset(&ts_end_time, 0, sizeof(ts_end_time));
	memset(&ts_st_time, 0, sizeof(ts_st_time));

	unsigned long length[13];
	my_bool is_null[13];
	my_bool error[13];

	memset(&length, 0, sizeof(length));
	memset(&is_null, 0, sizeof(is_null));
	memset(&error, 0, sizeof(error));
	int64_t id_res;
	int i_duration, i_mapping_id, i3_res;

	// for SELECT result
	binds[0].buffer_type= MYSQL_TYPE_LONGLONG;
	binds[0].buffer= (char *)&id_res;
	binds[0].is_null= &is_null[0];
	binds[0].length= &length[0];
	binds[0].error= &error[0];

	binds[1].buffer_type= MYSQL_TYPE_VAR_STRING;
	binds[1].buffer= (char *)cll_buf;
	binds[1].buffer_length= sizeof(cll_buf);
	binds[1].is_null= &is_null[1];
	binds[1].length= &length[1];
	binds[1].error= &error[1];

	binds[2].buffer_type= MYSQL_TYPE_VAR_STRING;
	binds[2].buffer= (char *)dst_buf;
	binds[2].buffer_length= sizeof(dst_buf);
	binds[2].is_null= &is_null[2];
	binds[2].length= &length[2];
	binds[2].error= &error[2];

	binds[3].buffer_type= MYSQL_TYPE_LONG;
	binds[3].buffer= (char *)&i_duration;
	binds[3].is_null= &is_null[3];
	binds[3].length= &length[3];
	binds[3].error= &error[3];

	binds[4].buffer_type= MYSQL_TYPE_DATETIME;
	binds[4].buffer= (char *)&ts_end_time;
	binds[4].is_null= &is_null[4];
	binds[4].length= &length[4];
	binds[4].error= &error[4];

	binds[5].buffer_type= MYSQL_TYPE_VAR_STRING;
	binds[5].buffer= (char *)lst_msg_buf;
	binds[5].buffer_length= sizeof(lst_msg_buf);
	binds[5].is_null= &is_null[5];
	binds[5].length= &length[5];
	binds[5].error= &error[5];

	binds[6].buffer_type= MYSQL_TYPE_VAR_STRING;
	binds[6].buffer= (char *)lst_st_buf;
	binds[6].buffer_length= sizeof(lst_st_buf);
	binds[6].is_null= &is_null[6];
	binds[6].length= &length[6];
	binds[6].error= &error[6];

	binds[7].buffer_type= MYSQL_TYPE_LONG;
	binds[7].buffer= (char *)&i_mapping_id;
	binds[7].is_null= &is_null[7];
	binds[7].length= &length[7];
	binds[7].error= &error[7];

	binds[8].buffer_type= MYSQL_TYPE_VAR_STRING;
	binds[8].buffer= (char *)prov_buf;
	binds[8].buffer_length= sizeof(prov_buf);
	binds[8].is_null= &is_null[8];
	binds[8].length= &length[8];
	binds[8].error= &error[8];

	binds[9].buffer_type= MYSQL_TYPE_VAR_STRING;
	binds[9].buffer= (char *)prov_id_buf;
	binds[9].buffer_length= sizeof(prov_id_buf);
	binds[9].is_null= &is_null[9];
	binds[9].length= &length[9];
	binds[9].error= &error[9];

	binds[10].buffer_type= MYSQL_TYPE_DATETIME;
	binds[10].buffer= (char *)&ts_st_time;
	binds[10].is_null= &is_null[10];
	binds[10].length= &length[10];
	binds[10].error= &error[10];

	binds[11].buffer_type= MYSQL_TYPE_VAR_STRING;
	binds[11].buffer= (char *)trck_num_buf;
	binds[11].buffer_length= sizeof(trck_num_buf);
	binds[11].is_null= &is_null[11];
	binds[11].length= &length[11];
	binds[11].error= &error[11];

	rc = mysql_stmt_execute(stmts);
	if (rc) {
		diag("mysql_stmt_execute() failed for SELECT with id %ld : %s", id, mysql_stmt_error(stmts));
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
		char buf1[256], buf2[256];

		diag("id expected/retrieved: %ld , %ld", copyid, is_null[0] ? 0 : id_res);
		if (copyid == (is_null[0] ? 0 : id_res))
			matches++;
		{
			diag("'call_num' expected/retrieved: %s , %s", cll_num ? cll_num : "NULL" , is_null[1] ? "NULL" : (char *)binds[1].buffer);
			if (cll_num == NULL && is_null[1]) {
				matches++;
			} else {
				if (cll_num && !is_null[1] && strcmp(cll_num,(char *)binds[1].buffer)==0)
				matches++;
			}
		}

		{
			diag("'dst_num' expected/retrieved: %s , %s", dst_num ? dst_num : "NULL" , is_null[2] ? "NULL" : (char *)binds[2].buffer);
			if (dst_num == NULL && is_null[2]) {
				matches++;
			} else {
				if (dst_num && !is_null[2] && strcmp(dst_num,(char *)binds[2].buffer)==0)
				matches++;
			}
		}

		{
			sprintf(buf1,"NULL");
			sprintf(buf2,"NULL");

			if (dur)
				sprintf(buf1, "%ld", *dur);
			if (!is_null[3])
				sprintf(buf2, "%d", i_duration);
			diag("'duration' expected/retrieved: %s , %s", buf1, buf2);
			if (strcmp(buf1,buf2)==0)
				matches++;
		}

		{
			if (end_time) {
				sprintf(buf1,"%d:%d:%d", end_time->hour, end_time->minute, end_time->second);
			} else {
				sprintf(buf1,"NULL");
			}
			if (is_null[4]) {
				sprintf(buf2,"NULL");
			} else {
				sprintf(buf2,"%d:%d:%d", ts_end_time.hour, ts_end_time.minute, ts_end_time.second);
			}
			if (strcmp(buf1,buf2)==0)
				matches++;
			diag("'end_time' expected/retrieved: %s , %s", buf1, buf2);
			sprintf(buf1,"NULL");
			sprintf(buf2,"NULL");
		}

		{
			diag("'last_msg' expected/retrieved: %s , %s", lst_msg ? lst_msg : "NULL" , is_null[5] ? "NULL" : (char *)binds[5].buffer);
			if (lst_msg == NULL && is_null[5]) {
				matches++;
			} else {
				if (lst_msg && !is_null[5] && strcmp(lst_msg,(char *)binds[5].buffer)==0)
				matches++;
			}
		}

		{
			diag("'last_st' expected/retrieved: %s , %s", lst_st ? lst_st : "NULL" , is_null[6] ? "NULL" : (char *)binds[6].buffer);
			if (lst_st == NULL && is_null[6]) {
				matches++;
			} else {
				if (lst_st && !is_null[6] && strcmp(lst_st,(char *)binds[6].buffer)==0)
				matches++;
			}
		}

		{
			sprintf(buf1,"NULL");
			sprintf(buf2,"NULL");

			if (mapping_id)
				sprintf(buf1, "%d", *mapping_id);
			if (!is_null[7])
				sprintf(buf2, "%d", i_mapping_id);
			diag("'mapping_id' expected/retrieved: %s , %s", buf1, buf2);
			if (strcmp(buf1,buf2)==0)
				matches++;
		}

		{
			diag("'prov' expected/retrieved: %s , %s", prov ? prov : "NULL" , is_null[8] ? "NULL" : (char *)binds[8].buffer);
			if (prov == NULL && is_null[8]) {
				matches++;
			} else {
				if (prov && !is_null[8] && strcmp(prov,(char *)binds[8].buffer)==0)
				matches++;
			}
		}

		{
			diag("'prov_id' expected/retrieved: %s , %s", prov_id ? prov_id : "NULL" , is_null[9] ? "NULL" : (char *)binds[9].buffer);
			if (prov_id == NULL && is_null[9]) {
				matches++;
			} else {
				if (prov_id && !is_null[9] && strcmp(prov_id,(char *)binds[9].buffer)==0)
				matches++;
			}
		}

		{
			if (st_time) {
				sprintf(buf1,"%d:%d:%d", st_time->hour, st_time->minute, st_time->second);
			} else {
				sprintf(buf1,"NULL");
			}
			if (is_null[10]) {
				sprintf(buf2,"NULL");
			} else {
				sprintf(buf2,"%d:%d:%d", ts_st_time.hour, ts_st_time.minute, ts_st_time.second);
			}
			if (strcmp(buf1,buf2)==0)
				matches++;
			diag("'st_time' expected/retrieved: %s , %s", buf1, buf2);
			sprintf(buf1,"NULL");
			sprintf(buf2,"NULL");
		}

		{
			diag("'trck_num' expected/retrieved: %s , %s", trck_num ? trck_num : "NULL" , is_null[11] ? "NULL" : (char *)binds[11].buffer);
			if (trck_num == NULL && is_null[11]) {
				matches++;
			} else {
				if (trck_num && !is_null[11] && strcmp(trck_num,(char *)binds[11].buffer)==0)
				matches++;
			}
		}

		ok(matches == 12, "Matching columns for ID %ld/%ld: %d (expected 12)\n", id, copyid, matches);
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
	np += 5*2; // number of INSERT+SELECT
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

	MYSQL_QUERY(proxysql_mysql, "DROP TABLE IF EXISTS test.reg_test_3603");
	MYSQL_QUERY(
		proxysql_mysql,
		"CREATE TABLE IF NOT EXISTS test.reg_test_3603 ("
			" `id` bigint(20) NOT NULL, `cll_num` varchar(255) DEFAULT NULL, `dst_num` varchar(255) DEFAULT NULL,"
			" `dur` INT DEFAULT NULL, `end_time` DATETIME DEFAULT NULL, `lst_msg` varchar(255) DEFAULT NULL,"
			" `last_status` varchar(255) DEFAULT NULL, `mapping_id` INT DEFAULT NULL, `prov` varchar(255) DEFAULT NULL,"
			" `prov_id` varchar(255) DEFAULT NULL, `start_time` DATETIME DEFAULT NULL, `trck_num` varchar(255) DEFAULT NULL, "
			"  PRIMARY KEY (id)) ENGINE=InnoDB"
	);
	MYSQL_QUERY(proxysql_mysql, "INSERT INTO test.reg_test_3603 (id) VALUES (14822133)");

	int rc;
	std::string query_u =
			"update test.reg_test_3603 set cll_num=?,dst_num=?,dur=?,"
			"end_time=?,lst_msg=?,last_status=?,mapping_id=?,prov=?,prov_id=?,"
			"start_time=?,trck_num=? where id=?";

	// Force the 'hostgroup' for the 'SELECT' query to avoid replication issues
	std::string query_s = "SELECT /* ;hostgroup=0 */ * FROM test.reg_test_3603 WHERE id=?";

	// init and prepare INSERT
	MYSQL_STMT *stmti = mysql_stmt_init(proxysql_mysql);
	ok(stmti != NULL, "mysql_stmt_init() %s",  stmti != NULL ? "succeeded" : "failed");
	if (!stmti) {
		return exit_status();
	}
	rc = mysql_stmt_prepare(stmti, query_u.c_str(), strlen(query_u.c_str()));
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
	MYSQL_TIME end_time;
	MYSQL_TIME st_time;
	int64_t i_duration=254;
	int i_mapping_id=558;

	memset(&end_time, 0, sizeof(end_time));
	memset(&st_time, 0, sizeof(st_time));
	end_time.time_type=MYSQL_TIMESTAMP_TIME;
	end_time.year= 2000; end_time.month= 10; end_time.day= 20;
	end_time.hour = 4; end_time.minute = 14; end_time.second=24; end_time.second_part= 10;
	st_time.year= 2000; st_time.month= 10; st_time.day= 20;
	st_time.hour = 10; st_time.minute = 20; st_time.second=30; st_time.second_part= 10;

	// This two operations should fail due to preservation of NULL values
	// ========================================================================
	update_and_check(
		stmti, stmts, 14822133, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL
	);
	update_and_check(
		stmti, stmts, 14822133, (char*)"123456789123", (char*)"123456789123", &i_duration, &end_time,
		NULL, (char*)"END", &i_mapping_id, (char*)"T",
		(char*)"CAb3f8fb2e3010f60b1d5dbcdfeb10e84d", &st_time, (char*)"912938481238"
	);
	// ========================================================================

	// This three operations should fail ending in a heap-buffer-overflow
	// ========================================================================
	update_and_check(
		stmti, stmts, 14822133, (char*)"123456789123", (char*)"123456789123", &i_duration, &end_time,
		NULL, (char*)"END", &i_mapping_id, (char*)"T",
		(char*)"DBc3g6fm7P8383F61b1bbb82878788e849", &st_time, (char*)"912938481238"
	);
	update_and_check(
		stmti, stmts, 14822133, (char*)"123456789123", NULL, NULL, NULL,
		(char*)"aalñjk1982371927831jlasñdjfalsñdfj", (char*)"END", &i_mapping_id, (char*)"T",
		(char*)"DBc3g6fm7P8383F61b1bbb82878788e849", &st_time, (char*)"912938481238"
	);
	update_and_check(
		stmti, stmts, 14822133, (char*)"123456789123", (char*)"123456789123", &i_duration, &end_time,
		NULL, (char*)"END", &i_mapping_id, (char*)"T",
		(char*)"DBc3g6fm7P8383F61b1bbb82878788e849", &st_time, (char*)"912938481238"
	);
	// ========================================================================

	mysql_close(proxysql_mysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
