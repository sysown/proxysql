#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;
	char buf[1024];

	const int STRING_SIZE=32;

	if(cl.getEnv())
		return exit_status();

	plan(10);
	diag("Testing PS host groups routing");

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
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}

	MYSQL_QUERY(mysql, "drop database if exists test");
	MYSQL_QUERY(mysql, "create database if not exists test");
	sprintf(buf, "create table if not exists test.test1 (c1 varchar(%d) primary key, c2 varchar(%d))", STRING_SIZE, STRING_SIZE);
	MYSQL_QUERY(mysql, buf);
	MYSQL_QUERY(mysql, "insert into test.test1 (c1,c2) values ('abcdef', 'abcdef')");

	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='true' where variable_name='mysql-forward_autocommit'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='false' where variable_name='mysql-enforce_autocommit_on_reads'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='true' where variable_name='mysql-autocommit_false_not_reusable'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='true' where variable_name='mysql-autocommit_false_is_transaction'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	MYSQL_QUERY(mysqladmin, "delete from mysql_query_rules");
	MYSQL_QUERY(mysqladmin, "insert into mysql_query_rules (rule_id, active, flagIN, match_digest, negate_match_pattern, re_modifiers, destination_hostgroup, apply) values (100, 1, 0, '^SELECT.*FOR UPDATE$', 0, 'CASELESS', 0, 1)");
	MYSQL_QUERY(mysqladmin, "insert into mysql_query_rules (rule_id, active, flagIN, match_digest, negate_match_pattern, re_modifiers, destination_hostgroup, apply) values (200, 1, 0, '^SELECT', 0, 'CASELESS', 1, 1)");
	MYSQL_QUERY(mysqladmin, "load mysql query rules to runtime");

	MYSQL_QUERY(mysql, "set autocommit=0");
	MYSQL_STMT *stmt = mysql_stmt_init(mysql);
	if (!stmt)
	{
		ok(false, " mysql_stmt_init(), out of memory\n");
		return exit_status();
	}

	std::string query = "SELECT * FROM test.test1";
	if (mysql_stmt_prepare(stmt, query.c_str(), query.size())) {
		fprintf(stderr, "Query error %s\n", mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	}
	ok(true, "Statement prepared");

	if (mysql_stmt_execute(stmt))
	{
		fprintf(stderr, " mysql_stmt_execute(), failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt));
		return exit_status();
	}
	ok(true, "Statement executed");

	MYSQL_BIND bind[2];
	char char_data0[STRING_SIZE];
	char char_data1[STRING_SIZE];
	my_bool is_null[2];
	long unsigned int length[2];
	my_bool error[2];
	memset(bind, 0, sizeof(bind));

	bind[0].buffer_type= MYSQL_TYPE_STRING;
	bind[0].buffer= (char *)&char_data0;
	bind[0].buffer_length= STRING_SIZE;
	bind[0].is_null= &is_null[0];
	bind[0].length= &length[0];
	bind[0].error= &error[0];

	bind[1].buffer_type= MYSQL_TYPE_STRING;
	bind[1].buffer= (char *)&char_data1;
	bind[1].buffer_length= STRING_SIZE;
	bind[1].is_null= &is_null[1];
	bind[1].length= &length[1];
	bind[1].error= &error[1];

	if (mysql_stmt_bind_result(stmt, bind))
	{
		fprintf(stderr, " mysql_stmt_bind_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt));
		return exit_status();
	}

	if (mysql_stmt_store_result(stmt))
	{
		fprintf(stderr, " mysql_stmt_store_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt));
		return exit_status();
	}
	ok(true, "Result stored");

	while (!mysql_stmt_fetch(stmt))	{
		ok(strcmp((char*)bind[0].buffer, "abcdef") == 0 &&  strcmp((char*)bind[1].buffer, "abcdef") == 0, "Data received");
	}
	ok(true, "Result fetched");

	MYSQL_QUERY(mysql, "update test.test1 set c1='aaaaaa'");

	ok(true, "Record is updated");

	if (mysql_stmt_execute(stmt))
	{
		fprintf(stderr, " mysql_stmt_execute(), failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt));
		return exit_status();
	}

	ok(true, "Statement executed second time");

	bind[0].buffer_type= MYSQL_TYPE_STRING;
	bind[0].buffer= (char *)&char_data0;
	bind[0].buffer_length= STRING_SIZE;
	bind[0].is_null= &is_null[0];
	bind[0].length= &length[0];
	bind[0].error= &error[0];

	bind[1].buffer_type= MYSQL_TYPE_STRING;
	bind[1].buffer= (char *)&char_data1;
	bind[1].buffer_length= STRING_SIZE;
	bind[1].is_null= &is_null[1];
	bind[1].length= &length[1];
	bind[1].error= &error[1];

	if (mysql_stmt_bind_result(stmt, bind))
	{
		fprintf(stderr, " mysql_stmt_bind_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt));
		return exit_status();
	}

	if (mysql_stmt_store_result(stmt))
	{
		fprintf(stderr, " mysql_stmt_store_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt));
		return exit_status();
	}
	ok(true, "Result stored");

	while (!mysql_stmt_fetch(stmt))	{
		ok(strcmp((char*)bind[0].buffer, "aaaaaa") == 0, "Read value that was updated. Expected [aaaaaa]. Actual [%s]", bind[0].buffer);
	}
	ok(true, "Result fetched");

	if (mysql_stmt_close(stmt))
	{
		fprintf(stderr, " failed while closing the statement\n");
		ok(false, " %s\n", mysql_error(mysql));
		return exit_status();
	}

	MYSQL_QUERY(mysqladmin, "load mysql variables from disk");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	MYSQL_QUERY(mysqladmin, "load mysql query rules from disk");
	MYSQL_QUERY(mysqladmin, "load mysql query rules to runtime");

	mysql_close(mysql);
	mysql_close(mysqladmin);
}

