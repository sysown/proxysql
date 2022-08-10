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

#include <stdlib.h>

int main(int argc, char** argv) {
	CommandLine cl;
	char buf[1024];

	const int STRING_SIZE=32;

	if(cl.getEnv())
		return exit_status();

	plan(1);
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

	MYSQL_QUERY(mysql, "create database if not exists test");
	MYSQL_QUERY(mysql, "drop table if exists test.ps_hg_routing");
	sprintf(buf, "create table if not exists test.ps_hg_routing (c1 varchar(%d) primary key, c2 varchar(%d))", STRING_SIZE, STRING_SIZE);
	MYSQL_QUERY(mysql, buf);
	MYSQL_QUERY(mysql, "insert into test.ps_hg_routing (c1,c2) values ('abcdef', 'abcdef')");

	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='true' where variable_name='mysql-forward_autocommit'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='false' where variable_name='mysql-enforce_autocommit_on_reads'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='true' where variable_name='mysql-autocommit_false_not_reusable'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='true' where variable_name='mysql-autocommit_false_is_transaction'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	MYSQL_QUERY(mysqladmin, "delete from mysql_query_rules");
	{
		char * query_in = "insert into mysql_query_rules (rule_id, active, flagIN, match_digest, negate_match_pattern, re_modifiers, destination_hostgroup, comment, apply) values (100, 1, 0, \"^SELECT.*FOR UPDATE$\", 0, \"CASELESS\", 0, \"\"\"hello\"\" 'world'\", 1)";
		char query_out[1024];
		mysql_real_escape_string(mysqladmin, query_out, query_in, strlen(query_in));
		diag("Running query: %s", query_out);
		MYSQL_QUERY(mysqladmin, query_out);
	}
	MYSQL_QUERY(mysqladmin, "insert into mysql_query_rules (rule_id, active, flagIN, match_digest, negate_match_pattern, re_modifiers, destination_hostgroup, apply) values (200, 1, 0, '^SELECT', 0, 'CASELESS', 2, 1)");
	MYSQL_QUERY(mysqladmin, "load mysql query rules to runtime");
	MYSQL_QUERY(mysqladmin, "save mysql query rules from runtime");
	MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_servers SELECT 2, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostgroup_id=0");
	MYSQL_QUERY(mysqladmin, "LOAD MYSQL SERVERS TO RUNTIME");

	std::string q0 = (const std::string)"mysql -h " + cl.host + (const std::string)" -u " + cl.admin_username + " -p" + cl.admin_password + " -P " + std::to_string(cl.admin_port) + " -t -e ";
	std::string q1 = q0 + "\"SELECT * FROM mysql_servers\"";
	std::string q2 = q0 + "\"SELECT * FROM mysql_query_rules\"";

	system(q1.c_str());
	system(q2.c_str());

	MYSQL_QUERY(mysql, "set autocommit=0");
	MYSQL_STMT *stmt = mysql_stmt_init(mysql);
	if (!stmt)
	{
		ok(false, " mysql_stmt_init(), out of memory\n");
		return exit_status();
	}

	std::string query = "SELECT * FROM test.ps_hg_routing";
	if (mysql_stmt_prepare(stmt, query.c_str(), query.size())) {
		ok(false, "mysql_stmt_prepare at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	}

	MYSQL_QUERY(mysql, "update test.ps_hg_routing set c1='aaaaaa'");

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

	if (mysql_stmt_execute(stmt))
	{
		ok(false, "mysql_stmt_execute at line %d failed: %s\n", __LINE__ , mysql_stmt_error(stmt));
		return exit_status();
	}

	if (mysql_stmt_bind_result(stmt, bind))
	{
		ok(false, "mysql_stmt_bind_result at line %d failed: %s\n", __LINE__ , mysql_stmt_error(stmt));
		return exit_status();
	}

	if (mysql_stmt_store_result(stmt))
	{
		ok(false, "mysql_stmt_store_result at line %d failed: %s\n", __LINE__ , mysql_stmt_error(stmt));
		return exit_status();
	}

	while (!mysql_stmt_fetch(stmt))	{
		ok(strcmp((char*)bind[0].buffer, "aaaaaa") == 0, "Read value that was updated. Expected [aaaaaa]. Actual [%s]", bind[0].buffer);
	}

	if (mysql_stmt_close(stmt))
	{
		ok(false, "mysql_stmt_close at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
		return exit_status();
	}

	MYSQL_QUERY(mysqladmin, "load mysql variables from disk");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	MYSQL_QUERY(mysqladmin, "load mysql query rules from disk");
	MYSQL_QUERY(mysqladmin, "load mysql query rules to runtime");

	MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_servers WHERE hostgroup_id=2");
	MYSQL_QUERY(mysqladmin, "LOAD MYSQL SERVERS TO RUNTIME");

	mysql_close(mysql);
	mysql_close(mysqladmin);
}

