#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <fstream>
#include <sstream>

#include <string>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int select_config_file(MYSQL* mysql, std::string& resultset) {
	if (mysql_query(mysql, "select config file")) {
	    fprintf(stderr, "File %s, line %d, Error: 2 %s\n",
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

	plan(1);
	diag("Testing SELECT CONFIG INTO OUTFILE");

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();
	
	if (!mysql_real_connect(mysql, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}
	
	MYSQL_QUERY(mysql, "delete from global_variables");
	MYSQL_QUERY(mysql, "delete from mysql_users");
	MYSQL_QUERY(mysql, "delete from mysql_servers");
	MYSQL_QUERY(mysql, "delete from mysql_query_rules");
	MYSQL_QUERY(mysql, "delete from mysql_replication_hostgroups");
	MYSQL_QUERY(mysql, "delete from mysql_group_replication_hostgroups");
	MYSQL_QUERY(mysql, "delete from mysql_galera_hostgroups");
	MYSQL_QUERY(mysql, "delete from mysql_aws_aurora_hostgroups");
	MYSQL_QUERY(mysql, "delete from scheduler");
	MYSQL_QUERY(mysql, "delete from proxysql_servers");

	MYSQL_QUERY(mysql, "insert into proxysql_servers (hostname, port, weight, comment) values ('hostname', 3333, 12, 'comment');");
	MYSQL_QUERY(mysql, "insert into scheduler (id, active, interval_ms, filename, arg1, arg2, arg3, arg4, arg5, comment) values "
					   " (1,1,1000,'filename','a1','a2','a3','a4','a5','comment');");
	MYSQL_QUERY(mysql, "insert into mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, aurora_port, "
					   " domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, "
					   " add_lag_ms, min_lag_ms, lag_num_checks, comment) "
					   " values (1,2,1,3,'.domain.net',20,106,107,1,9,10,20,1,'comment');");
	MYSQL_QUERY(mysql, "insert into mysql_galera_hostgroups (writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, "
					   " active, max_writers, writer_is_also_reader, max_transactions_behind, comment) values (1,2,3,4,1,23,1,1,'comment');");
	MYSQL_QUERY(mysql, "insert into mysql_group_replication_hostgroups (writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, "
					   " active, max_writers, writer_is_also_reader, max_transactions_behind, comment) values (1,2,3,4,1,23,1,1,'comment');");
	MYSQL_QUERY(mysql, "insert into mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type, comment) "
					   " values (10,20,'read_only','Master / Slave App 1');");
	MYSQL_QUERY(mysql, "insert into mysql_servers (hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, "
					   " max_replication_lag, use_ssl, max_latency_ms, comment) values (0,'127.0.0.1',3306,0,'ONLINE',1,0,1000,0,0,0,'comment2');");
	MYSQL_QUERY(mysql, "insert into mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, "
					   " match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, "
					   " cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, "
					   " error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) values "
					   " (1, 1, 'user', 'schema', 0, '.domain.com', '.proxy.com', 3333, 'ABC1', 'ABC', '^SELECT *', 0, 'CASE', 0, 1, 1, "
					   " 1, 1, 100, 1, 1, 100, 100, 0, 0, 1, 'Error', 'OK', 0, 0, 0, 0, 0, 'comm1')");
	MYSQL_QUERY(mysql, "insert into mysql_users (username, password, active, use_ssl, default_hostgroup, default_schema, schema_locked, "
					   " transaction_persistent, fast_forward, backend, frontend, max_connections, comment) values "
					   " ('user', 'password', 1, 0, 0, 'schema', 1, 0, 1, 1, 1, 10, 'comm1')");

	MYSQL_QUERY(mysql, "update global_variables set variable_value='admin' where variable_name like 'admin-%'");
	MYSQL_QUERY(mysql, "update global_variables set variable_value='mysql' where variable_name like 'mysql-%'");

	MYSQL_QUERY(mysql, "load mysql servers to runtime");

	std::string resultset;
	resultset.reserve(100000);
	select_config_file(mysql, resultset);

	{
		std::ifstream inFile;
		inFile.open("./tests/proxysql_reference_select_config_file.cnf"); //open the input file

		std::stringstream strStream;
		strStream << inFile.rdbuf(); //read the file
		std::string str = strStream.str(); //str holds the content of the file

		ok(!str.compare(resultset), "Files are equal");
	}

#if 0
	std::ofstream out("output.cnf");
	out << resultset;
	out.close();
#endif

	MYSQL_QUERY(mysql, "load mysql variables from disk");
	MYSQL_QUERY(mysql, "load admin variables from disk");
	MYSQL_QUERY(mysql, "load mysql users from disk");
	MYSQL_QUERY(mysql, "load mysql servers from disk");
	MYSQL_QUERY(mysql, "load scheduler from disk");
	MYSQL_QUERY(mysql, "load proxysql servers from disk");

	mysql_close(mysql);

	return exit_status();
}

