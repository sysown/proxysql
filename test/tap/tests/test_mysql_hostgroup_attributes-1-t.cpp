#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <vector>
#include <unordered_map>
#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

int run_queries_sets(std::vector<std::string>& queries, MYSQL *my, const std::string& message_prefix) {
	for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
		std::string q = *it;
		diag("%s: %s", message_prefix.c_str(), q.c_str());
		MYSQL_QUERY(my, q.c_str());
	}
	return 0;
}

int check_checksum(MYSQL *mysqladmin, const char *expected_checksum, const char *when) {
	MYSQL_QUERY(mysqladmin, "CHECKSUM MYSQL HOSTGROUP ATTRIBUTES");
	MYSQL_RES* result = mysql_store_result(mysqladmin);
	ok(mysql_num_rows(result) == 1, "Line %d: CHECKSUM returned 1 row" , __LINE__);
	if (mysql_num_rows(result) == 1) {
		MYSQL_ROW row = mysql_fetch_row(result);
		ok(strcmp(row[1],expected_checksum)==0, "Checksum %s: expected: %s, returned: %s", when, expected_checksum, row[1]);
	}
	mysql_free_result(result);
	return 0;
}

int run_one_test(MYSQL *mysqladmin, const char *expected_checksum, const char *query) {
	std::vector<std::string> queries = { "DELETE FROM mysql_hostgroup_attributes" };
	queries.push_back(std::string(query));
	queries.push_back("LOAD MYSQL SERVERS TO RUNTIME");
	if (run_queries_sets(queries, mysqladmin, "Running on Admin"))
		return 1;
	if (check_checksum(mysqladmin,expected_checksum,"before"))
		return 1;
	queries = { "DELETE FROM mysql_hostgroup_attributes", "SAVE MYSQL SERVERS FROM RUNTIME" };
	if (run_queries_sets(queries, mysqladmin, "Running on Admin"))
		return 1;
	if (check_checksum(mysqladmin,expected_checksum,"after"))
		return 1;
	return 0;
}

int main(int argc, char** argv) {

	std::unordered_map<std::string,std::string> queries_and_checksums = {
		{
			"0x666CFBEEDB76EE9C",
			"INSERT INTO mysql_hostgroup_attributes VALUES (19,1,1,10,'',1,1,10000,'','','','')"
		},
		{
			"0xE2FC2A5FEE8D18DC",
			"INSERT INTO mysql_hostgroup_attributes VALUES (19,1,1,10,'',1,1,10000,'','','',''),(18,2,-1,20,'SET sql_mode=\"\"',0,0,100,'','','','hello world')",
		},
		{
			"0xFACE1C64FF1C373E",
			"INSERT INTO mysql_hostgroup_attributes VALUES (19,1,1,10,'',1,1,10000,'','','',''),(18,2,-1,20,'SET sql_mode=\"\"',0,0,100,'','','','hello world'),(17,0,0,30,'SET long_query_time=0',1,0,123,'{\"session_variables\":[\"tmp_table_size\",\"join_buffer_size\"]}','','','filtering variables')"
		},
		{
			"0x161B2F2BB35BA05E",
			"INSERT INTO mysql_hostgroup_attributes VALUES (19,1,1,10,'',1,1,10000,'','','',''),"
				"(18,2,-1,20,'SET sql_mode=\"\"',0,0,100,'','','','hello world'),"
				"(17,0,0,30,'SET long_query_time=0',1,0,123,'{\"session_variables\":[\"tmp_table_size\",\"join_buffer_size\"]}','','','filtering variables'),"
				"(20,3,-1,40,'SET sql_mode=\"\"',1,0,124,'{\"session_variables\":[\"tmp_table_size\",\"join_buffer_size\"]}','','{\"weight\": 100, \"max_connections\": 1000}','servers defaults')"
		},
		{
			"0xF33858C81FDA7372",
			"INSERT INTO mysql_hostgroup_attributes VALUES (19,1,1,10,'',1,1,10000,'','','',''),"
				"(18,2,-1,20,'SET sql_mode=\"\"',0,0,100,'','','','hello world'),"
				"(17,0,0,30,'SET long_query_time=0',1,0,123,'{\"session_variables\":[\"tmp_table_size\",\"join_buffer_size\"]}','','','filtering variables'),"
				"(20,3,-1,40,'SET sql_mode=\"\"',1,0,124,'{\"session_variables\":[\"tmp_table_size\",\"join_buffer_size\"]}','','{\"weight\": 100, \"max_connections\": 1000}','servers defaults'),"
				"(21,2,-1,50,'SET sql_mode=\"\"',1,0,125,'{\"session_variables\":[\"tmp_table_size\",\"join_buffer_size\"]}','{\"handle_warnings\": 1}','{\"weight\": 100, \"max_connections\": 1000}','hostgroup settings')"
		}
	};

	plan(2 + queries_and_checksums.size()*4);
	diag("Testing the loading of mysql_hostgroup_attributes");

	MYSQL* mysqladmin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysqladmin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysqladmin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysqladmin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysqladmin->net.compress, "Compression: (%d)", mysqladmin->net.compress);
	}

	for (std::unordered_map<std::string,std::string>::iterator it = queries_and_checksums.begin(); it != queries_and_checksums.end(); it++) {
		if (run_one_test(mysqladmin, it->first.c_str() , it->second.c_str()) == 1)
			return exit_status();
		auto it2 = it;
		it2++;
		if (it2 != queries_and_checksums.end()) {
			diag("Sleeping 10 seconds because of Cluster");
			sleep(10);
		}
	}
	mysql_close(mysqladmin);

	return exit_status();
}

