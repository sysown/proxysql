#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <vector>
#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

char * username = (char *)"user1459";
char * password = (char *)"pass1459";

std::vector<std::string> queries_set1 = {
	"SET mysql-have_ssl='true'",
	"LOAD MYSQL VARIABLES TO RUNTIME",
	"DELETE FROM mysql_servers WHERE hostgroup_id IN (1458,1459)",
	"INSERT INTO mysql_servers (hostgroup_id, hostname, port, use_ssl) VALUES (1458, '127.0.0.1', 6030, 0),(1459, '127.0.0.1', 6030, 0)",
	"LOAD MYSQL SERVERS TO RUNTIME",
	"DELETE FROM mysql_users WHERE username = 'user1459'",
	"INSERT INTO mysql_users (username,password,default_hostgroup) VALUES ('" + std::string(username) + "','" + std::string(password) + "',0)",
	"LOAD MYSQL USERS TO RUNTIME",
	"DELETE FROM mysql_query_rules",
	"INSERT INTO mysql_query_rules (rule_id,active,username,attributes) VALUES (1,1,'user1459','{\"flagOUTs\":[{\"id\":1,\"weight\":1000},{\"id\":2,\"weight\":3000}]}')",
	"INSERT INTO mysql_query_rules (rule_id,active,flagIN,destination_hostgroup,apply) VALUES (2,1,1,1458,1), (3,1,2,1459,1)",
	"LOAD MYSQL QUERY RULES TO RUNTIME",
	"TRUNCATE TABLE stats_mysql_query_digest"
};

std::vector<std::string> queries_SQL1 = {
	"DROP TABLE IF EXISTS tbl1459",
	"CREATE TABLE tbl1459 (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , t1 VARCHAR)",
};

std::vector<std::string> queries_SQL4 = {
	"DROP TABLE IF EXISTS tbl1459",
	"VACUUM",
};


int run_queries_sets(std::vector<std::string>& queries, MYSQL *my, const std::string& message_prefix) {
	for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
		std::string q = *it;
		diag("%s: %s", message_prefix.c_str(), q.c_str());
		MYSQL_QUERY(my, q.c_str());
	}
	return 0;
}


int main(int argc, char** argv) {

	plan(2+2 + 4);

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

	diag("We will reconfigure ProxySQL to use SQLite3 Server on hostgroup 1458 and 1459, IP 127.0.0.1 and port 6030");
	diag("We will reconfigure query rules to load balance between these 2 hostgroups");
	if (run_queries_sets(queries_set1, mysqladmin, "Running on Admin"))
		return exit_status();

	MYSQL* mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql, cl.host, username, password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
	}


	// We now create a table named tbl1459
	if (run_queries_sets(queries_SQL1, mysql, "Running on SQLite3"))
		return exit_status();

	std::string s0 = "0";
	for (int i=1; i<=2000; i++) {
		std::string s = "INSERT INTO tbl1459 VALUES (" + std::to_string(i) + ",'hello')";
		MYSQL_QUERY(mysql, s.c_str());
	}

	for (int i=0; i<2; i++) {
		diag("Sleeping few seconds so query rules hits can be refreshed");
		sleep(2);
	}

	MYSQL_RES* status_res = NULL;

	std::string query = "SELECT * FROM stats_mysql_query_rules ORDER BY rule_id";
	diag("Running query: %s", query.c_str());
	MYSQL_QUERY(mysqladmin, query.c_str());

	status_res = mysql_store_result(mysqladmin);

	int num_rows = mysql_num_rows(status_res);
	ok(num_rows == 3 , "Num rows: %d", num_rows);
	if (num_rows != 3) {
		diag("Incorrect number of rows, exiting...");
		return exit_status();
	} else {
		uint32_t row_num = 0;
		MYSQL_ROW row = nullptr;
		std::vector<long> hits_vec = {};
		while (( row = mysql_fetch_row(status_res) )) {
			row_num++;
			std::string rule_id_s { row[0] };
			std::string hits_s { row[1] };
			long rule_id = stol(rule_id_s);
			long hits = stol(hits_s);
			if (row_num != rule_id) {
				diag("Error: Incorrect rule_id: %ld", rule_id);
				return exit_status();
			} else if (hits == 0) {
				diag("Error: Incorrect hits for rule_id %ld: %ld", rule_id, hits);
			} else {
				diag("Rule_id %ld was hit %ld times", rule_id, hits);
				hits_vec.push_back(hits);
			}
		}
		ok(hits_vec[0] == (hits_vec[1] + hits_vec[2]), "Total number of hits: %ld", hits_vec[0]); 
	}

	mysql_free_result(status_res);

	query = "SELECT hostgroup, SUM(count_star) FROM stats_mysql_query_digest WHERE hostgroup IN (1458,1459) GROUP BY hostgroup ORDER BY hostgroup";
	diag("Running query: %s", query.c_str());
	MYSQL_QUERY(mysqladmin, query.c_str());

	status_res = mysql_store_result(mysqladmin);

	num_rows = mysql_num_rows(status_res);
	ok(num_rows == 2 , "Num rows: %d", num_rows);
	if (num_rows != 2) {
		diag("Incorrect number of rows, exiting...");
		return exit_status();
	} else {
		uint32_t row_num = 0;
		MYSQL_ROW row = nullptr;
		long counts_vec[2];
		while (( row = mysql_fetch_row(status_res) )) {
			std::string hid_s { row[0] };
			std::string counts_s { row[1] };
			long hid = stol(hid_s);
			long counts = stol(counts_s);
			if ((row_num + 1458) != hid) {
				diag("Error: Incorrect hid: %ld", hid);
				return exit_status();
			} else if (counts == 0) {
				diag("Error: Incorrect counts for hid %ld: %ld", hid, counts);
			} else {
				diag("Hostgroup %ld ran %ld queries", hid, counts);
				counts_vec[row_num]=counts;
			}
			row_num++;
		}
		double total1459 = counts_vec[1];
		double expected_total1459 = counts_vec[0] + counts_vec[1];
		// on hostgroup 1459 we expect 3 times of queries of hostgroup 1458
		expected_total1459 *= 0.75;
		double error_margin_pct = fabs((1 - total1459/expected_total1459)*100);
		ok(error_margin_pct < 10 , "Delta is %f percentage", error_margin_pct);
	}

	mysql_free_result(status_res);



	if (run_queries_sets(queries_SQL4, mysql, "Running on SQLite3"))
		return exit_status();

	mysql_close(mysql);
	mysql_close(mysqladmin);

	return exit_status();
}

