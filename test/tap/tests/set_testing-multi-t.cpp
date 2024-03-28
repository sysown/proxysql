#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "mysql.h"
#include <string.h>
#include <string>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sstream>
#include <iostream>
#include <fstream>
#include <mutex>

#include "json.hpp"
#include "re2/re2.h"
#include "re2/regexp.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"


CommandLine cl;

std::string bn = "";
int queries_per_connections = 1;
unsigned int num_threads = 1;
int count=0;
//char *username = NULL;
//char *password = NULL;
//char *host = (char *)"localhost";
//int port = 3306;
int multiport = 1;
char *schema = (char *)"information_schema";
int silent = 0;
int sysbench = 0;
//int local = 0;
int queries = 0;
int uniquequeries = 0;
int histograms = -1;
int multi_users = 0;

bool is_mariadb = false;
bool is_cluster = false;
unsigned int g_connect_OK = 0;
unsigned int g_connect_ERR = 0;
unsigned int g_select_OK = 0;
unsigned int g_select_ERR = 0;

unsigned int g_passed = 0;
unsigned int g_failed = 0;

unsigned int status_connections = 0;
unsigned int connect_phase_completed = 0;
unsigned int query_phase_completed = 0;

__thread int g_seed;
std::mutex mtx_;
std::vector<std::string> forgotten_vars {};

#include "set_testing.h"

void * my_conn_thread(void *arg) {
	g_seed = time(NULL) ^ getpid() ^ pthread_self();
	unsigned int select_OK = 0;
	unsigned int select_ERR = 0;
	int i, j;
	MYSQL **mysqlconns=(MYSQL **)malloc(sizeof(MYSQL *)*count);
	std::vector<json> varsperconn(count);

	if (mysqlconns==NULL) {
		exit(EXIT_FAILURE);
	}

	std::vector<std::string> cs = {"latin1", "utf8", "utf8mb4", "latin2", "latin7"};

	for (i=0; i<count; i++) {

		std::string nextcs = cs[i%cs.size()];

		MYSQL *mysql = mysql_init(NULL);
		mysql_options(mysql, MYSQL_SET_CHARSET_NAME, nextcs.c_str());
		if (cl.use_ssl)
			mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
		if (cl.compression)
			mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
		MYSQL *rc = NULL;
		if (multi_users == 0) {
			diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
			rc = mysql_real_connect(mysql, cl.host, cl.username, cl.password, schema, cl.port + rand()%multiport, NULL, 0);
		} else {
			int i = (rand()%multi_users) + 1;
			std::string u = "sbtest" + std::to_string(i);
			std::string p = "sbtest" + std::to_string(i);
			diag("Connecting: username='%s' cl.use_ssl=%d cl.compression=%d", u.c_str(), cl.use_ssl, cl.compression);
			rc = mysql_real_connect(mysql, cl.host, u.c_str(), p.c_str(), schema, cl.port + rand()%multiport, NULL, 0);
		}
		if (rc == NULL) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			exit(EXIT_FAILURE);
		} else {
			const char * c = mysql_get_ssl_cipher(mysql);
			ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
			ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
		}

		mysqlconns[i] = mysql;
		__sync_add_and_fetch(&status_connections,1);
	}
	__sync_fetch_and_add(&connect_phase_completed,1);

	while(__sync_fetch_and_add(&connect_phase_completed,0) != num_threads) {
	}
	MYSQL *mysql = NULL;
	json vars;
	std::string paddress = "";
	for (j=0; j<queries; j++) {
		int fr = fastrand();
		int r1=fr%count;
		int r2=rand()%testCases.size();

		if (j%queries_per_connections==0) {
			mysql=mysqlconns[r1];
			vars = varsperconn[r1];
		}
		if (multi_users || strcmp(cl.username,(char *)"root")) {
			if (strstr(testCases[r2].command.c_str(),"database")) {
				std::lock_guard<std::mutex> lock(mtx_);
				skip(1, "mysql connection [%p], command [%s]", mysql, testCases[r2].command.c_str());
				continue;
			}
			if (strstr(testCases[r2].command.c_str(),"sql_log_bin")) {
				std::lock_guard<std::mutex> lock(mtx_);
				skip(1, "mysql connection [%p], command [%s]", mysql, testCases[r2].command.c_str());
				continue;
			}
		}
		std::vector<std::string> commands = split(testCases[r2].command.c_str(), ';');
		for (auto c : commands) {
			if (multi_users) {
				if (c == " ") {
					c = "DO 1";
				}
			}
			if (mysql_query(mysql, c.c_str())) {
				if (silent==0) {
					fprintf(stderr,"ERROR while running -- \"%s\" :  (%d) %s\n", c.c_str(), mysql_errno(mysql), mysql_error(mysql));
				}
			} else {
				MYSQL_RES *result = mysql_store_result(mysql);
				mysql_free_result(result);
				select_OK++;
				__sync_fetch_and_add(&g_select_OK,1);
			}
		}

		for (auto& el : testCases[r2].expected_vars.items()) {
			if (el.key() == "transaction_isolation") {
				if (is_mariadb) {
					vars["tx_isolation"] = el.value();
				}
				else {
					vars[el.key()] = el.value();
				}
			}
			else if (el.key() == "session_track_gtids") {
				if (!is_mariadb) {
					vars[el.key()] = el.value();
				}
			}
			else if (el.key() == "wsrep_sync_wait") {
				if (is_cluster) {
					vars[el.key()] = el.value();
				}
			}
			else if (el.key() == "transaction_read_only") {
				if (is_mariadb) {
					vars["tx_read_only"] = el.value();
				} else {
					vars[el.key()] = el.value();
				}
			} else if (el.key() == "max_execution_time") {
				if (is_mariadb) {
					vars["max_statement_time"] = el.value();
				} else {
					vars[el.key()] = el.value();
				}
			}
			else {
				vars[el.key()] = el.value();
			}
		}

		int sleepDelay = fastrand()%100;
		usleep(sleepDelay * 1000);

		char query[128];
		sprintf(query, "SELECT /* %p */ %d;", mysql, sleepDelay);
		if (mysql_query(mysql,query)) {
			select_ERR++;
			__sync_fetch_and_add(&g_select_ERR,1);
		} else {
			MYSQL_RES *result = mysql_store_result(mysql);
			mysql_free_result(result);
			select_OK++;
			__sync_fetch_and_add(&g_select_OK,1);
		}

		json mysql_vars;
		queryVariables(mysql, mysql_vars, paddress);

		json proxysql_vars;
		queryInternalStatus(mysql, proxysql_vars, paddress);

		if (!testCases[r2].reset_vars.empty()) {
			for (const auto& var : testCases[r2].reset_vars) {
				if (std::find(forgotten_vars.begin(), forgotten_vars.end(), var) == forgotten_vars.end()) {
					forgotten_vars.push_back(var);
				}
			}
		}

		bool testPassed = true;
		int variables_tested = 0;
		for (auto& el : vars.items()) {
			auto k = mysql_vars.find(el.key());
			auto s = proxysql_vars["conn"].find(el.key());

			if (std::find(forgotten_vars.begin(), forgotten_vars.end(), el.key()) != forgotten_vars.end()) {
				continue;
			}

			if (k == mysql_vars.end())
				fprintf(stderr, "Variable %s->%s in mysql resultset was not found.\nmysql data : %s\nproxysql data: %s\ncsv data %s\n",
						el.value().dump().c_str(), el.key().c_str(), mysql_vars.dump().c_str(), proxysql_vars.dump().c_str(), vars.dump().c_str());

			if (s == proxysql_vars["conn"].end())
				fprintf(stderr, "Variable %s->%s in proxysql resultset was not found.\nmysql data : %s\nproxysql data: %s\ncsv data %s\n",
						el.value().dump().c_str(), el.key().c_str(), mysql_vars.dump().c_str(), proxysql_vars.dump().c_str(), vars.dump().c_str());

			bool verified_special_sqlmode = false;
			bool special_sqlmode = false;

			if (el.key() == "sql_mode") {
				if (!el.value().is_string()) {
					diag("Invalid value for 'sql_mode' found. Provided value should be of 'string' type");
					exit(EXIT_FAILURE);
				}

				std::string str_val { el.value() };

				re2::RE2::Options options(RE2::Quiet);
				options.set_case_sensitive(false);
				options.set_longest_match(false);
				re2::RE2 concat_re("^CONCAT\\((|@@|@@session\\.)SQL_MODE,\"(.*)\"\\)", options);
				re2::StringPiece sp_input(str_val);

				std::string f_match {};
				std::string s_match {};

				re2::RE2::Consume(&sp_input, concat_re, &f_match, &s_match);

				if (!s_match.empty()) {
					special_sqlmode = true;

					// remove the initial 'comma' if exists
					if (s_match[0] == ',') {
						s_match = s_match.substr(1, std::string::npos);
					}

					std::string k_str_val { k.value() };
					verified_special_sqlmode =
						strcasestr(k_str_val.c_str(), s_match.c_str()) != NULL;
				}
			}

			if (
				(special_sqlmode == true && verified_special_sqlmode == false) ||
				(special_sqlmode == false &&
					(el.key() != "session_track_gtids" && (k.value() != el.value() || s.value() != el.value())) ||
					(el.key() == "session_track_gtids" && !check_session_track_gtids(el.value(), s.value(), k.value()))
				)
			) {
				__sync_fetch_and_add(&g_failed, 1);
				testPassed = false;
				fprintf(stderr, "Test failed for this case %s->%s.\n\nmysql data %s\n\n proxysql data %s\n\n csv data %s\n\n\n",
						el.value().dump().c_str(), el.key().c_str(), mysql_vars.dump().c_str(), proxysql_vars.dump().c_str(), vars.dump().c_str());
				ok(testPassed, "mysql connection [%p], thread_id [%lu], command [%s]", mysql, mysql->thread_id, testCases[r2].command.c_str());
				// In case of failing test, exit completely.
				exit(EXIT_FAILURE);
			} else {
				variables_tested++;
			}
		}
		{
			std::lock_guard<std::mutex> lock(mtx_);
			ok(testPassed, "mysql connection [%p], thread_id [%lu], variables_tested [%d], command [%s]", mysql, mysql->thread_id, variables_tested, testCases[r2].command.c_str());
		}
	}
	__sync_fetch_and_add(&query_phase_completed,1);

	return NULL;
}


int main(int argc, char *argv[]) {

	{
		bn = basename(argv[0]);
		std::string bn = basename(argv[0]);
		std::cerr << "Filename: " << bn << std::endl;
		if (bn == "set_testing-multi-t") {
			multi_users=4;
		}
	}

	std::string fileName(std::string(cl.workdir) + "/set_testing-t.csv");

	MYSQL* mysqladmin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysqladmin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysqladmin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysqladmin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysqladmin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysqladmin->net.compress, "Compression: (%d)", mysqladmin->net.compress);
	}
/*
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION' where variable_name='mysql-default_sql_mode'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='OFF' where variable_name='mysql-default_sql_safe_update'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='UTF8' where variable_name='mysql-default_character_set_results'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='REPEATABLE READ' where variable_name='mysql-default_isolation_level'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='REPEATABLE READ' where variable_name='mysql-default_tx_isolation'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='utf8_general_ci' where variable_name='mysql-default_collation_connection'");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='true' where variable_name='mysql-enforce_autocommit_on_reads'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

*/
	if (multi_users) {
		for (int i=1; i<=multi_users; i++) {
			std::string q = "INSERT OR IGNORE INTO mysql_users (username,password) VALUES ('sbtest" + std::to_string(i) + "','sbtest" + std::to_string(i) + "')";
			std::cerr << bn << ": " << q << std::endl;
			MYSQL_QUERY(mysqladmin, q.c_str());
		}
		std::string q = "LOAD MYSQL USERS TO RUNTIME";
		std::cerr << bn << ": " << q << std::endl;
		MYSQL_QUERY(mysqladmin, q.c_str());
		q = "UPDATE mysql_servers SET max_connections=3 WHERE hostgroup_id=0;";
		std::cerr << bn << ": " << q << std::endl;
		MYSQL_QUERY(mysqladmin, q.c_str());
		q = "LOAD MYSQL SERVERS TO RUNTIME";
		std::cerr << bn << ": " << q << std::endl;
		MYSQL_QUERY(mysqladmin, q.c_str());
	}

	if (detect_version(is_mariadb, is_cluster) != 0) {
		diag("Cannot detect MySQL version");
		return exit_status();
	}



	num_threads = 10;
	queries = 1000;
	queries_per_connections = 10;
	count = 10;
//	username = cl.username;
//	password = cl.password;
//	host = cl.host;
//	port = cl.port;

	int p = 2;										// admin connection
	p += 2 * queries / queries_per_connections;		// user connections
	p += queries * num_threads;						// tests
	plan(p);

	if (!readTestCases(fileName)) {
		fprintf(stderr, "Cannot read %s\n", fileName.c_str());
		return exit_status();
	}

//	if (strcmp(host,"localhost")==0) {
//		local = 1;
//	}
	if (uniquequeries == 0) {
		if (queries) uniquequeries=queries;
	}
	if (uniquequeries) {
		uniquequeries=(int)sqrt(uniquequeries);
	}

	pthread_t *thi=(pthread_t *)malloc(sizeof(pthread_t)*num_threads);
	if (thi==NULL)
		return exit_status();

	for (unsigned int i=0; i<num_threads; i++) {
		if ( pthread_create(&thi[i], NULL, my_conn_thread , NULL) != 0 )
			perror("Thread creation");
	}
	for (unsigned int i=0; i<num_threads; i++) {
		pthread_join(thi[i], NULL);
	}
	return exit_status();
}
