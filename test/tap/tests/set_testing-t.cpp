/**
 * @file set_testing-t.cpp
 * @brief This file tests multiple settings combinations for MySQL variables, and checks that they are
 *  actually being tracked correctly.
 * @details The test input is a 'csv' file with name 'set_testing-t.csv'. The file format consists in
 *  two primary columns which specifies the variables to set (first) and the expected result of setting
 *  those variables (second), and an optional third column which hold variables that shouldn't be checked
 *  anymore after the 'SET STATEMENTS' from the same line are executed.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <mysql.h>
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
#include <algorithm>

#include "json.hpp"
#include "re2/re2.h"
#include "re2/regexp.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"



int queries_per_connections=1;
unsigned int num_threads=1;
int count=0;
char *username=NULL;
char *password=NULL;
char *host=(char *)"localhost";
int port=3306;
int multiport=1;
char *schema=(char *)"information_schema";
int silent = 0;
int sysbench = 0;
int local=0;
int queries=0;
int uniquequeries=0;
int histograms=-1;

bool is_mariadb = false;
bool is_cluster = false;
unsigned int g_connect_OK=0;
unsigned int g_connect_ERR=0;
unsigned int g_select_OK=0;
unsigned int g_select_ERR=0;

unsigned int g_passed=0;
unsigned int g_failed=0;

unsigned int status_connections = 0;
unsigned int connect_phase_completed = 0;
unsigned int query_phase_completed = 0;

__thread int g_seed;
std::mutex mtx_;

std::vector<std::string> forgotten_vars {};

#include "set_testing.h"


/* TODO
	add support for variables with values out of range,
	for example setting auto_increment_increment to 100000
*/

void * my_conn_thread(void *arg) {
	g_seed = time(NULL) ^ getpid() ^ pthread_self();
	unsigned int select_OK=0;
	unsigned int select_ERR=0;
	int i, j;
	MYSQL **mysqlconns=(MYSQL **)malloc(sizeof(MYSQL *)*count);
	std::vector<json> varsperconn(count);

	if (mysqlconns==NULL) {
		exit(EXIT_FAILURE);
	}

	std::vector<std::string> cs = {"latin1", "utf8", "utf8mb4", "latin2", "latin7"};

	for (i=0; i<count; i++) {
		MYSQL *mysql=mysql_init(NULL);
		std::string nextcs = cs[i%cs.size()];

		mysql_options(mysql, MYSQL_SET_CHARSET_NAME, nextcs.c_str());
		if (mysql==NULL) {
			exit(EXIT_FAILURE);
		}
		MYSQL *rc=mysql_real_connect(mysql, host, username, password, schema, (local ? 0 : ( port + rand()%multiport ) ), NULL, 0);
		if (rc==NULL) {
			if (silent==0) {
				fprintf(stderr,"%s\n", mysql_error(mysql));
			}
			exit(EXIT_FAILURE);
		}
		mysqlconns[i]=mysql;
		__sync_add_and_fetch(&status_connections,1);
	}
	__sync_fetch_and_add(&connect_phase_completed,1);

	while(__sync_fetch_and_add(&connect_phase_completed,0) != num_threads) {
	}
	MYSQL *mysql=NULL;
	json vars;
	std::string paddress = "";
	for (j=0; j<queries; j++) {
		int fr = fastrand();
		int r1=fr%count;
		//int r2=fastrand()%testCases.size();
		int r2=rand()%testCases.size();

		if (j%queries_per_connections==0) {
			mysql=mysqlconns[r1];
			vars = varsperconn[r1];
		}
		if (strcmp(username,(char *)"root")) {
			if (strstr(testCases[r2].command.c_str(),"database")) {
				std::lock_guard<std::mutex> lock(mtx_);
				skip(1, "connections mysql[%p] proxysql[%s], command [%s]", mysql, paddress.c_str(), testCases[r2].command.c_str());
				continue;
			}
			if (strstr(testCases[r2].command.c_str(),"sql_log_bin")) {
				std::lock_guard<std::mutex> lock(mtx_);
				skip(1, "connections: mysql[%p] proxysql[%s], command [%s]", mysql, paddress.c_str(), testCases[r2].command.c_str());
				continue;
			}
		}
		diag("Thread_id: %lu, random number: %d . Query/ies: %s", mysql->thread_id, r2, testCases[r2].command.c_str());
		std::vector<std::string> commands = split(testCases[r2].command.c_str(), ';');
		for (auto c : commands) {
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
			}
			else if (el.key() == "max_execution_time") {
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

		// this allows connections to be moved around
		// and will also trigger --idle-threads code
		int sleepDelay = fastrand()%100;
		usleep(sleepDelay * 1000);

		char query[128];
		sprintf(query, "SELECT /* %p %s */ %d;", mysql, paddress.c_str(), sleepDelay);
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

		//diag("MySQL vars: %lu , ProxySQL vars: %lu" , mysql_vars.size(), proxysql_vars.size());
		{
			int lhg = proxysql_vars["locked_on_hostgroup"];
			if (lhg != -1) {
				diag("ProxySQL locked_on_hostgroup %d", lhg);
				diag("FAILED FOR: connections mysql[%p] proxysql[%s], thread_id [%lu], command [%s]", mysql, paddress.c_str(), mysql->thread_id, testCases[r2].command.c_str());
				exit(EXIT_FAILURE);
			}
		}

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
				diag("Variable %s->%s in mysql resultset was not found.\nmysql data : %s\nproxysql data: %s\ncsv data %s\n",
						el.value().dump().c_str(), el.key().c_str(), mysql_vars.dump().c_str(), proxysql_vars.dump().c_str(), vars.dump().c_str());

			if (s == proxysql_vars["conn"].end())
				diag("Variable %s->%s in proxysql resultset was not found.\nmysql data : %s\nproxysql data: %s\ncsv data %s\n",
						el.value().dump().c_str(), el.key().c_str(), mysql_vars.dump().c_str(), proxysql_vars.dump().c_str(), vars.dump().c_str());

			bool verified_special_sqlmode = false;
			bool special_sqlmode = false;

			if (el.key() == "sql_mode") {
				if (!el.value().is_string()) {
					diag("Invalid value for 'sql_mode' found. Provided value should be of 'string' type");
					exit(EXIT_FAILURE);
				}

				if (k.value() != el.value()) { // different in mysql
					std::string e_val { el.value() };
					std::string k_val { k.value() };
					std::string s_val { s.value() };
					if (e_val != s_val) {
						// try to replace " with '
						std::replace( e_val.begin(), e_val.end(), '"', '\'');
					}
					if (e_val == s_val) { // but same in proxysql
						std::string str_val { el.value() };
						if (strcasecmp(str_val.c_str(), "TRADITIONAL")==0) {
							if (k.value() == "STRICT_TRANS_TABLES,STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,TRADITIONAL,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION") {
								special_sqlmode = true;
								verified_special_sqlmode = true;
							}
						} else {
							if (strcasestr(e_val.c_str(), "sql_mode") != NULL) {
								// simplified
								special_sqlmode = true;
								verified_special_sqlmode = true;
							}
/*
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
*/
						}
					}
				}
			}

			if (
				(special_sqlmode == true && verified_special_sqlmode == false) ||
				(k == mysql_vars.end()) ||
				(s == proxysql_vars["conn"].end()) ||
				(special_sqlmode == false &&
					(el.key() != "session_track_gtids" && (k.value() != el.value() || s.value() != el.value())) ||
					(el.key() == "session_track_gtids" && !check_session_track_gtids(el.value(), s.value(), k.value()))
				)
			) {
				if (el.key() == "wsrep_sync_wait" && k == mysql_vars.end() && (s.value() == el.value())) {
					variables_tested++;
				} else {
					__sync_fetch_and_add(&g_failed, 1);
					testPassed = false;
					diag("Test failed for this case %s->%s.\n\nmysql data [%lu]: %s\n\n proxysql data [%lu]: %s\n\n csv data %s\n\n\n",
							el.value().dump(2).c_str(), el.key().c_str(),
							mysql_vars.size(), mysql_vars.dump(2).c_str(),
							proxysql_vars["conn"].size(), proxysql_vars["conn"].dump(2).c_str(),
							vars.dump(2).c_str());
					diag("FAILED FOR: connections mysql[%p] proxysql[%s], thread_id [%lu], command [%s]", mysql, paddress.c_str(), mysql->thread_id, testCases[r2].command.c_str());
					//ok(testPassed, "connections mysql[%p] proxysql[%s], thread_id [%lu], command [%s]", mysql, paddress.c_str(), mysql->thread_id, testCases[r2].command.c_str());
					// In case of failing test, exit completely.
					//exit(EXIT_FAILURE);
				}
			} else {
				variables_tested++;
			}
		}
		{
			std::lock_guard<std::mutex> lock(mtx_);
			ok(testPassed, "connections mysql[%p] proxysql[%s], thread_id [%lu], variables_tested [%d], command [%s]", mysql, paddress.c_str(), mysql->thread_id, variables_tested, testCases[r2].command.c_str());
		}
	}
	__sync_fetch_and_add(&query_phase_completed,1);

	return NULL;
}



int main(int argc, char *argv[]) {
	CommandLine cl;

	if(cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	std::string fileName(std::string(cl.workdir) + "/set_testing-t.csv");


	if (detect_version(cl, is_mariadb, is_cluster) != 0) {
		diag("Cannot detect MySQL version");
		return exit_status();
	}

	num_threads = 10;
	queries_per_connections = 10;
	count = 10;
	username = cl.username;
	password = cl.password;
	host = cl.host;
	port = cl.port;

	if (!readTestCases(fileName)) {
		fprintf(stderr, "Cannot read %s\n", fileName.c_str());
		return exit_status();
	}

	queries = 300;

	plan(queries * num_threads);

	if (strcmp(host,"localhost")==0) {
		local = 1;
	}
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
