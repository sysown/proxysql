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

int queries_per_connections = 10;
//unsigned int num_threads = 1;
//unsigned int num_threads = 5;
unsigned int num_threads = 20;
int count = 20;
int total_conn_having_client_deprecate_eof_support = (count * 0.2); // 20% of connections will have CLIENT_DEPRECATE_EOF flag enabled
//char *username = NULL;
//char *password = NULL;
//char *host = (char *)"localhost";
//int port = 3306;
int multiport = 1;
char *schema = (char *)"information_schema";
int silent = 0;
int sysbench = 0;
int local = 0;
int queries = 3000;
int uniquequeries = 0;
int histograms = -1;

bool is_mariadb = false;
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

#include "set_testing-240.h"

class var_counter {
	public:
	int count;
	int unknown;
	var_counter() {
		count=0;
		unknown=0;
	}
};

// Generate string containing randomly chosen characters between
// ';' and ' ', with length between 1 and 8
std::string generate_random_noise() {
	// Seed the random number generator with the current time
	std::srand(static_cast<unsigned int>(std::time(nullptr)));

	static const char characters[] = { ';', ' ' };
	static const int numCharacters = sizeof(characters) / sizeof(char);

	// max lengh of string is 8
	const int length = std::rand() % 8 + 1;

	std::string randomString;
	randomString.reserve(length);

	for (int i = 0; i < length; ++i) {
		char randomChar = characters[std::rand() % numCharacters];
		randomString.push_back(randomChar);
	}

	return randomString;
}

//std::unordered_map<std::string,int> unknown_var_counters;

std::unordered_map<std::string,var_counter> vars_counters;

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
	bool set_sql_mode[count];
	std::vector<json> varsperconn(count);

	if (mysqlconns==NULL) {
		exit(EXIT_FAILURE);
	}

	std::vector<std::string> cs = {"latin1", "utf8", "utf8mb4", "latin2", "latin7"};

	for (i=0; i<count; i++) {

		std::string nextcs = cs[i%cs.size()];

		MYSQL *mysql = mysql_init(NULL);
		diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
		mysql_options(mysql, MYSQL_SET_CHARSET_NAME, nextcs.c_str());
		if (i < total_conn_having_client_deprecate_eof_support) {
			// enable 'CLIENT_DEPRECATE_EOF' support
			mysql->options.client_flag |= CLIENT_DEPRECATE_EOF;
		}
		if (cl.use_ssl)
			mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
		if (cl.compression)
			mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
		int port = local ? 0 : ( cl.port + rand()%multiport );
		if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, schema, port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			exit(EXIT_FAILURE);
		} else {
			const char * c = mysql_get_ssl_cipher(mysql);
			ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
			ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
		}

		mysqlconns[i]=mysql;
		set_sql_mode[i]=false;
		__sync_add_and_fetch(&status_connections,1);
	}
	__sync_fetch_and_add(&connect_phase_completed,1);

	while(__sync_fetch_and_add(&connect_phase_completed,0) != num_threads) {
	}
	MYSQL *mysql = NULL;
	int mysql_idx = 0;
	json vars;
	std::string paddress = "";
	for (j=0; j<queries; j++) {
		int fr = rand();
		int r1=fr%count;
		//int r2=fastrand()%testCases.size();
		int r2=rand()%testCases.size();

		if (j%queries_per_connections==0) {
			mysql_idx=r1;
			mysql=mysqlconns[mysql_idx];
			vars = varsperconn[mysql_idx];
		}
		if (strcmp(cl.username,(char *)"root")) {
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
			c += generate_random_noise();
			if (mysql_query(mysql, c.c_str())) {
				if (silent==0) {
					fprintf(stderr,"ERROR while running -- \"%s\" :  (%d) %s\n", c.c_str(), mysql_errno(mysql), mysql_error(mysql));
				}
			} else {
				MYSQL_RES *result = mysql_store_result(mysql);
				mysql_free_result(result);
				select_OK++;
				__sync_fetch_and_add(&g_select_OK,1);
				if (strcasestr(c.c_str(),"sql_mode") != NULL) {
//					diag("Line %d: Debug NO_BACKSLASH_ESCAPES , set_sql_mode=%s , connections mysql[%p] proxysql[%s], thread_id [%lu], command [%s]", __LINE__, (set_sql_mode[mysql_idx] == true ? "true" : "false") , mysql, paddress.c_str(), mysql->thread_id, testCases[r2].command.c_str());
					if (set_sql_mode[mysql_idx] == false) {
						// first time we set sql_mode
						if (strcasestr(c.c_str(),"NO_BACKSLASH_ESCAPES") != NULL) {
							if (mysql->server_status & SERVER_STATUS_NO_BACKSLASH_ESCAPES) {
							} else {
								diag("Line %d: ERROR with NO_BACKSLASH_ESCAPES . connections mysql[%p] proxysql[%s], thread_id [%lu], command [%s]", __LINE__, mysql, paddress.c_str(), mysql->thread_id, testCases[r2].command.c_str());
								exit(EXIT_FAILURE);
							}
						} else {
							if (mysql->server_status & SERVER_STATUS_NO_BACKSLASH_ESCAPES) {
								diag("Line %d: ERROR with NO_BACKSLASH_ESCAPES . connections mysql[%p] proxysql[%s], thread_id [%lu], command [%s]", __LINE__, mysql, paddress.c_str(), mysql->thread_id, testCases[r2].command.c_str());
								exit(EXIT_FAILURE);
							} else {
							}
						}
						set_sql_mode[mysql_idx] = 1;
//						diag("Setting set_sql_mode=true . New value = %s . For: connections mysql[%p] proxysql[%s], thread_id [%lu], command [%s]" , (set_sql_mode[mysql_idx] == true ? "true" : "false") , mysql, paddress.c_str(), mysql->thread_id, testCases[r2].command.c_str());
					} else {
						if (strcasestr(c.c_str(),"NO_BACKSLASH_ESCAPES") != NULL) {
							if (mysql->server_status & SERVER_STATUS_NO_BACKSLASH_ESCAPES) {
							} else {
								diag("Line %d: ERROR with NO_BACKSLASH_ESCAPES . connections mysql[%p] proxysql[%s], thread_id [%lu], command [%s]", __LINE__, mysql, paddress.c_str(), mysql->thread_id, testCases[r2].command.c_str());
								exit(EXIT_FAILURE);
							}
						}
					}
				}
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
			else if (el.key() == "transaction_read_only") {
				if (is_mariadb) {
					vars["tx_read_only"] = el.value();
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
		//diag("ProxySQL internals: %s" , proxysql_vars.dump(2).c_str());
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

			bool parsing_optimizer_switch = false;
			bool optimizer_switch_matches = false;

			if (el.key() == "long_query_time") {
				// we remove the decimals
				std::string tsnd = mysql_vars["long_query_time"];
				if (tsnd.find(".") != std::string::npos) {
					tsnd = tsnd.substr(0, tsnd.find("."));
					mysql_vars["long_query_time"]=tsnd;
				}
			}

			if (el.key() == "timestamp") {
				// we remove the decimals
				std::string tsnd = mysql_vars["timestamp"];
				if (tsnd.find(".") != std::string::npos) {
					tsnd = tsnd.substr(0, tsnd.find("."));
					mysql_vars["timestamp"]=tsnd;
				}
			}
			if (el.key() == "max_join_size") {
				if (el.value() == "DEFAULT") {
					if (mysql_vars["max_join_size"] == "18446744073709551615") {
						mysql_vars["max_join_size"] = "DEFAULT";
					}
				}
			}

			if (el.key() == "optimizer_switch") {
				parsing_optimizer_switch = true;
				std::string e_val { el.value() };
				std::string k_val { k.value() };
				std::string s_val { s.value() };
				if (e_val == s_val) { // it matches in proxysql
					if (strstr(k_val.c_str(), e_val.c_str()) != NULL) {
						optimizer_switch_matches = true;
					}
				}
			}

			if (el.key() == "sql_mode") {
				if (!el.value().is_string()) {
					diag("Invalid value for 'sql_mode' found. Provided value should be of 'string' type");
					exit(EXIT_FAILURE);
				}

				if (k.value() != el.value()) { // different in mysql
					std::string e_val { el.value() };
					std::string k_val { k.value() };
					std::string s_val { s.value() };
					if (el.value() == s.value()) { // but same in proxysql
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
			if (std::find(possible_unknown_variables.begin(), possible_unknown_variables.end(), el.key()) != possible_unknown_variables.end()) {
				vars_counters[el.key()].count++;
			}
			if (
				(special_sqlmode == true && verified_special_sqlmode == false) ||
				(k == mysql_vars.end()) ||
				(s == proxysql_vars["conn"].end()) ||
				( (parsing_optimizer_switch == true) && (optimizer_switch_matches == false) ) ||
				(special_sqlmode == false && parsing_optimizer_switch == false &&
					(el.key() != "session_track_gtids" && (k.value() != el.value() || s.value() != el.value())) ||
					(el.key() == "session_track_gtids" && !check_session_track_gtids(el.value(), s.value(), k.value()))
				)
			) {
				if ( k != mysql_vars.end() && s != proxysql_vars["conn"].end()) {
					if (k.value() == UNKNOWNVAR) { // mysql doesn't recognize the variable
						if (s.value() == el.value()) { // but proxysql and CSV are the same
							variables_tested++;
							vars_counters[el.key()].unknown++;
						}
					}
				} else if (el.key() == "wsrep_sync_wait" && k == mysql_vars.end() && (s.value() == el.value())) {
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

	// close all connections
	for (i=0; i<count; i++) {
		mysql_close(mysqlconns[i]);
	}

	return NULL;
}


int main(int argc, char *argv[]) {

	std::string fileName2(std::string(cl.workdir) + "/set_testing-240.csv");

/*
	num_threads = 10;
	queries_per_connections = 10;
	count = 10;
*/
//	username = cl.username;
//	password = cl.password;
//	host = cl.host;
//	host = "127.0.0.1";
//	port = cl.port;
//	port = 6033;

	diag("Loading test cases from file. This will take some time...");
	if (!readTestCasesJSON(fileName2)) {
		fprintf(stderr, "Cannot read %s\n", fileName2.c_str());
		return exit_status();
	}

	MYSQL* proxysql_admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_admin->net.compress, "Compression: (%d)", proxysql_admin->net.compress);
	}

/* admin-hash_passwords has been deprecated
	diag("Disabling admin-hash_passwords to be able to run test on MySQL 8");
	MYSQL_QUERY(proxysql_admin, "SET admin-hash_passwords='false'");
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL USERS TO RUNTIME");
*/

	// find all reader host groups
	MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_servers WHERE hostgroup_id = 101");
	MYSQL_QUERY(proxysql_admin, "SELECT hostgroup_id, comment FROM mysql_servers WHERE hostgroup_id%10 = 1 GROUP BY hostgroup_id");
	MYSQL_RES *result = mysql_store_result(proxysql_admin);
	std::vector<mysql_res_row> rows_res { extract_mysql_rows(result) };
	mysql_free_result(result);

	for (const auto& act_row : rows_res) {
		diag("Found hostgroup: %s '%s'", act_row[0].c_str(), act_row[1].c_str());
	}

	//queries = 3000;
	//queries = testCases.size();
	queries = queries / rows_res.size();		// keep test duration constant
	unsigned int p = queries * num_threads;
	p *= 2;										// number of algorithms
	p *= rows_res.size();						// number of host groups
	p += 2 + 2*num_threads*count*2;				// number of connections (2 algorithms)
	plan(p);

	for (const auto& act_row : rows_res) {
		diag("Using hostgroup: %s '%s'", act_row[0].c_str(), act_row[1].c_str());

		diag("Creating new hostgroup 101: DELETE FROM mysql_servers WHERE hostgroup_id = 101");
		MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_servers WHERE hostgroup_id = 101");

		const std::string insert = "INSERT INTO mysql_servers (hostgroup_id, hostname, port, max_connections, max_replication_lag, comment) SELECT DISTINCT 101, hostname, port, 100, 0, comment FROM mysql_servers WHERE hostgroup_id = '" + act_row[0] + "'";
		diag("Creating new hostgroup 101: %s" , insert.c_str());
		MYSQL_QUERY(proxysql_admin, insert.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		const std::string update = "UPDATE mysql_query_rules SET destination_hostgroup=101 WHERE destination_hostgroup=" + act_row[0];
		diag("Changing read traffic to hostgroup 101: %s", update.c_str());
		MYSQL_QUERY(proxysql_admin, update.c_str());
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

		if (detect_version(is_mariadb) != 0) {
			diag("Cannot detect MySQL version");
			return exit_status();
		}

//		if (strcmp(cl.host, "localhost")==0) {
//			local = 1;
//		}

		for (int algo = 1; algo <= 2; algo++ ) {
			connect_phase_completed = 0;
			query_phase_completed = 0;
			std::string qu = "SET mysql-set_parser_algorithm=" + std::to_string(algo);
			diag("Setting %s", qu.c_str());
			MYSQL_QUERY(proxysql_admin, qu.c_str());
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
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
			free(thi);
		}
		for (std::unordered_map<std::string,var_counter>::iterator it = vars_counters.begin(); it!=vars_counters.end(); it++) {
			diag("Unknown variable %s:\t Count: %d , unknown: %d", it->first.c_str(), it->second.count, it->second.unknown);
		}
		sleep(10);

	}
	return exit_status();
}
