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
#include "json.hpp"

#include "tap.h"
#include "command_line.h"


using nlohmann::json;

struct TestCase {
    std::string command;
    json expected_vars;
};

std::vector<TestCase> testCases;

#define MAX_LINE 1024

int readTestCases(const std::string& fileName) {
    FILE* fp = fopen(fileName.c_str(), "r");
    if (!fp) return 0;

    char buf[MAX_LINE], col1[MAX_LINE], col2[MAX_LINE];
    int n = 0;
    for(;;) {
        if (fgets(buf, sizeof(buf), fp) == NULL) break;
        n = sscanf(buf, " \"%[^\"]\", \"%[^\"]\"", col1, col2);
        if (n == 0) break;

        char *p = col2;
        while(*p++) if(*p == '\'') *p = '\"';

        json vars = json::parse(col2);
        testCases.push_back({col1, vars});
    }

    fclose(fp);
    return 1;
}

unsigned long long monotonic_time() {
	struct timespec ts;
	//clock_gettime(CLOCK_MONOTONIC_COARSE, &ts); // this is faster, but not precise
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

struct cpu_timer
{
	cpu_timer() {
		begin = monotonic_time();
	}
	~cpu_timer()
	{
		unsigned long long end = monotonic_time();
		std::cerr << double( end - begin ) / 1000000 << " secs.\n" ;
		begin=end-begin;
	};
	unsigned long long begin;
};

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

inline int fastrand() {
	g_seed = (214013*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}

void parseResultJsonColumn(MYSQL_RES *result, json& j) {
        if(!result) return;
        MYSQL_ROW row;

        while ((row = mysql_fetch_row(result)))
            j = json::parse(row[0]);
}

void parseResult(MYSQL_RES *result, json& j) {
        if(!result) return;
        MYSQL_ROW row;

        while ((row = mysql_fetch_row(result)))
            j[row[0]] = row[1];
 }

void dumpResult(MYSQL_RES *result) {
        if(!result) return;
        MYSQL_ROW row;

        int num_fields = mysql_num_fields(result);

        while ((row = mysql_fetch_row(result)))
        {
            for(int i = 0; i < num_fields; i++)
            {
                printf("%s ", row[i] ? row[i] : "NULL");
            }
            printf("\n");
        }
 }

void queryVariables(MYSQL *mysql, json& j) {
    char *query = (char*)"SELECT * FROM performance_schema.session_variables WHERE variable_name IN "
                         " ('hostname', 'sql_log_bin', 'sql_mode', 'init_connect', 'time_zone', 'autocommit', 'sql_auto_is_null', "
                         " 'sql_safe_updates', 'session_track_gtids', 'max_join_size', 'net_write_timeout', 'sql_select_limit', "
                         " 'sql_select_limit', 'character_set_results');";
    if (mysql_query(mysql, query)) {
        if (silent==0) {
            fprintf(stderr,"%s\n", mysql_error(mysql));
        }
    } else {
        MYSQL_RES *result = mysql_store_result(mysql);
        parseResult(result, j);

        mysql_free_result(result);
        __sync_fetch_and_add(&g_select_OK,1);
    }
}

void queryInternalStatus(MYSQL *mysql, json& j) {
    char *query = (char*)"PROXYSQL INTERNAL SESSION";

    if (mysql_query(mysql, query)) {
        if (silent==0) {
            fprintf(stderr,"%s\n", mysql_error(mysql));
        }
    } else {
        MYSQL_RES *result = mysql_store_result(mysql);
        parseResultJsonColumn(result, j);

        mysql_free_result(result);
        __sync_fetch_and_add(&g_select_OK,1);
    }

    // value types in mysql and in proxysql are different
    // we should convert proxysql values to mysql format to compare
    for (auto& el : j.items()) {
        if (el.key() == "conn") {
            std::string sql_log_bin_value;

            // sql_log_bin {0|1}
            if (el.value()["sql_log_bin"] == 1) {
                el.value().erase("sql_log_bin");
                j["conn"]["sql_log_bin"] = "ON";
            }
            else if (el.value()["sql_log_bin"] == 0) {
                el.value().erase("sql_log_bin");
                j["conn"]["sql_log_bin"] = "OFF";
            }

			// autocommit {true|false}
			if (!el.value()["autocommit"].dump().compare("ON") ||
					!el.value()["autocommit"].dump().compare("1") ||
					!el.value()["autocommit"].dump().compare("on") ||
					el.value()["autocommit"] == 1) {
				el.value().erase("autocommit");
				j["conn"]["autocommit"] = "ON";
			}
			else if (!el.value()["autocommit"].dump().compare("OFF") ||
					!el.value()["autocommit"].dump().compare("0") ||
					!el.value()["autocommit"].dump().compare("off") ||
					el.value()["autocommit"] == 0) {
				el.value().erase("autocommit");
				j["conn"]["autocommit"] = "OFF";
			}

			// sql_safe_updates
			if (!el.value()["sql_safe_updates"].dump().compare("\"ON\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"1\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"on\"") ||
					el.value()["sql_safe_updates"] == 1) {
				el.value().erase("sql_safe_updates");
				j["conn"]["sql_safe_updates"] = "ON";
			}
			else if (!el.value()["sql_safe_updates"].dump().compare("\"OFF\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"0\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"off\"") ||
					el.value()["sql_safe_updates"] == 0) {
				el.value().erase("sql_safe_updates");
				j["conn"]["sql_safe_updates"] = "OFF";
			}

			std::stringstream ss;
			ss << 0xFFFFFFFFFFFFFFFF;
			// sql_select_limit
			if (!el.value()["sql_select_limit"].dump().compare("\"DEFAULT\"")) {
				el.value().erase("sql_select_limit");
				j["conn"]["sql_select_limit"] = strdup(ss.str().c_str());
			}
     }
    }
}

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
	for (i=0; i<count; i++) {
		MYSQL *mysql=mysql_init(NULL);
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
	MYSQL *mysql;
	json vars;
	for (j=0; j<queries; j++) {
		int fr = fastrand();
		int r1=fr%count;
        int r2=fastrand()%testCases.size();

		if (j%queries_per_connections==0) {
			mysql=mysqlconns[r1];
			vars = varsperconn[r1];
		}

        if (mysql_query(mysql, testCases[r2].command.c_str())) {
            if (silent==0) {
                fprintf(stderr,"%s\n", mysql_error(mysql));
            }
		} else {
			MYSQL_RES *result = mysql_store_result(mysql);
			mysql_free_result(result);
			select_OK++;
			__sync_fetch_and_add(&g_select_OK,1);
		}
        for (auto& el : testCases[r2].expected_vars.items()) {
            vars[el.key()] = el.value();
        }

		int sleepDelay = fastrand()%100;
		usleep(sleepDelay * 1000);

		char query[128];
		sprintf(query, "SELECT %d;", sleepDelay);
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
        queryVariables(mysql, mysql_vars);

        json proxysql_vars;
        queryInternalStatus(mysql, proxysql_vars);

		bool testPassed = true;
        for (auto& el : vars.items()) {
            auto k = mysql_vars.find(el.key());
            auto s = proxysql_vars["conn"].find(el.key());

            if (k.value() != el.value() || s.value() != el.value()) {
                __sync_fetch_and_add(&g_failed, 1);
				testPassed = false;
            }
        }
        ok(testPassed, "Test passed");
	}
	__sync_fetch_and_add(&query_phase_completed,1);

	return NULL;
}

int main(int argc, char *argv[]) {
	CommandLine cl;
	std::string fileName("./tests/set_testing-t.csv");

	if(cl.getEnv())
		return exit_status();

	num_threads = 10;
	queries = 100;
	queries_per_connections = 10;
	count = 10;
	username = cl.username;
	password = cl.password;
	host = cl.host;
	port = cl.port;

	plan(queries * num_threads);
    if (!readTestCases(fileName)) {
        fprintf(stderr, "Cannot read %s\n", fileName.c_str());
		return exit_status();
    }

	if (strcmp(host,"localhost")==0) {
		local = 1;
	}
	if (uniquequeries == 0) {
		if (queries) uniquequeries=queries;
	}
	if (uniquequeries) {
		uniquequeries=(int)sqrt(uniquequeries);
	}
	mysql_library_init(0, NULL, NULL);

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
