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
#include <mutex>
#include <atomic>

#include "tap.h"
#include "utils.h"
#include "command_line.h"


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

bool debug_diag = true;
unsigned int num_threads=5;
int count=10;
char *username=NULL;
char *password=NULL;
char *host=(char *)"localhost";
int port=3306;
char *schema=(char *)"information_schema";
int silent = 0;
int sysbench = 0;
int local=0;
int transactions=200;
int uniquequeries=0;
int histograms=-1;

unsigned int g_passed=0;
unsigned int g_failed=0;

std::atomic<int> cnt_transactions;
std::atomic<int> cnt_SELECT_outside_transactions;
std::atomic<int> cnt_expected_errors;

unsigned int status_connections = 0;
unsigned int connect_phase_completed = 0;
unsigned int query_phase_completed = 0;

__thread int g_seed;
std::mutex mtx_;

inline int fastrand() {
	g_seed = (214013*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}

void gen_random(char *s, const int len) {
    static const char alphanum[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[fastrand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
}

void * my_conn_thread(void *arg) {
	g_seed = time(NULL) ^ getpid() ^ pthread_self();
	unsigned int select_OK=0;
	unsigned int select_ERR=0;
	int i, j;
	MYSQL **mysqlconns=(MYSQL **)malloc(sizeof(MYSQL *)*count);

	if (mysqlconns==NULL) {
		exit(EXIT_FAILURE);
	}


	for (i=0; i<count; i++) {
		MYSQL *mysql=mysql_init(NULL);

		if (mysql==NULL) {
			exit(EXIT_FAILURE);
		}
		MYSQL *rc=mysql_real_connect(mysql, host, username, password, schema, (local ? 0 : port) , NULL, 0);
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
	std::string sel1 = "SELECT * FROM test.test_savepoint LIMIT 1";
	for (j=0; j<transactions; j++) {
		int fr = fastrand();
		int r1=fr%count;
		bool explicit_transaction = false;

			mysql=mysqlconns[r1];

		int sleepDelay;
		for (int i=0; i<fr%3; i++) {
			std::string q = "SET autocommit=" + std::to_string(fr%2);
			if (debug_diag==true)
				diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, q.c_str());
			if (mysql_query(mysql, q.c_str())) {
				fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
			sleepDelay = fastrand()%100;
			usleep(sleepDelay * 100);
		}
		{
			std::string q;
			if (fr%2) {
				q = "START TRANSACTION";
				explicit_transaction = true; 
			} else {
				q = "SET AUTOCOMMIT=0";
			}
			if (debug_diag==true)
				diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, q.c_str());
			if (mysql_query(mysql, q.c_str())) {
				fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
			sleepDelay = fastrand()%100;
			usleep(sleepDelay * 100);
		}

		if (fr%3 == 0 || explicit_transaction==false) {
			std::string sel;
			if (explicit_transaction==false) {
				// we need to issue a SELECT FOR UPDATE to trigger a transaction
				sel = sel1 + " FOR UPDATE";
			} else {
				sel = sel1;
			}
			if (debug_diag==true)
				diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, sel.c_str());
			if (mysql_query(mysql, sel.c_str())) {
				fprintf(stderr,"Error running query: %s. Error: %s\n", sel.c_str(), mysql_error(mysql));
			} else {
				MYSQL_RES *result = mysql_store_result(mysql);
				mysql_free_result(result);
				select_OK++;
//				if (explicit_transaction == false) {
//					cnt_SELECT_outside_transactions++;
//				}
			}
			sleepDelay = fastrand()%100;
			usleep(sleepDelay * 100);
		}

		char buf[16];
		memset(buf,0,16);
		gen_random(buf,14);
		{
			std::string q = "SAVEPOINT ";
			q += buf;
			if (debug_diag==true)
				diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, q.c_str());
			if (mysql_query(mysql, q.c_str())) {
				fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
			sleepDelay = fastrand()%100;
			usleep(sleepDelay * 100);
		}
		for (int i=0; i<fr%3+1; i++) {
			if (debug_diag==true)
				diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, sel1.c_str());
			if (mysql_query(mysql, sel1.c_str())) {
				fprintf(stderr,"Error running query: %s. Error: %s\n", sel1.c_str(), mysql_error(mysql));
			} else {
				MYSQL_RES *result = mysql_store_result(mysql);
				mysql_free_result(result);
				select_OK++;
			}
			sleepDelay = fastrand()%100;
			usleep(sleepDelay * 100);
		}
		int aa = fr%10;
		if (aa==2 || aa==3) { // sometime before RELEASE, sometimes before ROLLBACK
			std::string q = "ROLLBACK TO SAVEPOINT ";
			q+= buf;
			q+= "NonExistingSavePoint";
			if (debug_diag==true)
				diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, q.c_str());
			int rc = mysql_query(mysql, q.c_str());
			if (rc != 0) {
				cnt_expected_errors++;
				if (debug_diag==true)
					diag("EXPECTED error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysql));
			} else {
				ok(rc!=0, "Generating a \"not ok\" . We didn't receive any error for: %s", q.c_str());
			}
			sleepDelay = fastrand()%100;
			usleep(sleepDelay * 100);
		}
		if (aa < 3) {
			std::string q;
			q = "RELEASE SAVEPOINT ";
			q += buf;
			if (debug_diag==true)
				diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, q.c_str());
			if (mysql_query(mysql, q.c_str())) {
				fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
			sleepDelay = fastrand()%100;
			usleep(sleepDelay * 100);
		} else {
			std::string q;
			q = "ROLLBACK TO SAVEPOINT ";
			q += buf;
			if (debug_diag==true)
				diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, q.c_str());
			if (mysql_query(mysql, q.c_str())) {
				fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
			sleepDelay = fastrand()%100;
			usleep(sleepDelay * 100);
			if (aa > 7) {
				q = "RELEASE SAVEPOINT ";
				q += buf;
				if (debug_diag==true)
					diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, q.c_str());
				if (mysql_query(mysql, q.c_str())) {
					fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysql));
					exit(EXIT_FAILURE);
				}
				sleepDelay = fastrand()%100;
				usleep(sleepDelay * 100);
			}
		}
		{
			std::string q;
			int f = fr%3;
			if (f==0) {
				q = "COMMIT";
			} else {
				q = "ROLLBACK";
/*
				// FIXME: this code is currently commented because of another bug
				if (explicit_transaction==false) {
					if (f!=1) {
						q = "SET AUTOCOMMIT=1";
					}
				}
*/
			}
			if (debug_diag==true)
				diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, q.c_str());
			if (mysql_query(mysql, q.c_str())) {
				fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
			cnt_transactions++;
			sleepDelay = fastrand()%100;
			usleep(sleepDelay * 100);
		}
/*
		// we do not log every single transaction, too verbose
		bool testPassed = true;
		{
			std::lock_guard<std::mutex> lock(mtx_);
			ok(testPassed, "mysql connection [%p], thread_id [%lu], transaction completed", mysql, mysql->thread_id);
		}
*/
		if (fr%7 == 0) {
			std::string sel;
			sel = sel1;
			if (debug_diag==true)
				diag("Thread %lu , connection %p , query: %s", pthread_self(), mysql, sel.c_str());
			if (mysql_query(mysql, sel.c_str())) {
				fprintf(stderr,"Error running query: %s. Error: %s\n", sel.c_str(), mysql_error(mysql));
			} else {
				MYSQL_RES *result = mysql_store_result(mysql);
				mysql_free_result(result);
				select_OK++;
				cnt_SELECT_outside_transactions++;
			}
			sleepDelay = fastrand()%100;
			usleep(sleepDelay * 100);
		}

	}
	for (i=0; i<count; i++) {
		MYSQL *mysql = mysqlconns[i];
		mysql_close(mysql);
	}
	__sync_fetch_and_add(&query_phase_completed,1);

	return NULL;
}

void print_commands_stats(MYSQL *mysqladmin) {
	std::string q = "SELECT Command,Total_Time_us,Total_cnt FROM stats_mysql_commands_counters WHERE Command IN ('COMMIT','RELEASE_SAVEPOINT','ROLLBACK','ROLLBACK_SAVEPOINT','SELECT','SET','START_TRANSACTION') ORDER BY Command";
	{
		if (mysql_query(mysqladmin, q.c_str())) {
			fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysqladmin));
			exit(EXIT_FAILURE);
		}
		MYSQL_RES *result = mysql_store_result(mysqladmin);
		MYSQL_ROW row;
		std::cerr << "Stats from stats_mysql_commands_counters" << std::endl;
		while ((row = mysql_fetch_row(result)))
		{
			std::cerr << row[0] << " \tCount: " << row[2] << " \tTime: " << row[1] << std::endl;
		}
		mysql_free_result(result);
	}
}

void print_global_status(MYSQL *mysqladmin) {
	std::string q = "SELECT * FROM stats_mysql_global ORDER BY Variable_Name";
	{
		if (mysql_query(mysqladmin, q.c_str())) {
			fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysqladmin));
			exit(EXIT_FAILURE);
		}
		MYSQL_RES *result = mysql_store_result(mysqladmin);
		MYSQL_ROW row;
		std::cerr << "Stats from Variable_Name" << std::endl;
		while ((row = mysql_fetch_row(result)))
		{
			std::cerr << "stats_mysql_global: " << row[0] << " : " << row[1] << std::endl;
		}
		mysql_free_result(result);
	}
}

int main(int argc, char *argv[]) {
	cnt_transactions = 0;
	cnt_SELECT_outside_transactions = 0;
	cnt_expected_errors = 0;
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	username = cl.username;
	password = cl.password;
	host = cl.host;
	port = cl.port;

	{
		MYSQL *mysql=mysql_init(NULL);

		if (mysql==NULL) {
			exit(EXIT_FAILURE);
		}
		MYSQL *rc=mysql_real_connect(mysql, host, username, password, schema, (local ? 0 : port) , NULL, 0);
		if (rc==NULL) {
			if (silent==0) {
				fprintf(stderr,"%s\n", mysql_error(mysql));
			}
			exit(EXIT_FAILURE);
		}
		MYSQL_QUERY(mysql, "CREATE DATABASE IF NOT EXISTS test");
		MYSQL_QUERY(mysql, "CREATE TABLE IF NOT EXISTS test.test_savepoint(id INT NOT NULL AUTO_INCREMENT PRIMARY KEY) ENGINE=INNODB");
		MYSQL_QUERY(mysql, "DELETE FROM test.test_savepoint");
		MYSQL_QUERY(mysql, "INSERT INTO test.test_savepoint VALUES (1), (2)");

		mysql_close(mysql);
	}
	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value='false' where variable_name='mysql-enforce_autocommit_on_reads'");
	MYSQL_QUERY(mysqladmin, "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(mysqladmin, "DROP TABLE IF EXISTS mysql_query_rules_948");
	MYSQL_QUERY(mysqladmin, "CREATE TABLE mysql_query_rules_948 AS SELECT * FROM mysql_query_rules");
	MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_query_rules");
	MYSQL_QUERY(mysqladmin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	int MyHGM_myconnpoll_get = 0;
	std::string q;
	q = "SELECT * FROM stats_mysql_global WHERE variable_name IN ('MyHGM_myconnpoll_get','ConnPool_get_conn_immediate')";
	{
		if (mysql_query(mysqladmin, q.c_str())) {
			fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysqladmin));
			exit(EXIT_FAILURE);
		}
		MYSQL_RES *result = mysql_store_result(mysqladmin);
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(result)))
		{
			if (strcmp(row[0], "MyHGM_myconnpoll_get") == 0) {
				MyHGM_myconnpoll_get += atoi(row[1]);
			}
			if (strcmp(row[0], "ConnPool_get_conn_immediate") == 0) {
				MyHGM_myconnpoll_get += atoi(row[1]);
			}
		}
		mysql_free_result(result);
	}
	print_global_status(mysqladmin);
	print_commands_stats(mysqladmin);
	//num_threads = 4;
	//transactions = 200;
	//count = 10;

	// plan(transactions * num_threads + 1); // this was too verbose
	plan(1);

	if (debug_diag==true) {
		diag("Running test with debug enabled. Set debug_diag=false for less verbosity");
	} else {
		diag("Running test with debug disabled. Set debug_diag=true for more verbosity");
	}

	if (strcmp(host,"localhost")==0) {
		local = 1;
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
	{
		if (mysql_query(mysqladmin, q.c_str())) {
			fprintf(stderr,"Error running query: %s. Error: %s\n", q.c_str(), mysql_error(mysqladmin));
			exit(EXIT_FAILURE);
		}
		MYSQL_RES *result = mysql_store_result(mysqladmin);
		MYSQL_ROW row;
		int MyHGM_myconnpoll_get_post = 0;
		while ((row = mysql_fetch_row(result)))
		{
			if (strcmp(row[0], "MyHGM_myconnpoll_get") == 0) {
				MyHGM_myconnpoll_get_post += atoi(row[1]);
			}
			if (strcmp(row[0], "ConnPool_get_conn_immediate") == 0) {
				MyHGM_myconnpoll_get_post += atoi(row[1]);
			}
		}
		MyHGM_myconnpoll_get = MyHGM_myconnpoll_get_post - MyHGM_myconnpoll_get;
		mysql_free_result(result);
	}
	print_global_status(mysqladmin);
	print_commands_stats(mysqladmin);
	std::cerr << std::endl << "MyHGM_myconnpoll_get: " << MyHGM_myconnpoll_get << std::endl;
	std::cerr << "cnt_SELECT_outside_transactions: " << cnt_SELECT_outside_transactions << std::endl;
	std::cerr << "cnt_expected_errors: " << cnt_expected_errors << std::endl;
	std::cerr << "cnt_transactions: " << cnt_transactions << std::endl;
	//ok((MyHGM_myconnpoll_push == cnt_transactions+cnt_SELECT_outside_transactions) , "Number of transactions [%d] , Queries outside transaction [%d] , total connections returned [%d]", cnt_transactions.load(std::memory_order_relaxed), cnt_SELECT_outside_transactions.load(std::memory_order_relaxed), MyHGM_myconnpoll_push);
	// FIXME: until we fix the autocommit bug, we may have some minor mismatch
	//ok((MyHGM_myconnpoll_get <= cnt_transactions+cnt_SELECT_outside_transactions && MyHGM_myconnpoll_get >= cnt_transactions+cnt_SELECT_outside_transactions-10) , "Number of transactions [%d] , Queries outside transaction [%d] , total connections returned [%d]", cnt_transactions.load(std::memory_order_relaxed), cnt_SELECT_outside_transactions.load(std::memory_order_relaxed), MyHGM_myconnpoll_get);
	ok((MyHGM_myconnpoll_get == cnt_transactions+cnt_SELECT_outside_transactions) , "Number of transactions [%d] , Queries outside transaction [%d] , total connections returned [%d]", cnt_transactions.load(std::memory_order_relaxed), cnt_SELECT_outside_transactions.load(std::memory_order_relaxed), MyHGM_myconnpoll_get);
	MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_query_rules");
	MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_query_rules SELECT * FROM mysql_query_rules_948");
	MYSQL_QUERY(mysqladmin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	return exit_status();
}
