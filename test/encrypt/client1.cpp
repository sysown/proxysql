#include "proxysql.h"
#include "cpp.h"

#include <ctime>
#include <thread>

#define QUERY1	"SELECT ?"
#define NUMPREP	100000
#define NUMPRO	1000
#define NTHREADS	8

int shutdown_test=0;

typedef struct _thread_data_t {
	std::thread *thread;
	MYSQL *mysql;
	MYSQL_STMT **stmt;
} thread_data_t;


thread_data_t **GloThrData;

void * mysql_thread(int tid) {
	std::thread::id this_id = std::this_thread::get_id();
	std::hash<std::thread::id> hasher;
	std::mt19937 mt_rand(time(0)*hasher(this_id));
	MYSQL *mysql=mysql_init(NULL);
	if (!mysql_real_connect(mysql,"127.0.0.1","admin","admin","main",6032,NULL,0)) {
		fprintf(stderr, "Failed to connect: Error: %s\n", mysql_error(mysql));
		exit(EXIT_FAILURE);
	}
	char *query=NULL;
	while (__sync_fetch_and_add(&shutdown_test,0)==0) {
		if ((uint32_t)mt_rand()%10) { // reconnect
			mysql_close(mysql);
			mysql=mysql_init(NULL);
			if (!mysql_real_connect(mysql,"127.0.0.1","msandbox","msandbox",NULL,6033,NULL,0)) {
				fprintf(stderr, "Failed to connect: Error: %s\n", mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
		}
		query=(char *)"SELECT 1";
		if (mysql_query(mysql,query)) {
			fprintf(stderr, "Failed to run query: \"%s\" . Error: %s\n", query, mysql_error(mysql));
			exit(EXIT_FAILURE);
		}
		MYSQL_RES *result = mysql_store_result(mysql);
		mysql_free_result(result);
	}
	return NULL;
}

void * setup_admin() {
	std::thread::id this_id = std::this_thread::get_id();
	std::hash<std::thread::id> hasher;
	std::mt19937 mt_rand(time(0)*hasher(this_id));
	bool multiplex[2] = {false,false};
	bool hashed[2] = {false,false};
	MYSQL *mysql=mysql_init(NULL);
	if (!mysql_real_connect(mysql,"127.0.0.1","admin","admin","main",6032,NULL,0)) {
		fprintf(stderr, "Failed to connect to admin : Error: %s\n", mysql_error(mysql));
		exit(EXIT_FAILURE);
	}
	char *query=NULL;
	while (__sync_fetch_and_add(&shutdown_test,0)==0) {
		usleep(1000000);
		multiplex[0]=multiplex[1];
		if ((uint32_t)mt_rand()%2) {
			query=(char *)"SET mysql-multiplexing='true'";
			multiplex[1]=true;
		} else {
			query=(char *)"SET mysql-multiplexing='false'";
			multiplex[1]=false;
		}
		if (multiplex[0]!=multiplex[1]) {
			if (mysql_query(mysql,query)) {
				fprintf(stderr, "Failed to run query to admin : \"%s\" . Error: %s\n", query, mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
			query=(char *)"LOAD MYSQL VARIABLES TO RUNTIME";
			if (mysql_query(mysql,query)) {
				fprintf(stderr, "Failed to run query to admin : \"%s\" . Error: %s\n", query, mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
		}
		usleep(100000);
		hashed[0]=hashed[1];
		if ((uint32_t)mt_rand()%2) {
			query=(char *)"UPDATE mysql_users SET password='msandbox' WHERE username='msandbox'";
			hashed[1]=false;
		} else {
			query=(char *)"UPDATE mysql_users SET password='*6c387fc3893dba1e3ba155e74754da6682d04747' WHERE username='msandbox'";
			hashed[1]=true;
		}	
		if (hashed[0]!=hashed[1]) {
			if (mysql_query(mysql,query)) {
				fprintf(stderr, "Failed to run query to admin : \"%s\" . Error: %s\n", query, mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
			query=(char *)"LOAD MYSQL USERS TO RUNTIME";
			if (mysql_query(mysql,query)) {
				fprintf(stderr, "Failed to run query to admin : \"%s\" . Error: %s\n", query, mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
		}
	}
	return NULL;
}
			
int main() {
	// initialize mysql
	mysql_library_init(0,NULL,NULL);

	// create a new MySQL_STMT_Manager()
	//GloMyStmt=new MySQL_STMT_Manager();

	std::thread *admin_thread=new std::thread(&setup_admin);

	GloThrData = (thread_data_t **)malloc(sizeof(thread_data_t *)*NTHREADS);
	// starts N threads
	int i;
	
	for (i=0; i<NTHREADS; i++) {
		GloThrData[i]=(thread_data_t *)malloc(sizeof(thread_data_t));
		GloThrData[i]->thread = new std::thread(&mysql_thread,i);
	}
	sleep(30);
	__sync_fetch_and_add(&shutdown_test,1);
	admin_thread->join();
	// wait for the threads to complete
	for (i=0; i<NTHREADS; i++) {
		GloThrData[i]->thread->join();
	}
	return 0;
}
