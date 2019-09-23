#define PROXYSQL_EXTERN
#include "proxysql.h"
#include "cpp.h"

#include <ctime>
#include <thread>
#include <random>

#define QUERY1	"SELECT ?"
#define NUMPREP	100000
#define NUMPRO	20000
//#define NUMPREP	160
//#define NUMPRO	4
#define LOOPS	1
#define USER	"root"
#define SCHEMA	"test"

#define NTHREADS	4

MySQL_Logger *GloMyLogger;


typedef struct _thread_data_t {
	std::thread *thread;
	MYSQL *mysql;
	MYSQL_STMT **stmt;
} thread_data_t;


thread_data_t **GloThrData;

struct cpu_timer
{
	~cpu_timer()
	{
		auto end = std::clock() ;
		std::cout << double( end - begin ) / CLOCKS_PER_SEC << " secs.\n" ;
	};

	const std::clock_t begin = std::clock() ;
};


int run_stmt(MYSQL_STMT *stmt, int int_data) {
	MYSQL_BIND bind[1];
	MYSQL_RES     *prepare_meta_result;
	bind[0].buffer_type= MYSQL_TYPE_LONG;
	bind[0].buffer= (char *)&int_data;
	bind[0].is_null= 0;
	bind[0].length= 0;

	if (mysql_stmt_bind_param(stmt, bind)) {
		fprintf(stderr, " mysql_stmt_bind_param() failed\n");
		fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
//		exit(EXIT_FAILURE);
	}
	prepare_meta_result = mysql_stmt_result_metadata(stmt); // FIXME: no error check

	if (mysql_stmt_execute(stmt)) {
		fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
		fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
//		exit(EXIT_FAILURE);
	}

//	memset(bind, 0, sizeof(bind));
	if (mysql_stmt_store_result(stmt)) {
		fprintf(stderr, " mysql_stmt_store_result() failed\n");
		fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
//		exit(EXIT_FAILURE);
	}

	mysql_free_result(prepare_meta_result);
	return 0;
}


void * mysql_thread(const std::string& username, int tid) {
	std::mt19937 mt_rand(time(0) + tid);

	MYSQL *mysql;
	MYSQL_STMT *stmt;

	mysql = mysql_init(NULL);

	char buff[128];
	unsigned int bl=0;
	if (!mysql_real_connect(mysql,"127.0.0.1",username.c_str(),username.c_str(),SCHEMA,6033,NULL,0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
			return NULL;
	}
	for(;;) {

		stmt = mysql_stmt_init(mysql);

		if (!stmt) {
			fprintf(stderr, " mysql_stmt_init(), out of memory\n");
			return NULL;
		}
		sprintf(buff,"SELECT %u + ?",(uint32_t)mt_rand()%NUMPRO);

		if (mysql_stmt_prepare(stmt, buff, bl)) { // the prepared statement is created
			fprintf(stderr, " mysql_stmt_prepare(), failed: %s\n" , mysql_stmt_error(stmt));
			return NULL;
		}

		run_stmt(stmt,(uint32_t)mt_rand());

		if(mysql_stmt_close(stmt)) {
			fprintf(stderr, " mysql_stmt_close(), failed: %s\n" , mysql_stmt_error(stmt));
			return NULL;
		}

		uint32_t delay = (mt_rand()%5000) * 1000;
		usleep(delay);
	}
	return NULL;
}

#define NTHR 20
int main() {
	// initialize mysql
	mysql_library_init(0,NULL,NULL);
	std::vector<std::thread*> threads(NTHR);

	for (int i = 1; i<=NTHR; i++) {
		std::string name = "user" + std::to_string(i);
		threads[i-1]= new std::thread(&mysql_thread, name, i);
	}

	for (int i = 0; i < NTHR; i++)
		threads[i]->join();
}
