#include "proxysql.h"
#include "cpp.h"

#define QUERY1	"SELECT %u + ? + ? + ?"
#define DBG 0
#define ITERA	1000

#include <thread>

//MYSQL *mysql;
//MYSQL_STMT *stmt;
uint32_t statement_id;
uint16_t num_params;
uint16_t num_columns;
uint16_t warning_count;

std::mt19937 mt_rand(time(0));


int run_stmt(MYSQL_STMT *stmt, int int_data) {
	MYSQL_BIND bind[3];
	MYSQL_RES		 *prepare_meta_result;
	bind[0].buffer_type= MYSQL_TYPE_LONG;
	bind[0].buffer= (char *)&int_data;
	bind[0].is_null= 0;
	bind[0].length= 0;
	bind[1].buffer_type= MYSQL_TYPE_LONG;
	bind[1].buffer= (char *)&int_data;
	bind[1].is_null= 0;
	bind[1].length= 0;
	bind[2].buffer_type= MYSQL_TYPE_LONG;
	bind[2].buffer= (char *)&int_data;
	bind[2].is_null= 0;
	bind[2].length= 0;
	if (mysql_stmt_bind_param(stmt, bind)) {
		fprintf(stderr, " mysql_stmt_bind_param() failed\n");
		fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
		exit(EXIT_FAILURE);
	}
	prepare_meta_result = mysql_stmt_result_metadata(stmt); // FIXME: no error check
	if (mysql_stmt_execute(stmt)) {
		fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
		fprintf(stderr, " id=%lu , error=%s\n", stmt->stmt_id, mysql_stmt_error(stmt));
		exit(EXIT_FAILURE);
	}
//	memset(bind, 0, sizeof(bind));
	if (mysql_stmt_store_result(stmt)) {
		fprintf(stderr, " mysql_stmt_store_result() failed\n");
		fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
		exit(EXIT_FAILURE);
	}
	mysql_free_result(prepare_meta_result);
	return 0;
}


void run(MYSQL *mysql) {
	MYSQL_STMT *stmt;
	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		fprintf(stderr, " mysql_stmt_init(), out of memory\n");
		exit(EXIT_FAILURE);
	}
	uint32_t r=(uint32_t)mt_rand();
	r=r%30000;
	char *query=(char *)malloc(strlen(QUERY1)+16);
	sprintf(query,QUERY1,r);
	if (DBG) {
		fprintf(stdout,"%s\n",query);
	}
	//if (mysql_stmt_prepare(stmt, QUERY1, strlen(QUERY1))) {
	if (mysql_stmt_prepare(stmt, query, strlen(query))) {
		fprintf(stderr, " mysql_stmt_prepare(), failed: %d,  %s\n" , mysql_errno(mysql), mysql_stmt_error(stmt));
		exit(EXIT_FAILURE);
	}
	free(query);
//	param_count= mysql_stmt_param_count(stmt);
//	fprintf(stdout, " total parameters in Query1 : %d\n", param_count);
	statement_id=stmt->stmt_id;
	num_params=stmt->param_count;
	num_columns=stmt->field_count;
	warning_count=stmt->upsert_status.warning_count;
	if (DBG) {
		fprintf(stdout, "statement_id=%d , columns=%d , params=%d , warnings=%d\n", statement_id, num_columns, num_params, warning_count);
	}
	run_stmt(stmt,(uint32_t)mt_rand()%1000000);
	mysql_stmt_close(stmt);
}

int m_thread() {
	MYSQL *mysql;
	mysql = mysql_init(NULL);
	if (!mysql_real_connect(mysql,"127.0.0.1","msandbox","msandbox","test",6033,NULL,0)) {
	//if (!mysql_real_connect(mysql,"127.0.0.1","root","","test",3306,NULL,0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		exit(EXIT_FAILURE);
	}
	int i;
	for (i=0;i<ITERA;i++) {
		run(mysql);
	}
	return 0;
}

int main() {
#define NTH 10
	int i;
	std::thread *thr[NTH];
	for (i=0;i<NTH;i++) {
		thr[i] = new std::thread(&m_thread);
	}
	for (i=0;i<NTH;i++) {
		thr[i]->join();
	}
	return 0;
}
