#include "proxysql.h"
#include "cpp.h"

#include <ctime>

#define QUERY1	"SELECT ?"
#define NUMPREP	1000000
#define NUMPRO	10000
//#define NUMPREP	160
//#define NUMPRO	4
#define LOOPS	10
#define USER	"root"
#define SCHEMA	"test"
MYSQL *mysql;
MYSQL_STMT **stmt;
uint32_t statement_id;
uint16_t num_params;
uint16_t num_columns;
uint16_t warning_count;

MySQL_STMT_Manager *GloMyStmt;

struct cpu_timer
{
	~cpu_timer()
	{
		auto end = std::clock() ;
		std::cout << double( end - begin ) / CLOCKS_PER_SEC << " secs.\n" ;
	};

	const std::clock_t begin = std::clock() ;
};


int main() {
	std::mt19937 mt_rand(time(0));
	GloMyStmt=new MySQL_STMT_Manager();
	MySQL_STMTs_local *local_stmts=new MySQL_STMTs_local();
	mysql = mysql_init(NULL);
	char buff[128];
	unsigned int bl=0;
	if (!mysql_real_connect(mysql,"127.0.0.1",USER,"",SCHEMA,3306,NULL,0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		exit(EXIT_FAILURE);
	}
	int i;
	stmt=(MYSQL_STMT **)malloc(sizeof(MYSQL_STMT*)*NUMPREP);
	{
	cpu_timer t;
	for (i=0; i<NUMPREP; i++) {
		stmt[i] = mysql_stmt_init(mysql);
		if (!stmt[i]) {
			fprintf(stderr, " mysql_stmt_init(), out of memory\n");
			exit(EXIT_FAILURE);
		}
		sprintf(buff,"SELECT %u + ?",(uint32_t)mt_rand()%NUMPRO);
		bl=strlen(buff);
		uint64_t hash=local_stmts->compute_hash(0,(char *)USER,(char *)SCHEMA,buff,bl);
		MySQL_STMT_Global_info *a=GloMyStmt->find_prepared_statement_by_hash(hash);
		if (a==NULL) {
			if (mysql_stmt_prepare(stmt[i], buff, bl)) {
				fprintf(stderr, " mysql_stmt_prepare(), failed: %s\n" , mysql_stmt_error(stmt[i]));
				exit(EXIT_FAILURE);
			}
			uint32_t a=GloMyStmt->add_prepared_statement(0,(char *)USER,(char *)SCHEMA,buff,bl,stmt[i]);
			if (NUMPRO < 32)
				fprintf(stdout, "SERVER_statement_id=%lu , PROXY_statement_id=%u\n", stmt[i]->stmt_id, a);
			}
		}
	fprintf(stdout, "Prepared statements: %u client, %u proxy/server. ", NUMPREP, GloMyStmt->total_prepared_statements());
	fprintf(stdout, "Created in: ");
	}
	{
		unsigned int founds=0;
		cpu_timer t;
		for (i=0; i<NUMPREP*LOOPS; i++) {
			sprintf(buff,"SELECT %u + ?",(uint32_t)mt_rand()%NUMPRO);
			bl=strlen(buff);
			//uint64_t hash=local_stmts->compute_hash(0,(char *)USER,(char *)SCHEMA,buff,bl);
			//MySQL_STMT_Global_info *a=GloMyStmt->find_prepared_statement_by_hash(hash);
			//if (a) founds++;
		}
		fprintf(stdout, "Computed %u random strings in: ", i);
	}
	{
		unsigned int founds=0;
		cpu_timer t;
		for (i=0; i<NUMPREP*LOOPS; i++) {
			sprintf(buff,"SELECT %u + ?",(uint32_t)mt_rand()%NUMPRO);
			bl=strlen(buff);
			uint64_t hash=local_stmts->compute_hash(0,(char *)USER,(char *)SCHEMA,buff,bl);
			//MySQL_STMT_Global_info *a=GloMyStmt->find_prepared_statement_by_hash(hash);
			//if (a) founds++;
		}
		fprintf(stdout, "Computed %u hashes in: ", i);
	}
	{
		unsigned int founds=0;
		cpu_timer t;
		for (i=0; i<NUMPREP*LOOPS; i++) {
			sprintf(buff,"SELECT %u + ?",(uint32_t)mt_rand()%NUMPRO);
			bl=strlen(buff);
			uint64_t hash=local_stmts->compute_hash(0,(char *)USER,(char *)SCHEMA,buff,bl);
			MySQL_STMT_Global_info *a=GloMyStmt->find_prepared_statement_by_hash(hash);
			if (a) founds++;
		}
		fprintf(stdout, "Found %u prepared statements searching by hash in: ", founds);
	}
//	param_count= mysql_stmt_param_count(stmt);
//	fprintf(stdout, " total parameters in Query1 : %d\n", param_count);
//	statement_id=stmt->stmt_id;
//	num_params=stmt->param_count;
//	num_columns=stmt->field_count;
//	warning_count=stmt->upsert_status.warning_count;
//	fprintf(stdout, "statement_id=%d , columns=%d , params=%d , warnings=%d\n", statement_id, num_columns, num_params, warning_count);
	return 0;
}
