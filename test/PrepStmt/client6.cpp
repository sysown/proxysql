#define PROXYSQL_EXTERN
#include "proxysql.h"
#include "cpp.h"

#include <ctime>
#include <thread>

#define QUERY1	"SELECT ?"
#define NUMPREP	100000
#define NUMPRO	20000
//#define NUMPREP	160
//#define NUMPRO	4
#define LOOPS	1
#define USER	"root"
#define SCHEMA	"test"

#define NTHREADS	4

MySQL_STMT_Manager *GloMyStmt;
Query_Cache *GloQC;
MySQL_Authentication *GloMyAuth;
Query_Processor *GloQPro;
ProxySQL_Admin *GloAdmin;
MySQL_Threads_Handler *GloMTH;
MySQL_Monitor *GloMyMon;
std::thread *MyMon_thread;

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
		exit(EXIT_FAILURE);
	}
	prepare_meta_result = mysql_stmt_result_metadata(stmt); // FIXME: no error check
	if (mysql_stmt_execute(stmt)) {
		fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
		fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
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


void * mysql_thread(int tid) {
	std::mt19937 mt_rand(time(0));


	thread_data_t *THD;
	THD=GloThrData[tid];

	MySQL_Thread *worker = new MySQL_Thread();
	worker->init();

	MySrvC *mysrvc=new MySrvC((char *)"127.0.0.1", 3306, 100, MYSQL_SERVER_STATUS_ONLINE, 100, 0, 0, 0, 10000);

	{
		int i;
		MySQL_Session **SESS=(MySQL_Session **)malloc(16*sizeof(MySQL_Session *));
		
		for (i=0; i<16; i++) {
			SESS[i]=new MySQL_Session();
			MySQL_Session *sess=SESS[i];
			sess->mirror==true;
			sess->client_myds=NULL;
			sess->client_myds = new MySQL_Data_Stream();
			sess->client_myds->DSS=STATE_SLEEP;
			sess->client_myds->sess=sess;
			sess->client_myds->myds_type=MYDS_FRONTEND;
			sess->client_myds->PSarrayOUT= new PtrSizeArray();
			worker->register_session(sess);
			sess->current_hostgroup=0;
			sess->default_hostgroup=0;
			sess->mybe=sess->find_or_create_backend(sess->current_hostgroup);
			MySQL_Connection *myconn=new MySQL_Connection();
			sess->mybe->server_myds->attach_connection(myconn);
			myconn->userinfo->set((char *)"root",(char *)"",(char *)"information_schema");
			myconn->local_stmts = new MySQL_STMTs_local();
			//myconn->mysql=mysql_init(NULL);
			myconn->parent=mysrvc;
			/*
			if (!mysql_real_connect(myconn->mysql,"127.0.0.1",USER,"",SCHEMA,3306,NULL,0)) {
				fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(myconn->mysql));
				exit(EXIT_FAILURE);
  		}*/
			myconn->handler(0);
			if (myconn->mysql==NULL) {
				myconn->handler(0);
			}
		}
		for (i=0; i<16; i++) {
			MySQL_Session *sess=SESS[i];
			sess->status=PROCESSING_QUERY;
			sess->handler();
		}
	}

/*
	// in this version, each mysql thread has just ONE connection
	// for now we use blocking API
	MYSQL *mysql;

	//MYSQL_STMT **stmt;

	// we intialize the local mapping : MySQL_STMTs_local()
	MySQL_STMTs_local *local_stmts=new MySQL_STMTs_local();

	// we initialize a MYSQL structure
	THD->mysql = mysql_init(NULL);
	mysql=THD->mysql;

	char buff[128];
	unsigned int bl=0;

	// we establish a connection to the database
	if (!mysql_real_connect(mysql,"127.0.0.1",USER,"",SCHEMA,3306,NULL,0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		exit(EXIT_FAILURE);
	}
	int i;

	// array of (MYSQL_STMT *) ; we don't use it in this version
	//stmt=(MYSQL_STMT **)malloc(sizeof(MYSQL_STMT*)*NUMPREP);
	
	MYSQL_STMT *stmt;
	{
	cpu_timer t;
	// in this loop we create only some the prepared statements
	for (i=0; i<NUMPREP/100; i++) {
		sprintf(buff,"SELECT %u + ?",(uint32_t)mt_rand()%NUMPRO);
		bl=strlen(buff);
		uint64_t hash=local_stmts->compute_hash(0,(char *)USER,(char *)SCHEMA,buff,bl);
		MySQL_STMT_Global_info *a=GloMyStmt->find_prepared_statement_by_hash(hash);
		if (a==NULL) { // no prepared statement was found in global
			stmt = mysql_stmt_init(mysql);
			if (!stmt) {
				fprintf(stderr, " mysql_stmt_init(), out of memory\n");
				exit(EXIT_FAILURE);
			}
			if (mysql_stmt_prepare(stmt, buff, bl)) { // the prepared statement is created
				fprintf(stderr, " mysql_stmt_prepare(), failed: %s\n" , mysql_stmt_error(stmt));
				exit(EXIT_FAILURE);
			}
			uint32_t stmid=GloMyStmt->add_prepared_statement(0,(char *)USER,(char *)SCHEMA,buff,bl,stmt);
			if (NUMPRO < 32)
				fprintf(stdout, "SERVER_statement_id=%lu , PROXY_statement_id=%u\n", stmt->stmt_id, stmid);
			local_stmts->insert(stmid,stmt);
			}
	}
	fprintf(stdout, "Prepared statements: %u client, %u proxy/server. ", i, GloMyStmt->total_prepared_statements());
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
		fprintf(stdout, "Found    %u prepared statements searching by hash in: ", founds);
	}

	{
		unsigned int founds=0;
		unsigned int created=0;
		unsigned int executed=0;
		cpu_timer t;
		for (i=0; i<NUMPREP*LOOPS; i++) {
			sprintf(buff,"SELECT %u + ?",(uint32_t)mt_rand()%NUMPRO);
			bl=strlen(buff);
			uint64_t hash=local_stmts->compute_hash(0,(char *)USER,(char *)SCHEMA,buff,bl);
			MySQL_STMT_Global_info *a=GloMyStmt->find_prepared_statement_by_hash(hash);
			if (a) {
				// we have a prepared statement, we can run it
				MYSQL_STMT *stm=local_stmts->find(a->statement_id);
				if (stm) { // the statement exists in local
					run_stmt(stm,(uint32_t)mt_rand());
					founds++;
					executed++;
					local_stmts->erase(a->statement_id);
				} else { // the statement doesn't exist locally
					stmt = mysql_stmt_init(mysql);	
					if (!stmt) {
						fprintf(stderr, " mysql_stmt_init(), out of memory\n");
						exit(EXIT_FAILURE);
					}
					if (mysql_stmt_prepare(stmt, buff, bl)) { // the prepared statement is created
						fprintf(stderr, " mysql_stmt_prepare(), failed: %s\n" , mysql_stmt_error(stmt));
						exit(EXIT_FAILURE);
					}
					local_stmts->insert(a->statement_id,stmt);
					run_stmt(stmt,(uint32_t)mt_rand());
					created++;
					executed++;
					local_stmts->erase(a->statement_id);
				}
			} else { // no prepared statement was found in global
				stmt = mysql_stmt_init(mysql);	
				if (!stmt) {
					fprintf(stderr, " mysql_stmt_init(), out of memory\n");
					exit(EXIT_FAILURE);
				}
				if (mysql_stmt_prepare(stmt, buff, bl)) { // the prepared statement is created
					fprintf(stderr, " mysql_stmt_prepare(), failed: %s\n" , mysql_stmt_error(stmt));
					exit(EXIT_FAILURE);
				}
				uint32_t stmid=GloMyStmt->add_prepared_statement(0,(char *)USER,(char *)SCHEMA,buff,bl,stmt);
				if (NUMPRO < 32)
					fprintf(stdout, "SERVER_statement_id=%lu , PROXY_statement_id=%u\n", stmt->stmt_id, stmid);
				local_stmts->insert(stmid,stmt);
				run_stmt(stmt,(uint32_t)mt_rand());
				created++;
				executed++;
				local_stmts->erase(stmid);
			}
		}
		fprintf(stdout, "Found %u , created %u and executed %u prepared statements in: ", founds, created, executed);
	}
*/
/*
	{
		// for comparison, we run also queries in TEXT protocol
		cpu_timer t;
		for (i=0; i<NUMPREP*LOOPS; i++) {
			sprintf(buff,"SELECT %u + %u",i,(uint32_t)mt_rand()%NUMPRO);
			bl=strlen(buff);
			int rc=mysql_real_query(mysql,buff,bl);
			if (rc) {
				fprintf(stderr, " mysql_real_query(), failed: %s\n" , mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
			MYSQL_RES *res=mysql_store_result(mysql);
			if (res==NULL) {
				fprintf(stderr, " mysql_store_result(), failed: %s\n" , mysql_error(mysql));
				exit(EXIT_FAILURE);
			}
			mysql_free_result(res);
		}
		fprintf(stdout, "Executed %u queries in: ", i);
	}
	return 0;
*/
}

int main() {
	// initialize mysql
	mysql_library_init(0,NULL,NULL);

	sqlite3_config(SQLITE_CONFIG_URI, 1);

	MyHGM=new MySQL_HostGroups_Manager();
	GloMTH=new MySQL_Threads_Handler();
	GloMyLogger = new MySQL_Logger();

	GloVars.datadir=(char *)".";
	GloVars.admindb=(char *)"proxysql.db";
	GloAdmin = new ProxySQL_Admin();
  GloAdmin->init();

	// create a new MySQL_STMT_Manager()
	GloMyStmt=new MySQL_STMT_Manager();
	GloThrData = (thread_data_t **)malloc(sizeof(thread_data_t *)*NTHREADS);

	// starts N threads
	int i;
	for (i=0; i<NTHREADS; i++) {
		GloThrData[i]=(thread_data_t *)malloc(sizeof(thread_data_t));
		GloThrData[i]->thread = new std::thread(&mysql_thread,i);
	}
	while (glovars.shutdown==0) {
		sleep(1);   // FIXME: TERRIBLE UGLY
	}
	// wait for the threads to complete
	for (i=0; i<NTHREADS; i++) {
		GloThrData[i]->thread->join();
	}
	return 0;
}
