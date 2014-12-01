#include "proxysql.h"




#ifdef DEBUG
#ifdef DEBUG_EXTERN
#undef DEBUG_EXTERN
#endif /* DEBUG_EXTERN */
#endif /* DEBUG */

//extern debug_level *gdbg_lvl;
//extern int gdbg;


void crash_handler(int sig) {
#ifdef DEBUG
	//g_mem_profile();
	malloc_stats_print(NULL, NULL, "");
#endif
	void *arr[20];
	size_t s;

	s = backtrace(arr, 20);

	fprintf(stderr, "Error: signal %d:\n", sig);
	backtrace_symbols_fd(arr, s, STDERR_FILENO);
	exit(EXIT_FAILURE);
}

/*
void proxy_debug_func(enum debug_module module, int verbosity, const char *fmt, ...) {
	assert(module<PROXY_DEBUG_UNKNOWN);
	if (gdbg_lvl[module].verbosity < verbosity) return;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
};
*/

#define DEBUG_MSG_MAXSIZE	256

#ifdef DEBUG
void proxy_debug_func(enum debug_module module, int verbosity, int thr, const char *__file, int __line, const char *__func, const char *fmt, ...) {
	assert(module<PROXY_DEBUG_UNKNOWN);
//	if (gdbg_lvl[module].verbosity < verbosity) return;
	if (proxysql_foreground) {
		char debugbuff[DEBUG_MSG_MAXSIZE];
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(debugbuff, DEBUG_MSG_MAXSIZE,fmt,ap);
		va_end(ap);
		fprintf(stderr, "%d:%s:%d:%s(): LVL#%d : %s" , thr, __file, __line, __func, verbosity, debugbuff);
		return;
	}
/*
	//dbg_msg_t *dbg_msg=g_slice_alloc(sizeof(dbg_msg_t));
	SPIN_LOCK(glo_debug->glock);
	//dbg_msg_t *dbg_msg=g_malloc(sizeof(dbg_msg_t));
	dbg_msg_t *dbg_msg=__l_alloc(glo_debug->sfp,sizeof(dbg_msg_t));
	SPIN_UNLOCK(glo_debug->glock);
  gettimeofday(&dbg_msg->tv, NULL);
	dbg_msg->thr=thr;
	//dbg_msg->file=g_strdup(__file);
	dbg_msg->module=module;
	dbg_msg->file=(char *)__file;
	dbg_msg->line=__line;
	//dbg_msg->func=g_strdup(__func);
	dbg_msg->func=(char *)__func;
	dbg_msg->verb=verbosity;
	while (__sync_fetch_and_add(&glo_debug->msg_count,0)>9000) {usleep(10000); }
	SPIN_LOCK(glo_debug->glock);
	__sync_fetch_and_add(&glo_debug->msg_count,1);
	dbg_msg->msg=__l_alloc(glo_debug->sfp,DEBUG_MSG_MAXSIZE);
	SPIN_UNLOCK(glo_debug->glock);
	va_list ap;
	va_start(ap, fmt);
	//vfprintf(stderr, fmt, ap);
	vsnprintf(dbg_msg->msg,DEBUG_MSG_MAXSIZE,fmt,ap);
	va_end(ap);
	//memcpy(dbg_msg->msg,debugbuff,DEBUG_MSG_MAXSIZE);
	//dbg_msg->msg=g_strdup(debugbuff);
	g_async_queue_push(glo_debug->async_queue,dbg_msg);
*/
};
#endif

void proxy_error_func(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);	
};

void init_debug_struct() {
	int i;
	gdbg_lvl= (debug_level *) malloc(PROXY_DEBUG_UNKNOWN*sizeof(debug_level));
	for (i=0;i<PROXY_DEBUG_UNKNOWN;i++) {
		gdbg_lvl[i].module=(enum debug_module)i;
		gdbg_lvl[i].verbosity=( gdbg ? INT_MAX : 0 );
		gdbg_lvl[i].name=(char *)NULL;
	}
	gdbg_lvl[PROXY_DEBUG_GENERIC].name=(char *)"debug_generic"; 
	gdbg_lvl[PROXY_DEBUG_NET].name=(char *)"debug_net";
	gdbg_lvl[PROXY_DEBUG_PKT_ARRAY].name=(char *)"debug_pkt_array";
	gdbg_lvl[PROXY_DEBUG_POLL].name=(char *)"debug_poll";
	gdbg_lvl[PROXY_DEBUG_MYSQL_COM].name=(char *)"debug_mysql_com";
	gdbg_lvl[PROXY_DEBUG_MYSQL_SERVER].name=(char *)"debug_mysql_server";
	gdbg_lvl[PROXY_DEBUG_MYSQL_CONNECTION].name=(char *)"debug_mysql_connection";
	gdbg_lvl[PROXY_DEBUG_MYSQL_RW_SPLIT].name=(char *)"debug_mysql_rw_split";
	gdbg_lvl[PROXY_DEBUG_MYSQL_AUTH].name=(char *)"debug_mysql_auth";
	gdbg_lvl[PROXY_DEBUG_MEMORY].name=(char *)"debug_memory";
	gdbg_lvl[PROXY_DEBUG_ADMIN].name=(char *)"debug_admin";
	gdbg_lvl[PROXY_DEBUG_SQLITE].name=(char *)"debug_sqlite";
	gdbg_lvl[PROXY_DEBUG_IPC].name=(char *)"debug_ipc";
	gdbg_lvl[PROXY_DEBUG_QUERY_CACHE].name=(char *)"debug_query_cache";
	gdbg_lvl[PROXY_DEBUG_QUERY_STATISTICS].name=(char *)"debug_query_statistics";

	for (i=0;i<PROXY_DEBUG_UNKNOWN;i++) {
		// if this happen, the above table is not populated correctly
		assert(gdbg_lvl[i].name!=NULL);
	}
}

/*
#ifdef DEBUG
void *debug_logger() {
	FILE *debugfile=fopen(glovars.proxy_debuglog, "a+");
	if (debugfile==NULL) {
		fprintf(stderr,"Impossibe to open debug log %s : %s\n", glovars.proxy_debuglog, strerror(errno));
		exit(EXIT_SUCCESS);
	}
	time_t lt=0;
	sqlite3 *db=sqlite3debugdb;
	sqlite3_stmt *statement;
	int rc;

	char *query="INSERT INTO debug_log (timestamp, thread_id, module, filename, line, funct, level, message) VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6 , ?7 , ?8)";
	rc=sqlite3_prepare_v2(db, query, -1, &statement, 0);
	assert(rc==SQLITE_OK);
	sqlite3_exec_exit_on_failure(db,"BEGIN TRANSACTION");
	
	while(glovars.shutdown==0) {
		dbg_msg_t *dbg_msg=g_async_queue_timeout_pop(glo_debug->async_queue,1000000);
		if (dbg_msg) {
//			char __buffer[25];
//			char __buffer2[35];
//		struct timeval tv;
//  	gettimeofday(&tv, NULL);
//			struct tm *__tm_info=localtime(&dbg_msg->tv.tv_sec);
//			strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info);
//			sprintf(__buffer2, "%s:06%d", __buffer, (int)dbg_msg->tv.tv_usec);
//			sqlite3_exec_exit_on_failure(db,"BEGIN TRANSACTION");
			__sqlite3_debugdb__flush_debugs(statement, dbg_msg);
//			sqlite3_exec_exit_on_failure(db,"COMMIT");
//			fprintf(debugfile, "%s:%06d %d:%s:%d:%s(): LVL#%d : %s" , __buffer, (int)dbg_msg->tv.tv_usec, dbg_msg->thr, dbg_msg->file, dbg_msg->line, dbg_msg->func, dbg_msg->verb, dbg_msg->msg);
			if (dbg_msg->tv.tv_sec > lt + 4) {
				lt=dbg_msg->tv.tv_sec;
				fflush(debugfile);
				sqlite3_exec_exit_on_failure(db,"COMMIT");
				sqlite3_exec_exit_on_failure(db,"BEGIN TRANSACTION");
			}
			//g_free(dbg_msg->file);
			//g_free(dbg_msg->func);
	SPIN_LOCK(glo_debug->glock);
	__l_free(glo_debug->sfp,DEBUG_MSG_MAXSIZE, dbg_msg->msg);
	__sync_fetch_and_sub(&glo_debug->msg_count,1);
	__l_free(glo_debug->sfp, sizeof(dbg_msg_t), dbg_msg);
	//g_free(dbg_msg);
	SPIN_UNLOCK(glo_debug->glock);
		//	g_free(dbg_msg->msg);
			//g_slice_free1(sizeof(dbg_msg_t *),dbg_msg);
		} else {
			//sqlite3_exec_exit_on_failure(db,"COMMIT");
		}
	}
	return NULL;
}
#endif
*/
