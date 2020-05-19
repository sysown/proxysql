#include "proxysql.h"
#include "proxysql_atomic.h"
#include <cxxabi.h>


#ifdef DEBUG
#ifdef DEBUG_EXTERN
#undef DEBUG_EXTERN
#endif /* DEBUG_EXTERN */
#endif /* DEBUG */

#define PROXYSQL_DEBUG_PTHREAD_MUTEX

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC SYSTEM_CLOCK
#endif // CLOCK_MONOTONIC

#ifdef DEBUG
static unsigned long long pretime=0;
#ifdef PROXYSQL_DEBUG_PTHREAD_MUTEX
static pthread_mutex_t debug_mutex;
#else
static spinlock debug_spinlock;
#endif
#endif /* DEBUG */

static inline unsigned long long debug_monotonic_time() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}


#define DEBUG_MSG_MAXSIZE	1024

#ifdef DEBUG

void proxy_debug_func(enum debug_module module, int verbosity, int thr, const char *__file, int __line, const char *__func, const char *fmt, ...) {
	assert(module<PROXY_DEBUG_UNKNOWN);
	if (GloVars.global.gdbg_lvl[module].verbosity < verbosity) return;
	char debugbuff[DEBUG_MSG_MAXSIZE];
	char longdebugbuff[DEBUG_MSG_MAXSIZE*8];
	longdebugbuff[0]=0;
	if (GloVars.global.foreground) {
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(debugbuff, DEBUG_MSG_MAXSIZE,fmt,ap);
		va_end(ap);
#ifdef PROXYSQL_DEBUG_PTHREAD_MUTEX
		pthread_mutex_lock(&debug_mutex);
#else
		spin_lock(&debug_spinlock);
#endif
		unsigned long long curtime=debug_monotonic_time();
		//fprintf(stderr, "%d:%s:%d:%s(): MOD#%d LVL#%d : %s" , thr, __file, __line, __func, module, verbosity, debugbuff);
		sprintf(longdebugbuff, "%llu(%llu): %d:%s:%d:%s(): MOD#%d#%s LVL#%d : %s" , curtime, curtime-pretime, thr, __file, __line, __func, module, GloVars.global.gdbg_lvl[module].name, verbosity, debugbuff);
		pretime=curtime;
	}
#ifdef __GLIBC__
	if (GloVars.global.gdbg_lvl[module].verbosity>=10) {
		void *arr[20];
		char **strings;
		int s;
		s = backtrace(arr, 20);
		//backtrace_symbols_fd(arr, s, STDERR_FILENO);
		strings=backtrace_symbols(arr,s);
		if (strings == NULL) {
			perror("backtrace_symbols");
			exit(EXIT_FAILURE);
		}
		for (int i=0; i<s; i++) {
			//printf("%s\n", strings[i]);
			debugbuff[0]=0;
			sscanf(strings[i], "%*[^(](%100[^+]", debugbuff);
			int status;
			char *realname=NULL;
			realname=abi::__cxa_demangle(debugbuff, 0, 0, &status);
			if (realname) {
				sprintf(debugbuff," ---- %s : %s\n", strings[i], realname);
				strcat(longdebugbuff,debugbuff);
			}
		}
		//printf("\n");
		strcat(longdebugbuff,"\n");
		free(strings);
//	} else {
//		fprintf(stderr, "%s", longdebugbuff);
	}
#endif
	if (strlen(longdebugbuff)) fprintf(stderr, "%s", longdebugbuff);
#ifdef PROXYSQL_DEBUG_PTHREAD_MUTEX
	pthread_mutex_unlock(&debug_mutex);
#else
	spin_unlock(&debug_spinlock);
#endif
	if (GloVars.global.foreground) {
		return;
	}
};
#endif

void proxy_error_func(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);	
};

static void full_write(int fd, const char *buf, size_t len)
{
	while (len > 0) {
		ssize_t ret = write(fd, buf, len);

		if ((ret == -1) && (errno != EINTR))
			break;

		buf += (size_t) ret;
		len -= (size_t) ret;
	}
}

void print_backtrace(void)
{
	static const char start[] = "BACKTRACE ------------\n";
	static const char end[] = "----------------------\n";

	void *bt[1024];
	int bt_size;
	char **bt_syms;
	int i;

	bt_size = backtrace(bt, 1024);
	bt_syms = backtrace_symbols(bt, bt_size);
	full_write(STDERR_FILENO, start, strlen(start));
	for (i = 1; i < bt_size; i++) {
		size_t len = strlen(bt_syms[i]);
		full_write(STDERR_FILENO, bt_syms[i], len);
		full_write(STDERR_FILENO, "\n", 1);
	}
	full_write(STDERR_FILENO, end, strlen(end));
	free(bt_syms);
}

#ifdef DEBUG
void init_debug_struct() {	
	int i;
#ifdef PROXYSQL_DEBUG_PTHREAD_MUTEX
		pthread_mutex_init(&debug_mutex,NULL);
#else
	spinlock_init(&debug_spinlock);
#endif
	pretime=debug_monotonic_time();
	GloVars.global.gdbg_lvl= (debug_level *) malloc(PROXY_DEBUG_UNKNOWN*sizeof(debug_level));
	for (i=0;i<PROXY_DEBUG_UNKNOWN;i++) {
		GloVars.global.gdbg_lvl[i].module=(enum debug_module)i;
		GloVars.global.gdbg_lvl[i].verbosity=( GloVars.global.gdbg ? INT_MAX : 0 );
		GloVars.global.gdbg_lvl[i].name=(char *)NULL;
	}
	GloVars.global.gdbg_lvl[PROXY_DEBUG_GENERIC].name=(char *)"debug_generic"; 
	GloVars.global.gdbg_lvl[PROXY_DEBUG_NET].name=(char *)"debug_net";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_PKT_ARRAY].name=(char *)"debug_pkt_array";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_POLL].name=(char *)"debug_poll";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_MYSQL_COM].name=(char *)"debug_mysql_com";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_MYSQL_SERVER].name=(char *)"debug_mysql_server";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_MYSQL_CONNECTION].name=(char *)"debug_mysql_connection";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_MYSQL_CONNPOOL].name=(char *)"debug_mysql_connpool";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_MYSQL_RW_SPLIT].name=(char *)"debug_mysql_rw_split";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_MYSQL_AUTH].name=(char *)"debug_mysql_auth";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_MYSQL_PROTOCOL].name=(char *)"debug_mysql_protocol";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_MYSQL_QUERY_PROCESSOR].name=(char *)"debug_mysql_query_processor";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_MEMORY].name=(char *)"debug_memory";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_ADMIN].name=(char *)"debug_admin";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_SQLITE].name=(char *)"debug_sqlite";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_IPC].name=(char *)"debug_ipc";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_QUERY_CACHE].name=(char *)"debug_query_cache";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_QUERY_STATISTICS].name=(char *)"debug_query_statistics";

	for (i=0;i<PROXY_DEBUG_UNKNOWN;i++) {
		// if this happen, the above table is not populated correctly
		assert(GloVars.global.gdbg_lvl[i].name!=NULL);
	}
}


void init_debug_struct_from_cmdline() {
	if (GloVars.__cmd_proxysql_gdbg<0) return;
	int i;
	for (i=0;i<PROXY_DEBUG_UNKNOWN;i++) {
		GloVars.global.gdbg_lvl[i].verbosity=GloVars.__cmd_proxysql_gdbg;
	}
}
#endif /* DEBUG */

void proxy_info_(const char* msg, ...) {
	va_list args;
	va_start(args, msg);

	time_t __timer;
	char __buffer[25];

	// create the time info
	struct tm *__tm_info;
	time(&__timer);
	__tm_info = localtime(&__timer);
	strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info);

	// format the message
#ifdef DEBUG
	const char* debug_msg_fmt = " %s:%d:%s(): [INFO] ";
#else
	const char* debug_msg_fmt = " [INFO]";
#endif /* DEBUG */

	std::size_t msg_len = strlen(msg);
	char* str_buf = (char*)malloc(25 + strlen(debug_msg_fmt) + msg_len + 1);
	strcpy(str_buf, __buffer);
	strcat(str_buf, debug_msg_fmt);
	strcat(str_buf, msg);

	vfprintf(stderr, str_buf, args);

	free(str_buf);
	va_end(args);
}
