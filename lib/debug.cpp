#include <set>
#include "proxysql.h"
#include "proxysql_atomic.h"
#include <cxxabi.h>

#ifdef DEBUG
#ifdef DEBUG_EXTERN
#undef DEBUG_EXTERN
#endif /* DEBUG_EXTERN */
#endif /* DEBUG */

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC SYSTEM_CLOCK
#endif // CLOCK_MONOTONIC

#ifdef DEBUG
static unsigned long long pretime=0;
static pthread_mutex_t debug_mutex;
#endif /* DEBUG */

static inline unsigned long long debug_monotonic_time() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}


#define DEBUG_MSG_MAXSIZE	1024

#ifdef DEBUG


// this set will have all the filters related to debug
// for convention, the key is:
// filename:line:function
// this key structure applies also if line is 0 or function is empty
// filename is mandatory
std::set<std::string> debug_filters;

static bool filter_debug_entry(const char *__file, int __line, const char *__func) {
	pthread_mutex_lock(&debug_mutex);
	bool to_filter = false;
	if (debug_filters.size()) { // if the set is empty we aren't performing any filter, so we won't search
		std::string key(__file);
		key += ":" + std::to_string(__line);
		key += ":";
		key += __func;
		// we start with a full search
		if (debug_filters.find(key) != debug_filters.end()) {
			to_filter = true;
		} else {
			// we now search filename + line
			key = __file;
			key += ":" + std::to_string(__line);
			// remember to add the final ":"
			key += ":";
			if (debug_filters.find(key) != debug_filters.end()) {
				to_filter = true;
			} else {
				// we now search filename + function
				key = __file;
				// no line = 0
				key += ":0:";
				key += __func;
				if (debug_filters.find(key) != debug_filters.end()) {
					to_filter = true;
				} else {
					// we now search filename only
					key = __file;
					// remember to add ":" even if no line
					key += ":0:";
					if (debug_filters.find(key) != debug_filters.end()) {
						to_filter = true;
					} else {
						// if we reached here, we couldn't find any filter
					}
				}
			}
		}
	}
	pthread_mutex_unlock(&debug_mutex);
	return to_filter;
}

// we use this function to sent the filters to Admin
// we hold here the mutex on debug_mutex
void proxy_debug_get_filters(std::set<std::string>& f) {
	pthread_mutex_lock(&debug_mutex);
	f = debug_filters;
	pthread_mutex_unlock(&debug_mutex);
}

// we use this function to get the filters from Admin
// we hold here the mutex on debug_mutex
void proxy_debug_load_filters(std::set<std::string>& f) {
	pthread_mutex_lock(&debug_mutex);
	debug_filters.erase(debug_filters.begin(), debug_filters.end());
	debug_filters = f;
	pthread_mutex_unlock(&debug_mutex);
}

void proxy_debug_func(enum debug_module module, int verbosity, int thr, const char *__file, int __line, const char *__func, const char *fmt, ...) {
	assert(module<PROXY_DEBUG_UNKNOWN);
	if (GloVars.global.gdbg_lvl[module].verbosity < verbosity)
		return;
	if (filter_debug_entry(__file, __line, __func)) // check if the entry must be filtered
		return;
	char debugbuff[DEBUG_MSG_MAXSIZE];
	char longdebugbuff[DEBUG_MSG_MAXSIZE*8];
	longdebugbuff[0]=0;
	if (GloVars.global.foreground) {
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(debugbuff, DEBUG_MSG_MAXSIZE,fmt,ap);
		va_end(ap);
		pthread_mutex_lock(&debug_mutex);
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
	pthread_mutex_unlock(&debug_mutex);
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
	pthread_mutex_init(&debug_mutex,NULL);
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
