#include "proxysql.h"
#include "proxysql_atomic.h"

#include "sqlite3db.h"
#include "prometheus_helpers.h"

#include <set>
#include <cxxabi.h>
#include <string>
#include <unordered_map>
#include <array>

using std::string;
using std::unordered_map;

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

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using debug_dyn_counter_tuple = std::tuple<p_debug_dyn_counter::metric, metric_name, metric_help, metric_tags>;
using debug_dyn_counter_vector = std::vector<debug_dyn_counter_tuple>;

const std::tuple<debug_dyn_counter_vector> debug_metrics_map = std::make_tuple(
	debug_dyn_counter_vector {
		std::make_tuple (
			p_debug_dyn_counter::proxysql_message_count,
			"proxysql_message_count_total",
			"Number of times a particular message has been logged by ProxySQL.",
			metric_tags {}
		)
	}
);

std::map<std::string, prometheus::Counter*> p_proxysql_messages_map {};
std::array<prometheus::Family<prometheus::Counter>*, p_debug_dyn_counter::__size> p_debug_dyn_counter_array {};
std::mutex msg_stats_mutex {};

const int ProxySQL_MSG_STATS_FIELD_NUM = 7;

class ProxySQL_messages_stats {
public:
	const int32_t message_id = 0;
	const char* filename = nullptr;
	const int32_t line = 0;
	const char* func = nullptr;

	uint64_t count_star = 0;
	time_t first_seen = 0;
	time_t last_seen = 0;

	ProxySQL_messages_stats(
		const int32_t message_id_, const char* filename_, const int32_t line_, const char* func_, time_t first_seen_,
		time_t last_seen_, uint64_t count_star_
	) : message_id(message_id_), filename(filename_), line(line_), func(func_),  count_star(count_star_),
	    first_seen(first_seen_), last_seen(last_seen_)
	{
		assert(message_id_);
		assert(filename_);
		assert(line_);
		assert(func_);
	}

	char** get_row() const {
		char buf[128];

		char** pta = static_cast<char**>(malloc(sizeof(char *)*ProxySQL_MSG_STATS_FIELD_NUM));
		sprintf(buf,"%d",message_id);
		pta[0]=strdup(buf);
		pta[1]=strdup(filename);
		sprintf(buf,"%d",line);
		pta[2]=strdup(buf);
		pta[3]=strdup(func);
		sprintf(buf,"%lu",count_star);
		pta[4]=strdup(buf);
		sprintf(buf,"%ld", first_seen);
		pta[5]=strdup(buf);
		sprintf(buf,"%ld", last_seen);
		pta[6]=strdup(buf);

		return pta;
	}

	void add_time(uint64_t n) {
		count_star++;
		if (first_seen == 0) {
			first_seen = n;
		}
		last_seen=n;
	}

	void free_row(char **pta) const {
		for (int i=0; i < ProxySQL_MSG_STATS_FIELD_NUM; i++) {
			assert(pta[i]);
			free(pta[i]);
		}
		free(pta);
	}
};

unordered_map<string, ProxySQL_messages_stats> umap_msg_stats {};

/**
 * @brief Handles ProxySQL message logging.
 * @details The extra variadic arguments are expected to be received in the following order:
 *    ```
 *    proxy_error_func(msgid, fmt_message, time_buf, __FILE__, __LINE__, __func__ , ## __VA_ARGS__);
 *    ```
 *   Any other use of the function is UNSAFE. And will result in unespecified behavior.
 * @param msgid The message id of the message to be logged, when non-zero, stats about the message are updated in
 *   'umap_msg_stats'.
 * @param fmt The formatted string to be pass to 'vfprintf'.
 * @param ... The variadic list of arguments to be passed to 'vfprintf'.
 */
void proxy_error_func(int msgid, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);

	if (msgid != 0) {
		va_list stats_params;
		va_copy(stats_params, ap);

		// ignore 'time' buffer argument
		va_arg(stats_params, const char*);

		// collect arguments '__FILE__', '__LINE__' and '__func__'
		const char* file = va_arg(stats_params, const char*);
		const int32_t line = va_arg(stats_params, int32_t);
		const char* func = va_arg(stats_params, const char*);

		std::lock_guard<std::mutex> msg_stats_guard { msg_stats_mutex };

		string msg_stats_id { string { file } + ":" + std::to_string(line) + ":" + string { func } };
		auto msg_stats = umap_msg_stats.find(msg_stats_id);
		time_t tn = time(NULL);

		const std::map<string,string> m_labels {
			{ "message_id", std::to_string(msgid) }, { "filename", file },
			{ "line", std::to_string(line) }, { "func", func }
		};

		prometheus::Family<prometheus::Counter>* m_family =
			p_debug_dyn_counter_array[p_debug_dyn_counter::proxysql_message_count];

		p_inc_map_counter(p_proxysql_messages_map, m_family, msg_stats_id, m_labels);

		if (msg_stats != umap_msg_stats.end()) {
			msg_stats->second.add_time(tn);
		} else {
			umap_msg_stats.insert(
				{ msg_stats_id, ProxySQL_messages_stats(msgid, file, line, func, tn, tn, 1) }
			);
		}
	}

	vfprintf(stderr, fmt, ap);
	va_end(ap);	
};

SQLite3_result* proxysql_get_message_stats(bool reset) {
	std::lock_guard<std::mutex> msg_stats_guard { msg_stats_mutex };
	SQLite3_result* result = new SQLite3_result(ProxySQL_MSG_STATS_FIELD_NUM);

	result->add_column_definition(SQLITE_TEXT,"message_id");
	result->add_column_definition(SQLITE_TEXT,"filename");
	result->add_column_definition(SQLITE_TEXT,"line");
	result->add_column_definition(SQLITE_TEXT,"func");
	result->add_column_definition(SQLITE_TEXT,"count_star");
	result->add_column_definition(SQLITE_TEXT,"first_seen");
	result->add_column_definition(SQLITE_TEXT,"last_seen");

	for (const auto& msg_stats : umap_msg_stats) {
		char** pta = msg_stats.second.get_row();
		result->add_row(pta);
		msg_stats.second.free_row(pta);
	}

	if (reset) {
		umap_msg_stats.clear();
	}

	return result;
}

void proxysql_init_debug_prometheus_metrics() {
	init_prometheus_dyn_counter_array<debug_metrics_map_idx, p_debug_dyn_counter>(debug_metrics_map, p_debug_dyn_counter_array);
}

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
	GloVars.global.gdbg_lvl[PROXY_DEBUG_RESTAPI].name=(char *)"debug_restapi";
	GloVars.global.gdbg_lvl[PROXY_DEBUG_MONITOR].name=(char *)"debug_monitor";

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
