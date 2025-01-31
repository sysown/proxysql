
/*
#ifdef DEBUG
#ifndef DEBUG_EXTERN
#define DEBUG_EXTERN
extern debug_level *gdbg_lvl;
extern int gdbg;
#endif 
#endif 
*/

#ifndef __PROXYSQL_DEBUG_H
#define __PROXYSQL_DEBUG_H

#ifdef DEBUG
#define PROXY_TRACE() { proxy_debug(PROXY_DEBUG_GENERIC,10,"TRACE\n"); }
//#define PROXY_TRACE2() { proxy_info("TRACE\n"); }
#define PROXY_TRACE2()
#else
#define PROXY_TRACE()
#define PROXY_TRACE2()
#endif

#ifdef DEBUG
#if defined(__APPLE__) && defined(__MACH__)
#define proxy_debug(module, verbosity, fmt, ...) \
	do { \
	uint64_t tid; \
	pthread_threadid_np(NULL, &tid); \
	if (GloVars.global.gdbg) { \
	proxy_debug_func(module, verbosity, tid, __FILE__, __LINE__, __func__ ,  fmt,  ## __VA_ARGS__); \
	} \
	} while (0)
#elif defined(__linux__)
//#ifdef SYS_gettid
#define proxy_debug(module, verbosity, fmt, ...) \
	do { if (GloVars.global.gdbg) { \
	proxy_debug_func(module, verbosity, syscall(SYS_gettid), __FILE__, __LINE__, __func__ ,  fmt,  ## __VA_ARGS__); \
	} } while (0)
#else
#define proxy_debug(module, verbosity, fmt, ...)
#endif /* APPLE || linux */
#else
#define proxy_debug(module, verbosity, fmt, ...)
#endif /* DEBUG */

/*
#ifdef DEBUG
*/
// define the levels of logging messages
const int loglevel_error = 1;
const int loglevel_warning = 2;
const int loglevel_info = 3;

#define proxy_error(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[30]; \
		struct tm __tm_info; \
		time(&__timer); \
		localtime_r(&__timer, &__tm_info); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", &__tm_info); \
		proxy_error_func(0, loglevel_error, "%s %s:%d:%s(): [ERROR] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
	} while(0)

#define proxy_error2(ecode, fmt, ...) \
    do { \
        time_t __timer; \
        char __buffer[30]; \
        struct tm __tm_info; \
        time(&__timer); \
        localtime_r(&__timer, &__tm_info); \
        strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", &__tm_info); \
        proxy_error_func(ecode, loglevel_error, "%s %s:%d:%s(): [ERROR] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
    } while(0)

#define proxy_error_inline(fi, li, fu, fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[30]; \
		struct tm __tm_info; \
		time(&__timer); \
		localtime_r(&__timer, &__tm_info); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", &__tm_info); \
		proxy_error_func(0, loglevel_error, "%s %s:%d:%s(): [ERROR] " fmt, __buffer, fi, li, fu , ## __VA_ARGS__); \
	} while(0)
/*
#else
#define proxy_error(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
    proxy_error_func("%s [ERROR] " fmt , __buffer , ## __VA_ARGS__); \
	} while(0)
#endif
*/
/*
#ifdef DEBUG
*/
#define proxy_warning(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(0, loglevel_warning, "%s %s:%d:%s(): [WARNING] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
	} while(0)

#define proxy_warning2(ecode, fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(ecode, loglevel_warning, "%s %s:%d:%s(): [WARNING] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
	} while(0)

/*
#else
#define proxy_warning(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
    proxy_error_func("%s [WARNING] " fmt , __buffer , ## __VA_ARGS__); \
	} while(0)
#endif
*/
#ifdef DEBUG
#define proxy_info(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(0, loglevel_info, "%s %s:%d:%s(): [INFO] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
	} while(0)

#define proxy_info2(ecode, fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(ecode, loglevel_info, "%s %s:%d:%s(): [INFO] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
	} while(0)
#else
#define proxy_info(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(0, loglevel_info, "%s [INFO] " fmt , __buffer , ## __VA_ARGS__); \
	} while(0)

#define proxy_info2(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(ecode, loglevel_info, "%s [INFO] " fmt , __buffer , ## __VA_ARGS__); \
	} while(0)
#endif

#ifdef DEBUG
//void *debug_logger();
#endif

#define ASSERT_SQLITE_OK(rc, db) \
	do { \
		if (rc!=SQLITE_OK) { \
			proxy_error("SQLite3 error with return code %d. Error message: %s. Shutting down.\n", rc, db?(*proxy_sqlite3_errmsg)(db->get_db()):"The pointer to sqlite3 database is null. Cannot get error message."); \
			assert(0); \
		} \
	} while(0)

struct p_debug_dyn_counter {
	enum metric {
		proxysql_message_count = 0,
		__size
	};
};

struct debug_metrics_map_idx {
	enum index {
		dyn_counters,
	};
};

class SQLite3_result;
SQLite3_result* proxysql_get_message_stats(bool reset=false);

/**
 * @brief Initializes the prometheus metrics contained in 'debug.cpp'.
 */
void proxysql_init_debug_prometheus_metrics();


/**
 * @brief Set or unset if Admin has debugdb_disk fully initialized
 */
void proxysql_set_admin_debugdb_disk(SQLite3DB *_db);

void proxysql_set_admin_debug_output(unsigned int _do);

#endif
