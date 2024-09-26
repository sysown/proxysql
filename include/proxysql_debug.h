#ifndef __PROXYSQL_DEBUG_H
#define __PROXYSQL_DEBUG_H

#include <chrono>
#include <iostream>
#include <atomic>

#include "proxysql_macros.h"

#if ENABLE_TIMER // this is defined in proxysql_macros.h
class TimerCount {
	public:
	std::chrono::duration<double> Timer = std::chrono::seconds(0);
	unsigned int Count = 0;
};

class Timer {
	public:
		Timer(TimerCount& tc) : totalTime(tc.Timer) {
			start = std::chrono::high_resolution_clock::now();
			tc.Count++;
		}

		~Timer() {
			auto end = std::chrono::high_resolution_clock::now();
			std::chrono::duration<double> elapsed = end - start;
			totalTime += elapsed;
		}
	private:
		//std::atomic<std::chrono::duration<double>>& totalTime; // If using atomic , use this instead
		std::chrono::duration<double>& totalTime;
		std::chrono::time_point<std::chrono::high_resolution_clock> start;
};
#endif // ENABLE_TIMER

#ifdef DEBUG
#define PROXY_TRACE() { proxy_debug(PROXY_DEBUG_GENERIC,10,"TRACE\n"); }
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

#define proxy_error(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[30]; \
		struct tm __tm_info; \
		time(&__timer); \
		localtime_r(&__timer, &__tm_info); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", &__tm_info); \
		proxy_error_func(0, "%s %s:%d:%s(): [ERROR] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
	} while(0)

#define proxy_error2(ecode, fmt, ...) \
    do { \
        time_t __timer; \
        char __buffer[30]; \
        struct tm __tm_info; \
        time(&__timer); \
        localtime_r(&__timer, &__tm_info); \
        strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", &__tm_info); \
        proxy_error_func(ecode, "%s %s:%d:%s(): [ERROR] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
    } while(0)

#define proxy_error_inline(fi, li, fu, fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[30]; \
		struct tm __tm_info; \
		time(&__timer); \
		localtime_r(&__timer, &__tm_info); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", &__tm_info); \
		proxy_error_func(0, "%s %s:%d:%s(): [ERROR] " fmt, __buffer, fi, li, fu , ## __VA_ARGS__); \
	} while(0)

#define proxy_warning(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(0, "%s %s:%d:%s(): [WARNING] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
	} while(0)

#define proxy_warning2(ecode, fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(ecode, "%s %s:%d:%s(): [WARNING] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
	} while(0)

#ifdef DEBUG
#define proxy_info(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(0, "%s %s:%d:%s(): [INFO] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
	} while(0)

#define proxy_info2(ecode, fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(ecode, "%s %s:%d:%s(): [INFO] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
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
		proxy_error_func(0, "%s [INFO] " fmt , __buffer , ## __VA_ARGS__); \
	} while(0)

#define proxy_info2(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func(ecode, "%s [INFO] " fmt , __buffer , ## __VA_ARGS__); \
	} while(0)
#endif

#ifdef DEBUG
#endif

#define NULL_DB_MSG "The pointer to sqlite3 database is NULL. Cannot get error message."

#define ASSERT_SQLITE_OK(rc, db) \
	do { \
		if (rc!=SQLITE_OK) { \
			proxy_error( \
				"SQLite3 error. Shutting down   rc=%d msg='%s'\n", \
				rc, db ? (*proxy_sqlite3_errmsg)(db->get_db()) : NULL_DB_MSG); \
			assert(0); \
		} \
	} while(0)

#define ASSERT_SQLITE3_OK(rc, db) \
	do { \
		if (rc!=SQLITE_OK) { \
			proxy_error( \
				"SQLite3 error. Shutting down   rc=%d msg='%s'\n", \
				rc, db ? (*proxy_sqlite3_errmsg)(db) : NULL_DB_MSG); \
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

class SQLite3DB;
/**
 * @brief Set or unset if Admin has debugdb_disk fully initialized
 */
void proxysql_set_admin_debugdb_disk(SQLite3DB *_db);

void proxysql_set_admin_debug_output(unsigned int _do);

#endif // DEBUG
