#ifndef PROXYSQL_DEBUG_H__
#define PROXYSQL_DEBUG_H__

#include <ctime>

void proxy_error_func(const char *, ...);

#ifdef DEBUG
#define PROXY_TRACE() { proxy_debug(PROXY_DEBUG_GENERIC,10,"TRACE\n"); }
#else
#define PROXY_TRACE()
#endif

#ifdef DEBUG
#ifdef SYS_gettid
#define proxy_debug(module, verbosity, fmt, ...) \
	do { if (GloVars.global.gdbg) { \
	proxy_debug_func(module, verbosity, syscall(SYS_gettid), __FILE__, __LINE__, __func__ ,  fmt,  ## __VA_ARGS__); \
	} } while (0)
#else
#define proxy_debug(module, verbosity, fmt, ...)
#endif /* SYS_gettid */
#else
#define proxy_debug(module, verbosity, fmt, ...)
#endif /* DEBUG */

/*
#ifdef DEBUG
*/
#define proxy_error(fmt, ...) \
	do { \
		time_t __timer; \
		char __buffer[25]; \
		struct tm *__tm_info; \
		time(&__timer); \
		__tm_info = localtime(&__timer); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info); \
		proxy_error_func("%s %s:%d:%s(): [ERROR] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
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
		proxy_error_func("%s %s:%d:%s(): [WARNING] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
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
		proxy_error_func("%s %s:%d:%s(): [INFO] " fmt, __buffer, __FILE__, __LINE__, __func__ , ## __VA_ARGS__); \
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
    proxy_error_func("%s [INFO] " fmt , __buffer , ## __VA_ARGS__); \
	} while(0)
#endif

// list of possible debugging modules
enum debug_module {
	PROXY_DEBUG_GENERIC,
	PROXY_DEBUG_NET,
	PROXY_DEBUG_PKT_ARRAY,
	PROXY_DEBUG_POLL,
	PROXY_DEBUG_MYSQL_COM,
	PROXY_DEBUG_MYSQL_SERVER,
	PROXY_DEBUG_MYSQL_CONNECTION,
	PROXY_DEBUG_MYSQL_CONNPOOL,
	PROXY_DEBUG_MYSQL_RW_SPLIT,
	PROXY_DEBUG_MYSQL_AUTH,
	PROXY_DEBUG_MYSQL_PROTOCOL,
	PROXY_DEBUG_MYSQL_QUERY_PROCESSOR,
	PROXY_DEBUG_MEMORY,
	PROXY_DEBUG_ADMIN,
	PROXY_DEBUG_SQLITE,
	PROXY_DEBUG_IPC,
	PROXY_DEBUG_QUERY_CACHE,
	PROXY_DEBUG_QUERY_STATISTICS,
	PROXY_DEBUG_UNKNOWN // this module doesn't exist. It is used only to define the last possible module
};

#ifdef DEBUG
typedef struct {
	enum debug_module module;
	int verbosity;
	char *name;
} debug_level;
#endif /* DEBUG */
#endif //PROXYSQL_DEBUG_H__
