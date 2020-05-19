
/*
#ifdef DEBUG
#ifndef DEBUG_EXTERN
#define DEBUG_EXTERN
extern debug_level *gdbg_lvl;
extern int gdbg;
#endif 
#endif 
*/
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
		char __buffer[30]; \
		struct tm __tm_info; \
		time(&__timer); \
		localtime_r(&__timer, &__tm_info); \
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", &__tm_info); \
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

#define proxy_info__(fmt, ...) proxy_info_(fmt, __FILE__, __LINE__, __func__ , ## __VA_ARGS__)

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

#define proxy_info__(fmt, ...) proxy_info_(fmt, ## __VA_ARGS__)

#endif

#ifdef DEBUG
//void *debug_logger();
#endif

#define ASSERT_SQLITE_OK(rc, db) \
	do { \
		if (rc!=SQLITE_OK) { \
			proxy_error("SQLite3 error with return corde %d. Error message: %s. Shutting down.\n", rc, db?sqlite3_errmsg(db->get_db()):"The pointer to sqlite3 database is null. Cannot get error message."); \
			assert(0); \
		} \
	} while(0)


