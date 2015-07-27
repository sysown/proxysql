
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
#define proxy_debug(module, verbosity, fmt, ...) \
	do { if (GloVars.global.gdbg) { \
	proxy_debug_func(module, verbosity, syscall(SYS_gettid), __FILE__, __LINE__, __func__ ,  fmt,  ## __VA_ARGS__); \
	} } while (0)
#else
#define proxy_debug(module, verbosity, fmt, ...)
#endif

#ifdef DEBUG
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

#ifdef DEBUG
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

//void proxy_debug_func(enum debug_module, int, const char *, ...);
//void proxy_debug_func(enum debug_module, int, int, const char *, int, const char *, const char *, ...);
//void proxy_error_func(const char *, ...);
//void crash_handler(int);
//void init_debug_struct();
#ifdef DEBUG
//void *debug_logger();
#endif
