#ifdef __cplusplus
#include <string>
#include <stack>

#include <algorithm>
#include <set>

#ifndef EZOPTION
#define EZOPTION
#endif /* EZOPTION */
#endif
#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <string.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <sys/syscall.h>
#include <sys/stat.h>

#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include "openssl/bio.h"
#include "openssl/sha.h"
#include "openssl/md5.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <poll.h>
#include <execinfo.h>

#include <dlfcn.h>

#include <sys/ioctl.h>

#include "mysql.h"
#include "mariadb_com.h"

#include "proxysql_mem.h"

#include "proxysql_structs.h"
#include "proxysql_debug.h"
#include "proxysql_macros.h"
#include "proxysql_coredump.h"
#include "proxysql_sslkeylog.h"
#include "jemalloc.h"

#ifndef NOJEM
#if defined(__APPLE__) && defined(__MACH__)
#ifndef mallctl
#define mallctl(a, b, c, d, e) je_mallctl(a, b, c, d, e)
#endif
#endif // __APPLE__ and __MACH__
#endif // NOJEM

#ifdef DEBUG
//#define VALGRIND_ENABLE_ERROR_REPORTING
//#define VALGRIND_DISABLE_ERROR_REPORTING
#include "valgrind.h"
#else
#define VALGRIND_ENABLE_ERROR_REPORTING
#define VALGRIND_DISABLE_ERROR_REPORTING
#endif /* DEBUG */

#include "sqlite3.h"

#include "c_tokenizer.h"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_VERSION	GITVERSION DEB
#define PROXYSQL_CODENAME	"Truls"

#ifndef PROXYSQL_FUNC_DEFS
#define PROXYSQL_FUNC_DEFS

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int listen_on_port(char *ip, uint16_t port, int backlog, bool reuseport=false);
int listen_on_unix(char *, int);
int connect_socket(char *, int);
int config_file_is_readable(char *);
unsigned int CPY3(unsigned char *);

int pkt_ok(unsigned char *, unsigned int);
int pkt_end(unsigned char *, unsigned int);
int pkt_com_query(unsigned char *, unsigned int);
enum MySQL_response_type mysql_response(unsigned char *, unsigned int);

__attribute__((__format__ (__printf__, 3, 4)))
void proxy_error_func(int errcode, int loglevel, const char *, ...);
void print_backtrace(void);
void proxy_info_(const char* msg, ...);

#ifdef DEBUG
void init_debug_struct();
void init_debug_struct_from_cmdline();
/**
 * @brief Add a debug entry in the error log. To be used through 'proxy_debug' macro.
 * @details This function saves/restores the previous 'errno' value.
 */
__attribute__((__format__ (__printf__, 7, 8)))
void proxy_debug_func(enum debug_module, int, int, const char *, int, const char *, const char *, ...);
void proxy_debug_get_filters(std::set<std::string>&);
void proxy_debug_load_filters(std::set<std::string>&);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROXYSQL_FUNC_DEFS */
