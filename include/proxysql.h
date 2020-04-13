#ifdef __cplusplus
#include <string>
#include <stack>

#include <algorithm>

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
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <poll.h>

#include "backtrace.h"

#include <dlfcn.h>

#include <sys/ioctl.h>

#if !defined(__FreeBSD__) && !defined(__APPLE__)
#define HAVE_BOOL
#include "ma_global.h"
//#include "my_pthread.h"
#endif
#include "mysql.h"
#include "mariadb_com.h"

#include "proxysql_mem.h"

#include "proxysql_structs.h"
#include "proxysql_debug.h"
#include "proxysql_macros.h"

#include "jemalloc.h"

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

void proxy_error_func(const char *, ...);
void print_backtrace(void);

#ifdef DEBUG
void init_debug_struct();
void init_debug_struct_from_cmdline();
void proxy_debug_func(enum debug_module, int, int, const char *, int, const char *, const char *, ...);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROXYSQL_FUNC_DEFS */
