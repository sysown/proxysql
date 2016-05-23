#ifdef __cplusplus
#include <string>
#include <stack>
#include "btree_map.h"
#ifndef EZOPTION
//#include "ezOptionParser.hpp"
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
//#include <resolv.h>
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
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <poll.h>
//#include <glib.h>
#include <execinfo.h>

#include <dlfcn.h>


//#include <event2/buffer.h>
//#include <event2/thread.h>

//#include <sys/epoll.h>
#include <sys/ioctl.h>


#define HAVE_BOOL
#include "my_global.h"
#include "my_pthread.h"
#include "mysql.h"
#include "mysql_com.h"

#include "proxysql_mem.h"


#include "proxysql_structs.h"
#include "proxysql_debug.h"
#include "proxysql_macros.h"

#include "jemalloc.h"


#include "valgrind.h"

#include "sqlite3.h"

#include "c_tokenizer.h"

//#include "cpp.h"


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_VERSION	"1.2.0g" DEB
#define PROXYSQL_CODENAME	"Truls"

#ifndef PROXYSQL_FUNC_DEFS
#define PROXYSQL_FUNC_DEFS

#ifdef __cplusplus
extern "C" {
//int parse_mysql_pkt(unsigned char *, MySQL_Data_Stream *, int);
#endif /* __cplusplus */

//mysql_data_stream_t * mysql_data_stream_New(mysql_session_t *, int, mysql_backend_t *);
int listen_on_port(char *, uint16_t, int);
int listen_on_unix(char *, int);
int connect_socket(char *, int);
//void process_global_variables_from_file(GKeyFile *, int );
//void main_opts(gint *, gchar ***);
int config_file_is_readable(char *);
unsigned int CPY3(unsigned char *);

int pkt_ok(unsigned char *, unsigned int);
int pkt_end(unsigned char *, unsigned int);
int pkt_com_query(unsigned char *, unsigned int);
enum MySQL_response_type mysql_response(unsigned char *, unsigned int);


void pre_variable_mysql_threads(global_variable_entry_t *);

void proxy_error_func(const char *, ...);

#ifdef DEBUG
void init_debug_struct();
void init_debug_struct_from_cmdline();
void proxy_debug_func(enum debug_module, int, int, const char *, int, const char *, const char *, ...);
#endif


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROXYSQL_FUNC_DEFS */
