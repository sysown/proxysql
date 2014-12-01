#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <resolv.h>
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
#include <poll.h>
#include <glib.h>
#include <execinfo.h>

#include "my_global.h"
#include "my_pthread.h"
#include "mysql.h"
#include "mysql_com.h"


#include <mcheck.h>

#include "sqlite3.h"
#include "external.h"
#include "structs.h"
#include "mysql_protocol.h"
#include "fundadb.h"
#include "global_variables.h"
#include "debug.h"
#include "admin_sqlite.h"

#include "lutils.h"
#include "proxysql_macros.h"

#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

#include <jemalloc/jemalloc.h>



#undef max
#define max(x,y) ((x) > (y) ? (x) : (y))

/* PANIC() is a exit with message */
void PANIC(char* msg);
#define PANIC(msg)  { perror(msg); exit(EXIT_FAILURE); }

int listen_on_port(char *, uint16_t);
int listen_on_unix(char *);
int connect_socket(char *, int);
gboolean write_one_pkt_to_net(mysql_data_stream_t *, pkt *); 

void reset_query_rule(query_rule_t *);
void reset_query_rules();
void init_gloQR();
void init_query_metadata(mysql_session_t *, pkt *);
void process_query_rules(mysql_session_t *);
mysql_server * find_server_ptr(const char *, const uint16_t);
mysql_server * mysql_server_entry_create(const char *, const uint16_t, int, enum mysql_server_status);
void mysql_server_entry_add(mysql_server *);
void mysql_server_entry_add_hostgroup(mysql_server *, int);
MSHGE * mysql_server_random_entry_from_hostgroup__lock(int);
MSHGE * mysql_server_random_entry_from_hostgroup__nolock(int);
int mysql_session_create_backend_for_hostgroup(mysql_session_t *, int);
int force_remove_servers();
void admin_COM_QUERY(mysql_session_t *, pkt *);


void send_auth_pkt(mysql_session_t *);
mysql_session_t * mysql_session_new(proxy_mysql_thread_t *, int);
void mysql_session_delete(mysql_session_t *);


mysql_backend_t * mysql_backend_new();
void mysql_backend_delete(mysql_backend_t *);
void glomybepools_init();

void set_thread_attr(pthread_attr_t *, size_t);
void start_background_threads(pthread_attr_t *, void **);
void init_proxyipc();
mysql_data_stream_t * mysql_data_stream_new(mysql_session_t *, mysql_backend_t *);
void mysql_data_stream_delete(mysql_data_stream_t *);


gboolean reconnect_server_on_shut_fd(mysql_session_t *);
void mysql_connpool_init(global_variable_entry_t *);
void local_mysql_connpool_init();
void * mysql_connpool_purge_thread();
mysql_cp_entry_t *mysql_connpool_get_connection(int, mysql_connpool **, const char *, const char *, const char *, const char *, unsigned int);
void mysql_connpool_detach_connection(int, mysql_connpool **, mysql_cp_entry_t *, int);
mysql_connpool *mysql_connpool_exists_global(const char *, const char *, const char *, const char *, unsigned int);


void term_handler(int);
long monotonic_time();


char *mysql_query_digest(mysql_session_t *);
void cleanup_query_stats(qr_hash_entry *);
void query_statistics_set(mysql_session_t *);
// Added by chan -------
//void process_query_stats(mysql_session_t *);
char *str2md5(const char *);
/*
char is_token(char);
char is_digit(char *, char *);
char is_digit_char(char);
char is_space_char(char);
char is_token_char(char);
char is_digit_string(char *, char *);
*/
// Added by chan end.

void glo_DefHG_init(global_default_hostgroups_t *);


void sighup_handler(int sig);
int config_file_is_readable(char *);
