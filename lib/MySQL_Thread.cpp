//#define __CLASS_STANDARD_MYSQL_THREAD_H
#define MYSQL_THREAD_IMPLEMENTATION
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Thread.h"

#ifdef DEBUG
MySQL_Session *sess_stopat;
#endif

#ifdef epoll_create1
	#define EPOLL_CREATE epoll_create1(0)
#else
	#define EPOLL_CREATE epoll_create(1)
#endif

#define PROXYSQL_LISTEN_LEN 1024
#define MIN_THREADS_FOR_MAINTENANCE 8

extern Query_Processor *GloQPro;
extern MySQL_Authentication *GloMyAuth;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Monitor *GloMyMon;
extern MySQL_Logger *GloMyLogger;

const CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr) {
	const CHARSET_INFO * c = compiled_charsets;
	do {
		if (c->nr == nr) {
			return c;
		}
		++c;
	} while (c[0].nr != 0);
	return NULL;
}

CHARSET_INFO * proxysql_find_charset_name(const char *name) {
	CHARSET_INFO *c = (CHARSET_INFO *)compiled_charsets;
	do {
		if (!strcasecmp(c->csname, name)) {
			return c;
		}
		++c;
	} while (c[0].nr != 0);
	return NULL;
}

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef __cplusplus
}
#endif /* __cplusplus */


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_THREAD_VERSION "0.2.0902" DEB


#define DEFAULT_NUM_THREADS	4
#define DEFAULT_STACK_SIZE	1024*1024

#define SESSIONS_FOR_CONNECTIONS_HANDLER	64

__thread unsigned int __thread_MySQL_Thread_Variables_version;

volatile static unsigned int __global_MySQL_Thread_Variables_version;


MySQL_Listeners_Manager::MySQL_Listeners_Manager() {
	ifaces=new PtrArray();
}
MySQL_Listeners_Manager::~MySQL_Listeners_Manager() {
	while (ifaces->len) {
		iface_info *ifi=(iface_info *)ifaces->remove_index_fast(0);
		shutdown(ifi->fd,SHUT_RDWR);
		close(ifi->fd);
		if (ifi->port==0) {
			unlink(ifi->address);
		}
		delete ifi;
	}
	delete ifaces;
	ifaces=NULL;
}

int MySQL_Listeners_Manager::add(const char *iface, unsigned int num_threads, int **perthrsocks) {
	for (unsigned int i=0; i<ifaces->len; i++) {
		iface_info *ifi=(iface_info *)ifaces->index(i);
		if (strcmp(ifi->iface,iface)==0) {
			return -1;
		}
	}
	char *address=NULL; char *port=NULL;
	int s = -1;
        char *h = NULL;

        if (*(char *)iface == '[') {
                char *p = strchr((char *)iface, ']');
                if (p == NULL) {
                        proxy_error("Invalid IPv6 address: %s\n", iface);
                        return -1;
                }
                h = (char *)++iface; // remove first '['
                *p = '\0';
                iface = p++; // remove last ']'
                address = h;
                port = ++p; // remove ':'
        } else {
                c_split_2(iface, ":" , &address, &port);
        }

#ifdef SO_REUSEPORT
	if (GloVars.global.reuseport==false) {
		s = ( atoi(port) ? listen_on_port(address, atoi(port), PROXYSQL_LISTEN_LEN) : listen_on_unix(address, PROXYSQL_LISTEN_LEN));
	} else {
		if (atoi(port)==0) {
			s = listen_on_unix(address, PROXYSQL_LISTEN_LEN);
		} else {
			// for TCP we will use SO_REUSEPORT
			int *l_perthrsocks=(int *)malloc(sizeof(int)*num_threads);
			unsigned int i;
			for (i=0;i<num_threads;i++) {
				s=listen_on_port(address, atoi(port), PROXYSQL_LISTEN_LEN, true);
				ioctl_FIONBIO(s,1);
				iface_info *ifi=new iface_info((char *)iface, address, atoi(port), s);
				ifaces->add(ifi);
				l_perthrsocks[i]=s;
			}
			*perthrsocks=l_perthrsocks;
			s=0;
		}
	}
#else
	s = ( atoi(port) ? listen_on_port(address, atoi(port), PROXYSQL_LISTEN_LEN) : listen_on_unix(address, PROXYSQL_LISTEN_LEN));
#endif /* SO_REUSEPORT */
	if (s==-1) return s;
	if (s>0) {
		ioctl_FIONBIO(s,1);
		iface_info *ifi=new iface_info((char *)iface, address, atoi(port), s);
		ifaces->add(ifi);
	}
	return s;
}

int MySQL_Listeners_Manager::find_idx(const char *iface) {
	for (unsigned int i=0; i<ifaces->len; i++) {
		iface_info *ifi=(iface_info *)ifaces->index(i);
		if (strcmp(ifi->iface,iface)==0) {
			return i;
		}
	}
	return -1;
}

iface_info * MySQL_Listeners_Manager::find_iface_from_fd(int fd) {
	for (unsigned int i=0; i<ifaces->len; i++) {
		iface_info *ifi=(iface_info *)ifaces->index(i);
		if (ifi->fd==fd) {
			return ifi;
		}
	}
	return NULL;
}

int MySQL_Listeners_Manager::find_idx(const char *address, int port) {
	for (unsigned int i=0; i<ifaces->len; i++) {
		iface_info *ifi=(iface_info *)ifaces->index(i);
		if (strcmp(ifi->address,address)==0 && ifi->port==port) {
			return i;
		}
	}
	return -1;
}

int MySQL_Listeners_Manager::get_fd(unsigned int idx) {
	iface_info *ifi=(iface_info *)ifaces->index(idx);
	return ifi->fd;
}

void MySQL_Listeners_Manager::del(unsigned int idx) {
	iface_info *ifi=(iface_info *)ifaces->remove_index_fast(idx);
	if (ifi->port==0) {
		unlink(ifi->address);
	}
	delete ifi;
}

static char * mysql_thread_variables_names[]= {
	(char *)"shun_on_failures",
	(char *)"shun_recovery_time_sec",
	(char *)"query_retries_on_failure",
	(char *)"connect_retries_on_failure",
	(char *)"connect_retries_delay",
	(char *)"connection_max_age_ms",
	(char *)"connect_timeout_server",
	(char *)"connect_timeout_server_max",
	(char *)"eventslog_filename",
	(char *)"eventslog_filesize",
	(char *)"default_charset",
	(char *)"free_connections_pct",
#ifdef IDLE_THREADS
	(char *)"session_idle_ms",
#endif // IDLE_THREADS
	(char *)"have_compress",
	(char *)"client_found_rows",
	(char *)"interfaces",
	(char *)"monitor_enabled",
	(char *)"monitor_history",
	(char *)"monitor_connect_interval",
	(char *)"monitor_connect_timeout",
	(char *)"monitor_ping_interval",
	(char *)"monitor_ping_max_failures",
	(char *)"monitor_ping_timeout",
	(char *)"monitor_read_only_interval",
	(char *)"monitor_read_only_timeout",
	(char *)"monitor_replication_lag_interval",
	(char *)"monitor_replication_lag_timeout",
	(char *)"monitor_username",
	(char *)"monitor_password",
	(char *)"monitor_query_interval",
	(char *)"monitor_query_timeout",
	(char *)"monitor_slave_lag_when_null",
	(char *)"monitor_writer_is_also_reader",
	(char *)"max_allowed_packet",
	(char *)"max_transaction_time",
	(char *)"multiplexing",
	(char *)"forward_autocommit",
	(char *)"enforce_autocommit_on_reads",
	(char *)"hostgroup_manager_verbose",
	(char *)"threshold_query_length",
	(char *)"threshold_resultset_size",
	(char *)"query_digests_max_digest_length",
	(char *)"query_digests_max_query_length",
	(char *)"wait_timeout",
	(char *)"max_connections",
	(char *)"max_stmts_per_connection",
	(char *)"max_stmts_cache",
	(char *)"default_max_latency_ms",
	(char *)"default_query_delay",
	(char *)"default_query_timeout",
	(char *)"query_processor_iterations",
	(char *)"query_processor_regex",
	(char *)"long_query_time",
	(char *)"query_cache_size_MB",
	(char *)"ping_interval_server_msec",
	(char *)"ping_timeout_server",
	(char *)"default_schema",
	(char *)"poll_timeout",
	(char *)"poll_timeout_on_failure",
	(char *)"server_capabilities",
	(char *)"server_version",
	(char *)"sessions_sort",
#ifdef IDLE_THREADS
	(char *)"session_idle_show_processlist",
#endif // IDLE_THREADS
	(char *)"commands_stats",
	(char *)"query_digests",
	(char *)"query_digests_lowercase",
	(char *)"servers_stats",
	(char *)"default_reconnect",
	(char *)"session_debug",
	(char *)"ssl_p2s_ca",
	(char *)"ssl_p2s_cert",
	(char *)"ssl_p2s_key",
	(char *)"ssl_p2s_cipher",
	(char *)"stacksize",
	(char *)"threads",
	(char *)"init_connect",
	(char *)"default_sql_mode",
	(char *)"default_time_zone",
	NULL
};

MySQL_Threads_Handler::MySQL_Threads_Handler() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debagging version");
		exit(EXIT_FAILURE);
	}
	num_threads=0;
	mysql_threads=NULL;
#ifdef IDLE_THREADS
	mysql_threads_idles=NULL;
#endif // IDLE_THREADS
	stacksize=0;
	shutdown_=0;
	spinlock_rwlock_init(&rwlock);
	pthread_attr_init(&attr);
	variables.shun_on_failures=5;
	variables.shun_recovery_time_sec=10;
	variables.query_retries_on_failure=1;
	variables.connect_retries_on_failure=10;
	variables.connection_max_age_ms=0;
	variables.connect_timeout_server=1000;
	variables.connect_timeout_server_max=10000;
	variables.free_connections_pct=10;
	variables.connect_retries_delay=1;
	variables.monitor_enabled=true;
	variables.monitor_history=600000;
	variables.monitor_connect_interval=120000;
	variables.monitor_connect_timeout=600;
	variables.monitor_ping_interval=60000;
	variables.monitor_ping_max_failures=3;
	variables.monitor_ping_timeout=1000;
	variables.monitor_read_only_interval=1000;
	variables.monitor_read_only_timeout=800;
	variables.monitor_replication_lag_interval=10000;
	variables.monitor_replication_lag_timeout=1000;
	variables.monitor_query_interval=60000;
	variables.monitor_query_timeout=100;
	variables.monitor_slave_lag_when_null=60;
	variables.monitor_username=strdup((char *)"monitor");
	variables.monitor_password=strdup((char *)"monitor");
	variables.monitor_writer_is_also_reader=true;
	variables.max_allowed_packet=4*1024*1024;
	variables.max_transaction_time=4*3600*1000;
	variables.hostgroup_manager_verbose=1;
	variables.threshold_query_length=512*1024;
	variables.threshold_resultset_size=4*1024*1024;
	variables.query_digests_max_digest_length=2*1024;
	variables.query_digests_max_query_length=65000; // legacy default
	variables.wait_timeout=8*3600*1000;
	variables.max_connections=10*1000;
	variables.max_stmts_per_connection=20;
	variables.max_stmts_cache=10000;
	variables.default_max_latency_ms=1*1000; // by default, the maximum allowed latency for a host is 1000ms
	variables.default_query_delay=0;
	variables.default_query_timeout=24*3600*1000;
	variables.query_processor_iterations=0;
	variables.query_processor_regex=1;
	variables.long_query_time=1000;
	variables.query_cache_size_MB=256;
	variables.init_connect=NULL;
	variables.default_sql_mode=strdup((char *)MYSQL_DEFAULT_SQL_MODE);
	variables.default_time_zone=strdup((char *)MYSQL_DEFAULT_TIME_ZONE);
	variables.ping_interval_server_msec=10000;
	variables.ping_timeout_server=200;
	variables.default_schema=strdup((char *)"information_schema");
	variables.default_charset=33;
	variables.interfaces=strdup((char *)"");
	variables.server_version=strdup((char *)"5.5.30");
	variables.eventslog_filename=strdup((char *)""); // proxysql-mysql-eventslog is recommended
	variables.eventslog_filesize=100*1024*1024;
	variables.server_capabilities=CLIENT_FOUND_ROWS | CLIENT_PROTOCOL_41 | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB;
	variables.poll_timeout=2000;
	variables.poll_timeout_on_failure=100;
	variables.have_compress=true;
	variables.client_found_rows=true;
	variables.commands_stats=true;
	variables.multiplexing=true;
	variables.forward_autocommit=false;
	variables.enforce_autocommit_on_reads=false;
	variables.query_digests=true;
	variables.query_digests_lowercase=false;
	variables.sessions_sort=true;
#ifdef IDLE_THREADS
	variables.session_idle_ms=1000;
	variables.session_idle_show_processlist=false;
#endif // IDLE_THREADS
	variables.servers_stats=true;
	variables.default_reconnect=true;
	variables.ssl_p2s_ca=NULL;
	variables.ssl_p2s_cert=NULL;
	variables.ssl_p2s_key=NULL;
	variables.ssl_p2s_cipher=NULL;
#ifdef DEBUG
	variables.session_debug=true;
#endif /*debug */
	__global_MySQL_Thread_Variables_version=1;
	MLM = new MySQL_Listeners_Manager();
}


unsigned int MySQL_Threads_Handler::get_global_version() {
	return __sync_fetch_and_add(&__global_MySQL_Thread_Variables_version,0);
}

int MySQL_Threads_Handler::listener_add(const char *address, int port) {
	char *s=(char *)malloc(strlen(address)+32);
	sprintf(s,"%s:%d",address,port);
	int ret=listener_add((const char *)s);
	free(s);
	return ret;
}

int MySQL_Threads_Handler::listener_add(const char *iface) {
	int rc;
	int *perthrsocks=NULL;;
	rc=MLM->add(iface, num_threads, &perthrsocks);
	if (rc>-1) {
		unsigned int i;
		if (perthrsocks==NULL) {
			for (i=0;i<num_threads;i++) {
				MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
				while(!__sync_bool_compare_and_swap(&thr->mypolls.pending_listener_add,0,rc)) {
					usleep(10); // pause a bit
				}
			}
		} else {
			for (i=0;i<num_threads;i++) {
				MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
				while(!__sync_bool_compare_and_swap(&thr->mypolls.pending_listener_add,0,perthrsocks[i])) {
					usleep(10); // pause a bit
				}
			}
			free(perthrsocks);
		}
	}
	return rc;
}

int MySQL_Threads_Handler::listener_del(const char *iface) {
	int idx;
	idx=MLM->find_idx(iface);
	if (idx>-1) {
		unsigned int i;
		int fd=MLM->get_fd(idx);
		for (i=0;i<num_threads;i++) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			while(!__sync_bool_compare_and_swap(&thr->mypolls.pending_listener_del,0,fd));
		}
		for (i=0;i<num_threads;i++) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			while(__sync_fetch_and_add(&thr->mypolls.pending_listener_del,0));
		}
		MLM->del(idx);
		shutdown(fd,SHUT_RDWR);
		close(fd);
	}

	return 0;
}

void MySQL_Threads_Handler::wrlock() {
	spin_wrlock(&rwlock);
}

void MySQL_Threads_Handler::wrunlock() {
	spin_wrunlock(&rwlock);
}

void MySQL_Threads_Handler::commit() {
	__sync_add_and_fetch(&__global_MySQL_Thread_Variables_version,1);
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 1, "Increasing version number to %d - all threads will notice this and refresh their variables\n", __global_MySQL_Thread_Variables_version);
}

char * MySQL_Threads_Handler::get_variable_string(char *name) {
	if (!strncasecmp(name,"monitor_",8)) {
		if (!strcasecmp(name,"monitor_username")) return strdup(variables.monitor_username);
		if (!strcasecmp(name,"monitor_password")) return strdup(variables.monitor_password);
	}
	if (!strncasecmp(name,"ssl_",4)) {
		if (!strcasecmp(name,"ssl_p2s_ca")) {
			if (variables.ssl_p2s_ca==NULL || strlen(variables.ssl_p2s_ca)==0) {
				return NULL;
			} else {
				return strdup(variables.ssl_p2s_ca);
			}
		}
		if (!strcasecmp(name,"ssl_p2s_cert")) {
			if (variables.ssl_p2s_cert==NULL || strlen(variables.ssl_p2s_cert)==0) {
				return NULL;
			} else {
				return strdup(variables.ssl_p2s_cert);
			}
		}
		if (!strcasecmp(name,"ssl_p2s_key")) {
			if (variables.ssl_p2s_key==NULL || strlen(variables.ssl_p2s_key)==0) {
				return NULL;
			} else {
				return strdup(variables.ssl_p2s_key);
			}
		}
		if (!strcasecmp(name,"ssl_p2s_cipher")) {
			if (variables.ssl_p2s_cipher==NULL || strlen(variables.ssl_p2s_cipher)==0) {
				return NULL;
			} else {
				return strdup(variables.ssl_p2s_cipher);
			}
		}
	}
	if (!strcasecmp(name,"init_connect")) {
		if (variables.init_connect==NULL || strlen(variables.init_connect)==0) {
			return NULL;
		} else {
			return strdup(variables.init_connect);
		}
	}
	if (!strcasecmp(name,"default_sql_mode")) {
		if (variables.default_sql_mode==NULL) {
			variables.default_sql_mode=strdup((char *)MYSQL_DEFAULT_SQL_MODE);
		}
		return strdup(variables.default_sql_mode);
	}
	if (!strcasecmp(name,"default_time_zone")) {
		if (variables.default_time_zone==NULL) {
			variables.default_time_zone=strdup((char *)MYSQL_DEFAULT_TIME_ZONE);
		}
		return strdup(variables.default_time_zone);
	}
	if (!strcasecmp(name,"server_version")) return strdup(variables.server_version);
	if (!strcasecmp(name,"eventslog_filename")) return strdup(variables.eventslog_filename);
	if (!strcasecmp(name,"default_schema")) return strdup(variables.default_schema);
	if (!strcasecmp(name,"interfaces")) return strdup(variables.interfaces);
	proxy_error("Not existing variable: %s\n", name); assert(0);
	return NULL;
}

uint16_t MySQL_Threads_Handler::get_variable_uint16(char *name) {
	if (!strcasecmp(name,"server_capabilities")) return variables.server_capabilities;
	proxy_error("Not existing variable: %s\n", name); assert(0);
	return 0;
}

uint8_t MySQL_Threads_Handler::get_variable_uint8(char *name) {
	if (!strcasecmp(name,"default_charset")) return variables.default_charset;
	proxy_error("Not existing variable: %s\n", name); assert(0);
	return 0;
}

int MySQL_Threads_Handler::get_variable_int(char *name) {
#ifdef DEBUG
	if (!strcasecmp(name,"session_debug")) return (int)variables.session_debug;
#endif /* DEBUG */
	if (!strncasecmp(name,"monitor_",8)) {
		if (!strcasecmp(name,"monitor_enabled")) return (int)variables.monitor_enabled;
		if (!strcasecmp(name,"monitor_history")) return (int)variables.monitor_history;
		if (!strcasecmp(name,"monitor_connect_interval")) return (int)variables.monitor_connect_interval;
		if (!strcasecmp(name,"monitor_connect_timeout")) return (int)variables.monitor_connect_timeout;
		if (!strcasecmp(name,"monitor_ping_interval")) return (int)variables.monitor_ping_interval;
		if (!strcasecmp(name,"monitor_ping_max_failures")) return (int)variables.monitor_ping_max_failures;
		if (!strcasecmp(name,"monitor_ping_timeout")) return (int)variables.monitor_ping_timeout;
		if (!strcasecmp(name,"monitor_read_only_interval")) return (int)variables.monitor_read_only_interval;
		if (!strcasecmp(name,"monitor_read_only_timeout")) return (int)variables.monitor_read_only_timeout;
		if (!strcasecmp(name,"monitor_replication_lag_interval")) return (int)variables.monitor_replication_lag_interval;
		if (!strcasecmp(name,"monitor_replication_lag_timeout")) return (int)variables.monitor_replication_lag_timeout;
		if (!strcasecmp(name,"monitor_query_interval")) return (int)variables.monitor_query_interval;
		if (!strcasecmp(name,"monitor_query_timeout")) return (int)variables.monitor_query_timeout;
		if (!strcasecmp(name,"monitor_slave_lag_when_null")) return (int)variables.monitor_slave_lag_when_null;
		if (!strcasecmp(name,"monitor_writer_is_also_reader")) return (int)variables.monitor_writer_is_also_reader;
	}
	if (!strcasecmp(name,"shun_on_failures")) return (int)variables.shun_on_failures;
	if (!strcasecmp(name,"shun_recovery_time_sec")) return (int)variables.shun_recovery_time_sec;
	if (!strcasecmp(name,"query_retries_on_failure")) return (int)variables.query_retries_on_failure;
	if (!strcasecmp(name,"connect_retries_on_failure")) return (int)variables.connect_retries_on_failure;
	if (!strcasecmp(name,"connection_max_age_ms")) return (int)variables.connection_max_age_ms;
	if (!strcasecmp(name,"connect_timeout_server")) return (int)variables.connect_timeout_server;
	if (!strcasecmp(name,"connect_timeout_server_max")) return (int)variables.connect_timeout_server_max;
	if (!strcasecmp(name,"connect_retries_delay")) return (int)variables.connect_retries_delay;
	if (!strcasecmp(name,"eventslog_filesize")) return (int)variables.eventslog_filesize;
	if (!strcasecmp(name,"max_allowed_packet")) return (int)variables.max_allowed_packet;
	if (!strcasecmp(name,"max_transaction_time")) return (int)variables.max_transaction_time;
	if (!strcasecmp(name,"hostgroup_manager_verbose")) return (int)variables.hostgroup_manager_verbose;
	if (!strcasecmp(name,"threshold_query_length")) return (int)variables.threshold_query_length;
	if (!strcasecmp(name,"threshold_resultset_size")) return (int)variables.threshold_resultset_size;
	if (!strcasecmp(name,"query_digests_max_digest_length")) return (int)variables.query_digests_max_digest_length;
	if (!strcasecmp(name,"query_digests_max_query_length")) return (int)variables.query_digests_max_query_length;
	if (!strcasecmp(name,"wait_timeout")) return (int)variables.wait_timeout;
	if (!strcasecmp(name,"max_connections")) return (int)variables.max_connections;
	if (!strcasecmp(name,"max_stmts_per_connection")) return (int)variables.max_stmts_per_connection;
	if (!strcasecmp(name,"max_stmts_cache")) return (int)variables.max_stmts_cache;
	if (!strcasecmp(name,"default_query_delay")) return (int)variables.default_query_delay;
	if (!strcasecmp(name,"default_query_timeout")) return (int)variables.default_query_timeout;
	if (!strcasecmp(name,"query_processor_iterations")) return (int)variables.query_processor_iterations;
	if (!strcasecmp(name,"query_processor_regex")) return (int)variables.query_processor_regex;
	if (!strcasecmp(name,"default_max_latency_ms")) return (int)variables.default_max_latency_ms;
	if (!strcasecmp(name,"long_query_time")) return (int)variables.long_query_time;
	if (!strcasecmp(name,"query_cache_size_MB")) return (int)variables.query_cache_size_MB;
	if (!strcasecmp(name,"free_connections_pct")) return (int)variables.free_connections_pct;
#ifdef IDLE_THREADS
	if (!strcasecmp(name,"session_idle_ms")) return (int)variables.session_idle_ms;
#endif // IDLE_THREADS
	if (!strcasecmp(name,"ping_interval_server_msec")) return (int)variables.ping_interval_server_msec;
	if (!strcasecmp(name,"ping_timeout_server")) return (int)variables.ping_timeout_server;
	if (!strcasecmp(name,"have_compress")) return (int)variables.have_compress;
	if (!strcasecmp(name,"client_found_rows")) return (int)variables.client_found_rows;
	if (!strcasecmp(name,"multiplexing")) return (int)variables.multiplexing;
	if (!strcasecmp(name,"forward_autocommit")) return (int)variables.forward_autocommit;
	if (!strcasecmp(name,"enforce_autocommit_on_reads")) return (int)variables.enforce_autocommit_on_reads;
	if (!strcasecmp(name,"commands_stats")) return (int)variables.commands_stats;
	if (!strcasecmp(name,"query_digests")) return (int)variables.query_digests;
	if (!strcasecmp(name,"query_digests_lowercase")) return (int)variables.query_digests_lowercase;
	if (!strcasecmp(name,"sessions_sort")) return (int)variables.sessions_sort;
#ifdef IDLE_THREADS
	if (!strcasecmp(name,"session_idle_show_processlist")) return (int)variables.session_idle_show_processlist;
#endif // IDLE_THREADS
	if (!strcasecmp(name,"servers_stats")) return (int)variables.servers_stats;
	if (!strcasecmp(name,"default_reconnect")) return (int)variables.default_reconnect;
	if (!strcasecmp(name,"poll_timeout")) return variables.poll_timeout;
	if (!strcasecmp(name,"poll_timeout_on_failure")) return variables.poll_timeout_on_failure;
	if (!strcasecmp(name,"stacksize")) return ( stacksize ? stacksize : DEFAULT_STACK_SIZE);
	proxy_error("Not existing variable: %s\n", name); assert(0);
	return 0;
}

char * MySQL_Threads_Handler::get_variable(char *name) {	// this is the public function, accessible from admin
#define INTBUFSIZE	4096
	char intbuf[INTBUFSIZE];
	if (!strcasecmp(name,"init_connect")) {
		if (variables.init_connect==NULL || strlen(variables.init_connect)==0) {
			return NULL;
		} else {
			return strdup(variables.init_connect);
		}
	}
	if (!strcasecmp(name,"default_sql_mode")) {
		if (variables.default_sql_mode==NULL) {
			variables.default_sql_mode=strdup((char *)MYSQL_DEFAULT_SQL_MODE);
		}
		return strdup(variables.default_sql_mode);
	}
	if (!strcasecmp(name,"default_time_zone")) {
		if (variables.default_time_zone==NULL) {
			variables.default_time_zone=strdup((char *)MYSQL_DEFAULT_TIME_ZONE);
		}
		return strdup(variables.default_time_zone);
	}
	if (!strcasecmp(name,"server_version")) return strdup(variables.server_version);
	if (!strcasecmp(name,"eventslog_filename")) return strdup(variables.eventslog_filename);
	if (!strcasecmp(name,"default_schema")) return strdup(variables.default_schema);
	if (!strcasecmp(name,"interfaces")) return strdup(variables.interfaces);
	if (!strcasecmp(name,"server_capabilities")) {
		// FIXME : make it human readable
		sprintf(intbuf,"%d",variables.server_capabilities);
		return strdup(intbuf);
	}
	// SSL variables
	if (!strncasecmp(name,"ssl_",4)) {
		if (!strcasecmp(name,"ssl_p2s_ca")) {
			if (variables.ssl_p2s_ca==NULL || strlen(variables.ssl_p2s_ca)==0) {
				return NULL;
			} else {
				return strdup(variables.ssl_p2s_ca);
			}
		}
		if (!strcasecmp(name,"ssl_p2s_cert")) {
			if (variables.ssl_p2s_cert==NULL || strlen(variables.ssl_p2s_cert)==0) {
				return NULL;
			} else {
				return strdup(variables.ssl_p2s_cert);
			}
		}
		if (!strcasecmp(name,"ssl_p2s_key")) {
			if (variables.ssl_p2s_key==NULL || strlen(variables.ssl_p2s_key)==0) {
				return NULL;
			} else {
				return strdup(variables.ssl_p2s_key);
			}
		}
		if (!strcasecmp(name,"ssl_p2s_cipher")) {
			if (variables.ssl_p2s_cipher==NULL || strlen(variables.ssl_p2s_cipher)==0) {
				return NULL;
			} else {
				return strdup(variables.ssl_p2s_cipher);
			}
		}
	}
	// monitor variables
	if (!strncasecmp(name,"monitor_",8)) {
		if (!strcasecmp(name,"monitor_username")) return strdup(variables.monitor_username);
		if (!strcasecmp(name,"monitor_password")) return strdup(variables.monitor_password);
		if (!strcasecmp(name,"monitor_enabled")) {
			return strdup((variables.monitor_enabled ? "true" : "false"));
		}
		if (!strcasecmp(name,"monitor_history")) {
			sprintf(intbuf,"%d",variables.monitor_history);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_connect_interval")) {
			sprintf(intbuf,"%d",variables.monitor_connect_interval);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_connect_timeout")) {
			sprintf(intbuf,"%d",variables.monitor_connect_timeout);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_ping_interval")) {
			sprintf(intbuf,"%d",variables.monitor_ping_interval);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_ping_max_failures")) {
			sprintf(intbuf,"%d",variables.monitor_ping_max_failures);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_ping_timeout")) {
			sprintf(intbuf,"%d",variables.monitor_ping_timeout);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_read_only_interval")) {
			sprintf(intbuf,"%d",variables.monitor_read_only_interval);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_read_only_timeout")) {
			sprintf(intbuf,"%d",variables.monitor_read_only_timeout);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_replication_lag_interval")) {
			sprintf(intbuf,"%d",variables.monitor_replication_lag_interval);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_replication_lag_timeout")) {
			sprintf(intbuf,"%d",variables.monitor_replication_lag_timeout);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_query_interval")) {
			sprintf(intbuf,"%d",variables.monitor_query_interval);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_query_timeout")) {
			sprintf(intbuf,"%d",variables.monitor_query_timeout);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_slave_lag_when_null")) {
			sprintf(intbuf,"%d",variables.monitor_slave_lag_when_null);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"monitor_writer_is_also_reader")) {
			return strdup((variables.monitor_writer_is_also_reader ? "true" : "false"));
		}
	}
	if (!strcasecmp(name,"default_charset")) {
		const CHARSET_INFO *c = proxysql_find_charset_nr(variables.default_charset);
		if (!c) {
			proxy_error("Not existing charset number %u\n", variables.default_charset);
			assert(c);
		}
		return strdup(c->csname);
	}
	if (!strcasecmp(name,"shun_on_failures")) {
		sprintf(intbuf,"%d",variables.shun_on_failures);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"shun_recovery_time_sec")) {
		sprintf(intbuf,"%d",variables.shun_recovery_time_sec);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"query_retries_on_failure")) {
		sprintf(intbuf,"%d",variables.query_retries_on_failure);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"connect_retries_on_failure")) {
		sprintf(intbuf,"%d",variables.connect_retries_on_failure);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"connection_max_age_ms")) {
		sprintf(intbuf,"%d",variables.connection_max_age_ms);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"connect_timeout_server")) {
		sprintf(intbuf,"%d",variables.connect_timeout_server);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"connect_timeout_server_max")) {
		sprintf(intbuf,"%d",variables.connect_timeout_server_max);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"free_connections_pct")) {
		sprintf(intbuf,"%d",variables.free_connections_pct);
		return strdup(intbuf);
	}
#ifdef IDLE_THREADS
	if (!strcasecmp(name,"session_idle_ms")) {
		sprintf(intbuf,"%d",variables.session_idle_ms);
		return strdup(intbuf);
	}
#endif // IDLE_THREADS
	if (!strcasecmp(name,"connect_retries_delay")) {
		sprintf(intbuf,"%d",variables.connect_retries_delay);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"eventslog_filesize")) {
		sprintf(intbuf,"%d",variables.eventslog_filesize);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"max_allowed_packet")) {
		sprintf(intbuf,"%d",variables.max_allowed_packet);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"max_transaction_time")) {
		sprintf(intbuf,"%d",variables.max_transaction_time);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"hostgroup_manager_verbose")) {
		sprintf(intbuf,"%d",variables.hostgroup_manager_verbose);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"threshold_query_length")) {
		sprintf(intbuf,"%d",variables.threshold_query_length);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"threshold_resultset_size")) {
		sprintf(intbuf,"%d",variables.threshold_resultset_size);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"query_digests_max_digest_length")) {
		sprintf(intbuf,"%d",variables.query_digests_max_digest_length);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"query_digests_max_query_length")) {
		sprintf(intbuf,"%d",variables.query_digests_max_query_length);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"wait_timeout")) {
		sprintf(intbuf,"%d",variables.wait_timeout);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"max_connections")) {
		sprintf(intbuf,"%d",variables.max_connections);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"max_stmts_per_connection")) {
		sprintf(intbuf,"%d",variables.max_stmts_per_connection);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"max_stmts_cache")) {
		sprintf(intbuf,"%d",variables.max_stmts_cache);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"default_query_delay")) {
		sprintf(intbuf,"%d",variables.default_query_delay);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"default_query_timeout")) {
		sprintf(intbuf,"%d",variables.default_query_timeout);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"query_processor_iterations")) {
		sprintf(intbuf,"%d",variables.query_processor_iterations);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"query_processor_regex")) {
		sprintf(intbuf,"%d",variables.query_processor_regex);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"default_max_latency_ms")) {
		sprintf(intbuf,"%d",variables.default_max_latency_ms);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"long_query_time")) {
		sprintf(intbuf,"%d",variables.long_query_time);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"query_cache_size_MB")) {
		sprintf(intbuf,"%d",variables.query_cache_size_MB);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"ping_interval_server_msec")) {
		sprintf(intbuf,"%d",variables.ping_interval_server_msec);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"ping_timeout_server")) {
		sprintf(intbuf,"%d",variables.ping_timeout_server);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"poll_timeout")) {
		sprintf(intbuf,"%d",variables.poll_timeout);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"poll_timeout_on_failure")) {
		sprintf(intbuf,"%d",variables.poll_timeout_on_failure);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"threads")) {
		sprintf(intbuf,"%d", (num_threads ? num_threads : DEFAULT_NUM_THREADS));
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"stacksize")) {
		sprintf(intbuf,"%d", (int)(stacksize ? stacksize : DEFAULT_STACK_SIZE));
		return strdup(intbuf);
	}
#ifdef DEBUG
	if (!strcasecmp(name,"session_debug")) {
		return strdup((variables.session_debug ? "true" : "false"));
	}
#endif /* DEBUG */
	if (!strcasecmp(name,"have_compress")) {
		return strdup((variables.have_compress ? "true" : "false"));
	}
	if (!strcasecmp(name,"client_found_rows")) {
		return strdup((variables.client_found_rows ? "true" : "false"));
	}
	if (!strcasecmp(name,"multiplexing")) {
		return strdup((variables.multiplexing ? "true" : "false"));
	}
	if (!strcasecmp(name,"forward_autocommit")) {
		return strdup((variables.forward_autocommit ? "true" : "false"));
	}
	if (!strcasecmp(name,"enforce_autocommit_on_reads")) {
		return strdup((variables.enforce_autocommit_on_reads ? "true" : "false"));
	}
	if (!strcasecmp(name,"commands_stats")) {
		return strdup((variables.commands_stats ? "true" : "false"));
	}
	if (!strcasecmp(name,"query_digests")) {
		return strdup((variables.query_digests ? "true" : "false"));
	}
	if (!strcasecmp(name,"query_digests_lowercase")) {
		return strdup((variables.query_digests_lowercase ? "true" : "false"));
	}
	if (!strcasecmp(name,"sessions_sort")) {
		return strdup((variables.sessions_sort ? "true" : "false"));
	}
#ifdef IDLE_THREADS
	if (!strcasecmp(name,"session_idle_show_processlist")) {
		return strdup((variables.session_idle_show_processlist ? "true" : "false"));
	}
#endif // IDLE_THREADS
	if (!strcasecmp(name,"servers_stats")) {
		return strdup((variables.servers_stats ? "true" : "false"));
	}
	if (!strcasecmp(name,"default_reconnect")) {
		return strdup((variables.default_reconnect ? "true" : "false"));
	}
	return NULL;
}



bool MySQL_Threads_Handler::set_variable(char *name, char *value) {	// this is the public function, accessible from admin
	// IN:
	// name: variable name
	// value: variable value
	//
	// OUT:
	// false: unable to change the variable value, either because doesn't exist, or because out of range, or read only
	// true: variable value changed
	//
	if (!value) return false;
	size_t vallen=strlen(value);

	// monitor variables
	if (!strncasecmp(name,"monitor_",8)) {
		if (!strcasecmp(name,"monitor_username")) {
			if (vallen) {
				free(variables.monitor_username);
				variables.monitor_username=strdup(value);
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_password")) {
			free(variables.monitor_password);
			variables.monitor_password=strdup(value);
			return true;
		}
		if (!strcasecmp(name,"monitor_enabled")) {
			if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
				variables.monitor_enabled=true;
				return true;
			}
			if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
				variables.monitor_enabled=false;
				return true;
			}
			return false;
		}
		if (!strcasecmp(name,"monitor_history")) {
			int intv=atoi(value);
			if (intv >= 1000 && intv <= 7*24*3600*1000) {
				variables.monitor_history=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_connect_interval")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 7*24*3600*1000) {
				variables.monitor_connect_interval=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_connect_timeout")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 600*1000) {
				variables.monitor_connect_timeout=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_ping_interval")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 7*24*3600*1000) {
				variables.monitor_ping_interval=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_ping_max_failures")) {
			int intv=atoi(value);
			if (intv >= 1 && intv <= 1000*1000) {
				variables.monitor_ping_max_failures=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_ping_timeout")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 600*1000) {
				variables.monitor_ping_timeout=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_read_only_interval")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 7*24*3600*1000) {
				variables.monitor_read_only_interval=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_read_only_timeout")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 600*1000) {
				variables.monitor_read_only_timeout=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_replication_lag_interval")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 7*24*3600*1000) {
				variables.monitor_replication_lag_interval=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_replication_lag_timeout")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 600*1000) {
				variables.monitor_replication_lag_timeout=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_query_interval")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 7*24*3600*1000) {
				variables.monitor_query_interval=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_query_timeout")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 600*1000) {
				variables.monitor_query_timeout=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_slave_lag_when_null")) {
			int intv=atoi(value);
			if (intv >= 0 && intv <= 604800) {
				variables.monitor_slave_lag_when_null=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_writer_is_also_reader")) {
			if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
				variables.monitor_writer_is_also_reader=true;
				return true;
			}
			if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
				variables.monitor_writer_is_also_reader=false;
				return true;
			}
			return false;
		}
	}
	if (!strcasecmp(name,"max_allowed_packet")) {
		int intv=atoi(value);
		if (intv >= 8192 && intv <= 1024*1024*1024) {
			variables.max_allowed_packet=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"max_transaction_time")) {
		int intv=atoi(value);
		if (intv >= 1000 && intv <= 20*24*3600*1000) {
			variables.max_transaction_time=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"hostgroup_manager_verbose")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1) {
			variables.hostgroup_manager_verbose=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"threshold_query_length")) {
		int intv=atoi(value);
		if (intv >= 1024 && intv <= 1*1024*1024*1024) {
			variables.threshold_query_length=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"threshold_resultset_size")) {
		int intv=atoi(value);
		if (intv >= 1024 && intv <= 1*1024*1024*1024) {
			variables.threshold_resultset_size=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"query_digests_max_digest_length")) {
		int intv=atoi(value);
		if (intv >= 16 && intv <= 1*1024*1024) {
			variables.query_digests_max_digest_length=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"query_digests_max_query_length")) {
		int intv=atoi(value);
		if (intv >= 16 && intv <= 16*1024*1024) {
			variables.query_digests_max_query_length=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"wait_timeout")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 20*24*3600*1000) {
			variables.wait_timeout=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"free_connections_pct")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 100) {
			variables.free_connections_pct=intv;
			return true;
		} else {
			return false;
		}
	}
#ifdef IDLE_THREADS
	if (!strcasecmp(name,"session_idle_ms")) {
		int intv=atoi(value);
		if (intv >= 100 && intv <= 3600*1000) {
			variables.session_idle_ms=intv;
			return true;
		} else {
			return false;
		}
	}
#endif // IDLE_THREADS
	if (!strcasecmp(name,"max_connections")) {
		int intv=atoi(value);
		if (intv >= 1 && intv <= 1000*1000) {
			variables.max_connections=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"max_stmts_per_connection")) {
		int intv=atoi(value);
		if (intv >= 1 && intv <= 1024) {
			variables.max_stmts_per_connection=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"max_stmts_cache")) {
		int intv=atoi(value);
		if (intv >= 1024 && intv <= 1024*1024) {
			variables.max_stmts_cache=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"default_query_delay")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 3600*1000) {
			variables.default_query_delay=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"default_query_timeout")) {
		int intv=atoi(value);
		if (intv >= 1000 && intv <= 20*24*3600*1000) {
			variables.default_query_timeout=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"query_processor_iterations")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000*1000) {
			variables.query_processor_iterations=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"query_processor_regex")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000*1000) {
			variables.query_processor_regex=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"default_max_latency_ms")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 20*24*3600*1000) {
			variables.default_max_latency_ms=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"long_query_time")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 20*24*3600*1000) {
			variables.long_query_time=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"query_cache_size_MB")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1024*10240) {
			variables.query_cache_size_MB=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"ping_interval_server_msec")) {
		int intv=atoi(value);
		if (intv >= 1000 && intv <= 7*24*3600*1000) {
			variables.ping_interval_server_msec=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"ping_timeout_server")) {
		int intv=atoi(value);
		if (intv >= 10 && intv <= 600*1000) {
			variables.ping_timeout_server=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"shun_on_failures")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 10000000) {
			variables.shun_on_failures=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"shun_recovery_time_sec")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 3600*24*365) {
			variables.shun_recovery_time_sec=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"query_retries_on_failure")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000) {
			variables.query_retries_on_failure=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"connect_retries_on_failure")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000) {
			variables.connect_retries_on_failure=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"connection_max_age_ms")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 3600*24*1000) {
			variables.connection_max_age_ms=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"connect_timeout_server")) {
		int intv=atoi(value);
		if (intv >= 10 && intv <= 120*1000) {
			variables.connect_timeout_server=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"connect_timeout_server_max")) {
		int intv=atoi(value);
		if (intv >= 10 && intv <= 3600*1000) {
			variables.connect_timeout_server_max=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"connect_retries_delay")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 10000) {
			variables.connect_retries_delay=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"eventslog_filesize")) {
		int intv=atoi(value);
		if (intv >= 1024*1024 && intv <= 1*1024*1024*1024) {
			variables.eventslog_filesize=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"default_schema")) {
		if (vallen) {
			free(variables.default_schema);
			variables.default_schema=strdup(value);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"interfaces")) {
		if (vallen && strlen(variables.interfaces)==0) {
			free(variables.interfaces);
			variables.interfaces=strdup(value);
			return true;
		} else {
			if (vallen && strcmp(value,variables.interfaces)==0) {
				return true;
			} else {
				return false;
			}
		}
	}
	if (!strcasecmp(name,"server_version")) {
		if (vallen) {
			free(variables.server_version);
			if (strcmp(value,(const char *)"5.1.30")==0) { // per issue #632 , the default 5.1.30 is replaced with 5.5.30
				variables.server_version=strdup((char *)"5.5.30");
			} else {
				variables.server_version=strdup(value);
			}
			return true;
		} else {
			return false;
		}
	}

	if (!strcasecmp(name,"init_connect")) {
		if (variables.init_connect) free(variables.init_connect);
		variables.init_connect=NULL;
		if (vallen) {
			if (strcmp(value,"(null)"))
				variables.init_connect=strdup(value);
		}
		return true;
	}

	if (!strcasecmp(name,"default_sql_mode")) {
		if (variables.default_sql_mode) free(variables.default_sql_mode);
		variables.default_sql_mode=NULL;
		if (vallen) {
			if (strcmp(value,"(null)"))
				variables.default_sql_mode=strdup(value);
		}
		if (variables.default_sql_mode==NULL) {
			variables.default_sql_mode=strdup((char *)MYSQL_DEFAULT_SQL_MODE); // default
		}
		return true;
	}

	if (!strcasecmp(name,"default_time_zone")) {
		if (variables.default_time_zone) free(variables.default_time_zone);
		variables.default_time_zone=NULL;
		if (vallen) {
			if (strcmp(value,"(null)"))
				variables.default_time_zone=strdup(value);
		}
		if (variables.default_time_zone==NULL) {
			variables.default_time_zone=strdup((char *)MYSQL_DEFAULT_TIME_ZONE); // default
		}
		return true;
	}

	// SSL proxy to server variables
	if (!strcasecmp(name,"ssl_p2s_ca")) {
		if (variables.ssl_p2s_ca) free(variables.ssl_p2s_ca);
		variables.ssl_p2s_ca=NULL;
		if (vallen) {
			if (strcmp(value,"(null)"))
				variables.ssl_p2s_ca=strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name,"ssl_p2s_cert")) {
		if (variables.ssl_p2s_cert) free(variables.ssl_p2s_cert);
		variables.ssl_p2s_cert=NULL;
		if (vallen) {
			if (strcmp(value,"(null)"))
				variables.ssl_p2s_cert=strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name,"ssl_p2s_key")) {
		if (variables.ssl_p2s_key) free(variables.ssl_p2s_key);
		variables.ssl_p2s_key=NULL;
		if (vallen) {
			if (strcmp(value,"(null)"))
				variables.ssl_p2s_key=strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name,"ssl_p2s_cipher")) {
		if (variables.ssl_p2s_cipher) free(variables.ssl_p2s_cipher);
		variables.ssl_p2s_cipher=NULL;
		if (vallen) {
			if (strcmp(value,"(null)"))
				variables.ssl_p2s_cipher=strdup(value);
		}
		return true;
	}

	if (!strcasecmp(name,"eventslog_filename")) {
		free(variables.eventslog_filename);
		variables.eventslog_filename=strdup(value);
		return true;
	}
	if (!strcasecmp(name,"server_capabilities")) {
		int intv=atoi(value);
		if (intv > 10 && intv <= 65535) {
			variables.server_capabilities=intv;
			if (variables.server_capabilities & CLIENT_SSL) {
				// for now disable CLIENT_SSL
				variables.server_capabilities &= ~CLIENT_SSL;
			}
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"poll_timeout")) {
		int intv=atoi(value);
		if (intv >= 10 && intv <= 20000) {
			variables.poll_timeout=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"poll_timeout_on_failure")) {
		int intv=atoi(value);
		if (intv >= 10 && intv <= 20000) {
			variables.poll_timeout_on_failure=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"default_charset")) {
		if (vallen) {
			CHARSET_INFO * c=proxysql_find_charset_name(value);
			if (c) {
				variables.default_charset=c->nr;
				return true;
			} else {
				return false;
			}
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"stacksize")) {
		int intv=atoi(value);
		if (intv >= 256*1024 && intv <= 4*1024*1024) {
			stacksize=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"threads")) {
		unsigned int intv=atoi(value);
		if ((num_threads==0 || num_threads==intv || mysql_threads==NULL) && intv > 0 && intv < 256) {
			num_threads=intv;
			return true;
		} else {
			return false;
		}
	}
#ifdef DEBUG
	if (!strcasecmp(name,"session_debug")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.session_debug=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.session_debug=false;
			return true;
		}
		return false;
	}
#endif /* DEBUG */
	if (!strcasecmp(name,"have_compress")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.have_compress=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.have_compress=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"client_found_rows")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.client_found_rows=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.client_found_rows=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"multiplexing")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.multiplexing=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.multiplexing=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"forward_autocommit")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.forward_autocommit=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.forward_autocommit=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"enforce_autocommit_on_reads")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.enforce_autocommit_on_reads=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.enforce_autocommit_on_reads=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"commands_stats")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.commands_stats=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.commands_stats=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"query_digests")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.query_digests=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.query_digests=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"query_digests_lowercase")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.query_digests_lowercase=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.query_digests_lowercase=false;
			return true;
		}
		return false;
	}
#ifdef IDLE_THREADS
	if (!strcasecmp(name,"session_idle_show_processlist")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.session_idle_show_processlist=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.session_idle_show_processlist=false;
			return true;
		}
		return false;
	}
#endif // IDLE_THREADS
	if (!strcasecmp(name,"sessions_sort")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.sessions_sort=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.sessions_sort=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"servers_stats")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.servers_stats=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.servers_stats=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"default_reconnect")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.default_reconnect=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.default_reconnect=false;
			return true;
		}
		return false;
	}
	return false;
}

char ** MySQL_Threads_Handler::get_variables_list() {
	size_t l=sizeof(mysql_thread_variables_names)/sizeof(char *);
	unsigned int i;
	char **ret=(char **)malloc(sizeof(char *)*l);
	for (i=0;i<l;i++) {
		ret[i]=(i==l-1 ? NULL : strdup(mysql_thread_variables_names[i]));
	}
	return ret;
}

// Returns true if the given name is the name of an existing mysql variable
bool MySQL_Threads_Handler::has_variable(const char *name) {
	size_t no_vars = sizeof(mysql_thread_variables_names) / sizeof(char *);
	for (unsigned int i = 0; i < no_vars-1 ; ++i) {
		size_t var_len = strlen(mysql_thread_variables_names[i]);
		if (strlen(name) == var_len && !strncmp(name, mysql_thread_variables_names[i], var_len)) {
			return true;
		}
	}
	return false;
}

void MySQL_Threads_Handler::print_version() {
	fprintf(stderr,"Standard MySQL Threads Handler rev. %s -- %s -- %s\n", MYSQL_THREAD_VERSION, __FILE__, __TIMESTAMP__);
}

void MySQL_Threads_Handler::init(unsigned int num, size_t stack) {
	if (stack) {
		stacksize=stack;
	} else {
		if (stacksize==0) stacksize=DEFAULT_STACK_SIZE;
	}
	if (num) {
		num_threads=num;
	} else {
		if (num_threads==0) num_threads=DEFAULT_NUM_THREADS; //default
	}
	int rc=pthread_attr_setstacksize(&attr, stacksize);
	assert(rc==0);
	mysql_threads=(proxysql_mysql_thread_t *)malloc(sizeof(proxysql_mysql_thread_t)*num_threads);
#ifdef IDLE_THREADS
	mysql_threads_idles=(proxysql_mysql_thread_t *)malloc(sizeof(proxysql_mysql_thread_t)*num_threads);
#endif // IDLE_THREADS
}

proxysql_mysql_thread_t * MySQL_Threads_Handler::create_thread(unsigned int tn, void *(*start_routine) (void *), bool idles) {
	if (idles==false) {
		pthread_create(&mysql_threads[tn].thread_id, &attr, start_routine , &mysql_threads[tn]);
#ifdef IDLE_THREADS
	} else {
		pthread_create(&mysql_threads_idles[tn].thread_id, &attr, start_routine , &mysql_threads_idles[tn]);
#endif // IDLE_THREADS
	}
	return NULL;
}

void MySQL_Threads_Handler::shutdown_threads() {
	unsigned int i;
	shutdown_=1;
	if (mysql_threads) {
		for (i=0; i<num_threads; i++) {
			if (mysql_threads[i].worker)
				mysql_threads[i].worker->shutdown=1;
		}
#ifdef IDLE_THREADS
		if (GloVars.global.idle_threads) {
			for (i=0; i<num_threads; i++) {
				if (mysql_threads_idles[i].worker)
					mysql_threads_idles[i].worker->shutdown=1;
			}
		}
#endif /* IDLE_THREADS */
		signal_all_threads(1);
		for (i=0; i<num_threads; i++) {
			if (mysql_threads[i].worker)
				pthread_join(mysql_threads[i].thread_id,NULL);
#ifdef IDLE_THREADS
			if (GloVars.global.idle_threads) {
				if (mysql_threads_idles[i].worker)
					pthread_join(mysql_threads_idles[i].thread_id,NULL);
			}
#endif /* IDLE_THREADS */
		}
	}
}

void MySQL_Threads_Handler::start_listeners() {
	char *_tmp=NULL;
	_tmp=GloMTH->get_variable((char *)"interfaces");
	if (strlen(_tmp)==0) {
		GloMTH->set_variable((char *)"interfaces", (char *)"0.0.0.0:6033;/tmp/proxysql.sock"); // set default
	}
	free(_tmp);
	tokenizer_t tok = tokenizer( variables.interfaces, ";", TOKENIZER_NO_EMPTIES );
	const char* token;
	for (token = tokenize( &tok ); token; token = tokenize( &tok )) {
		listener_add((char *)token);
	}
	free_tokenizer( &tok );
}

void MySQL_Threads_Handler::stop_listeners() {
	if (variables.interfaces==NULL || strlen(variables.interfaces)==0)
		return;
	tokenizer_t tok = tokenizer( variables.interfaces, ";", TOKENIZER_NO_EMPTIES );
	const char* token;
	for (token = tokenize( &tok ); token; token = tokenize( &tok )) {
		listener_del((char *)token);
	}
	free_tokenizer( &tok );
}

MySQL_Threads_Handler::~MySQL_Threads_Handler() {
	if (variables.monitor_username) { free(variables.monitor_username); variables.monitor_username=NULL; }
	if (variables.monitor_password) { free(variables.monitor_password); variables.monitor_password=NULL; }
	if (variables.default_schema) free(variables.default_schema);
	if (variables.interfaces) free(variables.interfaces);
	if (variables.server_version) free(variables.server_version);
	if (variables.init_connect) free(variables.init_connect);
	if (variables.default_sql_mode) free(variables.default_sql_mode);
	if (variables.default_time_zone) free(variables.default_time_zone);
	if (variables.eventslog_filename) free(variables.eventslog_filename);
	if (variables.ssl_p2s_ca) free(variables.ssl_p2s_ca);
	if (variables.ssl_p2s_cert) free(variables.ssl_p2s_cert);
	if (variables.ssl_p2s_key) free(variables.ssl_p2s_key);
	if (variables.ssl_p2s_cipher) free(variables.ssl_p2s_cipher);
	free(mysql_threads);
	mysql_threads=NULL;
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		free(mysql_threads_idles);
		mysql_threads_idles=NULL;
	}
#endif // IDLE_THREADS
	delete MLM;
	MLM=NULL;
}

MySQL_Thread::~MySQL_Thread() {

	if (mysql_sessions) {
		while(mysql_sessions->len) {
			MySQL_Session *sess=(MySQL_Session *)mysql_sessions->remove_index_fast(0);
				delete sess;
			}
		delete mysql_sessions;
	}

#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		if (idle_mysql_sessions) {
			while(idle_mysql_sessions->len) {
				MySQL_Session *sess=(MySQL_Session *)idle_mysql_sessions->remove_index_fast(0);
					delete sess;
				}
			delete idle_mysql_sessions;
		}

		if (resume_mysql_sessions) {
			while(resume_mysql_sessions->len) {
				MySQL_Session *sess=(MySQL_Session *)resume_mysql_sessions->remove_index_fast(0);
					delete sess;
				}
			delete resume_mysql_sessions;
		}

		if (myexchange.idle_mysql_sessions) {
			while(myexchange.idle_mysql_sessions->len) {
				MySQL_Session *sess=(MySQL_Session *)myexchange.idle_mysql_sessions->remove_index_fast(0);
					delete sess;
				}
			delete myexchange.idle_mysql_sessions;
		}

		if (myexchange.resume_mysql_sessions) {
			while(myexchange.resume_mysql_sessions->len) {
				MySQL_Session *sess=(MySQL_Session *)myexchange.resume_mysql_sessions->remove_index_fast(0);
					delete sess;
				}
			delete myexchange.resume_mysql_sessions;
		}
	}
#endif // IDLE_THREADS

	if (cached_connections) {
		while(cached_connections->len) {
			MySQL_Connection *c=(MySQL_Connection *)cached_connections->remove_index_fast(0);
				delete c;
			}
		delete cached_connections;
	}

	unsigned int i;
	for (i=0;i<mypolls.len;i++) {
		if (
			mypolls.myds[i] && // fix bug #278 . This should be caused by not initialized datastreams used to ping the backend
			mypolls.myds[i]->myds_type==MYDS_LISTENER) {
			delete mypolls.myds[i];
		}
	}

	if (my_idle_conns)
		free(my_idle_conns);
	GloQPro->end_thread();

	if (mysql_thread___monitor_username) { free(mysql_thread___monitor_username); mysql_thread___monitor_username=NULL; }
	if (mysql_thread___monitor_password) { free(mysql_thread___monitor_password); mysql_thread___monitor_password=NULL; }
	if (mysql_thread___default_schema) { free(mysql_thread___default_schema); mysql_thread___default_schema=NULL; }
	if (mysql_thread___server_version) { free(mysql_thread___server_version); mysql_thread___server_version=NULL; }
	if (mysql_thread___init_connect) { free(mysql_thread___init_connect); mysql_thread___init_connect=NULL; }
	if (mysql_thread___default_sql_mode) { free(mysql_thread___default_sql_mode); mysql_thread___default_sql_mode=NULL; }
	if (mysql_thread___default_time_zone) { free(mysql_thread___default_time_zone); mysql_thread___default_time_zone=NULL; }
	if (mysql_thread___eventslog_filename) { free(mysql_thread___eventslog_filename); mysql_thread___eventslog_filename=NULL; }
	if (mysql_thread___ssl_p2s_ca) { free(mysql_thread___ssl_p2s_ca); mysql_thread___ssl_p2s_ca=NULL; }
	if (mysql_thread___ssl_p2s_cert) { free(mysql_thread___ssl_p2s_cert); mysql_thread___ssl_p2s_cert=NULL; }
	if (mysql_thread___ssl_p2s_key) { free(mysql_thread___ssl_p2s_key); mysql_thread___ssl_p2s_key=NULL; }
	if (mysql_thread___ssl_p2s_cipher) { free(mysql_thread___ssl_p2s_cipher); mysql_thread___ssl_p2s_cipher=NULL; }
}

MySQL_Session * MySQL_Thread::create_new_session_and_client_data_stream(int _fd) {
	int arg_on=1;
	MySQL_Session *sess=new MySQL_Session;
	register_session(sess); // register session
	sess->client_myds = new MySQL_Data_Stream();
	sess->client_myds->fd=_fd;
	setsockopt(sess->client_myds->fd, IPPROTO_TCP, TCP_NODELAY, (char *) &arg_on, sizeof(int));
#ifdef __APPLE__
		setsockopt(sess->client_myds->fd, SOL_SOCKET, SO_NOSIGPIPE, (char *) &arg_on, sizeof(int));
#endif
	sess->client_myds->init(MYDS_FRONTEND, sess, sess->client_myds->fd);
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p, DataStream=%p -- Created new client Data Stream\n", sess->thread, sess, sess->client_myds);
#ifdef DEBUG
	sess->client_myds->myprot.dump_pkt=true;
#endif
	MySQL_Connection *myconn=new MySQL_Connection();
	sess->client_myds->attach_connection(myconn);
	myconn->set_is_client(); // this is used for prepared statements
	myconn->last_time_used=curtime;
	myconn->myds=sess->client_myds; // 20141011
	myconn->fd=sess->client_myds->fd; // 20141011

	sess->client_myds->myprot.init(&sess->client_myds, sess->client_myds->myconn->userinfo, sess);
	return sess;
}

bool MySQL_Thread::init() {
	int i;
	mysql_sessions = new PtrArray();
	cached_connections = new PtrArray();
	assert(mysql_sessions);

#ifdef IDLE_THREADS
	idle_mysql_sessions = new PtrArray();
	resume_mysql_sessions = new PtrArray();

	myexchange.idle_mysql_sessions = new PtrArray();
	myexchange.resume_mysql_sessions = new PtrArray();
	pthread_mutex_init(&myexchange.mutex_idles,NULL);
	pthread_mutex_init(&myexchange.mutex_resumes,NULL);
	assert(idle_mysql_sessions);
	assert(resume_mysql_sessions);
#endif // IDLE_THREADS

	shutdown=0;
	my_idle_conns=(MySQL_Connection **)malloc(sizeof(MySQL_Connection *)*SESSIONS_FOR_CONNECTIONS_HANDLER);
	memset(my_idle_conns,0,sizeof(MySQL_Connection *)*SESSIONS_FOR_CONNECTIONS_HANDLER);
	GloQPro->init_thread();
	refresh_variables();
	i=pipe(pipefd);
	ioctl_FIONBIO(pipefd[1],1);
	mypolls.add(POLLIN, pipefd[0], NULL, 0);
	assert(i==0);
	return true;
}

struct pollfd * MySQL_Thread::get_pollfd(unsigned int i) {
	return &mypolls.fds[i];
}

void MySQL_Thread::poll_listener_add(int sock) {
	MySQL_Data_Stream *listener_DS = new MySQL_Data_Stream();
	listener_DS->myds_type=MYDS_LISTENER;
	listener_DS->fd=sock;

	proxy_debug(PROXY_DEBUG_NET,1,"Created listener %p for socket %d\n", listener_DS, sock);
	mypolls.add(POLLIN, sock, listener_DS, monotonic_time());
}

void MySQL_Thread::poll_listener_del(int sock) {
	int i=mypolls.find_index(sock);
	if (i>=0) {
		MySQL_Data_Stream *myds=mypolls.myds[i];
		mypolls.remove_index_fast(i);
		myds->fd=-1;	// this to prevent that delete myds will shutdown the fd;
		delete myds;
	}
}

void MySQL_Thread::register_session(MySQL_Session *_sess, bool up_start) {
	if (mysql_sessions==NULL) {
		mysql_sessions = new PtrArray();
	}
	mysql_sessions->add(_sess);
	_sess->thread=this;
	if (up_start)
		_sess->start_time=curtime;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Registered new session\n", _sess->thread, _sess);
}

void MySQL_Thread::unregister_session(int idx) {
	if (mysql_sessions==NULL) return;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Unregistered session\n", this, mysql_sessions->index(idx));
	mysql_sessions->remove_index_fast(idx);
}


// main loop
void MySQL_Thread::run() {
	unsigned int n;
	int rc;

#ifdef IDLE_THREADS
	bool idle_maintenance_thread=epoll_thread;
	if (idle_maintenance_thread) {
		// we check if it is the first time we are called
		if (efd==-1) {
			efd = EPOLL_CREATE;
			int fd=pipefd[0];
			struct epoll_event event;
			memset(&event,0,sizeof(event)); // let's make valgrind happy
			event.events = EPOLLIN;
			event.data.u32=0; // special value to point to the pipe
			epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
		}
	}
#endif // IDLE_THREADS

	curtime=monotonic_time();

	spin_wrlock(&thread_mutex);

	while (shutdown==0) {

#ifdef IDLE_THREADS
	if (idle_maintenance_thread) {
		goto __run_skip_1;
	}
#endif // IDLE_THREADS

	int num_idles;
	if (processing_idles==true &&	(last_processing_idles < curtime-mysql_thread___ping_timeout_server*1000)) {
		processing_idles=false;
	}
	if (processing_idles==false &&  (last_processing_idles < curtime-mysql_thread___ping_interval_server_msec*1000) ) {
		int i;
		num_idles=MyHGM->get_multiple_idle_connections(-1, curtime-mysql_thread___ping_interval_server_msec*1000, my_idle_conns, SESSIONS_FOR_CONNECTIONS_HANDLER);
		for (i=0; i<num_idles; i++) {
			MySQL_Data_Stream *myds;
			MySQL_Connection *mc=my_idle_conns[i];
			MySQL_Session *sess=new MySQL_Session();
			sess->mybe=sess->find_or_create_backend(mc->parent->myhgc->hid);

			myds=sess->mybe->server_myds;
			myds->attach_connection(mc);
			myds->assign_fd_from_mysql_conn();
			myds->myds_type=MYDS_BACKEND;

			sess->to_process=1;
			myds->wait_until=curtime+mysql_thread___ping_timeout_server*1000;	// max_timeout
			mc->last_time_used=curtime;
			myds->myprot.init(&myds, myds->myconn->userinfo, NULL);
			sess->status=PINGING_SERVER;
			myds->DSS=STATE_MARIADB_PING;
			register_session_connection_handler(sess,true);
			int rc=sess->handler();
			if (rc==-1) {
				unsigned int sess_idx=mysql_sessions->len-1;
				unregister_session(sess_idx);
				delete sess;
			}
		}
		processing_idles=true;
		last_processing_idles=curtime;
	}

#ifdef IDLE_THREADS
__run_skip_1:

		if (idle_maintenance_thread) {
			pthread_mutex_lock(&myexchange.mutex_idles);
			while (myexchange.idle_mysql_sessions->len) {
				MySQL_Session *mysess=(MySQL_Session *)myexchange.idle_mysql_sessions->remove_index_fast(0);
				register_session(mysess, false);
				MySQL_Data_Stream *myds=mysess->client_myds;
				mypolls.add(POLLIN, myds->fd, myds, monotonic_time());
				// add in epoll()
				struct epoll_event event;
				memset(&event,0,sizeof(event)); // let's make valgrind happy
				event.data.u32=mysess->thread_session_id;
				event.events = EPOLLIN;
				epoll_ctl (efd, EPOLL_CTL_ADD, myds->fd, &event);
				// we map thread_id -> position in mysql_session (end of the list)
				sessmap[mysess->thread_session_id]=mysql_sessions->len-1;
				//fprintf(stderr,"Adding session %p idx, DS %p idx %d\n",mysess,myds,myds->poll_fds_idx);
			}
			pthread_mutex_unlock(&myexchange.mutex_idles);
			goto __run_skip_1a;
		}
#endif // IDLE_THREADS
		for (n = 0; n < mypolls.len; n++) {
			MySQL_Data_Stream *myds=NULL;
			myds=mypolls.myds[n];
			mypolls.fds[n].revents=0;
			if (myds) {
#ifdef IDLE_THREADS
				if (GloVars.global.idle_threads) {
					// here we try to move it to the maintenance thread
					if (myds->myds_type==MYDS_FRONTEND && myds->sess) {
						if (myds->DSS==STATE_SLEEP && myds->sess->status==WAITING_CLIENT_DATA) {
							unsigned long long _tmp_idle = mypolls.last_recv[n] > mypolls.last_sent[n] ? mypolls.last_recv[n] : mypolls.last_sent[n] ;
							if (_tmp_idle < ( (curtime > (unsigned int)mysql_thread___session_idle_ms * 1000) ? (curtime - mysql_thread___session_idle_ms * 1000) : 0)) {
								if (myds->sess->client_myds == myds && myds->PSarrayOUT->len==0 && (myds->queueOUT.head - myds->queueOUT.tail)==0 ) { // extra check
									unsigned int j;
									int conns=0;
									for (j=0;j<myds->sess->mybes->len;j++) {
										MySQL_Backend *tmp_mybe=(MySQL_Backend *)myds->sess->mybes->index(j);
										MySQL_Data_Stream *__myds=tmp_mybe->server_myds;
										if (__myds->myconn) {
											conns++;
										}
									}
									unsigned long long idle_since = curtime - myds->sess->IdleTime();
									bool exit_cond=false;
									if (conns==0) {
										mypolls.remove_index_fast(n);
										myds->mypolls=NULL;
										unsigned int i;
										for (i=0;i<mysql_sessions->len;i++) {
											MySQL_Session *mysess=(MySQL_Session *)mysql_sessions->index(i);
											if (mysess==myds->sess) {
												mysess->thread=NULL;
												unregister_session(i);
												exit_cond=true;
												mysess->idle_since = idle_since;
												idle_mysql_sessions->add(mysess);
												break;
											}
										}
									}
									if (exit_cond) {
										continue;
									}
								}
							}
						}
					}
				}
#endif // IDLE_THREADS
				if (myds->wait_until) {
					if (myds->wait_until > curtime) {
						if (mypolls.poll_timeout==0 || (myds->wait_until - curtime < mypolls.poll_timeout) ) {
							mypolls.poll_timeout= myds->wait_until - curtime;
						}
					}
				}
				if (myds->sess) {
					if (myds->sess->pause_until > 0) {
						if (mypolls.poll_timeout==0 || (myds->sess->pause_until - curtime < mypolls.poll_timeout) ) {
							mypolls.poll_timeout= myds->sess->pause_until - curtime;
						}
					}
				}
			}
			if (myds) myds->revents=0;
			if (mypolls.myds[n] && mypolls.myds[n]->myds_type!=MYDS_LISTENER) {
				if (myds && myds->myds_type==MYDS_FRONTEND && myds->DSS==STATE_SLEEP && myds->sess && myds->sess->status==WAITING_CLIENT_DATA) {
					mypolls.myds[n]->set_pollout();
				} else {
					if (mypolls.myds[n]->DSS > STATE_MARIADB_BEGIN && mypolls.myds[n]->DSS < STATE_MARIADB_END) {
						mypolls.fds[n].events = POLLIN;
						if (mypolls.myds[n]->myconn->async_exit_status & MYSQL_WAIT_WRITE)
							mypolls.fds[n].events |= POLLOUT;
					} else {
						mypolls.myds[n]->set_pollout();
					}
				}
			}
			proxy_debug(PROXY_DEBUG_NET,1,"Poll for DataStream=%p will be called with FD=%d and events=%d\n", mypolls.myds[n], mypolls.fds[n].fd, mypolls.fds[n].events);
		}

#ifdef IDLE_THREADS
		if (GloVars.global.idle_threads) {
			if (idle_maintenance_thread==false) {
				int r=rand()%(GloMTH->num_threads);
				MySQL_Thread *thr=GloMTH->mysql_threads_idles[r].worker;
				if (shutdown==0 && thr->shutdown==0 && idle_mysql_sessions->len) {
					unsigned int ims=0;
					pthread_mutex_lock(&thr->myexchange.mutex_idles);
					bool empty_queue=true;
					if (thr->myexchange.idle_mysql_sessions->len) {
						// there are already sessions in the queues. We assume someone already notified worker 0
						empty_queue=false;
					}
					for (ims=0; ims<idle_mysql_sessions->len; ims++) {
						MySQL_Session *mysess=(MySQL_Session *)idle_mysql_sessions->remove_index_fast(0);
						thr->myexchange.idle_mysql_sessions->add(mysess);
					}
					pthread_mutex_unlock(&thr->myexchange.mutex_idles);
					if (empty_queue==true) {
						unsigned char c=1;
						int fd=thr->pipefd[1];
						if (write(fd,&c,1)==-1) {
							//proxy_error("Error while signaling maintenance thread\n");
						}
					}
				}
				pthread_mutex_lock(&myexchange.mutex_resumes);
				if (myexchange.resume_mysql_sessions->len) {
					//unsigned int maxsess=GloMTH->resume_mysql_sessions->len;
					while (myexchange.resume_mysql_sessions->len) {
						MySQL_Session *mysess=(MySQL_Session *)myexchange.resume_mysql_sessions->remove_index_fast(0);
						register_session(mysess, false);
						MySQL_Data_Stream *myds=mysess->client_myds;
						mypolls.add(POLLIN, myds->fd, myds, monotonic_time());
					}
				}
				pthread_mutex_unlock(&myexchange.mutex_resumes);
			}
		}


__run_skip_1a:
#endif // IDLE_THREADS

		spin_wrunlock(&thread_mutex);

		while ((n=__sync_add_and_fetch(&mypolls.pending_listener_add,0))) {	// spin here
			poll_listener_add(n);
			assert(__sync_bool_compare_and_swap(&mypolls.pending_listener_add,n,0));
		}

		if (mysql_thread___wait_timeout==0) {
			// we should be going into PAUSE mode
			if (mypolls.poll_timeout==0 || mypolls.poll_timeout > 100000) {
				mypolls.poll_timeout=100000;
			}
		}


		// flush mysql log file
		GloMyLogger->flush();

		pre_poll_time=curtime;
#ifdef IDLE_THREADS
		if (GloVars.global.idle_threads && idle_maintenance_thread) {
			memset(events,0,sizeof(struct epoll_event)*MY_EPOLL_THREAD_MAXEVENTS); // let's make valgrind happy. It also seems that needs to be zeroed anyway
			// we call epoll()
			rc = epoll_wait (efd, events, MY_EPOLL_THREAD_MAXEVENTS, mysql_thread___poll_timeout);
		} else {
#endif // IDLE_THREADS
		//this is the only portion of code not protected by a global mutex
		proxy_debug(PROXY_DEBUG_NET,5,"Calling poll with timeout %d\n", ( mypolls.poll_timeout ? ( mypolls.poll_timeout/1000 > (unsigned int) mysql_thread___poll_timeout ? mypolls.poll_timeout/1000 : mysql_thread___poll_timeout ) : mysql_thread___poll_timeout )  );
		// poll is called with a timeout of mypolls.poll_timeout if set , or mysql_thread___poll_timeout
		rc=poll(mypolls.fds,mypolls.len, ( mypolls.poll_timeout ? ( mypolls.poll_timeout/1000 < (unsigned int) mysql_thread___poll_timeout ? mypolls.poll_timeout/1000 : mysql_thread___poll_timeout ) : mysql_thread___poll_timeout ) );
		proxy_debug(PROXY_DEBUG_NET,5,"%s\n", "Returning poll");
#ifdef IDLE_THREADS
		}
#endif // IDLE_THREADS

		while ((n=__sync_add_and_fetch(&mypolls.pending_listener_del,0))) {	// spin here
			poll_listener_del(n);
			assert(__sync_bool_compare_and_swap(&mypolls.pending_listener_del,n,0));
		}

		spin_wrlock(&thread_mutex);
		mypolls.poll_timeout=0; // always reset this to 0 . If a session needs a specific timeout, it will set this one

		curtime=monotonic_time();
		poll_timeout_bool=false;
		if (
#ifdef IDLE_THREADS
			idle_maintenance_thread==false &&
#endif // IDLE_THREADS
			(curtime >= pre_poll_time + mypolls.poll_timeout)) {
				poll_timeout_bool=true;
			}
		unsigned int maintenance_interval = 1000000; // hardcoded value for now
#ifdef IDLE_THREADS
		if (idle_maintenance_thread) {
			maintenance_interval=maintenance_interval*2;
		}
#endif // IDLE_THREADS
		if (curtime > last_maintenance_time + maintenance_interval) {
			last_maintenance_time=curtime;
			maintenance_loop=true;
		} else {
			maintenance_loop=false;
		}

		// update polls statistics
		mypolls.loops++;
		mypolls.loop_counters->incr(curtime/1000000);

		if (maintenance_loop) {
			GloQPro->update_query_processor_stats();
		}
			if (rc == -1 && errno == EINTR)
				// poll() timeout, try again
				continue;
			if (rc == -1) {
				// error , exit
				perror("poll()");
				exit(EXIT_FAILURE);
			}

		if (__sync_add_and_fetch(&__global_MySQL_Thread_Variables_version,0) > __thread_MySQL_Thread_Variables_version) {
			refresh_variables();
		}

#ifdef IDLE_THREADS
		if (idle_maintenance_thread==false) {
#endif // IDLE_THREADS
			for (n=0; n<mysql_sessions->len; n++) {
				MySQL_Session *_sess=(MySQL_Session *)mysql_sessions->index(n);
				_sess->to_process=0;
			}
#ifdef IDLE_THREADS
		}
#endif // IDLE_THREADS

#ifdef IDLE_THREADS
		// here we handle epoll_wait()
		if (GloVars.global.idle_threads && idle_maintenance_thread) {
			if (rc) {
				int i;
				for (i=0; i<rc; i++) {
					if (events[i].data.u32) {
						// NOTE: not sure why, sometime events returns odd values. If set, we take it out as normal worker threads know how to handle it
						if (events[i].events) {
							uint32_t sess_thr_id=events[i].data.u32;
							uint32_t sess_pos=sessmap[sess_thr_id];
							MySQL_Session *mysess=(MySQL_Session *)mysql_sessions->index(sess_pos);
							MySQL_Data_Stream *tmp_myds=mysess->client_myds;
							int dsidx=tmp_myds->poll_fds_idx;
							//fprintf(stderr,"Removing session %p, DS %p idx %d\n",mysess,tmp_myds,dsidx);
							mypolls.remove_index_fast(dsidx);
							tmp_myds->mypolls=NULL;
							mysess->thread=NULL;
							// we first delete the association in sessmap
							sessmap.erase(mysess->thread_session_id);
							if (mysql_sessions->len) {
								// take the last element and adjust the map
								MySQL_Session *mysess_last=(MySQL_Session *)mysql_sessions->index(mysql_sessions->len-1);
								sessmap[mysess_last->thread_session_id]=sess_pos;
							}
							unregister_session(sess_pos);
							resume_mysql_sessions->add(mysess);
							epoll_ctl(efd, EPOLL_CTL_DEL, tmp_myds->fd, NULL);
						}
					}
				}
				for (i=0; i<rc; i++) {
					if (events[i].events == EPOLLIN && events[i].data.u32==0) {
						unsigned char c;
						int fd=pipefd[0];
						if (read(fd, &c, 1)==-1) {
						}
						i=rc;
						maintenance_loop=true;
					}
				}
			}
			if (mysql_sessions->len && maintenance_loop) {
#define	SESS_TO_SCAN	128
				if (mysess_idx + SESS_TO_SCAN > mysql_sessions->len) {
					mysess_idx=0;
				}
				unsigned int i;
				unsigned long long min_idle = 0;
				if (curtime > (unsigned long long)mysql_thread___wait_timeout*1000) {
					min_idle = curtime - (unsigned long long)mysql_thread___wait_timeout*1000;
				}
				for (i=0;i<SESS_TO_SCAN && mysess_idx < mysql_sessions->len; i++) {
					uint32_t sess_pos=mysess_idx;
					MySQL_Session *mysess=(MySQL_Session *)mysql_sessions->index(sess_pos);
					if (mysess->idle_since < min_idle) {
						mysess->killed=true;
						MySQL_Data_Stream *tmp_myds=mysess->client_myds;
						int dsidx=tmp_myds->poll_fds_idx;
						//fprintf(stderr,"Removing session %p, DS %p idx %d\n",mysess,tmp_myds,dsidx);
						mypolls.remove_index_fast(dsidx);
						tmp_myds->mypolls=NULL;
						mysess->thread=NULL;
						// we first delete the association in sessmap
						sessmap.erase(mysess->thread_session_id);
						if (mysql_sessions->len) {
						// take the last element and adjust the map
						MySQL_Session *mysess_last=(MySQL_Session *)mysql_sessions->index(mysql_sessions->len-1);
							sessmap[mysess_last->thread_session_id]=sess_pos;
						}
						unregister_session(sess_pos);
						resume_mysql_sessions->add(mysess);
						epoll_ctl(efd, EPOLL_CTL_DEL, tmp_myds->fd, NULL);
					}
					mysess_idx++;
				}
			}
			goto __run_skip_2;
		}
#endif // IDLE_THREADS

		for (n = 0; n < mypolls.len; n++) {
			proxy_debug(PROXY_DEBUG_NET,3, "poll for fd %d events %d revents %d\n", mypolls.fds[n].fd , mypolls.fds[n].events, mypolls.fds[n].revents);

			MySQL_Data_Stream *myds=mypolls.myds[n];
			if (myds==NULL) {
				if (mypolls.fds[n].revents) {
					unsigned char c;
					if (read(mypolls.fds[n].fd, &c, 1)==-1) {// read just one byte
						proxy_error("Error during read from signal_all_threads()\n");
					}
					proxy_debug(PROXY_DEBUG_GENERIC,3, "Got signal from admin , done nothing\n");
					//fprintf(stderr,"Got signal from admin , done nothing\n"); // FIXME: this is just the scheleton for issue #253
					if (c) {
						// we are being signaled to sleep for some ms. Before going to sleep we also release the mutex
						spin_wrunlock(&thread_mutex);
						usleep(c*1000);
						spin_wrlock(&thread_mutex);
						// we enter in maintenance loop only if c is set
						// when threads are signaling each other, there is no need to set maintenance_loop
						maintenance_loop=true;
					}
				}
			continue;
			}
			if (mypolls.fds[n].revents==0) {
			// FIXME: this logic was removed completely because we added mariadb client library. Yet, we need to implement a way to manage connection timeout
			// check for timeout
				// no events. This section is copied from process_data_on_data_stream()
				if (poll_timeout_bool) {
				MySQL_Data_Stream *_myds=mypolls.myds[n];
				if (_myds && _myds->sess) {
					if (_myds->wait_until && curtime > _myds->wait_until) {
						// timeout
						_myds->sess->to_process=1;
					} else {
						if (_myds->sess->pause_until && curtime > _myds->sess->pause_until) {
							// timeout
							_myds->sess->to_process=1;
						}
					}
				}
				}
			} else {
				// check if the FD is valid
				if (mypolls.fds[n].revents==POLLNVAL) {
					// debugging output before assert
					MySQL_Data_Stream *_myds=mypolls.myds[n];
					if (_myds) {
						if (_myds->myconn) {
							proxy_error("revents==POLLNVAL for FD=%d, events=%d, MyDSFD=%d, MyConnFD=%d\n", mypolls.fds[n].fd, mypolls.fds[n].events, myds->fd, myds->myconn->fd);
							assert(mypolls.fds[n].revents!=POLLNVAL);
						}
					}
					// if we reached her, we didn't assert() yet
					proxy_error("revents==POLLNVAL for FD=%d, events=%d, MyDSFD=%d\n", mypolls.fds[n].fd, mypolls.fds[n].events, myds->fd);
					assert(mypolls.fds[n].revents!=POLLNVAL);
				}
				switch(myds->myds_type) {
		// Note: this logic that was here was removed completely because we added mariadb client library.
					case MYDS_LISTENER:
						// we got a new connection!
						listener_handle_new_connection(myds,n);
						continue;
						break;
					default:
						break;
				}
				// data on exiting connection
				bool rc=process_data_on_data_stream(myds, n);
				if (rc==false) {
					n--;
				}
		}
		}

#ifdef IDLE_THREADS
__run_skip_2:
		if (GloVars.global.idle_threads && idle_maintenance_thread) {
			unsigned int w=rand()%(GloMTH->num_threads);
			MySQL_Thread *thr=GloMTH->mysql_threads[w].worker;
			if (resume_mysql_sessions->len) {
				pthread_mutex_lock(&thr->myexchange.mutex_resumes);
				unsigned int ims;
				if (shutdown==0 && thr->shutdown==0)
				for (ims=0; ims<resume_mysql_sessions->len; ims++) {
					MySQL_Session *mysess=(MySQL_Session *)resume_mysql_sessions->remove_index_fast(0);
					thr->myexchange.resume_mysql_sessions->add(mysess);
				}
				pthread_mutex_unlock(&thr->myexchange.mutex_resumes);
				{
					unsigned char c=0;
					//MySQL_Thread *thr=GloMTH->mysql_threads[w].worker;
					int fd=thr->pipefd[1];
					if (write(fd,&c,1)==-1) {
						//proxy_error("Error while signaling maintenance thread\n");
					}
				}
			} else {
				VALGRIND_DISABLE_ERROR_REPORTING;
				pthread_mutex_lock(&thr->myexchange.mutex_resumes);
				VALGRIND_ENABLE_ERROR_REPORTING;
				if (shutdown==0 && thr->shutdown==0 && thr->myexchange.resume_mysql_sessions->len) {
					unsigned char c=0;
					int fd=thr->pipefd[1];
					if (write(fd,&c,1)==-1) {
						//proxy_error("Error while signaling maintenance thread\n");
					}
				}
				VALGRIND_DISABLE_ERROR_REPORTING;
				pthread_mutex_unlock(&thr->myexchange.mutex_resumes);
				VALGRIND_ENABLE_ERROR_REPORTING;
			}
		} else {
#endif // IDLE_THREADS
			// iterate through all sessions and process the session logic
			process_all_sessions();

			return_local_connections();
#ifdef IDLE_THREADS
		}
#endif // IDLE_THREADS
	}
}

bool MySQL_Thread::process_data_on_data_stream(MySQL_Data_Stream *myds, unsigned int n) {
				if (mypolls.fds[n].revents) {
#ifdef IDLE_THREADS
					if (myds->myds_type==MYDS_FRONTEND) {
						if (epoll_thread) {
							mypolls.remove_index_fast(n);
							myds->mypolls=NULL;
							unsigned int i;
							for (i=0;i<mysql_sessions->len;i++) {
								MySQL_Session *mysess=(MySQL_Session *)mysql_sessions->index(i);
								if (mysess==myds->sess) {
									mysess->thread=NULL;
									unregister_session(i);
									//exit_cond=true;
									resume_mysql_sessions->add(myds->sess);
									return false;
								}
							}
						}
					}
#endif // IDLE_THREADS
					mypolls.last_recv[n]=curtime;
					myds->revents=mypolls.fds[n].revents;
					myds->sess->to_process=1;
					assert(myds->sess->status!=NONE);
				} else {
					// no events
					if (myds->wait_until && curtime > myds->wait_until) {
						// timeout
						myds->sess->to_process=1;
						assert(myds->sess->status!=NONE);
					} else {
						if (myds->sess->pause_until && curtime > myds->sess->pause_until) {
							// timeout
							myds->sess->to_process=1;
						}
					}
				}
				if (myds->myds_type==MYDS_BACKEND && myds->sess->status!=FAST_FORWARD) {
					return true;
				}
				if (mypolls.fds[n].revents) {
					if (mypolls.myds[n]->DSS < STATE_MARIADB_BEGIN || mypolls.myds[n]->DSS > STATE_MARIADB_END) {
						// only if we aren't using MariaDB Client Library
						myds->read_from_net();
						myds->read_pkts();
					} else {
						if (mypolls.fds[n].revents) {
							myds->myconn->handler(mypolls.fds[n].revents);
						}
					}
					if ( (mypolls.fds[n].events & POLLOUT)
							&&
							( (mypolls.fds[n].revents & POLLERR) || (mypolls.fds[n].revents & POLLHUP) )
					) {
						myds->set_net_failure();
					}
					myds->check_data_flow();
				}


	      if (myds->active==0) {
					if (myds->sess->client_myds==myds) {
						proxy_debug(PROXY_DEBUG_NET,1, "Session=%p, DataStream=%p -- Deleting FD %d\n", myds->sess, myds, myds->fd);
						myds->sess->set_unhealthy();
					} else {
						// if this is a backend with fast_forward, set unhealthy
						// if this is a backend without fast_forward, do not set unhealthy: it will be handled by client library
						if (myds->sess->session_fast_forward) { // if fast forward
							if (myds->myds_type==MYDS_BACKEND) { // and backend
								myds->sess->set_unhealthy(); // set unhealthy
							}
						}
					}
				}
	return true;
}


void MySQL_Thread::process_all_sessions() {
	unsigned int n;
	unsigned int total_active_transactions_=0;
#ifdef IDLE_THREADS
	bool idle_maintenance_thread=epoll_thread;
#endif // IDLE_THREADS
	int rc;
	bool sess_sort=mysql_thread___sessions_sort;
#ifdef IDLE_THREADS
	if (idle_maintenance_thread) {
		sess_sort=false;
	}
#endif // IDLE_THREADS
	if (sess_sort && mysql_sessions->len > 3) {
		unsigned int a=0;
		for (n=0; n<mysql_sessions->len; n++) {
			MySQL_Session *sess=(MySQL_Session *)mysql_sessions->index(n);
			if (sess->mybe && sess->mybe->server_myds) {
				if (sess->mybe->server_myds->max_connect_time) {
					MySQL_Session *sess2=(MySQL_Session *)mysql_sessions->index(a);
					if (sess2->mybe && sess2->mybe->server_myds && sess2->mybe->server_myds->max_connect_time && sess2->mybe->server_myds->max_connect_time <= sess->mybe->server_myds->max_connect_time) {
						// do nothing
					} else {
						void *p=mysql_sessions->pdata[a];
						mysql_sessions->pdata[a]=mysql_sessions->pdata[n];
						mysql_sessions->pdata[n]=p;
						a++;
					}
				}
			}
		}
	}
	for (n=0; n<mysql_sessions->len; n++) {
		MySQL_Session *sess=(MySQL_Session *)mysql_sessions->index(n);
#ifdef DEBUG
		if(sess==sess_stopat) {
			sess_stopat=sess;
		}
#endif
		if (sess->mirror==true) { // this is a mirror session
			if (sess->status==WAITING_CLIENT_DATA) { // the mirror session has completed
				unregister_session(n);
				n--;
				delete sess;
				continue;
			}
		}
		if (maintenance_loop) {
			unsigned int numTrx=0;
			unsigned long long sess_time = sess->IdleTime();
#ifdef IDLE_THREADS
			if (idle_maintenance_thread==false)
#endif // IDLE_THREADS
			{
				sess->to_process=1;
				if ( (sess_time/1000 > (unsigned long long)mysql_thread___max_transaction_time) || (sess_time/1000 > (unsigned long long)mysql_thread___wait_timeout) ) {
					numTrx = sess->NumActiveTransactions();
					if (numTrx) {
						// the session has idle transactions, kill it
						if (sess_time/1000 > (unsigned long long)mysql_thread___max_transaction_time) sess->killed=true;
					} else {
						// the session is idle, kill it
						if (sess_time/1000 > (unsigned long long)mysql_thread___wait_timeout) sess->killed=true;
					}
				}
			}
#ifdef IDLE_THREADS
				else
			{
				if ( (sess_time/1000 > (unsigned long long)mysql_thread___wait_timeout) ) {
					sess->killed=true;
					sess->to_process=1;
				}
			}
#endif // IDLE_THREADS
		}
		if (sess->healthy==0) {
			unregister_session(n);
			n--;
			delete sess;
		} else {
			if (sess->to_process==1) {
				if (sess->pause_until <= curtime) {
					rc=sess->handler();
					total_active_transactions_+=sess->active_transactions;
					if (rc==-1 || sess->killed==true) {
						unregister_session(n);
						n--;
						delete sess;
					}
				}
			} else {
				if (sess->killed==true) {
					// this is a special cause, if killed the session needs to be executed no matter if paused
					sess->handler();
					unregister_session(n);
					n--;
					delete sess;
				}
			}
		}
	}
	unsigned int total_active_transactions_tmp;
	total_active_transactions_tmp=__sync_add_and_fetch(&status_variables.active_transactions,0);
	__sync_bool_compare_and_swap(&status_variables.active_transactions,total_active_transactions_tmp,total_active_transactions_);
}

void MySQL_Thread::refresh_variables() {
	if (GloMTH==NULL) {
		return;
	}
	GloMTH->wrlock();
	__thread_MySQL_Thread_Variables_version=__global_MySQL_Thread_Variables_version;
	mysql_thread___max_allowed_packet=GloMTH->get_variable_int((char *)"max_allowed_packet");
	mysql_thread___max_transaction_time=GloMTH->get_variable_int((char *)"max_transaction_time");
	mysql_thread___threshold_query_length=GloMTH->get_variable_int((char *)"threshold_query_length");
	mysql_thread___threshold_resultset_size=GloMTH->get_variable_int((char *)"threshold_resultset_size");
	mysql_thread___query_digests_max_digest_length=GloMTH->get_variable_int((char *)"query_digests_max_digest_length");
	mysql_thread___query_digests_max_query_length=GloMTH->get_variable_int((char *)"query_digests_max_query_length");
	mysql_thread___wait_timeout=GloMTH->get_variable_int((char *)"wait_timeout");
	mysql_thread___max_connections=GloMTH->get_variable_int((char *)"max_connections");
	mysql_thread___max_stmts_per_connection=GloMTH->get_variable_int((char *)"max_stmts_per_connection");
	mysql_thread___max_stmts_cache=GloMTH->get_variable_int((char *)"max_stmts_cache");
	mysql_thread___default_query_delay=GloMTH->get_variable_int((char *)"default_query_delay");
	mysql_thread___default_query_timeout=GloMTH->get_variable_int((char *)"default_query_timeout");
	mysql_thread___query_processor_iterations=GloMTH->get_variable_int((char *)"query_processor_iterations");
	mysql_thread___query_processor_regex=GloMTH->get_variable_int((char *)"query_processor_regex");
	mysql_thread___default_max_latency_ms=GloMTH->get_variable_int((char *)"default_max_latency_ms");
	mysql_thread___long_query_time=GloMTH->get_variable_int((char *)"long_query_time");
	mysql_thread___query_cache_size_MB=GloMTH->get_variable_int((char *)"query_cache_size_MB");
	mysql_thread___ping_interval_server_msec=GloMTH->get_variable_int((char *)"ping_interval_server_msec");
	mysql_thread___ping_timeout_server=GloMTH->get_variable_int((char *)"ping_timeout_server");
	mysql_thread___shun_on_failures=GloMTH->get_variable_int((char *)"shun_on_failures");
	mysql_thread___shun_recovery_time_sec=GloMTH->get_variable_int((char *)"shun_recovery_time_sec");
	mysql_thread___query_retries_on_failure=GloMTH->get_variable_int((char *)"query_retries_on_failure");
	mysql_thread___connect_retries_on_failure=GloMTH->get_variable_int((char *)"connect_retries_on_failure");
	mysql_thread___connection_max_age_ms=GloMTH->get_variable_int((char *)"connection_max_age_ms");
	mysql_thread___connect_timeout_server=GloMTH->get_variable_int((char *)"connect_timeout_server");
	mysql_thread___connect_timeout_server_max=GloMTH->get_variable_int((char *)"connect_timeout_server_max");
	mysql_thread___free_connections_pct=GloMTH->get_variable_int((char *)"free_connections_pct");
#ifdef IDLE_THREADS
	mysql_thread___session_idle_ms=GloMTH->get_variable_int((char *)"session_idle_ms");
#endif // IDLE_THREADS
	mysql_thread___connect_retries_delay=GloMTH->get_variable_int((char *)"connect_retries_delay");

	if (mysql_thread___monitor_username) free(mysql_thread___monitor_username);
	mysql_thread___monitor_username=GloMTH->get_variable_string((char *)"monitor_username");
	if (mysql_thread___monitor_password) free(mysql_thread___monitor_password);
	mysql_thread___monitor_password=GloMTH->get_variable_string((char *)"monitor_password");

	// SSL proxy to server
	if (mysql_thread___ssl_p2s_ca) free(mysql_thread___ssl_p2s_ca);
	mysql_thread___ssl_p2s_ca=GloMTH->get_variable_string((char *)"ssl_p2s_ca");
	if (mysql_thread___ssl_p2s_cert) free(mysql_thread___ssl_p2s_cert);
	mysql_thread___ssl_p2s_cert=GloMTH->get_variable_string((char *)"ssl_p2s_cert");
	if (mysql_thread___ssl_p2s_key) free(mysql_thread___ssl_p2s_key);
	mysql_thread___ssl_p2s_key=GloMTH->get_variable_string((char *)"ssl_p2s_key");
	if (mysql_thread___ssl_p2s_cipher) free(mysql_thread___ssl_p2s_cipher);
	mysql_thread___ssl_p2s_cipher=GloMTH->get_variable_string((char *)"ssl_p2s_cipher");

	mysql_thread___monitor_writer_is_also_reader=(bool)GloMTH->get_variable_int((char *)"monitor_writer_is_also_reader");
	mysql_thread___monitor_enabled=(bool)GloMTH->get_variable_int((char *)"monitor_enabled");
	mysql_thread___monitor_history=GloMTH->get_variable_int((char *)"monitor_history");
	mysql_thread___monitor_connect_interval=GloMTH->get_variable_int((char *)"monitor_connect_interval");
	mysql_thread___monitor_connect_timeout=GloMTH->get_variable_int((char *)"monitor_connect_timeout");
	mysql_thread___monitor_ping_interval=GloMTH->get_variable_int((char *)"monitor_ping_interval");
	mysql_thread___monitor_ping_max_failures=GloMTH->get_variable_int((char *)"monitor_ping_max_failures");
	mysql_thread___monitor_ping_timeout=GloMTH->get_variable_int((char *)"monitor_ping_timeout");
	mysql_thread___monitor_read_only_interval=GloMTH->get_variable_int((char *)"monitor_read_only_interval");
	mysql_thread___monitor_read_only_timeout=GloMTH->get_variable_int((char *)"monitor_read_only_timeout");
	mysql_thread___monitor_replication_lag_interval=GloMTH->get_variable_int((char *)"monitor_replication_lag_interval");
	mysql_thread___monitor_replication_lag_timeout=GloMTH->get_variable_int((char *)"monitor_replication_lag_timeout");
	mysql_thread___monitor_query_interval=GloMTH->get_variable_int((char *)"monitor_query_interval");
	mysql_thread___monitor_query_timeout=GloMTH->get_variable_int((char *)"monitor_query_timeout");
	mysql_thread___monitor_slave_lag_when_null=GloMTH->get_variable_int((char *)"monitor_slave_lag_when_null");

	if (mysql_thread___init_connect) free(mysql_thread___init_connect);
	mysql_thread___init_connect=GloMTH->get_variable_string((char *)"init_connect");
	if (mysql_thread___default_sql_mode) free(mysql_thread___default_sql_mode);
	mysql_thread___default_sql_mode=GloMTH->get_variable_string((char *)"default_sql_mode");
	if (mysql_thread___default_time_zone) free(mysql_thread___default_time_zone);
	mysql_thread___default_time_zone=GloMTH->get_variable_string((char *)"default_time_zone");
	if (mysql_thread___server_version) free(mysql_thread___server_version);
	mysql_thread___server_version=GloMTH->get_variable_string((char *)"server_version");
	if (mysql_thread___eventslog_filename) free(mysql_thread___eventslog_filename);
	mysql_thread___eventslog_filesize=GloMTH->get_variable_int((char *)"eventslog_filesize");
	mysql_thread___eventslog_filename=GloMTH->get_variable_string((char *)"eventslog_filename");
	GloMyLogger->set_base_filename(); // both filename and filesize are set here
	if (mysql_thread___default_schema) free(mysql_thread___default_schema);
	mysql_thread___default_schema=GloMTH->get_variable_string((char *)"default_schema");
	mysql_thread___server_capabilities=GloMTH->get_variable_uint16((char *)"server_capabilities");
	mysql_thread___default_charset=GloMTH->get_variable_uint8((char *)"default_charset");
	mysql_thread___poll_timeout=GloMTH->get_variable_int((char *)"poll_timeout");
	mysql_thread___poll_timeout_on_failure=GloMTH->get_variable_int((char *)"poll_timeout_on_failure");
	mysql_thread___have_compress=(bool)GloMTH->get_variable_int((char *)"have_compress");
	mysql_thread___client_found_rows=(bool)GloMTH->get_variable_int((char *)"client_found_rows");
	mysql_thread___multiplexing=(bool)GloMTH->get_variable_int((char *)"multiplexing");
	mysql_thread___forward_autocommit=(bool)GloMTH->get_variable_int((char *)"forward_autocommit");
	mysql_thread___enforce_autocommit_on_reads=(bool)GloMTH->get_variable_int((char *)"enforce_autocommit_on_reads");
	mysql_thread___commands_stats=(bool)GloMTH->get_variable_int((char *)"commands_stats");
	mysql_thread___query_digests=(bool)GloMTH->get_variable_int((char *)"query_digests");
	mysql_thread___query_digests_lowercase=(bool)GloMTH->get_variable_int((char *)"query_digests_lowercase");
	mysql_thread___sessions_sort=(bool)GloMTH->get_variable_int((char *)"sessions_sort");
#ifdef IDLE_THREADS
	mysql_thread___session_idle_show_processlist=(bool)GloMTH->get_variable_int((char *)"session_idle_show_processlist");
#endif // IDLE_THREADS
	mysql_thread___servers_stats=(bool)GloMTH->get_variable_int((char *)"servers_stats");
	mysql_thread___default_reconnect=(bool)GloMTH->get_variable_int((char *)"default_reconnect");
#ifdef DEBUG
	mysql_thread___session_debug=(bool)GloMTH->get_variable_int((char *)"session_debug");
#endif /* DEBUG */
	GloMTH->wrunlock();
}

MySQL_Thread::MySQL_Thread() {
	spinlock_rwlock_init(&thread_mutex);
	my_idle_conns=NULL;
	cached_connections=NULL;
	mysql_sessions=NULL;
#ifdef IDLE_THREADS
	efd=-1;
	epoll_thread=false;
	mysess_idx=0;
	idle_mysql_sessions=NULL;
	resume_mysql_sessions=NULL;
	myexchange.idle_mysql_sessions=NULL;
	myexchange.resume_mysql_sessions=NULL;
#endif // IDLE_THREADS
	processing_idles=false;
	last_processing_idles=0;
	__thread_MySQL_Thread_Variables_version=0;
	mysql_thread___server_version=NULL;
	mysql_thread___init_connect=NULL;
	mysql_thread___eventslog_filename=NULL;

	// SSL proxy to server
	mysql_thread___ssl_p2s_ca=NULL;
	mysql_thread___ssl_p2s_cert=NULL;
	mysql_thread___ssl_p2s_key=NULL;
	mysql_thread___ssl_p2s_cipher=NULL;

	last_maintenance_time=0;
	maintenance_loop=true;

	status_variables.stmt_prepare=0;
	status_variables.stmt_execute=0;
	status_variables.stmt_close=0;
	status_variables.queries=0;
	status_variables.queries_slow=0;
	status_variables.queries_backends_bytes_sent=0;
	status_variables.queries_backends_bytes_recv=0;
	status_variables.query_processor_time=0;
	status_variables.backend_query_time=0;
	status_variables.mysql_backend_buffers_bytes=0;
	status_variables.mysql_frontend_buffers_bytes=0;
	status_variables.mysql_session_internal_bytes=0;
	status_variables.ConnPool_get_conn_immediate=0;
	status_variables.ConnPool_get_conn_success=0;
	status_variables.ConnPool_get_conn_failure=0;
	status_variables.active_transactions=0;
}

void MySQL_Thread::register_session_connection_handler(MySQL_Session *_sess, bool _new) {
	_sess->thread=this;
	_sess->connections_handler=true;
	assert(_new);
	mysql_sessions->add(_sess);
}

void MySQL_Thread::unregister_session_connection_handler(int idx, bool _new) {
	assert(_new);
	mysql_sessions->remove_index_fast(idx);
}


void MySQL_Thread::listener_handle_new_connection(MySQL_Data_Stream *myds, unsigned int n) {
	int c;
	union {
        	struct sockaddr_in in;
                struct sockaddr_in6 in6;
        } custom_sockaddr;
	struct sockaddr *addr=(struct sockaddr *)malloc(sizeof(custom_sockaddr));
	socklen_t addrlen=sizeof(custom_sockaddr);
	memset(addr, 0, sizeof(custom_sockaddr));
	if (GloMTH->num_threads > 1) {
		// there are more than 1 thread . We pause for a little bit to avoid all connections to be handled by the same thread
#ifdef SO_REUSEPORT
		if (GloVars.global.reuseport==false) { // only if reuseport is not enabled
			usleep(10+rand()%50);
		}
#else
		usleep(10+rand()%50);
#endif /* SO_REUSEPORT */
	}
	c=accept(myds->fd, addr, &addrlen);
	if (c>-1) { // accept() succeeded
		// create a new client connection
		mypolls.fds[n].revents=0;
		MySQL_Session *sess=create_new_session_and_client_data_stream(c);
		__sync_add_and_fetch(&MyHGM->status.client_connections_created,1);
		if (__sync_add_and_fetch(&MyHGM->status.client_connections,1) > mysql_thread___max_connections) {
			sess->max_connections_reached=true;
		}
		sess->client_myds->client_addrlen=addrlen;
		sess->client_myds->client_addr=addr;

                switch (sess->client_myds->client_addr->sa_family) {
                        case AF_INET: {
                                struct sockaddr_in *ipv4 = (struct sockaddr_in *)sess->client_myds->client_addr;
                                char buf[INET_ADDRSTRLEN];
	                        inet_ntop(sess->client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
		                sess->client_myds->addr.addr = strdup(buf);
			        sess->client_myds->addr.port = htons(ipv4->sin_port);
                                break;
                                }
                        case AF_INET6: {
                                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)sess->client_myds->client_addr;
                                char buf[INET6_ADDRSTRLEN];
	                        inet_ntop(sess->client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
		                sess->client_myds->addr.addr = strdup(buf);
			        sess->client_myds->addr.port = htons(ipv6->sin6_port);
                                break;
                        }
                        default:
                                sess->client_myds->addr.addr = strdup("localhost");
                                break;
                }

		iface_info *ifi=NULL;
		ifi=GloMTH->MLM_find_iface_from_fd(myds->fd); // here we try to get the info about the proxy bind address
		if (ifi) {
			sess->client_myds->proxy_addr.addr=strdup(ifi->address);
			sess->client_myds->proxy_addr.port=ifi->port;
		}
		sess->client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL, &sess->thread_session_id);
		ioctl_FIONBIO(sess->client_myds->fd, 1);
		mypolls.add(POLLIN|POLLOUT, sess->client_myds->fd, sess->client_myds, curtime);
		proxy_debug(PROXY_DEBUG_NET,1,"Session=%p -- Adding client FD %d\n", sess, sess->client_myds->fd);
	} else {
		free(addr);
		// if we arrive here, accept() failed
		// because multiple threads try to handle the same incoming connection, this is OK
	}
}

SQLite3_result * MySQL_Threads_Handler::SQL3_GlobalStatus() {
	const int colnum=2;
	char buf[256];
	char **pta=(char **)malloc(sizeof(char *)*colnum);
	Get_Memory_Stats();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping MySQL Global Status\n");
  SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"Variable_Name");
	result->add_column_definition(SQLITE_TEXT,"Variable_Value");
	// NOTE: as there is no string copy, we do NOT free pta[0] and pta[1]
	{ // uptime
		unsigned long long t1=monotonic_time();
		pta[0] = (char *)"ProxySQL_Uptime";
		sprintf(buf,"%llu",(t1-GloVars.global.start_time)/1000/1000);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Active Transactions
		pta[0]=(char *)"Active_Transactions";
		sprintf(buf,"%u",get_active_transations());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Connections created
		pta[0]=(char *)"Client_Connections_aborted";
		sprintf(buf,"%lu",MyHGM->status.client_connections_aborted);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Connections
		pta[0]=(char *)"Client_Connections_connected";
		sprintf(buf,"%d",MyHGM->status.client_connections);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Connections created
		pta[0]=(char *)"Client_Connections_created";
		sprintf(buf,"%lu",MyHGM->status.client_connections_created);
		pta[1]=buf;
		result->add_row(pta);
	}
	{
		// Connections
		pta[0]=(char *)"Server_Connections_aborted";
		sprintf(buf,"%lu",MyHGM->status.server_connections_aborted);
		pta[1]=buf;
		result->add_row(pta);
	}
	{
		// Connections
		pta[0]=(char *)"Server_Connections_connected";
		sprintf(buf,"%lu",MyHGM->status.server_connections_connected);
		pta[1]=buf;
		result->add_row(pta);
	}
	{
		// Connections
		pta[0]=(char *)"Server_Connections_created";
		sprintf(buf,"%lu",MyHGM->status.server_connections_created);
		pta[1]=buf;
		result->add_row(pta);
	}
#ifdef IDLE_THREADS
	{	// Connections non idle
		pta[0]=(char *)"Client_Connections_non_idle";
		sprintf(buf,"%u",get_non_idle_client_connections());
		pta[1]=buf;
		result->add_row(pta);
	}
#endif // IDLE_THREADS
	{	// Queries bytes recv
		pta[0]=(char *)"Queries_backends_bytes_recv";
		sprintf(buf,"%llu",get_queries_backends_bytes_recv());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries bytes recv
		pta[0]=(char *)"Queries_backends_bytes_sent";
		sprintf(buf,"%llu",get_queries_backends_bytes_sent());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Query Processor Time
		pta[0]=(char *)"Query_Processor_time_nsec";
		sprintf(buf,"%llu",get_query_processor_time());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Backend query time
		pta[0]=(char *)"Backend_query_time_nsec";
		sprintf(buf,"%llu",get_backend_query_time());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// MySQL Backend buffers bytes
		pta[0]=(char *)"mysql_backend_buffers_bytes";
		sprintf(buf,"%llu",get_mysql_backend_buffers_bytes());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// MySQL Frontend buffers bytes
		pta[0]=(char *)"mysql_frontend_buffers_bytes";
		sprintf(buf,"%llu",get_mysql_frontend_buffers_bytes());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// MySQL Frontend buffers bytes
		pta[0]=(char *)"mysql_session_internal_bytes";
		sprintf(buf,"%llu",get_mysql_session_internal_bytes());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries autocommit
		pta[0]=(char *)"Com_autocommit";
		sprintf(buf,"%llu",MyHGM->status.autocommit_cnt);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries filtered autocommit
		pta[0]=(char *)"Com_autocommit_filtered";
		sprintf(buf,"%llu",MyHGM->status.autocommit_cnt_filtered);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries commit
		pta[0]=(char *)"Com_commit";
		sprintf(buf,"%llu",MyHGM->status.commit_cnt);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries filtered commit
		pta[0]=(char *)"Com_commit_filtered";
		sprintf(buf,"%llu",MyHGM->status.commit_cnt_filtered);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries rollback
		pta[0]=(char *)"Com_rollback";
		sprintf(buf,"%llu",MyHGM->status.rollback_cnt);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries filtered rollback
		pta[0]=(char *)"Com_rollback_filtered";
		sprintf(buf,"%llu",MyHGM->status.rollback_cnt_filtered);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries backend CHANGE_USER
		pta[0]=(char *)"Com_backend_change_user";
		sprintf(buf,"%llu",MyHGM->status.backend_change_user);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries backend INIT DB
		pta[0]=(char *)"Com_backend_init_db";
		sprintf(buf,"%llu",MyHGM->status.backend_init_db);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries backend SET NAMES
		pta[0]=(char *)"Com_backend_set_names";
		sprintf(buf,"%llu",MyHGM->status.backend_set_names);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries frontend INIT DB
		pta[0]=(char *)"Com_frontend_init_db";
		sprintf(buf,"%llu",MyHGM->status.frontend_init_db);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries frontend SET NAMES
		pta[0]=(char *)"Com_frontend_set_names";
		sprintf(buf,"%llu",MyHGM->status.frontend_set_names);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries frontend USE DB
		pta[0]=(char *)"Com_frontend_use_db";
		sprintf(buf,"%llu",MyHGM->status.frontend_use_db);
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// stmt prepare
		pta[0]=(char *)"Com_stmt_prepare";
		sprintf(buf,"%llu",get_total_stmt_prepare());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// stmt execute
		pta[0]=(char *)"Com_stmt_execute";
		sprintf(buf,"%llu",get_total_stmt_execute());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// stmt prepare
		pta[0]=(char *)"Com_stmt_close";
		sprintf(buf,"%llu",get_total_stmt_close());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Queries
		pta[0]=(char *)"Questions";
		sprintf(buf,"%llu",get_total_queries());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Slow queries
		pta[0]=(char *)"Slow_queries";
		sprintf(buf,"%llu",get_slow_queries());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// Servers_table_version
		pta[0]=(char *)"Servers_table_version";
		sprintf(buf,"%u",MyHGM->get_servers_table_version());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// MySQL Threads workers
		pta[0]=(char *)"MySQL_Thread_Workers";
		sprintf(buf,"%d",num_threads);
		pta[1]=buf;
		result->add_row(pta);
	}
	if (GloMyMon) {
		{	// MySQL Monitor workers
			pta[0]=(char *)"MySQL_Monitor_Workers";
			sprintf(buf,"%d",( variables.monitor_enabled ? GloMyMon->num_threads : 0));
			pta[1]=buf;
			result->add_row(pta);
		}
	}
	{	// ConnPool_get_conn_immediate
		pta[0]=(char *)"ConnPool_get_conn_immediate";
		sprintf(buf,"%llu",get_ConnPool_get_conn_immediate());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// ConnPool_get_conn_success
		pta[0]=(char *)"ConnPool_get_conn_success";
		sprintf(buf,"%llu",get_ConnPool_get_conn_success());
		pta[1]=buf;
		result->add_row(pta);
	}
	{	// ConnPool_get_conn_failure
		pta[0]=(char *)"ConnPool_get_conn_failure";
		sprintf(buf,"%llu",get_ConnPool_get_conn_failure());
		pta[1]=buf;
		result->add_row(pta);
	}
	free(pta);
	return result;
}


void MySQL_Threads_Handler::Get_Memory_Stats() {
	unsigned int i;
	unsigned int j;
	signal_all_threads(1);
	MySQL_Thread *thr=NULL;
	j=num_threads;
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		j+=num_threads;
	}
#endif /* IDLE_THREADS */
	for (i=0;i<j;i++) {
		if (i<num_threads) {
			thr=(MySQL_Thread *)mysql_threads[i].worker;
#ifdef IDLE_THREADS
		} else {
			if (GloVars.global.idle_threads) {
				thr=(MySQL_Thread *)mysql_threads_idles[i-num_threads].worker;
			}
#endif /* IDLE_THREADS */
		}
		spin_wrlock(&thr->thread_mutex);
	}
	for (i=0;i<j;i++) {
		if (i<num_threads) {
			thr=(MySQL_Thread *)mysql_threads[i].worker;
#ifdef IDLE_THREADS
		} else {
			if (GloVars.global.idle_threads) {
				thr=(MySQL_Thread *)mysql_threads_idles[i-num_threads].worker;
			}
#endif /* IDLE_THREADS */
		}
		thr->Get_Memory_Stats();
	}
	for (i=0;i<j;i++) {
		if (i<num_threads) {
			thr=(MySQL_Thread *)mysql_threads[i].worker;
#ifdef IDLE_THREADS
		} else {
			if (GloVars.global.idle_threads) {
				thr=(MySQL_Thread *)mysql_threads_idles[i-num_threads].worker;
			}
#endif /* IDLE_THREADS */
		}
		spin_wrunlock(&thr->thread_mutex);
	}
}

SQLite3_result * MySQL_Threads_Handler::SQL3_Processlist() {
	const int colnum=14;
        char port[NI_MAXSERV];
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping MySQL Processlist\n");
  SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"ThreadID");
	result->add_column_definition(SQLITE_TEXT,"SessionID");
	result->add_column_definition(SQLITE_TEXT,"user");
	result->add_column_definition(SQLITE_TEXT,"db");
	result->add_column_definition(SQLITE_TEXT,"cli_host");
	result->add_column_definition(SQLITE_TEXT,"cli_port");
	result->add_column_definition(SQLITE_TEXT,"hostgroup");
	result->add_column_definition(SQLITE_TEXT,"l_srv_host");
	result->add_column_definition(SQLITE_TEXT,"l_srv_port");
	result->add_column_definition(SQLITE_TEXT,"srv_host");
	result->add_column_definition(SQLITE_TEXT,"srv_port");
	result->add_column_definition(SQLITE_TEXT,"command");
	result->add_column_definition(SQLITE_TEXT,"time_ms");
	result->add_column_definition(SQLITE_TEXT,"info");
	unsigned int i;
	unsigned int i2;
	signal_all_threads(1);
	MySQL_Thread *thr=NULL;
	i2=num_threads;
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		i2+=num_threads;
	}
#endif // IDLE_THREADS

	for (i=0;i<i2;i++) {
		if (i<num_threads) {
			thr=(MySQL_Thread *)mysql_threads[i].worker;
			spin_wrlock(&thr->thread_mutex);
#ifdef IDLE_THREADS
		} else {
			if (mysql_thread___session_idle_show_processlist) {
				thr=(MySQL_Thread *)mysql_threads_idles[i-num_threads].worker;
				spin_wrlock(&thr->thread_mutex);
			}
#endif // IDLE_THREADS
		}
	}
#ifdef IDLE_THREADS
	for (i=0;i < ( (mysql_thread___session_idle_show_processlist && GloVars.global.idle_threads ) ? num_threads*2 : num_threads); i++) {
#else
	for (i=0;i < num_threads; i++) {
#endif // IDLE_THREADS
		if (i<num_threads) {
			thr=(MySQL_Thread *)mysql_threads[i].worker;
#ifdef IDLE_THREADS
		} else {
			thr=(MySQL_Thread *)mysql_threads_idles[i-num_threads].worker;
#endif // IDLE_THREADS
		}
		unsigned int j;
		for (j=0; j<thr->mysql_sessions->len; j++) {
			MySQL_Session *sess=(MySQL_Session *)thr->mysql_sessions->pdata[j];
			if (sess->client_myds) {
				char buf[1024];
				char **pta=(char **)malloc(sizeof(char *)*colnum);
				sprintf(buf,"%d", i);
				pta[0]=strdup(buf);
				sprintf(buf,"%u", sess->thread_session_id);
				pta[1]=strdup(buf);
				MySQL_Connection_userinfo *ui=sess->client_myds->myconn->userinfo;
				pta[2]=NULL;
				pta[3]=NULL;
				if (ui) {
					if (ui->username) {
						pta[2]=strdup(ui->username);
					} else {
						pta[2]=strdup("unauthenticated user");
					}
					if (ui->schemaname) {
						pta[3]=strdup(ui->schemaname);
					}
				}

                                if (sess->mirror==false) {
                                        switch (sess->client_myds->client_addr->sa_family) {
                                        case AF_INET: {
                                                struct sockaddr_in *ipv4 = (struct sockaddr_in *)sess->client_myds->client_addr;
                                                inet_ntop(sess->client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
                                                pta[4] = strdup(buf);
                                                sprintf(port, "%d", ntohs(ipv4->sin_port));
                                                pta[5] = strdup(port);
                                                break;
                                                }
                                        case AF_INET6: {
                                                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)sess->client_myds->client_addr;
                                                inet_ntop(sess->client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
                                                pta[4] = strdup(buf);
                                                sprintf(port, "%d", ntohs(ipv6->sin6_port));
                                                pta[5] = strdup(port);
                                                break;
                                                }
                                        default:
                                                pta[4] = strdup("localhost");
                                                pta[5] = NULL;
                                                break;
                                        }
                                }
				sprintf(buf,"%d", sess->current_hostgroup);
				pta[6]=strdup(buf);
				if (sess->mybe && sess->mybe->server_myds && sess->mybe->server_myds->myconn) {
					MySQL_Connection *mc=sess->mybe->server_myds->myconn;


					struct sockaddr addr;
					socklen_t addr_len=sizeof(struct sockaddr);
					memset(&addr,0,addr_len);
					int rc;
					rc=getsockname(mc->fd, &addr, &addr_len);
					if (rc==0) {
                                        switch (addr.sa_family) { 
                                                case AF_INET: {
                                                        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
                                                        inet_ntop(addr.sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
                                                        pta[7] = strdup(buf);
                                                        sprintf(port, "%d", ntohs(ipv4->sin_port));
                                                        pta[8] = strdup(port);
                                                        break;
                                                        }
                                                case AF_INET6: {
                                                        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;
                                                        inet_ntop(addr.sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
                                                        pta[7] = strdup(buf);
                                                        sprintf(port, "%d", ntohs(ipv6->sin6_port));
                                                        pta[8] = strdup(port);
                                                        break;
                                                        }
                                                default:
                                                        pta[7] = strdup("localhost");
                                                        pta[8] = NULL;
                                                        break;
                                                }
					} else {
						pta[7]=NULL;
						pta[8]=NULL;
					}

					sprintf(buf,"%s", mc->parent->address);
					pta[9]=strdup(buf);
					sprintf(buf,"%d", mc->parent->port);
					pta[10]=strdup(buf);
					if (sess->CurrentQuery.stmt_info==NULL) { // text protocol
						if (mc->query.length) {
							pta[13]=(char *)malloc(mc->query.length+1);
							strncpy(pta[13],mc->query.ptr,mc->query.length);
							pta[13][mc->query.length]='\0';
						} else {
							pta[13]=NULL;
						}
					} else { // prepared statement
						MySQL_STMT_Global_info *si=sess->CurrentQuery.stmt_info;
						if (si->query_length) {
							pta[13]=(char *)malloc(si->query_length+1);
							strncpy(pta[13],si->query,si->query_length);
							pta[13][si->query_length]='\0';
						} else {
							pta[13]=NULL;
						}
					}
				} else {
					pta[7]=NULL;
					pta[8]=NULL;
					pta[9]=NULL;
					pta[10]=NULL;
					pta[13]=NULL;
				}
				switch (sess->status) {
					case CONNECTING_SERVER:
						pta[11]=strdup("Connect");
						break;
					case PROCESSING_QUERY:
						if (sess->pause_until > sess->thread->curtime) {
							pta[11]=strdup("Delay");
						} else {
							pta[11]=strdup("Query");
						}
						break;
					case WAITING_CLIENT_DATA:
						pta[11]=strdup("Sleep");
						break;
					case CHANGING_USER_SERVER:
						pta[11]=strdup("Change user");
						break;
					case CHANGING_SCHEMA:
						pta[11]=strdup("InitDB");
						break;
					case PROCESSING_STMT_EXECUTE:
						pta[11]=strdup("Execute");
						break;
					case PROCESSING_STMT_PREPARE:
						pta[11]=strdup("Prepare");
						break;
					default:
						sprintf(buf,"%d", sess->status);
						pta[11]=strdup(buf);
						break;
				}
				if (sess->mirror==false) {
					int idx=sess->client_myds->poll_fds_idx;
					unsigned long long last_sent=sess->thread->mypolls.last_sent[idx];
					unsigned long long last_recv=sess->thread->mypolls.last_recv[idx];
					unsigned long long last_time=(last_sent > last_recv ? last_sent : last_recv);
					if (last_time>sess->thread->curtime) {
						last_time=sess->thread->curtime;
					}
					sprintf(buf,"%llu", (sess->thread->curtime - last_time)/1000 );
				} else {
					// for mirror session we only consider the start time
					sprintf(buf,"%llu", (sess->thread->curtime - sess->start_time)/1000 );
				}
				pta[12]=strdup(buf);

				result->add_row(pta);
				unsigned int k;
				for (k=0; k<colnum; k++) {
					if (pta[k])
						free(pta[k]);
				}
				free(pta);
			}
		}
	}
#ifdef IDLE_THREADS
	for (i=0;i < ( (mysql_thread___session_idle_show_processlist && GloVars.global.idle_threads ) ? num_threads*2 : num_threads); i++) {
#else
	for (i=0;i < num_threads; i++) {
#endif // IDLE_THREADS
		if (i<num_threads) {
			thr=(MySQL_Thread *)mysql_threads[i].worker;
			spin_wrunlock(&thr->thread_mutex);
#ifdef IDLE_THREADS
		} else {
			if (mysql_thread___session_idle_show_processlist) {
				thr=(MySQL_Thread *)mysql_threads_idles[i-num_threads].worker;
				spin_wrunlock(&thr->thread_mutex);
			}
#endif // IDLE_THREADS
		}
	}
	return result;
}

void MySQL_Threads_Handler::signal_all_threads(unsigned char _c) {
	unsigned int i;
	unsigned char c=_c;
	if (mysql_threads==0) return;
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
		int fd=thr->pipefd[1];
		if (write(fd,&c,1)==-1) {
			proxy_error("Error during write in signal_all_threads()\n");
		}
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads_idles[i].worker;
		int fd=thr->pipefd[1];
		if (write(fd,&c,1)==-1) {
			proxy_error("Error during write in signal_all_threads()\n");
		}
	}
#endif // IDLE_THREADS
}

bool MySQL_Threads_Handler::kill_session(uint32_t _thread_session_id) {
	bool ret=false;
	unsigned int i;
	signal_all_threads(1);
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
		spin_wrlock(&thr->thread_mutex);
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads_idles[i].worker;
		spin_wrlock(&thr->thread_mutex);
	}
#endif // IDLE_THREADS
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
		unsigned int j;
		for (j=0; j<thr->mysql_sessions->len; j++) {
			MySQL_Session *sess=(MySQL_Session *)thr->mysql_sessions->pdata[j];
			if (sess->thread_session_id==_thread_session_id) {
				sess->killed=true;
				ret=true;
				goto __exit_kill_session;
			}
		}
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads_idles[i].worker;
		unsigned int j;
		for (j=0; j<thr->mysql_sessions->len; j++) {
			MySQL_Session *sess=(MySQL_Session *)thr->mysql_sessions->pdata[j];
			if (sess->thread_session_id==_thread_session_id) {
				sess->killed=true;
				ret=true;
				goto __exit_kill_session;
			}
		}
	}
#endif // IDLE_THREADS
__exit_kill_session:
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
		spin_wrunlock(&thr->thread_mutex);
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads_idles[i].worker;
		spin_wrunlock(&thr->thread_mutex);
	}
#endif // IDLE_THREADS
	return ret;
}

unsigned long long MySQL_Threads_Handler::get_total_stmt_prepare() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.stmt_prepare,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_total_stmt_execute() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.stmt_execute,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_total_stmt_close() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.stmt_close,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_total_queries() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.queries,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_slow_queries() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.queries_slow,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_queries_backends_bytes_recv() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.queries_backends_bytes_recv,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_queries_backends_bytes_sent() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.queries_backends_bytes_sent,0);
		}
	}
	return q;
}

unsigned int MySQL_Threads_Handler::get_active_transations() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.active_transactions,0);
		}
	}
	return q;
}

#ifdef IDLE_THREADS
unsigned int MySQL_Threads_Handler::get_non_idle_client_connections() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->mysql_sessions->len,0);
		}
	}
	return q;
}
#endif // IDLE_THREADS

unsigned long long MySQL_Threads_Handler::get_query_processor_time() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.query_processor_time,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_backend_query_time() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.backend_query_time,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_mysql_backend_buffers_bytes() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.mysql_backend_buffers_bytes,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_mysql_frontend_buffers_bytes() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.mysql_frontend_buffers_bytes,0);
		}
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
	for (i=0;i<num_threads;i++) {
		if (mysql_threads_idles) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads_idles[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.mysql_frontend_buffers_bytes,0);
		}
	}
#endif // IDLE_THREADS
	return q;
}

unsigned long long MySQL_Threads_Handler::get_mysql_session_internal_bytes() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.mysql_session_internal_bytes,0);
		}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
		if (mysql_threads_idles) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads_idles[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.mysql_session_internal_bytes,0);
		}
#endif // IDLE_THREADS
	}
	return q;
}

void MySQL_Thread::Get_Memory_Stats() {
	unsigned int i;
	status_variables.mysql_backend_buffers_bytes=0;
	status_variables.mysql_frontend_buffers_bytes=0;
	status_variables.mysql_session_internal_bytes=sizeof(MySQL_Thread);
	if (mysql_sessions) {
		status_variables.mysql_session_internal_bytes+=(mysql_sessions->size)*sizeof(MySQL_Session *);
		if (epoll_thread==false) {
			for (i=0; i<mysql_sessions->len; i++) {
				MySQL_Session *sess=(MySQL_Session *)mysql_sessions->index(i);
				sess->Memory_Stats();
			}
		} else {
			status_variables.mysql_frontend_buffers_bytes+=(mysql_sessions->len * QUEUE_T_DEFAULT_SIZE * 2);
			status_variables.mysql_session_internal_bytes+=(mysql_sessions->len * sizeof(MySQL_Connection));
#if !defined(__FreeBSD__) && !defined(__APPLE__)
			status_variables.mysql_session_internal_bytes+=((sizeof(int) + sizeof(int) + sizeof(std::_Rb_tree_node_base)) * mysql_sessions->len );
#else
			status_variables.mysql_session_internal_bytes+=((sizeof(int) + sizeof(int) + 32) * mysql_sessions->len );
#endif
		}
  }
}


MySQL_Connection * MySQL_Thread::get_MyConn_local(unsigned int _hid) {
	unsigned int i;
	MySQL_Connection *c=NULL;
	for (i=0; i<cached_connections->len; i++) {
		c=(MySQL_Connection *)cached_connections->index(i);
		if (c->parent->myhgc->hid==_hid) {
			c=(MySQL_Connection *)cached_connections->remove_index_fast(i);
			return c;
		}
	}
	return NULL;
}

void MySQL_Thread::push_MyConn_local(MySQL_Connection *c) {
	MySrvC *mysrvc=NULL;
	mysrvc=(MySrvC *)c->parent;
	if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) {
		if (c->async_state_machine==ASYNC_IDLE) {
			cached_connections->add(c);
			return; // all went well
		}
	}
	MyHGM->push_MyConn_to_pool(c);
}

void MySQL_Thread::return_local_connections() {
	if (cached_connections->len==0) {
		return;
	}
	MySQL_Connection **ca=(MySQL_Connection **)malloc(sizeof(MySQL_Connection *)*(cached_connections->len+1));
	unsigned int i=0;
	while (cached_connections->len) {
		ca[i]=(MySQL_Connection *)cached_connections->remove_index_fast(0);
		i++;
	}
	ca[i]=NULL;
	MyHGM->push_MyConn_to_pool_array(ca);
	free(ca);
}

unsigned long long MySQL_Threads_Handler::get_ConnPool_get_conn_immediate() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.ConnPool_get_conn_immediate,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_ConnPool_get_conn_success() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.ConnPool_get_conn_success,0);
		}
	}
	return q;
}

unsigned long long MySQL_Threads_Handler::get_ConnPool_get_conn_failure() {
	unsigned long long q=0;
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		if (mysql_threads) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			if (thr)
				q+=__sync_fetch_and_add(&thr->status_variables.ConnPool_get_conn_failure,0);
		}
	}
	return q;
}
