//#define __CLASS_STANDARD_MYSQL_THREAD_H
#define MYSQL_THREAD_IMPLEMENTATION
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Thread.h"

#define PROXYSQL_LISTEN_LEN 1024

extern Query_Processor *GloQPro;
extern MySQL_Threads_Handler *GloMTH;


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
#define MYSQL_THREAD_VERSION "0.1.1114" DEB


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
		delete ifi;
	}
	delete ifaces;
	ifaces=NULL;
}

int MySQL_Listeners_Manager::add(const char *iface) {
	for (unsigned int i=0; i<ifaces->len; i++) {
		iface_info *ifi=(iface_info *)ifaces->index(i);
		if (strcmp(ifi->iface,iface)==0) {
			return -1;
		}
	}
	char *address=NULL; char *port=NULL;
	c_split_2(iface, ":" , &address, &port);
	int s = ( atoi(port) ? listen_on_port(address, atoi(port), PROXYSQL_LISTEN_LEN) : listen_on_unix(address, PROXYSQL_LISTEN_LEN));
	if (s==-1) return s;
	ioctl_FIONBIO(s,1);
	iface_info *ifi=new iface_info((char *)iface, address, atoi(port), s);
	ifaces->add(ifi);
	return s;
}

int MySQL_Listeners_Manager::add(const char *address, int port) {
	char *s=(char *)malloc(strlen(address)+32);
	sprintf(s,"%s:%d",address,port);
	int ret=add((const char *)s);
	free(s);
	return ret;
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
	(char *)"shun_recovery_time",
	(char *)"connect_retries_on_failure",
	(char *)"connect_retries_delay",
	(char *)"connect_timeout_server",
	(char *)"connect_timeout_server_max",
	(char *)"default_charset",
	(char *)"free_connections_pct",
	(char *)"have_compress",
	(char *)"interfaces",
	(char *)"monitor_history",
	(char *)"monitor_connect_interval",
	(char *)"monitor_connect_timeout",
	(char *)"monitor_ping_interval",
	(char *)"monitor_ping_timeout",
	(char *)"monitor_replication_lag_interval",
	(char *)"monitor_replication_lag_timeout",
	(char *)"monitor_username",
	(char *)"monitor_password",
	(char *)"monitor_query_variables",
	(char *)"monitor_query_status",
	(char *)"monitor_query_interval",
	(char *)"monitor_query_timeout",
	(char *)"monitor_timer_cached",
	(char *)"max_transaction_time",
	(char *)"threshold_query_length",
	(char *)"wait_timeout",
	(char *)"max_connections",
	(char *)"default_query_delay",
	(char *)"default_query_timeout",
	(char *)"long_query_time",
	(char *)"ping_interval_server",
	(char *)"ping_timeout_server",
	(char *)"default_schema",
	(char *)"poll_timeout",
	(char *)"poll_timeout_on_failure",
	(char *)"server_capabilities",
	(char *)"server_version",
	(char *)"sessions_sort",
	(char *)"commands_stats",
	(char *)"query_digests",
	(char *)"servers_stats",
	(char *)"default_reconnect",
	(char *)"session_debug",
	(char *)"stacksize",
	(char *)"threads",
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
	stacksize=0;
	shutdown_=0;
	spinlock_rwlock_init(&rwlock);
	pthread_attr_init(&attr);
	variables.shun_on_failures=5;
	variables.shun_recovery_time=10;
	variables.connect_retries_on_failure=5;
	variables.connect_timeout_server=1000;
	variables.connect_timeout_server_max=10000;
	variables.free_connections_pct=10;
	variables.connect_retries_delay=1;
	variables.monitor_history=600000;
	variables.monitor_connect_interval=120000;
	variables.monitor_connect_timeout=200;
	variables.monitor_ping_interval=60000;
	variables.monitor_ping_timeout=100;
	variables.monitor_replication_lag_interval=10000;
	variables.monitor_replication_lag_timeout=1000;
	variables.monitor_query_interval=60000;
	variables.monitor_query_timeout=100;
	variables.monitor_username=strdup((char *)"monitor");
	variables.monitor_password=strdup((char *)"monitor");
	variables.monitor_query_variables=strdup((char *)"SELECT * FROM INFORMATION_SCHEMA.GLOBAL_VARIABLES");
	variables.monitor_query_status=strdup((char *)"SELECT * FROM INFORMATION_SCHEMA.GLOBAL_STATUS");
	variables.monitor_timer_cached=true;
	variables.max_transaction_time=4*3600*1000;
	variables.threshold_query_length=512*1024;
	variables.wait_timeout=8*3600*1000;
	variables.max_connections=10*1000;
	variables.default_query_delay=0;
	variables.default_query_timeout=24*3600*1000;
	variables.long_query_time=1000;
	variables.ping_interval_server=10000;
	variables.ping_timeout_server=200;
	variables.default_schema=strdup((char *)"information_schema");
	variables.default_charset=33;
	variables.interfaces=strdup((char *)"");
	variables.server_version=strdup((char *)"5.1.30");
	variables.server_capabilities=CLIENT_FOUND_ROWS | CLIENT_PROTOCOL_41 | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB | CLIENT_SSL;
	variables.poll_timeout=2000;
	variables.poll_timeout_on_failure=100;
	variables.have_compress=true;
	variables.commands_stats=true;
	variables.query_digests=true;
	variables.sessions_sort=true;
	variables.servers_stats=true;
	variables.default_reconnect=true;
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
	rc=MLM->add(iface);
	if (rc>-1) {
		unsigned int i;
		for (i=0;i<num_threads;i++) {
			MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
			while(!__sync_bool_compare_and_swap(&thr->mypolls.pending_listener_add,0,rc));
/*		
			while(!__sync_bool_compare_and_swap(&thr->mypolls.pending_listener_change,0,1)) { cpu_relax_pa(); }
			while(__sync_fetch_and_add(&thr->mypolls.pending_listener_change,0)==1) { cpu_relax_pa(); }
//			spin_wrlock(&thr->thread_mutex);
			thr->poll_listener_add(rc);
			while(!__sync_bool_compare_and_swap(&thr->mypolls.pending_listener_change,2,0));
//			spin_wrunlock(&thr->thread_mutex);
*/
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
		if (!strcasecmp(name,"monitor_query_variables")) return strdup(variables.monitor_query_variables);
		if (!strcasecmp(name,"monitor_query_status")) return strdup(variables.monitor_query_status);
	}
	if (!strcasecmp(name,"server_version")) return strdup(variables.server_version);
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
		if (!strcasecmp(name,"monitor_history")) return (int)variables.monitor_history;
		if (!strcasecmp(name,"monitor_connect_interval")) return (int)variables.monitor_connect_interval;
		if (!strcasecmp(name,"monitor_connect_timeout")) return (int)variables.monitor_connect_timeout;
		if (!strcasecmp(name,"monitor_ping_interval")) return (int)variables.monitor_ping_interval;
		if (!strcasecmp(name,"monitor_ping_timeout")) return (int)variables.monitor_ping_timeout;
		if (!strcasecmp(name,"monitor_replication_lag_interval")) return (int)variables.monitor_replication_lag_interval;
		if (!strcasecmp(name,"monitor_replication_lag_timeout")) return (int)variables.monitor_replication_lag_timeout;
		if (!strcasecmp(name,"monitor_query_interval")) return (int)variables.monitor_query_interval;
		if (!strcasecmp(name,"monitor_query_timeout")) return (int)variables.monitor_query_timeout;
		if (!strcasecmp(name,"monitor_timer_cached")) return (int)variables.monitor_timer_cached;
	}
	if (!strcasecmp(name,"shun_on_failures")) return (int)variables.shun_on_failures;
	if (!strcasecmp(name,"shun_recovery_time")) return (int)variables.shun_recovery_time;
	if (!strcasecmp(name,"connect_retries_on_failure")) return (int)variables.connect_retries_on_failure;
	if (!strcasecmp(name,"connect_timeout_server")) return (int)variables.connect_timeout_server;
	if (!strcasecmp(name,"connect_timeout_server_max")) return (int)variables.connect_timeout_server_max;
	if (!strcasecmp(name,"connect_retries_delay")) return (int)variables.connect_retries_delay;
	if (!strcasecmp(name,"max_transaction_time")) return (int)variables.max_transaction_time;
	if (!strcasecmp(name,"threshold_query_length")) return (int)variables.threshold_query_length;
	if (!strcasecmp(name,"wait_timeout")) return (int)variables.wait_timeout;
	if (!strcasecmp(name,"max_connections")) return (int)variables.max_connections;
	if (!strcasecmp(name,"default_query_delay")) return (int)variables.default_query_delay;
	if (!strcasecmp(name,"default_query_timeout")) return (int)variables.default_query_timeout;
	if (!strcasecmp(name,"long_query_time")) return (int)variables.long_query_time;
	if (!strcasecmp(name,"free_connections_pct")) return (int)variables.free_connections_pct;
	if (!strcasecmp(name,"ping_interval_server")) return (int)variables.ping_interval_server;
	if (!strcasecmp(name,"ping_timeout_server")) return (int)variables.ping_timeout_server;
	if (!strcasecmp(name,"have_compress")) return (int)variables.have_compress;
	if (!strcasecmp(name,"commands_stats")) return (int)variables.commands_stats;
	if (!strcasecmp(name,"query_digests")) return (int)variables.query_digests;
	if (!strcasecmp(name,"sessions_sort")) return (int)variables.sessions_sort;
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
	if (!strcasecmp(name,"server_version")) return strdup(variables.server_version);
	if (!strcasecmp(name,"default_schema")) return strdup(variables.default_schema);
	if (!strcasecmp(name,"interfaces")) return strdup(variables.interfaces);
	if (!strcasecmp(name,"server_capabilities")) {
		// FIXME : make it human readable
		sprintf(intbuf,"%d",variables.server_capabilities);
		return strdup(intbuf);
	}
	// monitor variables
	if (!strncasecmp(name,"monitor_",8)) {
		if (!strcasecmp(name,"monitor_username")) return strdup(variables.monitor_username);
		if (!strcasecmp(name,"monitor_password")) return strdup(variables.monitor_password);
		if (!strcasecmp(name,"monitor_query_variables")) return strdup(variables.monitor_query_variables);
		if (!strcasecmp(name,"monitor_query_status")) return strdup(variables.monitor_query_status);
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
		if (!strcasecmp(name,"monitor_ping_timeout")) {
			sprintf(intbuf,"%d",variables.monitor_ping_timeout);
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
		if (!strcasecmp(name,"monitor_timer_cached")) {
			return strdup((variables.monitor_timer_cached ? "true" : "false"));
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
	if (!strcasecmp(name,"shun_recovery_time")) {
		sprintf(intbuf,"%d",variables.shun_recovery_time);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"connect_retries_on_failure")) {
		sprintf(intbuf,"%d",variables.connect_retries_on_failure);
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
	if (!strcasecmp(name,"connect_retries_delay")) {
		sprintf(intbuf,"%d",variables.connect_retries_delay);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"max_transaction_time")) {
		sprintf(intbuf,"%d",variables.max_transaction_time);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"threshold_query_length")) {
		sprintf(intbuf,"%d",variables.threshold_query_length);
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
	if (!strcasecmp(name,"default_query_delay")) {
		sprintf(intbuf,"%d",variables.default_query_delay);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"default_query_timeout")) {
		sprintf(intbuf,"%d",variables.default_query_timeout);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"long_query_time")) {
		sprintf(intbuf,"%d",variables.long_query_time);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"ping_interval_server")) {
		sprintf(intbuf,"%d",variables.ping_interval_server);
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
	if (!strcasecmp(name,"commands_stats")) {
		return strdup((variables.commands_stats ? "true" : "false"));
	}
	if (!strcasecmp(name,"query_digests")) {
		return strdup((variables.query_digests ? "true" : "false"));
	}
	if (!strcasecmp(name,"sessions_sort")) {
		return strdup((variables.sessions_sort ? "true" : "false"));
	}
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
			if (vallen) {
				free(variables.monitor_password);
				variables.monitor_password=strdup(value);
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_query_variables")) {
			if (vallen) {
				free(variables.monitor_query_variables);
				variables.monitor_query_variables=strdup(value);
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"monitor_query_status")) {
			if (vallen) {
				free(variables.monitor_query_status);
				variables.monitor_query_status=strdup(value);
				return true;
			} else {
				return false;
			}
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
		if (!strcasecmp(name,"monitor_ping_timeout")) {
			int intv=atoi(value);
			if (intv >= 100 && intv <= 600*1000) {
				variables.monitor_ping_timeout=intv;
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
		if (!strcasecmp(name,"monitor_timer_cached")) {
			if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
				variables.monitor_timer_cached=true;
				return true;
			}
			if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
				variables.monitor_timer_cached=false;
				return true;
			}
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
	if (!strcasecmp(name,"threshold_query_length")) {
		int intv=atoi(value);
		if (intv >= 1024 && intv <= 1*1024*1024*1024) {
			variables.threshold_query_length=intv;
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
	if (!strcasecmp(name,"max_connections")) {
		int intv=atoi(value);
		if (intv >= 1 && intv <= 1000*1000) {
			variables.max_connections=intv;
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
	if (!strcasecmp(name,"long_query_time")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 20*24*3600*1000) {
			variables.long_query_time=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"ping_interval_server")) {
		int intv=atoi(value);
		if (intv >= 1000 && intv <= 7*24*3600*1000) {
			variables.ping_interval_server=intv;
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
	if (!strcasecmp(name,"shun_recovery_time")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 3600*24*365) {
			variables.shun_recovery_time=intv;
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
			variables.server_version=strdup(value);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"server_capabilities")) {
		int intv=atoi(value);
		if (intv > 10 && intv <= 65535) {
			variables.server_capabilities=intv;
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
}

proxysql_mysql_thread_t * MySQL_Threads_Handler::create_thread(unsigned int tn, void *(*start_routine) (void *)) {
	pthread_create(&mysql_threads[tn].thread_id, &attr, start_routine , &mysql_threads[tn]);
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
		for (i=0; i<num_threads; i++) {
			if (mysql_threads[i].worker)
				pthread_join(mysql_threads[i].thread_id,NULL);
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
	if (variables.default_schema) free(variables.default_schema);
	if (variables.interfaces) free(variables.interfaces);
	if (variables.server_version) free(variables.server_version);
	free(mysql_threads);
	mysql_threads=NULL;
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
	if (mysql_sessions_connections_handler) {
		while(mysql_sessions_connections_handler->len) {
			MySQL_Session *sess=(MySQL_Session *)mysql_sessions_connections_handler->remove_index_fast(0);
				delete sess;
			}
		delete mysql_sessions_connections_handler;
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
	//if (my_idle_myds)
	//	free(my_idle_myds);
	GloQPro->end_thread();

	if (mysql_thread___default_schema) { free(mysql_thread___default_schema); mysql_thread___default_schema=NULL; }
	if (mysql_thread___server_version) { free(mysql_thread___server_version); mysql_thread___server_version=NULL; }

}



MySQL_Session * MySQL_Thread::create_new_session_and_client_data_stream(int _fd) {
	int arg_on=1;
	MySQL_Session *sess=new MySQL_Session;
	register_session(sess); // register session
	//sess->client_fd=_fd;
	sess->client_myds = new MySQL_Data_Stream();
	sess->client_myds->fd=_fd;
	setsockopt(sess->client_myds->fd, IPPROTO_TCP, TCP_NODELAY, (char *) &arg_on, sizeof(int));
	sess->client_myds->init(MYDS_FRONTEND, sess, sess->client_myds->fd);
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p, DataStream=%p -- Created new client Data Stream\n", sess->thread, sess, sess->client_myds);
	//sess->prot.generate_server_handshake(sess->client_myds);
#ifdef DEBUG
	//sess->myprot_client.dump_pkt=true;
	sess->client_myds->myprot.dump_pkt=true;
#endif
	//sess->client_myds->myconn=new MySQL_Connection();
	//MySQL_Connection *myconn=sess->client_myds->myconn;
	MySQL_Connection *myconn=new MySQL_Connection;
	sess->client_myds->attach_connection(myconn);
	//myconn=new MySQL_Connection();  // 20141011
//	if (mysql_thread___have_compress) {
//		myconn->options.compression_min_length=50;
//		myconn->options.server_capabilities|=CLIENT_COMPRESS;
//	}
	myconn->last_time_used=curtime;
	myconn->myds=sess->client_myds; // 20141011
	myconn->fd=sess->client_myds->fd; // 20141011

	// FIXME: initializing both, later we will drop one
	//sess->myprot_client.init(&sess->client_myds, sess->client_myds->myconn->userinfo, sess);
	sess->client_myds->myprot.init(&sess->client_myds, sess->client_myds->myconn->userinfo, sess);
	return sess;
}

bool MySQL_Thread::init() {
	int i;
	mysql_sessions = new PtrArray();
	assert(mysql_sessions);
	mysql_sessions_connections_handler = new PtrArray();
	assert(mysql_sessions_connections_handler);
	for (i=0; i<SESSIONS_FOR_CONNECTIONS_HANDLER;i++) {
		MySQL_Session *sess=new MySQL_Session();
		register_session_connection_handler(sess, false);
	}
	shutdown=0;
	my_idle_conns=(MySQL_Connection **)malloc(sizeof(MySQL_Connection *)*SESSIONS_FOR_CONNECTIONS_HANDLER);
	memset(my_idle_conns,0,sizeof(MySQL_Connection *)*SESSIONS_FOR_CONNECTIONS_HANDLER);
	//my_idle_myds=(MySQL_Data_Stream **)malloc(sizeof(MySQL_Data_Stream *)*SESSIONS_FOR_CONNECTIONS_HANDLER);
	//memset(my_idle_myds,0,sizeof(MySQL_Data_Stream *)*SESSIONS_FOR_CONNECTIONS_HANDLER);
	GloQPro->init_thread();
	refresh_variables();
	i=pipe(pipefd);
	mypolls.add(POLLIN, pipefd[0], NULL, 0);
	assert(i==0);
	return true;
}

struct pollfd * MySQL_Thread::get_pollfd(unsigned int i) {
	return &mypolls.fds[i];
}

void MySQL_Thread::poll_listener_add(int sock) {
	MySQL_Data_Stream *listener_DS = new MySQL_Data_Stream;	
	listener_DS->myds_type=MYDS_LISTENER;
	listener_DS->fd=sock;

	proxy_debug(PROXY_DEBUG_NET,1,"Created listener %p for socket %d\n", listener_DS, sock);
	//mypoll_add(&mypolls, POLLIN, sock, listener_DS);	
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

void MySQL_Thread::register_session(MySQL_Session *_sess) {
	if (mysql_sessions==NULL) {
		mysql_sessions = new PtrArray();
	}
	mysql_sessions->add(_sess);
	_sess->thread=this;
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
	//int arg_on=1;


	unsigned long long oldtime=monotonic_time();

	curtime=monotonic_time();

	spin_wrlock(&thread_mutex);

	while (shutdown==0) {

	int num_idles;
	if (processing_idles==false &&  (last_processing_idles < curtime-mysql_thread___ping_interval_server*1000/10) ) {
		int i;
		num_idles=MyHGM->get_multiple_idle_connections(-1, curtime-mysql_thread___ping_interval_server*1000, my_idle_conns, SESSIONS_FOR_CONNECTIONS_HANDLER);
		for (i=0; i<num_idles; i++) {
			MySQL_Data_Stream *myds;
	//		myds=new MySQL_Data_Stream();
			MySQL_Connection *mc=my_idle_conns[i];
//			myds->myconn=mc;
	//		myds->attach_connection(mc);
	//		myds->assign_fd_from_mysql_conn();
	//		myds->myds_type=MYDS_BACKEND;
			//MySQL_Session *sess=(MySQL_Session *)mysql_sessions_connections_handler->index(i);
			MySQL_Session *sess=new MySQL_Session();
	//		myds->sess=sess;
	//		myds->init();
	//		my_idle_myds[i]=myds;
			sess->mybe=sess->find_or_create_backend(mc->parent->myhgc->hid);
	//		sess->mybe->server_myds=myds;

			myds=sess->mybe->server_myds;
			myds->attach_connection(mc);
			myds->assign_fd_from_mysql_conn();
			myds->myds_type=MYDS_BACKEND;

			sess->to_process=1;
			myds->wait_until=curtime+mysql_thread___ping_timeout_server*1000;	// max_timeout
//			sess->status=WAITING_SERVER_DATA;
			//myds->mypolls=&mypolls;
			mc->last_time_used=curtime;
			myds->myprot.init(&myds, myds->myconn->userinfo, NULL);
//			myds->myprot.generate_COM_PING(true,NULL,NULL);
//			myds->array2buffer_full();
//			myds->DSS=STATE_QUERY_SENT_DS;
			sess->status=PINGING_SERVER;
			myds->DSS=STATE_MARIADB_PING;
			register_session_connection_handler(sess,true);
			int rc=sess->handler();
			if (rc==-1) {
				unsigned int sess_idx=mysql_sessions->len-1;
				unregister_session(sess_idx);
				delete sess;
			}
//			myds->myconn->async_ping(0);
//			myds->myconn->async_state_machine=ASYNC_PING_START;
//			myds->myconn->handler(0);
//			mypolls.add(POLLIN|POLLOUT, myds->fd, myds, curtime);

		}
		processing_idles=true;
		last_processing_idles=curtime;
	}

	if (processing_idles==true &&	(last_processing_idles < curtime-3*mysql_thread___ping_timeout_server*1000)) {
		processing_idles=false;
/*
		int i;
		for (i=0; i<num_idles; i++) {
			MySQL_Data_Stream *myds;
			myds=my_idle_myds[i];
			if (myds->myconn) {
				MyHGM->destroy_MyConn_from_pool(myds->myconn);
				myds->myconn=NULL;
				if (myds->fd) {
					myds->shut_hard();
//					shutdown(myds->fd,SHUT_RDWR);
//					close(myds->fd);
					myds->fd=0;
          mypolls.remove_index_fast(myds->poll_fds_idx);
				}
			}
		}
*/
	}

		for (n = 0; n < mypolls.len; n++) {
			MySQL_Data_Stream *myds=NULL;
			myds=mypolls.myds[n];
			mypolls.fds[n].revents=0;
			if (myds) {
				if (myds->wait_until) {
					if (myds->wait_until > curtime) {
						if (mypolls.poll_timeout==0 || (myds->wait_until - curtime < mypolls.poll_timeout) ) {
							mypolls.poll_timeout= myds->wait_until - curtime;
						}
//					} else {
//						mypolls.poll_timeout=1000;
					}
				}
				if (myds->sess) {
					if (myds->sess->pause_until > 0) {
						if (mypolls.poll_timeout==0 || (myds->sess->pause_until - curtime < mypolls.poll_timeout) ) {
							mypolls.poll_timeout= myds->sess->pause_until - curtime;
						}
//					} else {
//						mypolls.poll_timeout=1000;
					}
				}
			}
			if (myds) myds->revents=0;
			if (mypolls.myds[n] && mypolls.myds[n]->myds_type!=MYDS_LISTENER) {
//				mypolls.myds[n]->set_pollout();
				if (mypolls.myds[n]->DSS > STATE_MARIADB_BEGIN && mypolls.myds[n]->DSS < STATE_MARIADB_END) {
					mypolls.fds[n].events = POLLIN;
					if (mypolls.myds[n]->myconn->async_exit_status & MYSQL_WAIT_WRITE)
						mypolls.fds[n].events |= POLLOUT;
				} else {
					mypolls.myds[n]->set_pollout();
				}
			}
			proxy_debug(PROXY_DEBUG_NET,1,"Poll for DataStream=%p will be called with FD=%d and events=%d\n", mypolls.myds[n], mypolls.fds[n].fd, mypolls.fds[n].events);
		}

	
		spin_wrunlock(&thread_mutex);

		while ((n=__sync_add_and_fetch(&mypolls.pending_listener_add,0))) {	// spin here
			poll_listener_add(n);
			assert(__sync_bool_compare_and_swap(&mypolls.pending_listener_add,n,0));
//			if (n==1) {
//				__sync_add_and_fetch(&mypolls.pending_listener_change,1);
//			}
		}	

		if (mysql_thread___wait_timeout==0) {
			// we should be going into PAUSE mode
			if (mypolls.poll_timeout==0 || mypolls.poll_timeout > 100000) {
				mypolls.poll_timeout=100000;
			}
		}

		//this is the only portion of code not protected by a global mutex
		//proxy_debug(PROXY_DEBUG_NET,5,"Calling poll with timeout %d\n", ( mypolls.poll_timeout ? mypolls.poll_timeout : mysql_thread___poll_timeout )  );
		proxy_debug(PROXY_DEBUG_NET,5,"Calling poll with timeout %d\n", ( mypolls.poll_timeout ? ( mypolls.poll_timeout/1000 > (unsigned int) mysql_thread___poll_timeout ? mypolls.poll_timeout/1000 : mysql_thread___poll_timeout ) : mysql_thread___poll_timeout )  );
		// poll is called with a timeout of mypolls.poll_timeout if set , or mysql_thread___poll_timeout
		rc=poll(mypolls.fds,mypolls.len, ( mypolls.poll_timeout ? ( mypolls.poll_timeout/1000 < (unsigned int) mysql_thread___poll_timeout ? mypolls.poll_timeout/1000 : mysql_thread___poll_timeout ) : mysql_thread___poll_timeout ) );
		proxy_debug(PROXY_DEBUG_NET,5,"%s\n", "Returning poll");

		while ((n=__sync_add_and_fetch(&mypolls.pending_listener_del,0))) {	// spin here
			poll_listener_del(n);
			assert(__sync_bool_compare_and_swap(&mypolls.pending_listener_del,n,0));
		}

		curtime=monotonic_time();

		spin_wrlock(&thread_mutex);
		mypolls.poll_timeout=0; // always reset this to 0 . If a session needs a specific timeout, it will set this one
		
		curtime=monotonic_time();

		// update polls statistics
		mypolls.loops++;
		mypolls.loop_counters->incr(curtime/1000000);

		if (curtime>(oldtime+(mysql_thread___poll_timeout*1000))) {
			oldtime=curtime;
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


		for (n = 0; n < mypolls.len; n++) {
			proxy_debug(PROXY_DEBUG_NET,3, "poll for fd %d events %d revents %d\n", mypolls.fds[n].fd , mypolls.fds[n].events, mypolls.fds[n].revents);




			MySQL_Data_Stream *myds=mypolls.myds[n];
			if (myds==NULL) {
				if (mypolls.fds[n].revents) {
					unsigned char c;
					read(mypolls.fds[n].fd, &c, 1);	// read just one byte , no need for error handling
					proxy_debug(PROXY_DEBUG_GENERIC,3, "Got signal from admin , done nothing\n");
					//fprintf(stderr,"Got signal from admin , done nothing\n"); // FIXME: this is just the scheleton for issue #253
					if (c) {
						// we are being signaled to sleep for some ms. Before going to sleep we also release the mutex
						spin_wrunlock(&thread_mutex);
						usleep(c*1000);
						spin_wrlock(&thread_mutex);
					}
				}
			continue;
			}
			if (mypolls.fds[n].revents==0) {
			// FIXME: this logic was removed completely because we added mariadb client library. Yet, we need to implement a way to manage connection timeout
			// check for timeout
			} else {
				// check if the FD is valid
				assert(mypolls.fds[n].revents!=POLLNVAL);
				switch(myds->myds_type) {
		// Note: this logic that was here was removed completely because we added mariadb client library.
					case MYDS_LISTENER:
						// we got a new connection!
						listener_handle_new_connection(myds,n);
						continue;
						break;
/*
					//Removing from here. Management of backend should be done within the session
					case MYDS_FRONTEND:
						// detected an error on backend
						if ( (mypolls.fds[n].revents & POLLERR) || (mypolls.fds[n].revents & POLLHUP) ) {
							// FIXME: try to handle it in a more graceful way
							myds->sess->set_unhealthy();
						}
						break;
*/
					default:
						break;
				}
				// data on exiting connection
				process_data_on_data_stream(myds, n);
		}
		}
		// iterate through all sessions and process the session logic
		process_all_sessions();


		process_all_sessions_connections_handler();

	}
}

void MySQL_Thread::process_data_on_data_stream(MySQL_Data_Stream *myds, unsigned int n) {
				if (mypolls.fds[n].revents) {
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
					}
				}
				if (myds->myds_type==MYDS_BACKEND && myds->sess->status!=FAST_FORWARD) {
					return;
				}
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
				

	      if (myds->active==FALSE) {
					if (myds->sess->client_myds==myds) {
						proxy_debug(PROXY_DEBUG_NET,1, "Session=%p, DataStream=%p -- Deleting FD %d\n", myds->sess, myds, myds->fd);
						myds->sess->set_unhealthy();
					}
				}
}


void MySQL_Thread::process_all_sessions() {
	unsigned int n;
	int rc;
	bool sess_sort=mysql_thread___sessions_sort;
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
		unsigned int numTrx=0;
		unsigned long long sess_time = sess->IdleTime();
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
		if (sess->healthy==0) {
			unregister_session(n);
			n--;
			delete sess;
		} else {
			if (sess->to_process==1 || sess->pause<=curtime ) {
				if (sess->pause <= curtime ) sess->pause=0;
				if (sess->pause_until <= curtime) {
					rc=sess->handler();
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
}

void MySQL_Thread::refresh_variables() {
	GloMTH->wrlock();
	__thread_MySQL_Thread_Variables_version=__global_MySQL_Thread_Variables_version;
	mysql_thread___max_transaction_time=GloMTH->get_variable_int((char *)"max_transaction_time");
	mysql_thread___threshold_query_length=GloMTH->get_variable_int((char *)"threshold_query_length");
	mysql_thread___wait_timeout=GloMTH->get_variable_int((char *)"wait_timeout");
	mysql_thread___max_connections=GloMTH->get_variable_int((char *)"max_connections");
	mysql_thread___default_query_delay=GloMTH->get_variable_int((char *)"default_query_delay");
	mysql_thread___default_query_timeout=GloMTH->get_variable_int((char *)"default_query_timeout");
	mysql_thread___long_query_time=GloMTH->get_variable_int((char *)"long_query_time");
	mysql_thread___ping_interval_server=GloMTH->get_variable_int((char *)"ping_interval_server");
	mysql_thread___ping_timeout_server=GloMTH->get_variable_int((char *)"ping_timeout_server");
	mysql_thread___shun_on_failures=GloMTH->get_variable_int((char *)"shun_on_failures");
	mysql_thread___shun_recovery_time=GloMTH->get_variable_int((char *)"shun_recovery_time");
	mysql_thread___connect_retries_on_failure=GloMTH->get_variable_int((char *)"connect_retries_on_failure");
	mysql_thread___connect_timeout_server=GloMTH->get_variable_int((char *)"connect_timeout_server");
	mysql_thread___connect_timeout_server_max=GloMTH->get_variable_int((char *)"connect_timeout_server_max");
	mysql_thread___free_connections_pct=GloMTH->get_variable_int((char *)"free_connections_pct");
	mysql_thread___connect_retries_delay=GloMTH->get_variable_int((char *)"connect_retries_delay");

	if (mysql_thread___monitor_username) free(mysql_thread___monitor_username);
	mysql_thread___monitor_username=GloMTH->get_variable_string((char *)"monitor_username");
	if (mysql_thread___monitor_password) free(mysql_thread___monitor_password);
	mysql_thread___monitor_password=GloMTH->get_variable_string((char *)"monitor_password");
	if (mysql_thread___monitor_query_variables) free(mysql_thread___monitor_query_variables);
	mysql_thread___monitor_query_variables=GloMTH->get_variable_string((char *)"monitor_query_variables");
	if (mysql_thread___monitor_query_status) free(mysql_thread___monitor_query_status);
	mysql_thread___monitor_query_status=GloMTH->get_variable_string((char *)"monitor_query_status");
	mysql_thread___monitor_timer_cached=(bool)GloMTH->get_variable_int((char *)"monitor_timer_cached");
	mysql_thread___monitor_history=GloMTH->get_variable_int((char *)"monitor_history");
	mysql_thread___monitor_connect_interval=GloMTH->get_variable_int((char *)"monitor_connect_interval");
	mysql_thread___monitor_connect_timeout=GloMTH->get_variable_int((char *)"monitor_connect_timeout");
	mysql_thread___monitor_ping_interval=GloMTH->get_variable_int((char *)"monitor_ping_interval");
	mysql_thread___monitor_ping_timeout=GloMTH->get_variable_int((char *)"monitor_ping_timeout");
	mysql_thread___monitor_replication_lag_interval=GloMTH->get_variable_int((char *)"monitor_replication_lag_interval");
	mysql_thread___monitor_replication_lag_timeout=GloMTH->get_variable_int((char *)"monitor_replication_lag_timeout");
	mysql_thread___monitor_query_interval=GloMTH->get_variable_int((char *)"monitor_query_interval");
	mysql_thread___monitor_query_timeout=GloMTH->get_variable_int((char *)"monitor_query_timeout");

	if (mysql_thread___server_version) free(mysql_thread___server_version);
	mysql_thread___server_version=GloMTH->get_variable_string((char *)"server_version");
	if (mysql_thread___default_schema) free(mysql_thread___default_schema);
	mysql_thread___default_schema=GloMTH->get_variable_string((char *)"default_schema");
	mysql_thread___server_capabilities=GloMTH->get_variable_uint16((char *)"server_capabilities");
	mysql_thread___default_charset=GloMTH->get_variable_uint8((char *)"default_charset");
	mysql_thread___poll_timeout=GloMTH->get_variable_int((char *)"poll_timeout");
	mysql_thread___poll_timeout_on_failure=GloMTH->get_variable_int((char *)"poll_timeout_on_failure");
	mysql_thread___have_compress=(bool)GloMTH->get_variable_int((char *)"have_compress");
	mysql_thread___commands_stats=(bool)GloMTH->get_variable_int((char *)"commands_stats");
	mysql_thread___query_digests=(bool)GloMTH->get_variable_int((char *)"query_digests");
	mysql_thread___sessions_sort=(bool)GloMTH->get_variable_int((char *)"sessions_sort");
	mysql_thread___servers_stats=(bool)GloMTH->get_variable_int((char *)"servers_stats");
	mysql_thread___default_reconnect=(bool)GloMTH->get_variable_int((char *)"default_reconnect");
#ifdef DEBUG
	mysql_thread___session_debug=(bool)GloMTH->get_variable_int((char *)"session_debug");
#endif /* DEBUG */
	GloMTH->wrunlock();
}

MySQL_Thread::MySQL_Thread() {
	spinlock_rwlock_init(&thread_mutex);
	mypolls.len=0;
	mypolls.size=0;
	mypolls.fds=NULL;
	mypolls.myds=NULL;
	my_idle_conns=NULL;
	//my_idle_myds=NULL;
	mysql_sessions=NULL;
	processing_idles=false;
	last_processing_idles=0;
	mysql_sessions_connections_handler=NULL;
	__thread_MySQL_Thread_Variables_version=0;
	mysql_thread___server_version=NULL;

	status_variables.queries=0;
	status_variables.queries_slow=0;
}


void MySQL_Thread::process_all_sessions_connections_handler() {
	unsigned int n;
	int rc;
	for (n=0; n<mysql_sessions_connections_handler->len; n++) {
		MySQL_Session *sess=(MySQL_Session *)mysql_sessions_connections_handler->index(n);
			//FIX_PING
		if (sess->to_process==1) {
			assert(sess->status!=NONE);
			rc=sess->handler();
			sess->to_process=0;
			if (rc==-1) {
				unregister_session_connection_handler(n, false);
				n--;
				delete sess;
				//sess=new MySQL_Session();
				//mysql_sessions_connections_handler->pdata[n]=sess;
				
			} else {
				sess->to_process=0;
			}
		}
	}
}

void MySQL_Thread::register_session_connection_handler(MySQL_Session *_sess, bool _new) {
	if (mysql_sessions_connections_handler==NULL) return;
	_sess->thread=this;
	_sess->connections_handler=true;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Registered new session for connection handler\n", _sess->thread, _sess);
	if (_new) {
		mysql_sessions->add(_sess);
	} else {
		mysql_sessions_connections_handler->add(_sess);
	}	
}

void MySQL_Thread::unregister_session_connection_handler(int idx, bool _new) {
	if (mysql_sessions_connections_handler==NULL) return;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Unregistered session\n", this, mysql_sessions_connections_handler->index(idx));
	if (_new) {
		mysql_sessions->remove_index_fast(idx);
	} else {
		mysql_sessions_connections_handler->remove_index_fast(idx);
	}
}


void MySQL_Thread::listener_handle_new_connection(MySQL_Data_Stream *myds, unsigned int n) {
	int c;
	struct sockaddr *addr=(struct sockaddr *)malloc(sizeof(struct sockaddr));
	socklen_t addrlen=sizeof(struct sockaddr);
	memset(addr, 0, sizeof(struct sockaddr));
	if (GloMTH->num_threads > 1) {
		// there are more than 1 thread . We pause for a little bit to avoid all connections to be handled by the same thread
		usleep(10+rand()%50);
	}
	c=accept(myds->fd, addr, &addrlen);
	if (c>-1) { // accept() succeeded
		// create a new client connection
		mypolls.fds[n].revents=0;
		MySQL_Session *sess=create_new_session_and_client_data_stream(c);
		//sess->myprot_client.generate_pkt_initial_handshake(sess->client_myds,true,NULL,NULL);
		//sess->myprot_client.generate_pkt_initial_handshake(true,NULL,NULL);
		__sync_add_and_fetch(&MyHGM->status.client_connections_created,1);
		if (__sync_add_and_fetch(&MyHGM->status.client_connections,1) > mysql_thread___max_connections) {
			sess->max_connections_reached=true;
		}
		sess->client_myds->client_addrlen=addrlen;
		sess->client_myds->client_addr=addr;
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
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping MySQL Global Status\n");
  SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"Variable_Name");
	result->add_column_definition(SQLITE_TEXT,"Variable_Value");
	// NOTE: as there is no string copy, we do NOT free pta[0] and pta[1]
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
	free(pta);
	return result;
}

SQLite3_result * MySQL_Threads_Handler::SQL3_Processlist() {
	const int colnum=14;
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
	signal_all_threads(1);
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
		spin_wrlock(&thr->thread_mutex);
	}
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
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
				if (sess->client_myds->client_addr->sa_family==AF_INET) {
					struct sockaddr_in * ipv4addr=(struct sockaddr_in *)sess->client_myds->client_addr;
					pta[4]=strdup(inet_ntoa(ipv4addr->sin_addr));
					sprintf(buf,"%d", htons(ipv4addr->sin_port));
					pta[5]=strdup(buf);
				} else {
					pta[4]=strdup("localhost");
					pta[5]=NULL;
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
						if (addr.sa_family==AF_INET) {
							struct sockaddr_in * ipv4addr=(struct sockaddr_in *)&addr;
							pta[7]=strdup(inet_ntoa(ipv4addr->sin_addr));
							sprintf(buf,"%d", htons(ipv4addr->sin_port));
							pta[8]=strdup(buf);
						} else {
							pta[7]=strdup("localhost");
							pta[8]=NULL;
						}
					} else {
						pta[7]=NULL;
						pta[8]=NULL;
					}

					sprintf(buf,"%s", mc->parent->address);
					pta[9]=strdup(buf);
					sprintf(buf,"%d", mc->parent->port);
					pta[10]=strdup(buf);
					if (mc->query.length) {
						pta[13]=(char *)malloc(mc->query.length+1);
						strncpy(pta[13],mc->query.ptr,mc->query.length);
						pta[13][mc->query.length]='\0';
					} else {
						pta[13]=NULL;
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
					default:
						sprintf(buf,"%d", sess->status);
						pta[11]=strdup(buf);
						break;
				}
				int idx=sess->client_myds->poll_fds_idx;
				unsigned long long last_sent=sess->thread->mypolls.last_sent[idx];
				unsigned long long last_recv=sess->thread->mypolls.last_recv[idx];
				unsigned long long last_time=(last_sent > last_recv ? last_sent : last_recv);
				sprintf(buf,"%llu", (sess->thread->curtime - last_time)/1000 );
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
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
		//if(thr!=sess->thread)
		spin_wrunlock(&thr->thread_mutex);
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
		write(fd,&c,1);
	}
}

bool MySQL_Threads_Handler::kill_session(uint32_t _thread_session_id) {
	bool ret=false;
	unsigned int i;
	signal_all_threads(1);
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
		spin_wrlock(&thr->thread_mutex);
	}
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
__exit_kill_session:
	for (i=0;i<num_threads;i++) {
		MySQL_Thread *thr=(MySQL_Thread *)mysql_threads[i].worker;
		spin_wrunlock(&thr->thread_mutex);
	}
	return ret;
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
