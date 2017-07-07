#ifndef __CLASS_MYSQL_THREAD_H
#define __CLASS_MYSQL_THREAD_H
#define ____CLASS_STANDARD_MYSQL_THREAD_H
#include "proxysql.h"
#include "cpp.h"
#ifdef IDLE_THREADS
#include <sys/epoll.h>
#endif // IDLE_THREADS

#define MIN_POLL_LEN 8
#define MIN_POLL_DELETE_RATIO  8
#define MY_EPOLL_THREAD_MAXEVENTS 128

#define ADMIN_HOSTGROUP	-2
#define STATS_HOSTGROUP	-3
#define SQLITE_HOSTGROUP -4


#define MYSQL_DEFAULT_SQL_MODE	""
#define MYSQL_DEFAULT_TIME_ZONE	"SYSTEM"

#define PROXYSQL_MYSQL_PTHREAD_MUTEX

static unsigned int near_pow_2 (unsigned int n) {
  unsigned int i = 1;
  while (i < n) i <<= 1;
  return i ? i : n;
}

#ifdef IDLE_THREADS
typedef struct __attribute__((aligned(CACHE_LINE_SIZE))) _conn_exchange_t {
	pthread_mutex_t mutex_idles;
	PtrArray *idle_mysql_sessions;
	pthread_mutex_t mutex_resumes;
	PtrArray *resume_mysql_sessions;
} conn_exchange_t;
#endif // IDLE_THREADS

class ProxySQL_Poll {

  private:
  void shrink() {
    unsigned int new_size=near_pow_2(len+1);
    fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
    myds=(MySQL_Data_Stream **)realloc(myds,new_size*sizeof(MySQL_Data_Stream *));
		last_recv=(unsigned long long *)realloc(last_recv,new_size*sizeof(unsigned long long));
		last_sent=(unsigned long long *)realloc(last_sent,new_size*sizeof(unsigned long long));
    size=new_size;
  };
  void expand(unsigned int more) {
    if ( (len+more) > size ) {
      unsigned int new_size=near_pow_2(len+more);
      fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
      myds=(MySQL_Data_Stream **)realloc(myds,new_size*sizeof(MySQL_Data_Stream *));
			last_recv=(unsigned long long *)realloc(last_recv,new_size*sizeof(unsigned long long));
			last_sent=(unsigned long long *)realloc(last_sent,new_size*sizeof(unsigned long long));
      size=new_size;
    }
  };

  public:
	unsigned int poll_timeout;
	unsigned long loops;
	StatCounters *loop_counters;
  unsigned int len;
  unsigned int size;
  struct pollfd *fds;
  MySQL_Data_Stream **myds;
	unsigned long long *last_recv;
	unsigned long long *last_sent;
	volatile int pending_listener_add;
	volatile int pending_listener_del;

  ProxySQL_Poll() {
#ifdef PROXYSQL_STATSCOUNTERS_NOLOCK
		loop_counters=new StatCounters(15,10);
#else
		loop_counters=new StatCounters(15,10,false);
#endif
		poll_timeout=0;
		loops=0;
		len=0;
		pending_listener_add=0;
		pending_listener_del=0;
    size=MIN_POLL_LEN;
    fds=(struct pollfd *)malloc(size*sizeof(struct pollfd));
    myds=(MySQL_Data_Stream **)malloc(size*sizeof(MySQL_Data_Stream *));
		last_recv=(unsigned long long *)malloc(size*sizeof(unsigned long long));
		last_sent=(unsigned long long *)malloc(size*sizeof(unsigned long long));
  };

  ~ProxySQL_Poll() {
    unsigned int i;
    for (i=0;i<len;i++) {
      if (
				myds[i] && // fix bug #278 . This should be caused by not initialized datastreams used to ping the backend
				myds[i]->myds_type==MYDS_LISTENER) {
        delete myds[i];
      }
    }
    free(myds);
    free(fds);
		free(last_recv);
		free(last_sent);
		delete loop_counters;
  };

  void add(uint32_t _events, int _fd, MySQL_Data_Stream *_myds, unsigned long long sent_time) {
    if (len==size) {
      expand(1);
    }
    myds[len]=_myds;
    fds[len].fd=_fd;
    fds[len].events=_events;
    fds[len].revents=0;
		if (_myds) {
			_myds->mypolls=this;
			_myds->poll_fds_idx=len;  // fix a serious bug
		}
    last_recv[len]=monotonic_time();
    last_sent[len]=sent_time;
    len++;
  };

  void remove_index_fast(unsigned int i) {
		if ((int)i==-1) return;
		myds[i]->poll_fds_idx=-1; // this prevents further delete
    if (i != (len-1)) {
      myds[i]=myds[len-1];
      fds[i].fd=fds[len-1].fd;
      fds[i].events=fds[len-1].events;
      fds[i].revents=fds[len-1].revents;
			myds[i]->poll_fds_idx=i;  // fix a serious bug
    	last_recv[i]=last_recv[len-1];
    	last_sent[i]=last_sent[len-1];
    }
    len--;
    if ( ( len>MIN_POLL_LEN ) && ( size > len*MIN_POLL_DELETE_RATIO ) ) {
      shrink();
    }
  };  

	int find_index(int fd) {
		unsigned int i;
		for (i=0; i<len; i++) {
			if (fds[i].fd==fd) {
				return i;
			}
		}
		return -1;
	}

};


class MySQL_Thread
{
	private:
	unsigned int servers_table_version_previous;
	unsigned int servers_table_version_current;
  unsigned long long last_processing_idles;
	MySQL_Connection **my_idle_conns;
  bool processing_idles;
	bool maintenance_loop;

	PtrArray *cached_connections;

#ifdef IDLE_THREADS
	struct epoll_event events[MY_EPOLL_THREAD_MAXEVENTS];
	int efd;
	unsigned int mysess_idx;
	std::map<unsigned int, unsigned int> sessmap;
#endif // IDLE_THREADS

	Session_Regex **match_regexes;

	protected:
	int nfds;

	public:

	void *gen_args;	// this is a generic pointer to create any sort of structure

	ProxySQL_Poll mypolls;
	pthread_t thread_id;
	unsigned long long curtime;
	unsigned long long pre_poll_time;
	unsigned long long last_maintenance_time;
	PtrArray *mysql_sessions;
	PtrArray *mirror_queue_mysql_sessions;
	PtrArray *mirror_queue_mysql_sessions_cache;
#ifdef IDLE_THREADS
	PtrArray *idle_mysql_sessions;
	PtrArray *resume_mysql_sessions;

	conn_exchange_t myexchange;
#endif // IDLE_THREADS

	int pipefd[2];
	int shutdown;

	bool epoll_thread;
	bool poll_timeout_bool;

	// status variables are per thread only
	// in this way, there is no need for atomic operation and there is no cache miss
	// when it is needed a total, all threads are checked
	struct {
		unsigned long long backend_stmt_prepare;
		unsigned long long backend_stmt_execute;
		unsigned long long backend_stmt_close;
		unsigned long long frontend_stmt_prepare;
		unsigned long long frontend_stmt_execute;
		unsigned long long frontend_stmt_close;
		unsigned long long queries;
		unsigned long long queries_slow;
		unsigned long long queries_backends_bytes_sent;
		unsigned long long queries_backends_bytes_recv;
		unsigned long long query_processor_time;
		unsigned long long backend_query_time;
		unsigned long long mysql_backend_buffers_bytes;
		unsigned long long mysql_frontend_buffers_bytes;
		unsigned long long mysql_session_internal_bytes;
		unsigned long long ConnPool_get_conn_immediate;
		unsigned long long ConnPool_get_conn_success;
		unsigned long long ConnPool_get_conn_failure;
		unsigned int active_transactions;
	} status_variables;


#ifdef PROXYSQL_MYSQL_PTHREAD_MUTEX
  pthread_mutex_t thread_mutex;
#else
  rwlock_t thread_mutex;
#endif
  MySQL_Thread();
  ~MySQL_Thread();
  MySQL_Session * create_new_session_and_client_data_stream(int _fd);
  bool init();
  void run();
  void poll_listener_add(int sock);
  void poll_listener_del(int sock);
  void register_session(MySQL_Session*, bool up_start=true);
  void unregister_session(int);
  struct pollfd * get_pollfd(unsigned int i);
  bool process_data_on_data_stream(MySQL_Data_Stream *myds, unsigned int n);
  void process_all_sessions();
  void refresh_variables();
  void register_session_connection_handler(MySQL_Session *_sess, bool _new=false);
  void unregister_session_connection_handler(int idx, bool _new=false);
  void listener_handle_new_connection(MySQL_Data_Stream *myds, unsigned int n);
	void Get_Memory_Stats();
	MySQL_Connection * get_MyConn_local(unsigned int);
	void push_MyConn_local(MySQL_Connection *);
	void return_local_connections();
};


typedef MySQL_Thread * create_MySQL_Thread_t();
typedef void destroy_MySQL_Thread_t(MySQL_Thread *);

class iface_info {
	public:
	char *iface;
	char *address;
	int port;
	int fd;
	iface_info(char *_i, char *_a, int p, int f) {
		iface=strdup(_i);
		address=strdup(_a);
		port=p;
		fd=f;
	}
	~iface_info() {
		free(iface);
		free(address);
		close(fd);
	}
};

class MySQL_Listeners_Manager {
	private:
	PtrArray *ifaces;
	public:
  MySQL_Listeners_Manager();
	~MySQL_Listeners_Manager();
	int add(const char *iface, unsigned int num_threads, int **perthrsocks);
	int find_idx(const char *iface);
	int find_idx(const char *address, int port);
	iface_info * find_iface_from_fd(int fd);
	int get_fd(unsigned int idx);
	void del(unsigned int idx);
};

class MySQL_Threads_Handler
{
	private:
	int shutdown_;
	size_t stacksize;
	pthread_attr_t attr;
#ifdef PROXYSQL_MYSQL_PTHREAD_MUTEX
	pthread_rwlock_t rwlock;
#else
	rwlock_t rwlock;
#endif
	PtrArray *bind_fds;
	MySQL_Listeners_Manager *MLM;
	public:
	struct {
		int monitor_history;
		int monitor_connect_interval;
		int monitor_connect_timeout;
		int monitor_ping_interval;
		int monitor_ping_max_failures;
		int monitor_ping_timeout;
		int monitor_read_only_interval;
		int monitor_read_only_timeout;
		bool monitor_enabled;
		bool monitor_wait_timeout;
		bool monitor_writer_is_also_reader;
		int monitor_replication_lag_interval;
		int monitor_replication_lag_timeout;
		int monitor_groupreplication_healthcheck_interval;
		int monitor_groupreplication_healthcheck_timeout;
		int monitor_query_interval;
		int monitor_query_timeout;
		int monitor_slave_lag_when_null;
		char *monitor_username;
		char *monitor_password;
		int ping_interval_server_msec;
		int ping_timeout_server;
		int shun_on_failures;
		int shun_recovery_time_sec;
		int query_retries_on_failure;
		int connect_retries_on_failure;
		int connect_retries_delay;
		int connection_delay_multiplex_ms;
		int connection_max_age_ms;
		int connect_timeout_server;
		int connect_timeout_server_max;
		int free_connections_pct;
#ifdef IDLE_THREADS
		int session_idle_ms;
		bool session_idle_show_processlist;
#endif // IDLE_THREADS
		bool sessions_sort;
		char *default_schema;
		char *interfaces;
		char *server_version;
		uint8_t default_charset;
		bool servers_stats;
		bool commands_stats;
		bool query_digests;
		bool query_digests_lowercase;
		bool default_reconnect;
		bool have_compress;
		bool client_found_rows;
		bool multiplexing;
//		bool stmt_multiplexing;
		bool forward_autocommit;
		bool enforce_autocommit_on_reads;
		bool autocommit_false_not_reusable;
		int max_allowed_packet;
		int max_transaction_time;
		int threshold_query_length;
		int threshold_resultset_size;
		int query_digests_max_digest_length;
		int query_digests_max_query_length;
		int wait_timeout;
		int max_connections;
		int max_stmts_per_connection;
		int max_stmts_cache;
		int mirror_max_concurrency;
		int mirror_max_queue_length;
		int default_max_latency_ms;
		int default_query_delay;
		int default_query_timeout;
		int query_processor_iterations;
		int query_processor_regex;
		int long_query_time;
		int hostgroup_manager_verbose;
		char *init_connect;
		char *default_sql_mode;
		char *default_time_zone;
#ifdef DEBUG
		bool session_debug;
#endif /* DEBUG */
		uint16_t server_capabilities;
		int poll_timeout;
		int poll_timeout_on_failure;
		char *eventslog_filename;
		int eventslog_filesize;
		// SSL related, proxy to server
		char * ssl_p2s_ca;
		char * ssl_p2s_cert;
		char * ssl_p2s_key;
		char * ssl_p2s_cipher;
		int query_cache_size_MB;
	} variables;
	struct {
		unsigned int mirror_sessions_current;
	} status_variables;
	unsigned int num_threads;
	proxysql_mysql_thread_t *mysql_threads;
#ifdef IDLE_THREADS
	proxysql_mysql_thread_t *mysql_threads_idles;
#endif // IDLE_THREADS
	unsigned int get_global_version();
	void wrlock();
 	void wrunlock();
	void commit();
	char *get_variable(char *name);
	bool set_variable(char *name, char *value);
	char **get_variables_list();
	bool has_variable(const char * name);

	MySQL_Threads_Handler();
	~MySQL_Threads_Handler();
	
	char *get_variable_string(char *name);
	uint8_t get_variable_uint8(char *name);
	uint16_t get_variable_uint16(char *name);
	int get_variable_int(char *name);
	void print_version();
	void init(unsigned int num=0, size_t stack=0);
	proxysql_mysql_thread_t *create_thread(unsigned int tn, void *(*start_routine) (void *), bool);
	void shutdown_threads();
	int listener_add(const char *iface);
	int listener_add(const char *address, int port);
	int listener_del(const char *iface);
	int listener_del(const char *address, int port);
	void start_listeners();
	void stop_listeners();
	void signal_all_threads(unsigned char _c=0);
	SQLite3_result * SQL3_Processlist();
	SQLite3_result * SQL3_GlobalStatus();
	bool kill_session(uint32_t _thread_session_id);
	unsigned long long get_total_mirror_queue();
	unsigned long long get_total_backend_stmt_prepare();
	unsigned long long get_total_backend_stmt_execute();
	unsigned long long get_total_backend_stmt_close();
	unsigned long long get_total_frontend_stmt_prepare();
	unsigned long long get_total_frontend_stmt_execute();
	unsigned long long get_total_frontend_stmt_close();
	unsigned long long get_total_queries();
	unsigned long long get_slow_queries();
	unsigned long long get_queries_backends_bytes_recv();
	unsigned long long get_queries_backends_bytes_sent();
	unsigned int get_active_transations();
#ifdef IDLE_THREADS
	unsigned int get_non_idle_client_connections();
#endif // IDLE_THREADS
	unsigned long long get_query_processor_time();
	unsigned long long get_backend_query_time();
	unsigned long long get_mysql_backend_buffers_bytes();
	unsigned long long get_mysql_frontend_buffers_bytes();
	unsigned long long get_mysql_session_internal_bytes();
	unsigned long long get_ConnPool_get_conn_immediate();
	unsigned long long get_ConnPool_get_conn_success();
	unsigned long long get_ConnPool_get_conn_failure();
	iface_info *MLM_find_iface_from_fd(int fd) {
		return MLM->find_iface_from_fd(fd);
	}
	void Get_Memory_Stats();
};


#endif /* __CLASS_MYSQL_THREAD_H */
