#ifndef __CLASS_MYSQL_THREAD_H
#define __CLASS_MYSQL_THREAD_H
#define ____CLASS_STANDARD_MYSQL_THREAD_H
#include "proxysql.h"
#include "cpp.h"
#ifdef IDLE_THREADS
#include <sys/epoll.h>
#endif // IDLE_THREADS
#include <atomic>

#define MIN_POLL_LEN 8
#define MIN_POLL_DELETE_RATIO  8
#define MY_EPOLL_THREAD_MAXEVENTS 128

#define ADMIN_HOSTGROUP	-2
#define STATS_HOSTGROUP	-3
#define SQLITE_HOSTGROUP -4


#define MYSQL_DEFAULT_TX_ISOLATION	"READ-COMMITTED"
#define MYSQL_DEFAULT_COLLATION_CONNECTION	""
#define MYSQL_DEFAULT_NET_WRITE_TIMEOUT	"60"
#define MYSQL_DEFAULT_MAX_JOIN_SIZE	"18446744073709551615"

#ifdef IDLE_THREADS
typedef struct __attribute__((aligned(64))) _conn_exchange_t {
	pthread_mutex_t mutex_idles;
	PtrArray *idle_mysql_sessions;
	pthread_mutex_t mutex_resumes;
	PtrArray *resume_mysql_sessions;
} conn_exchange_t;
#endif // IDLE_THREADS

typedef struct _thr_id_username_t {
	uint32_t id;
	char *username;
} thr_id_usr;

typedef struct _kill_queue_t {
	pthread_mutex_t m;
	std::vector<thr_id_usr *> conn_ids;
	std::vector<thr_id_usr *> query_ids;
} kill_queue_t;

class ProxySQL_Poll {
	private:
	void shrink();
	void expand(unsigned int more);

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

	ProxySQL_Poll();
	~ProxySQL_Poll();
	void add(uint32_t _events, int _fd, MySQL_Data_Stream *_myds, unsigned long long sent_time);
	void remove_index_fast(unsigned int i);
	int find_index(int fd);
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
	std::atomic<unsigned long long> atomic_curtime;
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
	kill_queue_t kq;

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
		unsigned long long queries_gtid;
		unsigned long long queries_with_max_lag_ms;
		unsigned long long queries_with_max_lag_ms__delayed;
		unsigned long long queries_with_max_lag_ms__total_wait_time_us;
		unsigned long long queries_backends_bytes_sent;
		unsigned long long queries_backends_bytes_recv;
		unsigned long long queries_frontends_bytes_sent;
		unsigned long long queries_frontends_bytes_recv;
		unsigned long long query_processor_time;
		unsigned long long backend_query_time;
		unsigned long long mysql_backend_buffers_bytes;
		unsigned long long mysql_frontend_buffers_bytes;
		unsigned long long mysql_session_internal_bytes;
		unsigned long long ConnPool_get_conn_immediate;
		unsigned long long ConnPool_get_conn_success;
		unsigned long long ConnPool_get_conn_failure;
		unsigned long long ConnPool_get_conn_latency_awareness;
		unsigned long long gtid_binlog_collected;
		unsigned long long gtid_session_collected;
		unsigned long long generated_pkt_err;
		unsigned long long max_connect_timeout_err;
		unsigned long long backend_lagging_during_query;
		unsigned long long backend_offline_during_query;
		unsigned long long unexpected_com_quit;
		unsigned long long unexpected_packet;
		unsigned long long killed_connections;
		unsigned long long killed_queries;
		unsigned long long hostgroup_locked;
		unsigned long long hostgroup_locked_set_cmds;
		unsigned long long hostgroup_locked_queries;
		unsigned long long aws_aurora_replicas_skipped_during_query;
		unsigned long long automatic_detected_sqli;
		unsigned long long whitelisted_sqli_fingerprint;
		unsigned int active_transactions;
	} status_variables;

	struct {
		int min_num_servers_lantency_awareness;
		int aurora_max_lag_ms_only_read_from_replicas;
		bool stats_time_backend_query;
		bool stats_time_query_processor;
		bool query_cache_stores_empty_result;
	} variables;

  pthread_mutex_t thread_mutex;
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
	MySQL_Connection * get_MyConn_local(unsigned int, MySQL_Session *sess, char *gtid_uuid, uint64_t gtid_trxid, int max_lag_ms);
	void push_MyConn_local(MySQL_Connection *);
	void return_local_connections();
	void Scan_Sessions_to_Kill(PtrArray *mysess);
	void Scan_Sessions_to_Kill_All();
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
	pthread_rwlock_t rwlock;
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
		int monitor_read_only_max_timeout_count;
		bool monitor_enabled;
		bool monitor_wait_timeout;
		bool monitor_writer_is_also_reader;
		int monitor_replication_lag_interval;
		int monitor_replication_lag_timeout;
		int monitor_groupreplication_healthcheck_interval;
		int monitor_groupreplication_healthcheck_timeout;
		int monitor_groupreplication_healthcheck_max_timeout_count;
		int monitor_groupreplication_max_transactions_behind_count;
		int monitor_galera_healthcheck_interval;
		int monitor_galera_healthcheck_timeout;
		int monitor_galera_healthcheck_max_timeout_count;
		int monitor_query_interval;
		int monitor_query_timeout;
		int monitor_slave_lag_when_null;
		int monitor_threads_min;
		int monitor_threads_max;
		int monitor_threads_queue_maxsize;
		char *monitor_username;
		char *monitor_password;
		char * monitor_replication_lag_use_percona_heartbeat;
		int ping_interval_server_msec;
		int ping_timeout_server;
		int shun_on_failures;
		int shun_recovery_time_sec;
		int query_retries_on_failure;
		bool client_multi_statements;
		int connect_retries_on_failure;
		int connect_retries_delay;
		int connection_delay_multiplex_ms;
		int connection_max_age_ms;
		int connect_timeout_server;
		int connect_timeout_server_max;
		int free_connections_pct;
		int show_processlist_extended;
#ifdef IDLE_THREADS
		int session_idle_ms;
		bool session_idle_show_processlist;
#endif // IDLE_THREADS
		bool sessions_sort;
		char *default_schema;
		char *interfaces;
		char *server_version;
		char *keep_multiplexing_variables;
		unsigned int default_charset;
		unsigned int handle_unknown_charset;
		bool servers_stats;
		bool commands_stats;
		bool query_digests;
		bool query_digests_lowercase;
		bool query_digests_replace_null;
		bool query_digests_no_digits;
		bool query_digests_normalize_digest_text;
		bool query_digests_track_hostname;
		bool default_reconnect;
		bool have_compress;
		bool have_ssl;
		bool client_found_rows;
		bool multiplexing;
//		bool stmt_multiplexing;
		bool log_unhealthy_connections;
		bool forward_autocommit;
		bool enforce_autocommit_on_reads;
		bool autocommit_false_not_reusable;
		bool autocommit_false_is_transaction;
		bool verbose_query_error;
		int max_allowed_packet;
		bool automatic_detect_sqli;
		bool firewall_whitelist_enabled;
		bool use_tcp_keepalive;
		int tcp_keepalive_time;
		int throttle_connections_per_sec_to_hostgroup;
		int max_transaction_time;
		int threshold_query_length;
		int threshold_resultset_size;
		int query_digests_max_digest_length;
		int query_digests_max_query_length;
		int wait_timeout;
		int throttle_max_bytes_per_second_to_client;
		int throttle_ratio_server_to_client;
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
		int set_query_lock_on_hostgroup;
		int reset_connection_algorithm;
		int auto_increment_delay_multiplex;
		int long_query_time;
		int hostgroup_manager_verbose;
		int binlog_reader_connect_retry_msec;
		char *init_connect;
		char *ldap_user_variable;
		char *add_ldap_user_comment;
		char *default_tx_isolation;
		char *default_variables[SQL_NAME_LAST];
		char *firewall_whitelist_errormsg;
#ifdef DEBUG
		bool session_debug;
#endif /* DEBUG */
		uint32_t server_capabilities;
		int poll_timeout;
		int poll_timeout_on_failure;
		int connpoll_reset_queue_length;
		char *eventslog_filename;
		int eventslog_filesize;
		int eventslog_default_log;
		int eventslog_format;
		char *auditlog_filename;
		int auditlog_filesize;
		// SSL related, proxy to server
		char * ssl_p2s_ca;
		char * ssl_p2s_cert;
		char * ssl_p2s_key;
		char * ssl_p2s_cipher;
		int query_cache_size_MB;
		int min_num_servers_lantency_awareness;
		int aurora_max_lag_ms_only_read_from_replicas;
		bool stats_time_backend_query;
		bool stats_time_query_processor;
		bool query_cache_stores_empty_result;
		bool kill_backend_connection_when_disconnect;
		bool client_session_track_gtid;
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
	unsigned int get_variable_uint(char *name);
	uint16_t get_variable_uint16(char *name);
	int get_variable_int(const char *name);
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
	SQLite3_result * SQL3_GlobalStatus(bool _memory);
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
	unsigned long long get_gtid_queries();
	unsigned long long get_gtid_session_collected();
	unsigned long long get_queries_backends_bytes_recv();
	unsigned long long get_queries_backends_bytes_sent();
	unsigned long long get_queries_frontends_bytes_recv();
	unsigned long long get_queries_frontends_bytes_sent();
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
	unsigned long long get_ConnPool_get_conn_latency_awareness();
	unsigned long long get_generated_pkt_err();
	unsigned long long get_max_connect_timeout();
	unsigned long long get_unexpected_com_quit();
	unsigned long long get_unexpected_packet();
	unsigned long long get_hostgroup_locked();
	unsigned long long get_hostgroup_locked_set_cmds();
	unsigned long long get_hostgroup_locked_queries();
	unsigned long long get_aws_aurora_replicas_skipped_during_query();
	unsigned long long get_automatic_detected_sqli();
	unsigned long long get_whitelisted_sqli_fingerprint();
	unsigned long long get_backend_lagging_during_query();
	unsigned long long get_backend_offline_during_query();
	unsigned long long get_queries_with_max_lag_ms();
	unsigned long long get_queries_with_max_lag_ms__delayed();
	unsigned long long get_queries_with_max_lag_ms__total_wait_time_us();
	unsigned long long get_killed_connections();
	unsigned long long get_killed_queries();
	iface_info *MLM_find_iface_from_fd(int fd) {
		return MLM->find_iface_from_fd(fd);
	}
	void Get_Memory_Stats();
	void kill_connection_or_query(uint32_t _thread_session_id, bool query, char *username);
};


#endif /* __CLASS_MYSQL_THREAD_H */
