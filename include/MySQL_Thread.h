#ifndef __CLASS_MYSQL_THREAD_H
#define __CLASS_MYSQL_THREAD_H
#define ____CLASS_STANDARD_MYSQL_THREAD_H
#include "prometheus/counter.h"
#include "prometheus/gauge.h"

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Variables.h"
#ifdef IDLE_THREADS
#include <sys/epoll.h>
#endif // IDLE_THREADS
#include <atomic>

#include "prometheus_helpers.h"

#include "set_parser.h"

/*
#define MIN_POLL_LEN 8
#define MIN_POLL_DELETE_RATIO  8
#define MY_EPOLL_THREAD_MAXEVENTS 128
*/

#define ADMIN_HOSTGROUP	-2
#define STATS_HOSTGROUP	-3
#define SQLITE_HOSTGROUP -4


#define MYSQL_DEFAULT_SESSION_TRACK_GTIDS      "OFF"
#define MYSQL_DEFAULT_COLLATION_CONNECTION	""
#define MYSQL_DEFAULT_NET_WRITE_TIMEOUT	"60"
#define MYSQL_DEFAULT_MAX_JOIN_SIZE	"18446744073709551615"

extern class MySQL_Variables mysql_variables;

#ifdef IDLE_THREADS
typedef struct __attribute__((aligned(64))) _conn_exchange_t {
	pthread_mutex_t mutex_idles;
	PtrArray *idle_mysql_sessions;
	pthread_mutex_t mutex_resumes;
	PtrArray *resume_mysql_sessions;
} conn_exchange_t;
#endif // IDLE_THREADS

enum MySQL_Thread_status_variable {
	st_var_backend_stmt_prepare,
	st_var_backend_stmt_execute,
	st_var_backend_stmt_close,
	st_var_frontend_stmt_prepare,
	st_var_frontend_stmt_execute,
	st_var_frontend_stmt_close,
	st_var_queries,
	st_var_queries_slow,
	st_var_queries_gtid,
	st_var_queries_with_max_lag_ms,
	st_var_queries_with_max_lag_ms__delayed,
	st_var_queries_with_max_lag_ms__total_wait_time_us,
	st_var_queries_backends_bytes_sent,
	st_var_queries_backends_bytes_recv,
	st_var_queries_frontends_bytes_sent,
	st_var_queries_frontends_bytes_recv,
	st_var_query_processor_time,
	st_var_backend_query_time,
	st_var_mysql_backend_buffers_bytes,
	st_var_mysql_frontend_buffers_bytes,
	st_var_mysql_session_internal_bytes,
	st_var_ConnPool_get_conn_immediate,
	st_var_ConnPool_get_conn_success,
	st_var_ConnPool_get_conn_failure,
	st_var_ConnPool_get_conn_latency_awareness,
	st_var_gtid_binlog_collected,
	st_var_gtid_session_collected,
	st_var_generated_pkt_err,
	st_var_max_connect_timeout_err,
	st_var_backend_lagging_during_query,
	st_var_backend_offline_during_query,
	st_var_unexpected_com_quit,
	st_var_unexpected_packet,
	st_var_killed_connections,
	st_var_killed_queries,
	st_var_hostgroup_locked,
	st_var_hostgroup_locked_set_cmds,
	st_var_hostgroup_locked_queries,
	st_var_aws_aurora_replicas_skipped_during_query,
	st_var_automatic_detected_sqli,
	st_var_mysql_whitelisted_sqli_fingerprint,
	st_var_client_host_error_killed_connections,
	MY_st_var_END
};

class __attribute__((aligned(64))) MySQL_Thread : public Base_Thread
{
	friend class PgSQL_Thread;
	private:
	unsigned int servers_table_version_previous;
	unsigned int servers_table_version_current;
  unsigned long long last_processing_idles;
	MySQL_Connection **my_idle_conns;
  bool processing_idles;
	//bool maintenance_loop;
	bool retrieve_gtids_required; // if any of the servers has gtid_port enabled, this needs to be turned on too

	PtrArray *cached_connections;

#ifdef IDLE_THREADS
	struct epoll_event events[MY_EPOLL_THREAD_MAXEVENTS];
	int efd;
	unsigned int mysess_idx;
	std::map<unsigned int, unsigned int> sessmap;
#endif // IDLE_THREADS

	//Session_Regex **match_regexes;

#ifdef IDLE_THREADS
	void worker_thread_assigns_sessions_to_idle_thread(MySQL_Thread *thr);
	void worker_thread_gets_sessions_from_idle_thread();
	void idle_thread_gets_sessions_from_worker_thread();
	void idle_thread_assigns_sessions_to_worker_thread(MySQL_Thread *thr);
	void idle_thread_check_if_worker_thread_has_unprocess_resumed_sessions_and_signal_it(MySQL_Thread *thr);
	void idle_thread_prepares_session_to_send_to_worker_thread(int i);
	void idle_thread_to_kill_idle_sessions();
	//bool move_session_to_idle_mysql_sessions(MySQL_Data_Stream *myds, unsigned int n);
	void run_Handle_epoll_wait(int);
#endif // IDLE_THREADS

	//unsigned int find_session_idx_in_mysql_sessions(MySQL_Session *sess);
	//bool set_backend_to_be_skipped_if_frontend_is_slow(MySQL_Data_Stream *myds, unsigned int n);
	void handle_mirror_queue_mysql_sessions();
	void handle_kill_queues();
	//void check_timing_out_session(unsigned int n);
	//void check_for_invalid_fd(unsigned int n);
	//void read_one_byte_from_pipe(unsigned int n);
	//void tune_timeout_for_myds_needs_pause(MySQL_Data_Stream *myds);
	//void tune_timeout_for_session_needs_pause(MySQL_Data_Stream *myds);
	//void configure_pollout(MySQL_Data_Stream *myds, unsigned int n);

	void run_MoveSessionsBetweenThreads();
	void run_BootstrapListener();
	int run_ComputePollTimeout();
	void run_StopListener();
	//void run_SetAllSession_ToProcess0();


	protected:
	int nfds;

	public:

	void *gen_args;	// this is a generic pointer to create any sort of structure

	ProxySQL_Poll<MySQL_Data_Stream> mypolls;
	pthread_t thread_id;
//	unsigned long long curtime;
	unsigned long long pre_poll_time;
	unsigned long long last_maintenance_time;
	//unsigned long long last_move_to_idle_thread_time;
	std::atomic<unsigned long long> atomic_curtime;
	//PtrArray *mysql_sessions;
	PtrArray *mirror_queue_mysql_sessions;
	PtrArray *mirror_queue_mysql_sessions_cache;
#ifdef IDLE_THREADS
	PtrArray *idle_mysql_sessions;
	PtrArray *resume_mysql_sessions;

	conn_exchange_t myexchange;
#endif // IDLE_THREADS

	int pipefd[2];
//	int shutdown;
	kill_queue_t kq;

	//bool epoll_thread;
	bool poll_timeout_bool;

	// status variables are per thread only
	// in this way, there is no need for atomic operation and there is no cache miss
	// when it is needed a total, all threads are checked
	struct {
		unsigned long long stvar[MY_st_var_END];
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

	// if set_parser_algorithm == 2 , a single thr_SetParser is used
	SetParser *thr_SetParser;

	MySQL_Thread();
	~MySQL_Thread();
	//MySQL_Session * create_new_session_and_client_data_stream(int _fd);
	bool init();
	void run___get_multiple_idle_connections(int& num_idles);
	void run___cleanup_mirror_queue();
  	//void ProcessAllMyDS_BeforePoll();
  	//void ProcessAllMyDS_AfterPoll();
	void run();
  void poll_listener_add(int sock);
  void poll_listener_del(int sock);
  //void register_session(MySQL_Session *, bool up_start=true);
  void unregister_session(int);
  struct pollfd * get_pollfd(unsigned int i);
  bool process_data_on_data_stream(MySQL_Data_Stream *myds, unsigned int n);
	//void ProcessAllSessions_SortingSessions();
	void ProcessAllSessions_CompletedMirrorSession(unsigned int& n, MySQL_Session *sess);
	void ProcessAllSessions_MaintenanceLoop(MySQL_Session *sess, unsigned long long sess_time, unsigned int& total_active_transactions_);
	void ProcessAllSessions_Healthy0(MySQL_Session *sess, unsigned int& n);
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

struct p_th_counter {
	enum metric {
		queries_backends_bytes_sent = 0,
		queries_backends_bytes_recv,
		queries_frontends_bytes_sent,
		queries_frontends_bytes_recv,
		query_processor_time_nsec,
		backend_query_time_nsec,
		com_backend_stmt_prepare,
		com_backend_stmt_execute,
		com_backend_stmt_close,
		com_frontend_stmt_prepare,
		com_frontend_stmt_execute,
		com_frontend_stmt_close,
		questions,
		slow_queries,
		gtid_consistent_queries,
		gtid_session_collected,
		connpool_get_conn_latency_awareness,
		connpool_get_conn_immediate,
		connpool_get_conn_success,
		connpool_get_conn_failure,
		generated_error_packets,
		max_connect_timeouts,
		backend_lagging_during_query,
		backend_offline_during_query,
		queries_with_max_lag_ms,
		queries_with_max_lag_ms__delayed,
		queries_with_max_lag_ms__total_wait_time_us,
		mysql_unexpected_frontend_com_quit,
		hostgroup_locked_set_cmds,
		hostgroup_locked_queries,
		mysql_unexpected_frontend_packets,
		aws_aurora_replicas_skipped_during_query,
		automatic_detected_sql_injection,
		mysql_whitelisted_sqli_fingerprint,
		mysql_killed_backend_connections,
		mysql_killed_backend_queries,
		client_host_error_killed_connections,
		__size
	};
};

struct p_th_gauge {
	enum metric {
		active_transactions = 0,
		client_connections_non_idle,
		client_connections_hostgroup_locked,
		mysql_backend_buffers_bytes,
		mysql_frontend_buffers_bytes,
		mysql_session_internal_bytes,
		mirror_concurrency,
		mirror_queue_lengths,
		mysql_thread_workers,
		// global_variables
		mysql_wait_timeout,
		mysql_max_connections,
		mysql_monitor_enabled,
		mysql_monitor_ping_interval,
		mysql_monitor_ping_timeout,
		mysql_monitor_ping_max_failures,
		mysql_monitor_aws_rds_topology_discovery_interval,
		mysql_monitor_read_only_interval,
		mysql_monitor_read_only_timeout,
		mysql_monitor_writer_is_also_reader,
		mysql_monitor_replication_lag_group_by_host,
		mysql_monitor_replication_lag_interval,
		mysql_monitor_replication_lag_timeout,
		mysql_monitor_history,
		__size
	};
};

struct th_metrics_map_idx {
	enum index {
		counters = 0,
		gauges
	};
};

/**
 * @brief Structure holding the data for a Client_Host_Cache entry.
 */
typedef struct _MySQL_Client_Host_Cache_Entry {
	/**
	 * @brief Last time the entry was updated.
	 */
	uint64_t updated_at;
	/**
	 * @brief Error count associated with the entry.
	 */
	uint32_t error_count;
} MySQL_Client_Host_Cache_Entry;

class MySQL_Threads_Handler
{
	private:
	int shutdown_;
	size_t stacksize;
	pthread_attr_t attr;
	pthread_rwlock_t rwlock;
	PtrArray *bind_fds;
	MySQL_Listeners_Manager *MLM;
	// VariablesPointers_int stores:
	// key: variable name
	// tuple:
	//   variable address
	//   min value
	//   max value
	//   special variable : if true, min and max values are ignored, and further input validation is required
	std::unordered_map<std::string, std::tuple<int *, int, int, bool>> VariablesPointers_int;
	// VariablesPointers_bool stores:
	// key: variable name
	// tuple:
	//   variable address
	//   special variable : if true, further input validation is required
	std::unordered_map<std::string, std::tuple<bool *, bool>> VariablesPointers_bool;
	/**
	 * @brief Holds the clients host cache. It keeps track of the number of
	 *   errors associated to a specific client:
	 *     - Key: client identifier, based on 'clientaddr'.
	 *     - Value: Structure of type 'MySQL_Client_Host_Cache_Entry' holding
	 *       the last time the entry was updated and the error count associated
	 *       with the client.
	 */
	std::unordered_map<std::string, MySQL_Client_Host_Cache_Entry> client_host_cache;
	/**
	 * @brief Holds the mutex for accessing 'client_host_cache', since every
	 *   access can potentially perform 'read/write' operations, a regular mutex
	 *   is enough.
	 */
	pthread_mutex_t mutex_client_host_cache;

	public:
	struct {
		int monitor_history;
		int monitor_connect_interval;
		int monitor_connect_timeout;
		//! Monitor ping interval. Unit: 'ms'.
		int monitor_ping_interval;
		int monitor_ping_max_failures;
		//! Monitor ping timeout. Unit: 'ms'.
		int monitor_ping_timeout;
		//! Monitor aws rds topology discovery interval. Unit: 'one discovery check per X monitor_read_only checks'.
		int monitor_aws_rds_topology_discovery_interval;
		//! Monitor read only timeout. Unit: 'ms'.
		int monitor_read_only_interval;
		//! Monitor read only timeout. Unit: 'ms'.
		int monitor_read_only_timeout;
		int monitor_read_only_max_timeout_count;
		bool monitor_enabled;
		//! ProxySQL session wait timeout. Unit: 'ms'.
		bool monitor_wait_timeout;
		bool monitor_writer_is_also_reader;
		bool monitor_replication_lag_group_by_host;
		//! How frequently a replication lag check is performed. Unit: 'ms'.
		int monitor_replication_lag_interval;
		//! Read only check timeout. Unit: 'ms'.
		int monitor_replication_lag_timeout;
		int monitor_replication_lag_count;
		int monitor_groupreplication_healthcheck_interval;
		int monitor_groupreplication_healthcheck_timeout;
		int monitor_groupreplication_healthcheck_max_timeout_count;
		int monitor_groupreplication_max_transactions_behind_count;
		int monitor_groupreplication_max_transactions_behind_for_read_only;
		int monitor_galera_healthcheck_interval;
		int monitor_galera_healthcheck_timeout;
		int monitor_galera_healthcheck_max_timeout_count;
		int monitor_query_interval;
		int monitor_query_timeout;
		int monitor_slave_lag_when_null;
		int monitor_threads_min;
		int monitor_threads_max;
		int monitor_threads_queue_maxsize;
		int monitor_local_dns_cache_ttl;
		int monitor_local_dns_cache_refresh_interval;
		int monitor_local_dns_resolver_queue_maxsize;
		char *monitor_username;
		char *monitor_password;
		char * monitor_replication_lag_use_percona_heartbeat;
		int ping_interval_server_msec;
		int ping_timeout_server;
		int shun_on_failures;
		int shun_recovery_time_sec;
		int unshun_algorithm;
		int query_retries_on_failure;
		bool connection_warming;
		int client_host_cache_size;
		int client_host_error_counts;
		int connect_retries_on_failure;
		int connect_retries_delay;
		int connection_delay_multiplex_ms;
		int connection_max_age_ms;
		int connect_timeout_client;
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
		char *default_authentication_plugin;
		char *proxy_protocol_networks;
		//unsigned int default_charset; // removed in 2.0.13 . Obsoleted previously using MySQL_Variables instead
		int handle_unknown_charset;
		int default_authentication_plugin_int;
		bool servers_stats;
		bool commands_stats;
		bool query_digests;
		bool query_digests_lowercase;
		bool query_digests_replace_null;
		bool query_digests_no_digits;
		bool query_digests_normalize_digest_text;
		bool query_digests_track_hostname;
		bool query_digests_keep_comment;
		int query_digests_grouping_limit;
		int query_digests_groups_grouping_limit;
		bool parse_failure_logs_digest;
		bool default_reconnect;
		bool have_compress;
		bool have_ssl;
		bool multiplexing;
//		bool stmt_multiplexing;
		bool log_unhealthy_connections;
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
		int max_transaction_idle_time;
		int max_transaction_time;
		int threshold_query_length;
		int threshold_resultset_size;
		int query_digests_max_digest_length;
		int query_digests_max_query_length;
		int query_rules_fast_routing_algorithm;
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
		int set_parser_algorithm;
		int reset_connection_algorithm;
		int auto_increment_delay_multiplex;
		int auto_increment_delay_multiplex_timeout_ms;
		int long_query_time;
		int hostgroup_manager_verbose;
		int binlog_reader_connect_retry_msec;
		char *init_connect;
		char *ldap_user_variable;
		char *add_ldap_user_comment;
		char *default_session_track_gtids;
		char *default_variables[SQL_NAME_LAST_LOW_WM];
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
		char * ssl_p2s_capath;
		char * ssl_p2s_cert;
		char * ssl_p2s_key;
		char * ssl_p2s_cipher;
		char * ssl_p2s_crl;
		char * ssl_p2s_crlpath;
		int query_cache_size_MB;
		int query_cache_soft_ttl_pct;
		int query_cache_handle_warnings;
		int min_num_servers_lantency_awareness;
		int aurora_max_lag_ms_only_read_from_replicas;
		bool stats_time_backend_query;
		bool stats_time_query_processor;
		bool query_cache_stores_empty_result;
		bool kill_backend_connection_when_disconnect;
		bool client_session_track_gtid;
		bool enable_client_deprecate_eof;
		bool enable_server_deprecate_eof;
		bool enable_load_data_local_infile;
		bool log_mysql_warnings_enabled;
		int data_packets_history_size;
		int handle_warnings;
		int evaluate_replication_lag_on_servers_load;
	} variables;
	struct {
		unsigned int mirror_sessions_current;
		int threads_initialized = 0;
		/// Prometheus metrics arrays
		std::array<prometheus::Counter*, p_th_counter::__size> p_counter_array {};
		std::array<prometheus::Gauge*, p_th_gauge::__size> p_gauge_array {};
	} status_variables;

	std::atomic<bool> bootstrapping_listeners;

	/**
	 * @brief Update the client host cache with the supplied 'client_sockaddr',
	 *   and the supplied 'error' parameter specifying if there was a connection
	 *   error or not.
	 *
	 *   NOTE: This function is not safe, the supplied 'client_sockaddr' should
	 *   have been initialized by 'accept' or 'getpeername'. NULL checks are not
	 *   performed.
	 *
	 * @details The 'client_sockaddr' parameter is inspected, and the
	 *   'client_host_cache' map is only updated in case of:
	 *    - 'address_family' is either 'AF_INET' or 'AF_INET6'.
	 *    - The address obtained from it isn't '127.0.0.1'.
	 *
	 *   In case 'client_sockaddr' matches the previous description, the update
	 *   of the client host cache is performed in the following way:
	 *     1. If the cache is full, the oldest element in the cache is searched.
	 *     In case the oldest element address doesn't match the supplied
	 *     address, the oldest element is removed.
	 *     2. The cache is searched looking for the supplied address, in case of
	 *     being found, the entry is updated, otherwise the entry is inserted in
	 *     the cache.
	 *
	 * @param client_sockaddr A 'sockaddr' holding the required client information
	 *   to update the 'client_host_cache_map'.
	 * @param error 'true' if there was an error in the connection that should be
	 *   register, 'false' otherwise.
	 */
	void update_client_host_cache(struct sockaddr* client_sockaddr, bool error);
	/**
	 * @brief Retrieves the entry of the underlying 'client_host_cache' map for
	 *   the supplied 'client_sockaddr' in case of existing. In case it doesn't
	 *   exist or the supplied 'client_sockaddr' doesn't met the requirements
	 *   for being registered in the map, and zeroed 'MySQL_Client_Host_Cache_Entry'
	 *   is returned.
	 *
	 *   NOTE: This function is not safe, the supplied 'client_sockaddr' should
	 *   have been initialized by 'accept' or 'getpeername'. NULL checks are not
	 *   performed.
	 *
	 * @details The 'client_sockaddr' parameter is inspected, and the
	 *   'client_host_cache' map is only searched in case of:
	 *    - 'address_family' is either 'AF_INET' or 'AF_INET6'.
	 *    - The address obtained from it isn't '127.0.0.1'.
	 *
	 * @param client_sockaddr A 'sockaddr' holding the required client information
	 *   to update the 'client_host_cache_map'.
	 * @return If found, the corresponding entry for the supplied 'client_sockaddr',
	 *   a zeroed 'MySQL_Client_Host_Cache_Entry' otherwise.
	 */
	MySQL_Client_Host_Cache_Entry find_client_host_cache(struct sockaddr* client_sockaddr);
	/**
	 * @brief Delete all the entries in the 'client_host_cache' internal map.
	 */
	void flush_client_host_cache();
	/**
	 * @brief Returns the current entries of 'client_host_cache' in a
	 *   'SQLite3_result'. In case the param 'reset' is specified, the structure
	 *   is cleaned after being queried.
	 *
	 * @param reset If 'true' the entries of the internal structure
	 *   'client_host_cache' will be cleaned after scrapping.
	 *
	 * @return SQLite3_result holding the current entries of the
	 *   'client_host_cache'. In the following format:
	 *
	 *    [ 'client_address', 'error_num', 'last_updated' ]
	 *
	 *    Where 'last_updated' is the last updated time expressed in 'ns'.
	 */
	SQLite3_result* get_client_host_cache(bool reset);
	/**
	 * @brief Callback to update the metrics.
	 */
	void p_update_metrics();
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
	bool set_variable(char *name, const char *value);
	char **get_variables_list();
	bool has_variable(const char * name);

	MySQL_Threads_Handler();
	~MySQL_Threads_Handler();
	
	char *get_variable_string(char *name);
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
	unsigned long long get_status_variable(enum MySQL_Thread_status_variable v_idx, p_th_counter::metric m_idx, unsigned long long conv = 0);
	unsigned long long get_status_variable(enum MySQL_Thread_status_variable v_idx, p_th_gauge::metric m_idx, unsigned long long conv = 0);
	unsigned int get_active_transations();
#ifdef IDLE_THREADS
	unsigned int get_non_idle_client_connections();
#endif // IDLE_THREADS
	unsigned long long get_mysql_backend_buffers_bytes();
	unsigned long long get_mysql_frontend_buffers_bytes();
	unsigned long long get_mysql_session_internal_bytes();
	iface_info *MLM_find_iface_from_fd(int fd) {
		return MLM->find_iface_from_fd(fd);
	}
	void Get_Memory_Stats();
	void kill_connection_or_query(uint32_t _thread_session_id, bool query, char *username);
};


#endif /* __CLASS_MYSQL_THREAD_H */
