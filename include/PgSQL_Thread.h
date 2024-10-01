#ifndef __CLASS_PGSQL_THREAD_H
#define __CLASS_PGSQL_THREAD_H
#define ____CLASS_STANDARD_PGSQL_THREAD_H
#include <prometheus/counter.h>
#include <prometheus/gauge.h>

#include "proxysql.h"
#include "Base_Thread.h"
#include "ProxySQL_Poll.h"
#include "PgSQL_Variables.h"
#ifdef IDLE_THREADS
#include <sys/epoll.h>
#endif // IDLE_THREADS
#include <atomic>

#include "prometheus_helpers.h"

#include "set_parser.h"

enum class AUTHENTICATION_METHOD {
	NO_PASSWORD,
	CLEAR_TEXT_PASSWORD,
	MD5_PASSWORD,
	SASL_SCRAM_SHA_256,
	SASL_SCRAM_SHA_256_PLUS
};

constexpr const char* AUTHENTICATION_METHOD_STR[] = {
	"NO_PASSWORD",
	"CLEAR_TEXT_PASSWORD",
	"MD5_PASSWORD",
	"SASL_SCRAM_SHA_256",
	"SASL_SCRAM_SHA_256_PLUS"
};

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

extern class PgSQL_Variables pgsql_variables;

#ifdef IDLE_THREADS
typedef struct __attribute__((aligned(64))) _pgsql_conn_exchange_t {
	pthread_mutex_t mutex_idles;
	PtrArray* idle_mysql_sessions;
	pthread_mutex_t mutex_resumes;
	PtrArray* resume_mysql_sessions;
} pgsql_conn_exchange_t;
#endif // IDLE_THREADS

typedef struct _pgsql_thr_id_username_t {
	uint32_t id;
	char* username;
} pgsql_thr_id_username;

typedef struct _pgsql_kill_queue_t {
	pthread_mutex_t m;
	std::vector<thr_id_usr*> conn_ids;
	std::vector<thr_id_usr*> query_ids;
} pgsql_kill_queue;

enum PgSQL_Thread_status_variable {
	/*st_var_backend_stmt_prepare,
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
	*/
	PG_st_var_END = 42 // to avoid ASAN complaining. TO FIX
};

class __attribute__((aligned(64))) PgSQL_Thread : public Base_Thread
{
private:
	unsigned int servers_table_version_previous;
	unsigned int servers_table_version_current;
	unsigned long long last_processing_idles;
	PgSQL_Connection** my_idle_conns;
	bool processing_idles;
	//bool maintenance_loop;

	PtrArray* cached_connections;

#ifdef IDLE_THREADS
	struct epoll_event events[MY_EPOLL_THREAD_MAXEVENTS];
	int efd;
	unsigned int mysess_idx;
	std::map<unsigned int, unsigned int> sessmap;
#endif // IDLE_THREADS

	//Session_Regex** match_regexes;

#ifdef IDLE_THREADS
	void worker_thread_assigns_sessions_to_idle_thread(PgSQL_Thread * thr);
	void worker_thread_gets_sessions_from_idle_thread();
	void idle_thread_gets_sessions_from_worker_thread();
	void idle_thread_assigns_sessions_to_worker_thread(PgSQL_Thread * thr);
	void idle_thread_check_if_worker_thread_has_unprocess_resumed_sessions_and_signal_it(PgSQL_Thread * thr);
	void idle_thread_prepares_session_to_send_to_worker_thread(int i);
	void idle_thread_to_kill_idle_sessions();
	//bool move_session_to_idle_mysql_sessions(PgSQL_Data_Stream * myds, unsigned int n);
#endif // IDLE_THREADS

	//unsigned int find_session_idx_in_mysql_sessions(PgSQL_Session * sess);
	//bool set_backend_to_be_skipped_if_frontend_is_slow(PgSQL_Data_Stream * myds, unsigned int n);
	void handle_mirror_queue_mysql_sessions();

	/**
	 * @brief Processes kill requests from the thread's kill queues.
	 *
	 * @details This function checks the thread's kill queues (`kq.conn_ids` and `kq.query_ids`)
	 * for any pending kill requests. If there are any requests, it calls `Scan_Sessions_to_Kill_All()`
	 * to iterate through all session arrays across all threads and identify sessions that match
	 * the kill requests. The `killed` flag is set to true for matching sessions. After processing
	 * all kill requests, the kill queues are cleared.
	 *
	 * @note This function is called within the `run()` function during a maintenance loop to
	 * process kill requests for connections and queries. It ensures that sessions matching
	 * kill requests are terminated.
	 *
	 */
	void handle_kill_queues();

	//void check_timing_out_session(unsigned int n);
	//void check_for_invalid_fd(unsigned int n);
	//void read_one_byte_from_pipe(unsigned int n);
	//void tune_timeout_for_myds_needs_pause(PgSQL_Data_Stream * myds);
	//void tune_timeout_for_session_needs_pause(PgSQL_Data_Stream * myds);
	//void configure_pollout(PgSQL_Data_Stream * myds, unsigned int n);

protected:
	int nfds;

public:

	void* gen_args;	// this is a generic pointer to create any sort of structure

	ProxySQL_Poll<PgSQL_Data_Stream> mypolls;
	pthread_t thread_id;
	unsigned long long pre_poll_time;
	unsigned long long last_maintenance_time;
	//unsigned long long last_move_to_idle_thread_time;
	std::atomic<unsigned long long> atomic_curtime;
	//PtrArray* mysql_sessions;
	PtrArray* mirror_queue_mysql_sessions;
	PtrArray* mirror_queue_mysql_sessions_cache;
#ifdef IDLE_THREADS
	PtrArray* idle_mysql_sessions;
	PtrArray* resume_mysql_sessions;

	pgsql_conn_exchange_t myexchange;
#endif // IDLE_THREADS

	int pipefd[2];
	kill_queue_t kq;

	//bool epoll_thread;
	bool poll_timeout_bool;

	// status variables are per thread only
	// in this way, there is no need for atomic operation and there is no cache miss
	// when it is needed a total, all threads are checked
	struct {
		unsigned long long stvar[PG_st_var_END];
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
	SetParser* thr_SetParser;

	/**
	 * @brief Default constructor for the PgSQL_Thread class.
	 *
	 * @details This constructor initializes various members of the PgSQL_Thread object to their
	 * default values. It sets up mutexes, initializes status variables, and sets up the thread's
	 * variables. It also sets the thread's `shutdown` flag to `false`, indicating that the thread
	 * is not yet in a shutdown state.
	 *
	 * @note This constructor is called when a new PgSQL_Thread object is created.
	 */
	PgSQL_Thread();

	/**
	 * @brief Destructor for the PgSQL_Thread class.
	 *
	 * @details This destructor cleans up the PgSQL_Thread object, releasing resources and
	 * freeing allocated memory. It deletes session objects, frees cached connections, and
	 * destroys mutexes. It also ensures that the thread's `shutdown` flag is set to `true`
	 * to indicate that the thread is no longer active.
	 *
	 * @note This destructor is called automatically when the PgSQL_Thread object goes out of
	 * scope or is explicitly deleted.
	 */
	~PgSQL_Thread();

	//	PgSQL_Session* create_new_session_and_client_data_stream(int _fd);

	/**
	 * @brief Initializes the PgSQL_Thread object.
	 *
	 * @return `true` if initialization is successful, `false` otherwise.
	 *
	 * @details This function performs the initial setup for the PgSQL_Thread object. It allocates
	 * memory for various data structures, initializes mutexes, creates a pipe for communication,
	 * and configures the thread's variables. It also sets up regular expressions for parsing
	 * certain SQL statements, such as `SET` commands.
	 *
	 * @note This function is called once during the thread's lifetime to prepare it for
	 * handling connections and processing queries.
	 *
	 */
	bool init();

	/**
	 * @brief Retrieves multiple idle connections from the global connection pool.
	 *
	 * @param num_idles A reference to an integer variable that will hold the number of idle connections retrieved.
	 *
	 * @details This function requests multiple idle connections from the global connection pool (`PgHGM`)
	 * and stores them in the `my_idle_conns` array. It then creates new sessions for each retrieved
	 * connection, attaches the connection to the session's backend data stream, and registers the
	 * session as a connection handler. It also sets the connection's status to `PINGING_SERVER`
	 * and initiates the pinging process.
	 *
	 * @note This function is called within the `run()` function to acquire idle connections
	 * from the global pool and prepare them for use by the thread.
	 *
	 */
	void run___get_multiple_idle_connections(int& num_idles);

	/**
	 * @brief Cleans up the mirror queue to manage concurrency.
	 *
	 * @details This function ensures that the number of mirror sessions in the `mirror_queue_mysql_sessions_cache`
	 * array does not exceed the maximum concurrency limit (`pgsql_thread___mirror_max_concurrency`).
	 * It removes sessions from the cache if the limit is exceeded.
	 *
	 * @note This function is called within the `run()` function during a maintenance loop to
	 * control the concurrency of mirror sessions.
	 *
	 */
	void run___cleanup_mirror_queue();

	//void ProcessAllMyDS_BeforePoll();
	//void ProcessAllMyDS_AfterPoll();

	/**
	 * @brief The main loop for the PgSQL_Thread object.
	 *
	 * @details This function implements the main loop for the thread. It handles events, processes
	 * sessions, manages connections, and performs maintenance tasks. It continuously monitors
	 * the `shutdown` flag and exits the loop when it is set to true. The loop includes various
	 * steps such as:
	 *
	 *   - Acquiring idle connections from the global pool.
	 *   - Processing the mirror queue for completed mirror sessions.
	 *   - Calling `ProcessAllMyDS_BeforePoll()` and `ProcessAllMyDS_AfterPoll()` functions to
	 *     handle data stream events before and after the `poll()` call.
	 *   - Adding and removing listeners to the polling loop.
	 *   - Calling `poll()` to wait for events on sockets.
	 *   - Processing all sessions using the `process_all_sessions()` function.
	 *   - Returning unused connections to the global pool.
	 *   - Refreshing the thread's variables.
	 *   - Handling kill requests for connections or queries.
	 *
	 * @note This function is the entry point for the thread's execution. It is responsible for
	 * managing all aspects of the thread's lifecycle, including handling connections, processing
	 * queries, and performing maintenance tasks.
	 *
	 */
	void run();

	/**
	 * @brief Adds a new listener socket to the polling loop.
	 *
	 * @param sock The file descriptor of the listener socket.
	 *
	 * @details This function creates a new `PgSQL_Data_Stream` object for the listener socket,
	 * sets its type to `MYDS_LISTENER`, and adds it to the `mypolls` array for monitoring.
	 *
	 * @note This function is called by the `run()` function when a new listener socket
	 * is added to the thread's monitoring list.
	 *
	 */
	void poll_listener_add(int sock);

	/**
	 * @brief Removes a listener socket from the polling loop.
	 *
	 * @param sock The file descriptor of the listener socket to remove.
	 *
	 * @details This function finds the listener socket in the `mypolls` array based on its file
	 * descriptor and removes it from the array. It then deletes the associated `PgSQL_Data_Stream`
	 * object.
	 *
	 * @note This function is called by the `run()` function when a listener socket is
	 * removed from the thread's monitoring list.
	 *
	 */
	void poll_listener_del(int sock);

	//void register_session(PgSQL_Session*, bool up_start = true);

	/**
	 * @brief Unregisters a session from the thread's session array.
	 *
	 * @param idx The index of the session to unregister.
	 *
	 * @details This function removes a session from the `mysql_sessions` array at the specified index.
	 * It does not delete the session object itself; it is assumed that the caller will handle
	 * the deletion.
	 *
	 * @note This function is called by various parts of the code when a session is no longer
	 * active and needs to be removed from the thread's session list.
	 *
	 */
	void unregister_session(int);

	/**
	 * @brief Returns a pointer to the `pollfd` structure for a specific data stream.
	 *
	 * @param i The index of the data stream in the `mypolls` array.
	 *
	 * @return A pointer to the `pollfd` structure for the specified data stream.
	 *
	 * @details This function provides access to the `pollfd` structure for a particular data
	 * stream in the `mypolls` array. This structure is used by the `poll()` function to
	 * monitor events on the associated socket.
	 *
	 * @note This function is used internally by the thread to obtain references to the
	 * `pollfd` structures for data streams when interacting with the `poll()` function.
	 *
	 */
	struct pollfd* get_pollfd(unsigned int i);

	/**
	 * @brief Processes data on a specific data stream.
	 *                       
	 * @param myds A pointer to the `PgSQL_Data_Stream` object to process.
	 * @param n The index of the data stream in the `mypolls` array.
	 *
	 * @return `true` if processing is successful, `false` if the session should be removed.
	 *
	 * @details This function handles data events on a specific data stream. It checks for events
	 * such as `POLLIN`, `POLLOUT`, `POLLERR`, and `POLLHUP`. Based on the events, it reads data
	 * from the network, processes packets, and updates the session's status. It also handles
	 * timeout events and connection failures.
	 *
	 * @note This function is called by the `run()` function after the `poll()` call to process
	 * events on each data stream. It is responsible for managing data flow and updating
	 * session states.
	 *
	 */
	bool process_data_on_data_stream(PgSQL_Data_Stream * myds, unsigned int n);

	//void ProcessAllSessions_SortingSessions();

	/**
	 * @brief Processes a completed mirror session and manages its resources.
	 *
	 * @param n The index of the session in the `mysql_sessions` array.
	 * @param sess A pointer to the `PgSQL_Session` object representing the completed mirror session.
	 *
	 * @details This function handles the completion of a mirror session. It removes the completed
	 * session from the `mysql_sessions` array and decrements the `n` index to reflect the removal.
	 * It then checks if the `mirror_queue_mysql_sessions_cache` array is below a certain length
	 * (determined by `pgsql_thread___mirror_max_concurrency` and a scaling factor).
	 * If the cache is not full, the session is added to the cache, otherwise, it is deleted.
	 *
	 * @note This function is called within the `process_all_sessions()` function when a mirror
	 * session reaches the `WAITING_CLIENT_DATA` status, indicating completion.
	 *
	 */
	void ProcessAllSessions_CompletedMirrorSession(unsigned int& n, PgSQL_Session * sess);

	/**
	 * @brief Performs maintenance tasks on a session during a maintenance loop.
	 *
	 * @param sess A pointer to the `PgSQL_Session` object to be maintained.
	 * @param sess_time The idle time of the session in milliseconds.
	 * @param total_active_transactions_ A reference to the total number of active transactions across all threads.
	 *
	 * @details This function performs various maintenance checks on a session during a maintenance
	 * loop. It checks for idle transactions, inactive sessions, and expired connections. It also
	 * handles situations where the server's table version has changed and ensures that sessions
	 * using offline nodes are terminated.
	 *
	 * @note This function is called within the `process_all_sessions()` function during a
	 * maintenance loop. It is responsible for ensuring that sessions are properly managed and
	 * that resources are released when necessary.
	 *
	 */
	void ProcessAllSessions_MaintenanceLoop(PgSQL_Session * sess, unsigned long long sess_time, unsigned int& total_active_transactions_);

	/**
	 * @brief Processes all active sessions associated with the current thread.
	 *
	 * @details This function iterates through all sessions in the `mysql_sessions` array. For each
	 * session, it performs the following actions:
	 *
	 *   - Checks for completed mirror sessions and calls `ProcessAllSessions_CompletedMirrorSession()`
	 *     if necessary.
	 *   - If a maintenance loop is active, it calls `ProcessAllSessions_MaintenanceLoop()` to
	 *     perform maintenance tasks on the session.
	 *   - If the session is healthy and needs processing, it calls the session's `handler()`
	 *     function to handle session logic.
	 *   - If the session is unhealthy, it closes the connection and removes the session from the
	 *     `mysql_sessions` array.
	 *
	 * @note This function is called within the `run()` function of the `PgSQL_Thread` class. It
	 * is the core function responsible for managing and processing all active sessions associated
	 * with the thread.
	 *
	 */
	void process_all_sessions();

	/**
	 * @brief Refreshes the thread's variables from the global variables handler.
	 *
	 * @details This function updates the thread's variables with the latest values from the
	 * global variables handler (`GloPTH`) to ensure consistency. It retrieves all relevant
	 * variables from the global handler and updates the corresponding variables in the
	 * thread's local scope.
	 *
	 * @note This function is called periodically by `PgSQL_Thread::run()` to ensure that
	 * the thread's variables are synchronized with the global variables handler.
	 *
	 */
	void refresh_variables();

	/**
	 * @brief Registers a session as a connection handler.
	 *
	 * @param _sess A pointer to the `PgSQL_Session` object to register.
	 * @param _new A boolean flag indicating whether the session is newly created (true) or not (false).
	 *
	 * @details This function marks a session as a connection handler, adding it to the
	 * `mysql_sessions` array. It sets the session's `thread` pointer to the current thread
	 * and sets the `connections_handler` flag to true.
	 *
	 * @note This function is used to track sessions that are responsible for handling
	 * connections.
	 *
	 */
	void register_session_connection_handler(PgSQL_Session * _sess, bool _new = false);

	/**
	 * @brief Unregisters a session as a connection handler.
	 *
	 * @param idx The index of the session in the `mysql_sessions` array.
	 * @param _new A boolean flag indicating whether the session is newly created (true) or not (false).
	 *
	 * @details This function removes a session from the `mysql_sessions` array, effectively
	 * unregistering it as a connection handler.
	 *
	 * @note This function is typically called when a session is no longer active or needs to be
	 * removed from the connection handler list.
	 *
	 */
	void unregister_session_connection_handler(int idx, bool _new = false);

	/**
	 * @brief Handles a new connection accepted by a listener.
	 *
	 * @param myds A pointer to the `PgSQL_Data_Stream` object representing the new connection.
	 * @param n The index of the listener in the `mypolls` array.
	 *
	 * @details This function handles the acceptance of a new connection from a listener. It
	 * accepts the connection using `accept()`, performs some sanity checks, and then creates
	 * a new `PgSQL_Session` object to manage the connection. It configures the session's
	 * data stream, adds the connection to the `mypolls` array, and sets the connection's
	 * state to `CONNECTING_CLIENT`.
	 *
	 * @note This function is called within the `run()` function of the `PgSQL_Thread` class
	 * when a new connection is accepted by a listener. It is responsible for initializing
	 * the session and adding the connection to the polling loop.
	 *
	 */
	void listener_handle_new_connection(PgSQL_Data_Stream * myds, unsigned int n);

	/**
	 * @brief Calculates and updates the memory statistics for the current thread.
	 *
	 * @details This function iterates through all sessions associated with the current
	 * thread and gathers memory usage information from each session. It updates
	 * the `status_variables` structure with the calculated memory statistics,
	 * including the following:
	 *
	 *   - `st_var_mysql_backend_buffers_bytes`: Total bytes used for backend
	 *     connection buffers when fast forwarding is enabled.
	 *   - `st_var_mysql_frontend_buffers_bytes`: Total bytes used for frontend
	 *     connection buffers (read/write buffers and other queues).
	 *   - `st_var_mysql_session_internal_bytes`: Total bytes used for internal
	 *     session data structures.
	 *
	 * @note This function is called by `SQL3_GlobalStatus()` when the `_memory`
	 * flag is set to true.
	 *
	 */
	void Get_Memory_Stats();

	/**
	 * @brief Retrieves a local connection from the thread's cached connection pool.
	 *
	 * @param _hid The hostgroup ID to search for connections in.
	 * @param sess The current session requesting the connection.
	 * @param gtid_uuid The UUID of the GTID to consider (if applicable).
	 * @param gtid_trxid The transaction ID of the GTID to consider (if applicable).
	 * @param max_lag_ms The maximum replication lag allowed for the connection (if applicable).
	 *
	 * @return A pointer to a `PgSQL_Connection` object if a suitable connection is found,
	 * `NULL` otherwise.
	 *
	 * @details This function attempts to find a suitable connection in the thread's
	 * cached connection pool (`cached_connections`). It checks for matching hostgroup
	 * ID, connection options, GTID (if provided), and maximum replication lag (if
	 * provided). If a matching connection is found, it is removed from the cache and
	 * returned.
	 *
	 * @note This function is used by `PgSQL_Session::handler()` to obtain a
	 * connection from the local cache before resorting to the global connection pool.
	 *
	 */
	PgSQL_Connection* get_MyConn_local(unsigned int, PgSQL_Session * sess, char* gtid_uuid, uint64_t gtid_trxid, int max_lag_ms);

	/**
	 * @brief Adds a connection to the thread's local connection cache.
	 *
	 * @param c The `PgSQL_Connection` object to add to the cache.
	 *
	 * @details This function checks the status of the connection's parent server
	 * (`c->parent->status`) and the connection's asynchronous state machine
	 * (`c->async_state_machine`). If the server is online and the connection is idle,
	 * the connection is added to the `cached_connections` pool. Otherwise, the
	 * connection is pushed to the global connection pool using
	 * `PgHGM->push_MyConn_to_pool()`.
	 *
	 * @note This function is used to manage the thread's local connection cache.
	 *
	 */
	void push_MyConn_local(PgSQL_Connection*);

	/**
	 * @brief Returns all connections in the thread's local cache to the global pool.
	 *
	 * @details This function iterates through the `cached_connections` pool and
	 * pushes each connection to the global connection pool using
	 * `PgHGM->push_MyConn_to_pool_array()`. After pushing the connections, the
	 * local cache is cleared.
	 *
	 * @note This function is called periodically by `PgSQL_Thread::run()` to
	 * ensure that unused connections are returned to the global pool.
	 *
	 */
	void return_local_connections();

	/**
	 * @brief Iterates through a session array to identify and kill sessions.
	 *
	 * @param mysess A pointer to the `PtrArray` containing the sessions to scan.
	 *
	 * @details This function iterates through the specified session array and checks
	 * each session against the thread's kill queues (`kq.conn_ids` and
	 * `kq.query_ids`). If a session matches a kill request, its `killed` flag is set
	 * to true. The kill queues are then updated to remove the processed kill
	 * requests.
	 *
	 * @note This function is called by `Scan_Sessions_to_Kill_All()` to kill
	 * sessions based on kill requests.
	 *
	 */
	void Scan_Sessions_to_Kill(PtrArray * mysess);

	/**
	 * @brief  Scans all session arrays across all threads to identify and kill sessions.
	 *
	 * @details This function iterates through all session arrays across different threads, including main worker threads and idle threads.
	 * It calls `Scan_Sessions_to_Kill()` for each session array to check for kill requests.
	 * The kill queues (`kq.conn_ids` and `kq.query_ids`) are cleared after processing all kill requests.
	 *
	 * @note This function is called by `PgSQL_Threads_Handler::kill_connection_or_query()` to kill sessions based on kill requests.
	 *
	 */
	void Scan_Sessions_to_Kill_All();
};


typedef PgSQL_Thread* create_PgSQL_Thread_t();
typedef void destroy_PgSQL_Thread_t(PgSQL_Thread*);

class PgSQL_Listeners_Manager {
private:
	PtrArray* ifaces;
public:
	PgSQL_Listeners_Manager();
	~PgSQL_Listeners_Manager();
	int add(const char* iface, unsigned int num_threads, int** perthrsocks);
	int find_idx(const char* iface);
	int find_idx(const char* address, int port);
	iface_info* find_iface_from_fd(int fd);
	int get_fd(unsigned int idx);
	void del(unsigned int idx);
};

/*struct p_th_counter {
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
*/
/**
 * @brief Structure holding the data for a Client_Host_Cache entry.
 */
typedef struct _PgSQL_Client_Host_Cache_Entry {
	/**
	 * @brief Last time the entry was updated.
	 */
	uint64_t updated_at;
	/**
	 * @brief Error count associated with the entry.
	 */
	uint32_t error_count;
} PgSQL_Client_Host_Cache_Entry;

class PgSQL_Threads_Handler
{
private:
	int shutdown_;
	size_t stacksize;
	pthread_attr_t attr;
	pthread_rwlock_t rwlock;
	PtrArray* bind_fds;
	PgSQL_Listeners_Manager* MLM;
	// VariablesPointers_int stores:
	// key: variable name
	// tuple:
	//   variable address
	//   min value
	//   max value
	//   special variable : if true, min and max values are ignored, and further input validation is required
	std::unordered_map<std::string, std::tuple<int*, int, int, bool>> VariablesPointers_int;
	// VariablesPointers_bool stores:
	// key: variable name
	// tuple:
	//   variable address
	//   special variable : if true, further input validation is required
	std::unordered_map<std::string, std::tuple<bool*, bool>> VariablesPointers_bool;
	/**
	 * @brief Holds the clients host cache. It keeps track of the number of
	 *   errors associated to a specific client:
	 *     - Key: client identifier, based on 'clientaddr'.
	 *     - Value: Structure of type 'PgSQL_Client_Host_Cache_Entry' holding
	 *       the last time the entry was updated and the error count associated
	 *       with the client.
	 */
	std::unordered_map<std::string, PgSQL_Client_Host_Cache_Entry> client_host_cache;
	/**
	 * @brief Holds the mutex for accessing 'client_host_cache', since every
	 *   access can potentially perform 'read/write' operations, a regular mutex
	 *   is enough.
	 */
	pthread_mutex_t mutex_client_host_cache;

public:
	struct {
		int authentication_method;
		char* server_version;

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
/* TODO: Remove
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
*/
		int monitor_threads;
/* TODO: Remove
		int monitor_threads_min;
		int monitor_threads_max;
		int monitor_threads_queue_maxsize;
*/
		int monitor_local_dns_cache_ttl;
		int monitor_local_dns_cache_refresh_interval;
		int monitor_local_dns_resolver_queue_maxsize;
		char* monitor_username;
		char* monitor_password;
		char* monitor_replication_lag_use_percona_heartbeat;
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
		char* default_schema;
		char* interfaces;
		char* keep_multiplexing_variables;
		char* default_client_encoding;
		//unsigned int default_charset; // removed in 2.0.13 . Obsoleted previously using PgSQL_Variables instead
		int handle_unknown_charset;
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
		int auto_increment_delay_multiplex;
		int auto_increment_delay_multiplex_timeout_ms;
		int long_query_time;
		int hostgroup_manager_verbose;
		int binlog_reader_connect_retry_msec;
		char* init_connect;
		char* ldap_user_variable;
		char* add_ldap_user_comment;
		char* default_session_track_gtids;
		char* default_variables[SQL_NAME_LAST_LOW_WM];
		char* firewall_whitelist_errormsg;
#ifdef DEBUG
		bool session_debug;
#endif /* DEBUG */
		uint32_t server_capabilities;
		int poll_timeout;
		int poll_timeout_on_failure;
		char* eventslog_filename;
		int eventslog_filesize;
		int eventslog_default_log;
		int eventslog_format;
		char* auditlog_filename;
		int auditlog_filesize;
		// SSL related, proxy to server
		char* ssl_p2s_ca;
		char* ssl_p2s_capath;
		char* ssl_p2s_cert;
		char* ssl_p2s_key;
		char* ssl_p2s_cipher;
		char* ssl_p2s_crl;
		char* ssl_p2s_crlpath;
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
	} variables;
	struct {
		unsigned int mirror_sessions_current;
		int threads_initialized = 0;
		/// Prometheus metrics arrays
		//std::array<prometheus::Counter*, p_th_counter::__size> p_counter_array{};
		//std::array<prometheus::Gauge*, p_th_gauge::__size> p_gauge_array{};
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
	 *   for being registered in the map, and zeroed 'PgSQL_Client_Host_Cache_Entry'
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
	 *   a zeroed 'PgSQL_Client_Host_Cache_Entry' otherwise.
	 */
	PgSQL_Client_Host_Cache_Entry find_client_host_cache(struct sockaddr* client_sockaddr);
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
	proxysql_pgsql_thread_t* pgsql_threads;
#ifdef IDLE_THREADS
	proxysql_pgsql_thread_t* pgsql_threads_idles;
#endif // IDLE_THREADS
	/**
	 * @brief Returns the current global version number for thread variables.
	 *
	 * @return The current global version number.
	 *
	 * @details This function retrieves the current global version number for thread variables.
	 * This number is incremented whenever a thread variable is changed, allowing threads to
	 * detect changes and refresh their local variables accordingly.
	 *
	 * @note This function is used by threads to check for changes in global variables and
	 * to update their local copies if necessary.
	 *
	 */
	unsigned int get_global_version();

	/**
	 * @brief Acquires a write lock on the thread variables.
	 *
	 * @details This function acquires a write lock on the thread variables using a read-write lock.
	 * This lock prevents other threads from modifying the variables while the lock is held.
	 *
	 * @note This function should be called before modifying any thread variables to ensure
	 * data consistency.
	 *
	 */
	void wrlock();

	/**
	 * @brief Releases a write lock on the thread variables.
	 *
	 * @details This function releases the write lock on the thread variables that was previously
	 * acquired using `wrlock()`. After calling this function, other threads can modify the
	 * variables.
	 *
	 * @note This function should be called after modifying thread variables to release the
	 * lock and allow other threads to access the variables.
	 *
	 */
	void wrunlock();

	/**
	 * @brief Commits changes to thread variables and increments the global version.
	 *
	 * @details This function increments the global version number for thread variables, signaling
	 * to other threads that changes have been made. It also updates the global variables
	 * handler (`GloPTH`) with the committed changes.
	 *
	 * @note This function should be called after modifying thread variables to ensure that
	 * other threads are notified of the changes and can update their local copies.
	 *
	 */
	void commit();

	/**
	 * @brief Retrieves the value of a thread variable as a string.
	 *
	 * @param name The name of the variable to retrieve.
	 *
	 * @return A pointer to a string containing the value of the variable, or `NULL` if
	 * the variable is not found.
	 *
	 * @details This function retrieves the value of a thread variable as a string. It first
	 * checks for monitor-related variables, then for SSL variables, and finally for default
	 * variables. If the variable is found, its value is returned as a dynamically allocated
	 * string. Otherwise, `NULL` is returned.
	 *
	 * @note This function is used to access the values of thread variables from other parts
	 * of the code.
	 *
	 */
	char* get_variable(char* name);

	/**
	 * @brief Sets the value of a thread variable.
	 *
	 * @param name The name of the variable to set.
	 * @param value The new value to assign to the variable.
	 *
	 * @return `true` if the variable is set successfully, `false` otherwise.
	 *
	 * @details This function sets the value of a thread variable. It first checks for monitor,
	 * SSL, and default variables. If the variable is found, it updates the variable's value
	 * with the provided string. For integer variables, it performs range validation. For
	 * boolean variables, it checks for valid "true" or "false" values. For some variables,
	 * it performs additional input validation. If the variable is not found or the provided
	 * value is invalid, `false` is returned.
	 *
	 * @note This function is used to modify the values of thread variables from other parts
	 * of the code.
	 *
	 */
	bool set_variable(char* name, const char* value);

	/**
	 * @brief Returns a list of all available thread variables.
	 *
	 * @return A dynamically allocated array of strings containing the names of all thread
	 * variables, or `NULL` if there are no variables.
	 *
	 * @details This function retrieves a list of all available thread variables. It scans both
	 * the `pgsql_thread_variables_names` array and the `mysql_tracked_variables` array to
	 * include both PgSQL-specific and MySQL-related variables. The returned list is dynamically
	 * allocated and should be freed by the caller.
	 *
	 * @note This function is used to obtain a list of available thread variables for
	 * display or other purposes.
	 *
	 */
	char** get_variables_list();

	/**
	 * @brief Checks if a thread variable exists.
	 *
	 * @param name The name of the variable to check.
	 *
	 * @return `true` if the variable exists, `false` otherwise.
	 *
	 * @details This function checks if a thread variable exists. It scans both the
	 * `pgsql_thread_variables_names` array and the `mysql_tracked_variables` array to
	 * determine if the variable is defined.
	 *
	 * @note This function is used to check for the existence of thread variables before
	 * attempting to access or modify them.
	 *
	 */
	bool has_variable(const char* name);

	/**
	 * @brief Default constructor for the PgSQL_Threads_Handler class.
	 *
	 * @details This constructor initializes various members of the PgSQL_Threads_Handler object
	 * to their default values. It sets up mutexes, initializes variables, and creates a
	 * `PgSQL_Listeners_Manager` object. It also sets the `bootstrapping_listeners` flag to
	 * `true` to indicate that the listener bootstrapping process is ongoing.
	 *
	 * @note This constructor is called when a new PgSQL_Threads_Handler object is created.
	 *
	 */
	PgSQL_Threads_Handler();

	/**
	 * @brief Destructor for the PgSQL_Threads_Handler class.
	 *
	 * @details This destructor cleans up the PgSQL_Threads_Handler object, releasing resources
	 * and freeing allocated memory. It frees dynamically allocated strings, deletes the
	 * `PgSQL_Listeners_Manager` object, and destroys mutexes.
	 *
	 * @note This destructor is called automatically when the PgSQL_Threads_Handler object
	 * goes out of scope or is explicitly deleted.
	 *
	 */
	~PgSQL_Threads_Handler();

	/**
	 * @brief Retrieves the value of a thread variable as a string.
	 *
	 * @param name The name of the variable to retrieve.
	 *
	 * @return A pointer to a string containing the value of the variable, or `NULL` if
	 * the variable is not found.
	 *
	 * @details This function retrieves the value of a thread variable as a string. It checks
	 * if the variable exists and then returns its value as a dynamically allocated string.
	 * If the variable is not found, it returns `NULL`.
	 *
	 * @note This function is used internally by the `get_variable()` function to retrieve
	 * the value of a variable as a string.
	 */
	char* get_variable_string(char* name);

	/**
	 * @brief Retrieves the value of a thread variable as a uint16_t.
	 *
	 * @param name The name of the variable to retrieve.
	 *
	 * @return The value of the variable as a uint16_t, or 0 if the variable is not found
	 * or its value is not a valid uint16_t.
	 *
	 * @details This function retrieves the value of a thread variable as a uint16_t. It checks
	 * if the variable exists and then converts its value to a uint16_t. If the variable is
	 * not found or its value is not a valid uint16_t, it returns 0.
	 *
	 * @note This function is used internally by the `get_variable()` function to retrieve
	 * the value of a variable as a uint16_t.
	 */
	uint16_t get_variable_uint16(char* name);

	/**
	 * @brief Retrieves the value of a thread variable as an integer.
	 *
	 * @param name The name of the variable to retrieve.
	 *
	 * @return The value of the variable as an integer, or 0 if the variable is not found
	 * or its value is not a valid integer.
	 *
	 * @details This function retrieves the value of a thread variable as an integer. It checks
	 * if the variable exists and then converts its value to an integer. If the variable is
	 * not found or its value is not a valid integer, it returns 0.
	 *
	 * @note This function is used internally by the `get_variable()` function to retrieve
	 * the value of a variable as an integer.
	 */
	int get_variable_int(const char* name);

	/**
	 * @brief Prints the current version of the PgSQL_Threads_Handler class.
	 *
	 * @details This function prints the current version of the PgSQL_Threads_Handler class
	 * to the standard error stream.
	 *
	 * @note This function is used for debugging and informational purposes.
	 */
	void print_version();

	/**
	 * @brief Initializes the PgSQL_Threads_Handler object.
	 *
	 * @param num The number of threads to create.
	 * @param stack The stack size for each thread.
	 *
	 * @details This function initializes the PgSQL_Threads_Handler object, creating the
	 * specified number of threads with the given stack size. It also initializes the
	 * global variables handler (`GloPTH`) and sets up the thread pool.
	 *
	 * @note This function is called once during the PgSQL_Threads_Handler object's
	 * lifetime to prepare it for managing threads.
	 */
	void init(unsigned int num = 0, size_t stack = 0);

	/**
	 * @brief Creates a new thread.
	 *
	 * @param tn The thread number.
	 * @param start_routine The start routine for the thread.
	 * @param epoll_thread A boolean flag indicating whether the thread is an epoll thread (true)
	 * or a worker thread (false).
	 *
	 * @return A pointer to the newly created thread object, or `NULL` if the thread creation
	 * failed.
	 *
	 * @details This function creates a new thread with the specified thread number, start routine,
	 * and thread type. It initializes the thread object, sets up the thread's variables, and
	 * starts the thread's execution.
	 *
	 * @note This function is used to create new threads for the PgSQL_Threads_Handler object.
	 *
	 */
	proxysql_pgsql_thread_t* create_thread(unsigned int tn, void* (*start_routine) (void*), bool);

	/**
	 * @brief Shuts down all threads in the thread pool.
	 *
	 * @details This function shuts down all threads in the thread pool, gracefully terminating
	 * their execution. It sets the `shutdown` flag to `true` for each thread, allowing them
	 * to exit their main loop. It then waits for all threads to terminate and frees any
	 * associated resources.
	 *
	 * @note This function is called when the PgSQL_Threads_Handler object is being shut down
	 * to gracefully terminate all managed threads.
	 *
	 */
	void shutdown_threads();

	/**
	 * @brief Adds a new listener to the thread pool, based on an interface string.
	 *
	 * @param iface The interface string in the format "address:port" or "[ipv6_address]:port".
	 *
	 * @return 0 on success, -1 on failure.
	 *
	 * @details This function adds a new listener to the thread pool based on the provided
	 * interface string. It delegates the actual listener creation to the `PgSQL_Listeners_Manager`
	 * object (`MLM`). If the listener is successfully added, it signals all threads in the pool
	 * to update their polling lists.
	 *
	 * @note This function is used to configure listeners for the PgSQL_Threads_Handler object.
	 */
	int listener_add(const char* iface);

	/**
	 * @brief Adds a new listener to the thread pool, based on an address and port.
	 *
	 * @param address The address of the listener.
	 * @param port The port of the listener.
	 *
	 * @return 0 on success, -1 on failure.
	 *
	 * @details This function adds a new listener to the thread pool based on the provided
	 * address and port. It delegates the actual listener creation to the `PgSQL_Listeners_Manager`
	 * object (`MLM`). If the listener is successfully added, it signals all threads in the pool
	 * to update their polling lists.
	 *
	 * @note This function is used to configure listeners for the PgSQL_Threads_Handler object.
	 */
	int listener_add(const char* address, int port);

	/**
	 * @brief Removes a listener from the thread pool, based on an interface string.
	 *
	 * @param iface The interface string in the format "address:port" or "[ipv6_address]:port".
	 *
	 * @return 0 on success, -1 on failure.
	 *
	 * @details This function removes a listener from the thread pool based on the provided
	 * interface string. It delegates the actual listener removal to the `PgSQL_Listeners_Manager`
	 * object (`MLM`). If the listener is successfully removed, it signals all threads in the pool
	 * to update their polling lists.
	 *
	 * @note This function is used to remove listeners from the PgSQL_Threads_Handler object.
	 */
	int listener_del(const char* iface);

	/**
	 * @brief Removes a listener from the thread pool, based on an address and port.
	 *
	 * @param address The address of the listener to remove.
	 * @param port The port of the listener to remove.
	 *
	 * @return 0 on success, -1 on failure.
	 *
	 * @details This function removes a listener from the thread pool based on the provided
	 * address and port. It delegates the actual listener removal to the `PgSQL_Listeners_Manager`
	 * object (`MLM`). If the listener is successfully removed, it signals all threads in the pool
	 * to update their polling lists.
	 *
	 * @note This function is used to remove listeners from the PgSQL_Threads_Handler object.
	 */
	int listener_del(const char* address, int port);

	/**
	 * @brief Starts all configured listeners in the thread pool.
	 *
	 * @details This function starts all listeners that have been configured for the
	 * PgSQL_Threads_Handler object. It parses the `interfaces` variable, which contains
	 * a list of interface strings, and calls `listener_add()` to add each listener
	 * to the pool. After all listeners have been added, it sets the `bootstrapping_listeners`
	 * flag to `false` to indicate that the listener bootstrapping process is complete.
	 *
	 * @note This function is called to initiate the listening process for the
	 * PgSQL_Threads_Handler object.
	 */
	void start_listeners();

	/**
	 * @brief Stops all listeners in the thread pool.
	 *
	 * @details This function stops all listeners that have been configured for the
	 * PgSQL_Threads_Handler object. It parses the `interfaces` variable, which contains
	 * a list of interface strings, and calls `listener_del()` to remove each listener
	 * from the pool.
	 *
	 * @note This function is called to terminate the listening process for the
	 * PgSQL_Threads_Handler object.
	 */
	void stop_listeners();

	/**
	 * @brief Signals all threads in the thread pool.
	 *
	 * @param _c The signal value to send to each thread.
	 *
	 * @details This function sends a signal to all threads in the thread pool. It iterates
	 * through the thread pool and writes the signal value to the pipe associated with each
	 * thread.
	 *
	 * @note This function is used to send signals to threads for various purposes, such as
	 * notifying them of changes in global variables, requesting a thread to perform a specific
	 * task, or signaling a shutdown event.
	 *
	 */
	void signal_all_threads(unsigned char _c = 0);

	/**
	 * @brief Retrieves a process list for all threads in the thread pool.
	 *
	 * @return A `SQLite3_result` object containing the process list, or `NULL` if an error
	 * occurred.
	 *
	 * @details This function retrieves a process list for all threads in the thread pool. It
	 * iterates through the thread pool and gathers information about each active session.
	 * The information is then formatted into a `SQLite3_result` object, which can be used
	 * by the SQLite3 engine to return the process list to the client.
	 *
	 * @note This function is used to provide a process list view for the PgSQL_Threads_Handler
	 * object, allowing administrators to monitor active sessions and their status.
	 *
	 */
	SQLite3_result* SQL3_Processlist();

	/**
	 * @brief Retrieves global status information for the thread pool.
	 *
	 * @param _memory A boolean flag indicating whether to include memory statistics in the
	 * global status information.
	 *
	 * @return A `SQLite3_result` object containing the global status information, or `NULL`
	 * if an error occurred.
	 *
	 * @details This function retrieves global status information for the thread pool, including
	 * metrics such as uptime, active transactions, connections, and queries. If the `_memory`
	 * flag is set to `true`, it also includes memory statistics for each thread.
	 *
	 * @note This function is used to provide a global status view for the PgSQL_Threads_Handler
	 * object, allowing administrators to monitor the overall health and performance of the
	 * thread pool.
	 *
	 */
	SQLite3_result* SQL3_GlobalStatus(bool _memory);

	/**
	 * @brief Kills a session based on its thread session ID.
	 *
	 * @param _thread_session_id The thread session ID of the session to kill.
	 *
	 * @return `true` if the session is found and killed, `false` otherwise.
	 *
	 * @details This function attempts to find and kill a session based on its thread session ID.
	 * It iterates through all threads in the thread pool and searches for a session with the
	 * matching ID. If the session is found, its `killed` flag is set to `true`, indicating that
	 * the session should be terminated.
	 *
	 * @note This function is used to terminate a specific session by its thread session ID.
	 *
	 */
	bool kill_session(uint32_t _thread_session_id);

	/**
	 * @brief Retrieves the total length of the mirror queue across all threads.
	 *
	 * @return The total length of the mirror queue.
	 *
	 * @details This function retrieves the total length of the mirror queue across all threads.
	 * It iterates through the thread pool and sums the length of the mirror queue for each
	 * thread.
	 *
	 * @note This function is used to monitor the size of the mirror queue, which is used
	 * to queue mirror sessions for processing.
	 *
	 */
	unsigned long long get_total_mirror_queue();

	//unsigned long long get_status_variable(enum PgSQL_Thread_status_variable v_idx, p_th_counter::metric m_idx, unsigned long long conv = 0);
	//unsigned long long get_status_variable(enum PgSQL_Thread_status_variable v_idx, p_th_gauge::metric m_idx, unsigned long long conv = 0);

	/**
	 * @brief Retrieves the total number of active transactions across all threads.
	 *
	 * @return The total number of active transactions.
	 *
	 * @details This function retrieves the total number of active transactions across all
	 * threads in the thread pool. It iterates through the thread pool and sums the number
	 * of active transactions for each thread.
	 *
	 * @note This function is used to monitor the number of active transactions, which is
	 * a key performance indicator for the PgSQL_Threads_Handler object.
	 *
	 */
	unsigned int get_active_transations();

#ifdef IDLE_THREADS
	/**
	 * @brief Retrieves the number of non-idle client connections across all threads.
	 *
	 * @return The number of non-idle client connections.
	 *
	 * @details This function retrieves the number of non-idle client connections across all
	 * threads in the thread pool. It iterates through the thread pool and sums the number
	 * of non-idle client connections for each thread.
	 *
	 * @note This function is used to monitor the number of active client connections, which
	 * is a key performance indicator for the PgSQL_Threads_Handler object.
	 *
	 */
	unsigned int get_non_idle_client_connections();
#endif // IDLE_THREADS

	/**
	 * @brief Retrieves the total number of bytes used for backend connection buffers across
	 * all threads.
	 *
	 * @return The total number of bytes used for backend connection buffers.
	 *
	 * @details This function retrieves the total number of bytes used for backend connection
	 * buffers across all threads in the thread pool. It iterates through the thread pool and
	 * sums the number of bytes used for backend connection buffers for each thread.
	 *
	 * @note This function is used to monitor the memory usage of backend connection buffers,
	 * which is a key performance indicator for the PgSQL_Threads_Handler object.
	 *
	 */
	unsigned long long get_pgsql_backend_buffers_bytes();

	/**
	 * @brief Retrieves the total number of bytes used for frontend connection buffers across
	 * all threads.
	 *
	 * @return The total number of bytes used for frontend connection buffers.
	 *
	 * @details This function retrieves the total number of bytes used for frontend connection
	 * buffers across all threads in the thread pool. It iterates through the thread pool and
	 * sums the number of bytes used for frontend connection buffers for each thread.
	 *
	 * @note This function is used to monitor the memory usage of frontend connection buffers,
	 * which is a key performance indicator for the PgSQL_Threads_Handler object.
	 *
	 */
	unsigned long long get_pgsql_frontend_buffers_bytes();

	/**
	 * @brief Retrieves the total number of bytes used for internal session data structures
	 * across all threads.
	 *
	 * @return The total number of bytes used for internal session data structures.
	 *
	 * @details This function retrieves the total number of bytes used for internal session
	 * data structures across all threads in the thread pool. It iterates through the thread pool
	 * and sums the number of bytes used for internal session data structures for each thread.
	 *
	 * @note This function is used to monitor the memory usage of internal session data
	 * structures, which is a key performance indicator for the PgSQL_Threads_Handler object.
	 *
	 */
	unsigned long long get_pgsql_session_internal_bytes();

	iface_info* MLM_find_iface_from_fd(int fd) {
		return MLM->find_iface_from_fd(fd);
	}

	/**
	 * @brief Calculates and updates the memory statistics for all threads in the pool.
	 *
	 * @details This function iterates through all threads in the thread pool and calls
	 * the `Get_Memory_Stats()` function for each thread to calculate and update its
	 * memory statistics. 
	 *
	 * @note This function is used to gather memory statistics for all threads in the
	 * pool, providing a comprehensive view of memory usage.
	 *
	 */
	void Get_Memory_Stats();

	/**
	 * @brief Sends a kill request to all threads in the pool to either kill a connection
	 * or a query.
	 *
	 * @param _thread_session_id The thread session ID of the connection or query to kill.
	 * @param query A boolean flag indicating whether to kill a query (true) or a connection
	 * (false).
	 * @param username The username associated with the connection or query.
	 *
	 * @details This function sends a kill request to all threads in the pool to either kill
	 * a connection or a query. It adds the kill request to the kill queue (`kq.conn_ids` or
	 * `kq.query_ids`) for each thread and then signals all threads to process the kill queue.
	 *
	 * @note This function is used to terminate a specific connection or query by its thread
	 * session ID.
	 *
	 */
	void kill_connection_or_query(uint32_t _thread_session_id, bool query, char* username);
};
	
	
#endif /* __CLASS_PGSQL_THREAD_H */
