#ifndef __MYSQLX_THREAD_H
#define __MYSQLX_THREAD_H

#include <cstdint>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <poll.h>
#include <openssl/ssl.h>
#include "mysqlx_data_stream.h"
#include "mysqlx_session.h"
#include "mysqlx_connection.h"

class MysqlxConfigStore;

class Mysqlx_Thread {
public:
	Mysqlx_Thread();
	~Mysqlx_Thread();

	void init(int thread_index);
	bool start();
	void stop();

	void run();

	int get_thread_index() const { return thread_index_; }
	size_t get_session_count() const;
	bool is_running() const { return running_.load(); }
	int get_listener_count() const;

	/**
	 * Creates a listener socket (bind + listen) and registers it with this
	 * thread under an optional logical route name.
	 *
	 * The route name is stored in the parallel `listener_route_names_` vector
	 * (same length / same index as `listener_fds_` and `listener_addrs_`),
	 * which lets `remove_listener_for_route` tear down a single listener by
	 * name. Passing `nullptr` or an empty string records an empty route name;
	 * those listeners can only be torn down via `remove_listeners()`.
	 *
	 * Returns 0 on success, -1 on any socket/bind/listen error.
	 */
	int add_listener(const char* bind_addr, int port, const char* route_name = nullptr);

	/**
	 * Closes and removes the listener owned by this thread for `route_name`.
	 *
	 * Returns true if a listener was found and removed (fd closed, parallel
	 * vectors pruned). Returns false if no listener under that name exists on
	 * this thread — missing-is-not-an-error, so reconciliation can call this
	 * idempotently.
	 */
	bool remove_listener_for_route(const char* route_name);

	void remove_listeners();

	MysqlxConnection* get_connection_from_cache(int hostgroup, const char* user, const char* schema);
	void return_connection_to_cache(MysqlxConnection* conn);
	size_t get_cached_connection_count() const;
	void set_max_cached_connections(size_t max) { max_cached_ = max; }
	void set_max_sessions(size_t max) { max_sessions_ = max; }
	size_t get_max_sessions() const { return max_sessions_; }
	void set_config_store(const MysqlxConfigStore* store) { config_store_ = store; }

	SSL_CTX* get_ssl_ctx() const;

private:
	void accept_new_connection(int listener_fd);
	void rebuild_poll_set();
	void process_ready_fds(int nfds);
	void process_all_sessions();

	int thread_index_;
	std::atomic<bool> running_;
	std::thread thread_;
	const MysqlxConfigStore* config_store_;

	std::vector<struct pollfd> poll_fds_;
	std::vector<MysqlxDataStream*> poll_ds_;

	// Parallel vectors describing this thread's listening sockets.
	// Invariant: all three vectors always have the same length, and the
	// element at a given index describes the same listener (its fd, its
	// bind host, and its logical route name from `mysqlx_routes.name`).
	// An empty string in `listener_route_names_` means the listener was
	// not associated with a named route.
	std::vector<int> listener_fds_;
	std::vector<std::string> listener_addrs_;
	std::vector<std::string> listener_route_names_;
	std::mutex listener_mutex_;

	std::vector<MysqlxSession*> sessions_;
	std::mutex sessions_mutex_;

	std::vector<MysqlxConnection*> conn_cache_;
	std::mutex conn_cache_mutex_;
	size_t max_cached_;
	size_t max_sessions_;

	int signal_pipe_[2];

	uint64_t curtime_;
};

#endif
