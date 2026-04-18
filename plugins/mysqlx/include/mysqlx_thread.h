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

	int add_listener(const char* bind_addr, int port);
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

	std::vector<int> listener_fds_;
	std::vector<std::string> listener_addrs_;
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
