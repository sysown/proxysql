#ifndef __DUCKDB_LISTENER_H
#define __DUCKDB_LISTENER_H

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class DuckDBConfigStore;
class DuckDBEngine;

// Binds the configured MySQL and PostgreSQL ports and runs one accept
// loop over all of them. Each accepted socket gets its own thread that
// builds a core session and runs it to completion.
//
// stop() joins every connection thread before returning, so the caller
// can safely close the DuckDBEngine afterwards. This is the property
// that makes plugin unload safe, and it is why the threads are tracked
// rather than detached the way SQLite3_Server's are.
class DuckDBListener {
public:
	DuckDBListener() = default;
	~DuckDBListener();

	DuckDBListener(const DuckDBListener&) = delete;
	DuckDBListener& operator=(const DuckDBListener&) = delete;

	bool start(DuckDBConfigStore& cfg, DuckDBEngine& engine, std::string& err);
	void stop();

	bool is_running() const { return running_.load(); }
	size_t listener_count() const;
	size_t connection_thread_count() const;

private:
	enum class Proto { mysql, pgsql };
	struct Listener { int fd; Proto proto; };

	void accept_loop();
	void handle_connection(int client_fd, Proto proto);
	template <typename Thr, typename Sess> void run_session(int client_fd);

	std::atomic<bool> running_ { false };
	std::atomic<bool> shutdown_ { false };
	int signal_pipe_[2] { -1, -1 };

	DuckDBEngine* engine_ { nullptr };

	mutable std::mutex mutex_;
	std::vector<Listener> listeners_;
	std::vector<std::thread> conn_threads_;
	std::thread accept_thread_;
};

#endif // __DUCKDB_LISTENER_H
