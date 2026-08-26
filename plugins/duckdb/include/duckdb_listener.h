#ifndef __DUCKDB_LISTENER_H
#define __DUCKDB_LISTENER_H

#include <atomic>
#include <cstddef>
#include <memory>
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

	// `done` is set by handle_connection() right before it returns, and
	// polled by accept_loop() to reap finished threads without waiting
	// for stop(): a std::thread that has finished running but is never
	// joined stays joinable and keeps its OS thread resources (control
	// block + stack) alive, so an unreaped conn_threads_ entry per
	// connection is a real per-connection leak for a long-running proxy,
	// not just an ever-growing vector. shared_ptr because both this
	// entry and the thread's own copy (passed into handle_connection)
	// must outlive whichever of the two finishes last.
	struct ConnThread {
		std::thread th;
		std::shared_ptr<std::atomic<bool>> done;
	};

	void accept_loop();
	void handle_connection(int client_fd, Proto proto, std::shared_ptr<std::atomic<bool>> done);
	template <typename Thr, typename Sess> void run_session(int client_fd);
	void reap_finished_threads();

	std::atomic<bool> running_ { false };
	std::atomic<bool> shutdown_ { false };
	int signal_pipe_[2] { -1, -1 };

	DuckDBEngine* engine_ { nullptr };

	mutable std::mutex mutex_;
	std::vector<Listener> listeners_;
	std::vector<ConnThread> conn_threads_;
	std::thread accept_thread_;
};

#endif // __DUCKDB_LISTENER_H
