#ifndef PROXYSQL_MYSQLX_WORKER_H
#define PROXYSQL_MYSQLX_WORKER_H

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct MysqlxListenerHandle {
	int fd { -1 };
	std::string bind_address {};
	uint16_t port { 0 };
	std::string route_name {};
};

class MysqlxWorker {
public:
	explicit MysqlxWorker(uint32_t worker_id);
	~MysqlxWorker();

	MysqlxWorker(const MysqlxWorker&) = delete;
	MysqlxWorker& operator=(const MysqlxWorker&) = delete;

	void start();
	void stop();
	bool is_running() const;
	void enqueue_client_fd(int fd);

private:
	void run();

	uint32_t worker_id_;
	std::atomic<bool> running_ { false };
	std::thread thread_ {};
	std::mutex queue_mutex_ {};
	std::vector<int> pending_fds_ {};
};

// Listener management — called from plugin start/stop
bool mysqlx_start_listeners_from_runtime_routes(class SQLite3DB& admindb);
void mysqlx_stop_listeners();

// Returns the number of active listeners (for testing)
size_t mysqlx_listener_count();

#endif /* PROXYSQL_MYSQLX_WORKER_H */
