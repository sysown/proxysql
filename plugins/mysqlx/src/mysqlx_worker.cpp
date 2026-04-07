#include "mysqlx_worker.h"

#include "mysqlx_frontend_session.h"
#include "mysqlx_plugin.h"
#include "sqlite3db.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

// Global listener state, managed by mysqlx_start/stop_listeners.
std::vector<MysqlxListenerHandle> g_listeners {};
std::vector<std::unique_ptr<MysqlxWorker>> g_workers {};
std::atomic<bool> g_accept_running { false };
std::thread g_accept_thread {};
uint32_t g_rr_index { 0 };

bool parse_bind(const std::string& bind, std::string& host, uint16_t& port) {
	auto pos = bind.rfind(':');
	if (pos == std::string::npos || pos == 0 || pos == bind.size() - 1) {
		return false;
	}

	host = bind.substr(0, pos);
	int p = std::atoi(bind.substr(pos + 1).c_str());
	if (p <= 0 || p > 65535) {
		return false;
	}

	port = static_cast<uint16_t>(p);
	return true;
}

int create_listener_socket(const std::string& host, uint16_t port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}

	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
		close(fd);
		return -1;
	}

	if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	if (listen(fd, 128) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

void accept_loop() {
	while (g_accept_running.load()) {
		// Simple poll across all listeners with a timeout so we can
		// check g_accept_running periodically.
		fd_set rfds;
		FD_ZERO(&rfds);
		int maxfd = -1;

		for (const auto& listener : g_listeners) {
			if (listener.fd >= 0) {
				FD_SET(listener.fd, &rfds);
				if (listener.fd > maxfd) {
					maxfd = listener.fd;
				}
			}
		}

		if (maxfd < 0) {
			// No valid listeners; sleep briefly and retry.
			struct timespec ts { 0, 100000000 }; // 100ms
			nanosleep(&ts, nullptr);
			continue;
		}

		struct timeval tv { 0, 200000 }; // 200ms timeout
		int ready = select(maxfd + 1, &rfds, nullptr, nullptr, &tv);
		if (ready <= 0) {
			continue;
		}

		for (const auto& listener : g_listeners) {
			if (listener.fd >= 0 && FD_ISSET(listener.fd, &rfds)) {
				sockaddr_in client_addr {};
				socklen_t client_len = sizeof(client_addr);
				int client_fd = accept(listener.fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
				if (client_fd < 0) {
					continue;
				}

				// Round-robin dispatch to workers.
				if (!g_workers.empty()) {
					uint32_t idx = g_rr_index++ % static_cast<uint32_t>(g_workers.size());
					g_workers[idx]->enqueue_client_fd(client_fd);
				} else {
					close(client_fd);
				}
			}
		}
	}
}

} // namespace

// ---------------------------------------------------------------------------
// MysqlxWorker
// ---------------------------------------------------------------------------

MysqlxWorker::MysqlxWorker(uint32_t worker_id) : worker_id_(worker_id) {}

MysqlxWorker::~MysqlxWorker() {
	stop();
}

void MysqlxWorker::start() {
	running_.store(true);
	thread_ = std::thread(&MysqlxWorker::run, this);
}

void MysqlxWorker::stop() {
	running_.store(false);
	if (thread_.joinable()) {
		thread_.join();
	}
}

bool MysqlxWorker::is_running() const {
	return running_.load();
}

void MysqlxWorker::enqueue_client_fd(int fd) {
	std::lock_guard<std::mutex> lock(queue_mutex_);
	pending_fds_.push_back(fd);
}

void MysqlxWorker::run() {
	while (running_.load()) {
		std::vector<int> fds {};
		{
			std::lock_guard<std::mutex> lock(queue_mutex_);
			fds.swap(pending_fds_);
		}

		for (int fd : fds) {
			MysqlxFrontendSession session(fd);
			MysqlxPluginContext& ctx = mysqlx_context();

			if (ctx.config_store && session.run_handshake_and_auth(*ctx.config_store)) {
				// Authentication succeeded.
				// Task 8 will add backend session relay here.
				// For now, send an error indicating no backend and close.
				mysqlx_send_error(fd, 4000, "No backend session available (Phase 1 stub)");
			}
			close(fd);
		}

		if (fds.empty()) {
			struct timespec ts { 0, 50000000 }; // 50ms
			nanosleep(&ts, nullptr);
		}
	}
}

// ---------------------------------------------------------------------------
// Listener management
// ---------------------------------------------------------------------------

bool mysqlx_start_listeners_from_runtime_routes(SQLite3DB& admindb) {
	// Read active routes from runtime_mysqlx_routes.
	char* error = nullptr;
	std::unique_ptr<SQLite3_result> result(
		admindb.execute_statement(
			"SELECT name, bind FROM runtime_mysqlx_routes WHERE active=1",
			&error
		)
	);
	if (error != nullptr) {
		free(error);
		return false;
	}
	if (!result || result->rows.empty()) {
		// No active routes — not an error, just nothing to listen on.
		return true;
	}

	// Open listeners.
	for (auto* row : result->rows) {
		if (row == nullptr || row->fields[0] == nullptr || row->fields[1] == nullptr) {
			continue;
		}

		std::string route_name = row->fields[0];
		std::string bind_str = row->fields[1];
		std::string host {};
		uint16_t port = 0;

		if (!parse_bind(bind_str, host, port)) {
			continue;
		}

		int fd = create_listener_socket(host, port);
		if (fd < 0) {
			continue;
		}

		MysqlxListenerHandle handle {};
		handle.fd = fd;
		handle.bind_address = host;
		handle.port = port;
		handle.route_name = route_name;
		g_listeners.push_back(std::move(handle));
	}

	if (g_listeners.empty()) {
		return true;
	}

	// Start one worker thread (MVP; scale later).
	g_workers.push_back(std::make_unique<MysqlxWorker>(0));
	g_workers.back()->start();

	// Start the accept thread.
	g_accept_running.store(true);
	g_accept_thread = std::thread(accept_loop);

	return true;
}

void mysqlx_stop_listeners() {
	// Signal the accept loop to stop.
	g_accept_running.store(false);
	if (g_accept_thread.joinable()) {
		g_accept_thread.join();
	}

	// Stop all workers.
	for (auto& worker : g_workers) {
		worker->stop();
	}
	g_workers.clear();

	// Close all listener sockets.
	for (auto& listener : g_listeners) {
		if (listener.fd >= 0) {
			close(listener.fd);
			listener.fd = -1;
		}
	}
	g_listeners.clear();
	g_rr_index = 0;
}

size_t mysqlx_listener_count() {
	return g_listeners.size();
}
