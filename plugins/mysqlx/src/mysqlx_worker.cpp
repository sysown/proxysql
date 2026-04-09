#include "mysqlx_worker.h"

#include "mysqlx_backend_session.h"
#include "mysqlx_frontend_session.h"
#include "mysqlx_plugin.h"
#include "mysqlx_stats.h"
#include "sqlite3db.h"

#include <arpa/inet.h>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

// Global listener state, managed by mysqlx_start/stop_listeners.
std::vector<MysqlxListenerHandle> g_listeners {};
std::vector<std::unique_ptr<MysqlxWorker>> g_workers {};
std::atomic<bool> g_accept_running { false };
std::thread g_accept_thread {};
std::atomic<uint32_t> g_rr_index { 0 };

bool parse_bind(const std::string& bind, std::string& host, uint16_t& port) {
	if (!bind.empty() && bind[0] == '[') {
		auto closing = bind.find(']');
		if (closing != std::string::npos) {
			host = bind.substr(1, closing - 1);
			port = 33060;
			if (closing + 1 < bind.size() && bind[closing + 1] == ':') {
				port = static_cast<uint16_t>(std::atoi(bind.substr(closing + 2).c_str()));
			}
			return true;
		}
	}
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
	std::string port_str = std::to_string(port);
	struct addrinfo hints {}, *result = nullptr;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(host.empty() ? nullptr : host.c_str(), port_str.c_str(), &hints, &result) != 0) {
		return -1;
	}

	int fd = -1;
	for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0) continue;

		int opt = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

		int nodelay = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen(fd, 128) == 0) {
			break;
		}
		close(fd);
		fd = -1;
	}
	freeaddrinfo(result);

	return fd;
}

void accept_loop() {
	while (g_accept_running.load()) {
		// Build pollfd array from listeners.
		std::vector<struct pollfd> pfds {};
		for (const auto& listener : g_listeners) {
			if (listener.fd >= 0) {
				pfds.push_back({ listener.fd, POLLIN, 0 });
			}
		}

		if (pfds.empty()) {
			struct timespec ts { 0, 100000000 }; // 100ms
			nanosleep(&ts, nullptr);
			continue;
		}

		int ready = poll(pfds.data(), static_cast<nfds_t>(pfds.size()), 200 /*ms*/);
		if (ready <= 0) {
			continue;
		}

		for (const auto& pfd : pfds) {
			if (pfd.revents & POLLIN) {
				int client_fd = accept(pfd.fd, nullptr, nullptr);
				if (client_fd < 0) {
					continue;
				}

				int nodelay = 1;
				setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

				if (!g_workers.empty()) {
					uint32_t idx = g_rr_index.fetch_add(1, std::memory_order_relaxed)
					             % static_cast<uint32_t>(g_workers.size());
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
				// Capture topology generation at session bind time.
				// A future GR observer only needs to call bump_topology_generation()
				// to trigger re-evaluation on the next session or reconnect.
				uint64_t bound_generation = ctx.config_store->topology_generation();
				(void)bound_generation; // Phase 2 seam: compare on reconnect/reroute.

				const MysqlxResolvedIdentity& identity = session.identity();
				MysqlxBackendEndpoint endpoint = ctx.config_store->pick_endpoint(identity.default_route);

				if (endpoint.hostname.empty()) {
					mysqlx_send_error(fd, 4000, "No backend endpoint available for route");
					int hg = ctx.config_store->route_hostgroup(identity.default_route);
					mysqlx_stats().record_conn_err(identity.default_route, hg);
				} else {
					MysqlxBackendSession backend;
					std::string err {};
					int hg = ctx.config_store->route_hostgroup(identity.default_route);
					if (backend.connect(identity, endpoint, err)) {
						mysqlx_stats().record_conn_ok(identity.default_route, hg);
						mysqlx_stats().record_conn_used(identity.default_route, hg);
						backend.relay(fd);
					} else {
						mysqlx_send_error(fd, 4001, "Backend connection failed: " + err);
						mysqlx_stats().record_conn_err(identity.default_route, hg);
					}
				}
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
