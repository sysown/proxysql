#include "mysqlx_thread.h"
#include "mysqlx_config_store.h"
#include "mysqlx_protocol.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <algorithm>

#include "proxysql_structs.h"

namespace {

uint64_t monotonic_time_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1000 + static_cast<uint64_t>(ts.tv_nsec) / 1000000;
}

constexpr uint64_t HANDSHAKE_TIMEOUT_MS = 10000;
constexpr uint64_t IDLE_TIMEOUT_MS = 28800000;

}

Mysqlx_Thread::Mysqlx_Thread()
	: thread_index_(0)
	, running_(false)
	, max_cached_(100)
	, max_sessions_(10000)
	, signal_pipe_{-1, -1}
	, config_store_(nullptr), curtime_(0) {
}

Mysqlx_Thread::~Mysqlx_Thread() {
	stop();

	{
		std::lock_guard<std::mutex> lock(listener_mutex_);
		for (int fd : listener_fds_) {
			close(fd);
		}
		listener_fds_.clear();
		listener_addrs_.clear();
		listener_ports_.clear();
		listener_route_names_.clear();
	}

	for (auto* sess : sessions_) {
		delete sess;
	}
	sessions_.clear();

	for (auto* conn : conn_cache_) {
		delete conn;
	}
	conn_cache_.clear();

	if (signal_pipe_[0] >= 0) close(signal_pipe_[0]);
	if (signal_pipe_[1] >= 0) close(signal_pipe_[1]);
}

void Mysqlx_Thread::init(int thread_index) {
	thread_index_ = thread_index;
	running_ = false;
	max_cached_ = 100;

	if (pipe(signal_pipe_) < 0) {
		signal_pipe_[0] = -1;
		signal_pipe_[1] = -1;
	} else {
		int flags = fcntl(signal_pipe_[0], F_GETFL, 0);
		fcntl(signal_pipe_[0], F_SETFL, flags | O_NONBLOCK);
	}
}

bool Mysqlx_Thread::start() {
	if (running_.load()) return false;
	running_ = true;
	thread_ = std::thread(&Mysqlx_Thread::run, this);
	return true;
}

void Mysqlx_Thread::stop() {
	if (!running_.load()) return;
	running_ = false;

	if (signal_pipe_[1] >= 0) {
		uint8_t b = 1;
		ssize_t wr = write(signal_pipe_[1], &b, 1);
		(void)wr;
	}

	if (thread_.joinable()) {
		thread_.join();
	}
}

void Mysqlx_Thread::run() {
	while (running_.load()) {
		curtime_ = static_cast<uint64_t>(time(nullptr));
		rebuild_poll_set();
		int nfds = static_cast<int>(poll_fds_.size());
		int rc = poll(poll_fds_.data(), nfds, 200);
		if (rc < 0) {
			if (errno == EINTR) continue;
			break;
		}
		if (rc > 0) process_ready_fds(nfds);
		process_all_sessions();
	}

	// Shutdown drain. The destructor will close fds and free sessions
	// shortly after we return. Before that, give every still-connected
	// client a clean X-Protocol Error frame (code 1053, "Server is
	// shutting down") plus a TLS close_notify so peers see a graceful
	// teardown rather than an unannounced TCP RST or a torn TLS record.
	// Best-effort: a single non-blocking write pass per session and a
	// quiet-shutdown SSL_shutdown, since process exit is imminent and
	// we cannot block on unresponsive peers.
	std::lock_guard<std::mutex> lock(sessions_mutex_);
	for (auto* sess : sessions_) {
		if (sess) sess->shutdown_notify_client();
	}
}

void Mysqlx_Thread::rebuild_poll_set() {
	poll_fds_.clear();
	poll_ds_.clear();

	struct pollfd pfd;
	pfd.fd = signal_pipe_[0];
	pfd.events = POLLIN;
	pfd.revents = 0;
	poll_fds_.push_back(pfd);
	poll_ds_.push_back(nullptr);

	{
		std::lock_guard<std::mutex> lock(listener_mutex_);
		for (int fd : listener_fds_) {
			struct pollfd lpfd;
			lpfd.fd = fd;
			lpfd.events = POLLIN;
			lpfd.revents = 0;
			poll_fds_.push_back(lpfd);
			poll_ds_.push_back(nullptr);
		}
	}

	std::lock_guard<std::mutex> lock(sessions_mutex_);
	for (auto* sess : sessions_) {
		MysqlxDataStream* cds = &sess->client_ds();
		struct pollfd spfd;
		spfd.fd = cds->get_fd();
		spfd.events = POLLIN;
		if (cds->write_buffer_size() > 0 || cds->has_ssl_pending_write()) spfd.events |= POLLOUT;
		spfd.revents = 0;
		cds->poll_fds_idx = static_cast<int>(poll_fds_.size());
		poll_fds_.push_back(spfd);
		poll_ds_.push_back(cds);

		MysqlxDataStream* sds = &sess->server_ds();
		if (sds->get_fd() >= 0 && sds->get_status() == XDS_READY) {
			struct pollfd bpfd;
			bpfd.fd = sds->get_fd();
			bpfd.events = POLLIN;
			if (sds->write_buffer_size() > 0 || sds->has_ssl_pending_write()) bpfd.events |= POLLOUT;
			bpfd.revents = 0;
			sds->poll_fds_idx = static_cast<int>(poll_fds_.size());
			poll_fds_.push_back(bpfd);
			poll_ds_.push_back(sds);
		}
	}
}

void Mysqlx_Thread::process_ready_fds(int nfds) {
	for (int n = 0; n < nfds; n++) {
		short revents = poll_fds_[n].revents;
		if (revents == 0) continue;

		if (n == 0) {
			uint8_t buf[64];
			while (read(signal_pipe_[0], buf, sizeof(buf)) > 0) {}
			continue;
		}

		int fd = poll_fds_[n].fd;

		bool is_listener = false;
		{
			std::lock_guard<std::mutex> lock(listener_mutex_);
			for (int lfd : listener_fds_) {
				if (lfd == fd) { is_listener = true; break; }
			}
		}
		if (is_listener && (revents & POLLIN)) {
			accept_new_connection(fd);
			continue;
		}

		MysqlxDataStream* ds = poll_ds_[n];
		if (ds) {
			ds->set_revents(revents);
		}
	}
}

void Mysqlx_Thread::accept_new_connection(int listener_fd) {
	while (true) {
		struct sockaddr_in addr;
		socklen_t addrlen = sizeof(addr);
		int client_fd = accept(listener_fd, (struct sockaddr*)&addr, &addrlen);
		if (client_fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) break;
			if (errno == EINTR) continue;
			break;
		}

		{
			std::lock_guard<std::mutex> lock(sessions_mutex_);
			if (sessions_.size() >= max_sessions_) {
				close(client_fd);
				break;
			}
		}

		int flag = 1;
		setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

		MysqlxSession* sess = new MysqlxSession();
		sess->init(client_fd, this);
		sess->to_process = true;

		const MysqlxConfigStore* store = config_store_;
		sess->set_identity_lookup(
			[store](const std::string& username) -> std::optional<MysqlxResolvedIdentity> {
				if (!store) return std::nullopt;
				return store->resolve_identity(username);
			}
		);

		std::lock_guard<std::mutex> lock(sessions_mutex_);
		sessions_.push_back(sess);
	}
}

void Mysqlx_Thread::process_all_sessions() {
	uint64_t now = monotonic_time_ms();
	std::lock_guard<std::mutex> lock(sessions_mutex_);
	auto it = sessions_.begin();
	while (it != sessions_.end()) {
		MysqlxSession* sess = *it;

		// Only invoke handler() when there is real work: a poll event landed
		// on either data stream, the session asked to be re-run, or there are
		// already-buffered frames to dispatch. Forcing to_process=true on every
		// tick burned the CPU at large session counts.
		short c_rev = sess->client_ds().get_revents();
		short s_rev = sess->server_ds().get_revents();
		bool fd_ready = (c_rev != 0) || (s_rev != 0);
		bool buffered = sess->client_ds().has_complete_frame() || sess->server_ds().has_complete_frame();
		int rc = 0;
		if (fd_ready || buffered || sess->to_process) {
			sess->to_process = true;
			rc = sess->handler();
		}

		bool timeout = false;
		MysqlxSession::Status st = sess->get_status();
		if (st < MysqlxSession::WAITING_CLIENT_XMSG) {
			timeout = (now - sess->get_start_time()) > HANDSHAKE_TIMEOUT_MS;
		} else {
			timeout = (now - sess->get_last_active_time()) > IDLE_TIMEOUT_MS;
		}

		if (!sess->is_healthy() || rc < 0 || timeout) {
			delete sess;
			it = sessions_.erase(it);
		} else {
			++it;
		}
	}
}

int Mysqlx_Thread::add_listener(const char* bind_addr, int port, const char* route_name) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;

	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind_addr && strlen(bind_addr) > 0 && strcmp(bind_addr, "0.0.0.0") != 0) {
		inet_pton(AF_INET, bind_addr, &addr.sin_addr);
	} else {
		addr.sin_addr.s_addr = INADDR_ANY;
	}

	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	if (listen(fd, 128) < 0) {
		close(fd);
		return -1;
	}

	{
		std::lock_guard<std::mutex> lock(listener_mutex_);
		listener_fds_.push_back(fd);
		if (bind_addr) listener_addrs_.push_back(bind_addr);
		else listener_addrs_.push_back("0.0.0.0");
		listener_ports_.push_back(port);
		listener_route_names_.push_back(route_name != nullptr ? route_name : "");
	}
	return 0;
}

// Removes the listener fd associated with `route_name`. Sessions that
// were already accepted on this listener and are mid-flight are NOT
// disturbed — they continue against their existing target_hostgroup_ /
// target_address_ / target_port_ until they finish their current
// transaction or hit idle timeout. This matches the surrounding
// MySQL-protocol behaviour (DROP TABLE doesn't cancel in-flight
// queries; an ALTER doesn't kick off open prepared statements). The
// route name is consulted at backend-target resolution time which only
// happens during auth, so an authenticated session does not depend on
// the route name still being live. If a future use case requires
// active disconnection of in-flight sessions on route removal, walk
// sessions_ here, match identity_->default_route, and call
// shutdown_notify_client() on each.
bool Mysqlx_Thread::remove_listener_for_route(const char* route_name) {
	if (route_name == nullptr) return false;
	std::lock_guard<std::mutex> lock(listener_mutex_);
	for (size_t i = 0; i < listener_route_names_.size(); i++) {
		if (listener_route_names_[i] == route_name) {
			close(listener_fds_[i]);
			listener_fds_.erase(listener_fds_.begin() + i);
			listener_addrs_.erase(listener_addrs_.begin() + i);
			listener_ports_.erase(listener_ports_.begin() + i);
			listener_route_names_.erase(listener_route_names_.begin() + i);
			return true;
		}
	}
	return false;
}

std::string Mysqlx_Thread::get_listener_addr_for_route(const std::string& route_name) const {
	std::lock_guard<std::mutex> lock(listener_mutex_);
	for (size_t i = 0; i < listener_route_names_.size(); i++) {
		if (listener_route_names_[i] == route_name) {
			return listener_addrs_[i] + ":" + std::to_string(listener_ports_[i]);
		}
	}
	return "";
}

void Mysqlx_Thread::remove_listeners() {
	std::lock_guard<std::mutex> lock(listener_mutex_);
	for (int fd : listener_fds_) {
		close(fd);
	}
	listener_fds_.clear();
	listener_addrs_.clear();
	listener_ports_.clear();
	listener_route_names_.clear();
}

int Mysqlx_Thread::get_listener_count() const {
	return static_cast<int>(listener_fds_.size());
}

size_t Mysqlx_Thread::get_session_count() const {
	std::lock_guard<std::mutex> lock(sessions_mutex_);
	return sessions_.size();
}

MysqlxConnection* Mysqlx_Thread::get_connection_from_cache(
		int hostgroup, const char* user, const char* schema) {
	std::lock_guard<std::mutex> lock(conn_cache_mutex_);
	for (auto it = conn_cache_.rbegin(); it != conn_cache_.rend(); ++it) {
		auto* conn = *it;
		if (conn->get_hostgroup() == hostgroup &&
		    strcmp(conn->get_user(), user) == 0 &&
		    strcmp(conn->get_schema(), schema) == 0 &&
		    conn->is_reusable()) {
			conn->set_state(MysqlxConnection::IN_USE);
			conn_cache_.erase(std::next(it).base());
			return conn;
		}
	}
	return nullptr;
}

void Mysqlx_Thread::return_connection_to_cache(MysqlxConnection* conn) {
	conn->reset();
	std::lock_guard<std::mutex> lock(conn_cache_mutex_);
	if (conn_cache_.size() >= max_cached_) {
		delete conn_cache_.front();
		conn_cache_.erase(conn_cache_.begin());
	}
	conn_cache_.push_back(conn);
}

size_t Mysqlx_Thread::get_cached_connection_count() const {
	return conn_cache_.size();
}

SSL_CTX* Mysqlx_Thread::get_ssl_ctx() const {
	return GloVars.get_SSL_ctx();
}
