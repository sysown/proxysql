#include "mysqlx_thread.h"
#include "mysqlx_config_store.h"
#include "mysqlx_protocol.h"
#include "proxysql.h"
#include "proxysql_debug.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
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

bool elapsed_exceeds(uint64_t now_ms, uint64_t then_ms, uint64_t limit_ms) {
	return now_ms > then_ms && (now_ms - then_ms) > limit_ms;
}

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
	// Resolve the listener's logical route name from the parallel
	// vectors. The lookup is unconditional (cheap: tens of entries
	// per thread max) so the session can pick up per-route policies
	// such as `tls_mode='passthrough'` before any X-Protocol message
	// arrives. An empty result is fine — sessions with no listener
	// route fall back to the deployment-wide defaults.
	std::string listener_route;
	{
		std::lock_guard<std::mutex> lock(listener_mutex_);
		for (size_t i = 0; i < listener_fds_.size(); ++i) {
			if (listener_fds_[i] == listener_fd) {
				if (i < listener_route_names_.size()) {
					listener_route = listener_route_names_[i];
				}
				break;
			}
		}
	}

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
		sess->init(client_fd, this, listener_route);
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
		//
		// Clear the per-stream revents bitmask AFTER handler() consumes it.
		// process_ready_fds() above writes set_revents(revents) on whichever
		// streams poll() flagged this iteration, but nothing else clears the
		// field — without the post-handler reset here, a session that received
		// one POLLIN event would re-enter handler() every poll cycle (each
		// time hitting EAGAIN) until the stream is closed, defeating the
		// "real work only" gating this whole block was added to provide.
		short c_rev = sess->client_ds().get_revents();
		short s_rev = sess->server_ds().get_revents();
		bool fd_ready = (c_rev != 0) || (s_rev != 0);
		bool buffered = sess->client_ds().has_complete_frame() || sess->server_ds().has_complete_frame();
		int rc = 0;
		if (fd_ready || buffered || sess->to_process) {
			sess->to_process = true;
			rc = sess->handler();
			// Consume the readiness flags so the next iteration only fires
			// on a fresh poll event (or buffered work / explicit to_process).
			sess->client_ds().set_revents(0);
			sess->server_ds().set_revents(0);
		}

		bool timeout = false;
		MysqlxSession::Status st = sess->get_status();
		if (st < MysqlxSession::WAITING_CLIENT_XMSG) {
			timeout = elapsed_exceeds(now, sess->get_start_time(), HANDSHAKE_TIMEOUT_MS);
		} else {
			timeout = elapsed_exceeds(now, sess->get_last_active_time(), IDLE_TIMEOUT_MS);
		}

		if (!sess->is_healthy() || rc < 0 || timeout) {
			delete sess;
			it = sessions_.erase(it);
		} else {
			++it;
		}
	}
}

#ifdef MYSQLX_TEST_BUILD
bool Mysqlx_Thread::elapsed_exceeds_for_test(uint64_t now_ms, uint64_t then_ms, uint64_t limit_ms) {
	return elapsed_exceeds(now_ms, then_ms, limit_ms);
}
#endif

int Mysqlx_Thread::add_listener(const char* bind_addr, int port, const char* route_name) {
	proxy_info("mysqlx: add_listener entered: bind=%s port=%d route=%s\n",
	           bind_addr ? bind_addr : "(null)", port,
	           route_name ? route_name : "(null)");
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		proxy_error("mysqlx: add_listener(%s:%d, route=%s): socket() failed: %s\n",
		            bind_addr ? bind_addr : "(null)", port,
		            route_name ? route_name : "(null)", strerror(errno));
		return -1;
	}

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
		proxy_error("mysqlx: add_listener(%s:%d, route=%s): bind() failed: %s\n",
		            bind_addr ? bind_addr : "(null)", port,
		            route_name ? route_name : "(null)", strerror(errno));
		close(fd);
		return -1;
	}
	if (listen(fd, 128) < 0) {
		proxy_error("mysqlx: add_listener(%s:%d, route=%s): listen() failed: %s\n",
		            bind_addr ? bind_addr : "(null)", port,
		            route_name ? route_name : "(null)", strerror(errno));
		close(fd);
		return -1;
	}
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
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
	proxy_info("mysqlx: add_listener(%s:%d, route=%s): bind+listen OK, fd=%d\n",
	           bind_addr ? bind_addr : "(null)", port,
	           route_name ? route_name : "(null)", fd);
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

namespace {

const char* session_status_to_string(MysqlxSession::Status s) {
	switch (s) {
		case MysqlxSession::NONE:                  return "NONE";
		case MysqlxSession::CONNECTING_CLIENT:     return "CONNECTING_CLIENT";
		case MysqlxSession::X_CAPABILITIES_GET:    return "X_CAPABILITIES_GET";
		case MysqlxSession::X_CAPABILITIES_SET:    return "X_CAPABILITIES_SET";
		case MysqlxSession::X_AUTH_START:          return "X_AUTH_START";
		case MysqlxSession::X_AUTH_CHALLENGE_SENT: return "X_AUTH_CHALLENGE_SENT";
		case MysqlxSession::X_AUTH_OK_SENT:        return "X_AUTH_OK_SENT";
		case MysqlxSession::X_AUTH_FAILED:         return "X_AUTH_FAILED";
		case MysqlxSession::WAITING_CLIENT_XMSG:   return "WAITING_CLIENT_XMSG";
		case MysqlxSession::PROCESSING_X_QUERY:    return "PROCESSING_X_QUERY";
		case MysqlxSession::CONNECTING_SERVER:     return "CONNECTING_SERVER";
		case MysqlxSession::WAITING_SERVER_XMSG:   return "WAITING_SERVER_XMSG";
		case MysqlxSession::X_TLS_ACCEPT_INIT:     return "X_TLS_ACCEPT_INIT";
		case MysqlxSession::X_TLS_ACCEPT_CONT:     return "X_TLS_ACCEPT_CONT";
		case MysqlxSession::X_TLS_ACCEPT_DONE:     return "X_TLS_ACCEPT_DONE";
		case MysqlxSession::X_TLS_CONNECT_INIT:    return "X_TLS_CONNECT_INIT";
		case MysqlxSession::X_TLS_CONNECT_CONT:    return "X_TLS_CONNECT_CONT";
		case MysqlxSession::X_TLS_CONNECT_DONE:    return "X_TLS_CONNECT_DONE";
		case MysqlxSession::X_SESSION_CLOSING:     return "X_SESSION_CLOSING";
		case MysqlxSession::X_SESSION_CLOSED:      return "X_SESSION_CLOSED";
		case MysqlxSession::X_SESSION_RESET_WAITING: return "X_SESSION_RESET_WAITING";
		case MysqlxSession::X_PASSTHROUGH_FORWARD: return "X_PASSTHROUGH_FORWARD";
	}
	return "UNKNOWN";
}

const char* backend_auth_mode_to_string(MysqlxBackendAuthMode m) {
	switch (m) {
		case MysqlxBackendAuthMode::mapped:          return "mapped";
		case MysqlxBackendAuthMode::service_account: return "service_account";
		case MysqlxBackendAuthMode::pass_through:    return "pass_through";
	}
	return "unknown";
}

} // namespace

void Mysqlx_Thread::snapshot_sessions_for_stats(
		std::vector<MysqlxSessionSnapshot>& out, uint64_t now_ms) const {
	std::lock_guard<std::mutex> lock(sessions_mutex_);
	out.reserve(out.size() + sessions_.size());
	for (const MysqlxSession* s : sessions_) {
		if (s == nullptr) continue;
		MysqlxSessionSnapshot row;
		row.username         = s->username_for_stats();
		row.route            = s->route_name_for_stats();
		row.worker_id        = thread_index_;
		row.backend_host     = s->target_address_for_test();
		row.backend_port     = s->target_port_for_test();
		auto id              = s->identity_for_stats();
		row.auth_mode        = id ? backend_auth_mode_to_string(id->backend_auth_mode) : "";
		row.connection_state = session_status_to_string(s->get_status());
		// bytes_in / bytes_out: aggregated per-route in P0; per-session
		// counters land in P1.
		row.bytes_in         = 0;
		row.bytes_out        = 0;
		uint64_t st          = s->start_time_for_stats();
		row.session_age_ms   = (st > 0 && now_ms >= st) ? (now_ms - st) : 0;
		out.push_back(std::move(row));
	}
}

MysqlxConnection* Mysqlx_Thread::get_connection_from_cache(
		int hostgroup, const char* user, const char* schema, bool tls_active) {
	std::lock_guard<std::mutex> lock(conn_cache_mutex_);
	for (auto it = conn_cache_.rbegin(); it != conn_cache_.rend(); ++it) {
		auto* conn = *it;
		// (hostgroup, user, schema, tls_active) is the cache key. The
		// tls_active dimension was added with mysqlx_tls_backend_mode
		// (issue #5693): an AsClient/required encrypted backend must
		// not be handed to a plaintext-frontend session, and a
		// plaintext-pooled backend must not be handed to a TLS
		// session — either would land the next dispatch on a socket
		// in the wrong encryption posture and corrupt the wire
		// protocol.
		if (conn->get_hostgroup() == hostgroup &&
		    strcmp(conn->get_user(), user) == 0 &&
		    strcmp(conn->get_schema(), schema) == 0 &&
		    conn->is_tls_active() == tls_active &&
		    conn->is_reusable()) {
			conn->set_state(MysqlxConnection::IN_USE);
			conn_cache_.erase(std::next(it).base());
			return conn;
		}
	}
	return nullptr;
}

void Mysqlx_Thread::return_connection_to_cache(MysqlxConnection* conn) {
	// Decide reuse BEFORE reset(). reset() unconditionally clears
	// in_transaction_ / has_prepared_stmt_ / sets reusable_=true
	// (mysqlx_connection.cpp::reset). If we called reset first and
	// THEN consulted is_reusable(), every connection — including ones
	// in mid-transaction, ones holding prepared statements, ones the
	// session explicitly marked non-reusable on a backend EOF or read
	// error — would come back as "reusable" and re-enter the cache.
	//
	// is_reusable() also fails if the underlying socket is dead (EOF
	// or read error path in mysqlx_session.cpp::~884 sets reusable_=
	// false before calling return_backend_to_pool); preserving that
	// signal here keeps dead fds out of the cache.
	if (!conn->is_reusable()) {
		delete conn;
		return;
	}
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
