#include "mysqlx_thread.h"

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

Mysqlx_Thread::Mysqlx_Thread()
	: thread_index_(0)
	, running_(false)
	, max_cached_(100)
	, signal_pipe_{-1, -1}
	, curtime_(0) {
}

Mysqlx_Thread::~Mysqlx_Thread() {
	stop();

	for (int fd : listener_fds_) {
		close(fd);
	}
	listener_fds_.clear();
	listener_addrs_.clear();

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

	for (int fd : listener_fds_) {
		struct pollfd lpfd;
		lpfd.fd = fd;
		lpfd.events = POLLIN;
		lpfd.revents = 0;
		poll_fds_.push_back(lpfd);
		poll_ds_.push_back(nullptr);
	}

	std::lock_guard<std::mutex> lock(sessions_mutex_);
	for (auto* sess : sessions_) {
		MysqlxDataStream* ds = &sess->client_ds();
		struct pollfd spfd;
		spfd.fd = ds->get_fd();
		spfd.events = POLLIN;
		if (ds->write_buffer_size() > 0) spfd.events |= POLLOUT;
		spfd.revents = 0;
		ds->poll_fds_idx = static_cast<int>(poll_fds_.size());
		poll_fds_.push_back(spfd);
		poll_ds_.push_back(ds);
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
		for (int lfd : listener_fds_) {
			if (lfd == fd) { is_listener = true; break; }
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
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int client_fd = accept(listener_fd, (struct sockaddr*)&addr, &addrlen);
	if (client_fd < 0) return;

	int flag = 1;
	setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

	MysqlxSession* sess = new MysqlxSession();
	sess->init(client_fd, this);
	sess->to_process = true;

	std::lock_guard<std::mutex> lock(sessions_mutex_);
	sessions_.push_back(sess);
}

void Mysqlx_Thread::process_all_sessions() {
	std::lock_guard<std::mutex> lock(sessions_mutex_);
	auto it = sessions_.begin();
	while (it != sessions_.end()) {
		MysqlxSession* sess = *it;
		sess->to_process = true;
		int rc = sess->handler();
		if (!sess->is_healthy() || rc < 0) {
			delete sess;
			it = sessions_.erase(it);
		} else {
			++it;
		}
	}
}

int Mysqlx_Thread::add_listener(const char* bind_addr, int port) {
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

	listener_fds_.push_back(fd);
	if (bind_addr) listener_addrs_.push_back(bind_addr);
	else listener_addrs_.push_back("0.0.0.0");
	return 0;
}

void Mysqlx_Thread::remove_listeners() {
	for (int fd : listener_fds_) {
		close(fd);
	}
	listener_fds_.clear();
	listener_addrs_.clear();
}

int Mysqlx_Thread::get_listener_count() const {
	return static_cast<int>(listener_fds_.size());
}

size_t Mysqlx_Thread::get_session_count() const {
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
