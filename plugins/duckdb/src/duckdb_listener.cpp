#include "duckdb_listener.h"

#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "duckdb_session.h"

#include "proxysql.h"
#include "proxysql_utils.h"
#include "gen_utils.h"
#include "MySQL_Thread.h"
#include "PgSQL_Thread.h"
#include "MySQL_Session.h"
#include "PgSQL_Session.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "MySQL_Protocol.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

// GloMTH is declared extern in include/proxysql_utils.h, which
// wait_for_glo_mth() (also declared there) reads. GloPTH has no such
// central declaration, but this file never needs it directly: per the
// task brief, waiting on GloMTH alone is the documented readiness gate
// for both protocols here (GloMTH and GloPTH are constructed back to
// back, on the same thread, in ProxySQL_Main_init_main_modules() --
// src/main.cpp -- so one becoming visible is a reasonable proxy for the
// other). GloMyQPro/GloPgQPro below are a separate, later readiness gate
// this file DOES need directly (see the comment on them), declared the
// same way every other core .cpp file that touches a Glo* pointer does:
// a local `extern` naming an existing global, not a new one. No header
// in include/ declares either of these two centrally.

// MySQL_Thread::~MySQL_Thread() / PgSQL_Thread::~PgSQL_Thread() (core,
// lib/MySQL_Thread.cpp and lib/PgSQL_Thread.cpp) unconditionally call
// GloMyQPro->end_thread() / GloPgQPro->end_thread() with no null check --
// "only for real threads" per the comment there. GloMTH/GloPTH are
// constructed in Phase 2 (ProxySQL_Main_init_main_modules(), called from
// ProxySQL_Main_init_phase2___not_started() before StartConfiguredPlugins()
// runs -- i.e. before any plugin's start()), but GloMyQPro/GloPgQPro are
// not constructed until Phase 3 (ProxySQL_Main_init_Query_module(), called
// from ProxySQL_Main_init_phase3___start_all(), which runs strictly after
// Phase 2 returns -- see src/main.cpp). So wait_for_glo_mth() alone is not
// enough: a client that connects and disconnects during the Phase 2/Phase 3
// window would construct and then destruct a MySQL_Thread/PgSQL_Thread
// while the matching Query Processor global is still null, crashing inside
// a core destructor we are not allowed to touch. We wait for the second
// global here instead, mirroring wait_for_glo_mth()'s own bound and poll
// interval.
class MySQL_Query_Processor;
class PgSQL_Query_Processor;
extern MySQL_Query_Processor* GloMyQPro;
extern PgSQL_Query_Processor* GloPgQPro;

namespace {

bool wait_for_glo_qpro_mysql() {
	for (int i = 0; i < 200; ++i) { // ~10s total, mirrors wait_for_glo_mth()
		if (GloMyQPro) return true;
		usleep(50000);
	}
	return false;
}

bool wait_for_glo_qpro_pgsql() {
	for (int i = 0; i < 200; ++i) {
		if (GloPgQPro) return true;
		usleep(50000);
	}
	return false;
}

// Best-effort: fills client_addr/client_addrlen and the addr.{addr,port}
// display fields from getpeername(), the same information
// src/SQLite3_Server.cpp's child_mysql fetches lazily on the first loop
// iteration and lib/ProxySQL_Admin.cpp's child_postgres fetches up front
// from the accept()-captured sockaddr. Several core handlers (e.g.
// PgSQL_Session::handler___status_NONE_or_default,
// MySQL_Session::handler___status_WAITING_CLIENT_DATA___default)
// dereference client_myds->client_addr->sa_family unconditionally on an
// unexpected-packet path with no null check, so leaving client_addr null
// is a latent crash the first time a real client trips one of those
// paths, not merely a missing log field.
template <typename DS>
void fill_client_addr(DS* myds, int fd) {
	if (myds->client_addr != nullptr) return;

	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} storage;
	struct sockaddr* addr = (struct sockaddr*)malloc(sizeof(storage));
	memset(addr, 0, sizeof(storage));
	socklen_t addrlen = sizeof(storage);
	// Failure leaves `addr` zeroed (sa_family == 0, unhandled by either
	// switch case below), which is a safe "unknown peer" fallback rather
	// than a null client_addr.
	(void)getpeername(fd, addr, &addrlen);

	myds->client_addrlen = addrlen;
	myds->client_addr = addr;

	char buf[INET6_ADDRSTRLEN];
	switch (addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr;
			inet_ntop(AF_INET, &ipv4->sin_addr, buf, sizeof(buf));
			myds->addr.addr = strdup(buf);
			myds->addr.port = ntohs(ipv4->sin_port);
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr;
			inet_ntop(AF_INET6, &ipv6->sin6_addr, buf, sizeof(buf));
			myds->addr.addr = strdup(buf);
			myds->addr.port = ntohs(ipv6->sin6_port);
			break;
		}
		default:
			myds->addr.addr = strdup("localhost");
			myds->addr.port = 0;
			break;
	}
}

} // namespace

DuckDBListener::~DuckDBListener() {
	stop();
}

bool DuckDBListener::start(DuckDBConfigStore& cfg, DuckDBEngine& engine, std::string& err) {
	if (running_.load()) {
		err = "listener already running";
		return false;
	}

	if (pipe(signal_pipe_) != 0) {
		err = "pipe() failed for the shutdown signal pipe";
		return false;
	}
	for (int fd : signal_pipe_) {
		const int flags = fcntl(fd, F_GETFL, 0);
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	}

	std::vector<Listener> bound;
	auto bind_all = [&](const std::vector<DuckDBIface>& ifaces, Proto proto) -> bool {
		for (const DuckDBIface& iface : ifaces) {
			const int fd = listen_on_port(const_cast<char*>(iface.addr.c_str()), iface.port, 128, true);
			if (fd < 0) {
				err = "listen_on_port failed for " + iface.addr + ":" + std::to_string(iface.port);
				return false;
			}
			bound.push_back(Listener { fd, proto });
		}
		return true;
	};

	if (!bind_all(cfg.mysql_ifaces(), Proto::mysql) || !bind_all(cfg.pgsql_ifaces(), Proto::pgsql)) {
		for (const Listener& l : bound) close(l.fd);
		close(signal_pipe_[0]);
		close(signal_pipe_[1]);
		signal_pipe_[0] = -1;
		signal_pipe_[1] = -1;
		return false;
	}

	listeners_ = std::move(bound);
	engine_ = &engine;
	shutdown_.store(false);
	running_.store(true);
	accept_thread_ = std::thread(&DuckDBListener::accept_loop, this);
	return true;
}

void DuckDBListener::stop() {
	if (!running_.load()) return;

	shutdown_.store(true);
	if (signal_pipe_[1] >= 0) {
		const uint8_t b = 1;
		ssize_t wr = write(signal_pipe_[1], &b, 1);
		(void)wr;
	}
	if (accept_thread_.joinable()) accept_thread_.join();

	for (const Listener& l : listeners_) close(l.fd);
	listeners_.clear();

	std::vector<std::thread> joining;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		joining = std::move(conn_threads_);
		conn_threads_.clear();
	}
	for (std::thread& t : joining) {
		if (t.joinable()) t.join();
	}

	if (signal_pipe_[0] >= 0) close(signal_pipe_[0]);
	if (signal_pipe_[1] >= 0) close(signal_pipe_[1]);
	signal_pipe_[0] = -1;
	signal_pipe_[1] = -1;

	engine_ = nullptr;
	running_.store(false);
	shutdown_.store(false);
}

size_t DuckDBListener::listener_count() const {
	std::lock_guard<std::mutex> lock(mutex_);
	return listeners_.size();
}

size_t DuckDBListener::connection_thread_count() const {
	std::lock_guard<std::mutex> lock(mutex_);
	return conn_threads_.size();
}

void DuckDBListener::accept_loop() {
	std::vector<struct pollfd> fds;

	while (true) {
		fds.clear();
		struct pollfd sp { signal_pipe_[0], POLLIN, 0 };
		fds.push_back(sp);
		for (const Listener& l : listeners_) {
			struct pollfd pfd { l.fd, POLLIN, 0 };
			fds.push_back(pfd);
		}

		const int rc = poll(fds.data(), fds.size(), -1);
		if (rc < 0) {
			if (errno == EINTR) continue;
			break;
		}

		if (fds[0].revents & POLLIN) {
			// Shutdown signal: drain and stop accepting.
			break;
		}

		for (size_t i = 0; i < listeners_.size(); i++) {
			if ((fds[i + 1].revents & POLLIN) == 0) continue;

			struct sockaddr_storage peer {};
			socklen_t peerlen = sizeof(peer);
			const int client_fd = accept(listeners_[i].fd, (struct sockaddr*)&peer, &peerlen);
			if (client_fd < 0) continue;

			// Reserve BEFORE any session object is built: on failure the
			// client just sees a dropped connection instead of a
			// half-built session that would then have to be torn down.
			if (!engine_->try_reserve_connection()) {
				close(client_fd);
				continue;
			}

			const Proto proto = listeners_[i].proto;
			std::lock_guard<std::mutex> lock(mutex_);
			conn_threads_.emplace_back(&DuckDBListener::handle_connection, this, client_fd, proto);
		}
	}
}

void DuckDBListener::handle_connection(int client_fd, Proto proto) {
	if (proto == Proto::mysql) {
		run_session<MySQL_Thread, MySQL_Session*>(client_fd);
	} else {
		run_session<PgSQL_Thread, PgSQL_Session*>(client_fd);
	}
	engine_->release_connection();
}

template <typename Thr, typename Sess>
void DuckDBListener::run_session(int client_fd) {
	// Plugins start() before Phase 3 brings GloMTH/GloPTH fully up, so wait.
	if (!wait_for_glo_mth()) { close(client_fd); return; }
	if (GloMTH == nullptr) { close(client_fd); return; }

	// See the wait_for_glo_qpro_{mysql,pgsql} comment above: without this,
	// deleting `thr` below could run ~MySQL_Thread()/~PgSQL_Thread() while
	// GloMyQPro/GloPgQPro is still null (Phase 2 vs. Phase 3 startup race).
	if constexpr (std::is_same_v<Thr, MySQL_Thread>) {
		if (!wait_for_glo_qpro_mysql()) { close(client_fd); return; }
	} else {
		if (!wait_for_glo_qpro_pgsql()) { close(client_fd); return; }
	}

	DuckDBSessionState& st = duckdb_session_state();
	std::string cerr;
	if (!engine_->connect(&st.conn, cerr)) { close(client_fd); return; }

	Thr* thr = new Thr();
	thr->curtime = monotonic_time();
	// Left null on purpose: core casts gen_args to SQLite3_Session* for
	// PROXYSQL_SESSION_SQLITE and null-checks first. Anything else here
	// would be type confusion.
	thr->gen_args = nullptr;
	thr->refresh_variables();

	auto* sess = thr->template create_new_session_and_client_data_stream<Thr, Sess>(client_fd);
	sess->thread = thr;
	sess->session_type = PROXYSQL_SESSION_SQLITE;
	sess->handler_function = duckdb_session_handler<typename std::remove_pointer<Sess>::type>;

	auto* myds = sess->client_myds;
	fill_client_addr(myds, client_fd);

	if constexpr (std::is_same_v<Thr, MySQL_Thread>) {
		// MySQL speaks first: send the initial handshake packet before
		// waiting on the client for anything.
		if (myds->myprot.generate_pkt_initial_handshake(true, NULL, NULL,
				&sess->thread_session_id, true) == false) {
			engine_->disconnect(&st.conn);
			thr->gen_args = nullptr;
			delete thr;
			return;
		}
	} else {
		// PgSQL's client speaks first (a startup packet). Priming DSS/
		// status here is what makes PgSQL_Session::handler() run the
		// startup/auth exchange when that first packet arrives, exactly
		// as lib/ProxySQL_Admin.cpp's child_postgres does for the admin
		// interface's own PgSQL listener.
		myds->DSS = STATE_SERVER_HANDSHAKE;
		sess->status = CONNECTING_CLIENT;
	}

	struct pollfd fds[1];
	fds[0].fd = client_fd;

	while (shutdown_.load() == false &&
	       __sync_fetch_and_add(&glovars.shutdown, 0) == 0) {
		fds[0].events = myds->available_data_out() ? (POLLIN | POLLOUT) : POLLIN;
		fds[0].revents = 0;
		const int rc = poll(fds, 1, 100);
		if (rc == -1) { if (errno == EINTR) continue; break; }
		myds->revents = fds[0].revents;
		int rb = myds->read_from_net();
		if (myds->net_failure) break;
		myds->read_pkts();
		if (myds->encrypted) {
			while (rb > 0) {
				rb = myds->read_from_net();
				if (myds->net_failure) break;
				myds->read_pkts();
			}
			if (myds->net_failure) break;
		}
		sess->to_process = 1;
		if (sess->handler() == -1) break;
	}

	engine_->disconnect(&st.conn);
	thr->gen_args = nullptr;
	delete thr;
}
