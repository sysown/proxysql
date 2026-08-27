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
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"

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

// `shutdown_flag` is DuckDBListener::shutdown_, checked alongside
// glovars.shutdown (process-wide shutdown) so a thread parked here
// during a plugin unload or process shutdown gives up within one
// 50ms tick instead of riding out the full ~10s bound -- mirroring
// the idiom lib/ProxySQL_Admin.cpp:2208 uses around wait_for_glo_mth():
// "if (shutdown || !wait_for_glo_mth() || !GloMTH)". wait_for_glo_mth()
// itself is core and cannot be changed to check shutdown internally;
// these two gates are ours, so they can and do.
bool wait_for_glo_qpro_mysql(const std::atomic<bool>& shutdown_flag) {
	for (int i = 0; i < 200; ++i) { // ~10s total, mirrors wait_for_glo_mth()
		if (shutdown_flag.load() || __sync_fetch_and_add(&glovars.shutdown, 0) != 0) return false;
		if (GloMyQPro) return true;
		usleep(50000);
	}
	return false;
}

bool wait_for_glo_qpro_pgsql(const std::atomic<bool>& shutdown_flag) {
	for (int i = 0; i < 200; ++i) {
		if (shutdown_flag.load() || __sync_fetch_and_add(&glovars.shutdown, 0) != 0) return false;
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

	std::vector<ConnThread> joining;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		joining = std::move(conn_threads_);
		conn_threads_.clear();
	}
	for (ConnThread& c : joining) {
		if (c.th.joinable()) c.th.join();
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

// Sweeps conn_threads_ for entries whose handle_connection() has already
// returned (done->load() == true), joins them and erases them. A
// finished-but-unjoined std::thread stays joinable and keeps its OS
// thread control block and stack alive, so without this every
// connection ever served would leak those resources for the life of the
// listener -- conn_threads_ would only ever shrink in stop(). Called
// once per accept_loop() wakeup, so reaping keeps pace with connection
// churn even when nothing new is being accepted.
//
// Mirrors stop()'s own "move out under the lock, join outside it" shape
// for the same reason stop() uses it: join() must never run while
// mutex_ is held, or every other mutex_ user (accept_loop()'s own
// push_back later in this function, connection_thread_count(),
// listener_count(), and stop()'s move-out step) stalls for however long
// the OS takes to finish tearing the thread down -- an interval that,
// unlike done->load(), is not contractually bounded.
//
// This cannot double-join against stop(): both this function and
// stop()'s harvest step remove an entry from conn_threads_ only while
// holding mutex_, so whichever of the two reaches a given entry first
// takes it out of conn_threads_ inside that critical section, and the
// other can no longer see it there to move out (or join) a second time.
// A given ConnThread therefore ends up in exactly one local vector --
// `finished` here or `joining` in stop() -- never both. (In practice the
// two never even run concurrently: reap_finished_threads() only runs on
// accept_thread_, and stop() only reaches its own conn_threads_ access
// after accept_thread_.join() has returned, i.e. after accept_loop() --
// and therefore every call to this function -- has already finished.
// The move-out-under-lock discipline holds regardless of that ordering,
// so the no-double-join property doesn't depend on it either.)
void DuckDBListener::reap_finished_threads() {
	std::vector<ConnThread> finished;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		for (auto it = conn_threads_.begin(); it != conn_threads_.end(); ) {
			if (it->done->load()) {
				finished.push_back(std::move(*it));
				it = conn_threads_.erase(it);
			} else {
				++it;
			}
		}
	}
	for (ConnThread& c : finished) {
		if (c.th.joinable()) c.th.join();
	}
}

void DuckDBListener::accept_loop() {
	std::vector<struct pollfd> fds;

	while (true) {
		// Reap before (re)building the poll set: keeps conn_threads_ (and
		// connection_thread_count()) close to "currently active" even
		// during a quiet period with no new connections, since the bounded
		// timeout below guarantees this loop wakes up periodically either
		// way.
		reap_finished_threads();

		fds.clear();
		struct pollfd sp { signal_pipe_[0], POLLIN, 0 };
		fds.push_back(sp);
		for (const Listener& l : listeners_) {
			struct pollfd pfd { l.fd, POLLIN, 0 };
			fds.push_back(pfd);
		}

		// Bounded (not infinite) so a quiet listener still wakes up
		// regularly to reap finished connection threads; 100ms matches
		// the per-connection loop's own poll timeout in run_session().
		const int rc = poll(fds.data(), fds.size(), 100);
		if (rc < 0) {
			if (errno == EINTR) continue;
			break;
		}
		if (rc == 0) continue; // timeout: nothing to accept, loop back to reap

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
			auto done = std::make_shared<std::atomic<bool>>(false);
			std::thread th(&DuckDBListener::handle_connection, this, client_fd, proto, done);
			std::lock_guard<std::mutex> lock(mutex_);
			conn_threads_.push_back(ConnThread { std::move(th), std::move(done) });
		}
	}
}

void DuckDBListener::handle_connection(int client_fd, Proto proto, std::shared_ptr<std::atomic<bool>> done) {
	if (proto == Proto::mysql) {
		run_session<MySQL_Thread, MySQL_Session*>(client_fd);
	} else {
		run_session<PgSQL_Thread, PgSQL_Session*>(client_fd);
	}
	engine_->release_connection();
	// Signals reap_finished_threads() that this entry can be joined and
	// erased. Set last: everything this thread touches (engine_, the
	// session/thread it built) is done by this point.
	done->store(true);
}

template <typename Thr, typename Sess>
void DuckDBListener::run_session(int client_fd) {
	// Mirrors lib/ProxySQL_Admin.cpp:2208's
	// "if (shutdown || !wait_for_glo_mth() || !GloMTH)" idiom: check
	// shutdown first so an already-shutting-down process/listener never
	// even enters wait_for_glo_mth()'s own (unshutdown-aware, core,
	// unmodifiable) up-to-10s poll.
	if (shutdown_.load() || __sync_fetch_and_add(&glovars.shutdown, 0) != 0) {
		close(client_fd);
		return;
	}
	// Plugins start() before Phase 3 brings GloMTH/GloPTH fully up, so wait.
	if (!wait_for_glo_mth()) { close(client_fd); return; }
	if (GloMTH == nullptr) { close(client_fd); return; }

	// See the wait_for_glo_qpro_{mysql,pgsql} comment above: without this,
	// deleting `thr` below could run ~MySQL_Thread()/~PgSQL_Thread() while
	// GloMyQPro/GloPgQPro is still null (Phase 2 vs. Phase 3 startup race).
	// shutdown_ is passed through so these gates give up promptly on
	// shutdown instead of riding out their own ~10s bound (Finding 1).
	if constexpr (std::is_same_v<Thr, MySQL_Thread>) {
		if (!wait_for_glo_qpro_mysql(shutdown_)) { close(client_fd); return; }
	} else {
		if (!wait_for_glo_qpro_pgsql(shutdown_)) { close(client_fd); return; }
	}

	DuckDBSessionState& st = duckdb_session_state();
	std::string cerr;
	if (!engine_->connect(&st.conn, cerr)) { close(client_fd); return; }

	Thr* thr = new Thr();
	thr->curtime = monotonic_time();
	// Required per-thread Query_Processor init. MySQL_Thread::init() /
	// PgSQL_Thread::init() -- the canonical thread-startup path used by
	// every other core accept loop, including src/SQLite3_Server.cpp's own
	// child_mysql() for the same PROXYSQL_SESSION_SQLITE session type --
	// always call GloMyQPro->init_thread() / GloPgQPro->init_thread()
	// before refresh_variables(). This constructs `Thr` directly via
	// `new Thr()` rather than through init(), so without this call the
	// thread-local Query_Processor rule table (_thr_SQP_rules, a `__thread`
	// pointer -- lib/Query_Processor.cpp) is left null for the life of the
	// thread. MySQL_Session::handler()'s query-processing path is not
	// skipped for PROXYSQL_SESSION_SQLITE (only the eventual backend-routing
	// decision is, via the plugin's handler_function); left uninitialized,
	// every query on this connection hung indefinitely with its
	// connection thread spinning at ~100% CPU instead of returning a
	// response -- reproduced end-to-end (Task 9) with a real MySQL client:
	// AUTH completes, but SELECT 42 (and even the @@VERSION fast-path
	// query) never got a reply. Confirmed fixed by adding this call:
	// query round-trip time went from "never returns" to ~4ms.
	// ~MySQL_Thread()/~PgSQL_Thread() unconditionally call end_thread()
	// (see the wait_for_glo_qpro_{mysql,pgsql} comment above), so leaving
	// init_thread() uncalled also meant end_thread() ran against never-
	// initialized per-thread state on every connection teardown. The
	// pairing is symmetric for both protocols: register_session() (called
	// from create_new_session_and_client_data_stream() below, via
	// Base_Thread.cpp) self-allocates `mysql_sessions` the first time a
	// session is registered on a thread that skipped init(), so the
	// destructor's `if (mysql_sessions)` guard around end_thread() is true
	// regardless -- end_thread() always ran here, unpaired, before this
	// fix. And this call site sits after the wait_for_glo_qpro_{mysql,
	// pgsql} gate above, so GloMyQPro/GloPgQPro are already confirmed
	// non-null by the time either init_thread() call below runs.
	if constexpr (std::is_same_v<Thr, MySQL_Thread>) {
		GloMyQPro->init_thread();
	} else {
		GloPgQPro->init_thread();
	}
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
		// Refreshed every iteration, matching lib/ProxySQL_Admin.cpp's
		// child_postgres (not src/SQLite3_Server.cpp's child_mysql, which
		// omits it but only ever serves short admin queries). thr->curtime
		// feeds CurrentQuery.start_time and session-age/timeout
		// comparisons; this plugin serves long-lived analytical
		// connections, so a value set once before the loop would go ever
		// staler for the connection's whole lifetime.
		thr->curtime = monotonic_time();
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
