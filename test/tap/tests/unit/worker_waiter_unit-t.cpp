#include "tap.h"

#ifdef __linux__
/**
 * Exercise real worker queue/poll cleanup at the handler boundary. The linked
 * handler doubles supply terminal/error/continued-wait outcomes without a
 * backend; session, stream, poll and worker lifetimes are production code.
 */
#include <any>
#include <sstream>
#include <type_traits>
#include <sys/socket.h>
#include <unistd.h>
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#define private public
#include "cpp.h"
#undef private
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"

extern PgSQL_Threads_Handler *GloPTH;
extern MySQL_Logger *GloMyLogger;
extern PgSQL_Logger *GloPgSQL_Logger;

enum class Outcome { wait, complete, error, killed };
static void *subject;
static Outcome outcome;
static unsigned other_calls;
template<class Session> int handle(Session *sess) {
	if (sess != subject) { ++other_calls; return 0; }
	if (outcome == Outcome::complete) sess->status = WAITING_CLIENT_DATA;
	if (outcome == Outcome::killed) sess->killed = true;
	return outcome == Outcome::error ? -1 : 0;
}
extern "C" int __wrap__ZN13MySQL_Session7handlerEv(MySQL_Session *s) { return handle(s); }
extern "C" int __wrap__ZN13PgSQL_Session7handlerEv(PgSQL_Session *s) { return handle(s); }

template<class Worker, class Session, class Stream>
Session *new_waiter(Worker& worker, int& peer) {
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) BAIL_OUT("socketpair failed");
	peer = fds[1];
	auto *sess = new Session();
	sess->connections_handler = true;
	sess->thread = &worker;
	sess->status = CONNECTING_SERVER;
	sess->client_myds = new Stream();
	sess->client_myds->sess = sess;
	sess->client_myds->myds_type = MYDS_FRONTEND;
	sess->client_myds->fd = fds[0];
	sess->client_myds->addr.addr = strdup("unit-client");
	sess->last_pool_ff = false;
	sess->last_pool_gtid = false;
	sess->last_pool_max_lag_ms = -1;
	worker.mysql_sessions->add(sess);
	worker.mypolls.add(POLLIN, fds[0], sess->client_myds, worker.curtime);
	worker.enter_waiter(sess, 1);
	return sess;
}

template<class Worker, class Session, class Stream>
void test_protocol(const char *name) {
	Worker worker;
	if (!worker.init()) BAIL_OUT("worker init failed");
	worker.maintenance_loop = false;
	worker.curtime = 1000000;
	const unsigned baseline_polls = worker.mypolls.len;
	for (Outcome expected : {Outcome::complete, Outcome::error, Outcome::killed, Outcome::wait}) {
		int peer;
		Session *sess = new_waiter<Worker, Session, Stream>(worker, peer);
		subject = sess;
		outcome = expected;
		worker.process_all_sessions();
		const bool terminal = expected == Outcome::error || expected == Outcome::killed;
		const bool waiting = expected == Outcome::wait;
		ok(worker.waiter_lists.empty() != waiting, "%s: outcome %d retains only active checkout waiters", name, int(expected));
		ok(worker.mysql_sessions->len == (terminal ? 0u : 1u), "%s: outcome %d disposes only terminal sessions", name, int(expected));
		ok(worker.mypolls.len == baseline_polls + (expected == Outcome::complete ? 1u : 0u), "%s: outcome %d restores polling only for a live completed client", name, int(expected));
		while (worker.mysql_sessions->len) {
			auto *s = static_cast<Session*>(worker.mysql_sessions->index(0));
			worker.unregister_session(0);
			delete s;
		}
		close(peer);
	}
	// A completed head must not block the next live waiter in the same hostgroup.
	for (Outcome expected : {Outcome::complete, Outcome::error, Outcome::wait}) {
		int first_peer, second_peer;
		subject = new_waiter<Worker, Session, Stream>(worker, first_peer);
		new_waiter<Worker, Session, Stream>(worker, second_peer);
		outcome = expected;
		other_calls = 0;
		worker.process_all_sessions();
		ok(other_calls == (expected == Outcome::wait ? 0u : 1u), "%s: head outcome %d advances only after the head finishes", name, int(expected));
		while (worker.mysql_sessions->len) {
			auto *s = static_cast<Session*>(worker.mysql_sessions->index(0));
			worker.unregister_session(0);
			delete s;
		}
		close(first_peer);
		close(second_peer);
	}
	int killed_peer;
	auto *killed = new_waiter<Worker, Session, Stream>(worker, killed_peer);
	killed->pause_until = worker.curtime + 10000000;
	killed->killed = true;
	subject = killed;
	outcome = Outcome::wait;
	worker.process_all_sessions();
	ok(worker.mysql_sessions->len == 0 && worker.waiter_lists.empty(), "%s: kill is honored while a waiter is paused", name);
	close(killed_peer);

	int head_peer, tail_peer;
	subject = new_waiter<Worker, Session, Stream>(worker, head_peer);
	auto *tail = new_waiter<Worker, Session, Stream>(worker, tail_peer);
	tail->killed = true;
	outcome = Outcome::wait;
	worker.process_all_sessions();
	ok(worker.mysql_sessions->len == 1, "%s: a still-starved head cannot prevent cleanup of a killed tail", name);
	while (worker.mysql_sessions->len) {
		auto *s = static_cast<Session*>(worker.mysql_sessions->index(0));
		worker.unregister_session(0);
		delete s;
	}
	close(head_peer);
	close(tail_peer);

	int first_fd, middle_fd, last_fd;
	auto *first = new_waiter<Worker, Session, Stream>(worker, first_fd);
	auto *middle = new_waiter<Worker, Session, Stream>(worker, middle_fd);
	auto *last = new_waiter<Worker, Session, Stream>(worker, last_fd);
	worker.leave_waiter(first);
	worker.leave_waiter(middle);
	worker.leave_waiter(last);
	const int middle_idx = middle->client_myds->poll_fds_idx;
	worker.drop_from_poll(middle->client_myds);
	ok(last->client_myds->poll_fds_idx == middle_idx && worker.mypolls.myds[middle_idx] == last->client_myds,
		"%s: indexed removal preserves the moved stream registration", name);
	worker.drop_from_poll(last->client_myds);
	worker.drop_from_poll(last->client_myds);
	ok(worker.mypolls.len == baseline_polls + 1 && first->client_myds->poll_fds_idx >= 0,
		"%s: removing a swapped or already absent stream preserves its peers", name);
	// Exercise the defensive fallback without removing the stream at the stale index.
	first->client_myds->poll_fds_idx = int(worker.mypolls.len) + 5;
	worker.drop_from_poll(first->client_myds);
	ok(worker.mypolls.len == baseline_polls && first->client_myds->mypolls == nullptr,
		"%s: inconsistent index falls back to safe removal", name);
	while (worker.mysql_sessions->len) {
		auto *s = static_cast<Session*>(worker.mysql_sessions->index(0));
		worker.unregister_session(0);
		delete s;
	}
	close(first_fd);
	close(middle_fd);
	close(last_fd);

	// A stream destructor must remove its poll entry even when the session is
	// deleted directly, as happens during worker shutdown.
	int peer;
	auto *sess = new_waiter<Worker, Session, Stream>(worker, peer);
	worker.mysql_sessions->remove_index_fast(0);
	delete sess;
	ok(worker.mypolls.len == baseline_polls && worker.waiter_lists.empty(), "%s: direct waiter destruction leaves no dangling poll entry", name);
	close(peer);
}

// A real processlist request must tolerate clients deliberately removed from
// poll, and preserve the timestamp behavior of clients still registered there.
template<class Worker, class Session, class Stream, class Connection, class Manager, class Slot>
void test_processlist(const char *name, Manager *manager, Slot *&slots, unsigned time_column) {
	Worker worker;
	if (!worker.init()) BAIL_OUT("worker init failed");
	worker.curtime = 1000000;
	Slot slot {};
	slot.worker = &worker;
	auto *saved_slots = slots;
	auto saved_threads = manager->num_threads;
	slots = &slot;
	manager->num_threads = 1;
	int peer;
	auto *sess = new_waiter<Worker, Session, Stream>(worker, peer);
	if constexpr (std::is_same<Connection, PgSQL_Connection>::value)
		sess->client_myds->myconn = new Connection(true);
	else
		sess->client_myds->myconn = new Connection();
	sess->client_myds->client_addr = static_cast<sockaddr*>(calloc(1, sizeof(sockaddr)));
	sess->client_myds->client_addr->sa_family = AF_UNIX;
	sess->start_time = 100000;
	processlist_config_t config {};
	auto check_time = [&](const char *expected, const char *context) {
		auto *rows = manager->SQL3_Processlist(config);
		ok(rows && rows->rows_count == 1 && rows->rows[0]->fields[time_column] &&
			strcmp(rows->rows[0]->fields[time_column], expected) == 0,
			"%s: %s (expected %s ms, got %s)", name, context, expected,
			rows && rows->rows_count == 1 ? rows->rows[0]->fields[time_column] : "missing");
		delete rows;
	};
	check_time("900", "off-poll waiter processlist uses session age");
	sess->client_myds->poll_fds_idx = worker.mypolls.len;
	check_time("900", "out-of-range poll index falls back to session age");
	sess->client_myds->poll_fds_idx = 0; // worker notification pipe, not this client
	check_time("900", "index belonging to another stream cannot supply client timestamps");
	sess->client_myds->poll_fds_idx = -1;
	sess->start_time = 2000000;
	check_time("0", "future session timestamp is clamped");
	sess->start_time = 100000;
	sess->status = WAITING_CLIENT_DATA;
	ok(sess->IdleTime() == 0, "%s: an unregistered frontend has no poll-based idle age", name);
	worker.leave_waiter(sess);
	int idx = sess->client_myds->poll_fds_idx;
	worker.mypolls.last_sent[idx] = 700000;
	worker.mypolls.last_recv[idx] = 800000;
	check_time("200", "registered frontend retains last I/O age");
	ok(sess->IdleTime() == 200000, "%s: registered idle age is preserved", name);
	worker.unregister_session(0);
	delete sess;
	close(peer);
	slots = saved_slots;
	manager->num_threads = saved_threads;
}

static void test_mysql_timeout() {
	MySQL_Thread worker;
	if (!worker.init()) BAIL_OUT("worker init failed");
	mysql_thread___wait_timeout = 10000;
	mysql_thread___poll_timeout = 2000;
	mysql_thread___poll_timeout_on_failure = 10;
	worker.mypolls.poll_timeout = 10000; // configured 10 ms retry, in microseconds
	PgSQL_Waiter_Node node;
	worker.waiter_lists.push_back(node);
	ok(worker.run_ComputePollTimeout() == 10, "MySQL: waiters preserve the configured retry timeout without a throughput signal");
	worker.mypolls.poll_timeout = 0;
	mysql_thread___poll_timeout_on_failure = 10;
	ok(worker.run_ComputePollTimeout() == 10, "MySQL: off-poll waiters keep bounded retries when an unrelated wake clears the timeout");
	worker.mypolls.poll_timeout = 500;
	ok(worker.run_ComputePollTimeout() == 0, "MySQL: an earlier deadline is never extended");
	worker.waiter_lists.unlink(node);
}

static void test_pgsql_timeout() {
	PgSQL_Thread worker;
	if (!worker.init()) BAIL_OUT("worker init failed");
	pgsql_thread___poll_timeout = 2000;
	pgsql_thread___poll_timeout_on_failure = 10;
	worker.curtime = 1000000;
	worker.mypolls.poll_timeout = 10000;
	PgSQL_Waiter_Node node;
	worker.waiter_lists.push_back(node);
	ok(worker.run_ComputePollTimeout() == 10, "PgSQL: no throughput preserves the configured failure timeout");
	worker.status_variables.stvar[st_var_queries] += 2000;
	ok(worker.run_ComputePollTimeout() == 1, "PgSQL: recent throughput enables prompt waiter retries even with cleared failure counters");
	worker.mypolls.poll_timeout = 500;
	ok(worker.run_ComputePollTimeout() == 0, "PgSQL: throughput never extends an earlier deadline");
	worker.curtime += 2200000;
	worker.mypolls.poll_timeout = 10000;
	ok(worker.run_ComputePollTimeout() == 10, "PgSQL: sustained starvation expires the rapid retry window");
	worker.mypolls.poll_timeout = 0;
	pgsql_thread___poll_timeout_on_failure = 10;
	ok(worker.run_ComputePollTimeout() == 10, "PgSQL: quiet off-poll waiters keep bounded retries when the timeout resets");
	worker.waiter_lists.unlink(node);
}

static void test_pgsql_cache() {
	PgSQL_Thread worker;
	if (!worker.init()) BAIL_OUT("worker init failed");
	GloPTH->num_threads = 1;
	PgSQL_srv_info_t info {"waiter-cache-unit", 5432, "unit"};
	PgSQL_srv_opts_t opts {1, 100, 0};
	PgHGM->wrlock();
	int rc = PgHGM->create_new_server_in_hg(105, info, opts);
	auto *hg = PgHGM->MyHGC_find(105);
	PgHGM->wrunlock();
	if (rc || !hg || hg->mysrvs->cnt() != 1) BAIL_OUT("server init failed");
	auto *server = hg->mysrvs->idx(0);
	auto *conn = new PgSQL_Connection(false);
	conn->parent = server;
	conn->async_state_machine = ASYNC_IDLE;
	conn->reusable = true;
	conn->largest_query_length = 0;
	server->ConnectionsUsed->add(conn);
	PgSQL_Waiter_Node node;
	node.hid = 105;
	worker.waiter_lists.push_back(node);
	worker.push_MyConn_local(conn);
	ok(server->ConnectionsUsed->conns_length() == 0 && server->ConnectionsFree->conns_length() == 1,
		"PgSQL: queued waiter bypasses the local cache with zero failure counters");
	worker.waiter_lists.unlink(node);
	worker.return_local_connections();
}

int main() {
	plan(65);
	if (test_init_minimal() || test_init_query_processor() || test_init_hostgroups()) BAIL_OUT("init failed");
	GloMyLogger = new MySQL_Logger();
	GloPgSQL_Logger = new PgSQL_Logger();
	test_protocol<MySQL_Thread, MySQL_Session, MySQL_Data_Stream>("MySQL");
	test_protocol<PgSQL_Thread, PgSQL_Session, PgSQL_Data_Stream>("PgSQL");
	test_processlist<MySQL_Thread, MySQL_Session, MySQL_Data_Stream, MySQL_Connection>("MySQL", GloMTH, GloMTH->mysql_threads, 12);
	test_processlist<PgSQL_Thread, PgSQL_Session, PgSQL_Data_Stream, PgSQL_Connection>("PgSQL", GloPTH, GloPTH->pgsql_threads, 14);
	test_mysql_timeout();
	test_pgsql_timeout();
	test_pgsql_cache();
	delete GloPgSQL_Logger; GloPgSQL_Logger = nullptr;
	delete GloMyLogger; GloMyLogger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}

#else
int main() {
	plan(1);
	skip(1, "worker waiter test requires Linux linker wrapping");
	return exit_status();
}
#endif
