/**
 * Exercise the real MySQL/PgSQL resume handoff and drain methods. No daemon or
 * backend connection is needed. Removing either load publication site breaks
 * the pending-count or empty-drain assertions below.
 */
#include <any>
#include <sstream>
#include <thread>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

// Access the existing handoff boundaries without adding production test APIs.
#define private public
#include "cpp.h"
#undef private
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"

extern MySQL_Logger *GloMyLogger;
extern PgSQL_Logger *GloPgSQL_Logger;

#ifdef IDLE_THREADS

template<class Session, class Stream>
Session *new_session() {
	auto *session = new Session();
	// These sessions have no authenticated frontend or backend connection.
	session->connections_handler = true;
	session->client_myds = new Stream();
	session->client_myds->sess = session;
	session->client_myds->myds_type = MYDS_FRONTEND;
	session->client_myds->fd = -1;
	return session;
}

template<class Worker, class Session>
void remove_session(Worker& worker) {
	auto *session = static_cast<Session*>(worker.mysql_sessions->index(0));
	worker.unregister_session(0);
	delete session;
}

template<class Worker, class Session, class Stream>
void test_protocol(const char *protocol) {
	Worker worker;
	if (!worker.init()) BAIL_OUT("%s worker init failed", protocol);
	ok(worker.worker_load.load(std::memory_order_relaxed) == 0,
		"%s: new worker has zero load", protocol);

	// The source staging queue and destination exchange queue are independent
	// arrays on this real worker. Reusing its staging queue lets us invoke both
	// sides deterministically without constructing two workers on one TLS.
	worker.resume_mysql_sessions->add(new_session<Session, Stream>());
	worker.resume_mysql_sessions->add(new_session<Session, Stream>());
	worker.idle_thread_assigns_sessions_to_worker_thread(&worker);
	ok(worker.worker_load.load(std::memory_order_relaxed) == 2,
		"%s: queued batch immediately contributes to load", protocol);
	ok(worker.resume_mysql_sessions->len == 0 && worker.myexchange.resume_mysql_sessions->len == 2,
		"%s: entire batch moves into the destination queue", protocol);

	worker.resume_mysql_sessions->add(new_session<Session, Stream>());
	worker.idle_thread_assigns_sessions_to_worker_thread(&worker);
	ok(worker.worker_load.load(std::memory_order_relaxed) == 3,
		"%s: another pending batch accumulates before the worker drains", protocol);
	worker.worker_thread_gets_sessions_from_idle_thread();
	ok(worker.worker_load.load(std::memory_order_relaxed) == 3 &&
		worker.mysql_sessions->len == 3 && worker.myexchange.resume_mysql_sessions->len == 0,
		"%s: pending-to-active transfer preserves load", protocol);

	remove_session<Worker, Session>(worker);
	remove_session<Worker, Session>(worker);
	worker.worker_thread_gets_sessions_from_idle_thread();
	ok(worker.worker_load.load(std::memory_order_relaxed) == 1,
		"%s: empty drain refreshes the load after active sessions leave", protocol);
	remove_session<Worker, Session>(worker);
	worker.worker_thread_gets_sessions_from_idle_thread();
	ok(worker.worker_load.load(std::memory_order_relaxed) == 0,
		"%s: empty drain publishes zero after the last departure", protocol);

	worker.resume_mysql_sessions->add(new_session<Session, Stream>());
	worker.shutdown = 1;
	worker.idle_thread_assigns_sessions_to_worker_thread(&worker);
	ok(worker.worker_load.load(std::memory_order_relaxed) == 0 &&
		worker.resume_mysql_sessions->len == 1 && worker.myexchange.resume_mysql_sessions->len == 0,
		"%s: shutdown rejects handoff without increasing load", protocol);
	worker.shutdown = 0;
	worker.idle_thread_assigns_sessions_to_worker_thread(&worker);
	worker.worker_thread_gets_sessions_from_idle_thread();
	remove_session<Worker, Session>(worker);
	worker.worker_thread_gets_sessions_from_idle_thread();

	// With a TSAN-instrumented library, this exercises cross-thread sampling
	// while actual production methods publish queued and active session counts.
	std::atomic<bool> ready {false};
	std::atomic<bool> done {false};
	unsigned long samples = 0;
	bool within_bounds = true;
	std::thread reader([&] {
		ready.store(true, std::memory_order_release);
		do {
			if (worker.worker_load.load(std::memory_order_relaxed) > 1) within_bounds = false;
			++samples;
		} while (!done.load(std::memory_order_acquire));
	});
	while (!ready.load(std::memory_order_acquire)) std::this_thread::yield();
	for (unsigned i = 0; i < 2000; ++i) {
		worker.resume_mysql_sessions->add(new_session<Session, Stream>());
		worker.idle_thread_assigns_sessions_to_worker_thread(&worker);
		worker.worker_thread_gets_sessions_from_idle_thread();
		remove_session<Worker, Session>(worker);
		worker.worker_thread_gets_sessions_from_idle_thread();
	}
	done.store(true, std::memory_order_release);
	reader.join();
	ok(samples > 0 && within_bounds, "%s: concurrent samples stay within live workload bounds", protocol);
	ok(worker.worker_load.load(std::memory_order_relaxed) == 0,
		"%s: repeated handoffs and departures return load to zero", protocol);
}
#endif

int main() {
#ifndef IDLE_THREADS
	BAIL_OUT("idle thread support is required");
#else
	plan(20);
	if (test_init_minimal() != 0 || test_init_query_processor() != 0 || test_init_hostgroups() != 0)
		BAIL_OUT("worker-load test initialization failed");
	GloVars.global.idle_threads = true;
	GloMyLogger = new MySQL_Logger();
	GloPgSQL_Logger = new PgSQL_Logger();
	{
		test_protocol<MySQL_Thread, MySQL_Session, MySQL_Data_Stream>("MySQL");
		test_protocol<PgSQL_Thread, PgSQL_Session, PgSQL_Data_Stream>("PgSQL");
	}
	delete GloPgSQL_Logger;
	GloPgSQL_Logger = nullptr;
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
#endif
	return exit_status();
}
