/**
 * Deadlines are due at equality, including a poll that wakes in the exact
 * microsecond of a query timeout (#6385). Strict comparisons here can drop
 * the deadline and defer cancellation by the default poll interval.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"

extern MySQL_Logger *GloMyLogger;
extern PgSQL_Logger *GloPgSQL_Logger;

template<class Worker, class Session, class Stream>
void test_deadlines(const char *protocol) {
	// The stream and session must outlive the worker's poll array.
	Session session;
	Stream stream;
	Worker worker;
	if (!worker.init()) BAIL_OUT("%s worker initialization failed", protocol);
	session.thread = &worker;
	session.connections_handler = true;
	session.status = PROCESSING_QUERY;
	stream.sess = &session;
	stream.myds_type = MYDS_BACKEND;
	worker.mypolls.add(POLLIN, -1, &stream, 100);
	worker.poll_timeout_bool = true;
	worker.curtime = 100;

	struct Case {
		unsigned long long wait_until;
		unsigned long long pause_until;
		int expected;
		const char *label;
	};
	const Case cases[] = {
		{0, 0, 0, "unset deadlines stay idle"},
		{101, 0, 0, "future query deadline stays idle"},
		{100, 0, 1, "query deadline at current time is due"},
		{99, 0, 1, "past query deadline is due"},
		{0, 101, 0, "future pause stays idle"},
		{0, 100, 1, "pause at current time is due"},
		{0, 99, 1, "past pause is due"},
	};
	for (const Case &c : cases) {
		stream.wait_until = c.wait_until;
		session.pause_until = c.pause_until;
		session.to_process = 0;
		worker.mypolls.fds[stream.poll_fds_idx].revents = 0;
		worker.template ProcessAllMyDS_AfterPoll<Worker>();
		ok(session.to_process == c.expected, "%s: %s", protocol, c.label);
	}
	worker.mypolls.remove_index_fast(stream.poll_fds_idx);
	stream.mypolls = nullptr;
}

int main() {
	plan(14);
	if (test_init_minimal() || test_init_query_processor() || test_init_hostgroups())
		BAIL_OUT("worker timeout test initialization failed");
	GloMyLogger = new MySQL_Logger();
	GloPgSQL_Logger = new PgSQL_Logger();
	test_deadlines<MySQL_Thread, MySQL_Session, MySQL_Data_Stream>("MySQL");
	test_deadlines<PgSQL_Thread, PgSQL_Session, PgSQL_Data_Stream>("PgSQL");
	delete GloPgSQL_Logger;
	GloPgSQL_Logger = nullptr;
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
