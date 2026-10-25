/** Exercise the real session/pool boundary; no handler or checkout doubles. */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Logger.hpp"
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

extern PgSQL_Threads_Handler* GloPTH;
extern PgSQL_Logger* GloPgSQL_Logger;
#ifdef PROXYSQL31

static void test_speculative_miss() {
	PgSQL_Thread worker;
	if (!worker.init()) BAIL_OUT("worker initialization failed");
	worker.curtime = 1000000;
	PgSQL_srv_info_t info {"127.0.0.1", 1, "scheduler unit"};
	PgSQL_srv_opts_t opts {1, 10, 0};
	PgHGM->wrlock();
	const int rc = PgHGM->create_new_server_in_hg(810, info, opts);
	auto* hg = PgHGM->MyHGC_find(810);
	PgHGM->wrunlock();
	if (rc || !hg) BAIL_OUT("hostgroup initialization failed");
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) BAIL_OUT("socketpair failed");
	auto* sess = new PgSQL_Session();
	sess->thread = &worker;
	sess->connections_handler = true;
	sess->status = CONNECTING_SERVER;
	sess->current_hostgroup = sess->default_hostgroup = 810;
	sess->client_myds = new PgSQL_Data_Stream();
	sess->client_myds->init(MYDS_FRONTEND, sess, fds[0]);
	sess->client_myds->myconn = new PgSQL_Connection(true);
	sess->client_myds->myconn->userinfo->set((char*)"scheduler", (char*)"", (char*)"unit", nullptr);
	sess->client_myds->DSS = STATE_SLEEP;
	sess->mybe = sess->find_or_create_backend(810);
	sess->mybe->server_myds->max_connect_time = worker.curtime + 1000000;
	sess->to_process = 1;
	worker.mysql_sessions->add(sess);
	worker.mypolls.add(POLLIN, fds[0], sess->client_myds, worker.curtime);
	const auto failures = worker.status_variables.stvar[st_var_ConnPool_get_conn_failure];
	const auto created = PgHGM->status.server_connections_created;
	const int poll_index = sess->client_myds->poll_fds_idx;
	const auto result = sess->run_step(PgSQL_Pool_Acquire_Mode::EstablishedOnly);
	ok(result == PgSQL_Session_Run_Result::EstablishedUnavailable && !sess->mybe->server_myds->myconn,
		"speculative checkout reports unavailable without acquiring a backend");
	ok(PgHGM->status.server_connections_created == created,
		"speculative empty-pool checkout never creates a backend");
	ok(!sess->waiter_node.session && worker.waiter_lists.empty(),
		"speculative miss does not park the session as a normal waiter");
	ok(sess->pause_until == 0,
		"speculative miss does not impose a connection retry delay");
	ok(sess->client_myds->poll_fds_idx == poll_index && sess->client_myds->mypolls == &worker.mypolls,
		"speculative miss preserves frontend poll registration");
	ok(worker.status_variables.stvar[st_var_ConnPool_get_conn_failure] == failures &&
		hg->pool_stats.lifetime_snapshot().waiters == 0,
		"speculative miss does not account a normal connection failure or wait episode");
	// An idle free connection for another user must remain untouched. A
	// speculative phase must not evict it or create a replacement.
	auto* server = hg->mysrvs->idx(0);
	auto* incompatible = new PgSQL_Connection(false);
	incompatible->parent = server;
	incompatible->async_state_machine = ASYNC_IDLE;
	incompatible->userinfo->set((char*)"other_user", (char*)"", (char*)"unit", nullptr);
	server->ConnectionsFree->add(incompatible);
	const auto incompatible_result = sess->run_step(PgSQL_Pool_Acquire_Mode::EstablishedOnly);
	ok(incompatible_result == PgSQL_Session_Run_Result::EstablishedUnavailable &&
		server->ConnectionsFree->conns_length() == 1 && server->ConnectionsFree->index(0) == incompatible &&
		PgHGM->status.server_connections_created == created,
		"speculative incompatible-pool checkout neither evicts nor creates a connection");
	ok(!sess->waiter_node.session && !sess->pause_until && sess->client_myds->poll_fds_idx == poll_index &&
		worker.status_variables.stvar[st_var_ConnPool_get_conn_failure] == failures,
		"incompatible speculative miss preserves waiter, retry, poll and failure state");
	worker.unregister_session(0);
	delete sess;
	close(fds[1]);
}

static void test_completion_output() {
	PgSQL_Thread worker;
	if (!worker.init()) BAIL_OUT("worker initialization failed");
	worker.curtime = 1000000;
	pgsql_thread___poll_timeout = 2000;
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) BAIL_OUT("socketpair failed");
	fcntl(fds[0], F_SETFL, O_NONBLOCK);
	const int small_buffer = 4096;
	setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &small_buffer, sizeof(small_buffer));
	auto* sess = new PgSQL_Session();
	sess->thread = &worker;
	sess->connections_handler = true;
	sess->status = WAITING_CLIENT_DATA;
	sess->client_myds = new PgSQL_Data_Stream();
	sess->client_myds->init(MYDS_FRONTEND, sess, fds[0]);
	sess->client_myds->myconn = new PgSQL_Connection(true);
	sess->client_myds->DSS = STATE_SLEEP;
	worker.mysql_sessions->add(sess);
	worker.mypolls.add(POLLIN, fds[0], sess->client_myds, worker.curtime);
	const std::string expected(65536, 'x');
	void* packet = malloc(expected.size());
	memcpy(packet, expected.data(), expected.size());
	sess->client_myds->PSarrayOUT->add(packet, expected.size());
	// Enter with settled request state and a release notification. The real
	// handler must attempt output before returning, with no next command to run.
	sess->scheduler_managed = true;
	sess->yield_after_release = true;
	sess->to_process = 1;
	const int rc = sess->handler();
	sess->scheduler_managed = false;
	ok(rc == 0 && !sess->continuation_queued,
		"completed request without buffered input needs no completion continuation");
	char first_byte;
	ok(recv(fds[1], &first_byte, 1, MSG_DONTWAIT | MSG_PEEK) == 1 && first_byte == 'x',
		"completed request attempts client output before returning to the scheduler");
	ok(sess->client_myds->available_data_out(), "short client write retains unsent output after completion");
	std::string received;
	for (int attempts = 0; attempts < 100 && worker.mysql_sessions->len && received.size() < expected.size(); ++attempts) {
		char bytes[16384];
		ssize_t n;
		while ((n = recv(fds[1], bytes, sizeof(bytes), MSG_DONTWAIT)) > 0) received.append(bytes, n);
		worker.ProcessAllMyDS_BeforePoll<PgSQL_Thread>();
		poll(worker.mypolls.fds, worker.mypolls.len, 0);
		sess->to_process = 0;
		worker.ProcessAllMyDS_AfterPoll();
		worker.process_all_sessions();
	}
	ok(received == expected && worker.mysql_sessions->len && sess->healthy, "POLLOUT delivers retained bytes exactly once and in order");
	if (worker.mysql_sessions->len) {
		worker.queue_session_continuation(sess);
		worker.unregister_session(0);
		delete sess;
	}
	worker.mypolls.poll_timeout = 0;
	ok(worker.run_ComputePollTimeout() == 2000, "session teardown cancels queued continuation and restores idle polling");
	close(fds[1]);
}
static void test_paused_buffered_work() {
	PgSQL_Thread worker;
	if (!worker.init()) BAIL_OUT("worker initialization failed");
	worker.curtime = 1000000;
	pgsql_thread___poll_timeout = 2000;
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) BAIL_OUT("socketpair failed");
	auto* sess = new PgSQL_Session();
	sess->thread = &worker;
	sess->connections_handler = true;
	sess->status = WAITING_CLIENT_DATA;
	sess->client_myds = new PgSQL_Data_Stream();
	sess->client_myds->init(MYDS_FRONTEND, sess, fds[0]);
	sess->client_myds->myconn = new PgSQL_Connection(true);
	sess->client_myds->DSS = STATE_SLEEP;
	worker.mysql_sessions->add(sess);
	worker.mypolls.add(POLLIN, fds[0], sess->client_myds, worker.curtime);
	// Already buffered Terminate proves normal packet processing resumes
	// without another POLLIN event. While paused it must remain untouched.
	const unsigned char terminate[] = {'X', 0, 0, 0, 4};
	void* packet = malloc(sizeof(terminate));
	memcpy(packet, terminate, sizeof(terminate));
	sess->client_myds->PSarrayIN->add(packet, sizeof(terminate));
	sess->pause_until = worker.curtime + 100000;
	sess->to_process = 0;
	worker.queue_session_continuation(sess);
	ok(worker.run_ComputePollTimeout() == 100,
		"paused buffered work uses its deadline instead of spinning poll");
	worker.process_all_sessions();
	ok(worker.mysql_sessions->len == 1,
		"queued next command does not execute before its pause expires");
	worker.curtime += 100000;
	ok(worker.run_ComputePollTimeout() == 0,
		"buffered work is runnable at its deadline without fresh socket input");
	worker.process_all_sessions();
	ok(worker.mysql_sessions->len == 0 && worker.run_ComputePollTimeout() == 2000,
		"normal handler consumes queued Terminate and removes its runnable entry");
	close(fds[1]);
}

#endif

int main() {
#ifdef PROXYSQL31
	plan(17);
	if (test_init_minimal() || test_init_query_processor() || test_init_hostgroups())
		BAIL_OUT("scheduler test initialization failed");
	GloPgSQL_Logger = new PgSQL_Logger();
	pgsql_thread___connect_retries_delay = 1;
	test_speculative_miss();
	test_completion_output();
	test_paused_buffered_work();
	delete GloPgSQL_Logger;
	GloPgSQL_Logger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
#else
	plan(1);
	skip(1, "phased scheduling is a PROXYSQL31 feature");
#endif
	return exit_status();
}
