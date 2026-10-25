/** Exercise the real session/pool boundary; no handler or checkout doubles. */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Logger.hpp"
#include <sys/socket.h>
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
	worker.unregister_session(0);
	delete sess;
	close(fds[1]);
}
#endif

int main() {
#ifdef PROXYSQL31
	plan(6);
	if (test_init_minimal() || test_init_query_processor() || test_init_hostgroups())
		BAIL_OUT("scheduler test initialization failed");
	GloPgSQL_Logger = new PgSQL_Logger();
	pgsql_thread___connect_retries_delay = 1;
	test_speculative_miss();
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
