/**
 * Regression for PR #6577: a CancelRequest arriving while a stateful backend
 * awaits the internal rollback of a poisoned transaction must not leave a
 * cancellation flag that forces poll(..., 0), either during cleanup or after it.
 *
 * Drives the real rollback starter, native protocol/reset handler, cancellation
 * queue and poll-timeout computation. Socketpair login state is seeded; the peer
 * receives the real ROLLBACK and sends CommandComplete + ReadyForQuery. No timing
 * threshold, live server, copied implementation, or CPU load is needed.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include <any>
#include <sstream>
#include <type_traits>
#define private public
#include "cpp.h"
#undef private
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Logger.hpp"
#include "MySQL_Logger.hpp"
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

extern PgSQL_Logger* GloPgSQL_Logger;
extern MySQL_Logger* GloMyLogger;

#ifdef PROXYSQL31
static int make_pair(int& peer) {
	int pair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) BAIL_OUT("socketpair failed");
	for (int fd : pair) {
		int flags = fcntl(fd, F_GETFL);
		if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) BAIL_OUT("nonblocking setup failed");
	}
	peer = pair[1];
	return pair[0];
}
static void run_scenario(int hostgroup, bool cancel_during) {
	diag("scenario=%s", cancel_during ? "cancel during internal rollback" : "no cancellation");
	PgSQL_Thread worker;
	if (!worker.init()) BAIL_OUT("worker initialization failed");
	worker.curtime = monotonic_time();
	worker.atomic_curtime = worker.curtime;
	pgsql_thread___poll_timeout = 10;
	// Keep connection deadlines away from the poll-timeout assertion.
	pgsql_thread___connect_timeout_server = 60000;
	pgsql_thread___connect_timeout_server_max = 60000;
	// A socketpair peer is not a separately authenticated PostgreSQL server
	// to which teardown could send an out-of-band terminate connection.
	pgsql_thread___kill_backend_connection_when_disconnect = false;
	PgSQL_srv_info_t info{"127.0.0.1", 1, "internal rollback cancellation unit fixture"};
	PgSQL_srv_opts_t opts{1, 10, 0};
	PgHGM->wrlock();
	// Ensure lookup addresses this fixture's hostgroup rather than the
	// previous scenario's same-address server when the group is absent.
	PgHGM->MyHGC_lookup(hostgroup);
	const int create_rc = PgHGM->create_new_server_in_hg(hostgroup, info, opts);
	auto* hg = PgHGM->MyHGC_find(hostgroup);
	PgHGM->wrunlock();
	if (create_rc || !hg || hg->mysrvs->cnt() != 1) BAIL_OUT("server fixture initialization failed");
	auto* server = hg->mysrvs->idx(0);
	int frontend_peer = -1, backend_peer = -1;
	const int frontend_fd = make_pair(frontend_peer);
	const int backend_fd = make_pair(backend_peer);
	auto* sess = new PgSQL_Session();
	sess->thread = &worker;
	sess->connections_handler = true;
	sess->status = WAITING_CLIENT_DATA;
	sess->current_hostgroup = sess->default_hostgroup = hostgroup;
	sess->thread_session_id = 1918;
	sess->cancel_secret_key = 0x12345678;
	sess->client_myds = new PgSQL_Data_Stream();
	sess->client_myds->init(MYDS_FRONTEND, sess, frontend_fd);
	sess->client_myds->myconn = new PgSQL_Connection(true);
	sess->client_myds->DSS = STATE_SLEEP;
	sess->client_myds->addr.addr = strdup("component-client");
	char username[] = "component", password[] = "", database[] = "unit";
	sess->client_myds->myconn->userinfo->set(username, password, database, nullptr);
	sess->mybe = sess->find_or_create_backend(hostgroup);
	auto* ds = sess->mybe->server_myds;
	ds->init(MYDS_BACKEND, sess, backend_fd);
	ds->DSS = STATE_MARIADB_GENERIC;
	auto* conn = new PgSQL_Connection(false);
	conn->userinfo->set(username, password, database, nullptr);
	conn->parent = server;
	conn->native_mode = true;
	conn->native_connected = true;
	conn->handler_first_call = false;
	conn->native_st = PgSQL_Connection::PG_Native_Conn_St::DONE;
	conn->fd = backend_fd;
	conn->async_state_machine = ASYNC_IDLE;
	conn->reusable = true;
	conn->healthy = true;
	conn->set_ready_for_query_status('T');
	conn->set_status(true, STATUS_PGSQL_CONNECTION_ADVISORY_LOCK);
	ds->attach_connection(conn);
	server->ConnectionsUsed->add(conn);
	worker.mysql_sessions->add(sess);
	worker.mypolls.add(POLLIN, frontend_fd, sess->client_myds, worker.curtime);
	// Reach the new path through actual session-state preservation logic.
	sess->tx_poisoned = true;
	sess->end_poisoned_transaction();
	ok(sess->poison_rollback_pending && conn->rollback_pending && ds->myconn == conn,
	   "ending a poisoned transaction preserves its stateful backend and schedules rollback");
	ok(sess->start_poison_rollback() && sess->status == RESETTING_CONNECTION_V2 && conn->reset_session_rollback_only,
	   "real rollback starter enters internal rollback-only reset");
	ds->revents = 0;
	int handler_rc = 0;
	const bool first_transition = sess->handler_again___status_RESETTING_CONNECTION(&handler_rc);
	ok(!first_transition && handler_rc == 0 && conn->async_state_machine == ASYNC_RESET_SESSION_CONT,
	   "real reset handler sends ROLLBACK and waits for its response");
	unsigned char request[128];
	const ssize_t received = recv(backend_peer, request, sizeof(request), 0);
	static const unsigned char expected[] = {'Q',0,0,0,13,'R','O','L','L','B','A','C','K',0};
	ok(received == ssize_t(sizeof(expected)) && memcmp(request, expected, sizeof(expected)) == 0,
	   "socket peer receives the production-generated ROLLBACK Query");
	if (first_transition || handler_rc != 0 || conn->async_state_machine != ASYNC_RESET_SESSION_CONT ||
		received != ssize_t(sizeof(expected)) || memcmp(request, expected, sizeof(expected)) != 0)
		BAIL_OUT("rollback protocol preconditions failed; cannot continue protocol regression");
	if (cancel_during) {
		// A CancelRequest targets a client statement, not this internal cleanup.
		worker.sess_intrpt_queue.query_ids.emplace_back(sess->thread_session_id, sess->cancel_secret_key);
		ok(!worker.Scan_Sessions_to_Kill___handle_query_cancellation(sess) && !ds->cancel_query &&
		   worker.sess_intrpt_queue.query_ids.empty(),
		   "secret-key cancellation during internal rollback is consumed without setting cancel_query");
		worker.sess_intrpt_queue.query_ids.emplace_back(sess->thread_session_id, username);
		ok(!worker.Scan_Sessions_to_Kill___handle_query_cancellation(sess) && !ds->cancel_query &&
		   worker.sess_intrpt_queue.query_ids.empty(),
		   "username cancellation during internal rollback is consumed without setting cancel_query");
	}
	worker.mypolls.poll_timeout = 0;
	worker.ProcessAllMyDS_BeforePoll<PgSQL_Thread>();
	ok(worker.run_ComputePollTimeout() > 0,
	   "waiting for the internal rollback reply does not force zero-timeout polling");
	static const unsigned char reply[] = {'C',0,0,0,13,'R','O','L','L','B','A','C','K',0,'Z',0,0,0,5,'I'};
	if (send(backend_peer, reply, sizeof(reply), MSG_NOSIGNAL) != ssize_t(sizeof(reply))) BAIL_OUT("fixture reply send failed");
	ds->revents = POLLIN;
	const bool completed = sess->handler_again___status_RESETTING_CONNECTION(&handler_rc);
	ok(completed && handler_rc == 0 && sess->status == WAITING_CLIENT_DATA && conn->async_state_machine == ASYNC_IDLE,
	   "real reset completion consumes the protocol reply and returns to client-idle");
	ok(ds->myconn == conn && conn->holds_session_state() && conn->last_ready_for_query_status() == 'I',
	   "stateful backend remains attached after its transaction ends");
	if (!completed || handler_rc != 0 || sess->status != WAITING_CLIENT_DATA ||
		conn->async_state_machine != ASYNC_IDLE || ds->myconn != conn ||
		!conn->holds_session_state() || conn->last_ready_for_query_status() != 'I')
		BAIL_OUT("reset completion preconditions failed; cannot continue protocol regression");
	ok(!ds->cancel_query, "successful internal rollback leaves no stale cancellation flag");
	worker.sess_intrpt_queue.query_ids.emplace_back(sess->thread_session_id, sess->cancel_secret_key);
	ok(!worker.Scan_Sessions_to_Kill___handle_query_cancellation(sess) && !ds->cancel_query &&
	   worker.sess_intrpt_queue.query_ids.empty(), "late cancellation is ignored once the client is idle");
	worker.mypolls.poll_timeout = 0;
	worker.ProcessAllMyDS_BeforePoll<PgSQL_Thread>();
	ok(worker.run_ComputePollTimeout() > 0,
	   "idle session with retained backend returns to blocking polling");

	// Controls: cancellations of actual client work must still be accepted,
	// including an ordinary reset performed before executing a client query.
	for (auto status : {PROCESSING_QUERY, CONNECTING_SERVER, RESETTING_CONNECTION_V2}) {
		sess->status = status;
		worker.sess_intrpt_queue.query_ids.emplace_back(sess->thread_session_id, sess->cancel_secret_key);
		ok(worker.Scan_Sessions_to_Kill___handle_query_cancellation(sess) && ds->cancel_query &&
		   ds->kill_type == 1 && worker.sess_intrpt_queue.query_ids.empty(),
		   "cancellation of client work is preserved in session status %d", int(status));
		ds->cancel_query = false;
		ds->kill_type = 0;
	}
	sess->status = WAITING_CLIENT_DATA;
	// The socketpair peer cannot service an asynchronous DISCARD ALL at teardown.
	ds->destroy_MySQL_Connection_From_Pool(false);
	worker.unregister_session(0);
	delete sess;
	close(frontend_peer);
	close(backend_peer);
}
#endif

int main() {
#ifndef PROXYSQL31
	plan(1);
	skip(1, "native rollback and scheduler fixture requires PROXYSQL31");
	return exit_status();
#else
	plan(28);
	if (test_init_minimal() || test_init_query_processor() || test_init_hostgroups()) BAIL_OUT("initialization failed");
	GloMyLogger = new MySQL_Logger();
	GloPgSQL_Logger = new PgSQL_Logger();
	run_scenario(918, false);
	run_scenario(919, true);
	delete GloPgSQL_Logger; GloPgSQL_Logger = nullptr;
	delete GloMyLogger; GloMyLogger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
#endif
}
