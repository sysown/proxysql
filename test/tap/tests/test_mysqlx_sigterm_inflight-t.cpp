/**
 * test_mysqlx_sigterm_inflight-t.cpp
 *
 * Behavioural validation TAP scaffolding for issue #5678 part (a):
 *
 *   When ProxySQL receives SIGTERM with X-Protocol clients connected
 *   and dispatching queries, each Mysqlx_Thread::run() worker calls
 *   MysqlxSession::shutdown_notify_client() on every owned session on
 *   the way out of the loop. shutdown_notify_client() must:
 *      - enqueue a fatal Mysqlx::Error frame (code 1053, "Server is
 *        shutting down") via send_error(..., fatal=true);
 *      - drain the queued frame to the wire via DataStream::write_to_net();
 *      - if TLS is active, set quiet shutdown + call SSL_shutdown so the
 *        peer's TLS stack sees a clean close_notify.
 *
 *   The connected client therefore observes a Mysqlx::Error frame
 *   (last app-level frame) followed by an orderly EOF -- NOT a TCP RST
 *   from kernel-level socket teardown.
 *
 * Contract reference:
 *   plugins/mysqlx/src/mysqlx_session.cpp:1875 shutdown_notify_client()
 *   plugins/mysqlx/src/mysqlx_thread.cpp:120-128 run() shutdown path
 *
 * Why this test does NOT run automatically in CI:
 *
 *   ProxySQL runs in its own Docker container (proxysql.INFRA_ID),
 *   the test runs in a separate test-runner.INFRA_ID container, and
 *   the test-runner does NOT have docker socket access. Even if it
 *   did, sending SIGTERM mid-test would tear down the proxysql
 *   container that the surrounding run-tests-isolated.bash harness
 *   expects to remain up for the entire group. There is no harness
 *   mode for "this test owns proxysql lifecycle"; adding one is a
 *   substantially larger change than the issue asks for.
 *
 *   The equivalent automated coverage already exists out-of-band:
 *
 *     test/scripts/mysqlx/behavioral_validation.py --scenario sigterm
 *
 *   That harness (1) opens N X-Protocol sessions via mysql-connector-
 *   python, (2) os.kill(pid, SIGTERM) against the proxysql process
 *   directly, and (3) verifies each client received a Mysqlx::Error
 *   frame with errno=1053 rather than a TCP RST. It is invoked
 *   manually against staging or local-loop infrastructure where
 *   tearing down the proxysql process is acceptable.
 *
 * Manual procedure (mirrors what the issue asks operators to
 * demonstrate):
 *
 *   1. Build proxysql + the mysqlx plugin and stand up a backend
 *      (e.g. via test/tap/groups/mysqlx-soak/setup-infras.bash inside
 *      a local docker stack, or via the dbdeployer recipe in
 *      test/tap/groups/mysqlx-e2e/setup-infras.bash with the plugin
 *      manually configured).
 *   2. From any host that can reach proxysql, run:
 *
 *        cd test/scripts/mysqlx
 *        pip install mysql-connector-python
 *        python3 behavioral_validation.py \
 *            --scenario sigterm \
 *            --proxysql-host HOST --proxysql-port ROUTE_PORT \
 *            --user alice --password alicepass \
 *            --proxysql-pid-file /var/run/proxysql.pid
 *
 *      Expected output line: "PASS: every client received a clean
 *      shutdown notification" (each session reports errno=1053).
 *
 *   3. Failure modes that indicate a regression:
 *      - errno = None / OperationalError without errno   -> TCP RST
 *      - errno != 1053 / different message                -> wrong frame
 *      - hung clients                                     -> SSL_shutdown
 *                                                            ordering issue
 *
 * This test compiles + links so the scaffolding is on the same build
 * cadence as the rest of the mysqlx TAP suite (groups.json registration
 * exercises the binary's existence on every CI run); it issues
 * skip_all() at runtime to keep CI green.
 *
 * NOSONAR(cpp:S2068) annotation is applied where test password literals
 * appear inline.
 */

#include "tap.h"

#include <cstdlib>
#include <string>

int main() {
	// Allow operators who DO want to run this test (e.g. on a single-host
	// dev loop where proxysql is the only process and SIGTERM is fine)
	// to opt in via MYSQLX_SIGTERM_INFLIGHT_OPT_IN=1. Without the opt-in
	// we skip_all so CI never tears down proxysql mid-suite.
	const char* opt_in = std::getenv("MYSQLX_SIGTERM_INFLIGHT_OPT_IN");
	if (opt_in == nullptr || std::string(opt_in) != "1") {
		skip_all(
		    "manual procedure -- see header comment. "
		    "To run automated equivalent: "
		    "test/scripts/mysqlx/behavioral_validation.py --scenario sigterm. "
		    "To opt in here: set MYSQLX_SIGTERM_INFLIGHT_OPT_IN=1 (will SIGTERM proxysql)."
		);
		return exit_status();
	}

	// If we ever wire this up, the implementation would mirror
	// scenario_sigterm() in test/scripts/mysqlx/behavioral_validation.py:
	//
	//   1. Open 5 X-Protocol clients in worker threads, each running
	//      a steady SELECT 1 loop (use the same handshake helpers as
	//      test_mysqlx_e2e_routing-t.cpp + test_mysqlx_route_drop_inflight-t.cpp).
	//   2. After ~2s of steady traffic, locate the proxysql pid:
	//        - read MYSQLX_SIGTERM_INFLIGHT_PIDFILE (env-driven, no
	//          baked-in path)
	//        - or fall back to pidof("proxysql")
	//      Then kill(pid, SIGTERM).
	//   3. For each client thread, the next mysqlx_read_frame() call
	//      should return a frame with message_type == MSG_SRV_ERROR
	//      whose decoded Mysqlx.Error has code() == 1053. The bytes
	//      AFTER that frame should be a clean EOF (recv() returns 0)
	//      not a kernel-level RST (which manifests as ECONNRESET on
	//      the next syscall).
	//
	// Even with opt-in, today this binary does not implement the body
	// because running it without infrastructure that expects proxysql
	// to die would corrupt the surrounding test group. Refuse loudly.
	plan(1);
	ok(false,
	   "MYSQLX_SIGTERM_INFLIGHT_OPT_IN is set but the in-process automated path is "
	   "not implemented. Use test/scripts/mysqlx/behavioral_validation.py --scenario sigterm.");
	return exit_status();
}
