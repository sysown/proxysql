/**
 * @file reg_test_3273_ssl_con-t.cpp
 * @brief Regression test for SSL busy/infinite loops for frontend connections.
 * @details When client disconnects unexpectedly closing the socket on a SSL connection, depending on the
 *   timing conditions, either an infinite loop or a busy loop could take place. These scenarios are:
 *   1. Closed socket while query running on backend (before data arrives), leads to busy loop.
 *   2. Closed socket after all the data has been written into the socket, since no more writing would take
 *      place in the socket an infinite loop would take place.
 */

#include <cstring>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include <poll.h>
#include <fcntl.h>

#include <sys/epoll.h>


#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::pair;
using std::vector;

/* Helper function to do the waiting for events on the socket. */
static int wait_for_mysql(MYSQL *mysql, int status) {
	struct pollfd pfd;
	int timeout, res;

	pfd.fd = mysql_get_socket(mysql);
	pfd.events =
		(status & MYSQL_WAIT_READ ? POLLIN : 0) |
		(status & MYSQL_WAIT_WRITE ? POLLOUT : 0) |
		(status & MYSQL_WAIT_EXCEPT ? POLLPRI : 0);
	if (status & MYSQL_WAIT_TIMEOUT)
		timeout = 1000*mysql_get_timeout_value(mysql);
	else
		timeout = -1;
	res = poll(&pfd, 1, timeout);
	if (res == 0)
		return MYSQL_WAIT_TIMEOUT;
	else if (res < 0)
		return MYSQL_WAIT_TIMEOUT;
	else {
		int status = 0;
		if (pfd.revents & POLLIN) status |= MYSQL_WAIT_READ;
		if (pfd.revents & POLLOUT) status |= MYSQL_WAIT_WRITE;
		if (pfd.revents & POLLPRI) status |= MYSQL_WAIT_EXCEPT;
		return status;
	}
}

enum BUSY_LOOP_T {
	BUSY_LOOP=0,
	INF_LOOP=1
};

struct th_args__in_t {
	// Input
	int argc { 0 };
	char** argv { nullptr };
	int secs { 0 };
	int busy_loop_type = BUSY_LOOP_T::BUSY_LOOP;
	CommandLine& cl;
};

struct th_args__out_t {
	// Output
	volatile int* query_started { nullptr };
	volatile int* routine_rc { nullptr };
};

struct th_args_t {
	th_args__in_t in_args;
	th_args__out_t out_args {};
};

void* perform_async_query(void* arg) {
	th_args_t* th_args = static_cast<th_args_t*>(arg);

	MYSQL* mysql = nullptr;

	{
		CommandLine& cl = th_args->in_args.cl;
		mysql = mysql_init(NULL);
		MYSQL* ret = NULL;
		int query_ret = 0;

		mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);

		int status = 0;

		if (th_args->in_args.argc == 2 && (strcmp(th_args->in_args.argv[1], "admin") == 0)) {
			status = mysql_real_connect_start(
				&ret, mysql, cl.host, "radmin", "radmin", NULL, 6032, NULL, CLIENT_SSL
			);
			diag("Creating 'Admin' connection   thread=%ld ret=%p status=%d", pthread_self(), ret, status);
		} else {
			status = mysql_real_connect_start(
				&ret, mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, CLIENT_SSL
			);

			diag("Creating 'MySQL' connection   thread=%ld ret=%p status=%d", pthread_self(), ret, status);
		}
		if (status == 0) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			__sync_fetch_and_add(th_args->out_args.routine_rc, 1);
			return NULL;
		}

		diag("Continue connection establishment   thread=%ld ret=%p status=%d", pthread_self(), ret, status);
		while (status) {
			status = wait_for_mysql(mysql, status);
			status = mysql_real_connect_cont(&ret, mysql, status);
			diag("'mysql_real_connect_cont'   thread=%ld ret=%p status=%d", pthread_self(), ret, status);
		}

		// NOTE: mariadbclient has an incompatibility between SSL and NONBLOCK flags. Flag needs to be reset
		// after 'mysql_real_connect_cont', otherwise API would become blocking.
		mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
		int f=fcntl(mysql->net.fd, F_GETFL);
		fcntl(mysql->net.fd, F_SETFL, f|O_NONBLOCK);

		const string sleep_query { "SELECT SLEEP(" + std::to_string(th_args->in_args.secs) + ")" };
		diag("mysql_query_start   thread=%ld query=%s", pthread_self(), sleep_query.c_str());

		status = mysql_real_query_start(&query_ret, mysql, sleep_query.c_str(), sleep_query.size());

		if (th_args->in_args.busy_loop_type == BUSY_LOOP_T::INF_LOOP) {
			// NOTE: When signaling after 'mysql_query_start' has finished, ProxySQL wont attempt to write more
			// to the closed pipe, this corresponds to 'busy_loop_type=2' and infinite loop.
			while (status) {
				status = wait_for_mysql(mysql, status);
				status = mysql_real_query_cont(&query_ret, mysql, status);
				diag("'mysql_real_connect_cont'   thread=%ld ret=%p status=%d", pthread_self(), ret, status);
			}
		}

		diag("Signaling query start   thread=%ld status=%d query_ret=%d", pthread_self(), status, query_ret);
		__sync_fetch_and_add(th_args->out_args.query_started, 1);

		// NOTE: Required for triggering the issue, thread exit isn't enough, either 'process exit' or
		// 'close()'. They should be immediate to the previous action, otherwise timing could be invalid.
		close(mysql->net.fd);

		while (true) {
			diag(
				"Sleeping after query started...   thread=%ld status=%d query_ret=%d",
				pthread_self(), status, query_ret
			);
			sleep(1);
		}
	}

	return NULL;
}

struct pthread_data_t {
	pthread_t id { 0 };
	int query_started { 0 };
	int routine_rc { EXIT_SUCCESS };
};

const int BUSY_THREADS = get_env_int("TAP_SSL_BUSY_WAIT__BUSY_THREADS", 4);
const int MAX_IDLE_CPU = get_env_int("TAP_SSL_BUSY_WAIT__MAX_IDLE_CPU", 20);
const int MAX_BUSY_CPU = get_env_int("TAP_SSL_BUSY_WAIT__MAX_BUSY_CPU", 25);

// NOTE: '10' is a nice value due to it's relationship with the 'system_cpu' interval
const int BUSY_WAIT_SECS = get_env_int("TAP_SSL_BUSY_WAIT__BUSY_WAIT_SECS", 10);
// NOTE: '5' is the min value due to time interval rounding 'round_intv_to_time_interval'
const int SAMPLE_INTV_SECS = get_env_int("TAP_SSL_BUSY_WAIT__SAMPLE_INTV_SEC", BUSY_WAIT_SECS / 2);

void create_busy_loops(int argc, char** argv, CommandLine& cl, BUSY_LOOP_T loop_type) {
	vector<pthread_data_t> ths_data {};
	vector<std::unique_ptr<th_args_t>> ths_args {};

	ths_data.resize(BUSY_THREADS);

	for (size_t i = 0; i < BUSY_THREADS; i++) {
		pthread_data_t& th_data = ths_data[i];
		std::unique_ptr<th_args_t> th_args {
			new th_args_t {
				th_args__in_t {
					argc, argv, BUSY_WAIT_SECS, loop_type, cl
				},
				th_args__out_t {
					&th_data.query_started,
					&th_data.routine_rc
				}
			}
		};

		pthread_create(&th_data.id, NULL, perform_async_query, th_args.get());
		ths_args.push_back(std::move(th_args));

		diag("Thread created   thread=%ld", th_data.id);
	}

	bool missing_query = true;
	bool query_failed = false;

	while (missing_query && !query_failed) {
		bool all_query_started = true;

		for (pthread_data_t& th_data : ths_data) {
			bool query_started = __sync_fetch_and_add(&th_data.query_started, 0);
			diag(
				"Thread data   thread=%ld routine_rc=%d query_started=%d",
				th_data.id, th_data.routine_rc, query_started
			);

			if (th_data.id == 0 && query_started == 1) {
				diag(
					"Thread alreay cancelled   thread=%ld routine_rc=%d query_started=%d",
					th_data.id, th_data.routine_rc, query_started
				);
				continue;
			}

			query_failed = __sync_fetch_and_add(&th_data.routine_rc, 0);

			if (query_failed) {
				diag(
					"Async query failed; aborting test   thread=%ld routine_rc=%d query_started=%d",
					th_data.id, th_data.routine_rc, query_started
				);
				break;
			}

			all_query_started &= query_started;

			if (query_started) {
				diag(
					"Async query started, killing thread   thread=%ld routine_rc=%d query_started=%d",
					th_data.id, th_data.routine_rc, query_started
				);
				pthread_cancel(th_data.id);
				th_data.id = 0;
			} else {
				diag(
					"Waiting for async query to start...   thread=%ld routine_rc=%d query_started=%d",
					th_data.id, th_data.routine_rc, query_started
				);
			}
		}

		missing_query = !all_query_started;
		usleep(500 * 1000);
	}
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(4);

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	pair<int,vector<MYSQL*>> p_err_nodes_conns { disable_core_nodes_scheduler(cl, admin) };
	if (p_err_nodes_conns.first) { return EXIT_FAILURE; }
	vector<MYSQL*>& nodes_conns { p_err_nodes_conns.second };

	diag("Checking ProxySQL idle CPU usage");
	double idle_cpu = 0;
	int ret_i_cpu = get_proxysql_cpu_usage(cl, idle_cpu, SAMPLE_INTV_SECS);
	if (ret_i_cpu) {
		diag("Getting initial CPU usage failed with error - %d", ret_i_cpu);
		diag("Aborting further testing");

		return EXIT_FAILURE;
	}

	ok(
		idle_cpu < MAX_IDLE_CPU, "Idle CPU usage should be below expected - Exp:%d%%, Act: %lf%%",
		MAX_IDLE_CPU, idle_cpu
	);

	diag("Trigger BUSY_LOOP regression    BUSY_THREADS=%d BUSY_WAIT_SECS=%d", BUSY_THREADS, BUSY_WAIT_SECS);
	create_busy_loops(argc, argv, cl, BUSY_LOOP_T::BUSY_LOOP);

	diag("Checking ProxySQL final CPU usage for 'BUSY_LOOP'");
	double final_cpu_usage = 0;
	int ret_f_cpu = get_proxysql_cpu_usage(cl, final_cpu_usage, SAMPLE_INTV_SECS);

	ok(
		final_cpu_usage < MAX_BUSY_CPU,
		"ProxySQL CPU usage should be below expected - Exp: %d%%, Act: %lf%%",
		MAX_BUSY_CPU, final_cpu_usage
	);

	// Extra wait to ensure cleanup of faulty client conns. See 'BUSY_WAIT_SECS' NOTE in def.
	int BUSY_WAIT_CLEANUP = BUSY_WAIT_SECS < 5 ? 5 : BUSY_WAIT_SECS / 2;
	diag("Sleeping for %d secs for BUSY_LOOP client cleanup", BUSY_WAIT_CLEANUP);
	sleep(BUSY_WAIT_CLEANUP);

	diag("Checking ProxySQL idle CPU usage");
	ret_i_cpu = get_proxysql_cpu_usage(cl, idle_cpu, SAMPLE_INTV_SECS);
	if (ret_i_cpu) {
		diag("Getting initial CPU usage failed with error - %d", ret_i_cpu);
		diag("Aborting further testing");

		return EXIT_FAILURE;
	}

	ok(
		idle_cpu < MAX_IDLE_CPU, "Idle CPU usage should be below expected - Exp:%d%%, Act: %lf%%",
		MAX_IDLE_CPU, idle_cpu
	);

	diag("Trigger INF_LOOP regression    BUSY_THREADS=%d BUSY_WAIT_SECS=%d", BUSY_THREADS, BUSY_WAIT_SECS);
	create_busy_loops(argc, argv, cl, BUSY_LOOP_T::INF_LOOP);

	diag("Checking ProxySQL final CPU usage for 'BUSY_LOOP'");
	final_cpu_usage = 0;
	ret_f_cpu = get_proxysql_cpu_usage(cl, final_cpu_usage, SAMPLE_INTV_SECS);

	ok(
		final_cpu_usage < MAX_BUSY_CPU,
		"ProxySQL CPU usage should be below expected - Exp: %d%%, Act: %lf%%",
		MAX_BUSY_CPU, final_cpu_usage
	);

	// Recover cluster scheduler
	for (MYSQL* myconn : nodes_conns) {
		MYSQL_QUERY_T(myconn, "LOAD SCHEDULER FROM DISK");
		MYSQL_QUERY_T(myconn, "LOAD SCHEDULER TO RUNTIME");

		mysql_close(myconn);
	}

	mysql_close(admin);

	return exit_status();
}
