/**
 * @file reg_test_unexp_ping_pkt-t.cpp
 * @brief Regression test exercising the special handling of unexpected COM_PING pkts.
 * @details The test sends invalid COM_PING packets after ProxySQL has started sending the resultset from a
 *   query to the client, and verifies that this COM_PING packets are being handled by ProxySQL. It exercises
 *   the previous flow for regular, SSL, compress and SSL + compress connections.
 */

#include "ezOptionParser.hpp"

#include <cstring>
#include <string>
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "mysql.h"
#include "openssl/ssl.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <functional>
#include <map>
#include <vector>
#include <utility>

using std::map;
using std::function;
using std::string;
using std::vector;
using std::pair;

struct cmd_opts_t {
	int ping_count { 2 };
	int ping_delay { 10 };
};

////////////////////////////////////////////////////////////////////////////////////////////////////
//          NOTE: JUST SOME DECLARATIONS (MARIADBCLIENT) FOR ACCESSING SSL CTX                    //
////////////////////////////////////////////////////////////////////////////////////////////////////

struct st_pvio_socket {
  my_socket socket;
  int fcntl_mode;
  MYSQL *mysql;
};

enum enum_pvio_type {
  PVIO_TYPE_UNIXSOCKET= 0,
  PVIO_TYPE_SOCKET,
  PVIO_TYPE_NAMEDPIPE,
  PVIO_TYPE_SHAREDMEM,
};

typedef struct st_ma_pvio_tls {
  void *data;
  MARIADB_PVIO *pvio;
  void *ssl;
} MARIADB_TLS;

struct st_ma_pvio {
  void *data;
  /* read ahead cache */
  uint8_t *cache;
  uint8_t *cache_pos;
  size_t cache_size;
  enum enum_pvio_type type;
  int timeout[3];
  int ssl_type;  /* todo: change to enum (ssl plugins) */
  MARIADB_TLS *ctls;
  MYSQL *mysql;
  void *methods;
  void (*set_error)(MYSQL *mysql, unsigned int error_nr, const char *sqlstate, const char *format, ...);
  void (*callback)(MARIADB_PVIO *pvio, my_bool is_read, const uint8_t *buffer, size_t length);
  size_t bytes_read;
  size_t bytes_sent;
};

////////////////////////////////////////////////////////////////////////////////////////////////////

rc_t<cmd_opts_t> get_cmd_options(int argc, const char* argv[]) {
	// command line options to extract
	cmd_opts_t opts {};

	// define the command line options
	ez::ezOptionParser opt_p {};
	opt_p.overview = "Regression test for unexpected COM_PING packet handling";
	opt_p.syntax = "reg_test_unexp_ping_pkt-t [OPTIONS]";
	opt_p.footer = "\n\nHave fun :)";

	// clang-format off
	opt_p.add(
		(const char *)"", 0, 0, 0, (const char *)"Display usage instructions.",
		(const char *)"-h", (const char *)"-help", (const char *)"--help", (const char *)"--usage"
	);
	opt_p.add(
		(const char *)"", 0, 1, 0, (const char *)"Number of COM_PING packets to send",
		(const char *)"-c", (const char *)"--count"
	);
	opt_p.add(
		(const char *)"", 0, 1, 0, (const char *)"Delay to use between COM_PING",
		(const char *)"-d", (const char *)"--delay"
	);
	// clang-format on

	// parse the arguments
	opt_p.parse(argc, argv);

	// extract command line options
	if (opt_p.isSet("-h")) {
		std::string usage {};
		opt_p.getUsage(usage);
		std::cout << usage << std::endl;

		exit(EXIT_SUCCESS);
	}
	if (opt_p.isSet("-c")) {
		opt_p.get("-c")->getInt(opts.ping_count);
	}
	if (opt_p.isSet("-d")) {
		opt_p.get("-d")->getInt(opts.ping_delay);
	}

	return { 0, opts };
}

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
		timeout = 1000 * mysql_get_timeout_value(mysql);
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

/**
 * @brief Hardcoded COM_PING_PKT packet header.
 */
unsigned char COM_PING_PKT[] = { 0x01,0x00,0x00,0x01,0x0E };
/**
 * @brief Hardcoded COMPRESS COM_PING_PKT packet header.
 */
unsigned char COM_PING_PKT_CMP[] = { 0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x01,0x0E };

const uint32_t MYSQL_DEF_TO = 3;

rc_t<MYSQL*> create_async_conn(const CommandLine& cl, uint64_t cflags) {
	MYSQL* proxy = mysql_init(NULL);
	// enable async API
	mysql_options(proxy, MYSQL_OPT_NONBLOCK, 0);

	// timeout for timing purposes on async API usage
	mysql_options(proxy, MYSQL_OPT_READ_TIMEOUT, &MYSQL_DEF_TO);
	mysql_options(proxy, MYSQL_OPT_CONNECT_TIMEOUT, &MYSQL_DEF_TO);
	mysql_options(proxy, MYSQL_OPT_WRITE_TIMEOUT, &MYSQL_DEF_TO);

	if (cflags | CLIENT_SSL) {
		mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);
	}
	cflags |= CLIENT_MULTI_STATEMENTS;

	MYSQL* ret { 0 };

	diag(
		"Creating 'ProxySQL' connection   host=\"%s\" user=\"%s\" flags=%ld",
		cl.host, cl.username, cflags
	);
	int st {
		mysql_real_connect_start(
			&ret, proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, cflags
		)
	};

	diag("Started 'ProxySQL' connection creation   ret=%p status=%d", ret, st);
	while (st) {
		diag("  + Waiting for 'ProxySQL'");
		st = wait_for_mysql(proxy, st);
		diag("  + Wait finished   st=%d", st);
		st = mysql_real_connect_cont(&ret, proxy, st);
		diag("  + Connection creation continues   ret=%p st=%d", ret, st);
	}
	diag("Finished 'ProxySQL' connection creation   ret=%p status=%d", ret, st);

	if (!ret) {
		diag("Connection creation failed   error=\"%s\"", mysql_error(proxy));
		return { mysql_errno(proxy), nullptr };
	} else {
		return { 0, proxy };
	}
}

rc_t<map<string,double>> get_prometheus_metrics(MYSQL* admin) {
	int rc = mysql_query_t(admin, "SHOW PROMETHEUS METRICS\\G");
	if (rc) { return { static_cast<int>(mysql_errno(admin)), {} }; }

	MYSQL_RES* p_resulset = mysql_store_result(admin);
	MYSQL_ROW data_row = mysql_fetch_row(p_resulset);

	std::string row_value {};
	if (data_row[0]) {
		row_value = data_row[0];
	} else {
		row_value = "NULL";
	}

	mysql_free_result(p_resulset);

	return { 0, parse_prometheus_metrics(row_value) };
}

int exec_config_queries(MYSQL* admin, const vector<string>& cfg_queries) {
	diag("Configuring ProxySQL for test");
	for (const string& q : cfg_queries) {
		int rc = mysql_query_t(admin, q.c_str());
		if (rc) {
			diag("Failed to configure ProxySQL for test   query=\"%s\"", q.c_str());
			return mysql_errno(admin);
		}
	}

	return 0;
}

int mysql_read_result(MYSQL* proxy) {
	int st { 0 };
	MYSQL_RES* res { nullptr };

	do {
		diag("Starting resultset fetching   st=%d", st);
		st = mysql_store_result_start(&res, proxy);

		while (st) {
			// diag("  + Waiting for 'ProxySQL'");
			st = wait_for_mysql(proxy, st);
			// diag("  + Wait finished   st=%d", st);
			st = mysql_store_result_cont(&res, proxy, st);
			// diag("  + Storing resultset continue    st=%d", st);
		}
		diag("Finished resultset fetching   st=%d", st);

		if (res) {
			while (MYSQL_ROW row = mysql_fetch_row(res)) {
				diag(
					"  + row_fetching - Received new row   size=%ld val=`%.20s`",
					row[0] ? strlen(row[0]) : 0, row[0] ? row[0] : "NULL"
				);
			}

			mysql_free_result(res);
		}

		diag("Fetching next resultset   st=%d", st);
		st = mysql_next_result_start(&st, proxy);
		while (st) {
			diag("  + Waiting for 'ProxySQL'");
			st = wait_for_mysql(proxy, st);
			diag("  + Wait finished   st=%d", st);
			st = mysql_next_result_cont(&st, proxy, st);
			diag("  + Fetching next resultset    st=%d", st);
		}
	} while (st || res);

	return EXIT_SUCCESS;
}

int test_unex_com_ping(MYSQL* proxy, const cmd_opts_t& opts) {
	int q_err = 0;

	const char q_sleep[] {
		"/* hostgroup=0 */ SELECT string FROM test.unexp_ping_rnd; SELECT SLEEP(2)"
	};

	diag("Issuing mysql_query_start   query=\"%s\"", q_sleep);
	int st = mysql_real_query_start(&q_err, proxy, q_sleep, sizeof(q_sleep));
	diag("Executed mysql_query_start   status=%d query=\"%s\"", st, q_sleep);

	if (q_err) {
		diag("'mysql_real_query_start()' failed   error=`%s`", mysql_error(proxy));
		return EXIT_FAILURE;
	}

	{
		// Write multiple COM_PING packet
		const int32_t wr_delay { opts.ping_delay * 1000 };
		const int32_t s_flags { MSG_DONTWAIT | MSG_NOSIGNAL };

		for (uint32_t i = 0; i < opts.ping_count; i++) {
			if (i == 0 && (true /* && rand() % 2 */)) {
				diag("Waiting to ensure session status isn't 'WAITING_CLIENT_DATA'");
				int w_res = wait_for_mysql(proxy, MYSQL_WAIT_READ | MYSQL_WAIT_TIMEOUT);
				diag("Wait finished   st=%d w_res=%d", st, w_res);
			} else {
				diag("Immediate write! Exercising packet queuing in PSarrayIN");
			}

			diag("Sending forced COM_PING packet");
			ssize_t sz { 0 };
			{
				errno = 0;
				MARIADB_TLS* ctls { proxy->net.pvio->ctls };

				const unsigned char* PING_PKT {
					proxy->options.compress ? COM_PING_PKT_CMP : COM_PING_PKT
				};
				const size_t PING_PKT_SZ {
					proxy->options.compress ? sizeof(COM_PING_PKT_CMP) : sizeof(COM_PING_PKT)
				};

				if (ctls) {
					sz = SSL_write((SSL*)ctls->ssl, PING_PKT, PING_PKT_SZ);
				} else {
					sz = send(proxy->net.fd, PING_PKT, PING_PKT_SZ, s_flags);
				}
			}
			diag("Sent forced COM_PING packet   rc=%ld errno=%d", sz, errno);

			diag("Delay between COM_PING packets (mix timing)   delay=%d", wr_delay);
			usleep(wr_delay);
		}
	}

	diag("Continue query execution   st=%d query=\"%s\"", st, q_sleep);
	while (st) {
		st = wait_for_mysql(proxy, st);
		st = mysql_real_query_cont(&q_err, proxy, st);
	}
	diag("Finished query execution   st=%d query=\"%s\"", st, q_sleep);

	if (q_err) {
		diag("Query execution failed   error=`%s` query=\"%s\"", mysql_error(proxy), q_sleep);
		return EXIT_FAILURE;
	}

	diag("Read query result   query=\"%s\"", q_sleep);
	{
		int res_rc { mysql_read_result(proxy) };
		if (res_rc) {
			return EXIT_FAILURE;
		}
	}

	diag("Read queued OK packets (if any) after resulset read");
	{
		char net_buf[4096] { 0 };
		char* buf_pos = net_buf;
		ssize_t r { 0 };

		st = wait_for_mysql(proxy, MYSQL_WAIT_READ | MYSQL_WAIT_TIMEOUT);
		diag("Waiting ProxySQL to signal for 'READING'   st=%d", st);

		while ((st && st != MYSQL_WAIT_TIMEOUT)) {
			r = read(proxy->net.fd, buf_pos + r, sizeof(net_buf));
			diag("  + Read COM_PING OK packet from ProxySQL   r=%ld", r);

			if (r <= 0) {
				break;
			} else {
				buf_pos += r;

				diag("  + Waiting for 'ProxySQL'");
				st = wait_for_mysql(proxy, MYSQL_WAIT_READ | MYSQL_WAIT_TIMEOUT);
				diag("  + Wait finished   st=%d", st);
			}
		}
	}

	// NOTE: This will not work due to limitations in libmariadbclient to handle the extra OK packets. Left
	// disabled in case it needs to be explored manually.
	/////////////////////////////////////////////////////////////////////////////////////////////////
	{
		// diag("Perform new query after OK packets handling");

		// const char q_one[] { "SELECT 2" };
		// diag("Issuing mysql_query_start   query=\"%s\"", q_one);
		// int st = mysql_real_query_start(&q_err, proxy, q_one, sizeof(q_one));
		// diag("Executed mysql_query_start   status=%d query=\"%s\" error=%d", st, q_one, q_err);

		// if (q_err) {
		// 	diag("'mysql_real_query_start()' failed   error=`%s`", mysql_error(proxy));
		// 	return EXIT_FAILURE;
		// }

		// diag("Continue query execution   st=%d query=\"%s\"", st, q_one);
		// while (st) {
		// 	st = wait_for_mysql(proxy, st);
		// 	st = mysql_real_query_cont(&q_err, proxy, st);
		// }
		// diag("Finished query execution   st=%d query=\"%s\"", st, q_one);

		// if (q_err) {
		// 	diag("'mysql_real_query_cont()' failed   error=`%s`", mysql_error(proxy));
		// 	return EXIT_FAILURE;
		// }

		// diag("Read query result   query=\"%s\"", q_one);
		// int res_rc { mysql_read_result(proxy) };
		// if (res_rc) {
		// 	return EXIT_FAILURE;
		// }
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////

	{
		// fix-leaks due to 'mysql_init_override'
		if (proxy->unused_0) {
			delete static_cast<string*>(proxy->unused_0);
			proxy->unused_0 = nullptr;
		}

		diag("Closing MySQL connection");
		mysql_close(proxy);
	}

	return EXIT_SUCCESS;
}

rc_t<MYSQL*> cfg_std(const CommandLine& cl, MYSQL* admin) {
	const vector<string> cfg_queries {
		"SET mysql-have_compress='false'",
		"SET mysql-have_ssl='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};

	int cfg_rc { exec_config_queries(admin, cfg_queries) };
	if (cfg_rc) { return { cfg_rc, nullptr }; }

	return create_async_conn(cl, 0);
}

rc_t<MYSQL*> cfg_compress(const CommandLine& cl, MYSQL* admin) {
	const vector<string> cfg_queries {
		"SET mysql-have_compress='true'",
		"SET mysql-have_ssl='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};

	int cfg_rc { exec_config_queries(admin, cfg_queries) };
	if (cfg_rc) { return { cfg_rc, nullptr }; }

	return create_async_conn(cl, CLIENT_COMPRESS);
}

rc_t<MYSQL*> cfg_ssl(const CommandLine& cl, MYSQL* admin) {
	const vector<string> cfg_queries {
		"SET mysql-have_compress='false'",
		"SET mysql-have_ssl='true'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};

	int cfg_rc { exec_config_queries(admin, cfg_queries) };
	if (cfg_rc) { return { cfg_rc, nullptr }; }

	return create_async_conn(cl, CLIENT_SSL);
}

rc_t<MYSQL*> cfg_compress_ssl(const CommandLine& cl, MYSQL* admin) {
	const vector<string> cfg_queries {
		"SET mysql-have_compress='true'",
		"SET mysql-have_ssl='true'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};

	int cfg_rc { exec_config_queries(admin, cfg_queries) };
	if (cfg_rc) { return { cfg_rc, nullptr }; }

	return create_async_conn(cl, CLIENT_SSL | CLIENT_COMPRESS);
}

const vector<pair<string,function<rc_t<MYSQL*>(const CommandLine&, MYSQL*)>>> test_cfgs {
	{ "STD",          cfg_std },
	{ "COMPRESS",     cfg_compress },
	{ "SSL",          cfg_ssl },
	{ "COMPRESS|SSL", cfg_compress_ssl }
};

int perfom_tests_with_cfgs(CommandLine& cl, MYSQL* admin, const cmd_opts_t& opts) {
	for (const auto& cfg_conn : test_cfgs) {
		diag("Starting new unexpected COM_PING test   config=\"%s\"", cfg_conn.first.c_str());
		rc_t<MYSQL*> rc_conn { cfg_conn.second(cl, admin) };

		if (rc_conn.second) {
			auto pre_metrics { get_prometheus_metrics(admin) };
			int rc { test_unex_com_ping(rc_conn.second, opts) };
			auto post_metrics { get_prometheus_metrics(admin) };

			const auto pre_val { pre_metrics.second["proxysql_mysql_unexpected_frontend_com_ping_total"] };
			const auto post_val { post_metrics.second["proxysql_mysql_unexpected_frontend_com_ping_total"] };
			const auto diff { post_val - pre_val };

			ok(rc == EXIT_SUCCESS, "Connection should be usable till close (no-disconnect)");

			ok(
				diff == opts.ping_count,
				"Metrics diff should match sent COM_PING packets   sent=%d pre_val=%lf post_val=%lf diff=%lf",
				opts.ping_count, pre_val, post_val, diff
			);

			if (rc) {
				diag("Test config failed; aborting further testing   config=\"%s\"", cfg_conn.first.c_str());
				return EXIT_FAILURE;
			}
		} else {
			diag("Conn creation failed; aborting further testing   mysql_errno=\"%d\"", rc_conn.first);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

int main(int argc, const char* argv[]) {
	plan(test_cfgs.size() * 2 + 1);

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	srand(static_cast<uint32_t>(time(0)));

	const auto opts { get_cmd_options(argc, argv) };
	if (opts.first) {
		fprintf(stderr, "Unable to process CMD options   error=%d", opts.first);
		return EXIT_FAILURE;
	}

	diag("Prepare server defaults; increasing packet limits");
	{
		MYSQL* proxy = mysql_init(NULL);

		if (
			!mysql_real_connect(
				proxy, cl.root_host, cl.root_username, cl.root_password, NULL, cl.mysql_port, NULL, 0
			)
		) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		}

		int recvbuf { 0 };
		socklen_t recvbuf_len { sizeof(recvbuf) } ;
		getsockopt(proxy->net.fd, SOL_SOCKET, SO_RCVBUF, &recvbuf, &recvbuf_len);
		diag("MySQL socket options   SO_RCVBUF=%d", recvbuf);

		MYSQL_QUERY_T(proxy,
			 ("/* hostgroup=0 */ SET GLOBAL max_allowed_packet=" + std::to_string(recvbuf * 1000)).c_str()
		);

		mysql_close(proxy);
	}

	diag("Prepare test data; create testing table");
	{
		MYSQL* proxy = mysql_init(NULL);

		if (
			!mysql_real_connect(
				proxy, cl.root_host, cl.root_username, cl.root_password, NULL, cl.mysql_port, NULL, 0
			)
		) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		}

		int recvbuf { 0 };
		socklen_t recvbuf_len { sizeof(recvbuf) } ;
		getsockopt(proxy->net.fd, SOL_SOCKET, SO_RCVBUF, &recvbuf, &recvbuf_len);
		diag("MySQL socket options   SO_RCVBUF=%d", recvbuf);

		MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
		MYSQL_QUERY_T(proxy, "CREATE TABLE IF NOT EXISTS test.unexp_ping_rnd (string LONGTEXT)");
		MYSQL_QUERY_T(proxy, "DELETE FROM test.unexp_ping_rnd");

		// NOTE: Theoretically 'recvbuf * 4' should be enough to hold the read on client side, and being able
		// to trigger the 'data-on-both-ends' flow protection by ProxySQL. But, since we need to take into
		// account SSL and compression, this is no longer the case, the buffers are not directly sockets but
		// maybe internal buffers by SSL and this could also be the case for compression. For avoiding issues
		// with this internal buffers we increase the size '25' times the required one.
		const string rnd_str { random_string(recvbuf * 100) };
		const char q_insert[] { "INSERT INTO test.unexp_ping_rnd (string) VALUES (?)" };

		MYSQL_STMT* stmt = mysql_stmt_init(proxy);
		if (mysql_stmt_prepare(stmt, q_insert, sizeof(q_insert))) {
			diag("PREPARE stmt failed   error=\"%s\"", mysql_stmt_error(stmt));
			mysql_stmt_close(stmt);
			return EXIT_FAILURE;
		}

		MYSQL_BIND bind[1];
		memset(bind, 0, sizeof(bind));

		{
			uint64_t len = rnd_str.size();
			bind[0].buffer_type = MYSQL_TYPE_STRING;
			bind[0].buffer = const_cast<char*>(rnd_str.c_str());
			bind[0].buffer_length = len;
			bind[0].length = &len;
		}

		if (mysql_stmt_bind_param(stmt, bind)) {
			diag("INSERT bind failed   error=\"%s\"", mysql_stmt_error(stmt));
			mysql_stmt_close(stmt);
			return EXIT_FAILURE;
		}

		diag("Inserting test data");
		if (mysql_stmt_execute(stmt)) {
			diag("INSERT execute failed   error=\"%s\"", mysql_stmt_error(stmt));
			mysql_stmt_close(stmt);
			return EXIT_FAILURE;
		}

		mysql_stmt_close(stmt);
		mysql_close(proxy);
	}
	diag("Test data preparation finished");

	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(
		admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0
	)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	diag("Cleanup 'connection_pool' to ensure reload of 'max_allowed_packet'");
	MYSQL_QUERY_T(admin, "UPDATE mysql_servers SET max_connections=0 WHERE hostgroup_id IN (0, 1)");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Wait for backend connection cleanup
	const string check_conn_cleanup {
		"SELECT IIF((SELECT SUM(ConnUsed + ConnFree) FROM stats.stats_mysql_connection_pool"
			" WHERE hostgroup=0 OR hostgroup=1)=0, 'TRUE', 'FALSE')"
	};
	int w_res = wait_for_cond(admin, check_conn_cleanup, 10);
	if (w_res != EXIT_SUCCESS) {
		diag("Waiting for backend connections failed   res:'%d'", w_res);
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(admin, "UPDATE mysql_servers SET max_connections=500 WHERE hostgroup_id IN (0, 1)");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	int rc { perfom_tests_with_cfgs(cl, admin, opts.second) };
	ok(rc == EXIT_SUCCESS, "Unexpected COM_PING tests should succeed for all cfgs   rc=%d", rc);

	mysql_close(admin);

	return exit_status();
}
