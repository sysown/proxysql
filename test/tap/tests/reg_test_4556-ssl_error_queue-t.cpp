/**
 * @file reg_test_4556-ssl_error_queue-t.cpp
 * @brief Regression test for SSL error queue cleanup in frontend/backend conns.
 * @details Two different kind of coherence checks are performed:
 *  1. SSL errors on fronted conns don't propagate or pollute other frontend/backend conns:
 *    1.1 Config ProxySQL for either perform conn retention or not (session_idle_ms). This ensure we
 *        test threads conn-sharing via 'idle-threads'.
 *    1.2 Warm-up the conn-pool with multiple conns per-thread, test even conn distribution.
 *    1.3 Force different kinds of SSL failures on frontend conns.
 *    1.4 Check that exercising all the other client conns doesn't result in errors. This ensures
 *    the thread that received the error, is not polluting other conns while processing the queries.
 *  2. SSL errors on backend conns don't propagate or pollute other frontend/backend conns:
 *    2.1 Config ProxySQL with the desired PING intv, will be used to check backend conns, and '100'
 *        as 'free_connections_pct' to prevent early cleanups.
 *    2.1 Warm-up the conn-pool creating backend conns for multiple threads.
 *    2.2 Connect to MySQL, and kill a random conn count from conn-pool.
 *    2.3 Let ProxySQL exercise backend conns via PING checks, ensure only killed conns died.
 *    2.4 Exercise all backend conns via trxs, exhausting the conn-pool, no errors should take place.
 */

#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <map>
#include <memory>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/resource.h>

#include "mysql.h"
#include "openssl/ssl.h"
#include "json.hpp"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::map;
using std::pair;
using std::string;
using std::vector;

using nlohmann::json;

#define TAP_NAME "TAP_SSL_ERROR_QUEUE___"

// Check ENV for partially disable test sections
const char* TEST_FRONTEND = getenv(TAP_NAME"TEST_FRONTEND_CONNS");
const char* TEST_CONN_DIST = getenv(TAP_NAME"TEST_CONN_DIST");
const char* TEST_BACKEND = getenv(TAP_NAME"TEST_BACKEND_CONNS");
const int HG_ID = get_env_int(TAP_NAME"MYSQL_SERVER_HOSTGROUP_ID", 0);
const int PER_THREAD_CONN_COUNT = get_env_int(TAP_NAME"PER_THREAD_CONN_COUNT", 20);

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

// Thread Input
struct th_args__in_t {
	CommandLine& cl;
};

// Thread Output
struct th_args__out_t {
	std::string thread_addr {};
};

struct th_args_t {
	th_args__in_t in_args;
	th_args__out_t out_args {};
};

void* create_ssl_conn_and_close_socket(void* arg) {
	th_args_t* th_args = static_cast<th_args_t*>(arg);
	CommandLine& cl = th_args->in_args.cl;

	MYSQL* myconn = mysql_init(NULL);
	mysql_ssl_set(myconn, NULL, NULL, NULL, NULL, NULL);

	if (!mysql_real_connect(myconn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, CLIENT_SSL)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(myconn));
		return NULL;
	}

	json j_session = fetch_internal_session(myconn, false);
	string thread_addr { j_session["thread"] };

	th_args->out_args.thread_addr = thread_addr;

	diag("Early closing socket of first conn   thread_addr=%s", thread_addr.c_str());
	close(myconn->net.fd);

	return NULL;
}

void* create_ssl_conn_and_close_socket_async(void* arg) {
	th_args_t* th_args = static_cast<th_args_t*>(arg);
	CommandLine& cl = th_args->in_args.cl;

	MYSQL* myconn = mysql_init(NULL);
	mysql_options(myconn, MYSQL_OPT_NONBLOCK, 0);
	mysql_ssl_set(myconn, NULL, NULL, NULL, NULL, NULL);

	MYSQL* ret = nullptr;
	diag("Starting async 'MySQL' connection   thread=%ld", pthread_self());
	int status = mysql_real_connect_start(
		&ret, myconn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, CLIENT_SSL
	);

	diag("Early closing socket of non-complete async conn  ret=%p status=%d", ret, status);
	close(myconn->net.fd);

	return NULL;
}

void* create_ssl_conn_inv_cert(void* arg) {
	th_args_t* th_args = static_cast<th_args_t*>(arg);
	CommandLine& cl = th_args->in_args.cl;

	MYSQL* myconn = mysql_init(NULL);
	mysql_options(myconn, MYSQL_OPT_NONBLOCK, 0);

	char* inv_cert_path = tempnam(nullptr, "tap");
	diag("Setting invalid CERT for conn with tmp file   path=%s", inv_cert_path);
	mysql_ssl_set(myconn, NULL, NULL, inv_cert_path, NULL, NULL);

	MYSQL* ret = nullptr;
	diag("Starting 'MySQL' connection with invalid CERT   thread=%ld", pthread_self());

	if (!mysql_real_connect(myconn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, CLIENT_SSL)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(myconn));
		return NULL;
	}

	return NULL;
}

/**
 * @brief Invalid cert data to place in temporary file.
 */
const char inv_cert[] {
	"-----BEGIN CERTIFICATE-----\n"
	"kDeWG8U5N5v61p9QRwUutjUnRgmtYQOoe52Ib8k6KTVhSk/BsxsKNBQ2CdbjhuDl\n"
	"5QIDc+5Z9FBIHFEL+jfivaA2X4jVRTZ52RPDDxqMK5Y3mTEyJZGE\n"
	"-----END CERTIFICATE-----"
};

void* create_ssl_conn_missing_cert(void* arg) {
	th_args_t* th_args = static_cast<th_args_t*>(arg);
	CommandLine& cl = th_args->in_args.cl;

	MYSQL* myconn = mysql_init(NULL);
	mysql_options(myconn, MYSQL_OPT_NONBLOCK, 0);

	char* inv_cert_path = tempnam(nullptr, "tap");
	FILE *tmp_file = fopen(inv_cert_path, "w");
	fprintf(tmp_file, inv_cert);
	fflush(tmp_file);

	diag("Setting invalid CERT for conn with tmp file   path=%s", inv_cert_path);
	mysql_ssl_set(myconn, NULL, NULL, inv_cert_path, NULL, NULL);

	MYSQL* ret = nullptr;
	diag("Starting 'MySQL' connection with invalid CERT   thread=%ld", pthread_self());

	if (!mysql_real_connect(myconn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, CLIENT_SSL)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(myconn));
		return NULL;
	}

	fclose(tmp_file);

	return NULL;
}

void check_threads_conns(const map<string,vector<MYSQL*>>& m_th_conns, const string& th_addr) {
	if (th_addr.empty()) {
		diag("Checking ALL threads conns");
	} else {
		diag("Checking conns filtered by thread   thread_addr=%s", th_addr.c_str());
	}

	for (const pair<string,vector<MYSQL*>>& p_th_conns : m_th_conns) {
		if (!th_addr.empty() && p_th_conns.first != th_addr) { continue; }

		diag("Checking thread conns   thread_addr=%s", p_th_conns.first.c_str());
		const vector<MYSQL*>& th_conns { p_th_conns.second };

		for (size_t i = 0; i < th_conns.size(); i++) {
			int rc = mysql_query(th_conns[i], "SELECT 1");

			ok(
				rc == 0,
				"Query should execute without error   rc=%d mysql_error='%s'",
				rc, mysql_error(th_conns[i])
			);

			MYSQL_RES* myres = mysql_store_result(th_conns[i]);

			ok(
				myres != nullptr && mysql_errno(th_conns[i]) == 0,
				"Resultset should be properly retreived   myres=%p mysql_error='%s'",
				myres, mysql_error(th_conns[i])
			);

			mysql_free_result(myres);
		}
	}
}

int create_conn(const CommandLine& cl) {
	struct sockaddr_in server_addr;

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Unable to create socket");
		return -1;
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(uint32_t(cl.port));

	if (inet_pton(AF_INET, cl.host, &server_addr.sin_addr) <= 0) {
		perror("'inet_pton' failed");
		close(sock);
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
		perror("Unable to connect");
		close(sock);
		return -1;
	}

	return sock;
}

char net_buf[4096] { 0 };

struct _mysql_hdr {
	u_int pkt_length:24, pkt_id:8;
};

int read_srv_handshake(int fd) {
	char* buf_pos = net_buf;

	int r = read(fd, buf_pos, sizeof(net_buf));
	if (r == -1) {
		perror("'read' failed");
		return r;
	}

	buf_pos += r;

	while (r > 0 && r < NET_HEADER_SIZE) {
		r = read(fd, buf_pos + r, sizeof(buf_pos));
		buf_pos += r;

		if (r == -1) {
			perror("'read' failed");
			return r;
		}
	}

	_mysql_hdr myhdr;
	memcpy(&myhdr, net_buf, sizeof(_mysql_hdr));

	while (r > 0 && r < myhdr.pkt_length) {
		r = read(fd, buf_pos + r, sizeof(buf_pos));
		buf_pos += r;

		if (r == -1) {
			perror("'read' failed");
			return r;
		}
	}

	return 0;
}

/**
 * @brief Hardcoded SSL_Request packet.
 */
unsigned char SSL_REQUEST_PKT[] = {
	0x20, 0x00, 0x00, 0x01, 0x85, 0xae, 0xff, 0x19,
	0x00, 0x00, 0x00, 0x01, 0xe0, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

void* force_ssl_pre_handshake_failure(void* arg) {
	th_args_t* th_args = static_cast<th_args_t*>(arg);
	CommandLine& cl = th_args->in_args.cl;

	diag("Creating TCP connection to ProxySQL");
	int sock = create_conn(cl);

	diag("Reading ServerHandshake packet");
	int rc = read_srv_handshake(sock);
	if (rc == -1) {
		diag("Failed to read ProxySQL init hanshake");
		return NULL;
	}

	diag("Sending harcoded 'SSLRequest'");
	rc = send(sock, SSL_REQUEST_PKT, sizeof(SSL_REQUEST_PKT), 0);
	if (rc == -1) {
		perror("'send' failed");
		return NULL;
	}

	diag("Closing socket just after 'SSLRequest'");
	close(sock);

	return NULL;
}

MYSQL* create_server_conn(CommandLine& cl) {
	MYSQL* server = mysql_init(NULL);

	if (
		!mysql_real_connect(
			server,
			cl.mysql_host,
			cl.mysql_username,
			cl.mysql_password,
			NULL,
			cl.mysql_port,
			NULL,
			0
		)
	) {
		diag(
			"Failed to create conn to MySQL   error=%s port=%d",
			mysql_error(server), cl.mysql_port
		);
		return NULL;
	}

	return server;
}

int create_test_database(CommandLine& cl, const string& name) {
	MYSQL* server = create_server_conn(cl);
	if (!server) { return EXIT_FAILURE; }

	const string q { "CREATE DATABASE IF NOT EXISTS " + name };
	if (mysql_query_t(server, q.c_str())) {
		diag("Query failed to execute   query=%s err=%s", q.c_str(), mysql_error(server));
		return EXIT_FAILURE;
	}

	mysql_close(server);
	return EXIT_SUCCESS;
}

const char CONNPOOL_DB[] { "reg_test_4556" };

pair<uint32_t,vector<MYSQL*>> warmup_conn_pool(CommandLine& cl, uint32_t CONNS_TOTAL) {
	// Create database to use to flag conn-pool connections
	diag("Creating testing database for connpool warming   database=%s", CONNPOOL_DB);
	if (create_test_database(cl, CONNPOOL_DB)) {
		diag("Failed to create testing db   database=%s", CONNPOOL_DB);
		return { EXIT_FAILURE, {} };
	}

	diag("Elevating process limits for conns creation");
	struct rlimit limits { 0, 0 };
	getrlimit(RLIMIT_NOFILE, &limits);
	diag("Old process limits   rlim_cur=%ld rlim_max=%ld", limits.rlim_cur, limits.rlim_max);
	if (limits.rlim_cur < CONNS_TOTAL * 2) {
		diag("Updating process max FD limit");
		limits.rlim_cur = CONNS_TOTAL * 2;
		setrlimit(RLIMIT_NOFILE, &limits);
	}
	diag("New process limits   rlim_cur=%ld rlim_max=%ld", limits.rlim_cur, limits.rlim_max);

	vector<MYSQL*> conns {};

	for (int i = 0; i < CONNS_TOTAL; i++) {
		MYSQL* myconn = mysql_init(NULL);

		if (!mysql_real_connect(myconn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			diag(
				"Failed to connect   addr=%s port=%d user=%s pass=%s err=%s",
				cl.host, cl.port, cl.username, cl.password, mysql_error(myconn)
			);
			return { EXIT_FAILURE, {} };
		}

		const vector<const char*> CONN_CREATE_QUERIES {
			"USE reg_test_4556",
			"/* create_new_connection=1 */ DO 1"
		};

		// Make sure to fill the connection pool
		for (const char* q : CONN_CREATE_QUERIES) {
			if (mysql_query_t(myconn, q)) {
				diag("Query failed to execute   query=%s err=%s", q, mysql_error(myconn));
				return { mysql_errno(myconn), {} };
			}
		}

		conns.push_back(myconn);
	}

	return { EXIT_SUCCESS, conns };
}

map<string,vector<MYSQL*>> create_conn_thread_map(vector<MYSQL*>& conns) {
	map<string,vector<MYSQL*>> m_thread_conns {};

	for (MYSQL* myconn : conns) {
		json j_session = fetch_internal_session(myconn, false);
		string thread_addr { j_session["thread"] };

		m_thread_conns[thread_addr].push_back(myconn);
	}

	return m_thread_conns;
}

void check_thread_conn_dist(const map<string,vector<MYSQL*>>& m_thread_conns) {
	if (TEST_CONN_DIST && strcasecmp(TEST_CONN_DIST, "0") == 0) { return; }

	size_t lo_count = 0;
	size_t hg_count = 0;

	diag("Dumping per-thread conn count:");
	for (const pair<string,vector<MYSQL*>>& thread_conns : m_thread_conns) {
		if (lo_count == 0 || thread_conns.second.size() < lo_count) {
			lo_count = thread_conns.second.size();
		}
		if (hg_count == 0 || thread_conns.second.size() > hg_count) {
			hg_count = thread_conns.second.size();
		}
		fprintf(stderr, "Map entry   thread=%s count=%ld\n", thread_conns.first.c_str(), thread_conns.second.size());
	}

	ok(lo_count != 0, "No thread should be left without connections   lo_count=%ld", lo_count);
}

int clean_conn_pool(MYSQL* admin) {
	// 0. Ensure connection pool cleanup
	MYSQL_QUERY_T(admin, "UPDATE mysql_servers SET max_connections=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	{
		MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_connection_pool");
		MYSQL_RES* myres = mysql_store_result(admin);
		diag("stats_mysql_connection_pool:\n%s", dump_as_table(myres).c_str());
	}

	const string COND_CONN_CLEANUP {
		"SELECT IIF((SELECT SUM(ConnUsed + ConnFree) FROM stats.stats_mysql_connection_pool"
			" WHERE hostgroup=" + std::to_string(HG_ID) + ")=0, 'TRUE', 'FALSE')"
	};
	int w_res = wait_for_cond(admin, COND_CONN_CLEANUP, 10);
	if (w_res) {
		{
			MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_connection_pool");
			MYSQL_RES* myres = mysql_store_result(admin);
			diag("stats_mysql_connection_pool:\n%s", dump_as_table(myres).c_str());
		}

		diag("Waiting for backend connections failed   res:'%d'", w_res);
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(admin, "UPDATE mysql_servers SET max_connections=500");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	{
		MYSQL_QUERY(admin, "SELECT * FROM stats_mysql_connection_pool");
		MYSQL_RES* myres = mysql_store_result(admin);
		diag("stats_mysql_connection_pool:\n%s", dump_as_table(myres).c_str());
	}

	return EXIT_SUCCESS;
}

int check_frontend_ssl_errs(
	CommandLine& cl, MYSQL* admin, int64_t thread_count, int64_t idle_sess_ms, void*(*ssl_err_cb)(void*)
) {
	// 0. Ensure connection pool cleanup
	int clean_rc = clean_conn_pool(admin);
	if (clean_rc) {
		diag("Conn-pool cleanup failed; aborting futher testing");
		return EXIT_FAILURE;
	}

	// 1. Configure ProxySQL forcing threads to retains conns
	MYSQL_QUERY_T(admin, ("SET mysql-session_idle_ms=" + std::to_string(idle_sess_ms)).c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// 2. Create connections based on number of threads
	pair<uint32_t,vector<MYSQL*>> p_rc_conns {};
	{
		uint32_t CONNS_TOTAL = thread_count * PER_THREAD_CONN_COUNT;
		diag(
			"Creating connections   threads=%ld per_thread_conns=%d total=%d",
			thread_count, PER_THREAD_CONN_COUNT, CONNS_TOTAL
		);

		p_rc_conns = warmup_conn_pool(cl, CONNS_TOTAL);
		if (p_rc_conns.first) { return EXIT_FAILURE; }
	}

	// 3. Check connection distribution on ProxySQL
	map<string,vector<MYSQL*>> m_thread_conns { create_conn_thread_map(p_rc_conns.second) };
	check_thread_conn_dist(m_thread_conns);

	// 4. Force a failure in a new connection; different kinds:
	//  - SSL failure due to pure SSL error, inv cert.
	//  - SSL failure due to closed socket; during query, or premature close.
	{
		pthread_t unexp_socket_close;
		void* th_ret = nullptr;
		std::unique_ptr<th_args_t> th_args {
			new th_args_t { th_args__in_t { cl }, th_args__out_t {} }
		};

		diag("Force early SSL failure in thread");
		pthread_create(&unexp_socket_close, NULL, ssl_err_cb, th_args.get());
		pthread_join(unexp_socket_close, &th_ret);
	}

	// 5. Check all the others client conns in same thread are not broken (SSL err queue).
	{
		diag("Checking connections handled by ALL threads");
		check_threads_conns(m_thread_conns, string {});
	}

	for (MYSQL* myconn : p_rc_conns.second) {
		mysql_close(myconn);
	}

	return EXIT_SUCCESS;
}

const uint32_t PING_INTV_MS { 1000 };

pair<int,double> fetch_metric_val(CommandLine& cl, const string& metric_id) {
	uint64_t curl_res_code = 0;
	string curl_res_data {};
	const char URL[] { "http://localhost:6070/metrics/" };

	diag("Fetching metric values via RESTAPI   URL=%s", URL);
	CURLcode code = perform_simple_get(URL, curl_res_code, curl_res_data);

	if (code != CURLE_OK || curl_res_code != 200) {
		diag("Failed to fetch current metrics   error=%s", curl_res_data.c_str());
		return { EXIT_FAILURE, 0 };
	}

	const map<string, double> m_id_val { parse_prometheus_metrics(curl_res_data) };
	diag(
		"Searching in fetched metrics   metric_id=%s map_size=%ld",
		metric_id.c_str(), m_id_val.size()
	);

	double error_count = 0;

	auto m_it = m_id_val.find(metric_id);
	if (m_it != m_id_val.end()) {
		error_count = m_it->second;
	}

	return { EXIT_SUCCESS, error_count };
}

/**
 * @brief Perform coherence checks on the backend conns.
 * @details The checks are performed in the following way:
 *   1. Warmup the conn-pool creating backend conns for multiple threads.
 *   2. Connect to MySQL, and kill random conns from conn-pool.
 *   3. Exercise all backend conns via PING checks, ensure only killed conns died.
 *   4. Exercise all backend conns via trxs, exhausting the conn-pool, no errors should take place.
 * @param cl Env config for conn creation.
 * @param admin Already open Admin conn for ProxySQL config.
 * @param thread_count Number of threads used by ProxySQL.
 * @return EXIT_SUCCESS if checks could be performed, EXIT_FAILURE otherwise.
 */
int check_backend_ssl_errs(CommandLine& cl, MYSQL* admin, int64_t thread_count) {
	// Ensure connection pool cleanup
	int clean_rc = clean_conn_pool(admin);
	if (clean_rc) {
		diag("Conn-pool cleanup failed; aborting futher testing");
		return EXIT_FAILURE;
	}

	// Configure ProxySQL to exercise backend connections via PING
	const string ping_intv_str { std::to_string(PING_INTV_MS) };
	MYSQL_QUERY(admin, ("SET mysql-ping_interval_server_msec=" + ping_intv_str).c_str());
	// Prevent early closing of backend conns; will interfere with error counting
	MYSQL_QUERY(admin, "SET mysql-free_connections_pct=100");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Create connections based on number of threads
	uint32_t CONNS_TOTAL = thread_count * PER_THREAD_CONN_COUNT;
	pair<uint32_t,vector<MYSQL*>> p_rc_conns {};

	diag(
		"Creating connections   threads=%ld per_thread_conns=%d total=%d",
		thread_count, PER_THREAD_CONN_COUNT, CONNS_TOTAL
	);

	p_rc_conns = warmup_conn_pool(cl, CONNS_TOTAL);
	if (p_rc_conns.first) { return EXIT_FAILURE; }

	// Create connection map for backend connetions; assuming high idle-sessions.
	map<string,vector<MYSQL*>> m_thread_conns { create_conn_thread_map(p_rc_conns.second) };

	// Kill several backend connnections; check ProxySQL only destroys the relevant ones
	MYSQL* server = create_server_conn(cl);
	if (!server) { return EXIT_FAILURE; }

	uint32_t TO_KILL = (thread_count * 2) + rand() % 10;
	uint32_t CONN_PCT = TO_KILL * 100 / CONNS_TOTAL;
	diag("Random conn kill count   kills=%d conn_pct=%d", TO_KILL, CONN_PCT);

	const string proc_list_q {
		"SELECT ID FROM information_schema.processlist"
			" WHERE DB='" + string { CONNPOOL_DB } + "'"
			" ORDER BY RAND() LIMIT " + std::to_string(TO_KILL)
	};
	diag("Fetching conns to be killed   query=%s", proc_list_q.c_str());
	const pair<uint32_t,vector<mysql_res_row>> p_conns_ids {
		mysql_query_ext_rows(server, proc_list_q)
	};
	if (p_conns_ids.first) {
		diag("Failed to fetch conns ids from processlist   error=%s", mysql_error(server));
		return EXIT_FAILURE;
	}

	// Fetch current connections errors to target server
	const string myport { std::to_string(cl.mysql_port) };
	const string m_srv_id {
		"mysql_error_total{"
			"address=\"" + string {cl.mysql_host} + "\",code=\"2013\","
			"hostgroup=\"" + std::to_string(HG_ID) + "\",port=\"" + myport + "\""
		"}"
	};

	pair<int,double> p_pre_count { fetch_metric_val(cl, m_srv_id) };
	if (p_pre_count.first) { return EXIT_FAILURE; }

	for (const mysql_res_row& conn_id_row : p_conns_ids.second) {
		MYSQL_QUERY_T(server, string {"KILL " + conn_id_row[0]}.c_str());
	}

	// Give time for ProxySQL to detect broken connections
	sleep((PING_INTV_MS / 1000 ) * 3);

	pair<int,double> p_post_count { fetch_metric_val(cl, m_srv_id) };

	ok(
		p_pre_count.second + TO_KILL == p_post_count.second,
		"Errors should be increased **ONLY** by killed conns   pre=%lf post=%lf to_kill=%d",
		p_pre_count.second, p_post_count.second, TO_KILL
	);

	// Check all conns remains viable using trxs to exhaust the conn-pool
	diag("Starting trxs   count=%ld", p_rc_conns.second.size());
	vector<int> trxs_rcs {};
	for (MYSQL* mysql : p_rc_conns.second) {
		int q_rc = mysql_query_t(mysql, "BEGIN");
		if (q_rc) {
			diag("Trx start failed   error=%s", mysql_error(mysql));
		}
		trxs_rcs.push_back(q_rc);
	}

	size_t failed_trxs = std::accumulate(trxs_rcs.begin(), trxs_rcs.end(), 0,
		[] (size_t acc, int n) {
			if (n != 0) { return acc + 1; }
			else { return acc; }
		}
	);

	ok(failed_trxs == 0, "No trxs should fail to start   failed_trxs=%ld", failed_trxs);

	for (MYSQL* mysql : p_rc_conns.second) {
		mysql_close(mysql);
	}

	return EXIT_SUCCESS;
}

const vector<int64_t> idle_sess_ms {
	10000 /* No session sharing on threads */,
	1     /* Session sharing between; via 'idle-threads' */
};

const vector<pair<string,void*(* const)(void*)>> ssl_failure_rts {
	{ "force_ssl_pre_handshake_failure", force_ssl_pre_handshake_failure },
	{ "create_ssl_conn_inv_cert", create_ssl_conn_inv_cert },
	{ "create_ssl_conn_missing_cert", create_ssl_conn_missing_cert }
};

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	diag("Init rand seed with current time");
	srand(time(NULL));

	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Disable query retry; required for further tests
	MYSQL_QUERY_T(admin, "SET mysql-query_retries_on_failure=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Ensure RESTAPI is enabled for backend conn errors fetching
	MYSQL_QUERY_T(admin, "SET admin-restapi_enabled=1");
	MYSQL_QUERY_T(admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// Update default hostgroup for user with target hostgroup
	MYSQL_QUERY_T(admin,
		("UPDATE mysql_users SET default_hostgroup=" + std::to_string(HG_ID) +
			" WHERE username='" + cl.username + "'").c_str()
	);
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	// Disable all queries rules if present; not required
	MYSQL_QUERY_T(admin, "UPDATE mysql_query_rules SET active=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	// Update MySQL servers config
	MYSQL_QUERY_T(admin,
		("UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id=" + std::to_string(HG_ID)).c_str()
	);
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	const char q_thread_count[] {
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-threads'"
	};
	ext_val_t<int64_t> ext_thread_count { mysql_query_ext_val(admin, q_thread_count, int64_t(0)) };

	if (ext_thread_count.err != EXIT_SUCCESS) {
		const string err { get_ext_val_err(admin, ext_thread_count) };
		diag("Failed getting 'mysql-threads'   query:`%s`, err:`%s`", q_thread_count, err.c_str());
		return EXIT_FAILURE;
	}

	const long conn_queries { PER_THREAD_CONN_COUNT * ext_thread_count.val * 2 };
	const size_t end_to_end_conns_checks { conn_queries * idle_sess_ms.size() * ssl_failure_rts.size() };
	const size_t thread_conn_dist_checks { ssl_failure_rts.size() * idle_sess_ms.size() };

	size_t frontend_conns_checks { 0 };
	size_t conns_dist_checks { 0 };
	size_t backend_conns_checks { 0 };

	if (!TEST_FRONTEND || (TEST_FRONTEND && strcasecmp(TEST_FRONTEND, "0") != 0)) {
		frontend_conns_checks = end_to_end_conns_checks;
	}
	if (!TEST_CONN_DIST || (TEST_CONN_DIST && strcasecmp(TEST_CONN_DIST, "0") != 0)) {
		conns_dist_checks = thread_conn_dist_checks;
	}
	if (!TEST_BACKEND || (TEST_BACKEND && strcasecmp(TEST_BACKEND, "0") != 0)) {
		backend_conns_checks = 2;
	}

	plan(frontend_conns_checks + conns_dist_checks + backend_conns_checks);

	if (!frontend_conns_checks) {
		goto backend_checks;
	}

frontend_checks:
	diag("START: Regression testing of #4556 for frontend conns");
	for (const pair<string, void*(*)(void*)> p_name_rt : ssl_failure_rts) {
		const char* rt_name = p_name_rt.first.c_str();
		void*(*ssl_fail_rt)(void*) = p_name_rt.second;

		for (size_t ms_idle : idle_sess_ms) {
			diag("Forcing SSL failure on fronted connection   routine=%s", p_name_rt.first.c_str());
			int rc = check_frontend_ssl_errs(cl, admin, ext_thread_count.val, ms_idle, ssl_fail_rt);
			if (rc) {
				diag("Unable to perform check, operation failed   routine=%s", p_name_rt.first.c_str());
				return EXIT_FAILURE;
			}
		}
	}

	if (!backend_conns_checks) {
		goto cleanup;
	}

backend_checks:
	diag("START: Regression testing for SSL errors on backend conns");
	{
		int rc = check_backend_ssl_errs(cl, admin, ext_thread_count.val);
		if (rc) {
			diag("Unable to perform check, operation failed");
			return EXIT_FAILURE;
		}
	}

cleanup:
	mysql_close(admin);

	return exit_status();
}
