/**
 * @file pgsql_login_refusal_shun_unit-t.cpp
 * @brief A login that PostgreSQL refuses must not shun the server.
 *
 * PgSQL_SrvC::connect_error() decides whether a failed backend connect counts toward shunning.
 * It was given 9999 for every failure, and its exemption list held only MySQL error numbers,
 * so a login PostgreSQL refused (wrong password, no pg_hba.conf entry, unknown database, no
 * CONNECT privilege) counted as a broken server: five in one second shunned it, and every
 * client of the hostgroup then waited for a backend connection.
 *
 * Backend connects: a fake backend on 127.0.0.1 answers every StartupMessage with an
 * ErrorResponse carrying the SQLSTATE under test. Real connects run through
 * PgSQL_Connection::async_connect(), as the session drives them, with the native and with the
 * libpq backend protocol. Checked:
 *  - the refusal reaches the connection with its SQLSTATE;
 *  - a refused login (28000, 28P01, 3D000, 42501 "permission denied for database") leaves the
 *    server ONLINE, and so do the connection limit of a role or a database (53300 "for role" /
 *    "for database"), a database that takes no connections or is invalid (55000), and a startup
 *    option the client sent that PostgreSQL rejects (22023, 42704, 55P02, 25001, 42602, 42601,
 *    0A000, 42501 "permission denied to set");
 *  - a failure of the server itself (57P03 starting up, 53300 server full, 42501 from a file
 *    permission or binary upgrade mode) still shuns it;
 *  - every failure is still counted in the server's connect_ERR, and in the pgsql error
 *    counter under its SQLSTATE (it was labelled 9999), a P0001 from the backend included.
 *
 * Session: a connect that fails without a backend error is counted by the connection and by the
 * session, both under the code the native protocol gives it: 08001 for a timeout (the session
 * labelled it XXXXX), 08006 for a refused port (libpq mode labelled it P0001). A connect that
 * fails with no error at all is labelled 08006 too.
 *
 * Monitor: a server whose last pgsql-monitor_ping_max_failures pings all failed is shunned and
 * its connections killed. Only "password authentication failed" was left out of that count, so
 * a monitor login refused for any other reason shunned every server. Checked through
 * server_responds_to_ping(), which runs the shunning query itself.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Monitor.hpp"
#include "PgSQL_Session.h"
#include "PgSQL_Thread.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <string>
#include <thread>

extern PgSQL_HostGroups_Manager* PgHGM;

using Conn = PgSQL_Connection;

// Failed connects per case: well above pgsql-shun_on_failures, so a counted failure shuns.
static const int CONNECTS = 12;

static bool read_exact(int fd, unsigned char* buf, size_t n, int ms) {
	size_t got = 0;
	while (got < n) {
		struct pollfd p { fd, POLLIN, 0 };
		if (poll(&p, 1, ms) <= 0) return false;
		ssize_t r = read(fd, buf + got, n - got);
		if (r <= 0) return false;
		got += r;
	}
	return true;
}

static std::string error_response(const char* sqlstate, const char* message) {
	std::string body;
	auto field = [&body](char type, const std::string& value) {
		body += type;
		body += value;
		body += '\0';
	};
	field('S', "FATAL");
	field('V', "FATAL");
	field('C', sqlstate);
	field('M', message);
	body += '\0';
	const uint32_t len = htonl(static_cast<uint32_t>(body.size() + 4));
	std::string msg(1, 'E');
	msg.append(reinterpret_cast<const char*>(&len), 4);
	return msg + body;
}

// A backend that refuses every login with one SQLSTATE: an SSL or GSS encryption request is
// declined with 'N', the StartupMessage is answered with the ErrorResponse, then it hangs up.
// With ask_password, it first asks for a cleartext password, and refuses whatever comes back.
struct FakeBackend {
	int lfd = -1;
	unsigned short port = 0;
	std::string reply;
	bool ask_password = false;
	std::atomic<bool> stop { false };
	std::thread th;

	FakeBackend(const char* sqlstate, const char* message, bool _ask_password = false)
		: reply(error_response(sqlstate, message)), ask_password(_ask_password) {
		lfd = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in a {};
		a.sin_family = AF_INET;
		inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
		socklen_t len = sizeof(a);
		if (lfd < 0 || bind(lfd, reinterpret_cast<sockaddr*>(&a), len) != 0 || listen(lfd, 16) != 0)
			BAIL_OUT("could not listen on 127.0.0.1");
		getsockname(lfd, reinterpret_cast<sockaddr*>(&a), &len);
		port = ntohs(a.sin_port);
		th = std::thread([this] { run(); });
	}

	~FakeBackend() {
		stop = true;
		th.join();
		close(lfd);
	}

	void run() {
		while (!stop) {
			struct pollfd p { lfd, POLLIN, 0 };
			if (poll(&p, 1, 50) <= 0) continue;
			int peer = accept(lfd, nullptr, nullptr);
			if (peer < 0) continue;
			serve(peer);
			close(peer);
		}
	}

	void serve(int peer) {
		for (;;) {
			unsigned char len_buf[4];
			if (!read_exact(peer, len_buf, 4, 2000)) return;
			uint32_t n = 0;
			memcpy(&n, len_buf, 4);
			n = ntohl(n);
			if (n < 8 || n > 10000) return;
			std::string rest(n - 4, '\0');
			if (!read_exact(peer, reinterpret_cast<unsigned char*>(&rest[0]), rest.size(), 2000)) return;
			uint32_t code = 0;
			memcpy(&code, rest.data(), 4);
			code = ntohl(code);
			if (n == 8 && (code == 80877103 || code == 80877104)) { // SSLRequest, GSSENCRequest
				if (write(peer, "N", 1) != 1) return;
				continue;
			}
			if (ask_password) {
				static const unsigned char auth_cleartext[] = { 'R', 0, 0, 0, 8, 0, 0, 0, 3 };
				if (write(peer, auth_cleartext, sizeof(auth_cleartext)) != (ssize_t)sizeof(auth_cleartext)) return;
				// The PasswordMessage, if the client sends one: libpq hangs up without a password.
				unsigned char hdr[5];
				if (!read_exact(peer, hdr, sizeof(hdr), 2000)) return;
				uint32_t m = 0;
				memcpy(&m, hdr + 1, 4);
				m = ntohl(m);
				if (m < 4 || m > 10000) return;
				std::string body(m - 4, '\0');
				if (!read_exact(peer, reinterpret_cast<unsigned char*>(&body[0]), body.size(), 2000)) return;
			}
			if (write(peer, reply.data(), reply.size()) != (ssize_t)reply.size()) return;
			return;
		}
	}
};

// The client's tracked variables, which the StartupMessage is built from.
static void fill_tracked_variables(PgSQL_Connection* conn) {
	for (int idx = 0; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {
		const char* def_val = pgsql_tracked_variables[idx].default_value;
		conn->variables[idx].value = strdup(def_val);
		conn->var_hash[idx] = SpookyHash::Hash32(def_val, strlen(def_val), 10);
	}
}

static PgSQL_SrvC* add_server(int hid, unsigned short port) {
	PgSQL_srv_info_t info;
	info.addr = "127.0.0.1";
	info.port = port;
	info.kind = "test";
	PgSQL_srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 100;
	opts.use_ssl = 0;
	PgHGM->wrlock();
	// find_server_in_hg() searches the last hostgroup when `hid` has none yet: create it first.
	PgHGM->MyHGC_lookup(hid);
	const int rc = PgHGM->create_new_server_in_hg(hid, info, opts);
	PgHGM->wrunlock();
	if (rc != 0) return nullptr;
	PgSQL_HGC* hgc = PgHGM->MyHGC_find(hid);
	for (unsigned int i = 0; hgc && i < hgc->mysrvs->cnt(); i++) {
		PgSQL_SrvC* srv = hgc->mysrvs->idx(i);
		if (srv->port == port) return srv;
	}
	return nullptr;
}

// One backend connect, driven the way the session drives it: async_connect() with the events
// polled on the connection's socket, until it succeeds (0) or fails (-1, -2). The SQLSTATE the
// connection ended with goes to `code`.
static int run_connect(PgSQL_SrvC* srv, PgSQL_Session* sess, PGSQL_ERROR_CODES* code, const char* password = "shun_test") {
	Conn* c = new Conn(false);
	c->parent = srv;
	c->userinfo->username = strdup("shun_test");
	c->userinfo->password = strdup(password);
	c->userinfo->dbname = strdup("shun_test");
	fill_tracked_variables(c);
	PgSQL_Data_Stream* ds = new PgSQL_Data_Stream();
	ds->init(MYDS_BACKEND, sess, -1);
	ds->attach_connection(c);

	int rc = 1;
	short revents = 0;
	for (int i = 0; i < 200 && rc == 1; i++) {
		sess->thread->curtime = monotonic_time();
		rc = c->async_connect(revents);
		if (rc != 1) break;
		short want = 0;
		if (c->async_exit_status & PG_EVENT_READ) want |= POLLIN;
		if (c->async_exit_status & PG_EVENT_WRITE) want |= POLLOUT;
		struct pollfd p { c->get_pg_socket_fd(), want ? want : (short)POLLIN, 0 };
		revents = (poll(&p, 1, 2000) > 0) ? p.revents : 0;
	}
	*code = c->get_error_code();
	ds->myconn = nullptr;
	delete ds;
	delete c;
	return rc;
}

struct Case {
	const char* sqlstate;
	const char* message; // PostgreSQL's own wording
	PGSQL_ERROR_CODES code;
	bool shuns; // whether this failure says the server itself is unusable
	const char* what;
};

static const Case CASES[] = {
	{ "28000", "no pg_hba.conf entry for host \"127.0.0.1\", user \"shun_test\", database \"shun_test\", no encryption",
		PGSQL_ERROR_CODES::ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION, false, "no pg_hba.conf entry" },
	{ "28P01", "password authentication failed for user \"shun_test\"",
		PGSQL_ERROR_CODES::ERRCODE_INVALID_PASSWORD, false, "wrong password" },
	{ "3D000", "database \"shun_test\" does not exist",
		PGSQL_ERROR_CODES::ERRCODE_INVALID_CATALOG_NAME, false, "unknown database" },
	{ "42501", "permission denied for database \"shun_test\"",
		PGSQL_ERROR_CODES::ERRCODE_INSUFFICIENT_PRIVILEGE, false, "no CONNECT privilege" },
	{ "55000", "database \"shun_test\" is not currently accepting connections",
		PGSQL_ERROR_CODES::ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE, false, "database not accepting connections" },
	{ "55000", "cannot connect to invalid database \"shun_test\"",
		PGSQL_ERROR_CODES::ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE, false, "invalid database" },
	// The client's own startup options, which reach the backend as -c key=value.
	{ "22023", "invalid value for parameter \"work_mem\": \"abc\"",
		PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE, false, "bad startup option value" },
	{ "42704", "unrecognized configuration parameter \"no_such_parameter\"",
		PGSQL_ERROR_CODES::ERRCODE_UNDEFINED_OBJECT, false, "unknown startup option" },
	{ "55P02", "parameter \"shared_buffers\" cannot be changed without restarting the server",
		PGSQL_ERROR_CODES::ERRCODE_CANT_CHANGE_RUNTIME_PARAM, false, "startup option not settable" },
	{ "25001", "SET TRANSACTION ISOLATION LEVEL must be called before any query",
		PGSQL_ERROR_CODES::ERRCODE_ACTIVE_SQL_TRANSACTION, false, "transaction_isolation startup option" },
	{ "42602", "invalid configuration parameter name \"app.tenant-id\"",
		PGSQL_ERROR_CODES::ERRCODE_INVALID_NAME, false, "bad startup option name" },
	{ "42601", "-c x requires a value",
		PGSQL_ERROR_CODES::ERRCODE_SYNTAX_ERROR, false, "unparsable startup option" },
	{ "0A000", "conversion between SJIS and LATIN1 is not supported",
		PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED, false, "client_encoding the database cannot convert" },
	{ "42501", "permission denied to set parameter \"session_replication_role\"",
		PGSQL_ERROR_CODES::ERRCODE_INSUFFICIENT_PRIVILEGE, false, "startup option needs a privilege" },
	// 42501 is also a file-permission error, which breaks every connect.
	{ "42501", "could not access directory \"base/16384\": Permission denied",
		PGSQL_ERROR_CODES::ERRCODE_INSUFFICIENT_PRIVILEGE, true, "database directory not readable" },
	{ "42501", "must be superuser to connect in binary upgrade mode",
		PGSQL_ERROR_CODES::ERRCODE_INSUFFICIENT_PRIVILEGE, true, "server in binary upgrade mode" },
	{ "53300", "too many connections for role \"shun_test\"",
		PGSQL_ERROR_CODES::ERRCODE_TOO_MANY_CONNECTIONS, false, "role connection limit" },
	{ "53300", "too many connections for database \"shun_test\"",
		PGSQL_ERROR_CODES::ERRCODE_TOO_MANY_CONNECTIONS, false, "database connection limit" },
	{ "53300", "sorry, too many clients already",
		PGSQL_ERROR_CODES::ERRCODE_TOO_MANY_CONNECTIONS, true, "server connection limit" },
	{ "57P03", "the database system is starting up",
		PGSQL_ERROR_CODES::ERRCODE_CANNOT_CONNECT_NOW, true, "server starting up" },
	// A P0001 the backend sends (a RAISE EXCEPTION in a PostgreSQL 17 login event trigger) keeps its
	// label in libpq mode too: only a libpq failure without a SQLSTATE is labelled 08006.
	{ "P0001", "logins are closed",
		PGSQL_ERROR_CODES::ERRCODE_RAISE_EXCEPTION, true, "RAISE EXCEPTION in a login event trigger" },
};
static const int CHECKS_PER_CASE = 4;

static void check_case(PgSQL_Session* sess, int hid, bool native, const Case& tc) {
	const char* mode = native ? "native" : "libpq";
	pgsql_thread___use_native_backend_protocol = native;
	FakeBackend backend(tc.sqlstate, tc.message);
	PgSQL_SrvC* srv = add_server(hid, backend.port);
	if (srv == nullptr) BAIL_OUT("could not add the test server to hostgroup %d", hid);

	int refused = 0;
	PGSQL_ERROR_CODES last = PGSQL_ERROR_CODES::ERRCODE_SUCCESSFUL_COMPLETION;
	for (int i = 0; i < CONNECTS; i++) {
		PGSQL_ERROR_CODES code;
		if (run_connect(srv, sess, &code) == -1 && code == tc.code) refused++;
		last = code;
	}
	ok(refused == CONNECTS, "%s %s (%s): every connect fails with that SQLSTATE (%d of %d, last %s)",
		mode, tc.sqlstate, tc.what, refused, CONNECTS, PgSQL_Error_Helper::get_error_code(last));
	ok(srv->connect_ERR == (unsigned int)CONNECTS,
		"%s %s (%s): every failure is counted in connect_ERR (%u)", mode, tc.sqlstate, tc.what, srv->connect_ERR);
	const std::string metric_id = std::to_string(hid) + ":127.0.0.1:" + std::to_string(backend.port) + ":" + tc.sqlstate;
	const auto& errors = PgHGM->status.p_pgsql_errors_map;
	const auto it = errors.find(metric_id);
	const double counted = (it == errors.end()) ? 0 : it->second->Value();
	ok(counted == CONNECTS, "%s %s (%s): the pgsql error counter has them under code=%s (%.0f)",
		mode, tc.sqlstate, tc.what, tc.sqlstate, counted);
	const bool shunned = srv->status == MYSQL_SERVER_STATUS_SHUNNED;
	ok(shunned == tc.shuns, "%s %s (%s): the server is %s after %d failures (status=%d)",
		mode, tc.sqlstate, tc.what, tc.shuns ? "shunned" : "left ONLINE", CONNECTS, (int)srv->status);
}

// A pgsql_users entry with no password, against a backend that asks for one. The native protocol
// sends it and PostgreSQL refuses it (28P01). libpq refuses to send it ("fe_sendauth: no password
// supplied") with no SQLSTATE, which set_error_from_PQerrorMessage() filled with P0001: that
// counted toward shunning, and the client got P0001.
static void check_empty_password(PgSQL_Session* sess, int hid, bool native) {
	const char* mode = native ? "native" : "libpq";
	pgsql_thread___use_native_backend_protocol = native;
	FakeBackend backend("28P01", "password authentication failed for user \"shun_test\"", true);
	PgSQL_SrvC* srv = add_server(hid, backend.port);
	if (srv == nullptr) BAIL_OUT("could not add the test server to hostgroup %d", hid);

	int refused = 0;
	PGSQL_ERROR_CODES last = PGSQL_ERROR_CODES::ERRCODE_SUCCESSFUL_COMPLETION;
	for (int i = 0; i < CONNECTS; i++) {
		PGSQL_ERROR_CODES code;
		if (run_connect(srv, sess, &code, "") == -1 && code == PGSQL_ERROR_CODES::ERRCODE_INVALID_PASSWORD) refused++;
		last = code;
	}
	ok(refused == CONNECTS, "%s empty password: every connect fails with 28P01 (%d of %d, last %s)",
		mode, refused, CONNECTS, PgSQL_Error_Helper::get_error_code(last));
	ok(srv->status == MYSQL_SERVER_STATUS_ONLINE, "%s empty password: the server is left ONLINE (status=%d)",
		mode, (int)srv->status);
}

// 3D000 is in ProxySQL's table twice, as ERRCODE_INVALID_CATALOG_NAME and ERRCODE_UNDEFINED_DATABASE.
// A lookup returns the first, which the connects above reach; the other one must not count either.
static void check_undefined_database(int hid) {
	PgSQL_SrvC* srv = add_server(hid, 1);
	if (srv == nullptr) BAIL_OUT("could not add the test server to hostgroup %d", hid);
	for (int i = 0; i < CONNECTS; i++) {
		srv->connect_error(PGSQL_ERROR_CODES::ERRCODE_UNDEFINED_DATABASE);
	}
	ok(srv->status == MYSQL_SERVER_STATUS_ONLINE,
		"ERRCODE_UNDEFINED_DATABASE (3D000): the server is left ONLINE after %d failures (status=%d)",
		CONNECTS, (int)srv->status);
}

// --- session connect failures -----------------------------------------------------------------

static double error_count(const std::string& metric_id) {
	const auto& errors = PgHGM->status.p_pgsql_errors_map;
	const auto it = errors.find(metric_id);
	return (it == errors.end()) ? 0 : it->second->Value();
}

// A connect that fails without a backend error. Both PgSQL_Connection::handler() and the session
// count it, and both must label it as the native protocol does:
//  - a backend that takes the TCP connection and never answers times out: 08001 (a timeout leaves
//    no error, and the session's count used to be XXXXX);
//  - a port that refuses the connection: 08006 (libpq reports its own failures without a SQLSTATE,
//    which set_error_from_PQerrorMessage() fills with P0001).
// Driven the way the thread drives it, through the session's handler().
static void check_session_connect_failure(PgSQL_Thread* thr, int hid, bool native, bool silent_backend) {
	const char* mode = native ? "native" : "libpq";
	const char* what = silent_backend ? "a silent backend times out" : "a refused port fails";
	const char* expected = silent_backend ? "08001" : "08006";
	pgsql_thread___use_native_backend_protocol = native;

	// Bound and listening: the kernel takes the connection and nobody answers. Bound only: refused.
	int silent = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in a {};
	a.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
	socklen_t len = sizeof(a);
	if (silent < 0 || bind(silent, reinterpret_cast<sockaddr*>(&a), len) != 0 || (silent_backend && listen(silent, 4) != 0))
		BAIL_OUT("could not bind on 127.0.0.1");
	getsockname(silent, reinterpret_cast<sockaddr*>(&a), &len);
	const unsigned short port = ntohs(a.sin_port);
	PgSQL_SrvC* srv = add_server(hid, port);
	int client_sp[2] = { -1, -1 };
	if (srv == nullptr || socketpair(AF_UNIX, SOCK_STREAM, 0, client_sp) != 0)
		BAIL_OUT("could not set up the session connect failure case");

	PgSQL_Session* sess = new PgSQL_Session();
	sess->thread = thr;
	sess->connections_handler = true; // keeps the session destructor away from PgHGM
	sess->session_fast_forward = SESSION_FORWARD_TYPE_PERMANENT;
	PgSQL_Data_Stream* client_ds = new PgSQL_Data_Stream();
	client_ds->init(MYDS_FRONTEND, sess, client_sp[0]);
	client_ds->myconn = new PgSQL_Connection(true);
	fill_tracked_variables(client_ds->myconn);
	sess->client_myds = client_ds;
	client_ds->myprot.init(&sess->client_myds, client_ds->myconn->userinfo, sess); // the session answers the client
	client_ds->DSS = STATE_SLEEP; // a fast_forward client waiting for its backend
	sess->mybe = sess->find_or_create_backend(hid);
	PgSQL_Data_Stream* server_ds = sess->mybe->server_myds;
	server_ds->reinit_queues();
	server_ds->connect_retries_on_failure = 0; // the first failure ends the connect
	sess->previous_status.push(FAST_FORWARD);
	sess->set_status(CONNECTING_SERVER);

	// As get_connection() leaves a new connection: in the server's used list, not started yet.
	Conn* c = new Conn(false);
	c->parent = srv;
	PgHGM->wrlock();
	srv->ConnectionsUsed->add(c);
	PgHGM->wrunlock();
	c->userinfo->username = strdup("shun_test");
	c->userinfo->password = strdup("shun_test");
	c->userinfo->dbname = strdup("shun_test");
	fill_tracked_variables(c);
	server_ds->attach_connection(c);

	const int saved_timeout = pgsql_thread___connect_timeout_server;
	pgsql_thread___connect_timeout_server = 200;
	bool gave_up = false;
	for (int i = 0; i < 300 && !gave_up; i++) {
		// As the thread loop does: poll the connection's socket for what it waits on, hand the
		// events to the session, then run it.
		short revents = 0;
		if (c->get_pg_socket_fd() >= 0) {
			short want = 0;
			if (c->async_exit_status & PG_EVENT_READ) want |= POLLIN;
			if (c->async_exit_status & PG_EVENT_WRITE) want |= POLLOUT;
			struct pollfd p { c->get_pg_socket_fd(), want ? want : (short)POLLIN, 0 };
			if (poll(&p, 1, 10) > 0) revents = p.revents;
		} else {
			usleep(10000);
		}
		server_ds->revents = revents;
		thr->curtime = monotonic_time();
		sess->to_process = 1;
		gave_up = sess->handler() == -1 || server_ds->myconn != c;
	}
	pgsql_thread___connect_timeout_server = saved_timeout;

	const std::string id = std::to_string(hid) + ":127.0.0.1:" + std::to_string(port) + ":";
	const double labelled = error_count(id + expected);
	const double unlabelled = error_count(id + "XXXXX");
	const double raise_exception = error_count(id + "P0001");
	ok(gave_up, "%s session: the connect to %s and the session gives up", mode, what);
	const bool right = labelled == 2 && unlabelled == 0 && raise_exception == 0;
	ok(right, "%s session: %s, counted under code=%s by the connection and the session (%s=%.0f, XXXXX=%.0f, P0001=%.0f)",
		mode, what, expected, expected, labelled, unlabelled, raise_exception);
	if (!right) {
		for (const auto& e : PgHGM->status.p_pgsql_errors_map) {
			if (e.first.compare(0, id.size(), id) == 0) diag("counted: %s = %.0f", e.first.c_str(), e.second->Value());
		}
	}
	close(client_sp[1]);
	close(silent);
}

// --- monitor shun recovery time --------------------------------------------------------------

// A server the monitor shuns stays out until its next ping can confirm it: when the ping interval
// is longer than pgsql-shun_recovery_time_sec, shun_and_killall() moves time_last_detected_error
// forward by the difference. It read MySQL's monitor variables, which a PgSQL monitor thread never
// sets, so the server came back before the next ping.
// The same server in two hostgroups: each one waits out the same 30 s, not 30 s more per hostgroup.
static void check_monitor_shun_recovery_time(int hid1, int hid2) {
	PgSQL_SrvC* srv1 = add_server(hid1, 2);
	PgSQL_SrvC* srv2 = add_server(hid2, 2);
	if (srv1 == nullptr || srv2 == nullptr) BAIL_OUT("could not add the test server to hostgroups %d and %d", hid1, hid2);
	const bool saved_enabled = pgsql_thread___monitor_enabled;
	const int saved_interval = pgsql_thread___monitor_ping_interval;
	pgsql_thread___monitor_enabled = true;
	pgsql_thread___monitor_ping_interval = 30000; // 30 s, against a 10 s pgsql-shun_recovery_time_sec
	const time_t before = time(NULL);
	const bool shunned = PgHGM->shun_and_killall(const_cast<char*>("127.0.0.1"), 2);
	const time_t after = time(NULL);
	pgsql_thread___monitor_enabled = saved_enabled;
	pgsql_thread___monitor_ping_interval = saved_interval;
	const time_t last1 = srv1->time_last_detected_error;
	const time_t last2 = srv2->time_last_detected_error;
	ok(shunned && srv1->status == MYSQL_SERVER_STATUS_SHUNNED && srv2->status == MYSQL_SERVER_STATUS_SHUNNED &&
		last1 >= before + 20 && last1 <= after + 20 && last2 == last1,
		"monitor: a server shunned by its pings waits out the 30 s ping interval, not the 10 s recovery time, "
		"in each of its hostgroups (time_last_detected_error = now%+ld s and now%+ld s)",
		(long)(last1 - after), (long)(last2 - after));
}

// A connect that fails with no error set (the backend's TLS could not be handed to a fast forward
// session) is labelled as a connection failure, 08006, not XXXXX.
static void check_connect_failure_without_error() {
	Conn* c = new Conn(false);
	c->async_state_machine = ASYNC_CONNECT_FAILED;
	const std::string label = c->get_connect_error_code_str();
	delete c;
	ok(label == "08006", "a connect that failed with no error is labelled 08006 (got '%s')", label.c_str());
}

// --- monitor pings ---------------------------------------------------------------------------

bool server_responds_to_ping(SQLite3DB& db, const char* addr, int port, int max_fails);

struct PingCase {
	const char* error; // as PQerrorMessage() reports it, newlines removed
	bool refused_login;
	const char* what;
};

#define PG_FAILED "connection to server at \"10.0.0.1\", port 5432 failed: "

static const PingCase PINGS[] = {
	{ PG_FAILED "FATAL:  password authentication failed for user \"monitor\"", true, "28P01 wrong password" },
	{ PG_FAILED "FATAL:  Ident authentication failed for user \"monitor\"", true, "28000 ident" },
	{ PG_FAILED "FATAL:  no pg_hba.conf entry for host \"10.0.0.2\", user \"monitor\", database \"postgres\", no encryption",
		true, "28000 no pg_hba.conf entry" },
	{ PG_FAILED "FATAL:  pg_hba.conf rejects connection for host \"10.0.0.2\", user \"monitor\", database \"postgres\", no encryption",
		true, "28000 pg_hba.conf reject" },
	{ PG_FAILED "FATAL:  connection requires a valid client certificate", true, "28000 client certificate" },
	{ PG_FAILED "FATAL:  role \"monitor\" does not exist", true, "28000 unknown role" },
	{ PG_FAILED "FATAL:  role \"monitor\" is not permitted to log in", true, "28000 NOLOGIN role" },
	{ PG_FAILED "FATAL:  database \"monitor\" does not exist", true, "3D000 unknown database" },
	{ PG_FAILED "FATAL:  permission denied for database \"postgres\" DETAIL:  User does not have CONNECT privilege.",
		true, "42501 no CONNECT privilege" },
	{ PG_FAILED "FATAL:  too many connections for role \"monitor\"", true, "53300 role connection limit" },
	{ PG_FAILED "FATAL:  too many connections for database \"postgres\"", true, "53300 database connection limit" },
	{ PG_FAILED "FATAL:  database \"postgres\" is not currently accepting connections", true, "55000 database not accepting" },
	{ PG_FAILED "FATAL:  cannot connect to invalid database \"postgres\"", true, "55000 invalid database" },
	{ PG_FAILED "Connection refused \tIs the server running on that host and accepting TCP/IP connections?",
		false, "connection refused" },
	{ PG_FAILED "FATAL:  sorry, too many clients already", false, "53300 server full" },
	{ PG_FAILED "FATAL:  remaining connection slots are reserved for roles with the SUPERUSER attribute",
		false, "53300 reserved slots" },
	{ PG_FAILED "FATAL:  the database system is not accepting connections DETAIL:  Hot standby mode is disabled.",
		false, "57P03 not accepting connections" },
	{ PG_FAILED "FATAL:  the database system is starting up", false, "57P03 starting up" },
	{ PG_FAILED "FATAL:  terminating connection due to administrator command", false, "57P01 terminated" },
	{ "timeout expired", false, "timeout" },
};

static void check_monitor_pings() {
	SQLite3DB db;
	db.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	if (!db.execute(MONITOR_SQLITE_TABLE_PGSQL_SERVER_PING_LOG)) BAIL_OUT("could not create pgsql_server_ping_log");

	const int max_fails = 3;
	int port = 20000;
	for (const PingCase& pc : PINGS) {
		port++;
		for (int i = 1; i <= max_fails; i++) {
			const std::string q = "INSERT INTO pgsql_server_ping_log VALUES ('10.0.0.1', " + std::to_string(port) +
				", " + std::to_string(i) + ", 0, '" + pc.error + "')";
			if (!db.execute(q.c_str())) BAIL_OUT("could not insert a ping row");
		}
		const bool responds = server_responds_to_ping(db, "10.0.0.1", port, max_fails);
		ok(responds == pc.refused_login, "monitor: %d failed pings (%s) %s", max_fails, pc.what,
			pc.refused_login ? "are not missed heartbeats" : "are missed heartbeats");
	}
}

int main() {
	if (test_init_minimal() != 0) BAIL_OUT("test_init_minimal failed");
	if (test_init_hostgroups() != 0) BAIL_OUT("test_init_hostgroups failed");
	// libpq must not find a password of its own for the empty-password case.
	unsetenv("PGPASSWORD");
	setenv("PGPASSFILE", "/dev/null", 1);

	// Shun on the 2nd counted failure within one second (the default is 5): a slow runner still
	// fits two connects in a second, and a failure that must not count is held to a stricter bar.
	pgsql_thread___shun_on_failures = 2;
	pgsql_thread___connect_retries_on_failure = 10;
	pgsql_thread___shun_recovery_time_sec = 10;
	pgsql_thread___connect_timeout_server = 10000;

	PgSQL_Thread* thr = new PgSQL_Thread();
	thr->curtime = monotonic_time();
	PgSQL_Session* sess = new PgSQL_Session();
	sess->thread = thr;
	sess->connections_handler = true; // keeps the session destructor away from PgHGM

	const int ncases = sizeof(CASES) / sizeof(CASES[0]);
	const int npings = sizeof(PINGS) / sizeof(PINGS[0]);
	plan(2 * ncases * CHECKS_PER_CASE + 2 * 2 + 1 + 2 * 2 * 2 + 1 + 1 + npings);

	int hid = 9600;
	for (bool native : { true, false }) {
		for (const Case& tc : CASES) {
			check_case(sess, hid++, native, tc);
		}
	}
	for (bool native : { true, false }) {
		check_empty_password(sess, hid++, native);
	}
	check_undefined_database(hid++);
	check_monitor_shun_recovery_time(hid, hid + 1);
	hid += 2;
	for (bool native : { true, false }) {
		check_session_connect_failure(thr, hid++, native, true);
		check_session_connect_failure(thr, hid++, native, false);
	}
	check_connect_failure_without_error();
	check_monitor_pings();

	return exit_status();
}
