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
 * A fake backend on 127.0.0.1 answers every StartupMessage with an ErrorResponse carrying the
 * SQLSTATE under test. Real connects run through PgSQL_Connection::async_connect(), as the
 * session drives them, with the native and with the libpq backend protocol. Checked:
 *  - the refusal reaches the connection with its SQLSTATE;
 *  - a refused login (28000, 28P01, 3D000, 42501) leaves the server ONLINE;
 *  - a failure of the server itself (57P03 starting up) still shuns it;
 *  - every failure is still counted in the server's connect_ERR.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_HostGroups_Manager.h"
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
struct FakeBackend {
	int lfd = -1;
	unsigned short port = 0;
	std::string reply;
	std::atomic<bool> stop { false };
	std::thread th;

	FakeBackend(const char* sqlstate, const char* message) : reply(error_response(sqlstate, message)) {
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
static int run_connect(PgSQL_SrvC* srv, PgSQL_Session* sess, PGSQL_ERROR_CODES* code) {
	Conn* c = new Conn(false);
	c->parent = srv;
	c->userinfo->username = strdup("shun_test");
	c->userinfo->password = strdup("shun_test");
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
	{ "57P03", "the database system is starting up",
		PGSQL_ERROR_CODES::ERRCODE_CANNOT_CONNECT_NOW, true, "server starting up" },
};
static const int CHECKS_PER_CASE = 3;

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
	const bool shunned = srv->status == MYSQL_SERVER_STATUS_SHUNNED;
	ok(shunned == tc.shuns, "%s %s (%s): the server is %s after %d failures (status=%d)",
		mode, tc.sqlstate, tc.what, tc.shuns ? "shunned" : "left ONLINE", CONNECTS, (int)srv->status);
}

int main() {
	if (test_init_minimal() != 0) BAIL_OUT("test_init_minimal failed");
	if (test_init_hostgroups() != 0) BAIL_OUT("test_init_hostgroups failed");

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
	plan(2 * ncases * CHECKS_PER_CASE);

	int hid = 9600;
	for (bool native : { true, false }) {
		for (const Case& tc : CASES) {
			check_case(sess, hid++, native, tc);
		}
	}

	return exit_status();
}
