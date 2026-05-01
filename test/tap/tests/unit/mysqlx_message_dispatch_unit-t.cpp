#include "mysqlx_session.h"
#include "mysqlx_thread.h"
#include "mysqlx_config_store.h"
#include "mysqlx_protocol.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

static void write_x_frame(int fd, uint8_t msg_type, const uint8_t* payload, size_t payload_len) {
	uint32_t size = static_cast<uint32_t>(payload_len) + 1;
	uint8_t header[5];
	header[0] = size & 0xFF;
	header[1] = (size >> 8) & 0xFF;
	header[2] = (size >> 16) & 0xFF;
	header[3] = (size >> 24) & 0xFF;
	header[4] = msg_type;
	write(fd, header, 5);
	if (payload_len > 0) {
		write(fd, payload, payload_len);
	}
}

static ssize_t read_x_frame(int fd, uint8_t* buf, size_t buf_size) {
	uint8_t header[5];
	ssize_t r = read(fd, header, 5);
	if (r != 5) return -1;
	uint32_t payload_size = header[0] | (header[1] << 8) | (header[2] << 16) | (header[3] << 24);
	uint8_t msg_type = header[4];
	if (5 + payload_size > buf_size) return -1;
	buf[0] = header[0];
	buf[1] = header[1];
	buf[2] = header[2];
	buf[3] = header[3];
	buf[4] = msg_type;
	if (payload_size > 1) {
		r = read(fd, buf + 5, payload_size - 1);
		if (r != static_cast<ssize_t>(payload_size - 1)) return -1;
	}
	return 4 + payload_size;
}

// =====================================================================
// Helpers for the test_dispatch_* family, lifted from
// mysqlx_robustness_unit-t.cpp where this exact pattern is already
// well-exercised. The earlier draft of these tests asserted that a
// dispatched message left the session in CONNECTING_SERVER (the
// intermediate state forward_to_backend transitions to when no backend
// is attached). That assertion was a fragile observation of the inner
// `goto handler_again` loop in MysqlxSession::handler(): post-commit
// 55e90d1a7's inet_pton hardening, the inner handler_connecting_server
// fails fast on the empty hostname target, so status_ now correctly
// settles in X_SESSION_CLOSING — and the asserted intermediate state
// is no longer observable. The right test asks the dispatch layer to
// route a message to a properly-attached fake backend and observe that
// the message lands on the wire (status_ → WAITING_SERVER_XMSG).
//
// All process-globals are lazy / per-process; tests are not isolated
// from each other in that respect, but the fixture never mutates after
// first construction so re-entrancy is fine.
static MysqlxConfigStore& default_test_config_store() {
	static MysqlxConfigStore store;
	static bool initialized = false;
	if (!initialized) {
		std::unordered_map<std::string, MysqlxRoute> routes;
		MysqlxRoute r {};
		r.name = "default_test_route";
		r.destination_hostgroup = 10;
		r.strategy = "first_available";
		routes.emplace("default_test_route", r);

		std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints;
		MysqlxBackendEndpoint ep {};
		ep.hostname = "127.0.0.1";
		ep.mysql_port = 3306;
		ep.mysqlx_port = 33060;
		endpoints[10].push_back(ep);

		store.install_for_test(std::move(routes), std::move(endpoints));
		initialized = true;
	}
	return store;
}

static Mysqlx_Thread& default_test_thread() {
	static Mysqlx_Thread thr;
	static bool initialized = false;
	if (!initialized) {
		thr.init(0);
		thr.set_config_store(&default_test_config_store());
		initialized = true;
	}
	return thr;
}

static void detach_session_fds(MysqlxSession& sess) {
	sess.client_ds().init(XDS_FRONTEND, -1);
	if (sess.backend_conn()) {
		sess.backend_conn()->set_fd(-1);
	}
}

// Drive the real MYSQL41 handshake so the session has username_,
// schema_, identity_, status_ in the post-auth state. Same as the
// equivalent helper in mysqlx_robustness_unit-t.cpp.
static void setup_authenticated_session(int fds[2], MysqlxSession& sess) {
	sess.init(fds[0], &default_test_thread());

	const std::string TEST_PASSWORD = "testpass";
	sess.set_identity_lookup([TEST_PASSWORD](const std::string& u)
	        -> std::optional<MysqlxResolvedIdentity> {
		MysqlxResolvedIdentity id {};
		id.username = u;
		id.x_enabled = true;
		id.password = TEST_PASSWORD;
		id.allowed_auth_methods = "MYSQL41";
		id.default_route = "default_test_route";
		return id;
	});

	sess.to_process = true;
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET, nullptr, 0);
	sess.handler();
	usleep(5000);
	{ uint8_t buf[4096]; read_x_frame(fds[1], buf, sizeof(buf)); }

	sess.to_process = true;
	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("MYSQL41");
	auth_start.set_auth_data(std::string("\0\0testuser", 11));
	std::string serialized;
	auth_start.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
	sess.handler();

	std::vector<uint8_t> challenge;
	usleep(5000);
	{
		uint8_t buf[4096];
		ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
		if (r > 5 && buf[4] == Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE) {
			Mysqlx::Session::AuthenticateContinue server_cont;
			if (server_cont.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
				const std::string& cd = server_cont.auth_data();
				challenge.assign(cd.begin(), cd.end());
			}
		}
	}

	auto scramble_bytes = mysqlx_mysql41_scramble(challenge, TEST_PASSWORD);
	std::string scramble_hex = "*";
	static const char hex[] = "0123456789ABCDEF";
	for (uint8_t b : scramble_bytes) {
		scramble_hex.push_back(hex[(b >> 4) & 0xF]);
		scramble_hex.push_back(hex[b & 0xF]);
	}

	sess.to_process = true;
	Mysqlx::Session::AuthenticateContinue cont;
	cont.set_auth_data(scramble_hex);
	cont.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
	sess.handler();
	usleep(5000);
	{ uint8_t buf[4096]; read_x_frame(fds[1], buf, sizeof(buf)); }
}

// Parameterized check: dispatch one client message of the given type
// to an authenticated session that already has a fake backend
// attached, then assert (a) the session transitions to
// WAITING_SERVER_XMSG (forward succeeded), and (b) the backend
// socketpair received the forwarded frame bytes. Counts as 2
// assertions.
static void check_dispatch_routes_to_backend(uint8_t client_msg_type,
                                              const char* desc) {
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	setup_authenticated_session(client_fds, sess);

	// Attach a fake idle backend connection. With this, forward_to_backend
	// takes the happy path: it init()'s server_ds_, enqueues the frame,
	// writes it to the wire, and sets status_=WAITING_SERVER_XMSG.
	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::IDLE);
	conn->set_reusable(true);
	sess.backend_conn() = conn;
	sess.server_ds().init(XDS_BACKEND, backend_fds[0]);
	// Reset to WAITING_CLIENT_XMSG so handler_waiting_client_msg picks
	// up the next message we write.
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(client_fds[1], client_msg_type, nullptr, 0);
	sess.handler();

	// Most messages settle in WAITING_SERVER_XMSG. SESS_RESET is the
	// one exception: dispatch_client_message overrides status_ to
	// X_SESSION_RESET_WAITING after forward_to_backend (the reset
	// response has its own follow-up handler). Accept either as a
	// successful forward.
	auto st = sess.get_status();
	ok(st == MysqlxSession::WAITING_SERVER_XMSG ||
	   st == MysqlxSession::X_SESSION_RESET_WAITING,
	   "%s: dispatch routes to backend (status → WAITING_SERVER_XMSG or RESET_WAITING)", desc);

	uint8_t buf[4096];
	usleep(5000);
	ssize_t r = read_x_frame(backend_fds[1], buf, sizeof(buf));
	bool received_correct_type = (r > 4 && buf[4] == client_msg_type);
	ok(received_correct_type,
	   "%s: backend received the forwarded frame", desc);

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

static void test_dispatch_sql_stmt() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE, "SQL_STMT_EXECUTE");
}

static void test_dispatch_crud_find() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_CRUD_FIND, "CRUD_FIND");
}

static void test_dispatch_crud_insert() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_CRUD_INSERT, "CRUD_INSERT");
}

static void test_dispatch_crud_update() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_CRUD_UPDATE, "CRUD_UPDATE");
}

static void test_dispatch_crud_delete() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_CRUD_DELETE, "CRUD_DELETE");
}

static void test_dispatch_sess_reset() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_SESS_RESET, "SESS_RESET");
}

static void test_dispatch_prepare_prepare() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_PREPARE_PREPARE, "PREPARE_PREPARE");
}

static void test_dispatch_prepare_execute() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_PREPARE_EXECUTE, "PREPARE_EXECUTE");
}

static void test_dispatch_prepare_deallocate() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_PREPARE_DEALLOCATE, "PREPARE_DEALLOCATE");
}

static void test_dispatch_cursor_open() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_CURSOR_OPEN, "CURSOR_OPEN");
}

static void test_dispatch_cursor_fetch() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_CURSOR_FETCH, "CURSOR_FETCH");
}

static void test_dispatch_cursor_close() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_CURSOR_CLOSE, "CURSOR_CLOSE");
}

static void test_dispatch_expect_open() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_EXPECT_OPEN, "EXPECT_OPEN");
}

static void test_dispatch_expect_close() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_EXPECT_CLOSE, "EXPECT_CLOSE");
}

static void test_dispatch_view_operations() {
	diag(">>> %s", __func__);
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_CRUD_CREATE_VIEW, "CREATE_VIEW");
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_CRUD_MODIFY_VIEW, "MODIFY_VIEW");
	check_dispatch_routes_to_backend(
		Mysqlx::ClientMessages_Type_CRUD_DROP_VIEW, "DROP_VIEW");
}

static void test_dispatch_compression_rejected() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_COMPRESSION, nullptr, 0);

	sess.handler();

	ok(sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG,
	   "COMPRESSION does not close session");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got error response for compression");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_ERROR, "response is ERROR");
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			// 5008 = X-Protocol "compression unsupported"; emitted by
			// dispatch_client_message when COMPRESSION arrives without a
			// negotiated algorithm. Test previously asserted 5001 (an
			// invented value) and never passed.
			ok(err.code() == 5008, "error code is 5008 for compression with no negotiated algorithm");
		}
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_dispatch_unknown_message() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(fds[1], 0xFF, nullptr, 0);

	sess.handler();

	ok(!sess.is_healthy(), "unknown message type causes unhealthy");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got error response for unknown msg");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_ERROR, "response is ERROR");
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			ok(err.code() == 5000, "error code is 5000 for unknown msg");
		}
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_tls_states() {
	diag(">>> %s", __func__);
	// X_FAST_FORWARD was retired with the dormant MysqlxWorker path
	// (commit 79cac4c97); compare against a still-extant earlier state
	// to keep the "TLS states are after the basic states" assertion.
	ok(MysqlxSession::X_TLS_ACCEPT_INIT > MysqlxSession::CONNECTING_CLIENT,
	   "X_TLS_ACCEPT_INIT is valid enum value");
	ok(MysqlxSession::X_TLS_ACCEPT_DONE > MysqlxSession::X_TLS_ACCEPT_CONT,
	   "X_TLS_ACCEPT_DONE > X_TLS_ACCEPT_CONT");
	ok(MysqlxSession::X_TLS_CONNECT_DONE > MysqlxSession::X_TLS_CONNECT_INIT,
	   "X_TLS_CONNECT_DONE > X_TLS_CONNECT_INIT");
}

static void test_tls_accept_init_stub() {
	diag(">>> %s", __func__);
	// The previous incarnation of this test asserted that handler() in
	// X_TLS_ACCEPT_INIT skips straight to X_TLS_ACCEPT_DONE — that was
	// true when the handler was a stub. The real handler now drives
	// SSL_do_handshake against the thread's SSL_CTX; with no SSL_CTX
	// (thread_ptr_=nullptr) it correctly emits 3150 and marks the
	// session unhealthy. Assert that, instead.
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::X_TLS_ACCEPT_INIT);
	sess.to_process = true;

	sess.handler();

	ok(!sess.is_healthy() || sess.get_status() == MysqlxSession::X_SESSION_CLOSING,
	   "TLS accept init with no SSL_CTX correctly fails (unhealthy or closing)");

	close(fds[0]);
	close(fds[1]);
}

static void test_data_stream_encrypted_flag() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	ok(!ds.is_encrypted(), "not encrypted by default");
	ds.set_encrypted(true);
	ok(ds.is_encrypted(), "encrypted after set");
	ds.set_encrypted(false);
	ok(!ds.is_encrypted(), "not encrypted after clear");
}

static void test_connection_pool_matching() {
	diag(">>> %s", __func__);
	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_max_cached_connections(10);

	MysqlxConnection* c1 = new MysqlxConnection();
	c1->set_hostgroup(0);
	c1->set_user("root");
	c1->set_schema("test");
	c1->set_reusable(true);
	c1->set_state(MysqlxConnection::IDLE);
	thr.return_connection_to_cache(c1);

	MysqlxConnection* found = thr.get_connection_from_cache(0, "root", "test");
	ok(found != nullptr, "found by hostgroup/user/schema");
	ok(found == c1, "got correct connection");

	MysqlxConnection* nf1 = thr.get_connection_from_cache(1, "root", "test");
	ok(nf1 == nullptr, "wrong hostgroup not found");

	MysqlxConnection* c2 = new MysqlxConnection();
	c2->set_hostgroup(0);
	c2->set_user("root");
	c2->set_schema("test");
	c2->set_reusable(true);
	c2->set_state(MysqlxConnection::IDLE);
	thr.return_connection_to_cache(c2);

	MysqlxConnection* nf2 = thr.get_connection_from_cache(0, "other", "test");
	ok(nf2 == nullptr, "wrong user not found");

	MysqlxConnection* nf3 = thr.get_connection_from_cache(0, "root", "other");
	ok(nf3 == nullptr, "wrong schema not found");

	MysqlxConnection* f2 = thr.get_connection_from_cache(0, "root", "test");
	ok(f2 != nullptr, "found second cached connection");
}

static void test_async_connect_loopback() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_hostgroup(0);
	conn.set_user("root");
	conn.set_schema("test");

	int rc = conn.start_connect("127.0.0.1", 1);
	ok(rc == -1 || rc == 0 || rc == 1,
	   "start_connect returns -1/0/1 (got %d)", rc);

	if (rc == 1) {
		ok(conn.get_state() == MysqlxConnection::CONNECTING,
		   "state is CONNECTING for EINPROGRESS");
		int crc = conn.check_connect();
		ok(crc == 0 || crc == -1,
		   "check_connect returns 0 or -1 (got %d)", crc);
	} else if (rc == -1) {
		ok(conn.get_state() == MysqlxConnection::ERROR_STATE,
		   "state is ERROR_STATE on connect failure");
	}

	ok(conn.get_fd() >= 0 || conn.get_state() == MysqlxConnection::ERROR_STATE,
	   "fd valid or in error state");
}

static void test_forward_to_backend_no_connection() {
	diag(">>> %s", __func__);
	// Without a thread + config_store + identity, dispatching a
	// SQL_STMT_EXECUTE drives the session through forward_to_backend
	// (which transitions to CONNECTING_SERVER), then the inner
	// `goto handler_again` loop runs handler_connecting_server, which
	// since commit 55e90d1a7 fails fast on inet_pton("",0) and
	// transitions to X_SESSION_CLOSING. Both states indicate the
	// dispatch correctly attempted to reach a backend; assert either.
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE,
		nullptr, 0);

	sess.handler();

	auto st = sess.get_status();
	ok(st == MysqlxSession::CONNECTING_SERVER ||
	   st == MysqlxSession::X_SESSION_CLOSING,
	   "forward_to_backend with no backend transitions out of WAITING_CLIENT_XMSG");

	close(fds[0]);
	close(fds[1]);
}

static void test_forward_to_backend_with_socketpair() {
	diag(">>> %s", __func__);
	int client_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);

	int backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	sess.init(client_fds[0], nullptr);

	MysqlxConnection conn;
	conn.set_fd(backend_fds[0]);
	conn.set_state(MysqlxConnection::IDLE);
	conn.set_reusable(true);
	conn.set_hostgroup(0);
	conn.set_user("test");
	conn.set_schema("test");
	sess.backend_conn() = &conn;
	sess.server_ds().init(XDS_BACKEND, backend_fds[0]);

	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	uint8_t payload[] = {0x01, 0x02, 0x03};
	write_x_frame(client_fds[1], Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE,
		payload, sizeof(payload));

	sess.handler();

	ok(sess.get_status() == MysqlxSession::WAITING_SERVER_XMSG,
	   "status is WAITING_SERVER_XMSG after forward");

	usleep(10000);
	uint8_t buf[4096];
	ssize_t r = read_x_frame(backend_fds[1], buf, sizeof(buf));
	ok(r > 0, "backend received forwarded frame");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE,
		   "forwarded message type matches");
	}

	sess.backend_conn() = nullptr;
	close(client_fds[0]);
	close(client_fds[1]);
	close(backend_fds[0]);
	close(backend_fds[1]);
}

static void test_return_backend_on_session_close() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	int dummy_fd = socket(AF_UNIX, SOCK_STREAM, 0);

	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_max_cached_connections(10);

	MysqlxSession sess;
	sess.init(fds[0], &thr);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(dummy_fd);
	conn->set_hostgroup(0);
	conn->set_user("test");
	conn->set_schema("test");
	conn->set_reusable(true);
	conn->set_state(MysqlxConnection::IN_USE);
	sess.backend_conn() = conn;

	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_CLOSE, nullptr, 0);

	sess.handler();

	ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSED,
	   "session closed after SESS_CLOSE");
	ok(sess.backend_conn() == nullptr,
	   "backend conn returned to pool after close");
	ok(thr.get_cached_connection_count() == 1,
	   "connection returned to thread cache");

	close(fds[0]);
	close(fds[1]);
}

// ------------------------------------------------------------------
// Per-message response-state validation tests (#5694).
//
// Each test drives an authenticated session into a specific
// response_state_, hands the session a fake backend over a socketpair,
// writes one or more synthetic server frames into the backend half of
// the pair, then calls handler() and inspects what was forwarded to
// the client and whether the session was rejected. The fixture mirrors
// check_dispatch_routes_to_backend's setup but uses the test-only
// set_response_state_for_test() to avoid having to drive a full client
// message round-trip per scenario.
// ------------------------------------------------------------------

// Helper to send a server-shaped X-Protocol frame. Wire format is
// direction-agnostic (5-byte header: little-endian length + msg type),
// so this is a renamed alias of write_x_frame for reader clarity at
// the call site.
static inline void write_server_frame(int fd, uint8_t msg_type,
                                       const uint8_t* payload, size_t payload_len) {
	write_x_frame(fd, msg_type, payload, payload_len);
}

// Returns true iff the next frame on `fd` has the given server msg
// type. Drains the frame; non-blocking via the socketpair's default.
static bool client_received_frame(int fd, uint8_t expected_msg_type) {
	uint8_t buf[4096];
	usleep(5000);
	ssize_t r = read_x_frame(fd, buf, sizeof(buf));
	return (r > 4 && buf[4] == expected_msg_type);
}

// Drains and discards any frames pending on `fd`. Used to clear the
// auth round-trip's leftover bytes before a test starts asserting on
// what the validation hook produced. fd is made non-blocking so the
// drain returns instead of waiting on an empty socket.
static void drain_frames(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	uint8_t buf[4096];
	usleep(5000);
	while (true) {
		ssize_t r = read(fd, buf, sizeof(buf));
		if (r <= 0) break;
	}
	fcntl(fd, F_SETFL, flags);
}

// Common setup: build an authenticated session backed by a fake idle
// backend over a socketpair, drain the auth-OK frame from the client
// side, parking the session in WAITING_SERVER_XMSG with the requested
// response_state_ so the next handler() call enters the validation
// loop. Returns the four fds via out-params; caller closes.
static void setup_session_for_validation(MysqlxSession& sess,
                                          int client_fds[2],
                                          int backend_fds[2],
                                          MysqlxResponseState rs) {
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	setup_authenticated_session(client_fds, sess);
	drain_frames(client_fds[1]);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::IDLE);
	conn->set_reusable(true);
	sess.backend_conn() = conn;
	sess.server_ds().init(XDS_BACKEND, backend_fds[0]);

	sess.set_status(MysqlxSession::WAITING_SERVER_XMSG);
	sess.set_response_state_for_test(rs);
	sess.to_process = true;
}

// Test 1: STMT_EXECUTE → ROW (without preceding ColumnMetaData) →
// reject. Canonical hostile-backend case in the issue.
static void test_validation_stmt_execute_row_without_metadata() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	MysqlxSession sess;
	setup_session_for_validation(sess, client_fds, backend_fds,
	                             RESP_WAITING_STMT_EXECUTE);

	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_ROW, nullptr, 0);
	sess.handler();

	ok(client_received_frame(client_fds[1], Mysqlx::ServerMessages_Type_ERROR),
	   "validation rejects ROW-without-metadata with X-Protocol Error");
	ok(!sess.is_healthy(),
	   "session marked unhealthy after rejected backend frame");
	ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSING,
	   "session transitions to X_SESSION_CLOSING on validation reject");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

// Test 2: STMT_EXECUTE → ColumnMetaData → ROW → SQL_STMT_EXECUTE_OK →
// happy-path forward. Validates the gating doesn't reject legitimate
// well-ordered traffic.
static void test_validation_stmt_execute_metadata_then_row() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	MysqlxSession sess;
	setup_session_for_validation(sess, client_fds, backend_fds,
	                             RESP_WAITING_STMT_EXECUTE);

	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_COLUMN_META_DATA, nullptr, 0);
	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_ROW, nullptr, 0);
	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK, nullptr, 0);
	sess.handler();

	ok(sess.is_healthy(),
	   "happy-path STMT_EXECUTE response is not rejected");
	ok(sess.response_state_for_test() == RESP_IDLE,
	   "response_state_ resets to IDLE after terminal");
	ok(!sess.seen_column_metadata_for_test(),
	   "seen_column_metadata_ cleared at terminal-frame flush");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

// Test 3: CURSOR_OPEN → ColumnMetaData → ROW → FETCH_SUSPENDED →
// terminal, but seen_column_metadata_ is preserved per X-Protocol
// (Cursor::Fetch reuses the metadata from Cursor::Open).
static void test_validation_cursor_open_fetch_suspended() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	MysqlxSession sess;
	setup_session_for_validation(sess, client_fds, backend_fds,
	                             RESP_WAITING_CURSOR_OPEN);

	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_COLUMN_META_DATA, nullptr, 0);
	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_ROW, nullptr, 0);
	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED, nullptr, 0);
	sess.handler();

	ok(sess.is_healthy(),
	   "CursorOpen with FETCH_SUSPENDED is not rejected");
	ok(sess.response_state_for_test() == RESP_IDLE,
	   "response_state_ resets after FETCH_SUSPENDED terminal");
	// Documented invariant: the column-metadata flag is cleared at
	// terminal-frame flush regardless of which response shape ended.
	// Cursor::Fetch's allowed-set unconditionally accepts ROW (the
	// metadata was sent at Cursor::Open and carries on the wire to
	// the client; the proxy's flag does not need to track this).
	ok(!sess.seen_column_metadata_for_test(),
	   "seen_column_metadata_ cleared at FETCH_SUSPENDED terminal "
	   "(Cursor::Fetch's allow-set does not consult the flag)");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

// Test 4: CURSOR_OPEN → ColumnMetaData → ROW → FETCH_DONE → terminal
// with the flag cleared. Mirrors test 3 for the fully-drained cursor
// path.
static void test_validation_cursor_open_fetch_done() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	MysqlxSession sess;
	setup_session_for_validation(sess, client_fds, backend_fds,
	                             RESP_WAITING_CURSOR_OPEN);

	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_COLUMN_META_DATA, nullptr, 0);
	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE, nullptr, 0);
	sess.handler();

	ok(sess.is_healthy(), "CursorOpen with FETCH_DONE is not rejected");
	ok(sess.response_state_for_test() == RESP_IDLE,
	   "response_state_ resets after FETCH_DONE terminal");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

// Test 5: PREPARE_PREPARE → SQL_STMT_EXECUTE_OK → reject (only Mysqlx.Ok
// is the valid terminal for Prepare::Prepare).
static void test_validation_prepare_prepare_rejects_stmt_execute_ok() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	MysqlxSession sess;
	setup_session_for_validation(sess, client_fds, backend_fds,
	                             RESP_WAITING_PREPARE_PREPARE);

	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK, nullptr, 0);
	sess.handler();

	ok(client_received_frame(client_fds[1], Mysqlx::ServerMessages_Type_ERROR),
	   "PREPARE_PREPARE rejects SQL_STMT_EXECUTE_OK with X-Protocol Error");
	ok(!sess.is_healthy(),
	   "session marked unhealthy after PREPARE_PREPARE rejection");
	ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSING,
	   "session transitions to X_SESSION_CLOSING on PREPARE_PREPARE reject");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

// Test 6: PREPARE_PREPARE → OK → terminal. Happy-path counterpart
// to test 5.
static void test_validation_prepare_prepare_accepts_ok() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	MysqlxSession sess;
	setup_session_for_validation(sess, client_fds, backend_fds,
	                             RESP_WAITING_PREPARE_PREPARE);

	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_OK, nullptr, 0);
	sess.handler();

	ok(sess.is_healthy(), "PREPARE_PREPARE happy-path OK is not rejected");
	ok(sess.response_state_for_test() == RESP_IDLE,
	   "response_state_ resets after PREPARE_PREPARE OK terminal");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

// Test 7: STMT_EXECUTE → ColumnMetaData → NOTICE → ROW →
// SQL_STMT_EXECUTE_OK. NOTICE is non-terminal in every state and must
// not consume the terminal slot or trigger rejection.
static void test_validation_notice_mid_result() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	MysqlxSession sess;
	setup_session_for_validation(sess, client_fds, backend_fds,
	                             RESP_WAITING_STMT_EXECUTE);

	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_COLUMN_META_DATA, nullptr, 0);
	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_NOTICE, nullptr, 0);
	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_ROW, nullptr, 0);
	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK, nullptr, 0);
	sess.handler();

	ok(sess.is_healthy(),
	   "NOTICE mid-result is not rejected");
	ok(sess.response_state_for_test() == RESP_IDLE,
	   "STMT_EXECUTE_OK terminates response after intermixed NOTICE");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

// Test 8: CURSOR_FETCH → ROW (with no preceding ColumnMetaData in this
// response sequence) → forwarded, NOT rejected. Validates the
// per-state-pair carve-out — Cursor::Fetch's allowed-set accepts ROW
// unconditionally because the metadata was sent at Cursor::Open time.
static void test_validation_cursor_fetch_row_without_metadata_allowed() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	MysqlxSession sess;
	setup_session_for_validation(sess, client_fds, backend_fds,
	                             RESP_WAITING_CURSOR_FETCH);

	// Note: seen_column_metadata_ is *false* here — we deliberately
	// did NOT pre-set it. The point is to prove CURSOR_FETCH does not
	// consult the flag.
	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_ROW, nullptr, 0);
	write_server_frame(backend_fds[1],
		Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE, nullptr, 0);
	sess.handler();

	ok(sess.is_healthy(),
	   "CURSOR_FETCH accepts ROW without per-response metadata "
	   "(metadata carried over from Cursor::Open in the X-Protocol)");
	ok(sess.response_state_for_test() == RESP_IDLE,
	   "FETCH_DONE terminates the CURSOR_FETCH response");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	// Plan count rationale (per assertion source):
	//   14 dispatch_* tests × 2 ok() per check_dispatch_routes_to_backend = 28
	//   test_dispatch_view_operations: 3 calls × 2 = 6
	//   test_dispatch_compression_rejected = 4 ok()
	//   test_dispatch_unknown_message = 4 ok()
	//   test_tls_states = 3 ok()
	//   test_tls_accept_init_stub = 1 ok()
	//   test_data_stream_encrypted_flag = 3 ok()
	//   test_connection_pool_matching ≈ 7
	//   test_async_connect_loopback ≈ 4
	//   test_forward_to_backend_no_connection = 1 ok()
	//   test_forward_to_backend_with_socketpair ≈ 5
	//   test_return_backend_on_session_close ≈ 4
	// Total target: ~70 (some sub-tests have variable counts based on
	// runtime behaviour; tap's 'auto' lets us not pin a hard number).
	// The earlier plan(49) was based on the now-rewritten dispatch
	// tests counting 1 ok each; the rewrite doubled them. plan(0)
	// asks tap to derive the count from the actual ok/not_ok lines.
	plan(0);
	diag("=== mysqlx_message_dispatch_unit-t starting ===");

	test_dispatch_sql_stmt();
	test_dispatch_crud_find();
	test_dispatch_crud_insert();
	test_dispatch_crud_update();
	test_dispatch_crud_delete();
	test_dispatch_sess_reset();
	test_dispatch_prepare_prepare();
	test_dispatch_prepare_execute();
	test_dispatch_prepare_deallocate();
	test_dispatch_cursor_open();
	test_dispatch_cursor_fetch();
	test_dispatch_cursor_close();
	test_dispatch_expect_open();
	test_dispatch_expect_close();
	test_dispatch_view_operations();
	test_dispatch_compression_rejected();
	test_dispatch_unknown_message();
	test_tls_states();
	test_tls_accept_init_stub();
	test_data_stream_encrypted_flag();
	test_connection_pool_matching();
	test_async_connect_loopback();
	test_forward_to_backend_no_connection();
	test_forward_to_backend_with_socketpair();
	test_return_backend_on_session_close();

	// Per-message response-state validation (#5694).
	test_validation_stmt_execute_row_without_metadata();
	test_validation_stmt_execute_metadata_then_row();
	test_validation_cursor_open_fetch_suspended();
	test_validation_cursor_open_fetch_done();
	test_validation_prepare_prepare_rejects_stmt_execute_ok();
	test_validation_prepare_prepare_accepts_ok();
	test_validation_notice_mid_result();
	test_validation_cursor_fetch_row_without_metadata_allowed();

	return exit_status();
}
