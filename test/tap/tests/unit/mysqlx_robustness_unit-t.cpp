#include "mysqlx_session.h"
#include "mysqlx_protocol.h"
#include "mysqlx_thread.h"
#include "mysqlx_plugin.h"
#include "sqlite3db.h"
#include "mysqlx_config_store.h"
#include "mysqlx_stats.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"
#include "mysqlx_resultset.pb.h"
#include "mysqlx_sql.pb.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <memory>
#include <mutex>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <atomic>

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

static ssize_t read_x_frame(int fd, uint8_t* buf, size_t buf_size, int timeout_ms = 200) {
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	int pret = poll(&pfd, 1, timeout_ms);
	if (pret <= 0) return -1;

	uint8_t header[5];
	ssize_t r;
	do {
		r = read(fd, header, 5);
	} while (r < 0 && errno == EINTR);
	if (r != 5) return -1;
	uint32_t payload_size = header[0] | (header[1] << 8) | (header[2] << 16) | (header[3] << 24);
	uint8_t msg_type = header[4];
	if (5 + payload_size > buf_size) return -1;
	buf[0] = header[0]; buf[1] = header[1]; buf[2] = header[2]; buf[3] = header[3]; buf[4] = msg_type;
	if (payload_size > 1) {
		pret = poll(&pfd, 1, timeout_ms);
		if (pret <= 0) return -1;
		do {
			r = read(fd, buf + 5, payload_size - 1);
		} while (r < 0 && errno == EINTR);
		if (r != static_cast<ssize_t>(payload_size - 1)) return -1;
	}
	return 4 + payload_size;
}

// Shared "default" config store and thread used by setup_authenticated_session.
// After the Task 4 wiring, a session that wants to reach WAITING_CLIENT_XMSG
// via the real auth handler needs: (a) an identity_lookup that returns an
// identity with a non-empty default_route, and (b) a config store reachable
// via the session's thread_ptr_ that knows about that route and has at least
// one endpoint in its hostgroup. Without these two ingredients,
// resolve_backend_target() will fail (4000/4001/4002) and the session will
// transition to X_SESSION_CLOSING instead of WAITING_CLIENT_XMSG.
//
// The helpers below lazily construct a process-global thread+store pair,
// configured once for the "default_test_route" happy-path fixture. Tests
// that want a different routing outcome should not call
// setup_authenticated_session; they should drive the session state
// machine directly (see test_routing_unknown_user for the pattern).
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

static void setup_authenticated_session(int fds[2], MysqlxSession& sess) {
	// Drive the real MYSQL41 handshake so the session's own fields
	// (username_, schema_, identity_, status_) land where the auth path
	// would leave them. The hardened auth flow refuses to authenticate
	// without an identity_lookup_ installed, so wire one that returns a
	// matching identity and compute a proper scramble against the
	// identity's password.
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

static void detach_session_fds(MysqlxSession& sess) {
	sess.client_ds().init(XDS_FRONTEND, -1);
	if (sess.backend_conn()) {
		sess.backend_conn()->set_fd(-1);
	}
}

static void test_server_response_terminal_frame() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	setup_authenticated_session(client_fds, sess);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::IDLE);
	conn->set_reusable(true);
	sess.backend_conn() = conn;
	sess.server_ds().init(XDS_BACKEND, backend_fds[0]);
	sess.set_status(MysqlxSession::WAITING_SERVER_XMSG);
	// SQL_STMT_EXECUTE_OK is only a terminal frame under the
	// RESP_WAITING_STMT_EXECUTE / RESP_WAITING_PREPARE_EXECUTE
	// response_state — see is_terminal_frame in mysqlx_session.cpp.
	// The default RESP_IDLE rejects every frame, so the test must
	// position the session in the response state matching the
	// terminator it's about to send.
	sess.set_response_state_for_test(RESP_WAITING_STMT_EXECUTE);

	Mysqlx::Sql::StmtExecuteOk exec_ok;
	std::string ok_s;
	exec_ok.SerializeToString(&ok_s);
	write_x_frame(backend_fds[1], Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK,
		reinterpret_cast<const uint8_t*>(ok_s.data()), ok_s.size());

	sess.to_process = true;
	sess.handler();

	ok(sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG,
	   "terminal frame (SQL_STMT_EXECUTE_OK) returns session to WAITING_CLIENT_XMSG");
	ok(sess.backend_conn() == nullptr, "backend returned to pool after terminal frame");

	uint8_t buf[4096];
	usleep(5000);
	ssize_t r = read_x_frame(client_fds[1], buf, sizeof(buf));
	ok(r > 0, "client received forwarded frame");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK,
		   "forwarded frame is SQL_STMT_EXECUTE_OK");
	} else {
		ok(false, "forwarded frame is SQL_STMT_EXECUTE_OK");
	}

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

static void test_server_response_non_terminal_keeps_waiting() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	setup_authenticated_session(client_fds, sess);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::IDLE);
	conn->set_reusable(true);
	sess.backend_conn() = conn;
	sess.server_ds().init(XDS_BACKEND, backend_fds[0]);
	sess.set_status(MysqlxSession::WAITING_SERVER_XMSG);
	// ColumnMetaData is only allowed under one of the resultset-
	// producing response states (STMT_EXECUTE / CRUD / PREPARE_EXECUTE
	// / CURSOR_OPEN). Pin to RESP_WAITING_STMT_EXECUTE — the
	// is_frame_allowed contract is identical for ColumnMetaData
	// across all four.
	sess.set_response_state_for_test(RESP_WAITING_STMT_EXECUTE);

	Mysqlx::Resultset::ColumnMetaData col;
	col.set_type(Mysqlx::Resultset::ColumnMetaData_FieldType_SINT);
	std::string col_s;
	col.SerializeToString(&col_s);
	write_x_frame(backend_fds[1], Mysqlx::ServerMessages_Type_RESULTSET_COLUMN_META_DATA,
		reinterpret_cast<const uint8_t*>(col_s.data()), col_s.size());

	sess.to_process = true;
	sess.handler();

	ok(sess.get_status() == MysqlxSession::WAITING_SERVER_XMSG,
	   "non-terminal frame (ColumnMetaData) keeps session in WAITING_SERVER_XMSG");
	ok(sess.backend_conn() != nullptr, "backend NOT returned to pool after non-terminal frame");

	uint8_t buf[4096];
	usleep(5000);
	ssize_t r = read_x_frame(client_fds[1], buf, sizeof(buf));
	ok(r > 0, "client received forwarded non-terminal frame");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_RESULTSET_COLUMN_META_DATA,
		   "forwarded frame is ColumnMetaData");
	} else {
		ok(false, "forwarded frame is ColumnMetaData");
	}

	detach_session_fds(sess);
	close(backend_fds[0]); close(backend_fds[1]);
	close(client_fds[0]);
	char drain[4096];
	while (read(client_fds[1], drain, sizeof(drain)) > 0);
	close(client_fds[1]);
}

static void test_server_response_multi_frame_pipeline() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	setup_authenticated_session(client_fds, sess);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::IDLE);
	conn->set_reusable(true);
	sess.backend_conn() = conn;
	sess.server_ds().init(XDS_BACKEND, backend_fds[0]);
	sess.set_status(MysqlxSession::WAITING_SERVER_XMSG);
	// Pipeline: ColumnMetaData → Row → SQL_STMT_EXECUTE_OK. All
	// three are accepted under RESP_WAITING_STMT_EXECUTE; Row's
	// allow-list is gated on seen_column_metadata_ which the
	// handler flips when it forwards the metadata frame.
	sess.set_response_state_for_test(RESP_WAITING_STMT_EXECUTE);

	uint8_t dummy_payload[] = {0x01, 0x02, 0x03};
	write_x_frame(backend_fds[1], Mysqlx::ServerMessages_Type_RESULTSET_COLUMN_META_DATA,
		dummy_payload, sizeof(dummy_payload));
	write_x_frame(backend_fds[1], Mysqlx::ServerMessages_Type_RESULTSET_ROW,
		dummy_payload, sizeof(dummy_payload));

	Mysqlx::Sql::StmtExecuteOk exec_ok;
	std::string ok_s;
	exec_ok.SerializeToString(&ok_s);
	write_x_frame(backend_fds[1], Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK,
		reinterpret_cast<const uint8_t*>(ok_s.data()), ok_s.size());

	sess.to_process = true;
	sess.handler();

	ok(sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG,
	   "multi-frame pipeline: session returns to WAITING_CLIENT_XMSG");
	ok(sess.backend_conn() == nullptr, "backend returned to pool after multi-frame response");

	uint8_t buf[4096];
	usleep(5000);
	int frame_count = 0;
	for (int i = 0; i < 10; i++) {
		ssize_t r = read_x_frame(client_fds[1], buf, sizeof(buf));
		if (r <= 0) break;
		frame_count++;
	}
	ok(frame_count == 3, "client received all 3 frames (ColumnMetaData + Row + StmtExecuteOk)");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

static void test_backend_disconnect_during_query() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	setup_authenticated_session(client_fds, sess);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::IDLE);
	conn->set_reusable(true);
	sess.backend_conn() = conn;
	sess.server_ds().init(XDS_BACKEND, backend_fds[0]);
	sess.set_status(MysqlxSession::WAITING_SERVER_XMSG);

	close(backend_fds[1]);

	sess.to_process = true;
	sess.handler();

	ok(!sess.is_healthy(), "session unhealthy after backend disconnect");
	ok(sess.backend_conn() == nullptr, "backend returned to pool after disconnect");

	uint8_t buf[4096];
	usleep(5000);
	ssize_t r = read_x_frame(client_fds[1], buf, sizeof(buf));
	ok(r > 0, "client received error response");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_ERROR, "response is ERROR after backend disconnect");
	} else {
		ok(false, "response is ERROR after backend disconnect");
	}

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
}

static void test_backend_fd_negative_no_crash() {
	diag(">>> %s", __func__);
	int client_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);

	MysqlxSession sess;
	setup_authenticated_session(client_fds, sess);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(-1);
	conn->set_state(MysqlxConnection::IDLE);
	sess.backend_conn() = conn;
	sess.server_ds().init(XDS_BACKEND, -1);
	sess.set_status(MysqlxSession::WAITING_SERVER_XMSG);

	sess.to_process = true;
	sess.handler();

	ok(sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG,
	   "session returns to WAITING_CLIENT_XMSG when server fd < 0");
	ok(sess.backend_conn() == nullptr, "backend returned to pool when server fd < 0");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
}

static void test_mysql41_no_credential_lookup_rejects() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	// Attach to the shared test thread+store and pre-seed a resolvable
	// identity. The asserted invariant here is that without an
	// identity_lookup set, credential verification in
	// handler_auth_challenge_response is skipped; a valid default_route
	// is still required to reach WAITING_CLIENT_XMSG (Task 4 wiring),
	// so we inject one directly.
	sess.init(fds[0], &default_test_thread());
	MysqlxResolvedIdentity id {};
	id.username = "testuser";
	id.x_enabled = true;
	id.default_route = "default_test_route";
	sess.inject_identity_for_test(id);

	sess.to_process = true;
	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("MYSQL41");
	auth_start.set_auth_data(std::string("\0\0testuser", 11));
	std::string serialized;
	auth_start.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
	sess.handler();

	uint8_t buf[4096];
	usleep(5000);
	read_x_frame(fds[1], buf, sizeof(buf));

	Mysqlx::Session::AuthenticateContinue cont;
	cont.set_auth_data("*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	cont.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	sess.to_process = true;
	sess.handler();

	ok(!sess.is_healthy(), "without credential_lookup, MYSQL41 auth must be rejected (no open-proxy fallback)");
	ok(sess.get_status() != MysqlxSession::WAITING_CLIENT_XMSG,
	   "session not in WAITING_CLIENT_XMSG after auth rejection");

	detach_session_fds(sess);
	close(fds[0]); close(fds[1]);
}

static void test_auth_start_empty_payload() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START, nullptr, 0);

	sess.handler();

	ok(!sess.is_healthy(), "unhealthy after empty AuthenticateStart payload");

	uint8_t buf[4096];
	usleep(5000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got error for empty payload");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_ERROR, "response is ERROR");
	} else {
		ok(false, "response is ERROR");
	}

	detach_session_fds(sess);
	close(fds[0]); close(fds[1]);
}

static void test_auth_start_malformed_protobuf() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	uint8_t garbage[] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB};
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START, garbage, sizeof(garbage));

	sess.handler();

	ok(!sess.is_healthy(), "unhealthy after malformed AuthenticateStart protobuf");

	uint8_t buf[4096];
	usleep(5000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got error for malformed protobuf");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_ERROR, "response is ERROR for malformed protobuf");
	} else {
		ok(false, "response is ERROR for malformed protobuf");
	}

	detach_session_fds(sess);
	close(fds[0]); close(fds[1]);
}

static void test_auth_challenge_wrong_msg_type() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("MYSQL41");
	std::string serialized;
	auth_start.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
	sess.handler();

	usleep(5000);
	uint8_t buf[4096];
	read_x_frame(fds[1], buf, sizeof(buf));

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE, nullptr, 0);

	sess.to_process = true;
	sess.handler();

	ok(!sess.is_healthy(), "unhealthy after wrong message type during auth challenge");

	detach_session_fds(sess);
	close(fds[0]); close(fds[1]);
}

static void test_return_backend_no_thread() {
	diag(">>> %s", __func__);
	int fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	setup_authenticated_session(fds, sess);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::IDLE);
	conn->set_reusable(true);
	sess.backend_conn() = conn;
	sess.server_ds().init(XDS_BACKEND, backend_fds[0]);
	sess.set_status(MysqlxSession::WAITING_SERVER_XMSG);

	sess.backend_conn()->set_fd(-1);
	close(backend_fds[1]);
	close(backend_fds[0]);

	sess.to_process = true;
	sess.handler();

	ok(sess.backend_conn() == nullptr, "backend_conn_ nulled after disconnect with no thread");

	detach_session_fds(sess);
	close(fds[0]); close(fds[1]);
}

static void test_connection_limit_config() {
	diag(">>> %s", __func__);
	Mysqlx_Thread thread;
	thread.set_max_sessions(1);
	ok(thread.get_max_sessions() == 1, "max_sessions set to 1");
	thread.set_max_sessions(100);
	ok(thread.get_max_sessions() == 100, "max_sessions updated to 100");
}

static void test_client_disconnect_detected() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	close(fds[1]);

	int rc = sess.handler();
	ok(!sess.is_healthy(), "session unhealthy after client disconnect");
	ok(rc == -1, "handler returns -1 on client disconnect");

	detach_session_fds(sess);
	close(fds[0]);
}

static void test_check_connect_bad_fd() {
	diag(">>> %s", __func__);
	// Bug fix (PR #5641 review): check_connect() must report a hard error
	// when poll() sees POLLNVAL on a closed/invalid fd, instead of waiting
	// out the connect timeout. Create an fd, close it so it's invalid, then
	// hand it to the connection and call check_connect().
	int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	ok(s >= 0, "socket() created for bad-fd test");
	close(s);

	MysqlxConnection conn;
	conn.set_fd(s);
	conn.set_state(MysqlxConnection::CONNECTING);
	conn.set_connect_timeout(10000);

	int rc = conn.check_connect();
	ok(rc == -1, "check_connect() returns -1 on invalid fd");
	ok(conn.get_state() == MysqlxConnection::ERROR_STATE,
	   "check_connect() transitions to ERROR_STATE on invalid fd");

	conn.set_fd(-1);  // prevent dtor from double-closing
}

static void test_check_connect_success_path() {
	diag(">>> %s", __func__);
	// Positive path: an already-connected socketpair endpoint reports POLLOUT
	// ready immediately, SO_ERROR is 0, so check_connect() must transition to
	// AUTHENTICATING and return 0.
	int fds[2];
	int sp = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	ok(sp == 0, "socketpair() created for success-path test");

	// Make non-blocking to mimic start_connect() fd flags.
	int flags = fcntl(fds[0], F_GETFL, 0);
	fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_state(MysqlxConnection::CONNECTING);
	conn.set_connect_timeout(10000);

	int rc = conn.check_connect();
	ok(rc == 0, "check_connect() returns 0 when socket is writable and SO_ERROR==0");
	ok(conn.get_state() == MysqlxConnection::AUTHENTICATING,
	   "check_connect() transitions to AUTHENTICATING on successful connect");

	conn.set_fd(-1);  // detach before manual close
	close(fds[0]);
	close(fds[1]);
}

// Regression guard: after backend auth completes, the data-plane reads/writes
// must route through backend_conn_->backend_ds(), not a session-owned stream
// re-wrapped around the raw backend fd. The TLS handshake (when backend TLS
// is required) runs against backend_conn_->backend_ds() and the resulting
// SSL* lives on that stream; rewrapping the fd would discard it and cause
// cleartext I/O on a TLS-expecting socket.
//
// We can't cheaply drive a full TLS handshake inside a unit test, so we
// instead assert the structural invariant: MysqlxSession::server_ds() is an
// alias for MysqlxConnection::backend_ds() whenever a backend is attached,
// and the session's placeholder stream is never initialized post-auth.
static void test_server_ds_aliases_backend_conn_backend_ds() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	setup_authenticated_session(client_fds, sess);

	// With no backend attached yet, server_ds() returns the session's
	// placeholder: fd == -1 and status never set to something data-plane
	// readers would treat as live.
	ok(sess.backend_conn() == nullptr,
	   "pre-attach: no backend connection is associated with the session");
	ok(sess.server_ds().get_fd() == -1,
	   "pre-attach: server_ds() placeholder has fd == -1");

	// Attach a backend and initialize its backend_ds() (as the real auth
	// path does via MysqlxConnection::init_backend_ds()).
	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::IDLE);
	conn->set_reusable(true);
	conn->init_backend_ds(backend_fds[0]);
	sess.backend_conn() = conn;

	// The critical invariant: server_ds() now aliases backend_conn_->backend_ds().
	// If this ever regresses to wrapping the raw fd in a fresh stream, the
	// TLS state living on backend_conn_->backend_ds_ would be bypassed.
	ok(&sess.server_ds() == &sess.backend_conn()->backend_ds(),
	   "post-attach: server_ds() aliases backend_conn_->backend_ds() (TLS state preserved)");
	ok(sess.server_ds().get_fd() == backend_fds[0],
	   "post-attach: server_ds().get_fd() reflects the backend fd");
	ok(sess.server_ds().get_status() == XDS_CONNECTED,
	   "post-attach: raw init leaves backend stream connected but not poll-ready");

	// return_backend_to_pool (via session close) must not tear down the
	// TLS-aware stream on the cached connection. Driving this path via the
	// session handler while the backend connection is null would invoke
	// return_backend_to_pool(); here we simply verify that after clearing
	// the backend pointer the placeholder is once again what server_ds()
	// returns and its fd is still -1.
	delete conn;
	sess.backend_conn() = nullptr;
	ok(sess.server_ds().get_fd() == -1,
	   "post-detach: server_ds() placeholder has fd == -1 (never re-initialized)");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

static void test_forward_empty_frame() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	setup_authenticated_session(client_fds, sess);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::IDLE);
	conn->set_reusable(true);
	sess.backend_conn() = conn;
	sess.server_ds().init(XDS_BACKEND, backend_fds[0]);

	sess.to_process = true;
	Mysqlx::Sql::StmtExecute stmt;
	stmt.set_stmt("SELECT 1");
	std::string stmt_s;
	stmt.SerializeToString(&stmt_s);
	write_x_frame(client_fds[1], Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE,
		reinterpret_cast<const uint8_t*>(stmt_s.data()), stmt_s.size());
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.handler();
	ok(sess.server_ds().get_status() == XDS_READY,
	   "forward_to_backend marks attached backend stream poll-ready");

	uint8_t buf[4096];
	usleep(5000);
	ssize_t r = read_x_frame(backend_fds[1], buf, sizeof(buf));
	ok(r > 0, "frame forwarded to backend");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE,
		   "forwarded message type is SQL_STMT_EXECUTE");
	} else {
		ok(false, "forwarded message type is SQL_STMT_EXECUTE");
	}

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

// Mirrors the atomic replace sequence used by sync_disk_to_memory() /
// copy_to_runtime() in plugins/mysqlx/src/mysqlx_plugin.cpp. Kept in the
// test to exercise the invariant that an empty source table overwrites a
// populated destination — the skip (if count==0) that used to guard this
// was a correctness bug that left stale rows in main.* across restarts.
//
// The signature/semantics match the production replace_table_atomically():
// every execute() return is checked, a failure at any step triggers ROLLBACK
// and the function returns false. This preserves the destination's
// pre-transaction state when the INSERT fails — the atomicity guarantee the
// transaction wrap is supposed to deliver.
static bool replace_table_contents(SQLite3DB& db,
                                   const char* dest_table,
                                   const char* source_table) {
	if (!db.execute("BEGIN")) {
		return false;
	}
	std::string q = "DELETE FROM ";
	q += dest_table;
	if (!db.execute(q.c_str())) {
		db.execute("ROLLBACK");
		return false;
	}

	q = "INSERT INTO ";
	q += dest_table;
	q += " SELECT * FROM ";
	q += source_table;
	if (!db.execute(q.c_str())) {
		db.execute("ROLLBACK");
		return false;
	}
	if (!db.execute("COMMIT")) {
		db.execute("ROLLBACK");
		return false;
	}
	return true;
}

static void test_empty_source_clears_stale_dest() {
	diag(">>> %s", __func__);
	SQLite3DB db;
	db.open(const_cast<char*>(":memory:"),
	        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

	db.execute("CREATE TABLE src (id INT PRIMARY KEY, name VARCHAR)");
	db.execute("CREATE TABLE dst (id INT PRIMARY KEY, name VARCHAR)");

	// Dest starts with stale rows; source is empty. This is exactly the
	// scenario the old `if (count == 0) continue;` mishandled — after
	// restart, sync_disk_to_memory would see disk count==0, skip, and
	// leave the stale rows in main.*.
	db.execute("INSERT INTO dst (id, name) VALUES (1, 'stale_a')");
	db.execute("INSERT INTO dst (id, name) VALUES (2, 'stale_b')");

	int src_cnt = db.return_one_int("SELECT COUNT(*) FROM src");
	int dst_cnt_before = db.return_one_int("SELECT COUNT(*) FROM dst");
	ok(src_cnt == 0 && dst_cnt_before == 2,
	   "precondition: empty source, 2 stale rows in dest");

	replace_table_contents(db, "dst", "src");

	int dst_cnt_after = db.return_one_int("SELECT COUNT(*) FROM dst");
	ok(dst_cnt_after == 0,
	   "empty source overwrites stale dest (dest is empty after replace)");
}

// Verifies that when INSERT fails mid-transaction, the DELETE is rolled back
// and the destination retains its pre-transaction contents. Without the
// execute()-return checks added by this follow-up, the unconditional COMMIT
// would persist the DELETE and silently wipe the destination.
static void test_insert_failure_rolls_back() {
	diag(">>> %s", __func__);
	SQLite3DB db;
	db.open(const_cast<char*>(":memory:"),
	        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

	// src has odd ids; dst has a CHECK that requires even ids. The INSERT
	// will fail at the first odd value, leaving the transaction needing
	// ROLLBACK to preserve the stale rows we seeded into dst.
	db.execute("CREATE TABLE src (id INT PRIMARY KEY)");
	db.execute("CREATE TABLE dst (id INT PRIMARY KEY CHECK (id % 2 = 0))");

	db.execute("INSERT INTO src (id) VALUES (1)");
	db.execute("INSERT INTO src (id) VALUES (3)");

	db.execute("INSERT INTO dst (id) VALUES (10)");
	db.execute("INSERT INTO dst (id) VALUES (20)");

	int dst_cnt_before = db.return_one_int("SELECT COUNT(*) FROM dst");
	ok(dst_cnt_before == 2,
	   "precondition: dst has 2 pre-existing rows");

	bool ok_return = replace_table_contents(db, "dst", "src");
	ok(ok_return == false,
	   "replace_table_contents returns false when INSERT violates CHECK");

	int dst_cnt_after = db.return_one_int("SELECT COUNT(*) FROM dst");
	ok(dst_cnt_after == 2,
	   "dst still has 2 rows after failed INSERT (DELETE was rolled back)");

	int dst_sum = db.return_one_int("SELECT COALESCE(SUM(id), 0) FROM dst");
	ok(dst_sum == 30,
	   "dst retains original rows (sum=30), not the invalid odd ids from src");
}

static void test_listener_route_tracking() {
	diag(">>> %s", __func__);
	// Construct two threads; associate a named route listener with each and
	// verify that `remove_listener_for_route` tears down only the target
	// listener and is idempotent when called a second time for the same name.
	Mysqlx_Thread thr0;
	Mysqlx_Thread thr1;
	thr0.init(0);
	thr1.init(1);

	int rc_a = thr0.add_listener("127.0.0.1", 0, "A");
	int rc_b = thr1.add_listener("127.0.0.1", 0, "B");
	ok(rc_a == 0 && thr0.get_listener_count() == 1,
	   "thread 0 has 1 listener for route A");
	ok(rc_b == 0 && thr1.get_listener_count() == 1,
	   "thread 1 has 1 listener for route B");

	bool removed_a = thr0.remove_listener_for_route("A");
	ok(removed_a && thr0.get_listener_count() == 0,
	   "remove_listener_for_route('A') removed thread 0's only listener");

	bool removed_again = thr0.remove_listener_for_route("A");
	ok(!removed_again,
	   "second remove_listener_for_route('A') returns false (idempotent)");

	thr1.remove_listeners();
}

static void test_listener_reconciliation() {
	diag(">>> %s", __func__);
	// Populate a fresh MysqlxConfigStore with one active route and verify
	// that `mysqlx_reconcile_listeners_impl` binds exactly one listener
	// across the two-thread pool and records the ownership mapping.
	// (The reconciler now reads its desired route set from the store, not
	// from runtime_mysqlx_routes — which is an admin-side projection of the
	// store, only populated on demand.)
	MysqlxConfigStore store;
	{
		std::unordered_map<std::string, MysqlxRoute> routes;
		MysqlxRoute r {};
		r.name = "route_rec";
		r.bind = "127.0.0.1:0";
		r.destination_hostgroup = 0;
		r.active = true;
		routes.emplace("route_rec", r);
		store.install_for_test(std::move(routes), {});
	}

	std::vector<std::unique_ptr<Mysqlx_Thread>> threads;
	for (int i = 0; i < 2; i++) {
		auto t = std::make_unique<Mysqlx_Thread>();
		t->init(i);
		threads.push_back(std::move(t));
	}

	std::map<std::string, int> route_to_thread;
	std::mutex route_map_mutex;
	int next_rr_index = 0;

	mysqlx_reconcile_listeners_impl(
		store, threads, route_to_thread, route_map_mutex, next_rr_index
	);

	int total = threads[0]->get_listener_count() + threads[1]->get_listener_count();
	ok(total == 1 && route_to_thread.count("route_rec") == 1,
	   "reconcile bound exactly one listener for route_rec and recorded mapping");

	for (auto& t : threads) {
		t->remove_listeners();
	}
}

// Ask the kernel for a free TCP port by binding to :0, reading back the
// assignment, and closing. Leaves a brief TIME_WAIT window but the listeners
// we build use SO_REUSEADDR so reuse is safe.
static int pick_free_port() {
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) return -1;
	int opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		close(s);
		return -1;
	}
	socklen_t len = sizeof(addr);
	if (getsockname(s, (struct sockaddr*)&addr, &len) < 0) {
		close(s);
		return -1;
	}
	int port = ntohs(addr.sin_port);
	close(s);
	return port;
}

static void test_listener_reconciliation_bind_change() {
	diag(">>> %s", __func__);
	// Verify that mutating a route's `bind` in MysqlxConfigStore and re-running
	// the reconciler closes the old listener and opens a new one at the new
	// port — i.e. the reconciler does NOT silently keep the stale listener
	// alive just because the route name is unchanged.
	int port1 = pick_free_port();
	int port2 = pick_free_port();
	ok(port1 > 0 && port2 > 0 && port1 != port2,
	   "picked two distinct free ports for bind-change reconcile test");

	auto install_route_with_bind = [](MysqlxConfigStore& store, int port) {
		std::unordered_map<std::string, MysqlxRoute> routes;
		MysqlxRoute r {};
		r.name = "reads";
		r.bind = std::string("127.0.0.1:") + std::to_string(port);
		r.destination_hostgroup = 0;
		r.active = true;
		routes.emplace("reads", r);
		store.install_for_test(std::move(routes), {});
	};

	MysqlxConfigStore store_v1;
	install_route_with_bind(store_v1, port1);

	std::vector<std::unique_ptr<Mysqlx_Thread>> threads;
	for (int i = 0; i < 2; i++) {
		auto t = std::make_unique<Mysqlx_Thread>();
		t->init(i);
		threads.push_back(std::move(t));
	}

	std::map<std::string, int> route_to_thread;
	std::mutex route_map_mutex;
	int next_rr_index = 0;

	mysqlx_reconcile_listeners_impl(
		store_v1, threads, route_to_thread, route_map_mutex, next_rr_index
	);

	int total1 = threads[0]->get_listener_count() + threads[1]->get_listener_count();
	ok(total1 == 1 && route_to_thread.count("reads") == 1,
	   "initial reconcile: one listener for 'reads' at port1");

	// Re-install with the new bind and re-reconcile.
	MysqlxConfigStore store_v2;
	install_route_with_bind(store_v2, port2);

	mysqlx_reconcile_listeners_impl(
		store_v2, threads, route_to_thread, route_map_mutex, next_rr_index
	);

	int total2 = threads[0]->get_listener_count() + threads[1]->get_listener_count();
	ok(total2 == 1,
	   "bind change reconcile: still exactly one listener (old closed, new opened)");

	// Confirm the current listener is bound to port2, not port1.
	int owner_tidx = route_to_thread.count("reads") ? route_to_thread["reads"] : -1;
	std::string addr = (owner_tidx >= 0)
		? threads[owner_tidx]->get_listener_addr_for_route("reads")
		: std::string();
	char expected[64];
	snprintf(expected, sizeof(expected), "127.0.0.1:%d", port2);
	ok(addr == expected,
	   "bind change reconcile: listener now bound to the new port");

	for (auto& t : threads) {
		t->remove_listeners();
	}
}

static void test_route_exists_predicate() {
	diag(">>> %s", __func__);
	// Empty store: any lookup returns false.
	{
		MysqlxConfigStore store;
		ok(store.route_exists("nope") == false,
		   "route_exists returns false for unknown route on empty store");
	}
	// Populated store: reports true for configured routes and false for
	// unconfigured names, letting callers distinguish "unknown route" from
	// "route exists but has no backend".
	{
		MysqlxConfigStore store;
		std::unordered_map<std::string, MysqlxRoute> routes;
		MysqlxRoute r {};
		r.name = "reads";
		r.destination_hostgroup = 20;
		routes.emplace("reads", r);
		std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints;
		store.install_for_test(std::move(routes), std::move(endpoints));
		ok(store.route_exists("reads") == true,
		   "route_exists returns true for configured route");
		ok(store.route_exists("writes") == false,
		   "route_exists returns false for route name not in store");
	}
}

// --- resolve_backend_target() tests ---

// Shared fixture: populate a config store with a single route "reads" that
// points at hostgroup 20, which in turn has one endpoint on 127.0.0.1:33060.
static void install_reads_route_with_endpoint(MysqlxConfigStore& store) {
	std::unordered_map<std::string, MysqlxRoute> routes;
	MysqlxRoute r {};
	r.name = "reads";
	r.destination_hostgroup = 20;
	r.strategy = "first_available";
	routes.emplace("reads", r);

	std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints;
	MysqlxBackendEndpoint ep {};
	ep.hostname = "127.0.0.1";
	ep.mysql_port = 3306;
	ep.mysqlx_port = 33060;
	endpoints[20].push_back(ep);

	store.install_for_test(std::move(routes), std::move(endpoints));
}

// Route "reads" -> hostgroup 20, but hostgroup 20 has no endpoints. Used
// to exercise the no-backend (4002) path distinctly from unknown-route.
static void install_reads_route_without_endpoint(MysqlxConfigStore& store) {
	std::unordered_map<std::string, MysqlxRoute> routes;
	MysqlxRoute r {};
	r.name = "reads";
	r.destination_hostgroup = 20;
	r.strategy = "first_available";
	routes.emplace("reads", r);

	std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints;
	store.install_for_test(std::move(routes), std::move(endpoints));
}

static void test_routing_happy_path() {
	diag(">>> %s", __func__);
	MysqlxConfigStore store;
	install_reads_route_with_endpoint(store);

	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_config_store(&store);

	MysqlxSession sess;
	sess.init(-1, &thr);

	MysqlxResolvedIdentity id {};
	id.username = "testuser";
	id.x_enabled = true;
	id.default_route = "reads";
	sess.inject_identity_for_test(id);

	int rc = sess.resolve_backend_target_for_test();
	ok(rc == 0, "resolve_backend_target returns 0 on happy path");
	ok(sess.target_hostgroup_for_test() == 20 &&
	   sess.target_address_for_test() == "127.0.0.1" &&
	   sess.target_port_for_test() == 33060,
	   "target fields populated: hostgroup=20, address=127.0.0.1, port=33060");
}

static void test_routing_no_default_route() {
	diag(">>> %s", __func__);
	MysqlxConfigStore store;  // intentionally empty

	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_config_store(&store);

	MysqlxSession sess;
	sess.init(-1, &thr);

	MysqlxResolvedIdentity id {};
	id.username = "u";
	id.x_enabled = true;
	id.default_route = "";  // no default route assigned
	sess.inject_identity_for_test(id);

	int rc = sess.resolve_backend_target_for_test();
	ok(rc == 4000, "resolve returns 4000 for empty default_route");
}

static void test_routing_unknown_route() {
	diag(">>> %s", __func__);
	MysqlxConfigStore store;  // no "nope" route installed

	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_config_store(&store);

	MysqlxSession sess;
	sess.init(-1, &thr);

	MysqlxResolvedIdentity id {};
	id.username = "u";
	id.x_enabled = true;
	id.default_route = "nope";
	sess.inject_identity_for_test(id);

	int rc = sess.resolve_backend_target_for_test();
	ok(rc == 4001, "resolve returns 4001 for unknown route");
}

static void test_routing_no_backend() {
	diag(">>> %s", __func__);
	MysqlxConfigStore store;
	install_reads_route_without_endpoint(store);

	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_config_store(&store);

	MysqlxSession sess;
	sess.init(-1, &thr);

	MysqlxResolvedIdentity id {};
	id.username = "u";
	id.x_enabled = true;
	id.default_route = "reads";
	sess.inject_identity_for_test(id);

	int rc = sess.resolve_backend_target_for_test();
	ok(rc == 4002, "resolve returns 4002 when route has no endpoints");
}

// For each failure mode, record_conn_err() must fire with a specific
// (route_name, hostgroup) tuple. Covering all three in one test keeps the
// assertion count aligned with the plan while still exercising each
// (route, hg) contract.
static void test_routing_stats_on_failure() {
	diag(">>> %s", __func__);
	// Empty default_route -> ("", 0)
	{
		MysqlxConfigStore store;
		Mysqlx_Thread thr;
		thr.init(0);
		thr.set_config_store(&store);
		MysqlxSession sess;
		sess.init(-1, &thr);
		MysqlxResolvedIdentity id {};
		id.x_enabled = true;
		id.default_route = "";
		sess.inject_identity_for_test(id);

		mysqlx_stats().reset_for_test();
		sess.resolve_backend_target_for_test();
		auto a = mysqlx_stats().get_last_conn_err_for_test();

		// Unknown route -> ("nope", 0)
		MysqlxConfigStore store2;
		Mysqlx_Thread thr2;
		thr2.init(0);
		thr2.set_config_store(&store2);
		MysqlxSession sess2;
		sess2.init(-1, &thr2);
		MysqlxResolvedIdentity id2 {};
		id2.x_enabled = true;
		id2.default_route = "nope";
		sess2.inject_identity_for_test(id2);

		mysqlx_stats().reset_for_test();
		sess2.resolve_backend_target_for_test();
		auto b = mysqlx_stats().get_last_conn_err_for_test();

		// No backend -> ("reads", 20)
		MysqlxConfigStore store3;
		install_reads_route_without_endpoint(store3);
		Mysqlx_Thread thr3;
		thr3.init(0);
		thr3.set_config_store(&store3);
		MysqlxSession sess3;
		sess3.init(-1, &thr3);
		MysqlxResolvedIdentity id3 {};
		id3.x_enabled = true;
		id3.default_route = "reads";
		sess3.inject_identity_for_test(id3);

		mysqlx_stats().reset_for_test();
		sess3.resolve_backend_target_for_test();
		auto c = mysqlx_stats().get_last_conn_err_for_test();

		bool all_match =
			a.has_value() && a->first == "" && a->second == 0 &&
			b.has_value() && b->first == "nope" && b->second == 0 &&
			c.has_value() && c->first == "reads" && c->second == 20;
		ok(all_match,
		   "record_conn_err tuples: ('',0) for no-default; ('nope',0) for "
		   "unknown; ('reads',20) for no-backend");
	}
}

// Drive the auth-start PLAIN path with an identity lookup that always
// returns nullopt. Expected: session emits Error 1045 and goes unhealthy
// without ever transitioning to WAITING_CLIENT_XMSG or sending Ok.
static void test_routing_unknown_user() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_identity_lookup([](const std::string&)
		-> std::optional<MysqlxResolvedIdentity> { return std::nullopt; });

	// PLAIN requires TLS at the protocol layer; the test covers only the
	// lookup-returns-nullopt branch in MYSQL41 challenge response.
	sess.to_process = true;
	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("MYSQL41");
	auth_start.set_auth_data(std::string("\0\0ghost", 8));
	std::string serialized;
	auth_start.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
	sess.handler();

	usleep(5000);
	uint8_t buf[4096];
	read_x_frame(fds[1], buf, sizeof(buf));

	Mysqlx::Session::AuthenticateContinue cont;
	cont.set_auth_data("*0000000000000000000000000000000000000000");
	cont.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	sess.to_process = true;
	sess.handler();

	ok(!sess.is_healthy() &&
	   sess.get_status() != MysqlxSession::WAITING_CLIENT_XMSG,
	   "unknown user: session unhealthy and did not reach WAITING_CLIENT_XMSG");

	detach_session_fds(sess);
	close(fds[0]); close(fds[1]);
}

// Integration test for the Task 4 wiring: PLAIN auth succeeds credential-
// wise (correct password) but the resolved identity carries an empty
// default_route. Expected outcome after resolve_backend_target() runs
// pre-Ok:
//   - session transitions to X_SESSION_CLOSING (not WAITING_CLIENT_XMSG).
//   - is_healthy() is false.
//   - the client sees an X-Protocol ERROR frame on the wire, NOT an Ok.
// Prior to this wiring, sessions reached WAITING_CLIENT_XMSG with
// target_address_ == "" and target_port_ == 0, then attempted to connect
// to ""; port 0 on the first client query. This test locks that door.
static void test_plain_auth_empty_default_route_closes_session() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	// Dedicated store/thread for this test so we don't pollute the shared
	// default fixture. The store is intentionally *not* populated with
	// "default_test_route" here; what matters is that the identity_lookup
	// returns an identity whose default_route is empty, which short-circuits
	// resolve_backend_target() with 4000 before any route lookup runs.
	MysqlxConfigStore store;
	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_config_store(&store);

	MysqlxSession sess;
	sess.init(fds[0], &thr);

	// PLAIN auth requires TLS at the protocol layer; mark the client data
	// stream as encrypted so handle_auth_plain() proceeds past the
	// "PLAIN authentication requires TLS" gate.
	sess.client_ds().set_encrypted(true);

	// Identity lookup returns an enabled user with a KNOWN password and
	// an EMPTY default_route. Credential verification must succeed so the
	// auth path reaches resolve_backend_target(), which then fails with 4000.
	sess.set_identity_lookup([](const std::string& username)
		-> std::optional<MysqlxResolvedIdentity> {
		MysqlxResolvedIdentity id {};
		id.username = username;
		id.x_enabled = true;
		id.password = "secret123";   // cleartext; derive_stored_hash SHA1s it.
		id.default_route = "";        // the point of this test
		return id;
	});

	// Send AuthenticateStart with PLAIN mechanism and correct password.
	// PLAIN auth_data is  \0 <authzid> \0 <user> \0 <password> ; we use
	// an empty authzid, "testuser", then "secret123".
	sess.to_process = true;
	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("PLAIN");
	std::string plain_payload;
	plain_payload.push_back('\0');
	plain_payload.append("testuser");
	plain_payload.push_back('\0');
	plain_payload.append("secret123");
	auth_start.set_auth_data(plain_payload);
	std::string serialized;
	auth_start.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
	sess.handler();

	ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSING,
	   "PLAIN auth + empty default_route: session in X_SESSION_CLOSING");
	ok(!sess.is_healthy(),
	   "PLAIN auth + empty default_route: session marked unhealthy");

	usleep(5000);
	uint8_t buf[4096];
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 5 && buf[4] == Mysqlx::ServerMessages_Type_ERROR,
	   "PLAIN auth + empty default_route: client receives ERROR frame (not Ok)");

	detach_session_fds(sess);
	close(fds[0]); close(fds[1]);
}

// Exercise the session's backend-connection setup site in
// handler_connecting_server and assert that the value passed to
// set_backend_user() tracks the resolved identity rather than only the
// frontend username. Pre-fix (PR #5641), the site hardcoded
// backend_conn_->set_backend_user(username_.c_str()) while pairing it
// with identity_->backend_password — which, for mysqlx_users rows whose
// backend_auth_mode is `service_account` and whose backend_username
// differs from the frontend username, paired userA's password with
// userB's name and broke backend auth.
//
// Strategy: drive the session far enough that username_ and identity_
// are both populated (setup_authenticated_session), then pre-seed
// backend_conn_ in AUTHENTICATING + BACKEND_AUTH_NOT_STARTED state
// attached to a valid socketpair fd. Flipping status_ to
// CONNECTING_SERVER and firing handler() lands us at the set_backend_user
// call site without invoking the real TCP connect. The socketpair is
// nonblocking (MysqlxDataStream::init sets O_NONBLOCK) so
// step_auth_capabilities_get() writes the cap-get frame and returns;
// the subsequent try_read_one_frame() sees nothing and the handler
// bails out cleanly with backend_user_ observable via the test accessor.
static void test_backend_user_uses_backend_username_when_set() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	setup_authenticated_session(client_fds, sess);

	// Replace identity_ so it carries a DISTINCT backend_username, mimicking
	// a service_account-mode mysqlx_users row.
	MysqlxResolvedIdentity id {};
	id.username = "front_user";
	id.x_enabled = true;
	id.default_route = "default_test_route";
	id.backend_auth_mode = MysqlxBackendAuthMode::service_account;
	id.backend_username = "svc_account_42";
	id.backend_password = "svc_pw";
	sess.inject_identity_for_test(id);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::AUTHENTICATING);
	sess.backend_conn() = conn;
	sess.set_status(MysqlxSession::CONNECTING_SERVER);

	sess.to_process = true;
	sess.handler();

	ok(std::string(conn->get_backend_user_for_test()) == "svc_account_42",
	   "service_account mode: set_backend_user uses identity_->backend_username");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

// Mirror test for the mapped-mode (default) path: identity has an EMPTY
// backend_username, so the fallback must reuse the frontend username_.
// setup_authenticated_session drives MYSQL41 auth with "testuser" as the
// frontend username, so that is what we expect to land in backend_user_.
static void test_backend_user_falls_back_to_frontend_username() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);

	MysqlxSession sess;
	setup_authenticated_session(client_fds, sess);

	// Re-inject identity with EMPTY backend_username: mapped-mode default.
	MysqlxResolvedIdentity id {};
	id.username = "testuser";
	id.x_enabled = true;
	id.default_route = "default_test_route";
	id.backend_auth_mode = MysqlxBackendAuthMode::mapped;
	id.backend_username = "";  // the point of this test
	sess.inject_identity_for_test(id);

	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(backend_fds[0]);
	conn->set_state(MysqlxConnection::AUTHENTICATING);
	sess.backend_conn() = conn;
	sess.set_status(MysqlxSession::CONNECTING_SERVER);

	sess.to_process = true;
	sess.handler();

	ok(std::string(conn->get_backend_user_for_test()) == "testuser",
	   "mapped mode (empty backend_username): set_backend_user falls back to frontend username_");

	detach_session_fds(sess);
	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(76);
	diag("=== mysqlx_robustness_unit-t starting ===");

	test_server_response_terminal_frame();
	test_server_response_non_terminal_keeps_waiting();
	test_server_response_multi_frame_pipeline();
	test_backend_disconnect_during_query();
	test_backend_fd_negative_no_crash();
	test_mysql41_no_credential_lookup_rejects();
	test_auth_start_empty_payload();
	test_auth_start_malformed_protobuf();
	test_auth_challenge_wrong_msg_type();
	test_return_backend_no_thread();
	test_connection_limit_config();
	test_client_disconnect_detected();
	test_check_connect_bad_fd();
	test_check_connect_success_path();
	test_server_ds_aliases_backend_conn_backend_ds();
	test_forward_empty_frame();
	test_empty_source_clears_stale_dest();
	test_insert_failure_rolls_back();
	test_listener_route_tracking();
	test_listener_reconciliation();
	test_listener_reconciliation_bind_change();
	test_route_exists_predicate();

	test_routing_happy_path();
	test_routing_no_default_route();
	test_routing_unknown_route();
	test_routing_no_backend();
	test_routing_stats_on_failure();
	test_routing_unknown_user();

	test_plain_auth_empty_default_route_closes_session();

	test_backend_user_uses_backend_username_when_set();
	test_backend_user_falls_back_to_frontend_username();

	return exit_status();
}
