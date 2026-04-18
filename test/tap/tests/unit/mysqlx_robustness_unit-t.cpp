#include "mysqlx_session.h"
#include "mysqlx_protocol.h"
#include "mysqlx_thread.h"
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
	// Attach the session to the shared test thread so resolve_backend_target()
	// finds a populated config store at auth-complete. Pre-seed identity_
	// directly rather than via set_identity_lookup: the latter would cause
	// the MYSQL41 challenge-response handler to re-run scramble verification
	// against a real password hash, which the helper's fixed all-zero
	// scramble cannot satisfy. With identity_lookup_ unset, the auth
	// handler's credential-verify block is skipped (matching the long-
	// standing "open-proxy" behavior covered by
	// test_mysql41_no_credential_lookup_accepts_any), but resolve_backend_target()
	// still sees a populated identity_ with a valid default_route.
	sess.init(fds[0], &default_test_thread());
	MysqlxResolvedIdentity id {};
	id.username = "testuser";
	id.x_enabled = true;
	id.default_route = "default_test_route";
	sess.inject_identity_for_test(id);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);

	sess.to_process = true;
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET, nullptr, 0);
	sess.handler();
	usleep(5000);
	{
		uint8_t buf[4096];
		read_x_frame(fds[1], buf, sizeof(buf));
	}

	sess.to_process = true;
	Mysqlx::Connection::CapabilitiesSet cap_set;
	auto* cap = cap_set.mutable_capabilities()->add_capabilities();
	cap->set_name("authentication.mechanisms");
	auto* val = cap->mutable_value();
	val->set_type(Mysqlx::Datatypes::Any::ARRAY);
	auto* arr = val->mutable_array();
	auto* v = arr->add_value();
	v->set_type(Mysqlx::Datatypes::Any::SCALAR);
	v->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	v->mutable_scalar()->mutable_v_string()->set_value("MYSQL41");
	std::string cap_s;
	cap_set.SerializeToString(&cap_s);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET,
		reinterpret_cast<const uint8_t*>(cap_s.data()), cap_s.size());
	sess.handler();
	usleep(5000);
	{
		uint8_t buf[4096];
		read_x_frame(fds[1], buf, sizeof(buf));
	}

	sess.to_process = true;
	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("MYSQL41");
	auth_start.set_auth_data(std::string("\0\0testuser", 11));
	std::string serialized;
	auth_start.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
	sess.handler();
	usleep(5000);
	{
		uint8_t buf[4096];
		read_x_frame(fds[1], buf, sizeof(buf));
	}

	sess.to_process = true;
	Mysqlx::Session::AuthenticateContinue cont;
	cont.set_auth_data("*0000000000000000000000000000000000000000");
	cont.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
	sess.handler();
	usleep(5000);
	{
		uint8_t buf[4096];
		read_x_frame(fds[1], buf, sizeof(buf));
	}
}

static void detach_session_fds(MysqlxSession& sess) {
	sess.client_ds().init(XDS_FRONTEND, -1);
	if (sess.backend_conn()) {
		sess.backend_conn()->set_fd(-1);
	}
}

static void test_server_response_terminal_frame() {
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

static void test_mysql41_no_credential_lookup_accepts_any() {
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

	ok(sess.is_healthy(), "without credential_lookup, invalid scramble accepted (open-proxy behavior)");
	ok(sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG,
	   "session in WAITING_CLIENT_XMSG after auth without verification");

	detach_session_fds(sess);
	close(fds[0]); close(fds[1]);
}

static void test_auth_start_empty_payload() {
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
	Mysqlx_Thread thread;
	thread.set_max_sessions(1);
	ok(thread.get_max_sessions() == 1, "max_sessions set to 1");
	thread.set_max_sessions(100);
	ok(thread.get_max_sessions() == 100, "max_sessions updated to 100");
}

static void test_client_disconnect_detected() {
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

static void test_forward_empty_frame() {
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

static void test_route_exists_predicate() {
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
	plan(48);

	test_server_response_terminal_frame();
	test_server_response_non_terminal_keeps_waiting();
	test_server_response_multi_frame_pipeline();
	test_backend_disconnect_during_query();
	test_backend_fd_negative_no_crash();
	test_mysql41_no_credential_lookup_accepts_any();
	test_auth_start_empty_payload();
	test_auth_start_malformed_protobuf();
	test_auth_challenge_wrong_msg_type();
	test_return_backend_no_thread();
	test_connection_limit_config();
	test_client_disconnect_detected();
	test_forward_empty_frame();
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
