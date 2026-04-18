#include "mysqlx_session.h"
#include "mysqlx_protocol.h"
#include "mysqlx_thread.h"
#include "sqlite3db.h"
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

static void setup_authenticated_session(int fds[2], MysqlxSession& sess) {
	sess.init(fds[0], nullptr);
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
	sess.init(fds[0], nullptr);

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

static void test_check_connect_bad_fd() {
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

int main() {
	plan(39);

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
	test_check_connect_bad_fd();
	test_check_connect_success_path();
	test_forward_empty_frame();
	test_empty_source_clears_stale_dest();
	test_insert_failure_rolls_back();

	return exit_status();
}
