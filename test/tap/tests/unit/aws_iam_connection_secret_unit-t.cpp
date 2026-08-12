/**
 * @file aws_iam_connection_secret_unit-t.cpp
 * @brief Verify AWS IAM tokens exist only for the backend handshake.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "Aws_Iam_Token_Manager.h"
#include "MySQL_Backend_Auth.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Logger.hpp"

#include <openssl/crypto.h>

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <unistd.h>

#ifndef __linux__

int main() {
	plan(1);
	skip(1, "requires GNU ld --wrap support");
	return exit_status();
}

#else

extern MySQL_HostGroups_Manager *MyHGM;
extern MySQL_Logger *GloMyLogger;

namespace {

struct ConnectorObservation {
	unsigned int connect_calls { 0 };
	std::string host;
	std::string password;
	std::string tls_server_name;
	bool ssl_enforce_seen { false };
	bool ssl_enforce { false };
	bool ssl_verify_seen { false };
	bool ssl_verify { false };
	bool cleartext_seen { false };
	bool cleartext { false };
	bool reconnect_seen { false };
	bool reconnect { false };
	bool defer_password_copy { false };
};

ConnectorObservation connector;
void *connector_password_copy = nullptr;
size_t connector_password_size = 0;
unsigned int connector_password_cleanse_calls = 0;
bool connector_password_was_zeroed = false;
unsigned int token_cleanse_calls = 0;
size_t token_cleanse_size = 0;
bool token_was_zeroed = false;
const char *connector_retained_password = nullptr;
bool connector_abort_seen = false;
bool token_cleansed_after_abort = false;

void reset_observations() {
	connector = ConnectorObservation {};
	connector_password_copy = nullptr;
	connector_password_size = 0;
	connector_password_cleanse_calls = 0;
	connector_password_was_zeroed = false;
	token_cleanse_calls = 0;
	token_cleanse_size = 0;
	token_was_zeroed = false;
	connector_retained_password = nullptr;
	connector_abort_seen = false;
	token_cleansed_after_abort = false;
}

bool all_zero(const void *ptr, size_t size) {
	const unsigned char *bytes = static_cast<const unsigned char *>(ptr);
	for (size_t i = 0; i < size; ++i) {
		if (bytes[i] != 0) {
			return false;
		}
	}
	return true;
}

void tracked_token_cleanse(void *ptr, size_t size) {
	++token_cleanse_calls;
	token_cleanse_size = size;
	OPENSSL_cleanse(ptr, size);
	token_was_zeroed = all_zero(ptr, size);
	token_cleansed_after_abort = connector_abort_seen;
}

std::string capture_stderr(const std::function<void()>& action) {
	FILE *captured = tmpfile();
	if (captured == nullptr) {
		BAIL_OUT("failed to create stderr capture file");
	}
	fflush(stderr);
	const int saved_stderr = dup(STDERR_FILENO);
	if (saved_stderr < 0 || dup2(fileno(captured), STDERR_FILENO) < 0) {
		BAIL_OUT("failed to redirect stderr");
	}
	action();
	fflush(stderr);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stderr);

	std::string output;
	char buffer[256];
	rewind(captured);
	while (fgets(buffer, sizeof(buffer), captured) != nullptr) {
		output += buffer;
	}
	fclose(captured);
	return output;
}

AwsIamTokenKey token_key() {
	return { "orders.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com",
		3306, "us-east-1", "iam_backend" };
}

AwsIamTokenResult token_result(const std::string& token, uint64_t generation = 73) {
	AwsIamTokenResult result;
	result.status = AwsIamStatus::OK;
	result.generation = generation;
	result.token = SecureString(token, tracked_token_cleanse);
	return result;
}

MySrvC *create_server() {
	srv_info_t info;
	info.addr = "198.51.100.23";
	info.port = 3306;
	info.kind = "aws-iam-connection-secret-unit";

	srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 100;
	opts.use_ssl = 0;

	MyHGM->wrlock();
	int rc = MyHGM->create_new_server_in_hg(606, info, opts);
	MyHGC *hostgroup = MyHGM->MyHGC_find(606);
	MyHGM->wrunlock();
	if (rc != 0 || hostgroup == nullptr || hostgroup->mysrvs->cnt() != 1) {
		BAIL_OUT("failed to create the IAM unit-test backend");
	}
	return hostgroup->mysrvs->idx(0);
}

class ConnectionFixture {
public:
	ConnectionFixture(MySQL_Thread& worker, MySrvC *server) {
		session = new MySQL_Session();
		session->thread = &worker;
		// Avoid changing process-wide frontend counters in this component test.
		session->connections_handler = true;

		frontend_stream = new MySQL_Data_Stream();
		frontend_stream->init(MYDS_FRONTEND, session, -1);
		frontend = new MySQL_Connection();
		frontend_stream->myconn = frontend;
		frontend->myds = frontend_stream;
		session->client_myds = frontend_stream;
		frontend->userinfo->set(
			const_cast<char *>("frontend_user"),
			const_cast<char *>("frontend-password-must-not-change"),
			const_cast<char *>("frontend_schema"), nullptr);

		backend_stream = new MySQL_Data_Stream();
		backend_stream->init(MYDS_BACKEND_NOT_CONNECTED, session, -1);
		connection = new MySQL_Connection();
		connection->send_quit = false;
		connection->parent = server;
		connection->myds = backend_stream;
		backend_stream->myconn = connection;
		MySQL_Backend *backend = session->create_backend(606, backend_stream);
		session->mybe = backend;
		connection->userinfo->set(
			const_cast<char *>("iam_backend"),
			const_cast<char *>("ordinary-backend-password"),
			const_cast<char *>("orders"), nullptr);
	}

	~ConnectionFixture() {
		destroy_connection();
		delete session;
	}

	void destroy_connection() {
		if (connection != nullptr) {
			backend_stream->myconn = nullptr;
			connection->myds = nullptr;
			delete connection;
			connection = nullptr;
		}
		connector_password_copy = nullptr;
		connector_password_size = 0;
	}

	const char *frontend_password() const {
		return frontend->userinfo->password;
	}

	MySQL_Session *session { nullptr };
	MySQL_Data_Stream *frontend_stream { nullptr };
	MySQL_Connection *frontend { nullptr };
	MySQL_Data_Stream *backend_stream { nullptr };
	MySQL_Connection *connection { nullptr };
};

void attach_iam(ConnectionFixture& fixture, const std::string& token) {
	fixture.connection->set_backend_auth_type(MySQLBackendAuthType::AWS_IAM);
	fixture.connection->attach_aws_iam_token(token_key(), token_result(token));
}

void check_cleanup(ConnectionFixture& fixture, const std::string& label, size_t token_size) {
	ok(!fixture.connection->has_aws_iam_handshake_secret(),
		"%s clears the ProxySQL handshake token", label.c_str());
	ok(fixture.connection->mysql == nullptr || fixture.connection->mysql->passwd == nullptr,
		"%s clears MYSQL::passwd", label.c_str());
	ok(token_cleanse_calls == 1 && token_cleanse_size == token_size && token_was_zeroed,
		"%s cleanses the complete ProxySQL token buffer", label.c_str());
	ok(connector_password_cleanse_calls == 1 && connector_password_was_zeroed,
		"%s cleanses the Connector/C password copy", label.c_str());
}

void test_password_mode(MySQL_Thread& worker, MySrvC *server) {
	reset_observations();
	ConnectionFixture fixture(worker, server);
	fixture.connection->connect_start();

	ok(fixture.connection->backend_auth_type() == MySQLBackendAuthType::PASSWORD,
		"password authentication remains the default backend mode");
	ok(connector.password == "ordinary-backend-password",
		"password mode still passes userinfo->password to Connector/C");
	ok(std::strcmp(fixture.frontend_password(), "frontend-password-must-not-change") == 0,
		"password-mode backend startup does not change the frontend password");
	connector_password_copy = nullptr;
}

void test_sha1_password_mode(MySQL_Thread& worker, MySrvC *server) {
	reset_observations();
	ConnectionFixture fixture(worker, server);
	fixture.connection->userinfo->set(
		const_cast<char *>("iam_backend"),
		const_cast<char *>("*0123456789012345678901234567890123456789"),
		const_cast<char *>("orders"),
		const_cast<char *>("sha1-stage-one-secret"));
	fixture.connection->connect_start();

	ok(connector.password == "sha1-stage-one-secret",
		"password mode preserves the existing SHA1 credential path");
	connector_password_copy = nullptr;
}

void test_iam_handshake_and_explicit_clear(MySQL_Thread& worker, MySrvC *server) {
	reset_observations();
	ConnectionFixture fixture(worker, server);
	const std::string token = "orders.cluster:3306/?Action=connect&" + std::string(2048, 'x');
	attach_iam(fixture, token);
	connector.defer_password_copy = true;
	fixture.connection->connect_start();

	ok(fixture.connection->backend_auth_type() == MySQLBackendAuthType::AWS_IAM,
		"IAM authentication is stored independently from userinfo");
	ok(connector.password == token,
		"IAM startup passes the full token instead of userinfo->password");
	ok(connector.host == "198.51.100.23",
		"Connector/C keeps using the DNS-cache transport IP");
	ok(connector.tls_server_name == token_key().endpoint,
		"TLS verification uses the configured RDS endpoint identity");
	ok(connector.ssl_enforce_seen && connector.ssl_enforce,
		"IAM startup enforces TLS");
	ok(connector.ssl_verify_seen && connector.ssl_verify,
		"IAM startup enables server-certificate verification");
	ok(connector.cleartext_seen && connector.cleartext,
		"IAM startup enables the cleartext authentication plugin");
	ok(connector.reconnect_seen && !connector.reconnect,
		"IAM startup explicitly disables Connector/C auto-reconnect");
	ok(std::strcmp(fixture.frontend_password(), "frontend-password-must-not-change") == 0,
		"IAM backend startup never changes the frontend password");

	ok(connector_retained_password != nullptr,
		"connector fake retains the exact IAM input pointer across the async yield");
	fixture.connection->clear_aws_iam_handshake_secret();
	ok(connector_abort_seen,
		"explicit clear aborts the connector coroutine before invalidating its password pointer");
	ok(token_cleanse_calls == 1 && token_cleanse_size == token.size() && token_was_zeroed,
		"explicit clear eventually cleanses the complete ProxySQL token buffer");
	ok(token_cleansed_after_abort,
		"explicit clear cleanses the token only after aborting the connector coroutine");
	ok(fixture.connection->mysql == nullptr,
		"explicit clear releases the aborted Connector/C handle");
}

void test_iam_to_password_transition(MySQL_Thread& worker, MySrvC *server) {
	reset_observations();
	ConnectionFixture fixture(worker, server);
	const std::string token = "transition-token";
	attach_iam(fixture, token);
	fixture.connection->set_backend_auth_type(MySQLBackendAuthType::PASSWORD);

	ok(!fixture.connection->has_aws_iam_handshake_secret() && token_cleanse_calls == 1,
		"IAM to password transition cleanses and drops the IAM handshake secret");
	fixture.connection->connect_start();
	ok(connector.password == "ordinary-backend-password",
		"IAM to password transition restores ordinary password authentication");
	fixture.connection->async_state_machine = ASYNC_CONNECT_END;
	fixture.connection->ret_mysql = fixture.connection->mysql;
	fixture.connection->handler(0);
	ok(fixture.connection->mysql->passwd != nullptr &&
		std::strcmp(fixture.connection->mysql->passwd, "ordinary-backend-password") == 0,
		"password-mode terminal cleanup preserves Connector/C's ordinary password state");
	ok(connector_password_cleanse_calls == 0,
		"password-mode terminal cleanup never treats the ordinary password as an IAM token");
	connector_password_copy = nullptr;
}

void test_unix_socket_rejected(MySQL_Thread& worker, MySrvC *tcp_server) {
	reset_observations();
	MySrvC unix_server(
		const_cast<char *>("/tmp/proxysql-iam-unit.sock"), 0, 0, 1,
		MYSQL_SERVER_STATUS_ONLINE, 0, 100, 0, 0, 0,
		const_cast<char *>("aws-iam-unix-unit"));
	unix_server.myhgc = tcp_server->myhgc;
	ConnectionFixture fixture(worker, &unix_server);
	const std::string token = "unix-socket-token";
	attach_iam(fixture, token);
	fixture.connection->handler(0);
	ok(connector.connect_calls == 0,
		"IAM mode rejects a Unix socket before Connector/C startup");
	ok(fixture.connection->ret_mysql == nullptr && fixture.connection->async_exit_status == 0,
		"Unix-socket rejection is a terminal connection error");
	ok(std::strcmp(fixture.frontend_password(), "frontend-password-must-not-change") == 0,
		"Unix-socket rejection does not change the frontend password");
	ok(token_cleanse_calls == 1 && token_was_zeroed,
		"Unix-socket rejection automatically cleanses the handshake token");
}

void test_missing_token_rejected(MySQL_Thread& worker, MySrvC *server) {
	reset_observations();
	ConnectionFixture fixture(worker, server);
	fixture.connection->set_backend_auth_type(MySQLBackendAuthType::AWS_IAM);
	fixture.connection->handler(0);
	ok(connector.connect_calls == 0,
		"IAM mode rejects a missing token before Connector/C startup");
	ok(fixture.connection->async_state_machine == ASYNC_CONNECT_FAILED,
		"missing IAM token reaches the terminal failed state");
}

void test_terminal_cleanup(MySQL_Thread& worker, MySrvC *server,
	MDB_ASYNC_ST terminal_state, bool success, const char *label)
{
	reset_observations();
	ConnectionFixture fixture(worker, server);
	const std::string token = std::string(label) + "-terminal-token";
	attach_iam(fixture, token);
	fixture.connection->connect_start();
	fixture.connection->async_state_machine = terminal_state;
	fixture.connection->ret_mysql = success ? fixture.connection->mysql : nullptr;
	fixture.backend_stream->wait_until = 1;
	worker.curtime = 2;
	fixture.connection->handler(0);

	check_cleanup(fixture, label, token.size());
	const MDB_ASYNC_ST expected = terminal_state == ASYNC_CONNECT_END
		? (success ? ASYNC_CONNECT_SUCCESSFUL : ASYNC_CONNECT_FAILED)
		: ASYNC_CONNECT_TIMEOUT;
	ok(fixture.connection->async_state_machine == expected,
		"%s preserves the expected terminal state", label);
}

void test_terminal_error_is_redacted(MySQL_Thread& worker, MySrvC *server) {
	reset_observations();
	ConnectionFixture fixture(worker, server);
	const std::string token = "sensitive-token-not-for-logs";
	attach_iam(fixture, token);
	fixture.connection->connect_start();
	std::snprintf(fixture.connection->mysql->net.last_error,
		sizeof(fixture.connection->mysql->net.last_error),
		"backend reflected credential: %s", token.c_str());
	fixture.connection->mysql->net.last_errno = 1045;
	fixture.connection->async_state_machine = ASYNC_CONNECT_END;
	fixture.connection->ret_mysql = nullptr;

	const std::string log = capture_stderr([&fixture]() { fixture.connection->handler(0); });
	ok(log.find(token) == std::string::npos &&
		log.find("backend reflected credential") == std::string::npos,
		"IAM terminal failure never logs raw backend or credential text");
	ok(log.find("details redacted") != std::string::npos,
		"IAM terminal failure emits a fixed redacted diagnostic");
}

void test_destructor_cleanup(MySQL_Thread& worker, MySrvC *server) {
	reset_observations();
	ConnectionFixture fixture(worker, server);
	const std::string token = "destructor-terminal-token";
	attach_iam(fixture, token);
	fixture.connection->connect_start();
	fixture.destroy_connection();

	ok(token_cleanse_calls == 1 && token_cleanse_size == token.size() && token_was_zeroed,
		"destructor cleanses the complete ProxySQL token buffer");
	ok(connector_password_cleanse_calls == 1 && connector_password_was_zeroed,
		"destructor cleanses the Connector/C password copy");
}

} // namespace

extern "C" {

int __real_mysql_options(MYSQL *, enum mysql_option, const void *);
void __real_OPENSSL_cleanse(void *, size_t);
void __real_mysql_close_no_command(MYSQL *);

int __wrap_mysql_options(MYSQL *mysql, enum mysql_option option, const void *arg) {
	switch (option) {
		case MARIADB_OPT_TLS_SERVER_NAME:
			connector.tls_server_name = arg != nullptr ? static_cast<const char *>(arg) : "";
			break;
		case MYSQL_OPT_SSL_ENFORCE:
			connector.ssl_enforce_seen = true;
			connector.ssl_enforce = arg != nullptr && *static_cast<const my_bool *>(arg) != 0;
			break;
		case MYSQL_OPT_SSL_VERIFY_SERVER_CERT:
			connector.ssl_verify_seen = true;
			connector.ssl_verify = arg != nullptr && *static_cast<const my_bool *>(arg) != 0;
			break;
		case MYSQL_ENABLE_CLEARTEXT_PLUGIN:
			connector.cleartext_seen = true;
			connector.cleartext = arg != nullptr && *static_cast<const my_bool *>(arg) != 0;
			break;
		case MYSQL_OPT_RECONNECT:
			connector.reconnect_seen = true;
			connector.reconnect = arg != nullptr && *static_cast<const my_bool *>(arg) != 0;
			break;
		default:
			break;
	}
	return __real_mysql_options(mysql, option, arg);
}

int __wrap_mysql_real_connect_start(MYSQL **ret, MYSQL *mysql, const char *host,
	const char *, const char *password, const char *, unsigned int port,
	const char *, unsigned long)
{
	++connector.connect_calls;
	connector.host = host != nullptr ? host : "";
	connector.password = password != nullptr ? password : "";
	connector_retained_password = password;
	*ret = nullptr;

	if (!connector.defer_password_copy) {
		mysql->passwd = strdup(password != nullptr ? password : "");
	}
	mysql->host = strdup(host != nullptr ? host : "");
	mysql->port = port;
	connector_password_copy = mysql->passwd;
	connector_password_size = mysql->passwd != nullptr ? std::strlen(mysql->passwd) : 0;
	return MYSQL_WAIT_READ;
}

void __wrap_mysql_close_no_command(MYSQL *mysql) {
	if (connector_retained_password != nullptr) {
		connector_abort_seen = true;
		connector_retained_password = nullptr;
	}
	__real_mysql_close_no_command(mysql);
}

void __wrap_OPENSSL_cleanse(void *ptr, size_t size) {
	__real_OPENSSL_cleanse(ptr, size);
	if (ptr == connector_password_copy && size == connector_password_size) {
		++connector_password_cleanse_calls;
		connector_password_was_zeroed = all_zero(ptr, size);
	}
}

} // extern "C"

int main() {
	plan(47);
	if (test_init_minimal() != 0 || test_init_query_processor() != 0 ||
		test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize the unit-test component globals");
	}
	GloMyLogger = new MySQL_Logger();

	MySrvC *server = create_server();
	{
		MySQL_Thread worker;
		if (!worker.init()) {
			BAIL_OUT("MySQL_Thread::init() failed");
		}
		test_password_mode(worker, server);
		test_sha1_password_mode(worker, server);
		test_iam_handshake_and_explicit_clear(worker, server);
		test_iam_to_password_transition(worker, server);
		test_unix_socket_rejected(worker, server);
		test_missing_token_rejected(worker, server);
		test_terminal_cleanup(worker, server, ASYNC_CONNECT_END, true, "terminal success");
		test_terminal_cleanup(worker, server, ASYNC_CONNECT_END, false, "terminal error");
		test_terminal_error_is_redacted(worker, server);
		test_terminal_cleanup(worker, server, ASYNC_CONNECT_TIMEOUT, false, "timeout");
		test_destructor_cleanup(worker, server);
	}

	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}

#endif // __linux__
