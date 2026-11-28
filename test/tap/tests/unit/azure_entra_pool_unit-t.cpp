/**
 * @file azure_entra_pool_unit-t.cpp
 * @brief Azure Entra pool reuse, reset and kill rules (#6649).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "Aws_Iam_Provider.h"
#include "Aws_Locality_Manager.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_Data_Stream.h"
#include "MySQL_Logger.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

extern MySQL_HostGroups_Manager *MyHGM;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
extern MySQL_Authentication *GloMyAuth;
extern void *HGCU_thread_run();

namespace {

constexpr const char *kUser = "pool_user";
constexpr const char *kOtherUser = "other_pool_user";
constexpr const char *kInvalidReloadUser = "invalid_reload_pool_user";
// A frontend-only user: no USERNAME_BACKEND row, so plain PASSWORD mode (#6413).
constexpr const char *kSchema = "pool_schema";

std::atomic<unsigned int> change_user_calls { 0 };
std::atomic<bool> change_user_immediate_success { false };
std::string change_user_username;
std::string change_user_password;
MySQL_Connection *kill_source_connection = nullptr;
unsigned int kill_helper_dispatches = 0;
bool kill_source_token_present_at_dispatch = false;
bool kill_args_password_absent = false;
unsigned long kill_args_id = 0;
int kill_args_type = 0;
MySQLBackendAuthType kill_args_auth_type = MySQLBackendAuthType::PASSWORD;
std::string kill_args_endpoint;
std::string kill_args_region;
std::string kill_args_database_user;
std::string kill_args_transport;
unsigned int kill_args_port = 0;
int kill_args_use_ssl = 0;
std::chrono::steady_clock::time_point kill_args_deadline;

using OwnedCString = std::unique_ptr<char, void(*)(void*)>;

OwnedCString make_owned_cstring(const char* value) {
	if (value == nullptr) return OwnedCString{nullptr, std::free};
	auto size = std::strlen(value) + 1;
	auto* copy = static_cast<char*>(std::malloc(size));
	if (copy == nullptr) BAIL_OUT("failed to allocate test-managed c-string");
	std::memcpy(copy, value, size);
	return OwnedCString{copy, std::free};
}

std::vector<char> make_mutable_string(const char* value) {
	std::vector<char> data(std::strlen(value) + 1);
	std::memcpy(data.data(), value, std::strlen(value) + 1);
	return data;
}

MySrvC *create_server(unsigned int hostgroup_id, const char *address) {
	srv_info_t info;
	info.addr = address;
	info.port = 3306;
	info.kind = "aws-iam-pool-unit";
	srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 100;
	opts.use_ssl = 0;

	MyHGM->wrlock();
	const int rc = MyHGM->create_new_server_in_hg(hostgroup_id, info, opts);
	MyHGC *hostgroup = MyHGM->MyHGC_find(hostgroup_id);
	MyHGM->wrunlock();
	if (rc != 0 || hostgroup == nullptr || hostgroup->mysrvs->cnt() != 1) {
		BAIL_OUT("failed to create pool fixture for hostgroup %u", hostgroup_id);
	}
	return hostgroup->mysrvs->idx(0);
}

std::unique_ptr<MySQL_Connection> create_established_connection(
	MySrvC *server, const char *username, MySQLBackendAuthType type)
{
	auto connection = std::make_unique<MySQL_Connection>();
	connection->mysql = mysql_init(nullptr);
	if (connection->mysql == nullptr) {
		BAIL_OUT("mysql_init() failed for pool fixture");
	}
	connection->ret_mysql = connection->mysql;
	connection->mysql->charset = mariadb_get_charset_by_name("utf8mb4");
	if (connection->mysql->charset == nullptr) {
		BAIL_OUT("failed to initialize connector charset for pool fixture");
	}
	connection->parent = server;
	auto conn_username = make_mutable_string(username);
	auto conn_password = make_mutable_string("password");
	auto schema = make_mutable_string(kSchema);
	connection->userinfo->set(
		conn_username.data(), conn_password.data(), schema.data(), nullptr);
	connection->set_backend_auth_type(type);
	connection->healthy = true;
	connection->reusable = true;
	connection->send_quit = false;
	connection->fd = 123;
	connection->async_state_machine = ASYNC_IDLE;
	return connection;
}

class SessionFixture {
public:
	SessionFixture(MySQL_Thread& worker, unsigned int hostgroup_id,
		MySQLBackendAuthType requested_type, const char *username = kUser)
		: worker(worker)
	{
		session = new MySQL_Session();
		session->thread = &worker;
		session->connections_handler = true;

		frontend_stream = new MySQL_Data_Stream();
		frontend_stream->init(MYDS_FRONTEND, session, -1);
		frontend = new MySQL_Connection();
		frontend_stream->attach_connection(frontend);
		frontend_stream->myprot.init(&frontend_stream, frontend->userinfo, session);
		session->client_myds = frontend_stream;
		std::string frontend_user = username;
		std::string frontend_password = "password";
		std::string frontend_schema = kSchema;
		frontend->userinfo->set(
			&frontend_user[0], &frontend_password[0], &frontend_schema[0], nullptr);
		frontend->set_backend_auth_type(requested_type);

		session->mybe = session->create_backend(hostgroup_id);
		session->current_hostgroup = hostgroup_id;
		session->default_hostgroup = hostgroup_id;
	}

	~SessionFixture() {
		if (session != nullptr) delete session;
	}

	void attach_backend(MySQL_Connection *connection) {
		MySQL_Data_Stream *stream = session->mybe->server_myds;
		stream->attach_connection(connection);
		stream->assign_fd_from_mysql_conn();
		stream->myds_type = MYDS_BACKEND;
		stream->DSS = STATE_MARIADB_QUERY;
	}

	MySQL_Connection *selected() const {
		return session->mybe != nullptr && session->mybe->server_myds != nullptr
			? session->mybe->server_myds->myconn : nullptr;
	}

	MySQL_Thread& worker;
	MySQL_Session *session = nullptr;
	MySQL_Data_Stream *frontend_stream = nullptr;
	MySQL_Connection *frontend = nullptr;
};


// A user switched to Azure Entra must not keep using connections opened with
// the password: the switch takes effect at once (#6649).
void test_entra_needs_entra_connection(MySQL_Thread& worker) {
	MySrvC *server = create_server(804, "entra-matrix");
	SessionFixture request(worker, 804, MySQLBackendAuthType::AZURE_ENTRA);
	auto password = create_established_connection(
		server, kUser, MySQLBackendAuthType::PASSWORD);
	auto entra = create_established_connection(
		server, kUser, MySQLBackendAuthType::AZURE_ENTRA);
	ok(password->requires_CHANGE_USER(request.frontend, MySQLBackendAuthType::AZURE_ENTRA),
		"a password connection does not serve the same user after a switch to Azure Entra");
	ok(!entra->requires_CHANGE_USER(request.frontend, MySQLBackendAuthType::AZURE_ENTRA),
		"an Azure Entra connection serves the same Azure Entra user");
	ok(!entra->requires_CHANGE_USER(request.frontend, MySQLBackendAuthType::PASSWORD),
		"an Azure Entra connection still serves the same user after a switch to password");
}















// #6649: an Azure Entra connection follows the same token rules as AWS IAM.
void test_entra_conn_not_reset_queued() {
	MySrvC *server = create_server(850, "app.mysql.database.azure.com");
	GloMTH->variables.connpoll_reset_queue_length = 50;
	auto entra = create_established_connection(
		server, kUser, MySQLBackendAuthType::AZURE_ENTRA);
	auto entra_ptr = entra.get();
	entra->send_quit = true;
	server->ConnectionsUsed->add(entra.release());
	MyHGM->destroy_MyConn_from_pool(entra_ptr);
	ok(MyHGM->queue.size() == 0 && server->ConnectionsUsed->conns_length() == 0,
		"entra_conn_not_reset_queued: destroy deletes an Entra connection, no COM_CHANGE_USER reset");
}

void test_entra_conn_keeps_identity() {
	MySrvC *server = create_server(851, "app851.mysql.database.azure.com");
	auto entra = create_established_connection(
		server, kUser, MySQLBackendAuthType::AZURE_ENTRA);
	AwsIamTokenResult token;
	token.status = AwsIamStatus::OK;
	token.generation = 3;
	token.token = SecureString("ENTRA_HANDSHAKE_TOKEN");
	entra->attach_aws_iam_token({ server->address, server->port, "", kUser }, std::move(token));
	entra->set_backend_auth_type(MySQLBackendAuthType::AZURE_ENTRA);
	ok(entra->has_aws_iam_handshake_secret(),
		"entra_conn_keeps_identity: setting AZURE_ENTRA keeps the attached token");
}

void test_entra_kill_args_type() {
	MySrvC *server = create_server(852, "app852.mysql.database.azure.com");
	server->use_ssl = 1;
	GloMTH->variables.connpoll_reset_queue_length = 50;
	mysql_thread___kill_backend_connection_when_disconnect = true;
	auto entra = create_established_connection(
		server, kUser, MySQLBackendAuthType::AZURE_ENTRA);
	auto entra_ptr = entra.get();
	AwsIamTokenResult token;
	token.status = AwsIamStatus::OK;
	token.generation = 5;
	token.token = SecureString("ENTRA_HANDSHAKE_TOKEN");
	entra->attach_aws_iam_token({ server->address, server->port, "", kUser }, std::move(token));
	entra->send_quit = true;
	entra->async_state_machine = ASYNC_QUERY_CONT;
	entra->mysql->thread_id = 742;
	entra->connected_host_details.ip = make_owned_cstring("198.51.100.29").release();
	server->ConnectionsUsed->add(entra.release());

	kill_source_connection = entra_ptr;
	kill_helper_dispatches = 0;
	kill_args_password_absent = false;
	kill_args_auth_type = MySQLBackendAuthType::PASSWORD;
	kill_args_endpoint.clear();
	kill_args_region.clear();
	MyHGM->destroy_MyConn_from_pool(entra_ptr);
	kill_source_connection = nullptr;
	mysql_thread___kill_backend_connection_when_disconnect = false;
	ok(kill_helper_dispatches == 1 && kill_args_password_absent &&
		kill_args_auth_type == MySQLBackendAuthType::AZURE_ENTRA &&
		kill_args_endpoint == "app852.mysql.database.azure.com" && kill_args_region.empty() &&
		MyHGM->queue.size() == 0,
		"entra_kill_args_type: an Entra KILL_CONNECTION helper carries AZURE_ENTRA and no password");
}





class PendingTokenSource final : public AwsIamTokenSource {
public:
	AwsIamRequestHandle request(const AwsIamTokenKey& key, uint64_t,
		std::weak_ptr<AwsIamCompletionSink>) override {
		keys.push_back(key);
		return {1};
	}
	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point) override { return {}; }
	void cancel(AwsIamRequestHandle) override {}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool) override {}
	void record_waiting_session(bool) override {}
	AwsIamStatsSnapshot snapshot() const override { return {}; }
	std::vector<AwsIamTokenKey> keys;
};



} // namespace

#ifdef __linux__
extern "C" {

int __real_mysql_change_user_start(
	my_bool *, MYSQL *, const char *, const char *, const char *);
int __real_mysql_real_connect_start(MYSQL **, MYSQL *, const char *, const char *,
	const char *, const char *, unsigned int, const char *, unsigned long);
int __real_pthread_create(pthread_t *, const pthread_attr_t *,
	void *(*)(void *), void *);

int __wrap_mysql_change_user_start(
	my_bool *ret, MYSQL *, const char *username, const char *password, const char *)
{
	change_user_username = username != nullptr ? username : "";
	change_user_password = password != nullptr ? password : "";
	change_user_calls.fetch_add(1);
	*ret = 0;
	return change_user_immediate_success.load()
		? 0 : MYSQL_WAIT_READ;
}

int __wrap_mysql_real_connect_start(MYSQL **ret, MYSQL *, const char *,
	const char *, const char *, const char *, unsigned int, const char *,
	unsigned long)
{
	*ret = nullptr;
	return MYSQL_WAIT_READ;
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
	void *(*start_routine)(void *), void *arg)
{
	if (start_routine != &kill_query_thread) {
		return __real_pthread_create(thread, attr, start_routine, arg);
	}
	++kill_helper_dispatches;
	KillArgs *kill_args = static_cast<KillArgs *>(arg);
	std::unique_ptr<KillArgs> owned_kill_args(kill_args);
	kill_source_token_present_at_dispatch =
		kill_source_connection != nullptr &&
		kill_source_connection->has_aws_iam_handshake_secret();
	kill_args_password_absent = kill_args->password == nullptr;
	kill_args_id = kill_args->id;
	kill_args_type = kill_args->kill_type;
	kill_args_auth_type = kill_args->backend_auth_type;
	kill_args_endpoint = kill_args->configured_endpoint;
	kill_args_region = kill_args->region;
	kill_args_database_user = kill_args->database_user;
	kill_args_transport = kill_args->get_host_address();
	kill_args_port = kill_args->port;
	kill_args_use_ssl = kill_args->use_ssl;
	kill_args_deadline = kill_args->token_deadline;
	return 0;
}

} // extern "C"
#endif

int main() {
#ifndef __linux__
	plan(1);
	skip(1, "requires GNU ld --wrap support");
	return exit_status();
#else
	plan(6);
	if (test_init_minimal() != 0 || test_init_auth() != 0 ||
		test_init_query_processor() != 0 ||
		test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	std::unique_ptr<MySQL_Logger> owned_logger(std::make_unique<MySQL_Logger>());
	MySQL_Logger *previous_logger = GloMyLogger;
	GloMyLogger = owned_logger.get();
	std::string user = kUser;
	std::string other_user = kOtherUser;
	std::string invalid_user = kInvalidReloadUser;
	std::string password = "password";
	char empty[] = "";
	if (!(
		GloMyAuth->add(&user[0], &password[0], USERNAME_BACKEND,
			false, 0, empty, false, false,
			false, 100, empty, empty) &&
		GloMyAuth->add(&other_user[0], &password[0], USERNAME_BACKEND,
			false, 0, empty, false, false,
			false, 100, empty, empty) &&
		GloMyAuth->add(&invalid_user[0], &password[0], USERNAME_BACKEND,
			false, 0, empty, false, false,
			false, 100, empty, empty))) {
		BAIL_OUT("failed to load backend user fixtures");
	}
	GloMTH->num_threads = 1;
	{
		MySQL_Thread worker;
		if (!worker.init()) BAIL_OUT("MySQL_Thread::init() failed");
		worker.curtime = 10000000;
		test_entra_needs_entra_connection(worker); // 3
		test_entra_conn_not_reset_queued();       // 1
		test_entra_conn_keeps_identity();         // 1
		test_entra_kill_args_type();              // 1
	}

	GloMyLogger = previous_logger;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
#endif
}
