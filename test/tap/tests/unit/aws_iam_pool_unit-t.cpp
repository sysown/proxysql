/**
 * @file aws_iam_pool_unit-t.cpp
 * @brief Pool-identity and reset-safety tests for MySQL AWS IAM backends.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "Aws_Iam_Provider.h"
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
constexpr const char *kRowlessPassthroughUser = "rowless_passthrough_pool_user";
constexpr const char *kSchema = "pool_schema";

std::atomic<unsigned int> change_user_calls { 0 };
std::atomic<bool> change_user_immediate_success { false };
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

void destroy_used(MySQL_Connection *connection) {
	if (connection == nullptr) return;
	connection->send_quit = false;
	MyHGM->destroy_MyConn_from_pool(connection);
}

void test_identity_matrix(MySQL_Thread& worker) {
	MySrvC *server = create_server(801, "identity-matrix");
	SessionFixture same_password(worker, 801, MySQLBackendAuthType::PASSWORD, kUser);
	SessionFixture same_iam(worker, 801, MySQLBackendAuthType::AWS_IAM, kUser);
	SessionFixture other_password(worker, 801, MySQLBackendAuthType::PASSWORD, kOtherUser);

	auto password = create_established_connection(
		server, kUser, MySQLBackendAuthType::PASSWORD);
	auto iam = create_established_connection(
		server, kUser, MySQLBackendAuthType::AWS_IAM);

	ok(!password->requires_CHANGE_USER(
		same_password.frontend, MySQLBackendAuthType::PASSWORD),
		"same username and password mode are compatible without CHANGE_USER");
	ok(password->requires_CHANGE_USER(
		other_password.frontend, MySQLBackendAuthType::PASSWORD),
		"different username in password mode still requires ordinary CHANGE_USER");
	ok(password->requires_CHANGE_USER(
		same_iam.frontend, MySQLBackendAuthType::AWS_IAM),
		"password connection cannot satisfy the same username in IAM mode");
	ok(iam->requires_CHANGE_USER(
		same_password.frontend, MySQLBackendAuthType::PASSWORD),
		"IAM connection cannot satisfy the same username in password mode");
	ok(!iam->requires_CHANGE_USER(
		same_iam.frontend, MySQLBackendAuthType::AWS_IAM),
		"same username and IAM mode are compatible without token-age checks");
	ok(iam->requires_CHANGE_USER(
		other_password.frontend, MySQLBackendAuthType::AWS_IAM),
		"different username in IAM mode cannot reuse the established connection");

	worker.curtime += 16ULL * 60ULL * 1000000ULL;
	ok(!iam->requires_CHANGE_USER(
		same_iam.frontend, MySQLBackendAuthType::AWS_IAM),
		"an established IAM connection remains reusable beyond token lifetime");

	password.reset();
	iam.reset();
}

void test_runtime_mode_changes_global(MySQL_Thread& worker) {
	MySrvC *password_server = create_server(802, "password-to-iam");
	SessionFixture iam_request(worker, 802, MySQLBackendAuthType::AWS_IAM);
	auto old_password = create_established_connection(
		password_server, kUser, MySQLBackendAuthType::PASSWORD);
	password_server->ConnectionsFree->add(old_password.release());
	MySQL_Connection *selected = MyHGM->get_MyConn_from_pool(
		802, iam_request.session, false, nullptr, 0, -1,
		MySQLBackendAuthType::AWS_IAM);
	ok(selected != nullptr && selected->fd == -1 &&
		password_server->ConnectionsFree->conns_length() == 0,
		"PASSWORD to IAM policy change lazily destroys the old global entry and creates fresh");
	destroy_used(selected);

	MySrvC *iam_server = create_server(803, "iam-to-password");
	SessionFixture password_request(worker, 803, MySQLBackendAuthType::PASSWORD);
	auto old_iam = create_established_connection(
		iam_server, kUser, MySQLBackendAuthType::AWS_IAM);
	iam_server->ConnectionsFree->add(old_iam.release());
	selected = MyHGM->get_MyConn_from_pool(
		803, password_request.session, false, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->fd == -1 &&
		iam_server->ConnectionsFree->conns_length() == 0,
		"IAM to PASSWORD policy change lazily destroys the old global entry and creates fresh");
	destroy_used(selected);
}

void test_runtime_mode_change_local(MySQL_Thread& worker) {
	MySrvC *server = create_server(804, "local-password-to-iam");
	SessionFixture request(worker, 804, MySQLBackendAuthType::AWS_IAM);
	auto old_password = create_established_connection(
		server, kUser, MySQLBackendAuthType::PASSWORD);
	auto old_password_ptr = old_password.get();
	server->ConnectionsUsed->add(old_password.release());
	worker.push_MyConn_local(old_password_ptr);

	MySQL_Connection *selected = worker.get_MyConn_local(
		804, request.session, nullptr, 0, -1,
		MySQLBackendAuthType::AWS_IAM);
	ok(selected == nullptr && server->ConnectionsUsed->conns_length() == 0,
		"local checkout lazily destroys a connection from the previous auth mode");
	if (selected != nullptr) destroy_used(selected);
}

void test_mixed_user_mode_global(MySQL_Thread& worker) {
	MySrvC *password_server = create_server(809, "mixed-global-password");
	SessionFixture password_request(
		worker, 809, MySQLBackendAuthType::PASSWORD, kUser);
	auto unrelated_iam = create_established_connection(
		password_server, kOtherUser, MySQLBackendAuthType::AWS_IAM);
	unrelated_iam->fd = 201;
	auto exact_password = create_established_connection(
		password_server, kUser, MySQLBackendAuthType::PASSWORD);
	exact_password->fd = 202;
	password_server->ConnectionsFree->add(unrelated_iam.release());
	password_server->ConnectionsFree->add(exact_password.release());
	MySQL_Connection *selected = MyHGM->get_MyConn_from_pool(
		809, password_request.session, false, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->fd == 202 &&
		password_server->ConnectionsFree->conns_length() == 1,
		"PASSWORD checkout preserves another user's idle IAM connection globally");
	destroy_used(selected);

	SessionFixture iam_request(
		worker, 809, MySQLBackendAuthType::AWS_IAM, kOtherUser);
	selected = MyHGM->get_MyConn_from_pool(
		809, iam_request.session, false, nullptr, 0, -1,
		MySQLBackendAuthType::AWS_IAM);
	ok(selected != nullptr && selected->fd == 201,
		"unrelated global IAM entry remains reusable by its exact identity");
	destroy_used(selected);

	MySrvC *iam_server = create_server(810, "mixed-global-iam");
	SessionFixture exact_iam_request(
		worker, 810, MySQLBackendAuthType::AWS_IAM, kUser);
	auto unrelated_password = create_established_connection(
		iam_server, kOtherUser, MySQLBackendAuthType::PASSWORD);
	unrelated_password->fd = 211;
	auto exact_iam = create_established_connection(
		iam_server, kUser, MySQLBackendAuthType::AWS_IAM);
	exact_iam->fd = 212;
	iam_server->ConnectionsFree->add(unrelated_password.release());
	iam_server->ConnectionsFree->add(exact_iam.release());
	selected = MyHGM->get_MyConn_from_pool(
		810, exact_iam_request.session, false, nullptr, 0, -1,
		MySQLBackendAuthType::AWS_IAM);
	ok(selected != nullptr && selected->fd == 212 &&
		iam_server->ConnectionsFree->conns_length() == 1,
		"IAM checkout preserves another user's idle PASSWORD connection globally");
	destroy_used(selected);

	SessionFixture unrelated_password_request(
		worker, 810, MySQLBackendAuthType::PASSWORD, kOtherUser);
	selected = MyHGM->get_MyConn_from_pool(
		810, unrelated_password_request.session, false, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->fd == 211,
		"unrelated global PASSWORD entry remains reusable by its exact identity");
	destroy_used(selected);
}

void test_mixed_user_mode_local(MySQL_Thread& worker) {
	MySrvC *password_server = create_server(811, "mixed-local-password");
	SessionFixture password_request(
		worker, 811, MySQLBackendAuthType::PASSWORD, kUser);
	auto unrelated_iam = create_established_connection(
		password_server, kOtherUser, MySQLBackendAuthType::AWS_IAM);
	unrelated_iam->fd = 301;
	auto exact_password = create_established_connection(
		password_server, kUser, MySQLBackendAuthType::PASSWORD);
	exact_password->fd = 302;
	auto unrelated_iam_ptr = unrelated_iam.get();
	auto exact_password_ptr = exact_password.get();
	password_server->ConnectionsUsed->add(unrelated_iam.release());
	password_server->ConnectionsUsed->add(exact_password.release());
	worker.push_MyConn_local(unrelated_iam_ptr);
	worker.push_MyConn_local(exact_password_ptr);
	MySQL_Connection *selected = worker.get_MyConn_local(
		811, password_request.session, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->fd == 302,
		"local PASSWORD checkout selects its exact identity in a mixed-mode cache");
	destroy_used(selected);

	SessionFixture iam_request(
		worker, 811, MySQLBackendAuthType::AWS_IAM, kOtherUser);
	selected = worker.get_MyConn_local(
		811, iam_request.session, nullptr, 0, -1,
		MySQLBackendAuthType::AWS_IAM);
	ok(selected != nullptr && selected->fd == 301,
		"local PASSWORD checkout preserves another user's reusable IAM entry");
	destroy_used(selected);

	MySrvC *iam_server = create_server(812, "mixed-local-iam");
	SessionFixture exact_iam_request(
		worker, 812, MySQLBackendAuthType::AWS_IAM, kUser);
	auto unrelated_password = create_established_connection(
		iam_server, kOtherUser, MySQLBackendAuthType::PASSWORD);
	unrelated_password->fd = 311;
	auto exact_iam = create_established_connection(
		iam_server, kUser, MySQLBackendAuthType::AWS_IAM);
	exact_iam->fd = 312;
	auto unrelated_password_ptr = unrelated_password.get();
	auto exact_iam_ptr = exact_iam.get();
	iam_server->ConnectionsUsed->add(unrelated_password.release());
	iam_server->ConnectionsUsed->add(exact_iam.release());
	worker.push_MyConn_local(unrelated_password_ptr);
	worker.push_MyConn_local(exact_iam_ptr);
	selected = worker.get_MyConn_local(
		812, exact_iam_request.session, nullptr, 0, -1,
		MySQLBackendAuthType::AWS_IAM);
	ok(selected != nullptr && selected->fd == 312,
		"local IAM checkout selects its exact identity in a mixed-mode cache");
	destroy_used(selected);

	SessionFixture unrelated_password_request(
		worker, 812, MySQLBackendAuthType::PASSWORD, kOtherUser);
	selected = worker.get_MyConn_local(
		812, unrelated_password_request.session, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->fd == 311,
		"local IAM checkout preserves another user's reusable PASSWORD entry");
	destroy_used(selected);
}

void load_invalid_reload_policy() {
	std::vector<char> invalid_user(std::strlen(kInvalidReloadUser) + 1);
	std::strcpy(invalid_user.data(), kInvalidReloadUser);
	char password[] = "password";
	char backend_auth[] = "{\"backend_auth\":{\"type\":17}}";
	char empty[] = "";
	if (!GloMyAuth->add(
		invalid_user.data(), password,
		USERNAME_BACKEND, false, 0, empty, false, false,
		false, 100, backend_auth, empty)) {
		BAIL_OUT("failed to load malformed backend policy fixture");
	}
}

void test_attached_password_reload_to_invalid_fails_closed(MySQL_Thread& worker) {
	MySrvC *server = create_server(813, "attached-invalid-policy");
	SessionFixture fixture(
		worker, 813, MySQLBackendAuthType::PASSWORD, kInvalidReloadUser);
	auto password = create_established_connection(
		server, kInvalidReloadUser, MySQLBackendAuthType::PASSWORD);
	auto password_ptr = password.get();
	server->ConnectionsUsed->add(password.release());
	fixture.attach_backend(password_ptr);
	fixture.session->set_status(PROCESSING_QUERY);
	load_invalid_reload_policy();
	change_user_calls.store(0);
	fixture.session->to_process = 1;
	fixture.session->handler();
	ok(fixture.session->status == WAITING_CLIENT_DATA &&
		fixture.selected() == nullptr && fixture.session->previous_status.empty() &&
		server->ConnectionsUsed->conns_length() == 0 &&
		change_user_calls.load() == 0,
		"attached PASSWORD connection fails terminally when reload makes policy INVALID");
}

void test_invalid_policy_cannot_continue_change_user(MySQL_Thread& worker) {
	MySrvC *server = create_server(814, "changing-user-invalid-policy");
	SessionFixture fixture(
		worker, 814, MySQLBackendAuthType::PASSWORD, kInvalidReloadUser);
	auto password = create_established_connection(
		server, kInvalidReloadUser, MySQLBackendAuthType::PASSWORD);
	auto password_ptr = password.get();
	server->ConnectionsUsed->add(password.release());
	fixture.attach_backend(password_ptr);
	fixture.session->previous_status.push(PROCESSING_QUERY);
	fixture.session->set_status(CHANGING_USER_SERVER);
	change_user_calls.store(0);
	fixture.session->to_process = 1;
	fixture.session->handler();
	ok(fixture.session->status == WAITING_CLIENT_DATA &&
		fixture.selected() == nullptr && fixture.session->previous_status.empty() &&
		server->ConnectionsUsed->conns_length() == 0 &&
		change_user_calls.load() == 0,
		"INVALID policy discovered in CHANGING_USER_SERVER cannot send a password");
}

void test_invalid_policy_cannot_enter_reset(MySQL_Thread& worker) {
	MySrvC *server = create_server(815, "reset-invalid-policy");
	SessionFixture fixture(
		worker, 815, MySQLBackendAuthType::PASSWORD, kInvalidReloadUser);
	auto password = create_established_connection(
		server, kInvalidReloadUser, MySQLBackendAuthType::PASSWORD);
	auto password_ptr = password.get();
	server->ConnectionsUsed->add(password.release());
	fixture.attach_backend(password_ptr);
	fixture.session->set_status(RESETTING_CONNECTION);
	change_user_calls.store(0);
	fixture.session->to_process = 1;
	const int rc = fixture.session->handler();
	ok(rc == -1 && fixture.session->status == session_status___NONE &&
		fixture.selected() == nullptr &&
		server->ConnectionsUsed->conns_length() == 0 &&
		change_user_calls.load() == 0,
		"INVALID backend policy destroys reset work without COM_CHANGE_USER");
}

void test_authorized_rowless_passthrough_can_enter_detached_reset(
	MySQL_Thread& worker)
{
	MySrvC *server = create_server(817, "reset-rowless-passthrough");
	SessionFixture fixture(
		worker, 817, MySQLBackendAuthType::PASSWORD,
		kRowlessPassthroughUser);
	auto password = create_established_connection(
		server, kRowlessPassthroughUser, MySQLBackendAuthType::PASSWORD);
	password->set_rowless_passthrough_authorized(true);
	auto password_ptr = password.get();
	server->ConnectionsUsed->add(password.release());
	fixture.attach_backend(password_ptr);
	fixture.session->set_status(RESETTING_CONNECTION);
	change_user_calls.store(0);
	fixture.session->to_process = 1;
	const int rc = fixture.session->handler();
	ok(rc == 0 && fixture.session->status == RESETTING_CONNECTION &&
		fixture.selected() == password_ptr &&
		server->ConnectionsUsed->conns_length() == 1 &&
		change_user_calls.load() == 1,
		"authorized rowless pass-through PASSWORD can enter detached reset");
}

void test_destroy_path_never_queues_iam() {
	MySrvC *server = create_server(805, "destroy-iam");
	GloMTH->variables.connpoll_reset_queue_length = 50;
	auto iam = create_established_connection(
		server, kUser, MySQLBackendAuthType::AWS_IAM);
	auto iam_ptr = iam.get();
	iam->send_quit = true;
	server->ConnectionsUsed->add(iam.release());
	MyHGM->destroy_MyConn_from_pool(iam_ptr);
	ok(MyHGM->queue.size() == 0 && server->ConnectionsUsed->conns_length() == 0,
		"destroy_MyConn_from_pool deletes IAM instead of queueing COM_CHANGE_USER reset");

	auto password = create_established_connection(
		server, kUser, MySQLBackendAuthType::PASSWORD);
	auto password_ptr = password.get();
	password->send_quit = true;
	server->ConnectionsUsed->add(password.release());
	MyHGM->destroy_MyConn_from_pool(password_ptr);
	ok(MyHGM->queue.size() == 1 && server->ConnectionsUsed->conns_length() == 1,
		"ordinary password connection keeps the existing reset-queue behavior");
	if (MyHGM->queue.size() != 0) {
		MySQL_Connection *queued = MyHGM->queue.remove();
		queued->send_quit = false;
		MyHGM->destroy_MyConn_from_pool(queued);
	}
}

void test_destroy_path_dispatches_detached_iam_connection_kill() {
	MySrvC *server = create_server(820, "kill-dispatch-iam");
	server->use_ssl = 1;
	server->myhgc->attributes.aws_iam_region = make_owned_cstring("us-east-1").release();
	GloMTH->variables.connpoll_reset_queue_length = 50;
	mysql_thread___kill_backend_connection_when_disconnect = true;

	auto iam = create_established_connection(
		server, kUser, MySQLBackendAuthType::AWS_IAM);
	auto iam_ptr = iam.get();
	AwsIamTokenResult token;
	token.status = AwsIamStatus::OK;
	token.generation = 77;
	token.token = SecureString("ORIGINAL_IAM_HANDSHAKE_TOKEN");
	iam->attach_aws_iam_token(
		{ server->address, server->port, "us-east-1", kUser },
		std::move(token));
	iam->send_quit = true;
	iam->async_state_machine = ASYNC_QUERY_CONT;
	iam->mysql->thread_id = 741;
	iam->connected_host_details.ip = make_owned_cstring("198.51.100.28").release();
	server->ConnectionsUsed->add(iam.release());

	kill_source_connection = iam_ptr;
	kill_helper_dispatches = 0;
	kill_source_token_present_at_dispatch = false;
	kill_args_password_absent = false;
	kill_args_id = 0;
	kill_args_type = 0;
	kill_args_auth_type = MySQLBackendAuthType::PASSWORD;
	kill_args_endpoint.clear();
	kill_args_region.clear();
	kill_args_database_user.clear();
	kill_args_transport.clear();
	kill_args_port = 0;
	kill_args_use_ssl = 0;
	kill_args_deadline = {};
	const auto before = std::chrono::steady_clock::now();
	MyHGM->destroy_MyConn_from_pool(iam_ptr);
	const auto after = std::chrono::steady_clock::now();
	kill_source_connection = nullptr;
	mysql_thread___kill_backend_connection_when_disconnect = false;

	ok(kill_helper_dispatches == 1 && kill_source_token_present_at_dispatch &&
		kill_args_password_absent && kill_args_id == 741 &&
		kill_args_type == KILL_CONNECTION &&
		kill_args_auth_type == MySQLBackendAuthType::AWS_IAM &&
		kill_args_endpoint == "kill-dispatch-iam" &&
		kill_args_region == "us-east-1" && kill_args_database_user == kUser &&
		kill_args_transport == "198.51.100.28" && kill_args_port == 3306 &&
		kill_args_use_ssl == 1 &&
		kill_args_deadline > before && kill_args_deadline > after &&
		MyHGM->queue.size() == 0 &&
		server->ConnectionsUsed->conns_length() == 0,
		"production destroy dispatches an IAM KILL_CONNECTION helper without changing the source token or entering reset");
}

void test_reset_queue_worker_never_changes_iam() {
	MySrvC *server = create_server(808, "reset-worker-iam");
	auto iam = create_established_connection(
		server, kUser, MySQLBackendAuthType::AWS_IAM);
	iam->set_rowless_passthrough_authorized(true);
	auto iam_ptr = iam.get();
	server->ConnectionsUsed->add(iam.release());
	MyHGM->queue.add(iam_ptr);
	change_user_calls.store(0);
	std::thread reset_worker([]() { HGCU_thread_run(); });
	bool removed = false;
	for (unsigned int attempt = 0; attempt < 1000 && !removed; ++attempt) {
		MyHGM->wrlock();
		removed = server->ConnectionsUsed->conns_length() == 0;
		MyHGM->wrunlock();
		if (!removed) usleep(1000);
	}
	MyHGM->queue.add(nullptr);
	reset_worker.join();
	ok(MyHGM->queue.size() == 0 &&
		removed && server->ConnectionsUsed->conns_length() == 0 &&
		change_user_calls.load() == 0,
		"reset queue worker destroys IAM without invoking COM_CHANGE_USER");
}

void test_reset_queue_worker_never_resets_invalid_policy() {
	MySrvC *server = create_server(816, "reset-worker-invalid-policy");
	auto password = create_established_connection(
		server, kInvalidReloadUser, MySQLBackendAuthType::PASSWORD);
	password->set_rowless_passthrough_authorized(true);
	auto password_ptr = password.get();
	server->ConnectionsUsed->add(password.release());
	MyHGM->queue.add(password_ptr);
	const unsigned long resets_before = MyHGM->status.myconnpoll_reset;
	change_user_calls.store(0);
	std::thread reset_worker([]() { HGCU_thread_run(); });
	bool removed = false;
	for (unsigned int attempt = 0; attempt < 1000 && !removed; ++attempt) {
		MyHGM->wrlock();
		removed = server->ConnectionsUsed->conns_length() == 0;
		MyHGM->wrunlock();
		if (!removed) usleep(1000);
	}
	MyHGM->queue.add(nullptr);
	reset_worker.join();
	ok(removed && MyHGM->status.myconnpoll_reset == resets_before &&
		change_user_calls.load() == 0,
		"reset queue worker discards INVALID policy before reset processing");
}

void test_reset_queue_worker_preserves_authorized_rowless_passthrough() {
	MySrvC *server = create_server(818, "reset-worker-rowless-passthrough");
	auto password = create_established_connection(
		server, kRowlessPassthroughUser, MySQLBackendAuthType::PASSWORD);
	password->set_rowless_passthrough_authorized(true);
	password->mysql->net.pvio =
		reinterpret_cast<decltype(password->mysql->net.pvio)>(1);
	password->mysql->net.fd = 123;
	password->mysql->net.buff =
		reinterpret_cast<decltype(password->mysql->net.buff)>(1);
	auto password_ptr = password.get();
	server->ConnectionsUsed->add(password.release());
	MyHGM->queue.add(password_ptr);
	const unsigned long resets_before = MyHGM->status.myconnpoll_reset;
	change_user_calls.store(0);
	change_user_immediate_success.store(true);
	std::thread reset_worker([]() { HGCU_thread_run(); });
	for (unsigned int attempt = 0;
		attempt < 1000 && change_user_calls.load() == 0;
		++attempt) {
		usleep(1000);
	}
	MyHGM->queue.add(nullptr);
	reset_worker.join();
	change_user_immediate_success.store(false);
	const bool returned_to_pool =
		server->ConnectionsFree->conns_length() == 1 &&
		server->ConnectionsUsed->conns_length() == 0;
	ok(MyHGM->status.myconnpoll_reset == resets_before + 1 &&
		change_user_calls.load() == 1 && returned_to_pool,
		"reset worker preserves authorized rowless pass-through PASSWORD semantics");
	password_ptr->mysql->net.pvio = nullptr;
	password_ptr->mysql->net.fd = 0;
	password_ptr->mysql->net.buff = nullptr;
}

void test_reset_queue_worker_discards_unmarked_rowless_password() {
	MySrvC *server = create_server(819, "reset-worker-unmarked-rowless");
	auto password = create_established_connection(
		server, kRowlessPassthroughUser, MySQLBackendAuthType::PASSWORD);
	auto password_ptr = password.get();
	server->ConnectionsUsed->add(password.release());
	MyHGM->queue.add(password_ptr);
	const unsigned long resets_before = MyHGM->status.myconnpoll_reset;
	change_user_calls.store(0);
	std::thread reset_worker([]() { HGCU_thread_run(); });
	bool removed = false;
	for (unsigned int attempt = 0; attempt < 1000 && !removed; ++attempt) {
		MyHGM->wrlock();
		removed = server->ConnectionsUsed->conns_length() == 0;
		MyHGM->wrunlock();
		if (!removed) usleep(1000);
	}
	MyHGM->queue.add(nullptr);
	reset_worker.join();
	ok(removed && MyHGM->status.myconnpoll_reset == resets_before &&
		change_user_calls.load() == 0,
		"unmarked rowless PASSWORD cannot bypass reset policy validation");
}

void test_change_user_state_replaces_iam(MySQL_Thread& worker) {
	MySrvC *server = create_server(806, "change-user-iam");
	SessionFixture fixture(worker, 806, MySQLBackendAuthType::PASSWORD, kOtherUser);
	auto iam = create_established_connection(
		server, kUser, MySQLBackendAuthType::AWS_IAM);
	auto iam_ptr = iam.get();
	server->ConnectionsUsed->add(iam.release());
	fixture.attach_backend(iam_ptr);
	fixture.session->previous_status.push(WAITING_CLIENT_DATA);
	fixture.session->set_status(CHANGING_USER_SERVER);
	change_user_calls.store(0);
	fixture.session->to_process = 1;
	fixture.session->handler();
	ok(fixture.selected() != nullptr && fixture.selected()->fd == -1 &&
		fixture.selected()->backend_auth_type() == MySQLBackendAuthType::PASSWORD &&
		server->ConnectionsUsed->conns_length() == 1 &&
		change_user_calls.load() == 0,
		"CHANGING_USER_SERVER destroys IAM and returns through fresh acquisition");
}

void test_resetting_state_destroys_iam(MySQL_Thread& worker) {
	MySrvC *server = create_server(807, "resetting-iam");
	SessionFixture fixture(worker, 807, MySQLBackendAuthType::AWS_IAM);
	auto iam = create_established_connection(
		server, kUser, MySQLBackendAuthType::AWS_IAM);
	auto iam_ptr = iam.get();
	server->ConnectionsUsed->add(iam.release());
	fixture.attach_backend(iam_ptr);
	fixture.session->set_status(RESETTING_CONNECTION);
	change_user_calls.store(0);
	fixture.session->to_process = 1;
	const int rc = fixture.session->handler();
	ok(rc == -1 && fixture.selected() == nullptr &&
		change_user_calls.load() == 0 &&
		server->ConnectionsUsed->conns_length() == 0 &&
		server->ConnectionsFree->conns_length() == 0,
		"RESETTING_CONNECTION destroys IAM without invoking COM_CHANGE_USER");
}

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
	my_bool *ret, MYSQL *, const char *, const char *, const char *)
{
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
	plan(31);
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
		test_identity_matrix(worker);            // 7
		test_runtime_mode_changes_global(worker); // 2
		test_runtime_mode_change_local(worker);   // 1
		test_mixed_user_mode_global(worker);       // 4
		test_mixed_user_mode_local(worker);        // 4
		test_attached_password_reload_to_invalid_fails_closed(worker); // 1
		test_invalid_policy_cannot_continue_change_user(worker); // 1
		test_invalid_policy_cannot_enter_reset(worker); // 1
		test_authorized_rowless_passthrough_can_enter_detached_reset(worker); // 1
		test_destroy_path_never_queues_iam();     // 2
		test_destroy_path_dispatches_detached_iam_connection_kill(); // 1
		test_reset_queue_worker_never_changes_iam(); // 1
		test_reset_queue_worker_never_resets_invalid_policy(); // 1
		test_reset_queue_worker_preserves_authorized_rowless_passthrough(); // 1
		test_reset_queue_worker_discards_unmarked_rowless_password(); // 1
		test_change_user_state_replaces_iam(worker); // 1
		test_resetting_state_destroys_iam(worker);   // 1
	}

	GloMyLogger = previous_logger;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
#endif
}
