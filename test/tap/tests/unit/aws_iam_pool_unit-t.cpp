/**
 * @file aws_iam_pool_unit-t.cpp
 * @brief Pool-identity and reset-safety tests for MySQL AWS IAM backends.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_Data_Stream.h"
#include "MySQL_Logger.hpp"

#include <atomic>
#include <cstring>
#include <thread>

extern MySQL_HostGroups_Manager *MyHGM;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
extern MySQL_Authentication *GloMyAuth;
extern void *HGCU_thread_run();

namespace {

constexpr const char *kUser = "pool_user";
constexpr const char *kOtherUser = "other_pool_user";
constexpr const char *kInvalidReloadUser = "invalid_reload_pool_user";
constexpr const char *kSchema = "pool_schema";

std::atomic<unsigned int> change_user_calls { 0 };

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

MySQL_Connection *create_established_connection(
	MySrvC *server, const char *username, MySQLBackendAuthType type)
{
	MySQL_Connection *connection = new MySQL_Connection();
	connection->mysql = mysql_init(nullptr);
	if (connection->mysql == nullptr) {
		delete connection;
		BAIL_OUT("mysql_init() failed for pool fixture");
	}
	connection->ret_mysql = connection->mysql;
	connection->mysql->charset = mariadb_get_charset_by_name("utf8mb4");
	if (connection->mysql->charset == nullptr) {
		delete connection;
		BAIL_OUT("failed to initialize connector charset for pool fixture");
	}
	connection->parent = server;
	connection->userinfo->set(
		const_cast<char *>(username), const_cast<char *>("password"),
		const_cast<char *>(kSchema), nullptr);
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
		frontend->userinfo->set(
			const_cast<char *>(username), const_cast<char *>("password"),
			const_cast<char *>(kSchema), nullptr);
		frontend->set_backend_auth_type(requested_type);

		session->mybe = session->create_backend(hostgroup_id);
		session->current_hostgroup = hostgroup_id;
		session->default_hostgroup = hostgroup_id;
	}

	~SessionFixture() {
		delete session;
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
	MySQL_Session *session { nullptr };
	MySQL_Data_Stream *frontend_stream { nullptr };
	MySQL_Connection *frontend { nullptr };
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

	MySQL_Connection *password = create_established_connection(
		server, kUser, MySQLBackendAuthType::PASSWORD);
	MySQL_Connection *iam = create_established_connection(
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

	delete password;
	delete iam;
}

void test_runtime_mode_changes_global(MySQL_Thread& worker) {
	MySrvC *password_server = create_server(802, "password-to-iam");
	SessionFixture iam_request(worker, 802, MySQLBackendAuthType::AWS_IAM);
	MySQL_Connection *old_password = create_established_connection(
		password_server, kUser, MySQLBackendAuthType::PASSWORD);
	password_server->ConnectionsFree->add(old_password);
	MySQL_Connection *selected = MyHGM->get_MyConn_from_pool(
		802, iam_request.session, false, nullptr, 0, -1,
		MySQLBackendAuthType::AWS_IAM);
	ok(selected != nullptr && selected->fd == -1 &&
		password_server->ConnectionsFree->conns_length() == 0,
		"PASSWORD to IAM policy change lazily destroys the old global entry and creates fresh");
	destroy_used(selected);

	MySrvC *iam_server = create_server(803, "iam-to-password");
	SessionFixture password_request(worker, 803, MySQLBackendAuthType::PASSWORD);
	MySQL_Connection *old_iam = create_established_connection(
		iam_server, kUser, MySQLBackendAuthType::AWS_IAM);
	iam_server->ConnectionsFree->add(old_iam);
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
	MySQL_Connection *old_password = create_established_connection(
		server, kUser, MySQLBackendAuthType::PASSWORD);
	server->ConnectionsUsed->add(old_password);
	worker.push_MyConn_local(old_password);

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
	MySQL_Connection *unrelated_iam = create_established_connection(
		password_server, kOtherUser, MySQLBackendAuthType::AWS_IAM);
	unrelated_iam->fd = 201;
	MySQL_Connection *exact_password = create_established_connection(
		password_server, kUser, MySQLBackendAuthType::PASSWORD);
	exact_password->fd = 202;
	password_server->ConnectionsFree->add(unrelated_iam);
	password_server->ConnectionsFree->add(exact_password);
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
	MySQL_Connection *unrelated_password = create_established_connection(
		iam_server, kOtherUser, MySQLBackendAuthType::PASSWORD);
	unrelated_password->fd = 211;
	MySQL_Connection *exact_iam = create_established_connection(
		iam_server, kUser, MySQLBackendAuthType::AWS_IAM);
	exact_iam->fd = 212;
	iam_server->ConnectionsFree->add(unrelated_password);
	iam_server->ConnectionsFree->add(exact_iam);
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
	MySQL_Connection *unrelated_iam = create_established_connection(
		password_server, kOtherUser, MySQLBackendAuthType::AWS_IAM);
	unrelated_iam->fd = 301;
	MySQL_Connection *exact_password = create_established_connection(
		password_server, kUser, MySQLBackendAuthType::PASSWORD);
	exact_password->fd = 302;
	password_server->ConnectionsUsed->add(unrelated_iam);
	password_server->ConnectionsUsed->add(exact_password);
	worker.push_MyConn_local(unrelated_iam);
	worker.push_MyConn_local(exact_password);
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
	MySQL_Connection *unrelated_password = create_established_connection(
		iam_server, kOtherUser, MySQLBackendAuthType::PASSWORD);
	unrelated_password->fd = 311;
	MySQL_Connection *exact_iam = create_established_connection(
		iam_server, kUser, MySQLBackendAuthType::AWS_IAM);
	exact_iam->fd = 312;
	iam_server->ConnectionsUsed->add(unrelated_password);
	iam_server->ConnectionsUsed->add(exact_iam);
	worker.push_MyConn_local(unrelated_password);
	worker.push_MyConn_local(exact_iam);
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
	if (!GloMyAuth->add(
		const_cast<char *>(kInvalidReloadUser), const_cast<char *>("password"),
		USERNAME_BACKEND, false, 0, const_cast<char *>(""), false, false,
		false, 100, const_cast<char *>("{\"backend_auth\":{\"type\":17}}"),
		const_cast<char *>(""))) {
		BAIL_OUT("failed to load malformed backend policy fixture");
	}
}

void test_attached_password_reload_to_invalid_fails_closed(MySQL_Thread& worker) {
	MySrvC *server = create_server(813, "attached-invalid-policy");
	SessionFixture fixture(
		worker, 813, MySQLBackendAuthType::PASSWORD, kInvalidReloadUser);
	MySQL_Connection *password = create_established_connection(
		server, kInvalidReloadUser, MySQLBackendAuthType::PASSWORD);
	server->ConnectionsUsed->add(password);
	fixture.attach_backend(password);
	fixture.session->set_status(PROCESSING_QUERY);
	load_invalid_reload_policy();
	change_user_calls.store(0, std::memory_order_relaxed);
	fixture.session->to_process = 1;
	fixture.session->handler();
	ok(fixture.session->status == WAITING_CLIENT_DATA &&
		fixture.selected() == nullptr && fixture.session->previous_status.empty() &&
		server->ConnectionsUsed->conns_length() == 0 &&
		change_user_calls.load(std::memory_order_relaxed) == 0,
		"attached PASSWORD connection fails terminally when reload makes policy INVALID");
}

void test_invalid_policy_cannot_continue_change_user(MySQL_Thread& worker) {
	MySrvC *server = create_server(814, "changing-user-invalid-policy");
	SessionFixture fixture(
		worker, 814, MySQLBackendAuthType::PASSWORD, kInvalidReloadUser);
	MySQL_Connection *password = create_established_connection(
		server, kInvalidReloadUser, MySQLBackendAuthType::PASSWORD);
	server->ConnectionsUsed->add(password);
	fixture.attach_backend(password);
	fixture.session->previous_status.push(PROCESSING_QUERY);
	fixture.session->set_status(CHANGING_USER_SERVER);
	change_user_calls.store(0, std::memory_order_relaxed);
	fixture.session->to_process = 1;
	fixture.session->handler();
	ok(fixture.session->status == WAITING_CLIENT_DATA &&
		fixture.selected() == nullptr && fixture.session->previous_status.empty() &&
		server->ConnectionsUsed->conns_length() == 0 &&
		change_user_calls.load(std::memory_order_relaxed) == 0,
		"INVALID policy discovered in CHANGING_USER_SERVER cannot send a password");
}

void test_invalid_policy_cannot_enter_reset(MySQL_Thread& worker) {
	MySrvC *server = create_server(815, "reset-invalid-policy");
	SessionFixture fixture(
		worker, 815, MySQLBackendAuthType::PASSWORD, kInvalidReloadUser);
	MySQL_Connection *password = create_established_connection(
		server, kInvalidReloadUser, MySQLBackendAuthType::PASSWORD);
	server->ConnectionsUsed->add(password);
	fixture.attach_backend(password);
	fixture.session->set_status(RESETTING_CONNECTION);
	change_user_calls.store(0, std::memory_order_relaxed);
	fixture.session->to_process = 1;
	const int rc = fixture.session->handler();
	ok(rc == -1 && fixture.session->status == session_status___NONE &&
		fixture.selected() == nullptr &&
		server->ConnectionsUsed->conns_length() == 0 &&
		change_user_calls.load(std::memory_order_relaxed) == 0,
		"INVALID backend policy destroys reset work without COM_CHANGE_USER");
}

void test_destroy_path_never_queues_iam() {
	MySrvC *server = create_server(805, "destroy-iam");
	GloMTH->variables.connpoll_reset_queue_length = 50;
	MySQL_Connection *iam = create_established_connection(
		server, kUser, MySQLBackendAuthType::AWS_IAM);
	iam->send_quit = true;
	server->ConnectionsUsed->add(iam);
	MyHGM->destroy_MyConn_from_pool(iam);
	ok(MyHGM->queue.size() == 0 && server->ConnectionsUsed->conns_length() == 0,
		"destroy_MyConn_from_pool deletes IAM instead of queueing COM_CHANGE_USER reset");

	MySQL_Connection *password = create_established_connection(
		server, kUser, MySQLBackendAuthType::PASSWORD);
	password->send_quit = true;
	server->ConnectionsUsed->add(password);
	MyHGM->destroy_MyConn_from_pool(password);
	ok(MyHGM->queue.size() == 1 && server->ConnectionsUsed->conns_length() == 1,
		"ordinary password connection keeps the existing reset-queue behavior");
	if (MyHGM->queue.size() != 0) {
		MySQL_Connection *queued = MyHGM->queue.remove();
		queued->send_quit = false;
		MyHGM->destroy_MyConn_from_pool(queued);
	}
}

void test_reset_queue_worker_never_changes_iam() {
	MySrvC *server = create_server(808, "reset-worker-iam");
	MySQL_Connection *iam = create_established_connection(
		server, kUser, MySQLBackendAuthType::AWS_IAM);
	server->ConnectionsUsed->add(iam);
	MyHGM->queue.add(iam);
	change_user_calls.store(0, std::memory_order_relaxed);
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
		change_user_calls.load(std::memory_order_relaxed) == 0,
		"reset queue worker destroys IAM without invoking COM_CHANGE_USER");
}

void test_reset_queue_worker_never_resets_invalid_policy() {
	MySrvC *server = create_server(816, "reset-worker-invalid-policy");
	MySQL_Connection *password = create_established_connection(
		server, kInvalidReloadUser, MySQLBackendAuthType::PASSWORD);
	server->ConnectionsUsed->add(password);
	MyHGM->queue.add(password);
	const unsigned long resets_before = MyHGM->status.myconnpoll_reset;
	change_user_calls.store(0, std::memory_order_relaxed);
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
		change_user_calls.load(std::memory_order_relaxed) == 0,
		"reset queue worker discards INVALID policy before reset processing");
}

void test_change_user_state_replaces_iam(MySQL_Thread& worker) {
	MySrvC *server = create_server(806, "change-user-iam");
	SessionFixture fixture(worker, 806, MySQLBackendAuthType::PASSWORD, kOtherUser);
	MySQL_Connection *iam = create_established_connection(
		server, kUser, MySQLBackendAuthType::AWS_IAM);
	server->ConnectionsUsed->add(iam);
	fixture.attach_backend(iam);
	fixture.session->previous_status.push(WAITING_CLIENT_DATA);
	fixture.session->set_status(CHANGING_USER_SERVER);
	change_user_calls.store(0, std::memory_order_relaxed);
	fixture.session->to_process = 1;
	fixture.session->handler();
	ok(fixture.selected() != nullptr && fixture.selected()->fd == -1 &&
		fixture.selected()->backend_auth_type() == MySQLBackendAuthType::PASSWORD &&
		server->ConnectionsUsed->conns_length() == 1 &&
		change_user_calls.load(std::memory_order_relaxed) == 0,
		"CHANGING_USER_SERVER destroys IAM and returns through fresh acquisition");
}

void test_resetting_state_destroys_iam(MySQL_Thread& worker) {
	MySrvC *server = create_server(807, "resetting-iam");
	SessionFixture fixture(worker, 807, MySQLBackendAuthType::AWS_IAM);
	MySQL_Connection *iam = create_established_connection(
		server, kUser, MySQLBackendAuthType::AWS_IAM);
	server->ConnectionsUsed->add(iam);
	fixture.attach_backend(iam);
	fixture.session->set_status(RESETTING_CONNECTION);
	change_user_calls.store(0, std::memory_order_relaxed);
	fixture.session->to_process = 1;
	const int rc = fixture.session->handler();
	ok(rc == -1 && fixture.selected() == nullptr &&
		change_user_calls.load(std::memory_order_relaxed) == 0 &&
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

int __wrap_mysql_change_user_start(
	my_bool *ret, MYSQL *, const char *, const char *, const char *)
{
	change_user_calls.fetch_add(1, std::memory_order_relaxed);
	*ret = 0;
	return MYSQL_WAIT_READ;
}

int __wrap_mysql_real_connect_start(MYSQL **ret, MYSQL *, const char *,
	const char *, const char *, const char *, unsigned int, const char *,
	unsigned long)
{
	*ret = nullptr;
	return MYSQL_WAIT_READ;
}

} // extern "C"
#endif

int main() {
#ifndef __linux__
	plan(1);
	skip(1, "requires GNU ld --wrap support");
	return exit_status();
#else
	plan(27);
	if (test_init_minimal() != 0 || test_init_auth() != 0 ||
		test_init_query_processor() != 0 ||
		test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	GloMyLogger = new MySQL_Logger();
	if (!GloMyAuth->add(
		const_cast<char *>(kUser), const_cast<char *>("password"), USERNAME_BACKEND,
		false, 0, const_cast<char *>(""), false, false, false, 100,
		const_cast<char *>(""), const_cast<char *>("")) ||
		!GloMyAuth->add(
			const_cast<char *>(kOtherUser), const_cast<char *>("password"), USERNAME_BACKEND,
			false, 0, const_cast<char *>(""), false, false, false, 100,
			const_cast<char *>(""), const_cast<char *>("")) ||
		!GloMyAuth->add(
			const_cast<char *>(kInvalidReloadUser), const_cast<char *>("password"), USERNAME_BACKEND,
			false, 0, const_cast<char *>(""), false, false, false, 100,
			const_cast<char *>(""), const_cast<char *>(""))) {
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
		test_destroy_path_never_queues_iam();     // 2
		test_reset_queue_worker_never_changes_iam(); // 1
		test_reset_queue_worker_never_resets_invalid_policy(); // 1
		test_change_user_state_replaces_iam(worker); // 1
		test_resetting_state_destroys_iam(worker);   // 1
	}

	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
#endif
}
