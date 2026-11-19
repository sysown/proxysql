/**
 * @file azure_entra_session_unit-t.cpp
 * @brief Azure Entra sessions: token slot, fail-closed, 1045 and reset rules (#6649).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "Aws_Iam_Provider.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_Data_Stream.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Logger.hpp"
#include "mysqld_error.h"
#include "errmsg.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <condition_variable>
#include <dlfcn.h>
#include <future>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <unistd.h>

using namespace std::chrono_literals;

extern MySQL_Authentication *GloMyAuth;
extern MySQL_HostGroups_Manager *MyHGM;
extern MySQL_Logger *GloMyLogger;

namespace {

constexpr int kHostgroup = 909;
constexpr const char *kEndpoint =
	"failure.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com";
constexpr const char *kRegion = "us-east-1";
constexpr const char *kIamUser = "iam_failure_backend";
constexpr const char *kPasswordUser = "password_failure_backend";
constexpr const char *kTokenOne = "FAKE_IAM_TOKEN_GENERATION_ONE";
constexpr const char *kTokenTwo = "FAKE_IAM_TOKEN_GENERATION_TWO";
constexpr const char *kBackendText =
	"backend reflected AKIAFAKEACCESSKEY and FAKE_SESSION_TOKEN";
MySrvC *failure_server = nullptr;
std::atomic<bool> blocking_source_destroyed { false };
// #6649: an Azure Entra user on an Azure host, in its own hostgroup.
constexpr int kEntraHostgroup = 910;
constexpr const char *kEntraEndpoint = "failure-entra.mysql.database.azure.com";
constexpr const char *kEntraUser = "entra_failure_backend";
MySrvC *entra_server = nullptr;

struct ConnectOutcome {
	unsigned int error;
	const char *message;
	bool pending;
};

std::vector<ConnectOutcome> connect_outcomes;
size_t connect_outcome_index = 0;
unsigned int connector_calls = 0;
uint16_t client_error_code = 0;
std::string client_error_state;
std::string client_error_message;

AwsIamTokenResult token_result(uint64_t generation, const char *token) {
	AwsIamTokenResult result;
	result.status = AwsIamStatus::OK;
	result.generation = generation;
	result.token = SecureString(token);
	return result;
}

class FakeTokenSource final : public AwsIamTokenSource {
public:
	AwsIamRequestHandle request(const AwsIamTokenKey& key, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink> sink) override {
		keys.push_back(key);
		const size_t index = keys.size() - 1;
		AwsIamCompletion completion;
		completion.opaque_id = opaque_id;
		completion.result = token_result(
			index < generations.size() ? generations[index] : generations.back(),
			index == 0 ? kTokenOne : kTokenTwo);
		if (auto target = sink.lock()) target->post(std::move(completion));
		return { next_handle++ };
	}

	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point) override {
		return {};
	}

	void cancel(AwsIamRequestHandle) override {}

	void invalidate(const AwsIamTokenKey& key, uint64_t generation) override {
		if (block_invalidation) {
			std::unique_lock<std::mutex> lock(invalidation_mutex);
			invalidation_entered = true;
			invalidation_cv.notify_all();
			invalidation_cv.wait(lock, [this] { return shutdown_started; });
			const bool shutdown_returned = invalidation_cv.wait_for(lock, 20ms,
				[this] { return shutdown_completed; });
			retirement_waited_for_invalidation = !shutdown_returned &&
				!blocking_source_destroyed.load(std::memory_order_acquire);
		}
		invalidated_keys.push_back(key);
		invalidated_generations.push_back(generation);
		if (cached_key == key && cached_generation == generation) {
			cached_generation = 0;
		}
	}

	void record_backend_connection(bool success) override {
		if (success) ++backend_successes;
		else {
			++backend_failures;
			if (corrupt_port_on_failure != nullptr) {
				corrupt_port_on_failure->aws_iam_connect_token_key.port = 0;
			}
		}
	}
	void record_waiting_session(bool waiting) override {
		if (waiting) ++waiting_sessions;
		else if (waiting_sessions != 0) --waiting_sessions;
	}

	AwsIamStatsSnapshot snapshot() const override {
		AwsIamStatsSnapshot result;
		result.waiting_sessions = waiting_sessions;
		return result;
	}

	bool wait_for_invalidation() {
		std::unique_lock<std::mutex> lock(invalidation_mutex);
		return invalidation_cv.wait_for(lock, 1s,
			[this] { return invalidation_entered; });
	}

	void mark_shutdown_completed() {
		std::lock_guard<std::mutex> lock(invalidation_mutex);
		shutdown_completed = true;
		invalidation_cv.notify_all();
	}

	void mark_shutdown_started() {
		std::lock_guard<std::mutex> lock(invalidation_mutex);
		shutdown_started = true;
		invalidation_cv.notify_all();
	}

	std::vector<uint64_t> generations { 1, 2 };
	uint64_t next_handle { 1 };
	std::vector<AwsIamTokenKey> keys;
	std::vector<AwsIamTokenKey> invalidated_keys;
	std::vector<uint64_t> invalidated_generations;
	AwsIamTokenKey cached_key;
	uint64_t cached_generation { 0 };
	unsigned int backend_successes { 0 };
	unsigned int backend_failures { 0 };
	uint64_t waiting_sessions { 0 };
	MySQL_Session *corrupt_port_on_failure { nullptr };
	bool block_invalidation { false };
	std::mutex invalidation_mutex;
	std::condition_variable invalidation_cv;
	bool invalidation_entered { false };
	bool shutdown_started { false };
	bool shutdown_completed { false };
	bool retirement_waited_for_invalidation { false };
};

class ScopedPublishedTokenSource {
public:
	explicit ScopedPublishedTokenSource(AwsIamTokenSource *source,
		BackendTokenProvider provider = BackendTokenProvider::AWS_IAM) : provider_(provider) {
		publish_global_backend_token_source(provider_, source);
	}
	~ScopedPublishedTokenSource() { publish_global_backend_token_source(provider_, nullptr); }
	BackendTokenProvider provider_;

	ScopedPublishedTokenSource(const ScopedPublishedTokenSource&) = delete;
	ScopedPublishedTokenSource& operator=(const ScopedPublishedTokenSource&) = delete;
};

bool add_backend_user(const char *username, const char *password,
	const char *attributes) {
	std::string username_mut(username);
	std::string password_mut(password);
	std::string region_mut("");
	std::string attributes_mut(attributes);
	std::string extra_attrs_mut("");
	return GloMyAuth->add(
		&username_mut[0], &password_mut[0], USERNAME_BACKEND,
		false, 0, &region_mut[0], false, false, false, 100,
		&attributes_mut[0], &extra_attrs_mut[0]);
}

void add_server() {
	srv_info_t info;
	info.addr = kEndpoint;
	info.port = 3306;
	info.kind = "aws-iam-failure-unit";
	srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 100;
	opts.use_ssl = 1;
	MyHGM->wrlock();
	const int rc = MyHGM->create_new_server_in_hg(kHostgroup, info, opts);
	MyHGC *hostgroup = MyHGM->MyHGC_find(kHostgroup);
	MyHGM->wrunlock();
	if (rc != 0 || hostgroup == nullptr) BAIL_OUT("failed to create failure fixture");
	free(hostgroup->attributes.aws_iam_region);
	hostgroup->attributes.aws_iam_region = strdup(kRegion);
	failure_server = hostgroup->mysrvs->idx(0);
}

void add_entra_server() {
	srv_info_t info;
	info.addr = kEntraEndpoint;
	info.port = 3306;
	info.kind = "azure-entra-failure-unit";
	srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 100;
	opts.use_ssl = 1;
	MyHGM->wrlock();
	const int rc = MyHGM->create_new_server_in_hg(kEntraHostgroup, info, opts);
	MyHGC *hostgroup = MyHGM->MyHGC_find(kEntraHostgroup);
	MyHGM->wrunlock();
	if (rc != 0 || hostgroup == nullptr) BAIL_OUT("failed to create Entra failure fixture");
	entra_server = hostgroup->mysrvs->idx(0);
}

MySQL_Connection *established_connection(MySrvC *server, const char *user,
	MySQLBackendAuthType type, int fd) {
	MySQL_Connection *connection = new MySQL_Connection();
	connection->mysql = mysql_init(nullptr);
	if (connection->mysql == nullptr) BAIL_OUT("mysql_init() failed for Entra fixture");
	connection->ret_mysql = connection->mysql;
	connection->mysql->charset = mariadb_get_charset_by_name("utf8mb4");
	connection->parent = server;
	std::string username = user;
	char password[] = "ordinary-password";
	std::string schema = "orders";
	connection->userinfo->set(&username[0], password, &schema[0], nullptr);
	connection->set_backend_auth_type(type);
	connection->healthy = true;
	connection->reusable = true;
	connection->send_quit = false;
	connection->fd = fd;
	connection->async_state_machine = ASYNC_IDLE;
	return connection;
}

std::string capture_stderr(const std::function<void()>& action) {
	FILE *captured = tmpfile();
	if (captured == nullptr) BAIL_OUT("tmpfile() failed");
	fflush(stderr);
	const int saved = dup(STDERR_FILENO);
	if (saved < 0 || dup2(fileno(captured), STDERR_FILENO) < 0) {
		BAIL_OUT("stderr redirect failed");
	}
	action();
	fflush(stderr);
	dup2(saved, STDERR_FILENO);
	close(saved);
	std::string output;
	char buffer[256];
	rewind(captured);
	while (fgets(buffer, sizeof(buffer), captured) != nullptr) output += buffer;
	fclose(captured);
	return output;
}

class SessionFixture {
public:
	SessionFixture(MySQL_Thread& worker, const char *username, int hostgroup = kHostgroup)
		: worker_(worker) {
		session = new MySQL_Session();
		session->thread = &worker_;
		session->connections_handler = true;
		frontend_stream = new MySQL_Data_Stream();
		frontend_stream->init(MYDS_FRONTEND, session, -1);
		frontend = new MySQL_Connection();
		frontend_stream->attach_connection(frontend);
		frontend_stream->myprot.init(&frontend_stream, frontend->userinfo, session);
		session->client_myds = frontend_stream;
		std::string frontend_user = username;
		std::string frontend_password = "ordinary-password";
		std::string frontend_schema = "orders";
		frontend->userinfo->set(
			&frontend_user[0], &frontend_password[0], &frontend_schema[0], nullptr);

		session->mybe = session->create_backend(hostgroup);
		session->current_hostgroup = hostgroup;
		session->default_hostgroup = hostgroup;
		session->CurrentQuery.start_time = worker_.curtime;
		session->previous_status.push(PROCESSING_QUERY);
		session->set_status(CONNECTING_SERVER);
	}

	~SessionFixture() { delete session; }

	int run() {
		session->to_process = 1;
		return session->handler();
	}

	MySQL_Data_Stream *backend() const {
		return session != nullptr && session->mybe != nullptr
			? session->mybe->server_myds : nullptr;
	}

	MySQL_Thread& worker_;
	MySQL_Session *session { nullptr };
	MySQL_Data_Stream *frontend_stream { nullptr };
	MySQL_Connection *frontend { nullptr };
};

void reset_connector(std::initializer_list<ConnectOutcome> outcomes) {
	connect_outcomes.assign(outcomes);
	connect_outcome_index = 0;
	connector_calls = 0;
}

void start_iam_attempt(SessionFixture& fixture, MySQL_Thread& worker) {
	fixture.run();
	worker.drain_aws_iam_completions();
	fixture.run();
}









// ---- #6649: sessions route azure_entra to the Azure slot -------------------

void test_entra_session_uses_azure_slot(MySQL_Thread& worker) {
	FakeTokenSource aws, azure;
	ScopedPublishedTokenSource published_aws(&aws);
	ScopedPublishedTokenSource published_azure(&azure, BackendTokenProvider::AZURE_ENTRA);
	reset_connector({});
	SessionFixture fixture(worker, kEntraUser, kEntraHostgroup);
	fixture.run();
	const AwsIamTokenKey expected { kEntraEndpoint, 3306, "", kEntraUser };
	ok(fixture.session->status == WAITING_AWS_IAM_TOKEN && aws.keys.empty() &&
		azure.keys.size() == 1 && azure.keys[0] == expected && connector_calls == 0,
		"entra_session_uses_azure_slot: an Entra session waits on the Azure slot only");
	worker.drain_aws_iam_completions();
}

void test_entra_no_source_fails_closed(MySQL_Thread& worker) {
	FakeTokenSource aws;
	ScopedPublishedTokenSource published_aws(&aws);
	reset_connector({});
	client_error_code = 0;
	SessionFixture fixture(worker, kEntraUser, kEntraHostgroup);
	const std::string log = capture_stderr([&fixture] { fixture.run(); });
	ok(fixture.session->status == WAITING_CLIENT_DATA && connector_calls == 0 &&
		aws.keys.empty() && client_error_code == 9002 &&
		log.find("Azure Entra backend token failure") != std::string::npos &&
		log.find("category='token_source_unavailable'") != std::string::npos,
		"entra_no_source_fails_closed: no Azure source means ERR 9002 and no connect attempt");
}

void test_entra_1045_invalidates_once(MySQL_Thread& worker) {
	FakeTokenSource azure;
	ScopedPublishedTokenSource published_azure(&azure, BackendTokenProvider::AZURE_ENTRA);
	reset_connector({ { ER_ACCESS_DENIED_ERROR, kBackendText, false },
		{ ER_ACCESS_DENIED_ERROR, kBackendText, false } });
	client_error_code = 0;
	SessionFixture fixture(worker, kEntraUser, kEntraHostgroup);
	fixture.backend()->connect_retries_on_failure = 3;
	const std::string log = capture_stderr([&] { start_iam_attempt(fixture, worker); fixture.run(); });
	const size_t first = log.find("category='backend_auth_rejected'");
	ok(azure.keys.size() == 1 && azure.invalidated_generations.size() == 1 && connector_calls == 1 &&
		fixture.session->status == WAITING_CLIENT_DATA && client_error_code == 9002 &&
		log.find("Azure Entra backend connection failure") != std::string::npos &&
		first != std::string::npos &&
		log.find("category='backend_auth_rejected'", first + 1) == std::string::npos &&
		log.find("clock") == std::string::npos,
		"entra_1045_no_retry: one invalidate (starts a refresh), no retry with the same token, one terminal backend_auth_rejected");
}

void test_entra_retry_flag_reset_on_success(MySQL_Thread& worker) {
	FakeTokenSource azure;
	ScopedPublishedTokenSource published_azure(&azure, BackendTokenProvider::AZURE_ENTRA);
	SessionFixture fixture(worker, kEntraUser, kEntraHostgroup);
	MySQL_Connection *pooled = established_connection(
		entra_server, kEntraUser, MySQLBackendAuthType::AZURE_ENTRA, 604);
	entra_server->ConnectionsUsed->add(pooled);
	fixture.backend()->attach_connection(pooled);
	fixture.session->aws_iam_fresh_token_retry_attempted = true;
	fixture.session->previous_status.pop();
	fixture.session->previous_status.push(WAITING_CLIENT_DATA);
	fixture.frontend_stream->active = 0;
	fixture.backend()->active = 0;
	fixture.run();
	fixture.frontend_stream->active = 1;
	fixture.backend()->active = 1;
	ok(!fixture.session->aws_iam_fresh_token_retry_attempted,
		"entra_retry_flag_reset_on_success: a successful Entra acquisition clears the retry latch");
	fixture.backend()->destroy_MySQL_Connection_From_Pool(false);
}

void test_entra_change_user_destroys(MySQL_Thread& worker) {
	FakeTokenSource azure;
	ScopedPublishedTokenSource published_azure(&azure, BackendTokenProvider::AZURE_ENTRA);
	SessionFixture fixture(worker, kEntraUser, kEntraHostgroup);
	MySQL_Connection *pooled = established_connection(
		entra_server, kPasswordUser, MySQLBackendAuthType::PASSWORD, 605);
	entra_server->ConnectionsUsed->add(pooled);
	fixture.backend()->attach_connection(pooled);
	fixture.session->set_status(CHANGING_USER_SERVER);
	fixture.run();
	ok(fixture.backend()->myconn != pooled &&
		entra_server->ConnectionsUsed->conns_length() <= 1 && azure.keys.size() == 1,
		"entra_change_user_destroys: a password connection is replaced, never COM_CHANGE_USER'd to an Entra user");
	worker.drain_aws_iam_completions();
}

void test_entra_reset_destroys(MySQL_Thread& worker) {
	SessionFixture fixture(worker, kEntraUser, kEntraHostgroup);
	MySQL_Connection *entra = established_connection(
		entra_server, kEntraUser, MySQLBackendAuthType::AZURE_ENTRA, 606);
	entra_server->ConnectionsUsed->add(entra);
	fixture.backend()->attach_connection(entra);
	const unsigned int sessions_before = worker.mysql_sessions->len;
	fixture.session->create_new_session_and_reset_connection(fixture.backend());
	ok(worker.mysql_sessions->len == sessions_before && fixture.backend()->myconn == nullptr,
		"entra_reset_destroys: an Entra connection is destroyed, no reset session is created");
}

void test_entra_connect_failure_log(MySQL_Thread& worker) {
	SessionFixture fixture(worker, kEntraUser, kEntraHostgroup);
	MySQL_Connection *entra = established_connection(
		entra_server, kEntraUser, MySQLBackendAuthType::AZURE_ENTRA, 607);
	entra_server->ConnectionsUsed->add(entra);
	fixture.backend()->attach_connection(entra);
	entra->mysql->net.last_errno = 1226;
	entra->ret_mysql = nullptr;
	entra->async_state_machine = ASYNC_CONNECT_END;
	const std::string log = capture_stderr([entra] { entra->handler(0); });
	ok(log.find("Failed to connect Azure Entra backend") != std::string::npos &&
		log.find("IAM backend") == std::string::npos,
		"entra_connect_failure_log: the failed-connect line names Azure Entra, not IAM");
}

} // namespace

extern "C" {

bool __real__ZN14MySQL_Protocol16generate_pkt_ERREbPPvPjhtPKcS4_b(
	MySQL_Protocol *, bool, void **, unsigned int *, uint8_t, uint16_t,
	const char *, const char *, bool);

bool __wrap__ZN14MySQL_Protocol16generate_pkt_ERREbPPvPjhtPKcS4_b(
	MySQL_Protocol *protocol, bool send, void **ptr, unsigned int *len,
	uint8_t sequence_id, uint16_t error_code, const char *sql_state,
	const char *sql_message, bool track) {
	client_error_code = error_code;
	client_error_state = sql_state != nullptr ? sql_state : "";
	client_error_message = sql_message != nullptr ? sql_message : "";
	return __real__ZN14MySQL_Protocol16generate_pkt_ERREbPPvPjhtPKcS4_b(
		protocol, send, ptr, len, sequence_id, error_code, sql_state,
		sql_message, track);
}

int __wrap_mysql_real_connect_start(MYSQL **ret, MYSQL *mysql, const char *host,
	const char *, const char *password, const char *, unsigned int port,
	const char *, unsigned long) {
	++connector_calls;
	const ConnectOutcome outcome = connect_outcome_index < connect_outcomes.size()
		? connect_outcomes[connect_outcome_index++]
		: ConnectOutcome { CR_CONNECTION_ERROR, "unexpected connector call", false };
	mysql->host = strdup(host != nullptr ? host : "");
	mysql->passwd = strdup(password != nullptr ? password : "");
	mysql->port = port;
	mysql->net.last_errno = outcome.error;
	std::snprintf(mysql->net.last_error, sizeof(mysql->net.last_error), "%s",
		outcome.message != nullptr ? outcome.message : "");
	std::snprintf(mysql->net.sqlstate, sizeof(mysql->net.sqlstate), "%s",
		outcome.error == ER_ACCESS_DENIED_ERROR ? "28000" : "HY000");
	*ret = nullptr;
	return outcome.pending ? MYSQL_WAIT_READ : 0;
}

} // extern "C"

int main() {
	plan(7);
	if (test_init_minimal() != 0 || test_init_auth() != 0 ||
		test_init_query_processor() != 0 || test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	std::unique_ptr<MySQL_Logger> owned_logger(std::make_unique<MySQL_Logger>());
	MySQL_Logger *previous_logger = GloMyLogger;
	GloMyLogger = owned_logger.get();
	if (!add_backend_user(kIamUser, "", "{\"backend_auth\":{\"type\":\"aws_iam\"}}") ||
		!add_backend_user(kPasswordUser, "ordinary-password", "") ||
		!add_backend_user(kEntraUser, "", "{\"backend_auth\":{\"type\":\"azure_entra\"}}")) {
		BAIL_OUT("failed to load backend user fixtures");
	}
	add_server();
	add_entra_server();

	{
		MySQL_Thread worker;
		if (!worker.init()) BAIL_OUT("MySQL_Thread::init() failed");
		// Sessions read aws_iam_region from the worker's copy of the hostgroup
		// strings, refreshed when the servers table version changes.
		MyHGM->status.servers_table_version++;
		worker.refresh_hostgroup_strings(MyHGM);
		free(mysql_thread___ssl_p2s_ca);
		mysql_thread___ssl_p2s_ca = strdup("/unit/fake-ca.pem");
		worker.curtime = 10000000;
		test_entra_session_uses_azure_slot(worker);
		test_entra_no_source_fails_closed(worker);
		test_entra_1045_invalidates_once(worker);
		test_entra_retry_flag_reset_on_success(worker);
		test_entra_change_user_destroys(worker);
		test_entra_reset_destroys(worker);
		test_entra_connect_failure_log(worker);
	}
	GloAwsIamTokenSource = nullptr;

	GloMyLogger = previous_logger;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
