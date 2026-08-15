/**
 * @file aws_iam_failure_unit-t.cpp
 * @brief IAM-only backend authentication retry and redaction regressions.
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
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <unistd.h>

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
};

class ScopedPublishedTokenSource {
public:
	explicit ScopedPublishedTokenSource(AwsIamTokenSource *source) {
		publish_global_aws_iam_token_source(source);
	}
	~ScopedPublishedTokenSource() { publish_global_aws_iam_token_source(nullptr); }

	ScopedPublishedTokenSource(const ScopedPublishedTokenSource&) = delete;
	ScopedPublishedTokenSource& operator=(const ScopedPublishedTokenSource&) = delete;
};

bool add_backend_user(const char *username, const char *password,
	const char *attributes) {
	return GloMyAuth->add(
		(char *)username, (char *)password, USERNAME_BACKEND,
		false, 0, (char *)"", false, false, false, 100,
		(char *)attributes, (char *)"");
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

MySQL_Connection *established_iam_connection(int fd) {
	MySQL_Connection *connection = new MySQL_Connection();
	connection->mysql = mysql_init(nullptr);
	if (connection->mysql == nullptr) BAIL_OUT("mysql_init() failed for retry pool fixture");
	connection->ret_mysql = connection->mysql;
	connection->mysql->charset = mariadb_get_charset_by_name("utf8mb4");
	if (connection->mysql->charset == nullptr) BAIL_OUT("charset fixture failed");
	connection->parent = failure_server;
	connection->userinfo->set(
		const_cast<char *>(kIamUser), const_cast<char *>(""),
		const_cast<char *>("orders"), nullptr);
	connection->set_backend_auth_type(MySQLBackendAuthType::AWS_IAM);
	connection->healthy = true;
	connection->reusable = true;
	connection->send_quit = false;
	connection->fd = fd;
	connection->async_state_machine = ASYNC_IDLE;
	return connection;
}

void destroy_used(MySQL_Connection *connection) {
	if (connection == nullptr) return;
	connection->send_quit = false;
	MyHGM->destroy_MyConn_from_pool(connection);
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
	SessionFixture(MySQL_Thread& worker, const char *username) : worker_(worker) {
		session = new MySQL_Session();
		session->thread = &worker_;
		session->connections_handler = true;
		frontend_stream = new MySQL_Data_Stream();
		frontend_stream->init(MYDS_FRONTEND, session, -1);
		frontend = new MySQL_Connection();
		frontend_stream->attach_connection(frontend);
		frontend_stream->myprot.init(&frontend_stream, frontend->userinfo, session);
		session->client_myds = frontend_stream;
		frontend->userinfo->set(
			const_cast<char *>(username), const_cast<char *>("ordinary-password"),
			const_cast<char *>("orders"), nullptr);

		session->mybe = session->create_backend(kHostgroup);
		session->current_hostgroup = kHostgroup;
		session->default_hostgroup = kHostgroup;
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

std::string process_terminal_connect(SessionFixture& fixture) {
	return capture_stderr([&fixture] { fixture.run(); });
}

void test_first_1045_retries_once(MySQL_Thread& worker) {
	FakeTokenSource source;
	ScopedPublishedTokenSource published_source(&source);
	reset_connector({ { ER_ACCESS_DENIED_ERROR, kBackendText, false },
		{ ER_ACCESS_DENIED_ERROR, kBackendText, false } });
	SessionFixture fixture(worker, kIamUser);
	fixture.backend()->connect_retries_on_failure = 3;
	start_iam_attempt(fixture, worker);
	process_terminal_connect(fixture);

	ok(source.invalidated_generations.size() == 1 &&
		source.invalidated_generations[0] == 1 &&
		source.invalidated_keys[0] == source.keys[0],
		"the first IAM 1045 conditionally invalidates its exact key and generation");
	ok(source.keys.size() == 2 && fixture.session->status == WAITING_AWS_IAM_TOKEN,
		"the first IAM 1045 acquires exactly one fresh token");
	ok(fixture.backend() != nullptr &&
		fixture.backend()->connect_retries_on_failure == 0,
		"the IAM fresh-token retry disables the ordinary multi-server retry budget");

	if (source.keys.size() == 2 && fixture.session->status == WAITING_AWS_IAM_TOKEN) {
		worker.drain_aws_iam_completions();
		client_error_code = 0;
		client_error_state.clear();
		client_error_message.clear();
		const std::string log = capture_stderr([&fixture] { fixture.run(); });
		ok(source.keys.size() == 2 && source.invalidated_generations.size() == 1 &&
			fixture.session->status == WAITING_CLIENT_DATA,
			"a repeated fresh-token 1045 is terminal with no third attempt");
		ok(client_error_code == 9002 && client_error_state == "HY000" &&
			client_error_message == "Unable to connect to backend" &&
			client_error_message.find(kEndpoint) == std::string::npos &&
			client_error_message.find(kRegion) == std::string::npos &&
			client_error_message.find(kBackendText) == std::string::npos &&
			client_error_message.find(kTokenOne) == std::string::npos &&
			client_error_message.find(kTokenTwo) == std::string::npos &&
			client_error_message.find("AKIAFAKEACCESSKEY") == std::string::npos &&
			client_error_message.find("FAKE_SESSION_TOKEN") == std::string::npos,
			"the IAM client error is fixed and contains no backend, AWS, or token detail");
		ok(log.find("user='iam_failure_backend'") != std::string::npos &&
			log.find("hostgroup=909") != std::string::npos &&
			log.find(kEndpoint) != std::string::npos &&
			log.find("region='us-east-1'") != std::string::npos &&
			log.find("category='backend_auth_rejected'") != std::string::npos &&
			log.find("code=''") != std::string::npos &&
			log.find("request_id=''") != std::string::npos &&
			log.find("clock") != std::string::npos,
			"the repeated 1045 diagnostic is redacted and includes a clock-skew hint");
		ok(log.find(kBackendText) == std::string::npos &&
			log.find(kTokenOne) == std::string::npos &&
			log.find(kTokenTwo) == std::string::npos &&
			log.find("AKIAFAKEACCESSKEY") == std::string::npos &&
			log.find("FAKE_SESSION_TOKEN") == std::string::npos,
			"the operator diagnostic contains no credential or backend error text");
	} else {
		ok(false, "a repeated fresh-token 1045 is terminal with no third attempt");
		ok(false, "the IAM client error is fixed and contains no backend, AWS, or token detail");
		ok(false, "the repeated 1045 diagnostic is redacted and includes a clock-skew hint");
		ok(false, "the operator diagnostic contains no credential or backend error text");
	}
}

void test_stale_generation_cannot_evict_newer(MySQL_Thread& worker) {
	FakeTokenSource source;
	source.generations = { 41, 42 };
	ScopedPublishedTokenSource published_source(&source);
	reset_connector({ { ER_ACCESS_DENIED_ERROR, kBackendText, false } });
	SessionFixture fixture(worker, kIamUser);
	fixture.backend()->connect_retries_on_failure = 3;
	start_iam_attempt(fixture, worker);
	source.cached_key = source.keys[0];
	source.cached_generation = 42;
	process_terminal_connect(fixture);
	ok(source.invalidated_generations.size() == 1 &&
		source.invalidated_generations[0] == 41 && source.cached_generation == 42,
		"a delayed generation-N 1045 cannot evict the cached generation N+1");
}

void test_transport_failure_does_not_invalidate(MySQL_Thread& worker) {
	FakeTokenSource source;
	ScopedPublishedTokenSource published_source(&source);
	reset_connector({ { CR_SSL_CONNECTION_ERROR, "TLS transport failed", false } });
	SessionFixture fixture(worker, kIamUser);
	fixture.backend()->connect_retries_on_failure = 3;
	start_iam_attempt(fixture, worker);
	process_terminal_connect(fixture);
	ok(source.invalidated_generations.empty() && source.keys.size() == 1 &&
		fixture.session->status == WAITING_CLIENT_DATA,
		"an IAM TLS or transport failure is terminal without token invalidation or retry");
}

void test_password_1045_keeps_normal_retry(MySQL_Thread& worker) {
	FakeTokenSource source;
	ScopedPublishedTokenSource published_source(&source);
	reset_connector({ { ER_ACCESS_DENIED_ERROR, "ordinary password rejected", false },
		{ 0, "", true } });
	SessionFixture fixture(worker, kPasswordUser);
	fixture.backend()->connect_retries_on_failure = 1;
	fixture.run();
	if (fixture.backend() == nullptr) BAIL_OUT("password fixture did not acquire a backend");
	fixture.run();
	ok(source.keys.empty() && source.invalidated_generations.empty() &&
		connector_calls == 2 && fixture.backend()->connect_retries_on_failure == 0 &&
		fixture.session->status == CONNECTING_SERVER,
		"password-mode 1045 retains the existing ordinary connection retry behavior");
}

void test_fresh_retry_bypasses_local_and_global_idle_iam(MySQL_Thread& worker) {
	FakeTokenSource source;
	ScopedPublishedTokenSource published_source(&source);
	SessionFixture fixture(worker, kIamUser);
	MySQL_Connection *local = established_iam_connection(601);
	MySQL_Connection *global = established_iam_connection(602);
	failure_server->ConnectionsUsed->add(local);
	worker.push_MyConn_local(local);
	failure_server->ConnectionsFree->add(global);
	fixture.session->aws_iam_fresh_token_retry_attempted = true;
	fixture.session->previous_status.pop();
	fixture.session->previous_status.push(WAITING_CLIENT_DATA);

	fixture.frontend_stream->active = 0;
	fixture.backend()->active = 0;
	fixture.run();
	fixture.frontend_stream->active = 1;
	fixture.backend()->active = 1;
	MySQL_Connection *selected = fixture.backend()->myconn;
	ok(selected != nullptr && selected->fd == -1 &&
		local->myds == nullptr &&
		failure_server->ConnectionsFree->conns_length() == 1 &&
		source.keys.size() == 1 && fixture.session->status == WAITING_AWS_IAM_TOKEN,
		"an IAM fresh-token retry bypasses compatible local and global idle connections and starts a new handshake");

	if (fixture.backend()->myconn != nullptr) {
		fixture.backend()->destroy_MySQL_Connection_From_Pool(false);
	}
	local = worker.get_MyConn_local(
		kHostgroup, fixture.session, nullptr, 0, -1,
		MySQLBackendAuthType::AWS_IAM);
	destroy_used(local);
	global = MyHGM->get_MyConn_from_pool(
		kHostgroup, fixture.session, false, nullptr, 0, -1,
		MySQLBackendAuthType::AWS_IAM);
	destroy_used(global);
}

void test_pooled_success_clears_latch_for_later_1045(MySQL_Thread& worker) {
	FakeTokenSource source;
	ScopedPublishedTokenSource published_source(&source);
	reset_connector({ { ER_ACCESS_DENIED_ERROR, kBackendText, false } });
	SessionFixture fixture(worker, kIamUser);
	MySQL_Connection *pooled = established_iam_connection(603);
	failure_server->ConnectionsUsed->add(pooled);
	fixture.backend()->attach_connection(pooled);
	fixture.session->aws_iam_fresh_token_retry_attempted = true;
	fixture.session->previous_status.pop();
	fixture.session->previous_status.push(WAITING_CLIENT_DATA);
	fixture.frontend_stream->active = 0;
	fixture.backend()->active = 0;
	fixture.run();
	fixture.frontend_stream->active = 1;
	fixture.backend()->active = 1;
	fixture.backend()->destroy_MySQL_Connection_From_Pool(false);
	fixture.session->previous_status.push(PROCESSING_QUERY);
	fixture.session->set_status(CONNECTING_SERVER);
	start_iam_attempt(fixture, worker);
	process_terminal_connect(fixture);

	ok(source.invalidated_generations.size() == 1 &&
		source.invalidated_generations[0] == 1 && source.keys.size() == 2 &&
		fixture.session->aws_iam_fresh_token_retry_attempted &&
		fixture.session->status == WAITING_AWS_IAM_TOKEN,
		"a pooled IAM acquisition success clears the retry latch so a later independent 1045 gets one fresh attempt");
}

void test_missing_port_cannot_retry_or_invalidate(MySQL_Thread& worker) {
	FakeTokenSource source;
	ScopedPublishedTokenSource published_source(&source);
	reset_connector({ { ER_ACCESS_DENIED_ERROR, kBackendText, false } });
	SessionFixture fixture(worker, kIamUser);
	source.corrupt_port_on_failure = fixture.session;
	start_iam_attempt(fixture, worker);
	ok(source.invalidated_generations.empty() && source.keys.size() == 1 &&
		fixture.session->status == WAITING_CLIENT_DATA,
		"an IAM 1045 with a missing key port is terminal without invalidation or retry");
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
	plan(13);
	if (test_init_minimal() != 0 || test_init_auth() != 0 ||
		test_init_query_processor() != 0 || test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	GloMyLogger = new MySQL_Logger();
	if (!add_backend_user(kIamUser, "", "{\"backend_auth\":{\"type\":\"aws_iam\"}}") ||
		!add_backend_user(kPasswordUser, "ordinary-password", "")) {
		BAIL_OUT("failed to load backend user fixtures");
	}
	add_server();

	{
		MySQL_Thread worker;
		if (!worker.init()) BAIL_OUT("MySQL_Thread::init() failed");
		free(mysql_thread___ssl_p2s_ca);
		mysql_thread___ssl_p2s_ca = strdup("/unit/fake-ca.pem");
		worker.curtime = 10000000;
		test_first_1045_retries_once(worker);
		test_stale_generation_cannot_evict_newer(worker);
		test_transport_failure_does_not_invalidate(worker);
		test_password_1045_keeps_normal_retry(worker);
		test_fresh_retry_bypasses_local_and_global_idle_iam(worker);
		test_pooled_success_clears_latch_for_later_1045(worker);
		test_missing_port_cannot_retry_or_invalidate(worker);
	}
	GloAwsIamTokenSource = nullptr;

	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
