/**
 * @file aws_iam_session_state_unit-t.cpp
 * @brief State-machine tests for asynchronous backend IAM token acquisition.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "Aws_Iam_Sdk.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_Data_Stream.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Logger.hpp"

#include <openssl/crypto.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <unistd.h>

extern MySQL_Authentication *GloMyAuth;
extern MySQL_HostGroups_Manager *MyHGM;
extern MySQL_Logger *GloMyLogger;

namespace {

constexpr int kHostgroup = 707;
constexpr const char *kEndpointA = "orders.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com";
constexpr const char *kEndpointB = "orders-ro.cluster-ro-abcdefghijkl.us-east-1.rds.amazonaws.com";
constexpr const char *kRegion = "us-east-1";
constexpr const char *kIamUser = "iam_backend";
constexpr const char *kPasswordUser = "password_backend";
constexpr const char *kUnknownPassthroughUser = "passthrough_unknown_backend";
constexpr const char *kMalformedPassthroughUser = "passthrough_malformed_backend";
constexpr const char *kSensitiveToken = "FAKE_AWS_SESSION_TOKEN_MUST_NOT_ESCAPE";

std::atomic<unsigned int> token_cleanse_calls { 0 };
std::atomic<unsigned int> connector_calls { 0 };

void tracked_cleanse(void *ptr, size_t size) {
	OPENSSL_cleanse(ptr, size);
	token_cleanse_calls.fetch_add(1, std::memory_order_relaxed);
}

AwsIamTokenResult result(AwsIamStatus status, bool include_token = false) {
	AwsIamTokenResult value;
	value.status = status;
	if (include_token) {
		value.token = SecureString(kSensitiveToken, tracked_cleanse);
	}
	if (status != AwsIamStatus::OK) {
		value.failure.category = "credential_provider";
		value.failure.aws_error_code = "NoCredentials";
		value.failure.request_id = "request-123";
	}
	return value;
}

class FakeTokenSource final : public AwsIamTokenSource {
public:
	enum class Mode { DELAYED, IMMEDIATE_OK, IMMEDIATE_QUEUE_FULL };

	explicit FakeTokenSource(Mode mode = Mode::DELAYED) : mode_(mode) {}

	AwsIamRequestHandle request(const AwsIamTokenKey& key, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink> sink) override {
		keys.push_back(key);
		opaque_ids.push_back(opaque_id);
		sinks.push_back(sink);
		AwsIamRequestHandle handle { next_handle++ };
		handles.push_back(handle);
		if (mode_ == Mode::IMMEDIATE_OK) {
			post(sinks.size() - 1, result(AwsIamStatus::OK, true));
		} else if (mode_ == Mode::IMMEDIATE_QUEUE_FULL) {
			post(sinks.size() - 1, result(AwsIamStatus::QUEUE_FULL));
		}
		return handle;
	}

	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point) override {
		return result(AwsIamStatus::PROVIDER_ERROR);
	}

	void cancel(AwsIamRequestHandle handle) override {
		if (handle.value != 0) canceled.push_back(handle.value);
	}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool success) override {
		if (success) ++backend_successes;
		else ++backend_failures;
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

	void post(size_t request_index, AwsIamTokenResult value) {
		if (auto sink = sinks.at(request_index).lock()) {
			AwsIamCompletion completion;
			completion.opaque_id = opaque_ids.at(request_index);
			completion.result = std::move(value);
			sink->post(std::move(completion));
		}
	}

	Mode mode_;
	uint64_t next_handle { 1 };
	std::vector<AwsIamTokenKey> keys;
	std::vector<uint64_t> opaque_ids;
	std::vector<std::weak_ptr<AwsIamCompletionSink>> sinks;
	std::vector<AwsIamRequestHandle> handles;
	std::vector<uint64_t> canceled;
	unsigned int backend_successes { 0 };
	unsigned int backend_failures { 0 };
	uint64_t waiting_sessions { 0 };
};

class BlockingFakeTokenSource final : public AwsIamTokenSource {
public:
	~BlockingFakeTokenSource() override { release_request(); }

	AwsIamRequestHandle request(const AwsIamTokenKey& key, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink> sink) override {
		{
			std::lock_guard<std::mutex> lock(request_mutex);
			request_entered = true;
			requests.push_back(key);
			opaque_ids.push_back(opaque_id);
			sinks.push_back(std::move(sink));
		}
		request_cv.notify_all();
		request_worker = std::thread([this] {
			std::unique_lock<std::mutex> lock(request_mutex);
			request_cv.wait(lock, [this] { return request_released; });
		});
		return AwsIamRequestHandle { next_handle++ };
	}

	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point) override {
		return result(AwsIamStatus::PROVIDER_ERROR);
	}

	void cancel(AwsIamRequestHandle handle) override {
		if (handle.value != 0) {
			{
				std::lock_guard<std::mutex> lock(request_mutex);
				canceled.push_back(handle.value);
			}
			release_request();
		}
	}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool) override {}
	void record_waiting_session(bool waiting) override {
		if (waiting) ++waiting_sessions;
		else if (waiting_sessions != 0) --waiting_sessions;
	}
	AwsIamStatsSnapshot snapshot() const override {
		AwsIamStatsSnapshot result;
		result.waiting_sessions = waiting_sessions;
		return result;
	}

	void wait_for_request() {
		std::unique_lock<std::mutex> lock(request_mutex);
		if (!request_cv.wait_for(lock, std::chrono::seconds(1),
			[this] { return request_entered; })) {
			BAIL_OUT("session did not enter the blocking IAM token source");
		}
	}

	void release_request() {
		{
			std::lock_guard<std::mutex> lock(request_mutex);
			request_released = true;
		}
		request_cv.notify_all();
		if (request_worker.joinable()) request_worker.join();
	}

	std::mutex request_mutex;
	std::condition_variable request_cv;
	bool request_entered { false };
	bool request_released { false };
	std::thread request_worker;
	uint64_t next_handle { 1 };
	std::vector<AwsIamTokenKey> requests;
	std::vector<uint64_t> opaque_ids;
	std::vector<std::weak_ptr<AwsIamCompletionSink>> sinks;
	std::vector<uint64_t> canceled;
	uint64_t waiting_sessions { 0 };
};

bool add_backend_user(const char *username, const char *password, const char *attributes) {
	return GloMyAuth->add(
		(char *)username, (char *)password, USERNAME_BACKEND,
		false, 0, (char *)"", false, false, false, 100,
		(char *)attributes, (char *)"");
}

MySrvC *add_server(const char *endpoint) {
	srv_info_t info;
	info.addr = endpoint;
	info.port = 3306;
	info.kind = "aws-iam-session-state-unit";
	srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 100;
	opts.use_ssl = 1;
	MyHGM->wrlock();
	const int rc = MyHGM->create_new_server_in_hg(kHostgroup, info, opts);
	MyHGC *hostgroup = MyHGM->MyHGC_find(kHostgroup);
	MyHGM->wrunlock();
	if (rc != 0 || hostgroup == nullptr) BAIL_OUT("failed to create IAM backend fixture");
	return MyHGM->find_server_in_hg(kHostgroup, endpoint, 3306);
}

std::string capture_stderr(const std::function<void()>& action) {
	FILE *captured = tmpfile();
	if (captured == nullptr) BAIL_OUT("tmpfile() failed");
	fflush(stderr);
	const int saved = dup(STDERR_FILENO);
	if (saved < 0 || dup2(fileno(captured), STDERR_FILENO) < 0) BAIL_OUT("stderr redirect failed");
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

std::string client_output(MySQL_Data_Stream *stream) {
	std::string bytes;
	if (stream == nullptr || stream->PSarrayOUT == nullptr) return bytes;
	for (unsigned int i = 0; i < stream->PSarrayOUT->len; ++i) {
		const PtrSize_t& packet = stream->PSarrayOUT->pdata[i];
		bytes.append(static_cast<const char *>(packet.ptr), packet.size);
	}
	return bytes;
}

class SessionFixture {
public:
	SessionFixture(MySQL_Thread& worker, const char *username = kIamUser) : worker_(worker) {
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

		session->mybe = session->find_or_create_backend(kHostgroup);
		session->current_hostgroup = kHostgroup;
		session->default_hostgroup = kHostgroup;
		session->CurrentQuery.start_time = worker_.curtime;
		session->previous_status.push(PROCESSING_QUERY);
		session->set_status(CONNECTING_SERVER);
	}

	~SessionFixture() {
		if (session != nullptr) delete session;
	}

	void start() {
		run();
	}

	int run() {
		session->to_process = 1;
		return session->handler();
	}

	MySQL_Connection *selected_connection() const {
		return session && session->mybe && session->mybe->server_myds
			? session->mybe->server_myds->myconn : nullptr;
	}

	MySrvC *selected_server() const {
		return selected_connection() ? selected_connection()->parent : nullptr;
	}

	MySQL_Thread& worker_;
	MySQL_Session *session { nullptr };
	MySQL_Data_Stream *frontend_stream { nullptr };
	MySQL_Connection *frontend { nullptr };
};

void complete_and_drain(MySQL_Thread& worker, FakeTokenSource& source,
	AwsIamTokenResult value, size_t request_index = 0) {
	source.post(request_index, std::move(value));
	worker.drain_aws_iam_completions();
}

void make_fast_forward(SessionFixture& fixture) {
	fixture.session->session_fast_forward = SESSION_FORWARD_TYPE_PERMANENT;
	while (!fixture.session->previous_status.empty()) {
		fixture.session->previous_status.pop();
	}
	fixture.session->previous_status.push(FAST_FORWARD);
}

void test_immediate_cache_hit(MySQL_Thread& worker) {
	FakeTokenSource source(FakeTokenSource::Mode::IMMEDIATE_OK);
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	fixture.start();
	MySQL_Connection *selected = fixture.selected_connection();
	MySrvC *server = fixture.selected_server();
	ok(fixture.session->status == WAITING_AWS_IAM_TOKEN && selected != nullptr && source.keys.size() == 1,
		"an immediate cache completion still enters the owner-thread waiting state");
	worker.drain_aws_iam_completions();
	const int rc = fixture.run();
	ok(rc == 0 && fixture.session->status == CONNECTING_SERVER &&
		fixture.selected_connection() == selected && fixture.selected_server() == server &&
		selected->has_aws_iam_handshake_secret(),
		"cache-hit completion resumes the selected fresh connection without reselection");
}

void test_delayed_completion(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	fixture.start();
	MySQL_Connection *selected = fixture.selected_connection();
	ok(fixture.run() == 0 &&
		fixture.session->status == WAITING_AWS_IAM_TOKEN && source.waiting_sessions == 1,
		"a session remains parked while its delayed token is unfinished");
	source.post(0, result(AwsIamStatus::OK, true));
	ok(fixture.session->status == WAITING_AWS_IAM_TOKEN && source.waiting_sessions == 1,
		"a queued completion leaves the live-session gauge set until owner-thread exit");
	worker.drain_aws_iam_completions();
	fixture.run();
	ok(fixture.session->status == CONNECTING_SERVER && fixture.selected_connection() == selected &&
		source.waiting_sessions == 0,
		"a delayed completion resumes the originally selected connection");
}

void test_provider_error_is_generic(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	fixture.start();
	complete_and_drain(worker, source, result(AwsIamStatus::PROVIDER_ERROR, true));
	const std::string log = capture_stderr([&fixture] {
		fixture.run();
	});
	const std::string output = client_output(fixture.frontend_stream);
	ok(fixture.session->status == WAITING_CLIENT_DATA && fixture.selected_connection() == nullptr,
		"provider error destroys the held fresh connection and returns to the client state");
	ok(output.find(kSensitiveToken) == std::string::npos &&
		output.find("NoCredentials") == std::string::npos &&
		log.find(kSensitiveToken) == std::string::npos,
		"provider failure never exposes a token or provider details to the client or log");
}

void test_queue_rejection(MySQL_Thread& worker) {
	FakeTokenSource source(FakeTokenSource::Mode::IMMEDIATE_QUEUE_FULL);
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	fixture.start();
	worker.drain_aws_iam_completions();
	fixture.run();
	ok(fixture.session->status == WAITING_CLIENT_DATA && fixture.selected_connection() == nullptr,
		"queue rejection follows the generic failure path and releases the fresh connection");
}

void test_five_second_deadline(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	fixture.start();
	worker.curtime += 5000000;
	fixture.run();
	ok(fixture.session->status == WAITING_CLIENT_DATA && source.canceled.size() == 1 &&
		fixture.selected_connection() == nullptr,
		"the five-second IAM deadline cancels the request and destroys the retained connection");
}

void test_existing_backend_deadline_wins(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	fixture.session->mybe->server_myds->max_connect_time = worker.curtime + 1000000;
	fixture.start();
	worker.curtime += 1000000;
	fixture.run();
	ok(fixture.session->status == WAITING_CLIENT_DATA && source.canceled.size() == 1 &&
		fixture.selected_connection() == nullptr,
		"an earlier backend-acquisition deadline wins over the five-second token deadline");
}

void test_frontend_disconnect(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	auto fixture = std::make_unique<SessionFixture>(worker);
	fixture->start();
	worker.register_session(&worker, fixture->session, false);
	fixture->session->healthy = 0;
	fixture->session = nullptr;
	worker.process_all_sessions();
	ok(source.canceled.size() == 1,
		"frontend teardown cancels and unregisters an in-flight IAM waiter");
}

void test_late_completion_is_dropped(MySQL_Thread& worker) {
	token_cleanse_calls.store(0, std::memory_order_relaxed);
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	fixture.start();
	worker.curtime += 5000000;
	fixture.run();
	complete_and_drain(worker, source, result(AwsIamStatus::OK, true));
	ok(token_cleanse_calls.load(std::memory_order_relaxed) == 1 &&
		fixture.selected_connection() == nullptr,
		"a late success after timeout is cleansed and cannot reattach a connection");
}

void test_shutdown_completion(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	fixture.start();
	complete_and_drain(worker, source, result(AwsIamStatus::SHUTDOWN));
	fixture.run();
	ok(fixture.session->status == WAITING_CLIENT_DATA && fixture.selected_connection() == nullptr,
		"token-source shutdown resumes the owner thread only to perform generic cleanup");
}

void test_session_wait_keeps_original_source_leased(MySQL_Thread& worker) {
	BlockingFakeTokenSource original_source;
	publish_global_aws_iam_token_source(&original_source);
	SessionFixture fixture(worker);
	fixture.start();
	original_source.wait_for_request();

	std::promise<void> shutdown_started;
	std::future<void> shutdown_started_future = shutdown_started.get_future();
	auto shutdown = std::async(std::launch::async, [&shutdown_started] {
		shutdown_started.set_value();
		shutdown_global_aws_iam_token_source();
	});
	shutdown_started_future.wait();
	const auto shutdown_entry_deadline =
		std::chrono::steady_clock::now() + std::chrono::seconds(1);
	for (;;) {
		AwsIamTokenSourceLease probe = acquire_global_aws_iam_token_source();
		if (!probe) break;
		if (std::chrono::steady_clock::now() >= shutdown_entry_deadline) {
			BAIL_OUT("global IAM shutdown did not disable new leases");
		}
		std::this_thread::yield();
	}
	const bool shutdown_waits_for_session_lease =
		shutdown.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout;

	ok(shutdown_waits_for_session_lease,
		"global shutdown waits for the session-owned IAM lease");
	fixture.session->cancel_aws_iam_wait();
	shutdown.get();

	FakeTokenSource republished_source;
	publish_global_aws_iam_token_source(&republished_source);
	ok(original_source.requests.size() == 1 && original_source.canceled.size() == 1 &&
		republished_source.keys.empty() && republished_source.canceled.empty(),
		"the old IAM wait never requests or cancels a republished token source");
	publish_global_aws_iam_token_source(nullptr);
}

void test_fast_forward_provider_failure_is_terminal(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	make_fast_forward(fixture);
	fixture.start();
	complete_and_drain(worker, source, result(AwsIamStatus::PROVIDER_ERROR));
	fixture.run();
	const size_t output_after_failure = client_output(fixture.frontend_stream).size();
	fixture.run();
	ok(fixture.session->status == WAITING_CLIENT_DATA &&
		fixture.selected_connection() == nullptr && worker.aws_iam_waiters.empty() &&
		client_output(fixture.frontend_stream).size() == output_after_failure,
		"fast-forward provider failure is terminal and cannot emit a second error");
}

void test_fast_forward_timeout_is_terminal(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	make_fast_forward(fixture);
	fixture.start();
	worker.curtime += 5000000;
	fixture.run();
	ok(fixture.session->status == WAITING_CLIENT_DATA && source.canceled.size() == 1 &&
		fixture.selected_connection() == nullptr && worker.aws_iam_waiters.empty(),
		"fast-forward IAM timeout cancels once and reaches a terminal client state");
}

void test_fast_forward_config_failure_is_terminal(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	char *saved_ca = mysql_thread___ssl_p2s_ca;
	mysql_thread___ssl_p2s_ca = strdup("");
	SessionFixture fixture(worker);
	make_fast_forward(fixture);
	fixture.start();
	free(mysql_thread___ssl_p2s_ca);
	mysql_thread___ssl_p2s_ca = saved_ca;
	ok(fixture.session->status == WAITING_CLIENT_DATA && source.keys.empty() &&
		fixture.selected_connection() == nullptr && worker.aws_iam_waiters.empty(),
		"fast-forward IAM configuration failure releases the connection and is terminal");
}

void test_worker_shutdown_closes_delivery_boundary() {
	token_cleanse_calls.store(0, std::memory_order_relaxed);
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	std::weak_ptr<AwsIamCompletionSink> delivery;
	{
		auto worker = std::make_unique<MySQL_Thread>();
		if (!worker->init()) BAIL_OUT("shutdown worker init failed");
		free(mysql_thread___ssl_p2s_ca);
		mysql_thread___ssl_p2s_ca = strdup("/unit/fake-ca.pem");
		worker->curtime = 10000000;
		auto fixture = std::make_unique<SessionFixture>(*worker);
		fixture->start();
		delivery = source.sinks.at(0);
		worker->register_session(worker.get(), fixture->session, false);
		fixture->session = nullptr;
		worker.reset();
	}
	source.post(0, result(AwsIamStatus::OK, true));
	ok(source.canceled.size() == 1 && delivery.expired() &&
		token_cleanse_calls.load(std::memory_order_relaxed) == 1,
		"worker shutdown cancels waiters before closing the inbox and late results cleanse/drop");
}

void test_selected_server_retention(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	SessionFixture fixture(worker);
	fixture.start();
	MySQL_Connection *selected = fixture.selected_connection();
	MySrvC *server = fixture.selected_server();
	complete_and_drain(worker, source, result(AwsIamStatus::OK, true));
	fixture.run();
	ok(source.keys.size() == 1 && fixture.selected_connection() == selected &&
		fixture.selected_server() == server && connector_calls.load(std::memory_order_relaxed) > 0,
		"request-through-connect retains one fresh connection and never chooses an alternate server");
}

void test_password_mode_unchanged(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	const unsigned int calls_before = connector_calls.load(std::memory_order_relaxed);
	SessionFixture fixture(worker, kPasswordUser);
	fixture.start();
	ok(source.keys.empty() && fixture.session->status == CONNECTING_SERVER &&
		fixture.selected_connection() != nullptr &&
		fixture.selected_connection()->backend_auth_type() == MySQLBackendAuthType::PASSWORD &&
		connector_calls.load(std::memory_order_relaxed) == calls_before + 1,
		"ordinary password-mode fresh connection acquisition remains synchronous and unchanged");
}

void test_unknown_user_passthrough_uses_password(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	const MySQLBackendAuthPolicy missing_policy =
		resolve_mysql_backend_auth_policy(*GloMyAuth, kUnknownPassthroughUser);
	const unsigned int calls_before = connector_calls.load(std::memory_order_relaxed);
	SessionFixture fixture(worker, kUnknownPassthroughUser);
	fixture.session->passthrough_credential = true;
	fixture.start();
	ok(missing_policy.type == MySQLBackendAuthType::INVALID &&
		missing_policy.failure_code == "backend_user_not_found" &&
		source.keys.empty() && fixture.session->status == CONNECTING_SERVER &&
		fixture.selected_connection() != nullptr &&
		fixture.selected_connection()->backend_auth_type() == MySQLBackendAuthType::PASSWORD &&
		connector_calls.load(std::memory_order_relaxed) == calls_before + 1,
		"authorized unknown-user pass-through keeps password backend semantics without a backend row");
}

void test_malformed_policy_stays_fail_closed_for_passthrough(MySQL_Thread& worker) {
	FakeTokenSource source;
	publish_global_aws_iam_token_source(&source);
	const unsigned int calls_before = connector_calls.load(std::memory_order_relaxed);
	SessionFixture fixture(worker, kMalformedPassthroughUser);
	fixture.session->passthrough_credential = true;
	fixture.start();
	ok(source.keys.empty() && fixture.session->status == WAITING_CLIENT_DATA &&
		fixture.selected_connection() == nullptr &&
		connector_calls.load(std::memory_order_relaxed) == calls_before,
		"pass-through authorization never overrides a malformed backend IAM policy");
}

#ifndef PROXYSQLAWSIAM
void test_sdk_off_source_reports_support_not_compiled(MySQL_Thread& worker) {
	AwsIamRuntimeConfig config;
	config.max_total_waiters = 128;
	config.max_waiters_per_key = 8;
	std::unique_ptr<AwsIamTokenSource> source = create_aws_iam_token_source(config);
	publish_global_aws_iam_token_source(source.get());
	SessionFixture fixture(worker);
	const std::string log = capture_stderr([&] {
		fixture.start();
		if (fixture.session->status == WAITING_AWS_IAM_TOKEN) {
			worker.drain_aws_iam_completions();
			fixture.run();
		}
	});
	publish_global_aws_iam_token_source(nullptr);
	ok(fixture.session->status == WAITING_CLIENT_DATA &&
		fixture.selected_connection() == nullptr &&
		log.find("category='support_not_compiled'") != std::string::npos,
		"the SDK-off source fails closed with the documented support_not_compiled operator reason");
}
#endif

} // namespace

extern "C" {

int __real_mysql_real_connect_start(MYSQL **, MYSQL *, const char *, const char *,
	const char *, const char *, unsigned int, const char *, unsigned long);

int __wrap_mysql_real_connect_start(MYSQL **ret, MYSQL *mysql, const char *host,
	const char *, const char *password, const char *, unsigned int port,
	const char *, unsigned long) {
	connector_calls.fetch_add(1, std::memory_order_relaxed);
	*ret = nullptr;
	mysql->host = strdup(host != nullptr ? host : "");
	mysql->passwd = strdup(password != nullptr ? password : "");
	mysql->port = port;
	return MYSQL_WAIT_READ;
}

} // extern "C"

int main() {
#ifdef PROXYSQLAWSIAM
	plan(25);
#else
	plan(26);
#endif
	if (test_init_minimal() != 0 || test_init_auth() != 0 ||
		test_init_query_processor() != 0 || test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	GloMyLogger = new MySQL_Logger();
	ok(add_backend_user(kIamUser, "", "{\"backend_auth\":{\"type\":\"aws_iam\"}}"),
		"IAM backend account fixture is loaded");
	ok(add_backend_user(kPasswordUser, "ordinary-password", ""),
		"password backend account fixture is loaded");
	if (!add_backend_user(kMalformedPassthroughUser, "ordinary-password",
		"{\"backend_auth\":{\"type\":17}}")) {
		BAIL_OUT("malformed backend account fixture failed to load");
	}
	add_server(kEndpointA);
	add_server(kEndpointB);
	MyHGC *hostgroup = MyHGM->MyHGC_find(kHostgroup);
	free(hostgroup->attributes.aws_iam_region);
	hostgroup->attributes.aws_iam_region = strdup(kRegion);

	{
		MySQL_Thread worker;
		if (!worker.init()) BAIL_OUT("MySQL_Thread::init() failed");
		free(mysql_thread___ssl_p2s_ca);
		mysql_thread___ssl_p2s_ca = strdup("/unit/fake-ca.pem");
		worker.curtime = 10000000;
		test_session_wait_keeps_original_source_leased(worker);
		test_immediate_cache_hit(worker);
		test_delayed_completion(worker);
		test_provider_error_is_generic(worker);
		test_queue_rejection(worker);
		test_five_second_deadline(worker);
		test_existing_backend_deadline_wins(worker);
		test_frontend_disconnect(worker);
		test_late_completion_is_dropped(worker);
		test_shutdown_completion(worker);
		test_fast_forward_provider_failure_is_terminal(worker);
		test_fast_forward_timeout_is_terminal(worker);
		test_fast_forward_config_failure_is_terminal(worker);
		test_selected_server_retention(worker);
		test_password_mode_unchanged(worker);
		test_unknown_user_passthrough_uses_password(worker);
		test_malformed_policy_stays_fail_closed_for_passthrough(worker);
#ifndef PROXYSQLAWSIAM
		test_sdk_off_source_reports_support_not_compiled(worker);
#endif
		publish_global_aws_iam_token_source(nullptr);
	}
	test_worker_shutdown_closes_delivery_boundary();
	publish_global_aws_iam_token_source(nullptr);

	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
