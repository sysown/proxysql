/**
 * @file aws_iam_kill_helper_unit-t.cpp
 * @brief Detached IAM query/connection kill credential regressions.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "Aws_Iam_Sdk.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Logger.hpp"

#include <openssl/crypto.h>

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

extern MySQL_HostGroups_Manager *MyHGM;
extern MySQL_Logger *GloMyLogger;

namespace {

using Clock = std::chrono::steady_clock;

constexpr unsigned int kHostgroup = 919;
constexpr const char *kEndpoint =
	"killer.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com";
constexpr const char *kTransportIp = "198.51.100.44";
constexpr const char *kRegion = "us-east-1";
constexpr const char *kDatabaseUser = "iam_kill_backend";
constexpr const char *kOriginalHandshakeToken = "ORIGINAL_HANDSHAKE_TOKEN_MUST_STAY_OWNED";
constexpr const char *kQueryToken = "CURRENT_QUERY_KILL_TOKEN";
constexpr const char *kConnectionToken = "CURRENT_CONNECTION_KILL_TOKEN";
constexpr const char *kPassword = "ordinary-password";

unsigned int secure_token_cleanse_calls = 0;
size_t secure_token_cleanse_size = 0;
bool secure_token_was_zeroed = false;

bool all_zero(const void *ptr, size_t size) {
	const auto *bytes = static_cast<const unsigned char *>(ptr);
	for (size_t i = 0; i < size; ++i) {
		if (bytes[i] != 0) return false;
	}
	return true;
}

void tracked_token_cleanse(void *ptr, size_t size) {
	OPENSSL_cleanse(ptr, size);
	++secure_token_cleanse_calls;
	secure_token_cleanse_size = size;
	secure_token_was_zeroed = all_zero(ptr, size);
}

class FakeBlockingTokenSource final : public AwsIamTokenSource {
public:
	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t,
		std::weak_ptr<AwsIamCompletionSink>) override { return {}; }

	AwsIamTokenResult request_blocking(const AwsIamTokenKey& key,
		Clock::time_point deadline) override {
		keys.push_back(key);
		deadlines.push_back(deadline);
		if (block_request) {
			std::unique_lock<std::mutex> lock(block_mutex);
			request_entered = true;
			block_cv.notify_all();
			block_cv.wait(lock, [this] { return request_released; });
		}
		if (wait_until_deadline) std::this_thread::sleep_until(deadline);
		AwsIamTokenResult result;
		result.status = status;
		if (status == AwsIamStatus::OK) {
			result.generation = keys.size();
			result.token = SecureString(next_token, tracked_token_cleanse);
		} else {
			result.failure.category = "credential_provider";
			result.failure.aws_error_code = "FakeProviderFailure";
			result.failure.request_id = "fake-request-id";
		}
		return result;
	}

	void cancel(AwsIamRequestHandle) override {}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool success) override {
		if (success) ++successes;
		else ++failures;
	}
	void record_waiting_session(bool) override {}
	AwsIamStatsSnapshot snapshot() const override { return {}; }

	AwsIamStatus status { AwsIamStatus::OK };
	std::string next_token { kQueryToken };
	std::vector<AwsIamTokenKey> keys;
	std::vector<Clock::time_point> deadlines;
	unsigned int successes { 0 };
	unsigned int failures { 0 };
	bool wait_until_deadline { false };
	bool block_request { false };
	bool request_entered { false };
	bool request_released { false };
	std::mutex block_mutex;
	std::condition_variable block_cv;
};

struct ConnectorObservation {
	unsigned int connect_calls { 0 };
	unsigned int query_calls { 0 };
	std::string expected_password;
	bool password_matches { false };
	bool original_password_reused { false };
	std::string host;
	std::string username;
	unsigned int port { 0 };
	std::string query;
	bool ssl_enforce { false };
	bool ssl_verify { false };
	bool cleartext { false };
	bool reconnect_seen { false };
	bool reconnect { true };
	bool connect_timeout_seen { false };
	unsigned int connect_timeout { 0 };
	std::string tls_server_name;
	char *connector_password { nullptr };
	size_t connector_password_size { 0 };
	unsigned int connector_cleanse_calls { 0 };
	bool connector_password_was_zeroed { false };
	bool passwd_null_at_close { false };
};

ConnectorObservation connector;

void reset_observations(const char *expected_password) {
	connector = ConnectorObservation {};
	connector.expected_password = expected_password != nullptr ? expected_password : "";
	secure_token_cleanse_calls = 0;
	secure_token_cleanse_size = 0;
	secure_token_was_zeroed = false;
}

KillArgs *iam_args(int kill_type, unsigned long id, Clock::time_point deadline) {
	return new KillArgs(
		const_cast<char *>(kDatabaseUser), nullptr,
		const_cast<char *>(kEndpoint), 3306, kHostgroup, id, kill_type, 1,
		nullptr, const_cast<char *>(kTransportIp), MySQLBackendAuthType::AWS_IAM,
		kEndpoint, kRegion, kDatabaseUser, deadline);
}

void test_iam_kill(FakeBlockingTokenSource& source, int kill_type,
	unsigned long id, const char *token, const char *expected_query,
	const char *label) {
	reset_observations(token);
	source.status = AwsIamStatus::OK;
	source.wait_until_deadline = false;
	source.next_token = token;
	const Clock::time_point deadline = Clock::now() + std::chrono::seconds(2);
	KillArgs *args = iam_args(kill_type, id, deadline);
	ok(args->password == nullptr,
		"%s carries IAM mode metadata without an original password or token", label);
	kill_query_thread(args);

	const AwsIamTokenKey expected_key { kEndpoint, 3306, kRegion, kDatabaseUser };
	ok(!source.keys.empty() && source.keys.back() == expected_key &&
		source.deadlines.back() == deadline && connector.connect_calls == 1 &&
		connector.host == kTransportIp && connector.username == kDatabaseUser &&
		connector.port == 3306 && connector.password_matches &&
		!connector.original_password_reused,
		"%s obtains its own current token with the exact key and helper deadline", label);
	ok(connector.ssl_enforce && connector.ssl_verify && connector.cleartext &&
		connector.reconnect_seen && !connector.reconnect &&
		connector.tls_server_name == kEndpoint &&
		connector.connect_timeout_seen && connector.connect_timeout >= 1 &&
		connector.connect_timeout <= 2,
		"%s enforces TLS, hostname verification, cleartext auth, no reconnect, and a deadline-bounded connect timeout", label);
	ok(connector.query_calls == 1 && connector.query == expected_query,
		"%s connects and issues only the requested KILL command", label);
	ok(secure_token_cleanse_calls == 1 &&
		secure_token_cleanse_size == std::strlen(token) && secure_token_was_zeroed &&
		connector.connector_cleanse_calls == 1 &&
		connector.connector_password_was_zeroed && connector.passwd_null_at_close,
		"%s cleanses the secure token and Connector/C password copies", label);
}

void test_helper_deadline(FakeBlockingTokenSource& source) {
	reset_observations(kQueryToken);
	source.status = AwsIamStatus::TIMEOUT;
	const Clock::time_point deadline = Clock::now() + std::chrono::milliseconds(5);
	KillArgs *args = iam_args(KILL_QUERY, 333, deadline);
	const size_t requests_before = source.keys.size();
	kill_query_thread(args);
	ok(source.keys.size() == requests_before + 1 &&
		source.deadlines.back() == deadline && connector.connect_calls == 0 &&
		connector.query_calls == 0,
		"an IAM kill helper passes through its deadline and never connects after timeout");
}

void test_deadline_expiring_during_token_request(FakeBlockingTokenSource& source) {
	reset_observations(kQueryToken);
	source.status = AwsIamStatus::OK;
	source.next_token = kQueryToken;
	source.wait_until_deadline = true;
	KillArgs *args = iam_args(
		KILL_QUERY, 334, Clock::now() + std::chrono::milliseconds(5));
	kill_query_thread(args);
	source.wait_until_deadline = false;
	ok(connector.connect_calls == 0 && connector.query_calls == 0,
		"an IAM helper does not start TCP connect after its deadline expires during token acquisition");
}

void test_password_mode_unchanged(FakeBlockingTokenSource& source) {
	reset_observations(kPassword);
	const size_t requests_before = source.keys.size();
	KillArgs *args = new KillArgs(
		const_cast<char *>("password_backend"), const_cast<char *>(kPassword),
		const_cast<char *>(kEndpoint), 3306, kHostgroup, 444, KILL_QUERY, 0,
		nullptr, const_cast<char *>(kTransportIp));
	kill_query_thread(args);
	ok(source.keys.size() == requests_before && connector.connect_calls == 1 &&
		connector.password_matches && !connector.ssl_enforce && !connector.ssl_verify &&
		!connector.cleartext && connector.tls_server_name.empty() &&
		connector.query == "KILL QUERY 444",
		"password-mode kill helpers retain their existing password connector behavior");
}

void test_helper_shutdown_lifetime(FakeBlockingTokenSource& source) {
	reset_observations(kQueryToken);
	source.status = AwsIamStatus::OK;
	source.next_token = kQueryToken;
	source.block_request = true;
	source.request_entered = false;
	source.request_released = false;
	std::thread helper([&] {
		kill_query_thread(iam_args(
			KILL_QUERY, 555, Clock::now() + std::chrono::seconds(2)));
	});
	{
		std::unique_lock<std::mutex> lock(source.block_mutex);
		if (!source.block_cv.wait_for(lock, std::chrono::seconds(1),
			[&source] { return source.request_entered; })) {
			BAIL_OUT("IAM helper did not enter the blocking token source");
		}
	}
	std::atomic<bool> shutdown_started { false };
	std::atomic<bool> shutdown_returned { false };
	std::thread shutdown([&] {
		shutdown_started.store(true, std::memory_order_release);
		shutdown_global_aws_iam_token_source();
		shutdown_returned.store(true, std::memory_order_release);
	});
	while (!shutdown_started.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}
	for (;;) {
		AwsIamTokenSourceLease probe = acquire_global_aws_iam_token_source();
		if (!probe) break;
		std::this_thread::yield();
	}
	const bool returned_while_helper_active =
		shutdown_returned.load(std::memory_order_acquire);
	{
		std::lock_guard<std::mutex> lock(source.block_mutex);
		source.request_released = true;
	}
	source.block_cv.notify_all();
	helper.join();
	shutdown.join();
	source.block_request = false;
	ok(!returned_while_helper_active &&
		shutdown_returned.load(std::memory_order_acquire) &&
		GloAwsIamTokenSource == nullptr && connector.connect_calls == 1 &&
		connector.query_calls == 1,
		"token-source shutdown waits until an already-running detached IAM helper finishes safely");

	const size_t requests_before = source.keys.size();
	reset_observations(kQueryToken);
	kill_query_thread(iam_args(
		KILL_QUERY, 556, Clock::now() + std::chrono::seconds(2)));
	ok(source.keys.size() == requests_before && connector.connect_calls == 0 &&
		connector.query_calls == 0,
		"an IAM helper starting after token-source shutdown is rejected safely");
}

} // namespace

extern "C" {

int __real_mysql_options(MYSQL *, enum mysql_option, const void *);
void __real_OPENSSL_cleanse(void *, size_t);
void __real_mysql_close(MYSQL *);

int __wrap_mysql_options(MYSQL *mysql, enum mysql_option option, const void *arg) {
	switch (option) {
		case MARIADB_OPT_TLS_SERVER_NAME:
			connector.tls_server_name = arg != nullptr
				? static_cast<const char *>(arg) : "";
			break;
		case MYSQL_OPT_SSL_ENFORCE:
			connector.ssl_enforce = arg != nullptr &&
				*static_cast<const my_bool *>(arg) != 0;
			break;
		case MYSQL_OPT_SSL_VERIFY_SERVER_CERT:
			connector.ssl_verify = arg != nullptr &&
				*static_cast<const my_bool *>(arg) != 0;
			break;
		case MYSQL_ENABLE_CLEARTEXT_PLUGIN:
			connector.cleartext = arg != nullptr &&
				*static_cast<const my_bool *>(arg) != 0;
			break;
		case MYSQL_OPT_RECONNECT:
			connector.reconnect_seen = true;
			connector.reconnect = arg != nullptr &&
				*static_cast<const my_bool *>(arg) != 0;
			break;
		case MYSQL_OPT_CONNECT_TIMEOUT:
			connector.connect_timeout_seen = true;
			connector.connect_timeout = arg != nullptr
				? *static_cast<const unsigned int *>(arg) : 0;
			break;
		default:
			break;
	}
	return __real_mysql_options(mysql, option, arg);
}

MYSQL *__wrap_mysql_real_connect(MYSQL *mysql, const char *host,
	const char *user, const char *password, const char *, unsigned int port,
	const char *, unsigned long) {
	++connector.connect_calls;
	connector.host = host != nullptr ? host : "";
	connector.username = user != nullptr ? user : "";
	connector.port = port;
	connector.password_matches = password != nullptr &&
		connector.expected_password == password;
	connector.original_password_reused = password != nullptr &&
		std::strcmp(password, kOriginalHandshakeToken) == 0;
	mysql->host = strdup(host != nullptr ? host : "");
	mysql->passwd = strdup(password != nullptr ? password : "");
	mysql->port = port;
	connector.connector_password = mysql->passwd;
	connector.connector_password_size = std::strlen(mysql->passwd);
	return mysql;
}

int __wrap_mysql_query(MYSQL *, const char *query) {
	++connector.query_calls;
	connector.query = query != nullptr ? query : "";
	return 0;
}

void __wrap_OPENSSL_cleanse(void *ptr, size_t size) {
	__real_OPENSSL_cleanse(ptr, size);
	if (ptr == connector.connector_password &&
		size == connector.connector_password_size) {
		++connector.connector_cleanse_calls;
		connector.connector_password_was_zeroed = all_zero(ptr, size);
	}
}

void __wrap_mysql_close(MYSQL *mysql) {
	connector.passwd_null_at_close = mysql == nullptr || mysql->passwd == nullptr;
	__real_mysql_close(mysql);
}

} // extern "C"

int main() {
	plan(15);
	if (test_init_minimal() != 0 || test_init_query_processor() != 0 ||
		test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	GloMyLogger = new MySQL_Logger();
	if (!GloMTH->set_variable("ssl_p2s_ca", "/unit/fake-ca.pem")) {
		BAIL_OUT("failed to configure helper CA fixture");
	}

	FakeBlockingTokenSource source;
	publish_global_aws_iam_token_source(&source);
	test_iam_kill(source, KILL_QUERY, 111, kQueryToken,
		"KILL QUERY 111", "IAM query kill");
	test_iam_kill(source, KILL_CONNECTION, 222, kConnectionToken,
		"KILL CONNECTION 222", "IAM connection kill");
	test_helper_deadline(source);
	test_deadline_expiring_during_token_request(source);
	test_password_mode_unchanged(source);
	test_helper_shutdown_lifetime(source);

	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
