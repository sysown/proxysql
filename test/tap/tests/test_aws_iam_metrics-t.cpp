#include "tap.h"

#include "Aws_Iam_Sdk.h"
#include "Aws_Iam_Token_Manager.h"
#include "ProxySQL_Statistics.hpp"
#include "cpp.h"
#include "proxysql.h"
#include "test_globals.h"
#include "test_init.h"

#include "prometheus/registry.h"
#include "prometheus/text_serializer.h"

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

extern ProxySQL_Admin *GloAdmin;
extern ProxySQL_Statistics *GloProxyStats;

namespace {

constexpr const char *kEndpoint =
	"metrics-secret.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com";
constexpr const char *kRegion = "metrics-secret-region";
constexpr const char *kUser = "metrics-secret-user";
constexpr const char *kToken = "FAKE_AWS_SESSION_TOKEN_METRICS";
constexpr const char *kAccessKey = "AKIAFAKEMETRICSACCESSKEY";
constexpr const char *kProfile = "fake-sensitive-profile";

class ScriptedSigner final : public AwsIamTokenSigner {
public:
	AwsIamSignResult sign(const AwsIamTokenKey& key) override {
		std::unique_lock<std::mutex> lock(mu_);
		if (key.endpoint == "blocked.example") {
			blocked_entered_ = true;
			entered_.notify_all();
			release_.wait(lock, [&] { return release_blocked_; });
		}

		AwsIamSignResult result;
		if (key.endpoint == "provider-failure.example") {
			result.status = AwsIamStatus::PROVIDER_ERROR;
			result.failure = { "provider", kAccessKey, kProfile };
		} else if (key.endpoint == "credential-failure.example") {
			result.status = AwsIamStatus::CREDENTIAL_PROVIDER_ERROR;
			result.failure = { "credential_provider", kAccessKey, kProfile };
		} else {
			result.status = AwsIamStatus::OK;
			result.token = SecureString(kToken);
		}
		return result;
	}

	bool wait_until_blocked() {
		std::unique_lock<std::mutex> lock(mu_);
		return entered_.wait_for(lock, 2s, [&] { return blocked_entered_; });
	}

	void release_blocked() {
		std::lock_guard<std::mutex> lock(mu_);
		release_blocked_ = true;
		release_.notify_all();
	}

private:
	std::mutex mu_;
	std::condition_variable entered_;
	std::condition_variable release_;
	bool blocked_entered_ { false };
	bool release_blocked_ { false };
};

class Sink final : public AwsIamCompletionSink {
public:
	void post(AwsIamCompletion&& completion) override {
		std::lock_guard<std::mutex> lock(mu_);
		completions_.push_back(std::move(completion));
		cv_.notify_all();
	}

	AwsIamTokenResult take() {
		std::unique_lock<std::mutex> lock(mu_);
		if (!cv_.wait_for(lock, 2s, [&] { return !completions_.empty(); })) {
			AwsIamTokenResult timeout;
			timeout.status = AwsIamStatus::TIMEOUT;
			return timeout;
		}
		AwsIamTokenResult result = std::move(completions_.front().result);
		completions_.erase(completions_.begin());
		return result;
	}

private:
	std::mutex mu_;
	std::condition_variable cv_;
	std::vector<AwsIamCompletion> completions_;
};

AwsIamTokenKey key(const char *endpoint) {
	return { endpoint, 3306, kRegion, kUser };
}

std::map<std::string, uint64_t> query_aws_iam_stats(SQLite3DB *db) {
	std::map<std::string, uint64_t> values;
	char *error = nullptr;
	int columns = 0;
	int affected_rows = 0;
	SQLite3_result *result = nullptr;
	db->execute_statement(
		"SELECT Variable_Name, Variable_Value FROM stats_mysql_global "
		"WHERE Variable_Name LIKE 'AwsIam_%' ORDER BY Variable_Name",
		&error, &columns, &affected_rows, &result);
	if (error != nullptr) {
		free(error);
		delete result;
		return values;
	}
	if (result != nullptr) {
		for (SQLite3_row *row : result->rows) {
			if (row->fields[0] != nullptr && row->fields[1] != nullptr) {
				values.emplace(row->fields[0], std::stoull(row->fields[1]));
			}
		}
	}
	delete result;
	return values;
}

bool has_unlabelled_sample(const std::string& text, const std::string& name,
	uint64_t value) {
	const std::string sample = name + " " + std::to_string(value) + "\n";
	return text.find(sample) != std::string::npos &&
		text.find(name + "{") == std::string::npos;
}

} // namespace

int main() {
	plan(9);

	const bool initialized = test_init_minimal() == 0 &&
		test_init_query_processor() == 0 && test_init_hostgroups() == 0;
	if (initialized) {
		GloVars.statsdb_disk = strdup(":memory:");
		GloProxyStats = new ProxySQL_Statistics();
		GloProxyStats->init();
		GloAdmin = new ProxySQL_Admin(); // NOSONAR: process-scoped partial fixture
		GloAdmin->statsdb = new SQLite3DB();
		char memory_db[] = ":memory:";
		GloAdmin->statsdb->open(
			memory_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		GloAdmin->statsdb->execute(
			"CREATE TABLE stats_mysql_global (Variable_Name VARCHAR NOT NULL PRIMARY KEY, "
			"Variable_Value VARCHAR NOT NULL)");
	}
	ok(initialized && GloAdmin != nullptr && GloAdmin->statsdb != nullptr,
		"production admin and process-registry fixture initializes");

	auto signer = std::make_shared<ScriptedSigner>();
	AwsIamTokenManagerConfig config(16);
	config.max_pending_keys = 1;
	config.max_cache_entries = 4;
	AwsIamTokenManager manager(signer, config);

	const AwsIamTokenKey success_key = key(kEndpoint);
	AwsIamTokenResult miss = manager.request_blocking(
		success_key, std::chrono::steady_clock::now() + 2s);
	AwsIamTokenResult hit = manager.request_blocking(
		success_key, std::chrono::steady_clock::now() + 2s);
	AwsIamTokenResult provider_failure = manager.request_blocking(
		key("provider-failure.example"), std::chrono::steady_clock::now() + 2s);
	AwsIamTokenResult credential_failure = manager.request_blocking(
		key("credential-failure.example"), std::chrono::steady_clock::now() + 2s);

	auto blocked_sink = std::make_shared<Sink>();
	manager.request(key("blocked.example"), 100, blocked_sink);
	const bool blocked = signer->wait_until_blocked();
	manager.record_waiting_session(true);
	AwsIamTokenResult helper_result;
	std::thread blocking_helper([&] {
		helper_result = manager.request_blocking(
			key("blocked.example"), std::chrono::steady_clock::now() + 2s);
	});
	const auto helper_registration_deadline = std::chrono::steady_clock::now() + 2s;
	while (manager.snapshot().token_requests < 6 &&
		std::chrono::steady_clock::now() < helper_registration_deadline) {
		std::this_thread::yield();
	}
	auto rejected_sink = std::make_shared<Sink>();
	manager.request(key("queue-rejected.example"), 101, rejected_sink);
	AwsIamTokenResult rejected = rejected_sink->take();
	manager.record_backend_connection(true);
	manager.record_backend_connection(false);

	const AwsIamStatsSnapshot active = manager.snapshot();
	ok(blocked && miss.status == AwsIamStatus::OK && hit.status == AwsIamStatus::OK &&
		provider_failure.status == AwsIamStatus::PROVIDER_ERROR &&
		credential_failure.status == AwsIamStatus::CREDENTIAL_PROVIDER_ERROR &&
		rejected.status == AwsIamStatus::QUEUE_FULL,
		"real manager drives success, hit, provider failures, and queue rejection");
	ok(active.token_requests == 7 && active.token_cache_entries == 1 &&
		active.in_flight_generations == 1 &&
		active.queued_generations == 0 && active.waiting_sessions == 1,
		"only the live session is counted while a blocking helper shares its generation");

	const std::map<std::string, uint64_t> expected {
		{ "AwsIam_Token_requests", 7 },
		{ "AwsIam_Token_cache_hits", 1 },
		{ "AwsIam_Token_refresh_successes", 1 },
		{ "AwsIam_Token_refresh_failures", 2 },
		{ "AwsIam_Credential_provider_failures", 1 },
		{ "AwsIam_Queue_rejections", 1 },
		{ "AwsIam_Backend_connection_successes", 1 },
		{ "AwsIam_Backend_connection_failures", 1 },
		{ "AwsIam_Token_cache_entries", 1 },
		{ "AwsIam_In_flight_generations", 1 },
		{ "AwsIam_Queued_generations", 0 },
		{ "AwsIam_Waiting_sessions", 1 },
	};
	publish_global_aws_iam_token_source(&manager);
	GloAdmin->stats___mysql_global();
	const std::map<std::string, uint64_t> stats = query_aws_iam_stats(GloAdmin->statsdb);
	ok(stats == expected, "stats_mysql_global rows have the fixed names and exact values");

	MySQL_Threads_Handler *saved_threads = GloMTH;
	GloMTH = nullptr;
	GloAdmin->p_update_metrics();
	GloMTH = saved_threads;
	prometheus::TextSerializer serializer;
	const std::string metrics = serializer.Serialize(GloVars.prometheus_registry->Collect());
	const std::map<std::string, uint64_t> prometheus_expected {
		{ "proxysql_mysql_aws_iam_token_requests_total", 7 },
		{ "proxysql_mysql_aws_iam_token_cache_hits_total", 1 },
		{ "proxysql_mysql_aws_iam_token_refresh_successes_total", 1 },
		{ "proxysql_mysql_aws_iam_token_refresh_failures_total", 2 },
		{ "proxysql_mysql_aws_iam_credential_provider_failures_total", 1 },
		{ "proxysql_mysql_aws_iam_queue_rejections_total", 1 },
		{ "proxysql_mysql_aws_iam_backend_connection_successes_total", 1 },
		{ "proxysql_mysql_aws_iam_backend_connection_failures_total", 1 },
		{ "proxysql_mysql_aws_iam_token_cache_entries", 1 },
		{ "proxysql_mysql_aws_iam_in_flight_generations", 1 },
		{ "proxysql_mysql_aws_iam_queued_generations", 0 },
		{ "proxysql_mysql_aws_iam_waiting_sessions", 1 },
	};
	bool prometheus_exact = true;
	for (const auto& metric : prometheus_expected) {
		prometheus_exact = prometheus_exact &&
			has_unlabelled_sample(metrics, metric.first, metric.second);
	}
	ok(prometheus_exact, "Prometheus exports all twelve exact label-free metric names and values");
	ok(metrics.find(kEndpoint) == std::string::npos &&
		metrics.find(kRegion) == std::string::npos && metrics.find(kUser) == std::string::npos &&
		metrics.find(kToken) == std::string::npos && metrics.find(kAccessKey) == std::string::npos &&
		metrics.find(kProfile) == std::string::npos,
		"Prometheus output contains no endpoint, region, user, token, access key, or profile text");

	signer->release_blocked();
	AwsIamTokenResult blocked_result = blocked_sink->take();
	blocking_helper.join();
	const AwsIamStatsSnapshot completed_but_session_waiting = manager.snapshot();
	ok(blocked_result.status == AwsIamStatus::OK && helper_result.status == AwsIamStatus::OK &&
		completed_but_session_waiting.in_flight_generations == 0 &&
		completed_but_session_waiting.waiting_sessions == 1,
		"a queued completion does not clear the gauge before the session exits its wait state");
	manager.record_waiting_session(false);
	manager.invalidate(success_key, miss.generation);
	manager.invalidate(key("blocked.example"), blocked_result.generation);
	const AwsIamStatsSnapshot cleaned = manager.snapshot();
	ok(blocked_result.status == AwsIamStatus::OK && cleaned.token_cache_entries == 0 &&
		cleaned.in_flight_generations == 0 && cleaned.queued_generations == 0 &&
		cleaned.waiting_sessions == 0,
		"all IAM gauges return to zero after completion and cache cleanup");

	publish_global_aws_iam_token_source(nullptr);
	// ProxySQL_Admin owns metric pointers registered in the original process
	// registry. Retain it while swapping in a fresh registry for the SDK-off
	// startup contract, just as each real process retains one registry for life.
	auto active_registry = GloVars.prometheus_registry;
	GloVars.prometheus_registry = std::make_shared<prometheus::Registry>();
	auto sdk_off_source = create_aws_iam_token_source({ 16, 16 });
	publish_global_aws_iam_token_source(sdk_off_source.get());
	GloAdmin->stats___mysql_global();
	saved_threads = GloMTH;
	GloMTH = nullptr;
	GloAdmin->p_update_metrics();
	GloMTH = saved_threads;
	const auto sdk_off_rows = query_aws_iam_stats(GloAdmin->statsdb);
	const std::string sdk_off_metrics =
		serializer.Serialize(GloVars.prometheus_registry->Collect());
	bool sdk_off_zero = sdk_off_rows.size() == 12;
	for (const auto& row : sdk_off_rows) {
		if (row.second != 0) diag("SDK-off row %s=%llu", row.first.c_str(),
			static_cast<unsigned long long>(row.second));
		sdk_off_zero = sdk_off_zero && row.second == 0;
	}
	for (const auto& metric : prometheus_expected) {
		const bool zero_sample = has_unlabelled_sample(sdk_off_metrics, metric.first, 0);
		if (!zero_sample) diag("missing SDK-off zero sample %s", metric.first.c_str());
		sdk_off_zero = sdk_off_zero && zero_sample;
	}
	ok(sdk_off_zero,
		"SDK-off source keeps the real admin table and process metrics at fixed zero values");
	publish_global_aws_iam_token_source(nullptr);

	return exit_status();
}
