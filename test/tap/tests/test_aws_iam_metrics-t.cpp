#include "tap.h"

#include "Aws_Iam_Provider.h"
#include "ProxySQL_Statistics.hpp"
#include "cpp.h"
#include "proxysql.h"
#include "test_globals.h"
#include "test_init.h"

#include "prometheus/registry.h"
#include "prometheus/text_serializer.h"

#include <cstdlib>
#include <map>
#include <memory>
#include <string>

extern ProxySQL_Admin *GloAdmin;
extern ProxySQL_Statistics *GloProxyStats;

namespace {

constexpr const char *kSensitiveEndpoint =
	"metrics-secret.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com";
constexpr const char *kSensitiveRegion = "metrics-secret-region";
constexpr const char *kSensitiveUser = "metrics-secret-user";
constexpr const char *kSensitiveToken = "FAKE_AWS_SESSION_TOKEN_METRICS";

class ScriptedSource final : public AwsIamTokenSource {
public:
	explicit ScriptedSource(AwsIamStatsSnapshot stats) : stats_(stats) {}

	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t,
		std::weak_ptr<AwsIamCompletionSink>) override {
		return {};
	}
	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point) override {
		return {};
	}
	void cancel(AwsIamRequestHandle) override {}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool) override {}
	void record_waiting_session(bool) override {}
	AwsIamStatsSnapshot snapshot() const override { return stats_; }

private:
	AwsIamStatsSnapshot stats_;
};

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
	plan(7);

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

	AwsIamStatsSnapshot chosen;
	chosen.token_requests = 17;
	chosen.token_cache_hits = 11;
	chosen.token_refresh_successes = 7;
	chosen.token_refresh_failures = 5;
	chosen.credential_provider_failures = 3;
	chosen.queue_rejections = 2;
	chosen.backend_connection_successes = 13;
	chosen.backend_connection_failures = 4;
	chosen.token_cache_entries = 6;
	chosen.in_flight_generations = 1;
	chosen.queued_generations = 8;
	chosen.waiting_sessions = 9;
	ScriptedSource source(chosen);
	publish_global_aws_iam_token_source(&source);
	auto lease = acquire_global_aws_iam_token_source();
	ok(lease && lease->snapshot().token_requests == 17 &&
		lease->snapshot().waiting_sessions == 9,
		"public stats consumers acquire the scripted provider snapshot");
	lease = AwsIamTokenSourceLease {};

	const std::map<std::string, uint64_t> expected {
		{ "AwsIam_Token_requests", 17 },
		{ "AwsIam_Token_cache_hits", 11 },
		{ "AwsIam_Token_refresh_successes", 7 },
		{ "AwsIam_Token_refresh_failures", 5 },
		{ "AwsIam_Credential_provider_failures", 3 },
		{ "AwsIam_Queue_rejections", 2 },
		{ "AwsIam_Backend_connection_successes", 13 },
		{ "AwsIam_Backend_connection_failures", 4 },
		{ "AwsIam_Token_cache_entries", 6 },
		{ "AwsIam_In_flight_generations", 1 },
		{ "AwsIam_Queued_generations", 8 },
		{ "AwsIam_Waiting_sessions", 9 },
	};
	GloAdmin->stats___mysql_global();
	const std::map<std::string, uint64_t> stats = query_aws_iam_stats(GloAdmin->statsdb);
	ok(stats == expected, "stats_mysql_global projects all twelve provider values");

	MySQL_Threads_Handler *saved_threads = GloMTH;
	GloMTH = nullptr;
	GloAdmin->p_update_metrics();
	GloMTH = saved_threads;
	prometheus::TextSerializer serializer;
	const std::string metrics = serializer.Serialize(GloVars.prometheus_registry->Collect());
	const std::map<std::string, uint64_t> prometheus_expected {
		{ "proxysql_mysql_aws_iam_token_requests_total", 17 },
		{ "proxysql_mysql_aws_iam_token_cache_hits_total", 11 },
		{ "proxysql_mysql_aws_iam_token_refresh_successes_total", 7 },
		{ "proxysql_mysql_aws_iam_token_refresh_failures_total", 5 },
		{ "proxysql_mysql_aws_iam_credential_provider_failures_total", 3 },
		{ "proxysql_mysql_aws_iam_queue_rejections_total", 2 },
		{ "proxysql_mysql_aws_iam_backend_connection_successes_total", 13 },
		{ "proxysql_mysql_aws_iam_backend_connection_failures_total", 4 },
		{ "proxysql_mysql_aws_iam_token_cache_entries", 6 },
		{ "proxysql_mysql_aws_iam_in_flight_generations", 1 },
		{ "proxysql_mysql_aws_iam_queued_generations", 8 },
		{ "proxysql_mysql_aws_iam_waiting_sessions", 9 },
	};
	bool prometheus_exact = true;
	for (const auto& metric : prometheus_expected) {
		prometheus_exact = prometheus_exact &&
			has_unlabelled_sample(metrics, metric.first, metric.second);
	}
	ok(prometheus_exact,
		"Prometheus projects all twelve exact label-free provider values");
	ok(metrics.find(kSensitiveEndpoint) == std::string::npos &&
		metrics.find(kSensitiveRegion) == std::string::npos &&
		metrics.find(kSensitiveUser) == std::string::npos &&
		metrics.find(kSensitiveToken) == std::string::npos,
		"provider metrics contain no endpoint, region, user, or token text");

	publish_global_aws_iam_token_source(nullptr);
	auto active_registry = GloVars.prometheus_registry;
	GloVars.prometheus_registry = std::make_shared<prometheus::Registry>();
	auto unavailable = create_aws_iam_token_source({ 16, 16 });
	const AwsIamTokenResult unavailable_result = unavailable->request_blocking(
		{}, std::chrono::steady_clock::now());
	ok(!unavailable->support_compiled() &&
		unavailable_result.status == AwsIamStatus::SUPPORT_NOT_COMPILED &&
		unavailable_result.failure.category == "support_not_compiled",
		"the provider-neutral fallback remains fail closed");
	publish_global_aws_iam_token_source(unavailable.get());
	GloAdmin->stats___mysql_global();
	saved_threads = GloMTH;
	GloMTH = nullptr;
	GloAdmin->p_update_metrics();
	GloMTH = saved_threads;
	const auto unavailable_rows = query_aws_iam_stats(GloAdmin->statsdb);
	const std::string unavailable_metrics =
		serializer.Serialize(GloVars.prometheus_registry->Collect());
	bool unavailable_zero = unavailable_rows.size() == 12;
	for (const auto& row : unavailable_rows) unavailable_zero = unavailable_zero && row.second == 0;
	for (const auto& metric : prometheus_expected) {
		unavailable_zero = unavailable_zero &&
			has_unlabelled_sample(unavailable_metrics, metric.first, 0);
	}
	ok(unavailable_zero,
		"the unavailable provider projects fixed zero admin and Prometheus values");
	shutdown_global_aws_iam_token_source();

	return exit_status();
}
