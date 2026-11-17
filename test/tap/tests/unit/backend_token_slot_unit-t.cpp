/**
 * @file backend_token_slot_unit-t.cpp
 * @brief One token-source slot per provider: AWS IAM and Azure Entra (issue #6649).
 */
#include "tap.h"

#include "proxysql.h"
#include "cpp.h"
#include "Aws_Iam_Provider.h"
#include "MySQL_Backend_Auth.h"

#include <atomic>
#include <chrono>
#include <dlfcn.h>
#include <future>
#include <memory>
#include <string>

#include "prometheus/registry.h"

using namespace std::chrono_literals;

namespace {

class FakeSource final : public AwsIamTokenSource {
public:
	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t,
		std::weak_ptr<AwsIamCompletionSink>) override { return { 1 }; }
	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point) override { return {}; }
	void cancel(AwsIamRequestHandle) override {}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool) override {}
	void record_waiting_session(bool) override {}
	AwsIamStatsSnapshot snapshot() const override { return {}; }
};

std::atomic<int> destroyed { 0 };
void destroy_fake(AwsIamTokenSource *source) {
	delete source;
	destroyed.fetch_add(1);
}

/** Install a new fake into a slot the way a plugin does; returns it, or nullptr. */
AwsIamTokenSource *install_fake(BackendTokenProvider provider) {
	void *module_handle = dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
	auto *source = new FakeSource();
	if (module_handle == nullptr ||
		!install_global_backend_token_source(provider, source, destroy_fake, module_handle)) {
		delete source;
		if (module_handle != nullptr) dlclose(module_handle);
		return nullptr;
	}
	return source;
}

/** Value of the first series of a family in the registry; found=false when absent. */
double metric_value(prometheus::Registry& registry, const std::string& name, bool& found) {
	found = false;
	for (const prometheus::MetricFamily& family : registry.Collect()) {
		if (family.name != name || family.metric.empty()) continue;
		found = true;
		return family.type == prometheus::MetricType::Counter
			? family.metric[0].counter.value : family.metric[0].gauge.value;
	}
	return 0;
}

void test_entra_prometheus_metrics() {
	GloVars.prometheus_registry = std::make_shared<prometheus::Registry>();
	prometheus::Registry& registry = *GloVars.prometheus_registry;
	AwsIamTokenSource *azure = install_fake(BackendTokenProvider::AZURE_ENTRA);
	bool registered = false;
	metric_value(registry, "proxysql_mysql_azure_entra_token_requests_total", registered);
	AwsIamStatsSnapshot snap;
	snap.token_refresh_failures = 5;
	snap.waiting_sessions = 2;
	update_backend_token_prometheus_metrics(BackendTokenProvider::AZURE_ENTRA, snap);
	bool failures_found = false, waiting_found = false, aws_found = false;
	const double failures = metric_value(registry,
		"proxysql_mysql_azure_entra_token_refresh_failures_total", failures_found);
	const double waiting = metric_value(registry, "proxysql_mysql_azure_entra_waiting_sessions", waiting_found);
	metric_value(registry, "proxysql_mysql_aws_iam_token_refresh_failures_total", aws_found);
	ok(azure != nullptr && registered && failures_found && failures == 5 && waiting_found && waiting == 2 &&
		!aws_found,
		"entra_prometheus_metrics: an Azure install registers proxysql_mysql_azure_entra_* series; AWS series stay off");
	if (azure != nullptr) uninstall_global_backend_token_source(BackendTokenProvider::AZURE_ENTRA, azure);
	GloVars.prometheus_registry.reset();
}

void test_provider_mapping() {
	BackendTokenProvider p = BackendTokenProvider::AWS_IAM;
	ok(backend_token_provider_for(MySQLBackendAuthType::AZURE_ENTRA, p) &&
		p == BackendTokenProvider::AZURE_ENTRA, "AZURE_ENTRA maps to the Azure slot");
	ok(backend_token_provider_for(MySQLBackendAuthType::AWS_IAM, p) &&
		p == BackendTokenProvider::AWS_IAM, "AWS_IAM maps to the AWS slot");
	ok(!backend_token_provider_for(MySQLBackendAuthType::PASSWORD, p) &&
		!backend_token_provider_for(MySQLBackendAuthType::INVALID, p), "non-token types have no slot");

	AwsIamStatsSnapshot snap;
	snap.token_requests = 7;
	snap.waiting_sessions = 3;
	const AwsIamNamedStats entra = backend_token_stats_mysql_global_rows(BackendTokenProvider::AZURE_ENTRA, snap);
	bool prefixed = true;
	for (const AwsIamNamedStat& row : entra) prefixed = prefixed && std::string(row.name).rfind("AzureEntra_", 0) == 0;
	const AwsIamNamedStats aws = aws_iam_stats_mysql_global_rows(snap);
	ok(prefixed && std::string(entra[0].name) == "AzureEntra_Token_requests" && entra[0].value == 7 &&
		std::string(entra[11].name) == "AzureEntra_Waiting_sessions" && entra[11].value == 3 &&
		std::string(aws[0].name) == "AwsIam_Token_requests" && aws[0].value == 7,
		"entra_stats_rows: Azure rows use the AzureEntra_ prefix, AWS rows are unchanged");
}

void test_slots_independent() {
	AwsIamTokenSource *aws = install_fake(BackendTokenProvider::AWS_IAM);
	AwsIamTokenSource *azure = install_fake(BackendTokenProvider::AZURE_ENTRA);
	ok(aws != nullptr && azure != nullptr, "both slots accept an install");
	ok(acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA).get() == azure,
		"slots_independent: Azure acquire returns the Azure source");
	ok(acquire_global_aws_iam_token_source().get() == aws,
		"slots_independent: the AWS wrapper returns the AWS source");
	ok(GloAwsIamTokenSource == aws, "GloAwsIamTokenSource follows the AWS slot only");
	ok(acquire_backend_token_source_for(MySQLBackendAuthType::AZURE_ENTRA).get() == azure &&
		acquire_backend_token_source_for(MySQLBackendAuthType::AWS_IAM).get() == aws &&
		!acquire_backend_token_source_for(MySQLBackendAuthType::PASSWORD) &&
		!acquire_backend_token_source_for(MySQLBackendAuthType::INVALID),
		"acquire_for_type: token types get their own slot, other types get no source");
	ok(install_fake(BackendTokenProvider::AZURE_ENTRA) == nullptr, "an occupied slot refuses a second install");

	ok(uninstall_global_backend_token_source(BackendTokenProvider::AZURE_ENTRA, azure) &&
		!acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA) &&
		acquire_global_aws_iam_token_source().get() == aws,
		"uninstall_one_keeps_other");
	ok(!uninstall_global_backend_token_source(BackendTokenProvider::AZURE_ENTRA, aws),
		"a slot does not uninstall another slot's source");
	shutdown_global_backend_token_sources();
}

void test_lease_blocks_own_slot_only() {
	AwsIamTokenSource *aws = install_fake(BackendTokenProvider::AWS_IAM);
	AwsIamTokenSource *azure = install_fake(BackendTokenProvider::AZURE_ENTRA);
	auto azure_lease = std::make_unique<AwsIamTokenSourceLease>(
		acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA));
	auto aws_done = std::async(std::launch::async, [aws] {
		return uninstall_global_backend_token_source(BackendTokenProvider::AWS_IAM, aws);
	});
	ok(aws_done.wait_for(2s) == std::future_status::ready && aws_done.get(),
		"an Azure lease does not block retiring the AWS slot");
	auto azure_done = std::async(std::launch::async, [azure] {
		return uninstall_global_backend_token_source(BackendTokenProvider::AZURE_ENTRA, azure);
	});
	ok(azure_done.wait_for(100ms) == std::future_status::timeout,
		"an Azure lease blocks retiring the Azure slot");
	azure_lease.reset();
	ok(azure_done.wait_for(2s) == std::future_status::ready && azure_done.get(),
		"releasing the lease lets the Azure slot retire");
}

void test_shutdown_retires_both() {
	const int before = destroyed.load();
	install_fake(BackendTokenProvider::AWS_IAM);
	install_fake(BackendTokenProvider::AZURE_ENTRA);
	shutdown_global_backend_token_sources();
	ok(!acquire_global_aws_iam_token_source() &&
		!acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA) &&
		destroyed.load() == before + 2, "shutdown_retires_both");
}

void test_publish_per_slot() {
	FakeSource azure;
	publish_global_backend_token_source(BackendTokenProvider::AZURE_ENTRA, &azure);
	ok(acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA).get() == &azure &&
		!acquire_global_aws_iam_token_source() && GloAwsIamTokenSource == nullptr,
		"publishing into the Azure slot leaves the AWS slot empty");
	publish_global_backend_token_source(BackendTokenProvider::AZURE_ENTRA, nullptr);
	ok(!acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA), "unpublish empties the slot");
}

} // namespace

int main() {
	plan(0);
	test_entra_prometheus_metrics();
	test_provider_mapping();
	test_slots_independent();
	test_lease_blocks_own_slot_only();
	test_shutdown_retires_both();
	test_publish_per_slot();
	return exit_status();
}
