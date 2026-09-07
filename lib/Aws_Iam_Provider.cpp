#include "Aws_Iam_Provider.h"
#include "proxysql.h"

#include "prometheus/counter.h"
#include "prometheus/family.h"
#include "prometheus/gauge.h"
#include "prometheus/registry.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <dlfcn.h>
#include <mutex>
#include <utility>

namespace {

constexpr std::array<const char *, 8> kAwsIamCounterNames {{
	"proxysql_mysql_aws_iam_token_requests_total",
	"proxysql_mysql_aws_iam_token_cache_hits_total",
	"proxysql_mysql_aws_iam_token_refresh_successes_total",
	"proxysql_mysql_aws_iam_token_refresh_failures_total",
	"proxysql_mysql_aws_iam_credential_provider_failures_total",
	"proxysql_mysql_aws_iam_queue_rejections_total",
	"proxysql_mysql_aws_iam_backend_connection_successes_total",
	"proxysql_mysql_aws_iam_backend_connection_failures_total",
}};

constexpr std::array<const char *, 4> kAwsIamGaugeNames {{
	"proxysql_mysql_aws_iam_token_cache_entries",
	"proxysql_mysql_aws_iam_in_flight_generations",
	"proxysql_mysql_aws_iam_queued_generations",
	"proxysql_mysql_aws_iam_waiting_sessions",
}};

struct AwsIamTokenSourceDestroyer {
	void operator()(AwsIamTokenSource* source) const noexcept {
		if (source == nullptr) return;
		if (destroy == nullptr) {
			delete source;
		} else {
			destroy(source);
		}
	}

	AwsIamTokenSourceDestroyFn destroy { nullptr };
};

struct AwsIamPrometheusState {
	std::mutex mutex;
	prometheus::Registry *registry { nullptr };
	std::array<prometheus::Counter *, 8> counters {};
	std::array<prometheus::Gauge *, 4> gauges {};
};

AwsIamPrometheusState& aws_iam_prometheus_state() {
	static AwsIamPrometheusState state;
	return state;
}

std::array<uint64_t, 8> aws_iam_counter_values(const AwsIamStatsSnapshot& stats) {
	return {{
		stats.token_requests,
		stats.token_cache_hits,
		stats.token_refresh_successes,
		stats.token_refresh_failures,
		stats.credential_provider_failures,
		stats.queue_rejections,
		stats.backend_connection_successes,
		stats.backend_connection_failures,
	}};
}

std::array<uint64_t, 4> aws_iam_gauge_values(const AwsIamStatsSnapshot& stats) {
	return {{
		stats.token_cache_entries,
		stats.in_flight_generations,
		stats.queued_generations,
		stats.waiting_sessions,
	}};
}

std::mutex global_source_mutex;
std::condition_variable global_source_cv;
AwsIamTokenSource *leased_global_source = nullptr;
size_t global_source_leases = 0;
bool global_source_accepting = false;
bool global_source_retirement_active = false;
// Count queued as well as active retirement callers so a replacement cannot
// slip between two waiters and be claimed by the lagging caller.
size_t global_source_retirement_requests = 0;

// A plugin supplies an extra dlopen() reference with its source. Core keeps
// that reference until every session lease has drained, then invokes the
// plugin's destroy callback before dlclose(). This prevents a source vtable
// from pointing at an already-unmapped plugin during shutdown.
struct AwsIamOwnedSource {
	std::unique_ptr<AwsIamTokenSource, AwsIamTokenSourceDestroyer> source {
		nullptr, AwsIamTokenSourceDestroyer {} };
	AwsIamModuleHandle module_handle { nullptr };

	AwsIamOwnedSource() = default;
	AwsIamOwnedSource(const AwsIamOwnedSource&) = delete;
	AwsIamOwnedSource& operator=(const AwsIamOwnedSource&) = delete;
	AwsIamOwnedSource(AwsIamOwnedSource&& other) noexcept
		: source(std::move(other.source)), module_handle(other.module_handle) {
		other.module_handle = nullptr;
	}
	AwsIamOwnedSource& operator=(AwsIamOwnedSource&& other) noexcept {
		if (this != &other) {
			reset();
			source = std::move(other.source);
			module_handle = other.module_handle;
			other.module_handle = nullptr;
		}
		return *this;
	}

	~AwsIamOwnedSource() noexcept { reset(); }

	void reset() noexcept {
		source.reset();
		if (module_handle != nullptr) {
			dlclose(module_handle);
		}
		module_handle = nullptr;
	}
};

AwsIamOwnedSource installed_source;

class AwsIamNotCompiledTokenSource final : public AwsIamTokenSource {
public:
	bool support_compiled() const override { return false; }

	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink> sink) override {
		AwsIamRequestHandle handle { next_handle_.fetch_add(1) };
		if (auto live_sink = sink.lock()) {
			AwsIamCompletion completion;
			completion.opaque_id = opaque_id;
			completion.result.status = AwsIamStatus::SUPPORT_NOT_COMPILED;
			completion.result.failure.category = "support_not_compiled";
			live_sink->post(std::move(completion));
		}
		return handle;
	}

	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point) override {
		AwsIamTokenResult result;
		result.status = AwsIamStatus::SUPPORT_NOT_COMPILED;
		result.failure.category = "support_not_compiled";
		return result;
	}

	void cancel(AwsIamRequestHandle handle) override {
		// Token invalidation state is not tracked in the non-SDK fallback.
		(void)handle;
	}
	void invalidate(const AwsIamTokenKey&, uint64_t generation) override {
		// Fallback path does not cache state between generations.
		(void)generation;
	}
	void record_backend_connection(bool success) override {
		// No backend connection accounting is available when SDK is disabled.
		(void)success;
	}
	void record_waiting_session(bool waiting) override {
		// Session-wait metrics are not collected for the non-SDK fallback.
		(void)waiting;
	}
	AwsIamStatsSnapshot snapshot() const override { return {}; }

private:
	std::atomic<uint64_t> next_handle_ { 1 };
};

} // namespace

AwsIamNamedStats aws_iam_stats_mysql_global_rows(const AwsIamStatsSnapshot& stats) {
	return {{
		{ "AwsIam_Token_requests", stats.token_requests },
		{ "AwsIam_Token_cache_hits", stats.token_cache_hits },
		{ "AwsIam_Token_refresh_successes", stats.token_refresh_successes },
		{ "AwsIam_Token_refresh_failures", stats.token_refresh_failures },
		{ "AwsIam_Credential_provider_failures", stats.credential_provider_failures },
		{ "AwsIam_Queue_rejections", stats.queue_rejections },
		{ "AwsIam_Backend_connection_successes", stats.backend_connection_successes },
		{ "AwsIam_Backend_connection_failures", stats.backend_connection_failures },
		{ "AwsIam_Token_cache_entries", stats.token_cache_entries },
		{ "AwsIam_In_flight_generations", stats.in_flight_generations },
		{ "AwsIam_Queued_generations", stats.queued_generations },
		{ "AwsIam_Waiting_sessions", stats.waiting_sessions },
	}};
}

void initialize_aws_iam_prometheus_metrics(prometheus::Registry& registry) {
	AwsIamPrometheusState& state = aws_iam_prometheus_state();
	std::lock_guard<std::mutex> lock(state.mutex);
	if (state.registry == &registry) return;
	// A ProxySQL process owns one registry for its lifetime. Supporting a new
	// registry here also keeps isolated tests deterministic after fresh setup.
	state.registry = &registry;
	state.counters.fill(nullptr);
	state.gauges.fill(nullptr);
	for (size_t i = 0; i < kAwsIamCounterNames.size(); ++i) {
		auto& family = prometheus::BuildCounter()
			.Name(kAwsIamCounterNames[i])
			.Help("ProxySQL AWS IAM backend authentication counter.")
			.Register(registry);
		state.counters[i] = std::addressof(family.Add({}));
	}
	for (size_t i = 0; i < kAwsIamGaugeNames.size(); ++i) {
		auto& family = prometheus::BuildGauge()
			.Name(kAwsIamGaugeNames[i])
			.Help("ProxySQL AWS IAM backend authentication gauge.")
			.Register(registry);
		state.gauges[i] = std::addressof(family.Add({}));
	}
}

void update_aws_iam_prometheus_metrics(const AwsIamStatsSnapshot& stats) {
	AwsIamPrometheusState& state = aws_iam_prometheus_state();
	std::lock_guard<std::mutex> lock(state.mutex);
	if (state.registry == nullptr) return;
	const auto counters = aws_iam_counter_values(stats);
	const auto gauges = aws_iam_gauge_values(stats);
	for (size_t i = 0; i < counters.size(); ++i) {
		const double current = state.counters[i]->Value();
		if (static_cast<double>(counters[i]) > current) {
			state.counters[i]->Increment(static_cast<double>(counters[i]) - current);
		}
	}
	for (size_t i = 0; i < gauges.size(); ++i) {
		state.gauges[i]->Set(static_cast<double>(gauges[i]));
	}
}

void AwsIamTokenSourceLease::release() {
	if (source_ == nullptr) return;
	{
		std::lock_guard<std::mutex> lock(global_source_mutex);
		if (global_source_leases != 0) --global_source_leases;
	}
	source_ = nullptr;
	global_source_cv.notify_all();
}

AwsIamTokenSourceLease::~AwsIamTokenSourceLease() { release(); }

AwsIamTokenSourceLease::AwsIamTokenSourceLease(
	AwsIamTokenSourceLease&& other) noexcept : source_(other.source_) {
	other.source_ = nullptr;
}

AwsIamTokenSourceLease& AwsIamTokenSourceLease::operator=(
	AwsIamTokenSourceLease&& other) noexcept {
	if (this != &other) {
		release();
		source_ = other.source_;
		other.source_ = nullptr;
	}
	return *this;
}

void publish_global_aws_iam_token_source(AwsIamTokenSource *source) {
	std::lock_guard<std::mutex> lock(global_source_mutex);
	if (global_source_retirement_requests != 0) {
		if (source != nullptr) {
			proxy_warning("Refusing to publish an AWS IAM token source during retirement\n");
		}
		return;
	}
	if (installed_source.source != nullptr &&
		source != installed_source.source.get()) {
		proxy_warning("Refusing to replace the plugin-owned AWS IAM token source\n");
		return;
	}
	if (source != nullptr && GloVars.prometheus_registry != nullptr) {
		initialize_aws_iam_prometheus_metrics(*GloVars.prometheus_registry);
		update_aws_iam_prometheus_metrics(source->snapshot());
	}
	leased_global_source = source;
	global_source_accepting = source != nullptr;
	GloAwsIamTokenSource = source;
}

bool install_global_aws_iam_token_source(
	AwsIamTokenSource *source, AwsIamTokenSourceDestroyFn destroy, AwsIamModuleHandle module_handle) {
	if (source == nullptr || destroy == nullptr || module_handle == nullptr) return false;

	std::lock_guard<std::mutex> lock(global_source_mutex);
	if (global_source_retirement_requests != 0 || global_source_accepting ||
		leased_global_source != nullptr ||
		installed_source.source != nullptr) {
		return false;
	}
	if (GloVars.prometheus_registry != nullptr) {
		initialize_aws_iam_prometheus_metrics(*GloVars.prometheus_registry);
		update_aws_iam_prometheus_metrics(source->snapshot());
	}
	installed_source.source = std::unique_ptr<AwsIamTokenSource, AwsIamTokenSourceDestroyer>(
		source, AwsIamTokenSourceDestroyer{destroy});
	installed_source.module_handle = module_handle;
	leased_global_source = source;
	global_source_accepting = true;
	GloAwsIamTokenSource = source;
	return true;
}

bool uninstall_global_aws_iam_token_source(AwsIamTokenSource *expected_source) {
	AwsIamOwnedSource retired_source;
	bool matched = false;
	{
		std::unique_lock<std::mutex> lock(global_source_mutex);
		++global_source_retirement_requests;
		global_source_cv.wait(lock, [] {
			return !global_source_retirement_active;
		});
		matched = expected_source != nullptr && installed_source.source.get() == expected_source &&
			leased_global_source == expected_source;
		if (matched) {
			global_source_retirement_active = true;
			global_source_accepting = false;
			GloAwsIamTokenSource = nullptr;
			global_source_cv.wait(lock, [] { return global_source_leases == 0; });
			leased_global_source = nullptr;
			retired_source = std::move(installed_source);
		} else {
			--global_source_retirement_requests;
		}
	}
	if (!matched) {
		global_source_cv.notify_all();
		return false;
	}
	retired_source.reset();
	{
		std::lock_guard<std::mutex> lock(global_source_mutex);
		global_source_retirement_active = false;
		--global_source_retirement_requests;
	}
	global_source_cv.notify_all();
	return true;
}

AwsIamTokenSourceLease acquire_global_aws_iam_token_source() {
	std::lock_guard<std::mutex> lock(global_source_mutex);
	if (!global_source_accepting || leased_global_source == nullptr) return {};
	++global_source_leases;
	return AwsIamTokenSourceLease(leased_global_source);
}

void shutdown_global_aws_iam_token_source() {
	AwsIamOwnedSource retired_source;
	{
		std::unique_lock<std::mutex> lock(global_source_mutex);
		++global_source_retirement_requests;
		global_source_cv.wait(lock, [] {
			return !global_source_retirement_active;
		});
		global_source_retirement_active = true;
		global_source_accepting = false;
		GloAwsIamTokenSource = nullptr;
		global_source_cv.wait(lock, [] { return global_source_leases == 0; });
		leased_global_source = nullptr;
		retired_source = std::move(installed_source);
	}
	retired_source.reset();
	{
		std::lock_guard<std::mutex> lock(global_source_mutex);
		global_source_retirement_active = false;
		--global_source_retirement_requests;
	}
	global_source_cv.notify_all();
}

std::unique_ptr<AwsIamTokenSource> create_aws_iam_token_source(
	const AwsIamRuntimeConfig& config) {
	(void)config;
	return std::make_unique<AwsIamNotCompiledTokenSource>();
}
