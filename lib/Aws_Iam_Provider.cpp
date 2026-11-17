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

// AWS IAM backend authentication is a v4.0 feature: the token source is
// installed by the plugin chassis, which only exists with PROXYSQL40. Under
// v3.0/v3.1 this translation unit compiles to nothing.
#ifdef PROXYSQL40

namespace {

// Index = BackendTokenProvider. Each provider has its own series, so the AWS names never change (#6649).
constexpr std::array<std::array<const char *, 8>, 2> kTokenCounterNames {{
	{{
		"proxysql_mysql_aws_iam_token_requests_total",
		"proxysql_mysql_aws_iam_token_cache_hits_total",
		"proxysql_mysql_aws_iam_token_refresh_successes_total",
		"proxysql_mysql_aws_iam_token_refresh_failures_total",
		"proxysql_mysql_aws_iam_credential_provider_failures_total",
		"proxysql_mysql_aws_iam_queue_rejections_total",
		"proxysql_mysql_aws_iam_backend_connection_successes_total",
		"proxysql_mysql_aws_iam_backend_connection_failures_total",
	}},
	{{
		"proxysql_mysql_azure_entra_token_requests_total",
		"proxysql_mysql_azure_entra_token_cache_hits_total",
		"proxysql_mysql_azure_entra_token_refresh_successes_total",
		"proxysql_mysql_azure_entra_token_refresh_failures_total",
		"proxysql_mysql_azure_entra_credential_provider_failures_total",
		"proxysql_mysql_azure_entra_queue_rejections_total",
		"proxysql_mysql_azure_entra_backend_connection_successes_total",
		"proxysql_mysql_azure_entra_backend_connection_failures_total",
	}},
}};

constexpr std::array<std::array<const char *, 4>, 2> kTokenGaugeNames {{
	{{
		"proxysql_mysql_aws_iam_token_cache_entries",
		"proxysql_mysql_aws_iam_in_flight_generations",
		"proxysql_mysql_aws_iam_queued_generations",
		"proxysql_mysql_aws_iam_waiting_sessions",
	}},
	{{
		"proxysql_mysql_azure_entra_token_cache_entries",
		"proxysql_mysql_azure_entra_in_flight_generations",
		"proxysql_mysql_azure_entra_queued_generations",
		"proxysql_mysql_azure_entra_waiting_sessions",
	}},
}};

constexpr std::array<const char *, 2> kTokenMetricHelp {{
	"ProxySQL AWS IAM backend authentication",
	"ProxySQL Azure Entra backend authentication",
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

AwsIamPrometheusState& token_prometheus_state(BackendTokenProvider provider) {
	static std::array<AwsIamPrometheusState, 2> states;
	return states[static_cast<size_t>(provider)];
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

} // namespace

struct BackendTokenSlot {
	std::mutex mutex;
	std::condition_variable cv;
	AwsIamTokenSource *leased = nullptr;
	size_t leases = 0;
	bool accepting = false;
	bool retirement_active = false;
	// Count queued as well as active retirement callers so a replacement cannot
	// slip between two waiters and be claimed by the lagging caller.
	size_t retirement_requests = 0;
	AwsIamOwnedSource installed;
};

namespace {

std::array<BackendTokenSlot, 2> backend_token_slots;

BackendTokenSlot& slot_for(BackendTokenProvider provider) {
	return backend_token_slots[static_cast<size_t>(provider)];
}

bool is_aws_slot(const BackendTokenSlot& slot) {
	return &slot == &slot_for(BackendTokenProvider::AWS_IAM);
}

const char *slot_name(const BackendTokenSlot& slot) {
	return is_aws_slot(slot) ? "AWS IAM" : "Azure Entra";
}

// GloAwsIamTokenSource and the AWS Prometheus metrics describe the AWS slot only.
void set_aws_global(const BackendTokenSlot& slot, AwsIamTokenSource *source) {
	if (is_aws_slot(slot)) GloAwsIamTokenSource = source;
}

void init_slot_metrics(const BackendTokenSlot& slot, AwsIamTokenSource *source) {
	if (source != nullptr && GloVars.prometheus_registry != nullptr) {
		const BackendTokenProvider provider = is_aws_slot(slot)
			? BackendTokenProvider::AWS_IAM : BackendTokenProvider::AZURE_ENTRA;
		initialize_backend_token_prometheus_metrics(provider, *GloVars.prometheus_registry);
		update_backend_token_prometheus_metrics(provider, source->snapshot());
	}
}

void shutdown_slot(BackendTokenSlot& slot);

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

AwsIamNamedStats backend_token_stats_mysql_global_rows(BackendTokenProvider provider,
	const AwsIamStatsSnapshot& stats) {
	static const char *const names[2][12] = {
		{ "AwsIam_Token_requests", "AwsIam_Token_cache_hits", "AwsIam_Token_refresh_successes",
		  "AwsIam_Token_refresh_failures", "AwsIam_Credential_provider_failures", "AwsIam_Queue_rejections",
		  "AwsIam_Backend_connection_successes", "AwsIam_Backend_connection_failures",
		  "AwsIam_Token_cache_entries", "AwsIam_In_flight_generations", "AwsIam_Queued_generations",
		  "AwsIam_Waiting_sessions" },
		{ "AzureEntra_Token_requests", "AzureEntra_Token_cache_hits", "AzureEntra_Token_refresh_successes",
		  "AzureEntra_Token_refresh_failures", "AzureEntra_Credential_provider_failures",
		  "AzureEntra_Queue_rejections", "AzureEntra_Backend_connection_successes",
		  "AzureEntra_Backend_connection_failures", "AzureEntra_Token_cache_entries",
		  "AzureEntra_In_flight_generations", "AzureEntra_Queued_generations", "AzureEntra_Waiting_sessions" },
	};
	const char *const *n = names[static_cast<size_t>(provider)];
	return {{
		{ n[0], stats.token_requests },
		{ n[1], stats.token_cache_hits },
		{ n[2], stats.token_refresh_successes },
		{ n[3], stats.token_refresh_failures },
		{ n[4], stats.credential_provider_failures },
		{ n[5], stats.queue_rejections },
		{ n[6], stats.backend_connection_successes },
		{ n[7], stats.backend_connection_failures },
		{ n[8], stats.token_cache_entries },
		{ n[9], stats.in_flight_generations },
		{ n[10], stats.queued_generations },
		{ n[11], stats.waiting_sessions },
	}};
}

AwsIamNamedStats aws_iam_stats_mysql_global_rows(const AwsIamStatsSnapshot& stats) {
	return backend_token_stats_mysql_global_rows(BackendTokenProvider::AWS_IAM, stats);
}

void initialize_backend_token_prometheus_metrics(BackendTokenProvider provider, prometheus::Registry& registry) {
	const size_t p = static_cast<size_t>(provider);
	AwsIamPrometheusState& state = token_prometheus_state(provider);
	std::lock_guard<std::mutex> lock(state.mutex);
	if (state.registry == &registry) return;
	// A ProxySQL process owns one registry for its lifetime. Supporting a new
	// registry here also keeps isolated tests deterministic after fresh setup.
	state.registry = &registry;
	state.counters.fill(nullptr);
	state.gauges.fill(nullptr);
	const std::string help = kTokenMetricHelp[p];
	for (size_t i = 0; i < kTokenCounterNames[p].size(); ++i) {
		auto& family = prometheus::BuildCounter()
			.Name(kTokenCounterNames[p][i])
			.Help(help + " counter.")
			.Register(registry);
		state.counters[i] = std::addressof(family.Add({}));
	}
	for (size_t i = 0; i < kTokenGaugeNames[p].size(); ++i) {
		auto& family = prometheus::BuildGauge()
			.Name(kTokenGaugeNames[p][i])
			.Help(help + " gauge.")
			.Register(registry);
		state.gauges[i] = std::addressof(family.Add({}));
	}
}

void update_backend_token_prometheus_metrics(BackendTokenProvider provider, const AwsIamStatsSnapshot& stats) {
	AwsIamPrometheusState& state = token_prometheus_state(provider);
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

void initialize_aws_iam_prometheus_metrics(prometheus::Registry& registry) {
	initialize_backend_token_prometheus_metrics(BackendTokenProvider::AWS_IAM, registry);
}

void update_aws_iam_prometheus_metrics(const AwsIamStatsSnapshot& stats) {
	update_backend_token_prometheus_metrics(BackendTokenProvider::AWS_IAM, stats);
}

void AwsIamTokenSourceLease::release() {
	if (source_ == nullptr) return;
	BackendTokenSlot *slot = slot_;
	{
		std::lock_guard<std::mutex> lock(slot->mutex);
		if (slot->leases != 0) --slot->leases;
	}
	source_ = nullptr;
	slot_ = nullptr;
	slot->cv.notify_all();
}

AwsIamTokenSourceLease::~AwsIamTokenSourceLease() { release(); }

AwsIamTokenSourceLease::AwsIamTokenSourceLease(
	AwsIamTokenSourceLease&& other) noexcept : source_(other.source_), slot_(other.slot_) {
	other.source_ = nullptr;
	other.slot_ = nullptr;
}

AwsIamTokenSourceLease& AwsIamTokenSourceLease::operator=(
	AwsIamTokenSourceLease&& other) noexcept {
	if (this != &other) {
		release();
		source_ = other.source_;
		slot_ = other.slot_;
		other.source_ = nullptr;
		other.slot_ = nullptr;
	}
	return *this;
}

void publish_global_backend_token_source(BackendTokenProvider provider, AwsIamTokenSource *source) {
	BackendTokenSlot& slot = slot_for(provider);
	std::lock_guard<std::mutex> lock(slot.mutex);
	if (slot.retirement_requests != 0) {
		if (source != nullptr) {
			proxy_warning("Refusing to publish an %s token source during retirement\n", slot_name(slot));
		}
		return;
	}
	if (slot.installed.source != nullptr &&
		source != slot.installed.source.get()) {
		proxy_warning("Refusing to replace the plugin-owned %s token source\n", slot_name(slot));
		return;
	}
	init_slot_metrics(slot, source);
	slot.leased = source;
	slot.accepting = source != nullptr;
	set_aws_global(slot, source);
}

bool install_global_backend_token_source(BackendTokenProvider provider, AwsIamTokenSource *source,
	AwsIamTokenSourceDestroyFn destroy, AwsIamModuleHandle module_handle) {
	if (source == nullptr || destroy == nullptr || module_handle == nullptr) return false;

	BackendTokenSlot& slot = slot_for(provider);
	std::lock_guard<std::mutex> lock(slot.mutex);
	if (slot.retirement_requests != 0 || slot.accepting ||
		slot.leased != nullptr ||
		slot.installed.source != nullptr) {
		return false;
	}
	init_slot_metrics(slot, source);
	slot.installed.source = std::unique_ptr<AwsIamTokenSource, AwsIamTokenSourceDestroyer>(
		source, AwsIamTokenSourceDestroyer{destroy});
	slot.installed.module_handle = module_handle;
	slot.leased = source;
	slot.accepting = true;
	set_aws_global(slot, source);
	return true;
}

bool uninstall_global_backend_token_source(BackendTokenProvider provider,
	AwsIamTokenSource *expected_source) {
	BackendTokenSlot& slot = slot_for(provider);
	AwsIamOwnedSource retired_source;
	bool matched = false;
	{
		std::unique_lock<std::mutex> lock(slot.mutex);
		++slot.retirement_requests;
		slot.cv.wait(lock, [&slot] {
			return !slot.retirement_active;
		});
		matched = expected_source != nullptr && slot.installed.source.get() == expected_source &&
			slot.leased == expected_source;
		if (matched) {
			slot.retirement_active = true;
			slot.accepting = false;
			set_aws_global(slot, nullptr);
			slot.cv.wait(lock, [&slot] { return slot.leases == 0; });
			slot.leased = nullptr;
			retired_source = std::move(slot.installed);
		} else {
			--slot.retirement_requests;
		}
	}
	if (!matched) {
		slot.cv.notify_all();
		return false;
	}
	retired_source.reset();
	{
		std::lock_guard<std::mutex> lock(slot.mutex);
		slot.retirement_active = false;
		--slot.retirement_requests;
	}
	slot.cv.notify_all();
	return true;
}

AwsIamTokenSourceLease acquire_backend_token_source(BackendTokenProvider provider) {
	BackendTokenSlot& slot = slot_for(provider);
	std::lock_guard<std::mutex> lock(slot.mutex);
	if (!slot.accepting || slot.leased == nullptr) return {};
	++slot.leases;
	return AwsIamTokenSourceLease(slot.leased, &slot);
}

namespace {

void shutdown_slot(BackendTokenSlot& slot) {
	AwsIamOwnedSource retired_source;
	{
		std::unique_lock<std::mutex> lock(slot.mutex);
		++slot.retirement_requests;
		slot.cv.wait(lock, [&slot] {
			return !slot.retirement_active;
		});
		slot.retirement_active = true;
		slot.accepting = false;
		set_aws_global(slot, nullptr);
		slot.cv.wait(lock, [&slot] { return slot.leases == 0; });
		slot.leased = nullptr;
		retired_source = std::move(slot.installed);
	}
	retired_source.reset();
	{
		std::lock_guard<std::mutex> lock(slot.mutex);
		slot.retirement_active = false;
		--slot.retirement_requests;
	}
	slot.cv.notify_all();
}

} // namespace

void shutdown_global_backend_token_sources() {
	for (BackendTokenSlot& slot : backend_token_slots) shutdown_slot(slot);
}

void publish_global_aws_iam_token_source(AwsIamTokenSource *source) {
	publish_global_backend_token_source(BackendTokenProvider::AWS_IAM, source);
}

bool install_global_aws_iam_token_source(
	AwsIamTokenSource *source, AwsIamTokenSourceDestroyFn destroy, AwsIamModuleHandle module_handle) {
	return install_global_backend_token_source(BackendTokenProvider::AWS_IAM, source, destroy, module_handle);
}

bool uninstall_global_aws_iam_token_source(AwsIamTokenSource *expected_source) {
	return uninstall_global_backend_token_source(BackendTokenProvider::AWS_IAM, expected_source);
}

AwsIamTokenSourceLease acquire_global_aws_iam_token_source() {
	return acquire_backend_token_source(BackendTokenProvider::AWS_IAM);
}

void shutdown_global_aws_iam_token_source() {
	shutdown_slot(slot_for(BackendTokenProvider::AWS_IAM));
}

std::unique_ptr<AwsIamTokenSource> create_aws_iam_token_source(
	const AwsIamRuntimeConfig& config) {
	(void)config;
	return std::make_unique<AwsIamNotCompiledTokenSource>();
}

#endif // PROXYSQL40
