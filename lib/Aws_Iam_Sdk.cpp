#include "Aws_Iam_Sdk.h"
#include "proxysql.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <dlfcn.h>
#include <mutex>
#include <utility>

namespace {
std::mutex global_source_mutex;
std::condition_variable global_source_cv;
AwsIamTokenSource *leased_global_source = nullptr;
size_t global_source_leases = 0;
bool global_source_accepting = false;

// A plugin supplies an extra dlopen() reference with its source. Core keeps
// that reference until every session lease has drained, then invokes the
// plugin's destroy callback before dlclose(). This prevents a source vtable
// from pointing at an already-unmapped plugin during shutdown.
struct AwsIamOwnedSource {
	AwsIamTokenSource *source { nullptr };
	AwsIamTokenSourceDestroyFn destroy { nullptr };
	void *module_handle { nullptr };

	AwsIamOwnedSource() = default;
	AwsIamOwnedSource(const AwsIamOwnedSource&) = delete;
	AwsIamOwnedSource& operator=(const AwsIamOwnedSource&) = delete;
	AwsIamOwnedSource(AwsIamOwnedSource&& other) noexcept
		: source(other.source), destroy(other.destroy), module_handle(other.module_handle) {
		other.source = nullptr;
		other.destroy = nullptr;
		other.module_handle = nullptr;
	}
	AwsIamOwnedSource& operator=(AwsIamOwnedSource&& other) noexcept {
		if (this != &other) {
			reset();
			source = other.source;
			destroy = other.destroy;
			module_handle = other.module_handle;
			other.source = nullptr;
			other.destroy = nullptr;
			other.module_handle = nullptr;
		}
		return *this;
	}

	void reset() noexcept {
		if (source != nullptr) {
			if (destroy != nullptr) {
				destroy(source);
			} else {
				delete source;
			}
		}
		if (module_handle != nullptr) {
			dlclose(module_handle);
		}
		source = nullptr;
		destroy = nullptr;
		module_handle = nullptr;
	}
};

AwsIamOwnedSource installed_source;

class AwsIamNotCompiledTokenSource final : public AwsIamTokenSource {
public:
	bool support_compiled() const override { return false; }

	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink> sink) override {
		AwsIamRequestHandle handle { next_handle_.fetch_add(1, std::memory_order_relaxed) };
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

	void cancel(AwsIamRequestHandle) override {}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool) override {}
	void record_waiting_session(bool) override {}
	AwsIamStatsSnapshot snapshot() const override { return {}; }

private:
	std::atomic<uint64_t> next_handle_ { 1 };
};
} // namespace

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
	if (installed_source.source != nullptr && source != installed_source.source) {
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
	AwsIamTokenSource *source, AwsIamTokenSourceDestroyFn destroy, void *module_handle) {
	if (source == nullptr || destroy == nullptr || module_handle == nullptr) return false;

	std::lock_guard<std::mutex> lock(global_source_mutex);
	if (global_source_accepting || leased_global_source != nullptr || installed_source.source != nullptr) {
		return false;
	}
	if (GloVars.prometheus_registry != nullptr) {
		initialize_aws_iam_prometheus_metrics(*GloVars.prometheus_registry);
		update_aws_iam_prometheus_metrics(source->snapshot());
	}
	installed_source.source = source;
	installed_source.destroy = destroy;
	installed_source.module_handle = module_handle;
	leased_global_source = source;
	global_source_accepting = true;
	GloAwsIamTokenSource = source;
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
		global_source_accepting = false;
		GloAwsIamTokenSource = nullptr;
		global_source_cv.wait(lock, [] { return global_source_leases == 0; });
		leased_global_source = nullptr;
		retired_source = std::move(installed_source);
	}
	retired_source.reset();
}

std::unique_ptr<AwsIamTokenSource> create_aws_iam_token_source(
	const AwsIamRuntimeConfig& config) {
	(void)config;
	return std::make_unique<AwsIamNotCompiledTokenSource>();
}
