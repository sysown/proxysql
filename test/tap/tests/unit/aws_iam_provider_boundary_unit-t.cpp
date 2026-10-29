#include "tap.h"

#include "Aws_Iam_Provider.h"

#include <openssl/crypto.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <dlfcn.h>
#include <future>
#include <memory>
#include <string_view>
#include <thread>

using namespace std::chrono_literals;

namespace {

using DlModuleHandle = decltype(dlopen(nullptr, RTLD_NOW | RTLD_LOCAL));

constexpr std::string_view kToken { "FAKE_PROVIDER_BOUNDARY_TOKEN" };
std::atomic<unsigned int> cleanse_calls { 0 };
std::atomic<bool> source_destroyed { false };
std::atomic<bool> replacement_install_attempted { false };
std::atomic<bool> replacement_install_succeeded { false };
std::atomic<bool> replacement_destroyed { false };

void tracked_cleanse(std::byte* memory, size_t size) {
	if (size == kToken.size() && std::memcmp(memory, kToken.data(), size) == 0) {
		cleanse_calls.fetch_add(1);
	}
	OPENSSL_cleanse(memory, size);
}

class CapturingSink final : public AwsIamCompletionSink {
public:
	void post(AwsIamCompletion&& completion) override {
		called = true;
		value = std::move(completion);
	}

	bool called { false };
	AwsIamCompletion value;
};

class FakeSource final : public AwsIamTokenSource {
public:
	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink> sink) override {
		AwsIamCompletion completion;
		completion.opaque_id = opaque_id;
		completion.result.status = AwsIamStatus::OK;
		completion.result.token = SecureString(kToken, [](void* memory, size_t bytes_size) {
			tracked_cleanse(static_cast<std::byte*>(memory), bytes_size);
		});
		if (auto live = sink.lock()) live->post(std::move(completion));
		return { 1 };
	}

	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point) override {
		AwsIamTokenResult result;
		result.status = AwsIamStatus::OK;
		result.token = SecureString(kToken, [](void* memory, size_t bytes_size) {
			tracked_cleanse(static_cast<std::byte*>(memory), bytes_size);
		});
		return result;
	}

	void cancel(AwsIamRequestHandle) override {
		// Cancellation path is not expected in this fake source.
	}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {
		// Invalidations are not exercised by this fake source.
	}
	void record_backend_connection(bool) override {
		// Backend connection metadata is not exercised by this fake source.
	}
	void record_waiting_session(bool) override {
		// Waiting session metrics are not exercised by this fake source.
	}
	AwsIamStatsSnapshot snapshot() const override { return {}; }
};

void destroy_source(AwsIamTokenSource *source) {
	std::unique_ptr<AwsIamTokenSource> owned_source(source);
	source_destroyed.store(true);
}

void destroy_replacement(AwsIamTokenSource *source) {
	std::unique_ptr<AwsIamTokenSource> owned_source(source);
	replacement_destroyed.store(true);
}

void destroy_source_and_attempt_replacement(AwsIamTokenSource *source) {
	std::unique_ptr<AwsIamTokenSource> owned_source(source);
	DlModuleHandle module_handle = dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
	auto replacement = std::make_unique<FakeSource>();
	replacement_install_attempted.store(true);
	const bool installed = module_handle != nullptr &&
		install_global_aws_iam_token_source(
			replacement.get(), destroy_replacement, module_handle);
	replacement_install_succeeded.store(installed);
	if (!installed) {
		replacement.reset();
		if (module_handle != nullptr) dlclose(module_handle);
	} else {
		replacement.release();
	}
}

bool all_stats_zero(const AwsIamStatsSnapshot& snapshot) {
	const AwsIamNamedStats rows = aws_iam_stats_mysql_global_rows(snapshot);
	for (const AwsIamNamedStat& row : rows) {
		if (row.value != 0) return false;
	}
	return true;
}

} // namespace

int main() {
	plan(14);
	shutdown_global_aws_iam_token_source();
	ok(!acquire_global_aws_iam_token_source(),
		"provider registry starts without an installed source");

	DlModuleHandle module_handle = dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
	auto source = std::make_unique<FakeSource>();
	ok(module_handle != nullptr && install_global_aws_iam_token_source(
		source.get(), destroy_source, module_handle),
		"provider registry accepts a source with a retained module handle");

	AwsIamTokenSourceLease lease = acquire_global_aws_iam_token_source();
	ok(lease && lease.get() == source.get(),
		"acquiring the registry returns a retained source lease");

	auto sink = std::make_shared<CapturingSink>();
	const AwsIamTokenKey key {
		"boundary.example", 3306, "boundary-region", "boundary-user"
	};
	const AwsIamRequestHandle request = lease->request(key, 42, sink);
	ok(request.value == 1 && sink->called && sink->value.opaque_id == 42 &&
		sink->value.result.status == AwsIamStatus::OK &&
		std::string_view(sink->value.result.token.c_str(),
			sink->value.result.token.size()) == kToken,
		"a provider token moves through the public completion sink");
	sink->value.result.token.clear();
	ok(cleanse_calls.load() == 1,
		"the moved token is cleansed by the public secure-string contract");

	std::packaged_task<bool()> uninstall_task(
		[source = source.get()] { return uninstall_global_aws_iam_token_source(source); });
	auto uninstall = uninstall_task.get_future();
	std::thread uninstall_worker(std::move(uninstall_task));
	const auto stop_deadline = std::chrono::steady_clock::now() + 1s;
	while (acquire_global_aws_iam_token_source() &&
		std::chrono::steady_clock::now() < stop_deadline) {
		std::this_thread::yield();
	}
	ok(!acquire_global_aws_iam_token_source(),
		"uninstall rejects new leases before draining the retained source");
	ok(uninstall.wait_for(20ms) == std::future_status::timeout &&
		!source_destroyed.load(),
		"uninstall waits for the outstanding source lease before destruction");
	lease = AwsIamTokenSourceLease {};
	ok(uninstall.get() && source_destroyed.load(),
		"uninstall destroys the source only after its final lease drains");
	uninstall_worker.join();
	source.release();

	std::unique_ptr<AwsIamTokenSource> unavailable =
		create_aws_iam_token_source({ 16, 8 });
	const AwsIamTokenResult unavailable_result = unavailable->request_blocking(
		key, std::chrono::steady_clock::now() + 1s);
	ok(!unavailable->support_compiled() &&
		unavailable_result.status == AwsIamStatus::SUPPORT_NOT_COMPILED &&
		unavailable_result.failure.category == "support_not_compiled",
		"the provider-neutral fallback fails closed with a fixed diagnostic");

	publish_global_aws_iam_token_source(unavailable.get());
	shutdown_global_aws_iam_token_source();
	ok(!acquire_global_aws_iam_token_source() &&
		all_stats_zero(unavailable->snapshot()),
		"shutdown removes the fallback source and leaves all twelve stats zero");

	replacement_install_attempted.store(false);
	replacement_install_succeeded.store(false);
	replacement_destroyed.store(false);
	DlModuleHandle retiring_handle = dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
	auto retiring_source = std::make_unique<FakeSource>();
	auto *retiring_source_ptr = retiring_source.get();
	if (retiring_handle == nullptr || !install_global_aws_iam_token_source(
		retiring_source_ptr, destroy_source_and_attempt_replacement, retiring_handle)) {
		BAIL_OUT("failed to install overlapping-retirement source");
	}
	retiring_source.release();
	AwsIamTokenSourceLease retirement_lease =
		acquire_global_aws_iam_token_source();
	std::packaged_task<bool()> overlapping_uninstall_task(
		[retiring_source_ptr] { return uninstall_global_aws_iam_token_source(retiring_source_ptr); });
	auto overlapping_uninstall = overlapping_uninstall_task.get_future();
	std::thread overlapping_uninstall_worker(std::move(overlapping_uninstall_task));
	std::packaged_task<void()> overlapping_shutdown_task(
		[] { shutdown_global_aws_iam_token_source(); });
	auto overlapping_shutdown = overlapping_shutdown_task.get_future();
	std::thread overlapping_shutdown_worker(std::move(overlapping_shutdown_task));
	const auto retirement_deadline = std::chrono::steady_clock::now() + 1s;
	while (acquire_global_aws_iam_token_source() &&
		std::chrono::steady_clock::now() < retirement_deadline) {
		std::this_thread::yield();
	}
	ok(overlapping_uninstall.wait_for(20ms) == std::future_status::timeout &&
		overlapping_shutdown.wait_for(20ms) == std::future_status::timeout,
		"overlapping uninstall and shutdown both wait for the claimed source lease");
	retirement_lease = AwsIamTokenSourceLease {};
	overlapping_uninstall.get();
	overlapping_shutdown.get();
	overlapping_uninstall_worker.join();
	overlapping_shutdown_worker.join();
	ok(replacement_install_attempted.load() &&
		!replacement_install_succeeded.load() &&
		!replacement_destroyed.load(),
		"replacement publication is rejected until overlapping retirement finishes");

	// Clean up the replacement that an unfixed registry may have accepted before
	// checking that publication reopens after both retirement callers return.
	shutdown_global_aws_iam_token_source();
	replacement_destroyed.store(false);
	DlModuleHandle survivor_handle = dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
	auto survivor = std::make_unique<FakeSource>();
	FakeSource *survivor_observer = survivor.get();
	const bool survivor_installed = survivor_handle != nullptr &&
		install_global_aws_iam_token_source(
			survivor_observer, destroy_replacement, survivor_handle);
	if (survivor_installed) {
		(void)survivor.release();
	} else if (survivor_handle != nullptr) {
		dlclose(survivor_handle);
	}
	ok(survivor_installed,
		"replacement publication reopens after every retirement caller finishes");
	AwsIamTokenSourceLease survivor_lease = acquire_global_aws_iam_token_source();
	ok(survivor_lease && survivor_lease.get() == survivor_observer &&
		!replacement_destroyed.load(),
		"the post-retirement replacement remains published and alive");
	survivor_lease = AwsIamTokenSourceLease {};
	shutdown_global_aws_iam_token_source();

	return exit_status();
}
