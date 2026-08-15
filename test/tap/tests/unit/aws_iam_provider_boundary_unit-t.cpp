#include "tap.h"

#include "Aws_Iam_Provider.h"

#include <openssl/crypto.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <dlfcn.h>
#include <future>
#include <memory>
#include <string_view>
#include <thread>

using namespace std::chrono_literals;

namespace {

constexpr std::string_view kToken { "FAKE_PROVIDER_BOUNDARY_TOKEN" };
std::atomic<unsigned int> cleanse_calls { 0 };
std::atomic<bool> source_destroyed { false };

void tracked_cleanse(void *memory, size_t size) {
	if (size == kToken.size() && std::memcmp(memory, kToken.data(), size) == 0) {
		cleanse_calls.fetch_add(1, std::memory_order_relaxed);
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
		completion.result.token = SecureString(kToken, tracked_cleanse);
		if (auto live = sink.lock()) live->post(std::move(completion));
		return { 1 };
	}

	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point) override {
		AwsIamTokenResult result;
		result.status = AwsIamStatus::OK;
		result.token = SecureString(kToken, tracked_cleanse);
		return result;
	}

	void cancel(AwsIamRequestHandle) override {}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool) override {}
	void record_waiting_session(bool) override {}
	AwsIamStatsSnapshot snapshot() const override { return {}; }
};

void destroy_source(AwsIamTokenSource *source) {
	delete source;
	source_destroyed.store(true, std::memory_order_release);
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
	plan(10);
	shutdown_global_aws_iam_token_source();
	ok(!acquire_global_aws_iam_token_source(),
		"provider registry starts without an installed source");

	void *module_handle = dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
	auto *source = new FakeSource();
	ok(module_handle != nullptr && install_global_aws_iam_token_source(
		source, destroy_source, module_handle),
		"provider registry accepts a source with a retained module handle");

	AwsIamTokenSourceLease lease = acquire_global_aws_iam_token_source();
	ok(lease && lease.get() == source,
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
	ok(cleanse_calls.load(std::memory_order_relaxed) == 1,
		"the moved token is cleansed by the public secure-string contract");

	auto uninstall = std::async(std::launch::async, [source] {
		return uninstall_global_aws_iam_token_source(source);
	});
	const auto stop_deadline = std::chrono::steady_clock::now() + 1s;
	while (acquire_global_aws_iam_token_source() &&
		std::chrono::steady_clock::now() < stop_deadline) {
		std::this_thread::yield();
	}
	ok(!acquire_global_aws_iam_token_source(),
		"uninstall rejects new leases before draining the retained source");
	ok(uninstall.wait_for(20ms) == std::future_status::timeout &&
		!source_destroyed.load(std::memory_order_acquire),
		"uninstall waits for the outstanding source lease before destruction");
	lease = AwsIamTokenSourceLease {};
	ok(uninstall.get() && source_destroyed.load(std::memory_order_acquire),
		"uninstall destroys the source only after its final lease drains");

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

	return exit_status();
}
