#include "tap.h"

#include "Aws_Locality_Manager.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {

struct FakeProviderState {
	struct Pending {
		AwsMetadataRequestHandle handle;
		AwsMetadataRequest request;
		std::weak_ptr<AwsMetadataCompletionSink> sink;
	};

	std::mutex mutex;
	std::condition_variable cv;
	std::vector<Pending> requests;
	std::vector<uint64_t> canceled;
	uint64_t next_handle { 1 };
	bool shut_down { false };
	bool destroyed { false };
	bool block_requests { false };
	bool request_entered { false };
	bool release_requests { false };
};

class FakeProvider final : public AwsMetadataProvider {
public:
	explicit FakeProvider(std::shared_ptr<FakeProviderState> state)
		: state_(std::move(state)) {}

	~FakeProvider() override {
		std::lock_guard<std::mutex> lock(state_->mutex);
		state_->destroyed = true;
		state_->cv.notify_all();
	}

	AwsMetadataRequestHandle request(
		const AwsMetadataRequest& request,
		std::weak_ptr<AwsMetadataCompletionSink> sink) override {
		std::unique_lock<std::mutex> lock(state_->mutex);
		const AwsMetadataRequestHandle handle { state_->next_handle++ };
		state_->requests.push_back({handle, request, std::move(sink)});
		state_->request_entered = true;
		state_->cv.notify_all();
		state_->cv.wait(lock, [&] {
			return !state_->block_requests || state_->release_requests;
		});
		return handle;
	}

	void cancel(AwsMetadataRequestHandle handle) override {
		std::lock_guard<std::mutex> lock(state_->mutex);
		state_->canceled.push_back(handle.value);
		state_->cv.notify_all();
	}

	void shutdown() override {
		std::lock_guard<std::mutex> lock(state_->mutex);
		state_->shut_down = true;
		state_->cv.notify_all();
	}

private:
	std::shared_ptr<FakeProviderState> state_;
};

void destroy_fake_provider(AwsMetadataProvider* provider) {
	delete provider;
}

bool wait_for_request_count(
	const std::shared_ptr<FakeProviderState>& state,
	size_t count) {
	std::unique_lock<std::mutex> lock(state->mutex);
	return state->cv.wait_for(lock, 2s, [&] {
		return state->requests.size() >= count;
	});
}

std::vector<FakeProviderState::Pending> requests_copy(
	const std::shared_ptr<FakeProviderState>& state) {
	std::lock_guard<std::mutex> lock(state->mutex);
	return state->requests;
}

bool complete_request(
	const std::shared_ptr<FakeProviderState>& state,
	AwsMetadataRequestKind kind,
	const std::string& region,
	AwsMetadataResult result,
	size_t occurrence = 0) {
	FakeProviderState::Pending pending;
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		size_t found = 0;
		for (const auto& item : state->requests) {
			if (item.request.kind == kind && item.request.region == region) {
				if (found++ == occurrence) {
					pending = item;
					break;
				}
			}
		}
	}
	if (pending.handle.value == 0) {
		return false;
	}
	if (auto sink = pending.sink.lock()) {
		AwsMetadataCompletion completion;
		completion.opaque_id = pending.request.opaque_id;
		completion.generation = pending.request.generation;
		completion.result = std::move(result);
		sink->post(std::move(completion));
		return true;
	}
	return false;
}

bool complete_request_after(
	const std::shared_ptr<FakeProviderState>& state,
	AwsMetadataRequestKind kind,
	const std::string& region,
	AwsMetadataResult result,
	size_t first_request) {
	FakeProviderState::Pending pending;
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		for (size_t index = first_request; index < state->requests.size(); ++index) {
			const auto& item = state->requests[index];
			if (item.request.kind == kind && item.request.region == region) {
				pending = item;
				break;
			}
		}
	}
	if (pending.handle.value == 0) {
		return false;
	}
	if (auto sink = pending.sink.lock()) {
		AwsMetadataCompletion completion;
		completion.opaque_id = pending.request.opaque_id;
		completion.generation = pending.request.generation;
		completion.result = std::move(result);
		sink->post(std::move(completion));
		return true;
	}
	return false;
}

template <typename Predicate>
bool wait_until(Predicate predicate) {
	const auto deadline = std::chrono::steady_clock::now() + 2s;
	while (std::chrono::steady_clock::now() < deadline) {
		if (predicate()) {
			return true;
		}
		std::this_thread::sleep_for(1ms);
	}
	return predicate();
}

AwsLocalityHostgroupConfig make_hostgroup(
	uint32_t id,
	double region_multiplier,
	double az_multiplier,
	uint32_t refresh,
	uint32_t stale,
	std::initializer_list<const char*> endpoints) {
	AwsLocalityHostgroupConfig config;
	config.hostgroup_id = id;
	config.policy.valid = true;
	config.policy.same_region_multiplier = region_multiplier;
	config.policy.same_az_multiplier = az_multiplier;
	config.policy.refresh_interval_seconds = refresh;
	config.policy.stale_ttl_seconds = stale;
	for (const char* endpoint : endpoints) {
		config.backends.push_back(recognize_rds_endpoint(id, endpoint, 3306));
	}
	return config;
}

const AwsLocalitySnapshotEntry* lookup(
	const std::shared_ptr<const AwsLocalitySnapshot>& snapshot,
	uint32_t hostgroup_id,
	const char* hostname) {
	return snapshot->find(hostgroup_id, hostname, 3306);
}

} // namespace

int main() {
	plan(49);

	auto provider_state = std::make_shared<FakeProviderState>();
	ok(install_global_aws_metadata_provider(
		new FakeProvider(provider_state), destroy_fake_provider, nullptr),
		"metadata provider can be installed without an SDK dependency in core");
	{
		auto lease = acquire_global_aws_metadata_provider();
		ok(lease && lease.get() != nullptr,
			"installed provider is available through a retained lease");
	}

	std::atomic<int64_t> steady_seconds { 0 };
	std::atomic<int64_t> wall_seconds { 1700000000 };
	AwsLocalityManagerConfig manager_config;
	manager_config.steady_clock = [&] {
		return std::chrono::steady_clock::time_point(
			std::chrono::seconds(steady_seconds.load()));
	};
	manager_config.wall_clock = [&] {
		return std::chrono::system_clock::time_point(
			std::chrono::seconds(wall_seconds.load()));
	};
	manager_config.request_timeout = 5s;

	MySQLAwsLocalityManager manager(manager_config);
	const auto east_one = "db-1.abcdefghijkl.us-east-1.rds.amazonaws.com";
	const auto east_missing = "db-missing.abcdefghijkl.us-east-1.rds.amazonaws.com";
	const auto west_one = "db-2.abcdefghijkl.eu-west-1.rds.amazonaws.com";
	manager.configure({
		make_hostgroup(10, 2.0, 4.0, 300, 1800, {east_one, east_missing}),
		make_hostgroup(11, 1.5, 3.0, 60, 120, {east_one, west_one}),
	});
	const auto disabled_snapshot = manager.snapshot();
	const auto* disabled_entry = lookup(disabled_snapshot, 10, east_one);
	ok(disabled_entry && disabled_entry->status == AwsLocalityMetadataStatus::disabled &&
		disabled_entry->multiplier == 1.0,
		"configured manager publishes neutral diagnostic rows while disabled");

	manager.set_enabled(true);
	ok(wait_for_request_count(provider_state, 3),
		"enable dispatches local identity and one coalesced request per Region");
	const auto initial_requests = requests_copy(provider_state);
	const auto east_request = std::find_if(initial_requests.begin(), initial_requests.end(),
		[](const auto& pending) {
			return pending.request.kind == AwsMetadataRequestKind::rds_region &&
				pending.request.region == "us-east-1";
		});
	ok(east_request != initial_requests.end() && east_request->request.endpoints.size() == 2,
		"duplicate endpoint registrations across hostgroups are coalesced");
	ok(east_request != initial_requests.end() &&
		east_request->request.deadline == manager_config.steady_clock() + 5s,
		"provider request receives the configured monotonic deadline");

	AwsMetadataResult local_result;
	local_result.status = AwsMetadataStatus::ok;
	local_result.local = {"us-east-1", "us-east-1a", "111122223333"};
	ok(complete_request(provider_state, AwsMetadataRequestKind::local_location,
		"", std::move(local_result)), "local identity completion is accepted");

	AwsMetadataResult east_result;
	east_result.status = AwsMetadataStatus::ok;
	east_result.endpoints.push_back({east_one, 3306, AwsEndpointType::instance,
		"us-east-1", "us-east-1a", "111122223333"});
	ok(complete_request(provider_state, AwsMetadataRequestKind::rds_region,
		"us-east-1", std::move(east_result)), "east Region completion is accepted");

	AwsMetadataResult west_result;
	west_result.status = AwsMetadataStatus::ok;
	west_result.endpoints.push_back({west_one, 3306, AwsEndpointType::instance,
		"eu-west-1", "eu-west-1a", "111122223333"});
	ok(complete_request(provider_state, AwsMetadataRequestKind::rds_region,
		"eu-west-1", std::move(west_result)), "west Region completion is accepted");

	ok(wait_until([&] {
		auto snapshot = manager.snapshot();
		const auto* entry = lookup(snapshot, 10, east_one);
		return entry != nullptr && entry->status == AwsLocalityMetadataStatus::fresh;
	}), "immutable snapshot is published after normalized completions");

	auto snapshot = manager.snapshot();
	const auto* hg10_east = lookup(snapshot, 10, east_one);
	const auto* hg11_east = lookup(snapshot, 11, east_one);
	const auto* hg11_west = lookup(snapshot, 11, west_one);
	const auto* missing = lookup(snapshot, 10, east_missing);
	ok(hg10_east && hg10_east->locality == AwsLocalityClass::same_az &&
		hg10_east->multiplier == 4.0,
		"same-AZ result uses only the hostgroup's AZ multiplier");
	ok(hg11_east && hg11_east->multiplier == 3.0,
		"one backend can use a different policy in another hostgroup");
	ok(hg11_west && hg11_west->locality == AwsLocalityClass::remote &&
		hg11_west->multiplier == 1.0,
		"known remote backend remains neutral");
	ok(missing && missing->status == AwsLocalityMetadataStatus::error &&
		missing->failure_category == "endpoint_not_found" && missing->multiplier == 1.0,
		"authoritative endpoint-not-found is redacted and neutral");
	ok(snapshot->effective_weight(10, east_one, 3306, 10) == 40 &&
		snapshot->effective_weight(11, west_one, 3306, 30) == 30,
		"snapshot computes temporary weights without mutating configuration");

	steady_seconds.store(61);
	wall_seconds.store(1700000061);
	manager.request_refresh();
	ok(wait_for_request_count(provider_state, 6),
		"shortest configured refresh interval drives the next coalesced cycle");
	snapshot = manager.snapshot();
	hg10_east = lookup(snapshot, 10, east_one);
	hg11_east = lookup(snapshot, 11, east_one);
	ok(hg10_east && hg10_east->status == AwsLocalityMetadataStatus::fresh &&
		hg11_east && hg11_east->status == AwsLocalityMetadataStatus::stale,
		"freshness is evaluated independently for each hostgroup policy");
	ok(hg11_east && hg11_east->multiplier == 3.0,
		"stale but unexpired metadata remains active");
	AwsMetadataResult refresh_failure;
	refresh_failure.status = AwsMetadataStatus::timeout;
	const bool failed_refreshes_delivered =
		complete_request(provider_state, AwsMetadataRequestKind::local_location,
			"", refresh_failure, 1) &&
		complete_request(provider_state, AwsMetadataRequestKind::rds_region,
			"us-east-1", refresh_failure, 1) &&
		complete_request(provider_state, AwsMetadataRequestKind::rds_region,
			"eu-west-1", std::move(refresh_failure), 1);
	const auto failed_refresh_snapshot = manager.snapshot();
	const auto* failed_refresh_entry = lookup(failed_refresh_snapshot, 11, east_one);
	ok(failed_refreshes_delivered &&
		failed_refresh_entry != nullptr &&
		failed_refresh_entry->status == AwsLocalityMetadataStatus::stale,
		"failed refresh preserves the last successful value within stale TTL");

	steady_seconds.store(121);
	wall_seconds.store(1700000121);
	manager.request_refresh();
	ok(wait_for_request_count(provider_state, 9),
		"forced scheduler wake dispatches another due refresh cycle");
	snapshot = manager.snapshot();
	hg11_east = lookup(snapshot, 11, east_one);
	ok(hg11_east && hg11_east->status == AwsLocalityMetadataStatus::expired &&
		hg11_east->multiplier == 1.0,
		"expired metadata becomes neutral");

	size_t canceled_before_reload = 0;
	{
		std::lock_guard<std::mutex> lock(provider_state->mutex);
		canceled_before_reload = provider_state->canceled.size();
	}
	manager.configure({
		make_hostgroup(12, 2.0, 4.0, 300, 1800,
			{"db-new.abcdefghijkl.us-east-1.rds.amazonaws.com"}),
	});
	ok(wait_until([&] {
		std::lock_guard<std::mutex> lock(provider_state->mutex);
		return provider_state->canceled.size() > canceled_before_reload;
	}), "configuration generation change cancels obsolete requests");
	const uint64_t new_generation = manager.snapshot()->generation;
	ok(new_generation > snapshot->generation,
		"configuration reload advances the immutable snapshot generation");

	AwsMetadataResult late_result;
	late_result.status = AwsMetadataStatus::ok;
	late_result.endpoints.push_back({east_one, 3306, AwsEndpointType::instance,
		"us-east-1", "us-east-1a", "111122223333"});
	ok(complete_request(provider_state, AwsMetadataRequestKind::rds_region,
		"us-east-1", std::move(late_result), 1),
		"obsolete provider callback can still reach the completion sink safely");
	ok(manager.snapshot()->find(10, east_one, 3306) == nullptr,
		"completion from an obsolete generation cannot repopulate removed policy state");

	manager.set_enabled(false);
	ok(wait_until([&] {
		const auto current = manager.snapshot();
		const auto* entry = lookup(current, 12,
			"db-new.abcdefghijkl.us-east-1.rds.amazonaws.com");
		return entry && entry->status == AwsLocalityMetadataStatus::disabled &&
			entry->multiplier == 1.0;
	}), "disabling the master switch retains neutral diagnostic rows");
	const size_t requests_while_disabled = requests_copy(provider_state).size();
	manager.request_refresh();
	std::this_thread::yield();
	ok(requests_copy(provider_state).size() == requests_while_disabled,
		"disabled manager does not dispatch provider work");

	manager.set_enabled(true);
	ok(wait_for_request_count(provider_state, requests_while_disabled + 2),
		"re-enabling resumes local and regional discovery");
	manager.shutdown();
	const auto shutdown_snapshot = manager.snapshot();
	ok(lookup(shutdown_snapshot, 12,
		"db-new.abcdefghijkl.us-east-1.rds.amazonaws.com") != nullptr,
		"manager shutdown retains its final neutral diagnostic snapshot");

	std::atomic<bool> global_shutdown_done { false };
	auto held_lease = acquire_global_aws_metadata_provider();
	std::thread shutdown_thread([&] {
		shutdown_global_aws_metadata_provider();
		global_shutdown_done.store(true);
	});
	ok(wait_until([&] {
		return !acquire_global_aws_metadata_provider();
	}) && !global_shutdown_done.load(),
		"global shutdown rejects new leases while waiting for an active lease");
	held_lease = {};
	shutdown_thread.join();
	ok(global_shutdown_done.load(),
		"global shutdown completes after the final provider lease drains");
	ok(provider_state->shut_down && provider_state->destroyed,
		"provider shutdown and destruction occur after leases drain");

	MySQLAwsLocalityManager absent_provider_manager(manager_config);
	const auto absent_endpoint = "db-absent.abcdefghijkl.us-east-1.rds.amazonaws.com";
	auto absent_hostgroup =
		make_hostgroup(20, 2.0, 4.0, 300, 1800, {absent_endpoint});
	absent_hostgroup.backends[0].configured_weight = 37;
	absent_provider_manager.configure({std::move(absent_hostgroup)});
	absent_provider_manager.set_enabled(true);
	ok(wait_until([&] {
		const auto current = absent_provider_manager.snapshot();
		const auto* entry = lookup(current, 20, absent_endpoint);
		return entry && entry->status == AwsLocalityMetadataStatus::error &&
			entry->failure_category == "provider_unavailable";
	}), "missing plugin provider is reported with a fixed neutral category");
	const auto absent_snapshot = absent_provider_manager.snapshot();
	const auto* absent_entry = lookup(absent_snapshot, 20, absent_endpoint);
	ok(absent_entry != nullptr && absent_entry->configured_weight == 37 &&
		absent_entry->multiplier == 1.0 &&
		absent_snapshot->effective_weight(20, absent_endpoint, 3306, 37) == 37,
		"missing provider preserves configured and effective neutral weights");

	auto replacement_state = std::make_shared<FakeProviderState>();
	ok(install_global_aws_metadata_provider(
		new FakeProvider(replacement_state), destroy_fake_provider, nullptr),
		"provider registry accepts a replacement after complete shutdown");
	absent_provider_manager.request_refresh();
	ok(wait_for_request_count(replacement_state, 2),
		"manager acquires the replacement provider on its next refresh");
	absent_provider_manager.shutdown();

	MySQLAwsLocalityManager concurrent_manager(manager_config);
	std::vector<AwsLocalityHostgroupConfig> concurrent_hostgroups;
	concurrent_hostgroups.reserve(100);
	std::vector<std::string> concurrent_regions;
	std::vector<std::string> concurrent_endpoints;
	for (uint32_t index = 1; index <= 100; ++index) {
		const std::string region = "us-test-" + std::to_string(index);
		const std::string endpoint = "db-" + std::to_string(index) +
			".abcdefghijkl." + region + ".rds.amazonaws.com";
		AwsLocalityHostgroupConfig hostgroup;
		hostgroup.hostgroup_id = 100 + index;
		hostgroup.policy = {true, 2.0, 4.0, 300, 1800};
		hostgroup.backends.push_back(recognize_rds_endpoint(
			hostgroup.hostgroup_id, endpoint, 3306));
		concurrent_regions.push_back(region);
		concurrent_endpoints.push_back(endpoint);
		concurrent_hostgroups.push_back(std::move(hostgroup));
	}
	concurrent_manager.configure(std::move(concurrent_hostgroups));
	concurrent_manager.set_enabled(true);
	ok(wait_for_request_count(replacement_state, 103),
		"100-Region fixture publishes one request per distinct Region");
	AwsMetadataResult concurrent_local;
	concurrent_local.status = AwsMetadataStatus::ok;
	concurrent_local.local = {"us-test-1", "us-test-1a", "111122223333"};
	complete_request(replacement_state, AwsMetadataRequestKind::local_location,
		"", std::move(concurrent_local), 1);
	std::atomic<size_t> posted_completions { 0 };
	std::vector<std::thread> producers;
	producers.reserve(100);
	for (size_t index = 0; index < 100; ++index) {
		producers.emplace_back([&, index] {
			AwsMetadataResult result;
			result.status = AwsMetadataStatus::ok;
			result.endpoints.push_back({concurrent_endpoints[index], 3306,
				AwsEndpointType::instance, concurrent_regions[index],
				concurrent_regions[index] + "a", "111122223333"});
			if (complete_request(replacement_state,
				AwsMetadataRequestKind::rds_region, concurrent_regions[index],
				std::move(result))) {
				posted_completions.fetch_add(1);
			}
		});
	}
	for (auto& producer : producers) {
		producer.join();
	}
	ok(posted_completions.load() == 100,
		"100 concurrent completion producers all reach the shared sink");
	ok(wait_until([&] {
		const auto current = concurrent_manager.snapshot();
		return current->entries.size() == 100 &&
			std::all_of(current->entries.begin(), current->entries.end(),
				[](const auto& item) {
					return item.second.status == AwsLocalityMetadataStatus::fresh;
				});
	}), "concurrent completions publish one consistent immutable snapshot");
	concurrent_manager.shutdown();

	const size_t startup_request_count = requests_copy(replacement_state).size();
	MySQLAwsLocalityManager startup_manager(manager_config);
	startup_manager.set_enabled(true);
	startup_manager.configure({
		make_hostgroup(250, 2.0, 4.0, 300, 1800,
			{"db-startup.abcdefghijkl.us-east-2.rds.amazonaws.com"}),
	});
	ok(wait_for_request_count(replacement_state, startup_request_count + 2),
		"configuration starts discovery when the master switch was enabled first");
	startup_manager.shutdown();

	std::mutex completion_hook_mutex;
	std::condition_variable completion_hook_cv;
	bool completion_hook_entered = false;
	bool release_completion = false;
	AwsLocalityManagerConfig blocking_config = manager_config;
	blocking_config.before_completion = [&] {
		std::unique_lock<std::mutex> lock(completion_hook_mutex);
		completion_hook_entered = true;
		completion_hook_cv.notify_all();
		completion_hook_cv.wait_for(lock, 2s, [&] { return release_completion; });
	};
	MySQLAwsLocalityManager blocking_manager(blocking_config);
	const auto blocking_endpoint = "db-block.abcdefghijkl.ap-block-1.rds.amazonaws.com";
	const size_t blocking_request_count = requests_copy(replacement_state).size();
	blocking_manager.configure({
		make_hostgroup(300, 2.0, 4.0, 300, 1800, {blocking_endpoint}),
	});
	blocking_manager.set_enabled(true);
	ok(wait_for_request_count(replacement_state, blocking_request_count + 2),
		"callback-shutdown fixture dispatches local and regional requests");
	std::atomic<bool> callback_returned { false };
	std::thread callback_thread([&] {
		AwsMetadataResult result;
		result.status = AwsMetadataStatus::ok;
		result.local = {"ap-block-1", "ap-block-1a", "111122223333"};
		complete_request_after(replacement_state,
			AwsMetadataRequestKind::local_location, "", std::move(result),
			blocking_request_count);
		callback_returned.store(true);
	});
	{
		std::unique_lock<std::mutex> lock(completion_hook_mutex);
		if (!completion_hook_cv.wait_for(lock, 2s, [&] { return completion_hook_entered; })) {
			BAIL_OUT("completion hook did not enter before shutdown fixture deadline");
		}
	}
	std::mutex shutdown_mutex;
	std::condition_variable shutdown_cv;
	bool shutdown_done = false;
	std::thread blocking_shutdown([&] {
		blocking_manager.shutdown();
		std::lock_guard<std::mutex> lock(shutdown_mutex);
		shutdown_done = true;
		shutdown_cv.notify_all();
	});
	bool shutdown_finished_early = false;
	{
		std::unique_lock<std::mutex> lock(shutdown_mutex);
		shutdown_finished_early = shutdown_cv.wait_for(lock, 100ms, [&] {
			return shutdown_done;
		});
	}
	ok(!shutdown_finished_early,
		"manager shutdown waits for an active completion callback");
	{
		std::lock_guard<std::mutex> lock(completion_hook_mutex);
		release_completion = true;
		completion_hook_cv.notify_all();
	}
	callback_thread.join();
	blocking_shutdown.join();
	ok(callback_returned.load() && shutdown_done,
		"callback and shutdown finish without accessing detached manager state");

	AwsLocalityManagerConfig bounded_disable_config = manager_config;
	bounded_disable_config.disable_wait_timeout = 50ms;
	MySQLAwsLocalityManager bounded_disable_manager(bounded_disable_config);
	{
		std::lock_guard<std::mutex> lock(replacement_state->mutex);
		replacement_state->block_requests = true;
		replacement_state->request_entered = false;
		replacement_state->release_requests = false;
	}
	bounded_disable_manager.configure({
		make_hostgroup(400, 2.0, 4.0, 300, 1800,
			{"db-disable.abcdefghijkl.us-east-2.rds.amazonaws.com"}),
	});
	bounded_disable_manager.set_enabled(true);
	{
		std::unique_lock<std::mutex> lock(replacement_state->mutex);
		if (!replacement_state->cv.wait_for(lock, 2s, [&] {
				return replacement_state->request_entered;
			})) {
			BAIL_OUT("provider request did not enter bounded-disable fixture");
		}
	}
	std::mutex disable_mutex;
	std::condition_variable disable_cv;
	bool disable_returned = false;
	std::thread disable_thread([&] {
		bounded_disable_manager.set_enabled(false);
		std::lock_guard<std::mutex> lock(disable_mutex);
		disable_returned = true;
		disable_cv.notify_all();
	});
	bool disable_returned_within_bound = false;
	{
		std::unique_lock<std::mutex> lock(disable_mutex);
		disable_returned_within_bound = disable_cv.wait_for(lock, 250ms, [&] {
			return disable_returned;
		});
	}
	ok(disable_returned_within_bound,
		"disabling locality does not block admin on a stalled provider call");
	{
		std::lock_guard<std::mutex> lock(replacement_state->mutex);
		replacement_state->release_requests = true;
		replacement_state->cv.notify_all();
	}
	disable_thread.join();
	bounded_disable_manager.shutdown();

	MySQLAwsLocalityManager invalid_identity_manager(manager_config);
	AwsLocalityHostgroupConfig invalid_identity_hostgroup;
	invalid_identity_hostgroup.hostgroup_id = 500;
	invalid_identity_hostgroup.policy = {true, 2.0, 4.0, 300, 1800};
	AwsEndpointCandidate ipv6_identity;
	ipv6_identity.hostgroup_id = 500;
	ipv6_identity.hostname = "fe80::1";
	ipv6_identity.port = 3306;
	AwsEndpointCandidate path_identity = ipv6_identity;
	path_identity.hostname = "bad/name";
	invalid_identity_hostgroup.backends.emplace_back(ipv6_identity, 7);
	invalid_identity_hostgroup.backends.emplace_back(path_identity, 9);
	invalid_identity_manager.configure({std::move(invalid_identity_hostgroup)});
	const auto invalid_identity_snapshot = invalid_identity_manager.snapshot();
	const auto* ipv6_entry = invalid_identity_snapshot->find(500, "fe80::1", 3306);
	const auto* path_entry = invalid_identity_snapshot->find(500, "bad/name", 3306);
	ok(invalid_identity_snapshot->entries.size() == 2 && ipv6_entry != nullptr &&
		path_entry != nullptr && ipv6_entry->configured_weight == 7 &&
		path_entry->configured_weight == 9,
		"rejected DNS spellings retain distinct snapshot identities");
	invalid_identity_manager.shutdown();

	const size_t lease_drain_request_count = requests_copy(replacement_state).size();
	MySQLAwsLocalityManager lease_drain_manager(manager_config);
	lease_drain_manager.configure({
		make_hostgroup(600, 2.0, 4.0, 300, 1800,
			{"db-drain.abcdefghijkl.us-east-2.rds.amazonaws.com"}),
	});
	lease_drain_manager.set_enabled(true);
	ok(wait_for_request_count(replacement_state, lease_drain_request_count + 2),
		"enabled manager retains the installed provider during discovery");
	std::atomic<bool> unload_done { false };
	std::thread unload_thread([&] {
		shutdown_global_aws_metadata_provider();
		unload_done.store(true);
	});
	ok(wait_until([&] {
		return !acquire_global_aws_metadata_provider();
	}) && !unload_done.load(),
		"provider unload rejects new leases while the manager lease is active");
	lease_drain_manager.set_enabled(false);
	unload_thread.join();
	ok(unload_done.load() && replacement_state->shut_down &&
		replacement_state->destroyed,
		"disabling locality drains the manager lease before provider destruction");
	const size_t requests_after_unload = requests_copy(replacement_state).size();
	lease_drain_manager.shutdown();
	lease_drain_manager.set_enabled(true);
	lease_drain_manager.request_refresh();
	std::this_thread::sleep_for(20ms);
	ok(requests_copy(replacement_state).size() == requests_after_unload,
		"manager shutdown leaves no locality worker able to restart provider work");

	return exit_status();
}
