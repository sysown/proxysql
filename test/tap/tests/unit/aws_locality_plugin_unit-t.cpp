#include "tap.h"

#include "aws_locality_provider.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace std::chrono_literals;

namespace {

class CapturingSink final : public AwsMetadataCompletionSink {
public:
	void post(AwsMetadataCompletion&& completion) override {
		std::lock_guard<std::mutex> lock(mutex_);
		completions_.push_back(std::move(completion));
		cv_.notify_all();
	}

	bool wait_for(size_t count) {
		std::unique_lock<std::mutex> lock(mutex_);
		return cv_.wait_for(lock, 2s, [&] { return completions_.size() >= count; });
	}

	std::vector<AwsMetadataCompletion> snapshot() const {
		std::lock_guard<std::mutex> lock(mutex_);
		return completions_;
	}

private:
	mutable std::mutex mutex_;
	std::condition_variable cv_;
	std::vector<AwsMetadataCompletion> completions_;
};

class BlockingBackend final : public AwsLocalityDiscoveryBackend {
public:
	AwsMetadataResult discover(
		const AwsMetadataRequest& request,
		const AwsLocalityCancelPredicate& cancelled) override {
		const int active = active_.fetch_add(1) + 1;
		int observed = max_active_.load();
		while (active > observed &&
			!max_active_.compare_exchange_weak(observed, active)) {}
		{
			std::unique_lock<std::mutex> lock(mutex_);
			started_.push_back(request.opaque_id);
			cv_.notify_all();
			cv_.wait(lock, [&] { return released_ || cancelled(); });
		}
		active_.fetch_sub(1);
		AwsMetadataResult result;
		result.status = cancelled() ? AwsMetadataStatus::cancelled : AwsMetadataStatus::ok;
		result.failure_category = "FAKE_SECRET_RAW_ERROR";
		result.local.region = request.region;
		return result;
	}

	bool wait_started(size_t count) {
		std::unique_lock<std::mutex> lock(mutex_);
		return cv_.wait_for(lock, 2s, [&] { return started_.size() >= count; });
	}

	void release() {
		std::lock_guard<std::mutex> lock(mutex_);
		released_ = true;
		cv_.notify_all();
	}

	int max_active() const { return max_active_.load(); }

private:
	std::atomic<int> active_ { 0 };
	std::atomic<int> max_active_ { 0 };
	std::mutex mutex_;
	std::condition_variable cv_;
	std::vector<uint64_t> started_;
	bool released_ { false };
};

class FakeImdsTransport final : public AwsImdsTransport {
public:
	AwsImdsResponse put_token(
		std::chrono::steady_clock::time_point,
		const AwsLocalityCancelPredicate&) override {
		++token_calls;
		return token;
	}

	AwsImdsResponse get_identity_document(
		const std::string& supplied_token,
		std::chrono::steady_clock::time_point,
		const AwsLocalityCancelPredicate&) override {
		++document_calls;
		seen_token = supplied_token;
		return document;
	}

	AwsImdsResponse token { true, 200, "imds-token" };
	AwsImdsResponse document { true, 200,
		R"({"region":"us-east-1","availabilityZone":"us-east-1b","accountId":"111122223333"})" };
	int token_calls { 0 };
	int document_calls { 0 };
	std::string seen_token;
};

class FakeRdsApi final : public AwsRdsDiscoveryApi {
public:
	AwsRdsInstancesPage describe_instances(
		const std::string&, const std::string& marker,
		std::chrono::steady_clock::time_point,
		const AwsLocalityCancelPredicate&) override {
		++instance_calls;
		if (marker.empty()) {
			AwsRdsInstancesPage page;
			page.status = AwsMetadataStatus::ok;
			page.next_marker = "instances-2";
			page.instances.push_back({
				"DB-ONE.ABCDEFGHIJKL.US-EAST-1.RDS.AMAZONAWS.COM.", 3306,
				"us-east-1a", "arn:aws:rds:us-east-1:111122223333:db:one"});
			page.instances.push_back({
				"missing-port.abcdefghijkl.us-east-1.rds.amazonaws.com", 0,
				"us-east-1a", "arn:aws:rds:us-east-1:111122223333:db:missing"});
			return page;
		}
		AwsRdsInstancesPage page;
		page.status = AwsMetadataStatus::ok;
		page.instances.push_back({
			"db-one.abcdefghijkl.us-east-1.rds.amazonaws.com", 3306,
			"us-east-1d", "arn:aws:rds:us-east-1:111122223333:db:one"});
		page.instances.push_back({
			"db-two.abcdefghijkl.us-east-1.rds.amazonaws.com", 3307,
			"us-east-1c", "arn:aws:rds:us-east-1:444455556666:db:two"});
		return page;
	}

	AwsRdsClustersPage describe_clusters(
		const std::string&, const std::string&,
		std::chrono::steady_clock::time_point,
		const AwsLocalityCancelPredicate&) override {
		++cluster_calls;
		AwsRdsClustersPage page;
		page.status = AwsMetadataStatus::ok;
		page.clusters.push_back({
			"cluster-one", "cluster-one.abcdefghijkl.us-east-1.rds.amazonaws.com",
			"cluster-ro-one.abcdefghijkl.us-east-1.rds.amazonaws.com", 3306,
			{"custom-one.abcdefghijkl.us-east-1.rds.amazonaws.com"},
			"arn:aws:rds:us-east-1:111122223333:cluster:cluster-one"});
		return page;
	}

	AwsRdsClusterEndpointsPage describe_cluster_endpoints(
		const std::string&, const std::string&,
		std::chrono::steady_clock::time_point,
		const AwsLocalityCancelPredicate&) override {
		++endpoint_calls;
		AwsRdsClusterEndpointsPage page;
		page.status = AwsMetadataStatus::ok;
		page.endpoints.push_back({
			"custom-two.abcdefghijkl.us-east-1.rds.amazonaws.com",
			"CUSTOM", "cluster-one"});
		return page;
	}

	int instance_calls { 0 };
	int cluster_calls { 0 };
	int endpoint_calls { 0 };
};

const AwsMetadataEndpoint* find_endpoint(
	const AwsMetadataResult& result,
	const std::string& hostname,
	uint16_t port) {
	for (const auto& endpoint : result.endpoints) {
		if (endpoint.hostname == hostname && endpoint.port == port) return &endpoint;
	}
	return nullptr;
}

} // namespace

int main() {
	plan(30);

	auto backend = std::make_shared<BlockingBackend>();
	AwsSdkMetadataProvider provider(backend, AwsMetadataProviderConfig {2, 3});
	auto sink = std::make_shared<CapturingSink>();
	std::vector<AwsMetadataRequestHandle> handles;
	for (uint64_t id = 1; id <= 4; ++id) {
		AwsMetadataRequest request;
		request.kind = AwsMetadataRequestKind::rds_region;
		request.opaque_id = id;
		request.generation = 17;
		request.region = "us-east-1";
		request.deadline = std::chrono::steady_clock::now() + 2s;
		handles.push_back(provider.request(request, sink));
	}
	ok(backend->wait_started(2), "provider starts its two bounded workers");
	ok(backend->max_active() == 2, "provider never exceeds two concurrent discoveries");
	ok(handles[0].value != 0 && handles[1].value != 0 && handles[2].value != 0,
		"accepted work receives cancellable handles");
	ok(handles[3].value == 0 && sink->wait_for(1),
		"bounded queue rejects excess work immediately");
	auto completions = sink->snapshot();
	ok(completions.size() >= 1 && completions[0].opaque_id == 4 && completions[0].generation == 17 &&
		completions[0].result.status == AwsMetadataStatus::throttled,
		"queue rejection preserves request identity with a fixed category");
	ok(completions.size() >= 1 && completions[0].result.failure_category == "throttled" &&
		completions[0].result.failure_category.find("FAKE_SECRET") == std::string::npos,
		"provider never forwards a backend's raw failure text");
	provider.cancel(handles[2]);
	backend->release();
	ok(sink->wait_for(3), "accepted non-cancelled work completes");
	completions = sink->snapshot();
	bool saw_one = false;
	bool saw_two = false;
	bool saw_three = false;
	for (const auto& completion : completions) {
		saw_one = saw_one || (completion.opaque_id == 1 && completion.generation == 17);
		saw_two = saw_two || (completion.opaque_id == 2 && completion.generation == 17);
		saw_three = saw_three || completion.opaque_id == 3;
	}
	ok(saw_one && saw_two && !saw_three,
		"queued cancellation suppresses its callback without affecting other work");

	AwsMetadataRequest expired;
	expired.opaque_id = 9;
	expired.generation = 18;
	expired.deadline = std::chrono::steady_clock::now() - 1ms;
	ok(provider.request(expired, sink).value == 0 && sink->wait_for(4),
		"already-expired work is rejected without entering the backend");
	completions = sink->snapshot();
	ok(!completions.empty() && completions.back().opaque_id == 9 &&
		completions.back().result.status == AwsMetadataStatus::timeout &&
		completions.back().result.failure_category == "timeout",
		"deadline rejection is normalized and preserves identity");
	provider.shutdown();
	ok(provider.request(expired, sink).value == 0,
		"shutdown permanently rejects new metadata work");

	const std::unordered_map<std::string, std::string> env {
		{"AWS_REGION", "us-west-2"},
		{"AWS_DEFAULT_REGION", "eu-west-1"},
		{"AWS_AVAILABILITY_ZONE", "us-west-2b"},
		{"AWS_ACCOUNT_ID", "999900001111"},
	};
	const auto env_getter = [&](const char* name) {
		const auto found = env.find(name);
		return found == env.end() ? std::string() : found->second;
	};
	AwsLocalLocation environment = aws_locality_environment_location(env_getter);
	ok(environment.region == "us-west-2",
		"AWS_REGION takes precedence over AWS_DEFAULT_REGION");
	ok(environment.availability_zone == "us-west-2b" &&
		environment.account_id == "999900001111",
		"environment fallback retains optional AZ and account assertion");
	const auto partial_getter = [](const char* name) {
		return std::string(name) == "AWS_DEFAULT_REGION" ? "eu-central-1" : "";
	};
	environment = aws_locality_environment_location(partial_getter);
	ok(environment.region == "eu-central-1" &&
		environment.availability_zone.empty() && environment.account_id.empty(),
		"partial environment fallback keeps Region while leaving AZ/account unknown");

	auto imds = std::make_shared<FakeImdsTransport>();
	AwsLocalityLocalDiscovery local_discovery(imds, env_getter);
	const auto never_cancelled = [] { return false; };
	AwsMetadataResult local_result = local_discovery.discover(
		std::chrono::steady_clock::now() + 1s, never_cancelled);
	ok(local_result.status == AwsMetadataStatus::ok &&
		local_result.local.region == "us-east-1" &&
		local_result.local.availability_zone == "us-east-1b" &&
		local_result.local.account_id == "111122223333",
		"IMDSv2 identity document supplies Region, AZ, and account");
	ok(imds->token_calls == 1 && imds->document_calls == 1 &&
		imds->seen_token == "imds-token",
		"IMDSv2 token is required for the identity-document request");
	imds->token = {false, 0, "FAKE_SECRET_TRANSPORT_ERROR"};
	local_result = local_discovery.discover(
		std::chrono::steady_clock::now() + 1s, never_cancelled);
	ok(local_result.status == AwsMetadataStatus::ok &&
		local_result.local.region == "us-west-2",
		"IMDS unavailability falls back to process environment");
	ok(local_result.failure_category.empty(),
		"successful environment fallback exposes no IMDS transport detail");
	imds->token = {true, 200, "imds-token"};
	imds->document = {true, 200, "{not-json-FAKE_SECRET}"};
	AwsLocalityLocalDiscovery invalid_local(imds,
		[](const char*) { return std::string(); });
	local_result = invalid_local.discover(
		std::chrono::steady_clock::now() + 1s, never_cancelled);
	ok(local_result.status == AwsMetadataStatus::invalid_response &&
		local_result.failure_category == "invalid_response",
		"malformed IMDS data without fallback returns only a fixed category");

	auto rds_api = std::make_shared<FakeRdsApi>();
	AwsLocalityRdsDiscovery rds_discovery(rds_api);
	AwsMetadataRequest rds_request;
	rds_request.kind = AwsMetadataRequestKind::rds_region;
	rds_request.region = "us-east-1";
	rds_request.deadline = std::chrono::steady_clock::now() + 2s;
	AwsMetadataResult rds_result = rds_discovery.discover(rds_request, never_cancelled);
	ok(rds_result.status == AwsMetadataStatus::ok,
		"paginated RDS discovery completes successfully");
	ok(rds_api->instance_calls == 2 && rds_api->cluster_calls == 1 &&
		rds_api->endpoint_calls == 1,
		"RDS instances, clusters, and cluster endpoints are all paginated");
	const auto* instance_one = find_endpoint(rds_result,
		"db-one.abcdefghijkl.us-east-1.rds.amazonaws.com", 3306);
	ok(instance_one != nullptr && instance_one->endpoint_type == AwsEndpointType::instance &&
		instance_one->availability_zone == "us-east-1d" &&
		instance_one->account_id == "111122223333",
		"later duplicate instance metadata replaces the earlier page after failover");
	size_t instance_one_count = 0;
	for (const auto& endpoint : rds_result.endpoints) {
		if (endpoint.hostname == "db-one.abcdefghijkl.us-east-1.rds.amazonaws.com" &&
			endpoint.port == 3306) ++instance_one_count;
	}
	ok(instance_one_count == 1,
		"duplicate paginated endpoint metadata is emitted exactly once");
	const auto* instance_two = find_endpoint(rds_result,
		"db-two.abcdefghijkl.us-east-1.rds.amazonaws.com", 3307);
	ok(instance_two != nullptr && instance_two->account_id == "444455556666",
		"later instance pages and cross-account identities are retained");
	ok(find_endpoint(rds_result,
		"missing-port.abcdefghijkl.us-east-1.rds.amazonaws.com", 0) == nullptr,
		"instance metadata without a valid port is rejected");
	const auto* cluster = find_endpoint(rds_result,
		"cluster-one.abcdefghijkl.us-east-1.rds.amazonaws.com", 3306);
	const auto* reader = find_endpoint(rds_result,
		"cluster-ro-one.abcdefghijkl.us-east-1.rds.amazonaws.com", 3306);
	ok(cluster != nullptr && cluster->endpoint_type == AwsEndpointType::cluster &&
		reader != nullptr && reader->endpoint_type == AwsEndpointType::reader &&
		cluster->availability_zone.empty() && reader->availability_zone.empty(),
		"cluster writer and reader endpoints have Region/account but no stable AZ");
	const auto* custom_one = find_endpoint(rds_result,
		"custom-one.abcdefghijkl.us-east-1.rds.amazonaws.com", 0);
	const auto* custom_two = find_endpoint(rds_result,
		"custom-two.abcdefghijkl.us-east-1.rds.amazonaws.com", 0);
	ok(custom_one != nullptr && custom_two != nullptr &&
		custom_one->endpoint_type == AwsEndpointType::custom &&
		custom_two->endpoint_type == AwsEndpointType::custom &&
		custom_two->account_id == "111122223333",
		"custom endpoints from both cluster APIs inherit cluster account and no port");

	class RepeatingApi final : public AwsRdsDiscoveryApi {
	public:
		AwsRdsInstancesPage describe_instances(const std::string&, const std::string&,
			std::chrono::steady_clock::time_point,
			const AwsLocalityCancelPredicate&) override {
			AwsRdsInstancesPage page;
			page.status = AwsMetadataStatus::ok;
			page.next_marker = "same";
			return page;
		}
		AwsRdsClustersPage describe_clusters(const std::string&, const std::string&,
			std::chrono::steady_clock::time_point,
			const AwsLocalityCancelPredicate&) override { return {}; }
		AwsRdsClusterEndpointsPage describe_cluster_endpoints(
			const std::string&, const std::string&,
			std::chrono::steady_clock::time_point,
			const AwsLocalityCancelPredicate&) override { return {}; }
	};
	AwsLocalityRdsDiscovery repeating(std::make_shared<RepeatingApi>());
	rds_result = repeating.discover(rds_request, never_cancelled);
	ok(rds_result.status == AwsMetadataStatus::invalid_response &&
		rds_result.failure_category == "invalid_response",
		"repeated pagination markers fail with a fixed category");

	class ShutdownBackend final : public AwsLocalityDiscoveryBackend {
	public:
		AwsMetadataResult discover(const AwsMetadataRequest&,
			const AwsLocalityCancelPredicate& cancelled) override {
			started.store(true);
			while (!cancelled()) std::this_thread::yield();
			AwsMetadataResult result;
			result.status = AwsMetadataStatus::cancelled;
			return result;
		}
		std::atomic<bool> started { false };
	};
	auto shutdown_backend = std::make_shared<ShutdownBackend>();
	AwsSdkMetadataProvider shutdown_provider(
		shutdown_backend, AwsMetadataProviderConfig {2, 8});
	auto shutdown_sink = std::make_shared<CapturingSink>();
	AwsMetadataRequest shutdown_request;
	shutdown_request.opaque_id = 44;
	shutdown_request.deadline = std::chrono::steady_clock::now() + 2s;
	shutdown_provider.request(shutdown_request, shutdown_sink);
	while (!shutdown_backend->started.load()) std::this_thread::yield();
	std::thread shutdown_one([&] { shutdown_provider.shutdown(); });
	std::thread shutdown_two([&] { shutdown_provider.shutdown(); });
	shutdown_one.join();
	shutdown_two.join();
	ok(shutdown_sink->snapshot().empty(),
		"concurrent shutdown is idempotent, cancels work, and publishes no late callback");
	ok(shutdown_provider.request(shutdown_request, shutdown_sink).value == 0,
		"post-shutdown requests remain rejected");

	return exit_status();
}
