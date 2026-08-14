#include "aws_locality_provider.h"

#include "json.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>
#include <utility>

#ifdef PROXYSQL_AWS_SDK_PROVIDER
#include "curl/curl.h"

#include <aws/core/client/CoreErrors.h>
#include <aws/core/client/DefaultRetryStrategy.h>
#include <aws/core/http/HttpResponse.h>
#include <aws/rds/RDSClient.h>
#include <aws/rds/model/DescribeDBClusterEndpointsRequest.h>
#include <aws/rds/model/DescribeDBClustersRequest.h>
#include <aws/rds/model/DescribeDBInstancesRequest.h>
#endif

using nlohmann::json;

namespace {

const char* fixed_failure_category(AwsMetadataStatus status) {
	switch (status) {
		case AwsMetadataStatus::ok: return "";
		case AwsMetadataStatus::provider_unavailable: return "provider_unavailable";
		case AwsMetadataStatus::access_denied: return "access_denied";
		case AwsMetadataStatus::throttled: return "throttled";
		case AwsMetadataStatus::imds_unavailable: return "imds_unavailable";
		case AwsMetadataStatus::timeout: return "timeout";
		case AwsMetadataStatus::cancelled: return "cancelled";
		case AwsMetadataStatus::invalid_response: return "invalid_response";
		case AwsMetadataStatus::shutdown: return "cancelled";
	}
	return "invalid_response";
}

AwsMetadataResult fixed_failure(AwsMetadataStatus status) {
	AwsMetadataResult result;
	result.status = status;
	result.failure_category = fixed_failure_category(status);
	return result;
}

void normalize_failure(AwsMetadataResult& result) {
	result.failure_category = fixed_failure_category(result.status);
	if (result.status != AwsMetadataStatus::ok) {
		result.local = {};
		result.endpoints.clear();
	}
}

bool valid_location_value(const std::string& value, size_t maximum) {
	if (value.empty() || value.size() > maximum) return false;
	for (const unsigned char character : value) {
		if (!(std::isalnum(character) || character == '-')) return false;
	}
	return true;
}

bool valid_account_id(const std::string& value) {
	return value.size() == 12 && std::all_of(value.begin(), value.end(),
		[](unsigned char character) { return std::isdigit(character); });
}

std::string account_from_rds_arn(
	const std::string& arn,
	const std::string& expected_region) {
	size_t begin = 0;
	std::string fields[6];
	for (size_t field = 0; field < 5; ++field) {
		const size_t end = arn.find(':', begin);
		if (end == std::string::npos) return {};
		fields[field] = arn.substr(begin, end - begin);
		begin = end + 1;
	}
	fields[5] = arn.substr(begin);
	if (fields[0] != "arn" || fields[2] != "rds" ||
		fields[3] != expected_region || !valid_account_id(fields[4])) {
		return {};
	}
	return fields[4];
}

AwsEndpointType endpoint_type(const std::string& input) {
	std::string value;
	value.reserve(input.size());
	for (const unsigned char character : input) {
		value.push_back(static_cast<char>(std::toupper(character)));
	}
	if (value == "WRITER") return AwsEndpointType::cluster;
	if (value == "READER") return AwsEndpointType::reader;
	if (value == "CUSTOM") return AwsEndpointType::custom;
	return AwsEndpointType::unknown;
}

bool expired(
	std::chrono::steady_clock::time_point deadline,
	const AwsLocalityCancelPredicate& cancelled,
	AwsMetadataResult& result) {
	if (cancelled()) {
		result = fixed_failure(AwsMetadataStatus::cancelled);
		return true;
	}
	if (std::chrono::steady_clock::now() >= deadline) {
		result = fixed_failure(AwsMetadataStatus::timeout);
		return true;
	}
	return false;
}

} // namespace

class AwsSdkMetadataProvider::Impl {
public:
	struct Job {
		AwsMetadataRequestHandle handle;
		AwsMetadataRequest request;
		std::weak_ptr<AwsMetadataCompletionSink> sink;
		std::atomic<bool> cancelled { false };
	};

	Impl(
		std::shared_ptr<AwsLocalityDiscoveryBackend> backend,
		AwsMetadataProviderConfig config)
		: backend_(std::move(backend)), config_(std::move(config)) {
		if (config_.worker_count == 0) config_.worker_count = 1;
		if (config_.worker_count > 2) config_.worker_count = 2;
		if (config_.max_pending < config_.worker_count) {
			config_.max_pending = config_.worker_count;
		}
		workers_.reserve(config_.worker_count);
		for (size_t i = 0; i < config_.worker_count; ++i) {
			workers_.emplace_back([this] { worker_loop(); });
		}
	}

	~Impl() { shutdown(); }

	AwsMetadataRequestHandle request(
		const AwsMetadataRequest& request,
		std::weak_ptr<AwsMetadataCompletionSink> sink) {
		AwsMetadataResult immediate;
		bool deliver = false;
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (stopping_ || backend_ == nullptr) return {};
			if (config_.steady_clock() >= request.deadline) {
				immediate = fixed_failure(AwsMetadataStatus::timeout);
				deliver = true;
			} else if (jobs_.size() >= config_.max_pending) {
				immediate = fixed_failure(AwsMetadataStatus::throttled);
				deliver = true;
			} else {
				auto job = std::make_shared<Job>();
				job->handle.value = next_handle_++;
				job->request = request;
				job->sink = std::move(sink);
				jobs_.emplace(job->handle.value, job);
				queue_.push_back(job);
				cv_.notify_one();
				return job->handle;
			}
		}
		if (deliver) deliver_immediate(request, std::move(sink), std::move(immediate));
		return {};
	}

	void cancel(AwsMetadataRequestHandle handle) {
		if (handle.value == 0) return;
		std::lock_guard<std::mutex> lock(mutex_);
		const auto found = jobs_.find(handle.value);
		if (found != jobs_.end()) found->second->cancelled.store(true);
		cv_.notify_all();
	}

	void shutdown() {
		{
			std::unique_lock<std::mutex> lock(mutex_);
			if (shutdown_complete_) return;
			if (shutdown_started_) {
				cv_.wait(lock, [&] { return shutdown_complete_; });
				return;
			}
			shutdown_started_ = true;
			stopping_ = true;
			for (const auto& item : jobs_) item.second->cancelled.store(true);
			cv_.notify_all();
		}
		for (auto& worker : workers_) {
			if (worker.joinable()) worker.join();
		}
		{
			std::unique_lock<std::mutex> lock(mutex_);
			cv_.wait(lock, [&] { return active_callbacks_ == 0; });
			jobs_.clear();
			queue_.clear();
			shutdown_complete_ = true;
			cv_.notify_all();
		}
	}

private:
	void deliver_immediate(
		const AwsMetadataRequest& request,
		std::weak_ptr<AwsMetadataCompletionSink> weak_sink,
		AwsMetadataResult result) {
		auto sink = weak_sink.lock();
		if (!sink) return;
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (stopping_) return;
			++active_callbacks_;
		}
		AwsMetadataCompletion completion;
		completion.opaque_id = request.opaque_id;
		completion.generation = request.generation;
		completion.result = std::move(result);
		try {
			sink->post(std::move(completion));
		} catch (...) {
			// Plugin callbacks must not escape across the provider ABI boundary.
		}
		{
			std::lock_guard<std::mutex> lock(mutex_);
			--active_callbacks_;
			cv_.notify_all();
		}
	}

	void worker_loop() {
		for (;;) {
			std::shared_ptr<Job> job;
			{
				std::unique_lock<std::mutex> lock(mutex_);
				cv_.wait(lock, [&] { return stopping_ || !queue_.empty(); });
				if (stopping_ && queue_.empty()) return;
				job = queue_.front();
				queue_.pop_front();
			}

			AwsMetadataResult result;
			if (job->cancelled.load()) {
				result = fixed_failure(AwsMetadataStatus::cancelled);
			} else if (config_.steady_clock() >= job->request.deadline) {
				result = fixed_failure(AwsMetadataStatus::timeout);
			} else {
				try {
					result = backend_->discover(job->request,
						[job, this] {
							return job->cancelled.load() || stopping_.load();
						});
				} catch (...) {
					result = fixed_failure(AwsMetadataStatus::provider_unavailable);
				}
				if (config_.steady_clock() >= job->request.deadline) {
					result = fixed_failure(AwsMetadataStatus::timeout);
				}
			}
			normalize_failure(result);

			std::shared_ptr<AwsMetadataCompletionSink> sink;
			{
				std::lock_guard<std::mutex> lock(mutex_);
				jobs_.erase(job->handle.value);
				if (!stopping_ && !job->cancelled.load()) {
					sink = job->sink.lock();
					if (sink) ++active_callbacks_;
				}
			}
			if (sink) {
				AwsMetadataCompletion completion;
				completion.opaque_id = job->request.opaque_id;
				completion.generation = job->request.generation;
				completion.result = std::move(result);
				try {
					sink->post(std::move(completion));
				} catch (...) {
					// Keep worker and shutdown bookkeeping intact on a bad consumer.
				}
				std::lock_guard<std::mutex> lock(mutex_);
				--active_callbacks_;
				cv_.notify_all();
			}
		}
	}

	std::shared_ptr<AwsLocalityDiscoveryBackend> backend_;
	AwsMetadataProviderConfig config_;
	std::mutex mutex_;
	std::condition_variable cv_;
	std::deque<std::shared_ptr<Job>> queue_;
	std::unordered_map<uint64_t, std::shared_ptr<Job>> jobs_;
	std::vector<std::thread> workers_;
	std::atomic<bool> stopping_ { false };
	bool shutdown_started_ { false };
	bool shutdown_complete_ { false };
	uint64_t next_handle_ { 1 };
	size_t active_callbacks_ { 0 };
};

AwsSdkMetadataProvider::AwsSdkMetadataProvider(
	std::shared_ptr<AwsLocalityDiscoveryBackend> backend,
	AwsMetadataProviderConfig config)
	: impl_(new Impl(std::move(backend), std::move(config))) {}

AwsSdkMetadataProvider::~AwsSdkMetadataProvider() = default;

AwsMetadataRequestHandle AwsSdkMetadataProvider::request(
	const AwsMetadataRequest& request,
	std::weak_ptr<AwsMetadataCompletionSink> sink) {
	return impl_->request(request, std::move(sink));
}

void AwsSdkMetadataProvider::cancel(AwsMetadataRequestHandle handle) {
	impl_->cancel(handle);
}

void AwsSdkMetadataProvider::shutdown() {
	impl_->shutdown();
}

AwsLocalLocation aws_locality_environment_location(
	const AwsLocalityEnvironmentGetter& getenv_value) {
	AwsLocalLocation location;
	if (!getenv_value) return location;
	location.region = getenv_value("AWS_REGION");
	if (!valid_location_value(location.region, 64)) {
		location.region = getenv_value("AWS_DEFAULT_REGION");
	}
	if (!valid_location_value(location.region, 64)) {
		location.region.clear();
		return location;
	}
	location.availability_zone = getenv_value("AWS_AVAILABILITY_ZONE");
	if (!valid_location_value(location.availability_zone, 64)) {
		location.availability_zone.clear();
	}
	location.account_id = getenv_value("AWS_ACCOUNT_ID");
	if (!valid_account_id(location.account_id)) location.account_id.clear();
	return location;
}

AwsLocalityLocalDiscovery::AwsLocalityLocalDiscovery(
	std::shared_ptr<AwsImdsTransport> transport,
	AwsLocalityEnvironmentGetter getenv_value)
	: transport_(std::move(transport)), getenv_value_(std::move(getenv_value)) {}

AwsMetadataResult AwsLocalityLocalDiscovery::discover(
	std::chrono::steady_clock::time_point deadline,
	const AwsLocalityCancelPredicate& cancelled) const {
	AwsMetadataResult result;
	if (expired(deadline, cancelled, result)) return result;

	auto fallback = [&](AwsMetadataStatus failure_status) {
		AwsMetadataResult fallback_result;
		fallback_result.local = aws_locality_environment_location(getenv_value_);
		if (!fallback_result.local.region.empty()) {
			fallback_result.status = AwsMetadataStatus::ok;
			return fallback_result;
		}
		return fixed_failure(failure_status);
	};

	if (!transport_) return fallback(AwsMetadataStatus::imds_unavailable);
	AwsImdsResponse token = transport_->put_token(deadline, cancelled);
	if (expired(deadline, cancelled, result)) return result;
	if (!token.transport_ok || token.status_code != 200 || token.body.empty() ||
		token.body.size() > 4096) {
		if (!token.body.empty()) OPENSSL_cleanse(&token.body[0], token.body.size());
		return fallback(AwsMetadataStatus::imds_unavailable);
	}

	AwsImdsResponse document = transport_->get_identity_document(
		token.body, deadline, cancelled);
	OPENSSL_cleanse(&token.body[0], token.body.size());
	if (expired(deadline, cancelled, result)) return result;
	if (!document.transport_ok || document.status_code != 200) {
		return fallback(AwsMetadataStatus::imds_unavailable);
	}
	if (document.body.empty() || document.body.size() > 16384) {
		return fallback(AwsMetadataStatus::invalid_response);
	}

	try {
		const json identity = json::parse(document.body);
		if (!identity.is_object() || !identity.contains("region") ||
			!identity["region"].is_string()) {
			return fallback(AwsMetadataStatus::invalid_response);
		}
		result.local.region = identity["region"].get<std::string>();
		if (!valid_location_value(result.local.region, 64)) {
			return fallback(AwsMetadataStatus::invalid_response);
		}
		if (identity.contains("availabilityZone") &&
			identity["availabilityZone"].is_string()) {
			result.local.availability_zone =
				identity["availabilityZone"].get<std::string>();
			if (!valid_location_value(result.local.availability_zone, 64)) {
				result.local.availability_zone.clear();
			}
		}
		if (identity.contains("accountId") && identity["accountId"].is_string()) {
			result.local.account_id = identity["accountId"].get<std::string>();
			if (!valid_account_id(result.local.account_id)) result.local.account_id.clear();
		}
		result.status = AwsMetadataStatus::ok;
		return result;
	} catch (...) {
		return fallback(AwsMetadataStatus::invalid_response);
	}
}

AwsLocalityRdsDiscovery::AwsLocalityRdsDiscovery(
	std::shared_ptr<AwsRdsDiscoveryApi> api)
	: api_(std::move(api)) {}

AwsMetadataResult AwsLocalityRdsDiscovery::discover(
	const AwsMetadataRequest& request,
	const AwsLocalityCancelPredicate& cancelled) const {
	AwsMetadataResult result;
	if (request.region.empty() || !api_) {
		return fixed_failure(AwsMetadataStatus::invalid_response);
	}
	if (expired(request.deadline, cancelled, result)) return result;
	result.status = AwsMetadataStatus::ok;

	std::unordered_map<std::string, size_t> endpoint_indices;
	auto append = [&](const std::string& hostname_input, int port,
		AwsEndpointType type, const std::string& az, const std::string& account) {
		const std::string hostname = aws_locality_normalized_hostname(hostname_input);
		if (hostname.empty() || type == AwsEndpointType::unknown ||
			port < 0 || port > 65535) return;
		AwsMetadataEndpoint endpoint;
		endpoint.hostname = hostname;
		endpoint.port = static_cast<uint16_t>(port);
		endpoint.endpoint_type = type;
		endpoint.region = request.region;
		endpoint.availability_zone = az;
		endpoint.account_id = account;
		const std::string key = hostname + "\n" + std::to_string(port);
		const auto found = endpoint_indices.find(key);
		if (found == endpoint_indices.end()) {
			endpoint_indices.emplace(key, result.endpoints.size());
			result.endpoints.push_back(std::move(endpoint));
		} else {
			result.endpoints[found->second] = std::move(endpoint);
		}
	};

	auto fail = [&](AwsMetadataStatus status) {
		result = fixed_failure(status);
		return result;
	};
	auto check_page = [&](AwsMetadataStatus status) {
		if (cancelled()) return AwsMetadataStatus::cancelled;
		if (std::chrono::steady_clock::now() >= request.deadline) {
			return AwsMetadataStatus::timeout;
		}
		return status;
	};

	std::set<std::string> markers;
	std::string marker;
	for (;;) {
		AwsRdsInstancesPage page = api_->describe_instances(
			request.region, marker, request.deadline, cancelled);
		const AwsMetadataStatus status = check_page(page.status);
		if (status != AwsMetadataStatus::ok) return fail(status);
		for (const auto& instance : page.instances) {
			if (instance.port <= 0 || instance.port > 65535) continue;
			append(instance.endpoint, instance.port, AwsEndpointType::instance,
				instance.availability_zone,
				account_from_rds_arn(instance.arn, request.region));
		}
		if (page.next_marker.empty()) break;
		if (!markers.insert(page.next_marker).second) {
			return fail(AwsMetadataStatus::invalid_response);
		}
		marker = std::move(page.next_marker);
	}

	std::unordered_map<std::string, std::string> cluster_accounts;
	markers.clear();
	marker.clear();
	for (;;) {
		AwsRdsClustersPage page = api_->describe_clusters(
			request.region, marker, request.deadline, cancelled);
		const AwsMetadataStatus status = check_page(page.status);
		if (status != AwsMetadataStatus::ok) return fail(status);
		for (const auto& cluster : page.clusters) {
			const std::string account = account_from_rds_arn(cluster.arn, request.region);
			if (!cluster.identifier.empty()) cluster_accounts[cluster.identifier] = account;
			if (cluster.port > 0 && cluster.port <= 65535) {
				append(cluster.endpoint, cluster.port, AwsEndpointType::cluster, {}, account);
				append(cluster.reader_endpoint, cluster.port, AwsEndpointType::reader, {}, account);
			}
			for (const auto& custom : cluster.custom_endpoints) {
				append(custom, 0, AwsEndpointType::custom, {}, account);
			}
		}
		if (page.next_marker.empty()) break;
		if (!markers.insert(page.next_marker).second) {
			return fail(AwsMetadataStatus::invalid_response);
		}
		marker = std::move(page.next_marker);
	}

	markers.clear();
	marker.clear();
	for (;;) {
		AwsRdsClusterEndpointsPage page = api_->describe_cluster_endpoints(
			request.region, marker, request.deadline, cancelled);
		const AwsMetadataStatus status = check_page(page.status);
		if (status != AwsMetadataStatus::ok) return fail(status);
		for (const auto& endpoint : page.endpoints) {
			const auto account = cluster_accounts.find(endpoint.cluster_identifier);
			append(endpoint.endpoint, 0, endpoint_type(endpoint.endpoint_type), {},
				account == cluster_accounts.end() ? std::string() : account->second);
		}
		if (page.next_marker.empty()) break;
		if (!markers.insert(page.next_marker).second) {
			return fail(AwsMetadataStatus::invalid_response);
		}
		marker = std::move(page.next_marker);
	}

	return result;
}

AwsLocalityCompositeDiscovery::AwsLocalityCompositeDiscovery(
	std::shared_ptr<AwsImdsTransport> imds,
	AwsLocalityEnvironmentGetter getenv_value,
	std::shared_ptr<AwsRdsDiscoveryApi> rds)
	: local_(std::move(imds), std::move(getenv_value)),
	  rds_(std::move(rds)) {}

AwsMetadataResult AwsLocalityCompositeDiscovery::discover(
	const AwsMetadataRequest& request,
	const AwsLocalityCancelPredicate& cancelled) {
	if (request.kind == AwsMetadataRequestKind::local_location) {
		return local_.discover(request.deadline, cancelled);
	}
	if (request.kind == AwsMetadataRequestKind::rds_region) {
		return rds_.discover(request, cancelled);
	}
	return fixed_failure(AwsMetadataStatus::invalid_response);
}

#ifdef PROXYSQL_AWS_SDK_PROVIDER
namespace {

struct CurlResponseContext {
	std::string* body;
	size_t maximum;
	bool overflow { false };
};

size_t imds_write_callback(char* data, size_t size, size_t count, void* opaque) {
	auto* context = static_cast<CurlResponseContext*>(opaque);
	if (size != 0 && count > context->maximum / size) {
		context->overflow = true;
		return 0;
	}
	const size_t bytes = size * count;
	if (bytes > context->maximum - std::min(context->maximum, context->body->size())) {
		context->overflow = true;
		return 0;
	}
	context->body->append(data, bytes);
	return bytes;
}

struct CurlProgressContext {
	std::chrono::steady_clock::time_point deadline;
	const AwsLocalityCancelPredicate* cancelled;
};

int imds_progress_callback(void* opaque, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
	auto* context = static_cast<CurlProgressContext*>(opaque);
	return (*(context->cancelled))() ||
		std::chrono::steady_clock::now() >= context->deadline;
}

AwsImdsResponse imds_request(
	const char* url,
	const char* method,
	struct curl_slist* headers,
	size_t maximum,
	std::chrono::steady_clock::time_point deadline,
	const AwsLocalityCancelPredicate& cancelled) {
	AwsImdsResponse response;
	if (cancelled() || std::chrono::steady_clock::now() >= deadline) return response;
	CURL* handle = curl_easy_init();
	if (handle == nullptr) return response;
	CurlResponseContext write_context {&response.body, maximum};
	CurlProgressContext progress_context {deadline, &cancelled};
	const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
		deadline - std::chrono::steady_clock::now()).count();
	const long timeout = static_cast<long>(std::max<int64_t>(1, remaining));
	curl_easy_setopt(handle, CURLOPT_URL, url);
	curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, method);
	curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(handle, CURLOPT_NOBODY, 0L);
	curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
	curl_easy_setopt(handle, CURLOPT_NOPROXY, "*");
	// IMDS is an HTTP-only link-local service. Restrict the handle to that
	// protocol and retain a secure TLS floor if the transport URL ever changes.
	curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "http");
	curl_easy_setopt(handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
	curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, std::min<long>(timeout, 500L));
	curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, timeout);
	curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &imds_write_callback);
	curl_easy_setopt(handle, CURLOPT_WRITEDATA, &write_context);
	curl_easy_setopt(handle, CURLOPT_XFERINFOFUNCTION, &imds_progress_callback);
	curl_easy_setopt(handle, CURLOPT_XFERINFODATA, &progress_context);
	curl_easy_setopt(handle, CURLOPT_NOPROGRESS, 0L);
	const CURLcode code = curl_easy_perform(handle);
	curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response.status_code);
	curl_easy_cleanup(handle);
	response.transport_ok = code == CURLE_OK && !write_context.overflow;
	if (!response.transport_ok) response.body.clear();
	return response;
}

template <typename Error>
AwsMetadataStatus map_sdk_error(const Error& error) {
	const int type = static_cast<int>(error.GetErrorType());
	const int code = static_cast<int>(error.GetResponseCode());
	if (type == static_cast<int>(Aws::Client::CoreErrors::ACCESS_DENIED) || code == 401 || code == 403) {
		return AwsMetadataStatus::access_denied;
	}
	if (type == static_cast<int>(Aws::Client::CoreErrors::THROTTLING) ||
		type == static_cast<int>(Aws::Client::CoreErrors::SLOW_DOWN) || code == 429) {
		return AwsMetadataStatus::throttled;
	}
	if (type == static_cast<int>(Aws::Client::CoreErrors::REQUEST_TIMEOUT) ||
		type == static_cast<int>(Aws::Client::CoreErrors::NETWORK_CONNECTION)) {
		return AwsMetadataStatus::timeout;
	}
	return AwsMetadataStatus::provider_unavailable;
}

} // namespace

AwsImdsResponse AwsCurlImdsTransport::put_token(
	std::chrono::steady_clock::time_point deadline,
	const AwsLocalityCancelPredicate& cancelled) {
	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, "X-aws-ec2-metadata-token-ttl-seconds: 21600");
	AwsImdsResponse response = imds_request(
		"http://169.254.169.254/latest/api/token", "PUT", headers,
		4096, deadline, cancelled);
	curl_slist_free_all(headers);
	return response;
}

AwsImdsResponse AwsCurlImdsTransport::get_identity_document(
	const std::string& token,
	std::chrono::steady_clock::time_point deadline,
	const AwsLocalityCancelPredicate& cancelled) {
	struct curl_slist* headers = nullptr;
	std::string token_header = "X-aws-ec2-metadata-token: " + token;
	headers = curl_slist_append(headers, token_header.c_str());
	AwsImdsResponse response = imds_request(
		"http://169.254.169.254/latest/dynamic/instance-identity/document",
		"GET", headers, 16384, deadline, cancelled);
	curl_slist_free_all(headers);
	if (!token_header.empty()) {
		OPENSSL_cleanse(&token_header[0], token_header.size());
	}
	return response;
}

std::shared_ptr<Aws::RDS::RDSClient> AwsSdkRdsDiscoveryApi::client_for_region(
	const std::string& region) {
	std::lock_guard<std::mutex> lock(clients_mutex_);
	const auto found = clients_.find(region);
	if (found != clients_.end()) return found->second;
	Aws::Client::ClientConfiguration config;
	config.region = region.c_str();
	config.connectTimeoutMs = 500;
	config.requestTimeoutMs = 4000;
	config.httpRequestTimeoutMs = 4000;
	config.retryStrategy = std::make_shared<Aws::Client::DefaultRetryStrategy>(2, 50);
	auto client = std::make_shared<Aws::RDS::RDSClient>(config);
	clients_.emplace(region, client);
	return client;
}

AwsRdsInstancesPage AwsSdkRdsDiscoveryApi::describe_instances(
	const std::string& region,
	const std::string& marker,
	std::chrono::steady_clock::time_point deadline,
	const AwsLocalityCancelPredicate& cancelled) {
	AwsRdsInstancesPage page;
	if (cancelled()) { page.status = AwsMetadataStatus::cancelled; return page; }
	if (std::chrono::steady_clock::now() >= deadline) {
		page.status = AwsMetadataStatus::timeout;
		return page;
	}
	Aws::RDS::Model::DescribeDBInstancesRequest request;
	if (!marker.empty()) request.SetMarker(marker.c_str());
	const auto outcome = client_for_region(region)->DescribeDBInstances(request);
	if (!outcome.IsSuccess()) {
		page.status = map_sdk_error(outcome.GetError());
		return page;
	}
	page.status = AwsMetadataStatus::ok;
	page.next_marker = outcome.GetResult().GetMarker().c_str();
	for (const auto& instance : outcome.GetResult().GetDBInstances()) {
		const auto& endpoint = instance.GetEndpoint();
		page.instances.push_back({endpoint.GetAddress().c_str(), endpoint.GetPort(),
			instance.GetAvailabilityZone().c_str(), instance.GetDBInstanceArn().c_str()});
	}
	return page;
}

AwsRdsClustersPage AwsSdkRdsDiscoveryApi::describe_clusters(
	const std::string& region,
	const std::string& marker,
	std::chrono::steady_clock::time_point deadline,
	const AwsLocalityCancelPredicate& cancelled) {
	AwsRdsClustersPage page;
	if (cancelled()) { page.status = AwsMetadataStatus::cancelled; return page; }
	if (std::chrono::steady_clock::now() >= deadline) {
		page.status = AwsMetadataStatus::timeout;
		return page;
	}
	Aws::RDS::Model::DescribeDBClustersRequest request;
	if (!marker.empty()) request.SetMarker(marker.c_str());
	const auto outcome = client_for_region(region)->DescribeDBClusters(request);
	if (!outcome.IsSuccess()) {
		page.status = map_sdk_error(outcome.GetError());
		return page;
	}
	page.status = AwsMetadataStatus::ok;
	page.next_marker = outcome.GetResult().GetMarker().c_str();
	for (const auto& cluster : outcome.GetResult().GetDBClusters()) {
		std::vector<std::string> custom;
		for (const auto& endpoint : cluster.GetCustomEndpoints()) {
			custom.emplace_back(endpoint.c_str());
		}
		page.clusters.push_back({cluster.GetDBClusterIdentifier().c_str(),
			cluster.GetEndpoint().c_str(), cluster.GetReaderEndpoint().c_str(),
			cluster.GetPort(), std::move(custom), cluster.GetDBClusterArn().c_str()});
	}
	return page;
}

AwsRdsClusterEndpointsPage AwsSdkRdsDiscoveryApi::describe_cluster_endpoints(
	const std::string& region,
	const std::string& marker,
	std::chrono::steady_clock::time_point deadline,
	const AwsLocalityCancelPredicate& cancelled) {
	AwsRdsClusterEndpointsPage page;
	if (cancelled()) { page.status = AwsMetadataStatus::cancelled; return page; }
	if (std::chrono::steady_clock::now() >= deadline) {
		page.status = AwsMetadataStatus::timeout;
		return page;
	}
	Aws::RDS::Model::DescribeDBClusterEndpointsRequest request;
	if (!marker.empty()) request.SetMarker(marker.c_str());
	const auto outcome = client_for_region(region)->DescribeDBClusterEndpoints(request);
	if (!outcome.IsSuccess()) {
		page.status = map_sdk_error(outcome.GetError());
		return page;
	}
	page.status = AwsMetadataStatus::ok;
	page.next_marker = outcome.GetResult().GetMarker().c_str();
	for (const auto& endpoint : outcome.GetResult().GetDBClusterEndpoints()) {
		page.endpoints.push_back({endpoint.GetEndpoint().c_str(),
			endpoint.GetEndpointType().c_str(), endpoint.GetDBClusterIdentifier().c_str()});
	}
	return page;
}
#endif // PROXYSQL_AWS_SDK_PROVIDER
