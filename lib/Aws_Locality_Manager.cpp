#include "Aws_Locality_Manager.h"

#include "json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <dlfcn.h>
#include <exception>
#include <limits>
#include <map>
#include <mutex>
#include <locale>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

using nlohmann::json;

namespace {

AwsLocalityPolicy invalid_policy(
	uint32_t hostgroup_id,
	const char* field,
	AwsLocalityPolicyError& error) {
	error.hostgroup_id = hostgroup_id;
	error.field = field;
	return {};
}

bool read_multiplier(const json& object, const char* field, double& value) {
	const auto it = object.find(field);
	if (it == object.end() || !it->is_number()) {
		return false;
	}

	value = it->get<double>();
	return std::isfinite(value) && value >= 1.0 && value <= 10.0;
}

bool read_seconds(
	const json& object,
	const char* field,
	uint32_t default_value,
	uint32_t minimum,
	uint32_t maximum,
	uint32_t& value) {
	const auto it = object.find(field);
	if (it == object.end()) {
		value = default_value;
		return value >= minimum && value <= maximum;
	}
	if (!it->is_number_unsigned() && !it->is_number_integer()) {
		return false;
	}

	const int64_t parsed = it->get<int64_t>();
	if (parsed < static_cast<int64_t>(minimum) ||
		parsed > static_cast<int64_t>(maximum)) {
		return false;
	}
	value = static_cast<uint32_t>(parsed);
	return true;
}

bool ends_with(const std::string& value, const std::string& suffix) {
	return value.size() >= suffix.size() &&
		value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool valid_region(const std::string& region) {
	if (region.empty() || region.front() == '-' || region.back() == '-') {
		return false;
	}

	unsigned int hyphens = 0;
	for (const char character : region) {
		if (character == '-') {
			++hyphens;
		} else if (!aws_locality_is_alnum_dash_or_dot(std::locale::classic(),
			character) ||
			character == '.') {
			return false;
		}
	}
	return hyphens >= 2 &&
		region.back() >= '0' &&
		region.back() <= '9';
}

bool is_rds_proxy_endpoint_prefix(const std::string& prefix) {
	// RDS Proxy endpoints have the canonical shape
	// <proxy-name>.proxy-<generated-id>.<region>.rds.amazonaws.com.  A normal
	// DB identifier is allowed to begin with "proxy-", so only the reserved
	// generated-ID label after a proxy name identifies this endpoint type.
	const size_t separator = prefix.rfind('.');
	return separator != std::string::npos && separator != 0 &&
		prefix.size() - separator - 1 > 6 &&
		prefix.compare(separator + 1, 6, "proxy-") == 0;
}

} // namespace

AwsLocalityPolicy parse_aws_locality_policy(
	const json& policy_json,
	uint32_t hostgroup_id,
	AwsLocalityPolicyError& error) {
	error = {};
	if (!policy_json.is_object()) {
		return invalid_policy(hostgroup_id, "locality_awareness", error);
	}

	AwsLocalityPolicy policy;
	if (!read_multiplier(policy_json, "same_region_multiplier",
			policy.same_region_multiplier)) {
		return invalid_policy(hostgroup_id, "same_region_multiplier", error);
	}
	if (!read_multiplier(policy_json, "same_az_multiplier",
			policy.same_az_multiplier) ||
		policy.same_az_multiplier < policy.same_region_multiplier) {
		return invalid_policy(hostgroup_id, "same_az_multiplier", error);
	}
	if (!read_seconds(policy_json, "refresh_interval_seconds", 300, 30, 86400,
			policy.refresh_interval_seconds)) {
		return invalid_policy(hostgroup_id, "refresh_interval_seconds", error);
	}
	if (!read_seconds(policy_json, "stale_ttl_seconds", 1800,
			policy.refresh_interval_seconds, 604800,
			policy.stale_ttl_seconds)) {
		return invalid_policy(hostgroup_id, "stale_ttl_seconds", error);
	}

	policy.valid = true;
	return policy;
}

AwsEndpointCandidate recognize_rds_endpoint(
	uint32_t hostgroup_id,
	std::string_view hostname_input,
	uint16_t port) {
	AwsEndpointCandidate result;
	result.hostgroup_id = hostgroup_id;
	result.port = port;
	result.hostname = aws_locality_normalized_hostname(hostname_input);
	if (result.hostname.empty()) {
		return result;
	}

	const std::string china_suffix = ".rds.amazonaws.com.cn";
	const std::string standard_suffix = ".rds.amazonaws.com";
	const std::string* suffix = nullptr;
	if (ends_with(result.hostname, china_suffix)) {
		suffix = &china_suffix;
	} else if (ends_with(result.hostname, standard_suffix)) {
		suffix = &standard_suffix;
	} else {
		return result;
	}

	const std::string before_suffix = result.hostname.substr(
		0, result.hostname.size() - suffix->size());
	const size_t region_separator = before_suffix.rfind('.');
	if (region_separator == std::string::npos || region_separator == 0 ||
		region_separator + 1 == before_suffix.size()) {
		return result;
	}

	const std::string endpoint_prefix = before_suffix.substr(0, region_separator);
	result.region = before_suffix.substr(region_separator + 1);
	if (is_rds_proxy_endpoint_prefix(endpoint_prefix) || !valid_region(result.region)) {
		result.region.clear();
		return result;
	}

	if (result.region.compare(0, 3, "cn-") == 0) {
		result.partition = "aws-cn";
	} else if (result.region.compare(0, 7, "us-gov-") == 0) {
		result.partition = "aws-us-gov";
	} else {
		result.partition = "aws";
	}
	result.recognized = true;
	return result;
}

AwsLocalityClass classify_aws_locality(
	const AwsLocalLocation& local,
	const AwsBackendLocation& backend) {
	if (local.region.empty() || backend.region.empty()) {
		return AwsLocalityClass::unknown;
	}
	if (local.region != backend.region) {
		return AwsLocalityClass::remote;
	}
	if (backend.endpoint_type == AwsEndpointType::instance &&
		!local.availability_zone.empty() &&
		local.availability_zone == backend.availability_zone &&
		!local.account_id.empty() &&
		local.account_id == backend.account_id) {
		return AwsLocalityClass::same_az;
	}
	return AwsLocalityClass::same_region;
}

uint64_t aws_locality_effective_weight(
	int64_t configured_weight,
	double multiplier) {
	if (configured_weight <= 0 || !std::isfinite(multiplier) || multiplier <= 0.0) {
		return 0;
	}

	const long double product = static_cast<long double>(configured_weight) *
		static_cast<long double>(multiplier);
	const long double maximum = static_cast<long double>(
		std::numeric_limits<uint64_t>::max());
	if (product >= maximum) {
		return std::numeric_limits<uint64_t>::max();
	}
	return static_cast<uint64_t>(product);
}

uint64_t aws_locality_saturating_add(uint64_t lhs, uint64_t rhs) {
	const uint64_t maximum = std::numeric_limits<uint64_t>::max();
	return maximum - lhs < rhs ? maximum : lhs + rhs;
}

size_t aws_locality_weighted_index(
	const uint64_t* weights,
	size_t count,
	uint64_t random_value) {
	if (weights == nullptr || count == 0) {
		return count;
	}

	uint64_t total = 0;
	for (size_t i = 0; i < count; ++i) {
		total = aws_locality_saturating_add(total, weights[i]);
	}
	if (total == 0) {
		return count;
	}

	const uint64_t target = random_value % total;
	uint64_t cumulative = 0;
	for (size_t i = 0; i < count; ++i) {
		cumulative = aws_locality_saturating_add(cumulative, weights[i]);
		if (target < cumulative) {
			return i;
		}
	}
	return count;
}

namespace {

std::mutex metadata_provider_mutex;
std::condition_variable metadata_provider_cv;
AwsMetadataProvider* leased_metadata_provider = nullptr;
AwsMetadataProviderDestroyFn metadata_provider_destroy = nullptr;
AwsMetadataModuleHandle metadata_provider_module = nullptr;
size_t metadata_provider_leases = 0;
bool metadata_provider_accepting = false;

bool dns_identity_length(std::string_view input, size_t& length) {
	const auto& loc = std::locale::classic();
	if (input.empty()) return false;
	length = input.size();
	if (input[length - 1] == '.') --length;
	if (length == 0 || input[length - 1] == '.') return false;
	for (size_t index = 0; index < length; ++index) {
		if (!aws_locality_is_alnum_dash_or_dot(loc, input[index])) {
			return false;
		}
	}
	return true;
}

uint64_t identity_hash(
	uint32_t hostgroup_id,
	std::string_view hostname,
	uint16_t port) {
	uint64_t hash = 14695981039346656037ULL;
	auto append = [&hash](unsigned char value) {
		hash ^= value;
		hash *= 1099511628211ULL;
	};
	for (unsigned int shift = 0; shift < 32; shift += 8) {
		append(static_cast<unsigned char>(hostgroup_id >> shift));
	}
	append(static_cast<unsigned char>(port));
	append(static_cast<unsigned char>(port >> 8));
	size_t length = 0;
	const bool valid_dns = dns_identity_length(hostname, length);
	append(valid_dns ? 1 : 0);
	if (!valid_dns) length = hostname.size();
	const auto& loc = std::locale::classic();
	for (size_t index = 0; index < length; ++index) {
		const unsigned char value = static_cast<unsigned char>(hostname[index]);
		append(valid_dns
			? static_cast<unsigned char>(aws_locality_to_lower(loc,
				static_cast<char>(value)))
			: value);
	}
	return hash;
}

bool same_hostname_identity(std::string_view lhs, std::string_view rhs) {
	size_t lhs_length = 0;
	size_t rhs_length = 0;
	const bool lhs_dns = dns_identity_length(lhs, lhs_length);
	const bool rhs_dns = dns_identity_length(rhs, rhs_length);
	if (lhs_dns != rhs_dns) return false;
	if (!lhs_dns) return lhs == rhs;
	if (lhs_length != rhs_length) return false;
	const auto& loc = std::locale::classic();
	for (size_t index = 0; index < lhs_length; ++index) {
		if (aws_locality_to_lower(loc, lhs[index]) !=
			aws_locality_to_lower(loc, rhs[index])) {
			return false;
		}
	}
	return true;
}

std::string endpoint_key(std::string_view hostname_input, uint16_t port) {
	const std::string hostname = aws_locality_normalized_hostname(hostname_input);
	return (hostname.empty() ? "raw:" + std::string(hostname_input)
		: "dns:" + hostname) + "\n" + std::to_string(port);
}

const char* failure_category(AwsMetadataStatus status) {
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

int64_t wall_seconds(std::chrono::system_clock::time_point value) {
	return std::chrono::duration_cast<std::chrono::seconds>(
		value.time_since_epoch()).count();
}

} // namespace

void AwsMetadataProviderLease::release() {
	if (provider_ == nullptr) {
		return;
	}
	{
		std::lock_guard<std::mutex> lock(metadata_provider_mutex);
		if (metadata_provider_leases != 0) {
			--metadata_provider_leases;
		}
	}
	provider_ = nullptr;
	metadata_provider_cv.notify_all();
}

AwsMetadataProviderLease::~AwsMetadataProviderLease() {
	release();
}

AwsMetadataProviderLease::AwsMetadataProviderLease(
	AwsMetadataProviderLease&& other) noexcept
	: provider_(other.provider_) {
	other.provider_ = nullptr;
}

AwsMetadataProviderLease& AwsMetadataProviderLease::operator=(
	AwsMetadataProviderLease&& other) noexcept {
	if (this != &other) {
		release();
		provider_ = other.provider_;
		other.provider_ = nullptr;
	}
	return *this;
}

bool install_global_aws_metadata_provider(
	AwsMetadataProvider* provider,
	AwsMetadataProviderDestroyFn destroy,
	AwsMetadataModuleHandle module_handle) {
	if (provider == nullptr || destroy == nullptr) {
		return false;
	}

	std::lock_guard<std::mutex> lock(metadata_provider_mutex);
	if (metadata_provider_accepting || leased_metadata_provider != nullptr ||
		metadata_provider_destroy != nullptr) {
		return false;
	}
	leased_metadata_provider = provider;
	metadata_provider_destroy = destroy;
	metadata_provider_module = module_handle;
	metadata_provider_accepting = true;
	return true;
}

AwsMetadataProviderLease acquire_global_aws_metadata_provider() {
	std::lock_guard<std::mutex> lock(metadata_provider_mutex);
	if (!metadata_provider_accepting || leased_metadata_provider == nullptr) {
		return {};
	}
	++metadata_provider_leases;
	return AwsMetadataProviderLease(leased_metadata_provider);
}

void shutdown_global_aws_metadata_provider() {
	AwsMetadataProvider* provider = nullptr;
	AwsMetadataProviderDestroyFn destroy = nullptr;
	AwsMetadataModuleHandle module_handle = nullptr;
	{
		std::unique_lock<std::mutex> lock(metadata_provider_mutex);
		metadata_provider_accepting = false;
		metadata_provider_cv.wait(lock, [] {
			return metadata_provider_leases == 0;
		});
		provider = leased_metadata_provider;
		destroy = metadata_provider_destroy;
		module_handle = metadata_provider_module;
		leased_metadata_provider = nullptr;
		metadata_provider_destroy = nullptr;
		metadata_provider_module = nullptr;
	}

	if (provider != nullptr) {
		provider->shutdown();
		destroy(provider);
	}
	if (module_handle != nullptr) {
		dlclose(module_handle);
	}
}

const AwsLocalitySnapshotEntry* AwsLocalitySnapshot::find(
	uint32_t hostgroup_id,
	std::string_view hostname,
	uint16_t port) const {
	const auto range = entries.equal_range(identity_hash(hostgroup_id, hostname, port));
	for (auto it = range.first; it != range.second; ++it) {
		const auto& entry = it->second;
		if (entry.hostgroup_id == hostgroup_id && entry.port == port &&
			same_hostname_identity(entry.hostname, hostname)) {
			return &entry;
		}
	}
	return nullptr;
}

uint64_t AwsLocalitySnapshot::effective_weight(
	uint32_t hostgroup_id,
	std::string_view hostname,
	uint16_t port,
	int64_t configured_weight) const {
	const auto* entry = find(hostgroup_id, hostname, port);
	return aws_locality_effective_weight(
		configured_weight, entry == nullptr ? 1.0 : entry->multiplier);
}

AwsLocalityManagerConfig::AwsLocalityManagerConfig()
	: steady_clock([] { return std::chrono::steady_clock::now(); }),
	  wall_clock([] { return std::chrono::system_clock::now(); }) {}

class MySQLAwsLocalityManager::Impl {
public:
	explicit Impl(AwsLocalityManagerConfig config)
		: config_(std::move(config)), sink_(std::make_shared<CompletionSink>(this)) {
		auto initial = std::make_shared<AwsLocalitySnapshot>();
		std::atomic_store(
			&published_, std::shared_ptr<const AwsLocalitySnapshot>(std::move(initial)));
	}

	~Impl() noexcept {
		try {
			shutdown();
		} catch (...) {
			// Destructors must not let allocation/system exceptions from the
			// final snapshot publication escape. Ensure the scheduler thread
			// cannot make std::thread's destructor terminate the process.
			try {
				std::thread worker;
				{
					std::lock_guard<std::mutex> lock(mutex_);
					stopping_ = true;
					enabled_ = false;
					cancel_requested_ = true;
					cv_.notify_all();
					worker = std::move(worker_);
				}
				if (worker.joinable()) worker.join();
				sink_->detach();
			} catch (...) {
				std::terminate();
			}
		}
	}

	void configure(std::vector<AwsLocalityHostgroupConfig> hostgroups) {
		std::lock_guard<std::mutex> lock(mutex_);
		if (stopping_) {
			return;
		}
		for (auto& hostgroup : hostgroups) {
			for (auto& backend : hostgroup.backends) {
				backend.endpoint.hostgroup_id = hostgroup.hostgroup_id;
			}
		}
		hostgroups_.clear();
		for (auto& hostgroup : hostgroups) {
			if (hostgroup.policy.valid) {
				hostgroups_.push_back(std::move(hostgroup));
			}
		}
		++generation_;
		cancel_requested_ = true;
		force_refresh_ = enabled_ && !hostgroups_.empty();
		if (force_refresh_) {
			ensure_worker_locked();
		}
		publish_locked();
		cv_.notify_all();
	}

	void set_enabled(bool enabled) {
		std::unique_lock<std::mutex> lock(mutex_);
		if (stopping_) {
			return;
		}
		enabled_ = enabled;
		if (enabled_ && !hostgroups_.empty()) {
			ensure_worker_locked();
			force_refresh_ = true;
		} else {
			cancel_requested_ = true;
			disable_acknowledged_ = !worker_.joinable();
		}
		publish_locked();
		cv_.notify_all();
		if (!enabled_ && worker_.joinable()) {
			const auto disable_acknowledged = std::addressof(disable_acknowledged_);
			const auto stopping = std::addressof(stopping_);
			cv_.wait_for(lock, config_.disable_wait_timeout, [disable_acknowledged, stopping] {
				return *disable_acknowledged || *stopping;
			});
		}
	}

	void request_refresh() {
		std::lock_guard<std::mutex> lock(mutex_);
		if (stopping_ || !enabled_ || hostgroups_.empty()) {
			return;
		}
		force_refresh_ = true;
		publish_locked();
		cv_.notify_all();
	}

	std::shared_ptr<const AwsLocalitySnapshot> snapshot() const {
		return std::atomic_load(&published_);
	}

	std::vector<AwsLocalitySnapshotEntry> diagnostic_rows() const {
		const auto current = snapshot();
		std::vector<AwsLocalitySnapshotEntry> rows;
		rows.reserve(current->entries.size());
		for (const auto& item : current->entries) {
			rows.push_back(item.second);
		}
		std::sort(rows.begin(), rows.end(), [](const auto& lhs, const auto& rhs) {
			if (lhs.hostgroup_id != rhs.hostgroup_id) {
				return lhs.hostgroup_id < rhs.hostgroup_id;
			}
			if (lhs.hostname != rhs.hostname) {
				return lhs.hostname < rhs.hostname;
			}
			return lhs.port < rhs.port;
		});
		return rows;
	}

	void shutdown() {
		std::thread worker;
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (shutdown_complete_) {
				return;
			}
			stopping_ = true;
			enabled_ = false;
			cancel_requested_ = true;
			publish_locked();
			cv_.notify_all();
			worker = std::move(worker_);
		}
		if (worker.joinable()) {
			worker.join();
		}
		sink_->detach();
		{
			std::lock_guard<std::mutex> lock(mutex_);
			shutdown_complete_ = true;
			publish_locked();
		}
	}

private:
	struct EndpointRecord {
		bool has_value { false };
		AwsBackendLocation value;
		std::chrono::steady_clock::time_point success_steady {};
		int64_t success_wall { 0 };
		int64_t attempt_wall { 0 };
		std::string error;
	};

	struct LocalRecord {
		bool has_value { false };
		AwsLocalLocation value;
		std::chrono::steady_clock::time_point success_steady {};
		int64_t success_wall { 0 };
		int64_t attempt_wall { 0 };
		std::string error;
	};

	struct InFlight {
		AwsMetadataRequest request;
		AwsMetadataRequestHandle handle;
	};

	class CompletionSink final : public AwsMetadataCompletionSink {
	public:
		explicit CompletionSink(Impl* owner) : owner_(owner) {}

		void post(AwsMetadataCompletion&& completion) override {
			Impl* owner = nullptr;
			{
				std::lock_guard<std::mutex> lock(mutex_);
				if (owner_ == nullptr) {
					return;
				}
				owner = owner_;
				++active_;
			}
			owner->on_completion(std::move(completion));
			{
				std::lock_guard<std::mutex> lock(mutex_);
				--active_;
				cv_.notify_all();
			}
		}

		void detach() {
			std::unique_lock<std::mutex> lock(mutex_);
			owner_ = nullptr;
			cv_.wait(lock, [this] { return active_ == 0; });
		}

	private:
		std::mutex mutex_;
		std::condition_variable cv_;
		Impl* owner_ { nullptr };
		size_t active_ { 0 };
	};

	void ensure_worker_locked() {
		if (!worker_.joinable()) {
			worker_ = std::thread([this] { worker_loop(); });
		}
	}

	uint32_t minimum_refresh_seconds_locked() const {
		uint32_t result = 86400;
		for (const auto& hostgroup : hostgroups_) {
			result = std::min(result, hostgroup.policy.refresh_interval_seconds);
		}
		return result;
	}

	std::vector<AwsMetadataRequest> build_cycle_locked(
		std::chrono::steady_clock::time_point now) {
		std::vector<AwsMetadataRequest> requests;
		AwsMetadataRequest local;
		local.kind = AwsMetadataRequestKind::local_location;
		local.opaque_id = next_opaque_id_++;
		local.generation = generation_;
		local.deadline = now + config_.request_timeout;
		requests.push_back(local);

		std::map<std::string, std::map<std::string, AwsEndpointCandidate>> regions;
		for (const auto& hostgroup : hostgroups_) {
			for (const auto& backend : hostgroup.backends) {
				const auto& endpoint = backend.endpoint;
				if (!endpoint.recognized) {
					continue;
				}
				regions[endpoint.region][endpoint_key(endpoint.hostname, endpoint.port)] = endpoint;
			}
		}
		for (const auto& region : regions) {
			AwsMetadataRequest request;
			request.kind = AwsMetadataRequestKind::rds_region;
			request.opaque_id = next_opaque_id_++;
			request.generation = generation_;
			request.region = region.first;
			request.deadline = now + config_.request_timeout;
			for (const auto& item : region.second) {
				request.endpoints.push_back(item.second);
				if (request.partition.empty()) {
					request.partition = item.second.partition;
				}
			}
			requests.push_back(std::move(request));
		}

		const int64_t attempt = wall_seconds(config_.wall_clock());
		local_.attempt_wall = attempt;
		++local_in_flight_;
		for (const auto& request : requests) {
			in_flight_.emplace(request.opaque_id, InFlight {request, {}});
			if (request.kind == AwsMetadataRequestKind::rds_region) {
				++region_in_flight_[request.region];
				for (const auto& endpoint : request.endpoints) {
					endpoint_cache_[endpoint_key(endpoint.hostname, endpoint.port)].attempt_wall = attempt;
				}
			}
		}
		publish_locked();
		return requests;
	}

	void cancel_all_requests(AwsMetadataProvider* provider) {
		std::vector<AwsMetadataRequestHandle> handles;
		{
			std::lock_guard<std::mutex> lock(mutex_);
			for (const auto& item : in_flight_) {
				if (item.second.handle.value != 0) {
					handles.push_back(item.second.handle);
				}
			}
			in_flight_.clear();
			local_in_flight_ = 0;
			region_in_flight_.clear();
			publish_locked();
		}
		if (provider != nullptr) {
			for (const auto handle : handles) {
				provider->cancel(handle);
			}
		}
	}

	void provider_unavailable(uint64_t generation) {
		std::lock_guard<std::mutex> lock(mutex_);
		if (generation != generation_ || stopping_) {
			return;
		}
		const int64_t attempt = wall_seconds(config_.wall_clock());
		local_.attempt_wall = attempt;
		local_.error = "provider_unavailable";
		for (const auto& hostgroup : hostgroups_) {
			for (const auto& backend : hostgroup.backends) {
				auto& record = endpoint_cache_[endpoint_key(
					backend.endpoint.hostname, backend.endpoint.port)];
				record.attempt_wall = attempt;
				record.error = "provider_unavailable";
			}
		}
		in_flight_.clear();
		local_in_flight_ = 0;
		region_in_flight_.clear();
		publish_locked();
	}

	void worker_loop() {
		AwsMetadataProviderLease provider_lease;
		bool cycle_started = false;
		auto next_due = config_.steady_clock();

		for (;;) {
			std::vector<AwsMetadataRequest> requests;
			bool cancel = false;
			bool release_provider = false;
			bool stop_now = false;
			bool acknowledge_disable = false;
			uint64_t dispatch_generation = 0;
			{
				std::unique_lock<std::mutex> lock(mutex_);
				while (!stopping_) {
					if (cancel_requested_ || force_refresh_) {
						break;
					}
					if (!enabled_ || hostgroups_.empty()) {
						cv_.wait(lock, [this] {
							return stopping_ || cancel_requested_ || force_refresh_ ||
								(enabled_ && !hostgroups_.empty());
						});
						continue;
					}
					const auto now = config_.steady_clock();
					if (!cycle_started || now >= next_due) {
						break;
					}
					const auto delay = next_due - now;
					cv_.wait_for(lock, delay);
				}

				if (stopping_) {
					cancel = true;
					release_provider = true;
				} else {
					cancel = cancel_requested_;
					cancel_requested_ = false;
					if (cancel) {
						// Cancel the previous generation before constructing new work.
						// Otherwise the cancellation sweep can consume requests that
						// were created in this same scheduler iteration.
						if (!enabled_) {
							release_provider = true;
							acknowledge_disable = true;
						}
					} else if (!enabled_ || hostgroups_.empty()) {
						release_provider = true;
						acknowledge_disable = !enabled_;
						force_refresh_ = false;
						publish_locked();
					} else {
						const auto now = config_.steady_clock();
						if (force_refresh_ || !cycle_started || now >= next_due) {
							force_refresh_ = false;
							requests = build_cycle_locked(now);
							dispatch_generation = generation_;
							cycle_started = true;
							next_due = now + std::chrono::seconds(
								minimum_refresh_seconds_locked());
						}
					}
				}
				stop_now = stopping_;
			}

			if (cancel) {
				cancel_all_requests(provider_lease.get());
			}
			if (release_provider) {
				provider_lease = {};
			}
			if (acknowledge_disable) {
				std::lock_guard<std::mutex> lock(mutex_);
				disable_acknowledged_ = true;
				cv_.notify_all();
			}
			if (stop_now) {
				break;
			}
			if (requests.empty()) {
				continue;
			}

			if (!provider_lease) {
				provider_lease = acquire_global_aws_metadata_provider();
			}
			if (!provider_lease) {
				provider_unavailable(dispatch_generation);
				continue;
			}

			for (const auto& request : requests) {
				AwsMetadataRequestHandle handle;
				try {
					handle = provider_lease->request(request, sink_);
				} catch (...) {
					AwsMetadataCompletion completion;
					completion.opaque_id = request.opaque_id;
					completion.generation = request.generation;
					completion.result.status = AwsMetadataStatus::provider_unavailable;
					on_completion(std::move(completion));
					continue;
				}
				std::lock_guard<std::mutex> lock(mutex_);
				const auto it = in_flight_.find(request.opaque_id);
				if (it != in_flight_.end()) {
					it->second.handle = handle;
				}
			}
		}
	}

	void on_completion(AwsMetadataCompletion&& completion) {
		if (config_.before_completion) {
			config_.before_completion();
		}
		std::lock_guard<std::mutex> lock(mutex_);
		const auto pending = in_flight_.find(completion.opaque_id);
		if (pending == in_flight_.end()) {
			return;
		}
		const AwsMetadataRequest request = pending->second.request;
		in_flight_.erase(pending);
		if (request.kind == AwsMetadataRequestKind::local_location) {
			if (local_in_flight_ != 0) {
				--local_in_flight_;
			}
		} else {
			auto region = region_in_flight_.find(request.region);
			if (region != region_in_flight_.end() && region->second != 0) {
				--region->second;
				if (region->second == 0) {
					region_in_flight_.erase(region);
				}
			}
		}
		if (completion.generation != request.generation ||
			completion.generation != generation_ || stopping_) {
			publish_locked();
			return;
		}

		const auto now_steady = config_.steady_clock();
		const int64_t now_wall = wall_seconds(config_.wall_clock());
		if (request.kind == AwsMetadataRequestKind::local_location) {
			local_.attempt_wall = now_wall;
			if (completion.result.status == AwsMetadataStatus::ok &&
				!completion.result.local.region.empty()) {
				local_.has_value = true;
				local_.value = std::move(completion.result.local);
				local_.success_steady = now_steady;
				local_.success_wall = now_wall;
				local_.error.clear();
			} else {
				local_.error = completion.result.status == AwsMetadataStatus::ok
					? "invalid_response" : failure_category(completion.result.status);
			}
		} else {
			apply_region_completion_locked(request, completion.result,
				now_steady, now_wall);
		}
		publish_locked();
	}

	void apply_region_completion_locked(
		const AwsMetadataRequest& request,
		const AwsMetadataResult& result,
		std::chrono::steady_clock::time_point now_steady,
		int64_t now_wall) {
		if (result.status != AwsMetadataStatus::ok) {
			for (const auto& endpoint : request.endpoints) {
				auto& record = endpoint_cache_[endpoint_key(endpoint.hostname, endpoint.port)];
				record.attempt_wall = now_wall;
				record.error = failure_category(result.status);
			}
			return;
		}

		std::unordered_map<std::string, const AwsMetadataEndpoint*> returned;
		for (const auto& endpoint : result.endpoints) {
			const std::string hostname = aws_locality_normalized_hostname(endpoint.hostname);
			if (!hostname.empty() && endpoint.region == request.region) {
				returned[endpoint_key(hostname, endpoint.port)] = &endpoint;
				if (endpoint.port == 0) {
					returned[endpoint_key(hostname, 0)] = &endpoint;
				}
			}
		}

		for (const auto& endpoint : request.endpoints) {
			auto& record = endpoint_cache_[endpoint_key(endpoint.hostname, endpoint.port)];
			record.attempt_wall = now_wall;
			const auto exact = returned.find(endpoint_key(endpoint.hostname, endpoint.port));
			const auto no_port = returned.find(endpoint_key(endpoint.hostname, 0));
			const AwsMetadataEndpoint* match = exact != returned.end()
				? exact->second : (no_port != returned.end() ? no_port->second : nullptr);
			if (match == nullptr || match->endpoint_type == AwsEndpointType::unknown) {
				record.error = "endpoint_not_found";
				continue;
			}
			record.has_value = true;
			record.value = {match->endpoint_type, match->region,
				match->availability_zone, match->account_id};
			record.success_steady = now_steady;
			record.success_wall = now_wall;
			record.error.clear();
		}
	}

	AwsLocalitySnapshotEntry build_entry_locked(
		const AwsLocalityHostgroupConfig& hostgroup,
		const AwsLocalityBackendConfig& backend_config,
		std::chrono::steady_clock::time_point now) const {
		AwsLocalitySnapshotEntry entry;
		entry.hostgroup_id = hostgroup.hostgroup_id;
		entry.hostname = backend_config.endpoint.hostname;
		entry.port = backend_config.endpoint.port;
		entry.configured_weight = backend_config.configured_weight;
		entry.local = local_.value;

		const auto endpoint = endpoint_cache_.find(endpoint_key(
			backend_config.endpoint.hostname, backend_config.endpoint.port));
		if (endpoint != endpoint_cache_.end()) {
			entry.backend = endpoint->second.value;
			entry.endpoint_type = endpoint->second.value.endpoint_type;
			entry.last_attempt_timestamp = std::max(
				local_.attempt_wall, endpoint->second.attempt_wall);
			if (local_.success_wall != 0 && endpoint->second.success_wall != 0) {
				entry.last_success_timestamp = std::min(
					local_.success_wall, endpoint->second.success_wall);
			}
		} else {
			entry.last_attempt_timestamp = local_.attempt_wall;
		}

		if (!enabled_) {
			entry.status = AwsLocalityMetadataStatus::disabled;
			return entry;
		}
		if (!backend_config.endpoint.recognized) {
			entry.status = AwsLocalityMetadataStatus::error;
			entry.failure_category = "invalid_response";
			return entry;
		}

		// A missing provider is different from a transient provider error: no
		// concrete locality authority remains installed.  Do not continue to
		// apply a multiplier derived from a previous provider's cached result.
		const bool provider_unavailable = local_.error == "provider_unavailable" ||
			(endpoint != endpoint_cache_.end() &&
				endpoint->second.error == "provider_unavailable");
		if (provider_unavailable) {
			entry.status = AwsLocalityMetadataStatus::error;
			entry.failure_category = "provider_unavailable";
			return entry;
		}

		const bool endpoint_pending = region_in_flight_.find(
			backend_config.endpoint.region) != region_in_flight_.end();
		if (!local_.has_value || endpoint == endpoint_cache_.end() ||
			!endpoint->second.has_value) {
			if ((!local_.has_value && local_in_flight_ != 0) ||
				(endpoint != endpoint_cache_.end() && !endpoint->second.has_value &&
					endpoint_pending)) {
				entry.status = AwsLocalityMetadataStatus::pending;
			} else {
				entry.status = AwsLocalityMetadataStatus::error;
			}
			if (endpoint != endpoint_cache_.end() && !endpoint->second.error.empty()) {
				entry.failure_category = endpoint->second.error;
			} else if (!local_.error.empty()) {
				entry.failure_category = local_.error;
			}
			return entry;
		}

		const auto local_age = now >= local_.success_steady
			? now - local_.success_steady : std::chrono::steady_clock::duration::zero();
		const auto endpoint_age = now >= endpoint->second.success_steady
			? now - endpoint->second.success_steady : std::chrono::steady_clock::duration::zero();
		const auto age = std::max(local_age, endpoint_age);
		const auto refresh = std::chrono::seconds(hostgroup.policy.refresh_interval_seconds);
		const auto stale_ttl = std::chrono::seconds(hostgroup.policy.stale_ttl_seconds);
		if (age > stale_ttl) {
			entry.status = AwsLocalityMetadataStatus::expired;
			return entry;
		}
		const bool refresh_failed = !local_.error.empty() || !endpoint->second.error.empty();
		entry.status = age > refresh || refresh_failed
			? AwsLocalityMetadataStatus::stale : AwsLocalityMetadataStatus::fresh;
		entry.failure_category = !endpoint->second.error.empty()
			? endpoint->second.error : local_.error;
		entry.locality = classify_aws_locality(local_.value, endpoint->second.value);
		if (entry.locality == AwsLocalityClass::same_az) {
			entry.multiplier = hostgroup.policy.same_az_multiplier;
		} else if (entry.locality == AwsLocalityClass::same_region) {
			entry.multiplier = hostgroup.policy.same_region_multiplier;
		}
		return entry;
	}

	void publish_locked() {
		auto next = std::make_shared<AwsLocalitySnapshot>();
		next->generation = generation_;
		next->enabled = enabled_;
		const auto now = config_.steady_clock();
		for (const auto& hostgroup : hostgroups_) {
			next->hostgroups.insert(hostgroup.hostgroup_id);
			for (const auto& backend : hostgroup.backends) {
				auto entry = build_entry_locked(hostgroup, backend, now);
				next->entries.emplace(identity_hash(entry.hostgroup_id,
					entry.hostname, entry.port), std::move(entry));
			}
		}
		std::atomic_store(&published_, std::shared_ptr<const AwsLocalitySnapshot>(
			std::move(next)));
	}

	AwsLocalityManagerConfig config_;
	mutable std::mutex mutex_;
	std::condition_variable cv_;
	std::vector<AwsLocalityHostgroupConfig> hostgroups_;
	uint64_t generation_ { 0 };
	uint64_t next_opaque_id_ { 1 };
	bool enabled_ { false };
	bool stopping_ { false };
	bool shutdown_complete_ { false };
	bool cancel_requested_ { false };
	bool force_refresh_ { false };
	bool disable_acknowledged_ { true };
	std::thread worker_;
	std::shared_ptr<CompletionSink> sink_;
	std::shared_ptr<const AwsLocalitySnapshot> published_;
	LocalRecord local_;
	std::unordered_map<std::string, EndpointRecord> endpoint_cache_;
	std::unordered_map<uint64_t, InFlight> in_flight_;
	size_t local_in_flight_ { 0 };
	std::unordered_map<std::string, size_t> region_in_flight_;
};

MySQLAwsLocalityManager::MySQLAwsLocalityManager(AwsLocalityManagerConfig config)
	: impl_(std::make_unique<Impl>(std::move(config))) {}

MySQLAwsLocalityManager::~MySQLAwsLocalityManager() = default;

void MySQLAwsLocalityManager::configure(
	std::vector<AwsLocalityHostgroupConfig> hostgroups) {
	impl_->configure(std::move(hostgroups));
}

void MySQLAwsLocalityManager::set_enabled(bool enabled) {
	impl_->set_enabled(enabled);
}

void MySQLAwsLocalityManager::request_refresh() {
	impl_->request_refresh();
}

std::shared_ptr<const AwsLocalitySnapshot> MySQLAwsLocalityManager::snapshot() const {
	return impl_->snapshot();
}

std::vector<AwsLocalitySnapshotEntry> MySQLAwsLocalityManager::diagnostic_rows() const {
	return impl_->diagnostic_rows();
}

void MySQLAwsLocalityManager::shutdown() {
	impl_->shutdown();
}
