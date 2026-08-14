#ifndef __CLASS_AWS_LOCALITY_TYPES_H
#define __CLASS_AWS_LOCALITY_TYPES_H

#include <chrono>
#include <cctype>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

inline std::string aws_locality_normalized_hostname(std::string_view input) {
	if (input.empty()) return {};
	std::string hostname(input);
	if (hostname.back() == '.') hostname.pop_back();
	if (hostname.empty() || hostname.back() == '.') return {};
	for (char& character : hostname) {
		const unsigned char value = static_cast<unsigned char>(character);
		if (!(std::isalnum(value) || character == '-' || character == '.')) return {};
		character = static_cast<char>(std::tolower(value));
	}
	return hostname;
}

enum class AwsEndpointType : uint8_t {
	unknown,
	instance,
	cluster,
	reader,
	custom,
};

enum class AwsLocalityClass : uint8_t {
	unknown,
	remote,
	same_region,
	same_az,
};

enum class AwsLocalityMetadataStatus : uint8_t {
	disabled,
	pending,
	fresh,
	stale,
	expired,
	error,
};

struct AwsLocalityPolicy {
	bool valid { false };
	double same_region_multiplier { 1.0 };
	double same_az_multiplier { 1.0 };
	uint32_t refresh_interval_seconds { 300 };
	uint32_t stale_ttl_seconds { 1800 };
};

struct AwsLocalityPolicyError {
	uint32_t hostgroup_id { 0 };
	std::string field;
};

struct AwsEndpointCandidate {
	bool recognized { false };
	uint32_t hostgroup_id { 0 };
	std::string hostname;
	uint16_t port { 0 };
	std::string region;
	std::string partition;
};

struct AwsLocalLocation {
	std::string region;
	std::string availability_zone;
	std::string account_id;
};

struct AwsBackendLocation {
	AwsEndpointType endpoint_type { AwsEndpointType::unknown };
	std::string region;
	std::string availability_zone;
	std::string account_id;
};

enum class AwsMetadataRequestKind : uint8_t {
	local_location,
	rds_region,
};

enum class AwsMetadataStatus : uint8_t {
	ok,
	provider_unavailable,
	access_denied,
	throttled,
	imds_unavailable,
	timeout,
	cancelled,
	invalid_response,
	shutdown,
};

struct AwsMetadataRequestHandle {
	uint64_t value { 0 };
};

struct AwsMetadataRequest {
	AwsMetadataRequestKind kind { AwsMetadataRequestKind::local_location };
	uint64_t opaque_id { 0 };
	uint64_t generation { 0 };
	std::string region;
	std::string partition;
	std::vector<AwsEndpointCandidate> endpoints;
	std::chrono::steady_clock::time_point deadline {};
};

struct AwsMetadataEndpoint {
	std::string hostname;
	uint16_t port { 0 };
	AwsEndpointType endpoint_type { AwsEndpointType::unknown };
	std::string region;
	std::string availability_zone;
	std::string account_id;
};

struct AwsMetadataResult {
	AwsMetadataStatus status { AwsMetadataStatus::provider_unavailable };
	AwsLocalLocation local;
	std::vector<AwsMetadataEndpoint> endpoints;
	std::string failure_category;
};

struct AwsMetadataCompletion {
	uint64_t opaque_id { 0 };
	uint64_t generation { 0 };
	AwsMetadataResult result;
};

class AwsMetadataCompletionSink {
public:
	virtual void post(AwsMetadataCompletion&& completion) = 0;
	virtual ~AwsMetadataCompletionSink() = default;
};

class AwsMetadataProvider {
public:
	virtual AwsMetadataRequestHandle request(
		const AwsMetadataRequest& request,
		std::weak_ptr<AwsMetadataCompletionSink> sink) = 0;
	virtual void cancel(AwsMetadataRequestHandle handle) = 0;
	virtual void shutdown() = 0;
	virtual ~AwsMetadataProvider() = default;
};

struct AwsLocalityBackendConfig {
	AwsEndpointCandidate endpoint;
	int64_t configured_weight { 0 };

	AwsLocalityBackendConfig() = default;
	AwsLocalityBackendConfig(AwsEndpointCandidate value, int64_t weight = 0)
		: endpoint(std::move(value)), configured_weight(weight) {}
};

struct AwsLocalityHostgroupConfig {
	uint32_t hostgroup_id { 0 };
	AwsLocalityPolicy policy;
	std::vector<AwsLocalityBackendConfig> backends;
};

#endif // __CLASS_AWS_LOCALITY_TYPES_H
