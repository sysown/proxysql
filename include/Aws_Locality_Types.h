#ifndef AWS_LOCALITY_TYPES_H
#define AWS_LOCALITY_TYPES_H

#include <cstdint>
#include <string>

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

#endif // AWS_LOCALITY_TYPES_H
