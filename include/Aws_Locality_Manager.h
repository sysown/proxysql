#ifndef AWS_LOCALITY_MANAGER_H
#define AWS_LOCALITY_MANAGER_H

#include "Aws_Locality_Types.h"
#include "json_fwd.hpp"

#include <cstdint>
#include <string_view>

AwsLocalityPolicy parse_aws_locality_policy(
	const nlohmann::json& policy_json,
	uint32_t hostgroup_id,
	AwsLocalityPolicyError& error);

AwsEndpointCandidate recognize_rds_endpoint(
	uint32_t hostgroup_id,
	std::string_view hostname,
	uint16_t port);

AwsLocalityClass classify_aws_locality(
	const AwsLocalLocation& local,
	const AwsBackendLocation& backend);

uint64_t aws_locality_effective_weight(
	int64_t configured_weight,
	double multiplier);

#endif // AWS_LOCALITY_MANAGER_H
