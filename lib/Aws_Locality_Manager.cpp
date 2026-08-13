#include "Aws_Locality_Manager.h"

#include "json.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <limits>
#include <string>

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
		return true;
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

std::string normalized_hostname(std::string_view input) {
	if (input.empty()) {
		return {};
	}

	std::string hostname(input);
	if (hostname.back() == '.') {
		hostname.pop_back();
	}
	if (hostname.empty() || hostname.back() == '.') {
		return {};
	}

	for (char& character : hostname) {
		const unsigned char value = static_cast<unsigned char>(character);
		if (!(std::isalnum(value) || character == '-' || character == '.')) {
			return {};
		}
		character = static_cast<char>(std::tolower(value));
	}
	return hostname;
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
		} else if (!std::islower(static_cast<unsigned char>(character)) &&
			!std::isdigit(static_cast<unsigned char>(character))) {
			return false;
		}
	}
	return hyphens >= 2 &&
		std::isdigit(static_cast<unsigned char>(region.back()));
}

bool contains_proxy_label(const std::string& prefix) {
	size_t begin = 0;
	while (begin < prefix.size()) {
		const size_t end = prefix.find('.', begin);
		const size_t length = end == std::string::npos
			? prefix.size() - begin : end - begin;
		if (length >= 6 && prefix.compare(begin, 6, "proxy-") == 0) {
			return true;
		}
		if (end == std::string::npos) {
			break;
		}
		begin = end + 1;
	}
	return false;
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
	result.hostname = normalized_hostname(hostname_input);
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
	if (contains_proxy_label(endpoint_prefix) || !valid_region(result.region)) {
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
