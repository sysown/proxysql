#include "tap.h"

#include "json.hpp"
#include "Aws_Locality_Manager.h"

#include <cstdint>
#include <limits>
#include <string>

using nlohmann::json;

namespace {

void test_policy_validation() {
	AwsLocalityPolicyError error;
	AwsLocalityPolicy policy = parse_aws_locality_policy(
		json::parse(R"({"same_region_multiplier":2.5,"same_az_multiplier":4.75})"),
		10, error);
	ok(policy.valid && policy.same_region_multiplier == 2.5 &&
		policy.same_az_multiplier == 4.75 &&
		policy.refresh_interval_seconds == 300 &&
		policy.stale_ttl_seconds == 1800 && error.field.empty(),
		"valid policy uses explicit multipliers and timing defaults");

	policy = parse_aws_locality_policy(json::parse(
		R"({"same_region_multiplier":1.0,"same_az_multiplier":10.0,"refresh_interval_seconds":30,"stale_ttl_seconds":604800})"),
		11, error);
	ok(policy.valid && policy.refresh_interval_seconds == 30 &&
		policy.stale_ttl_seconds == 604800,
		"inclusive multiplier and timing boundaries are accepted");

	policy = parse_aws_locality_policy(json::parse(
		R"({"same_az_multiplier":4.0})"), 12, error);
	ok(!policy.valid && error.field == "same_region_multiplier",
		"missing same-Region multiplier rejects the complete locality policy");

	policy = parse_aws_locality_policy(json::parse(
		R"({"same_region_multiplier":2.0,"same_az_multiplier":"4"})"), 13, error);
	ok(!policy.valid && error.field == "same_az_multiplier",
		"a numeric-looking string is not accepted as a multiplier");

	json non_finite = {
		{"same_region_multiplier", std::numeric_limits<double>::quiet_NaN()},
		{"same_az_multiplier", 4.0}
	};
	policy = parse_aws_locality_policy(non_finite, 14, error);
	ok(!policy.valid && error.field == "same_region_multiplier",
		"non-finite multiplier is rejected");

	policy = parse_aws_locality_policy(json::parse(
		R"({"same_region_multiplier":5.0,"same_az_multiplier":4.0})"), 15, error);
	ok(!policy.valid && error.field == "same_az_multiplier",
		"same-AZ multiplier cannot be lower than same-Region multiplier");

	policy = parse_aws_locality_policy(json::parse(
		R"({"same_region_multiplier":0.99,"same_az_multiplier":4.0})"), 16, error);
	ok(!policy.valid && error.field == "same_region_multiplier",
		"multiplier below 1.0 is rejected");

	policy = parse_aws_locality_policy(json::parse(
		R"({"same_region_multiplier":2.0,"same_az_multiplier":10.01})"), 17, error);
	ok(!policy.valid && error.field == "same_az_multiplier",
		"multiplier above 10.0 is rejected");

	policy = parse_aws_locality_policy(json::parse(
		R"({"same_region_multiplier":2.0,"same_az_multiplier":4.0,"refresh_interval_seconds":29})"),
		18, error);
	ok(!policy.valid && error.field == "refresh_interval_seconds",
		"refresh interval below 30 seconds is rejected");

	policy = parse_aws_locality_policy(json::parse(
		R"({"same_region_multiplier":2.0,"same_az_multiplier":4.0,"refresh_interval_seconds":500,"stale_ttl_seconds":499})"),
		19, error);
	ok(!policy.valid && error.field == "stale_ttl_seconds",
		"stale TTL shorter than refresh interval is rejected");

	policy = parse_aws_locality_policy(json::parse(
		R"({"same_region_multiplier":2.0,"same_az_multiplier":4.0,"refresh_interval_seconds":3600})"),
		20, error);
	ok(!policy.valid && error.field == "stale_ttl_seconds",
		"omitted stale TTL cannot undercut an explicit refresh interval");

	policy = parse_aws_locality_policy(json::array(), 21, error);
	ok(!policy.valid && error.field == "locality_awareness",
		"non-object locality policy is rejected");
}

void test_endpoint_recognition() {
	AwsEndpointCandidate candidate = recognize_rds_endpoint(
		10, "DB-1.ABCDEF.us-east-1.rds.amazonaws.com.", 3306);
	ok(candidate.recognized &&
		candidate.hostname == "db-1.abcdef.us-east-1.rds.amazonaws.com" &&
		candidate.region == "us-east-1" && candidate.partition == "aws" &&
		candidate.hostgroup_id == 10 && candidate.port == 3306,
		"standard RDS endpoint is normalized and routed to its Region");

	candidate = recognize_rds_endpoint(
		11, "db.cluster-abcdefghijkl.us-gov-west-1.rds.amazonaws.com", 3306);
	ok(candidate.recognized && candidate.region == "us-gov-west-1" &&
		candidate.partition == "aws-us-gov",
		"GovCloud RDS endpoint is recognized");

	candidate = recognize_rds_endpoint(
		12, "db.cluster-ro-abcdefghijkl.cn-north-1.rds.amazonaws.com.cn", 3306);
	ok(candidate.recognized && candidate.region == "cn-north-1" &&
		candidate.partition == "aws-cn",
		"China RDS endpoint is recognized");

	candidate = recognize_rds_endpoint(
		13, "db.cluster-custom-abcdefghijkl.eu-west-1.rds.amazonaws.com", 3306);
	ok(candidate.recognized && candidate.region == "eu-west-1",
		"Aurora custom endpoint is a valid discovery candidate");

	ok(!recognize_rds_endpoint(14, "db.proxy-abcdefghijkl.us-east-1.rds.amazonaws.com", 3306).recognized,
		"RDS Proxy endpoint is excluded from the first version");
	candidate = recognize_rds_endpoint(
		14, "proxy-app1.abcdefghijkl.us-east-1.rds.amazonaws.com", 3306);
	ok(candidate.recognized && candidate.region == "us-east-1",
		"an ordinary RDS identifier beginning with proxy- is not misclassified as RDS Proxy");
	ok(!recognize_rds_endpoint(15, "db.internal.example.com", 3306).recognized,
		"custom CNAME is not inferred as RDS");
	ok(!recognize_rds_endpoint(16, "db.us-east-1.rds.amazonaws.com.evil.example", 3306).recognized,
		"AWS-looking hostname with a false suffix is rejected");
	ok(!recognize_rds_endpoint(17, "db.INVALID_REGION.rds.amazonaws.com", 3306).recognized,
		"malformed candidate Region is rejected");
}

void test_classification() {
	const AwsLocalLocation local {"us-east-1", "us-east-1a", "111122223333"};

	AwsBackendLocation backend {
		AwsEndpointType::instance, "us-east-1", "us-east-1a", "111122223333"
	};
	ok(classify_aws_locality(local, backend) == AwsLocalityClass::same_az,
		"instance in same account and AZ receives same-AZ classification");

	backend.account_id = "444455556666";
	ok(classify_aws_locality(local, backend) == AwsLocalityClass::same_region,
		"same AZ name in a different account is only same-Region");

	backend.account_id.clear();
	ok(classify_aws_locality(local, backend) == AwsLocalityClass::same_region,
		"unknown backend account cannot receive same-AZ classification");

	backend = {AwsEndpointType::cluster, "us-east-1", "us-east-1a", "111122223333"};
	ok(classify_aws_locality(local, backend) == AwsLocalityClass::same_region,
		"cluster endpoint never receives same-AZ classification");

	backend = {AwsEndpointType::reader, "us-east-1", "", "111122223333"};
	ok(classify_aws_locality(local, backend) == AwsLocalityClass::same_region,
		"reader endpoint can receive same-Region classification");

	backend = {AwsEndpointType::instance, "eu-west-1", "eu-west-1a", "111122223333"};
	ok(classify_aws_locality(local, backend) == AwsLocalityClass::remote,
		"different known Region is remote");

	backend.region.clear();
	ok(classify_aws_locality(local, backend) == AwsLocalityClass::unknown,
		"missing backend Region is neutral");

	AwsLocalLocation unknown_local {"", "", ""};
	backend.region = "us-east-1";
	ok(classify_aws_locality(unknown_local, backend) == AwsLocalityClass::unknown,
		"missing local Region is neutral");
}

void test_effective_weight() {
	ok(aws_locality_effective_weight(3, 2.5) == 7,
		"effective weight truncates toward zero");
	ok(aws_locality_effective_weight(0, 10.0) == 0,
		"configured zero weight remains zero");
	ok(aws_locality_effective_weight(-1, 4.0) == 0,
		"unexpected negative configured weight is safely neutralized");
	ok(aws_locality_effective_weight(std::numeric_limits<int64_t>::max(), 10.0) ==
		std::numeric_limits<uint64_t>::max(),
		"effective weight saturates before the 64-bit accumulator");
	ok(aws_locality_effective_weight(10, 1.0) == 10,
		"neutral multiplier preserves configured weight");
}

} // namespace

int main() {
	plan(34);
	test_policy_validation();
	test_endpoint_recognition();
	test_classification();
	test_effective_weight();
	return exit_status();
}
