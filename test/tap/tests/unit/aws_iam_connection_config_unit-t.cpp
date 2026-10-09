#include "tap.h"

#include "MySQL_Backend_Auth.h"
#include "MySQL_HostGroups_Manager.h"

#include <cstring>
#include <cstdio>
#include <string>
#include <unistd.h>

void init_myhgc_hostgroup_settings(const char* hostgroup_settings, MyHGC* myhgc);

namespace {

AwsIamConnectionConfigInput valid_input(const char* endpoint, const char* region) {
	AwsIamConnectionConfigInput input;
	input.database_user = "iam_database_user";
	input.configured_endpoint = endpoint;
	input.port = 3306;
	input.region = region;
	input.use_ssl = true;
	input.ssl_ca = "/etc/ssl/rds-ca.pem";
	input.support_compiled = true;
	return input;
}

void ok_status(const AwsIamConnectionConfigInput& input, const char* name) {
	const AwsIamConnectionConfigResult result = validate_mysql_aws_iam_connection(input);
	ok(result.status == AwsIamConnectionConfigStatus::OK, "%s", name);
	if (result.status == AwsIamConnectionConfigStatus::OK) {
		ok(result.key.endpoint == input.configured_endpoint &&
			result.key.port == input.port &&
			result.key.region == input.region &&
			result.key.database_user == input.database_user,
			"%s preserves the exact IAM token key", name);
	}
}

void failure_status(const AwsIamConnectionConfigInput& input,
	AwsIamConnectionConfigStatus expected_status, const char* expected_code, const char* name) {
	const AwsIamConnectionConfigResult result = validate_mysql_aws_iam_connection(input);
	ok(result.status == expected_status && result.failure_code == expected_code, "%s", name);
}

void test_valid_rds_endpoint_shapes() {
	ok_status(valid_input("instance.abcdef.us-east-1.rds.amazonaws.com", "us-east-1"),
		"RDS instance endpoint is accepted");
	ok_status(valid_input("cluster-main.abcdef.us-east-1.rds.amazonaws.com", "us-east-1"),
		"Aurora cluster endpoint is accepted");
	ok_status(valid_input("cluster-ro-main.abcdef.us-east-1.rds.amazonaws.com", "us-east-1"),
		"Aurora reader endpoint is accepted");
	ok_status(valid_input("cluster-custom-main.abcdef.us-east-1.rds.amazonaws.com", "us-east-1"),
		"Aurora custom-cluster endpoint is accepted");
	ok_status(valid_input("instance.abcdef.cn-north-1.rds.amazonaws.com.cn", "cn-north-1"),
		"China RDS endpoint is accepted");
	ok_status(valid_input("instance.abcdef.us-gov-west-1.rds.amazonaws.com", "us-gov-west-1"),
		"GovCloud RDS endpoint is accepted");
	ok_status(valid_input("instance.abcdef.us-iso-east-1.rds.c2s.ic.gov", "us-iso-east-1"),
		"ISO RDS endpoint is accepted");
	ok_status(valid_input("instance.abcdef.us-isob-east-1.rds.sc2s.sgov.gov", "us-isob-east-1"),
		"ISOB RDS endpoint is accepted");
}

void test_validation_failures() {
	AwsIamConnectionConfigInput input = valid_input("instance.abcdef.us-east-1.rds.amazonaws.com", "us-east-1");
	input.support_compiled = false;
	failure_status(input, AwsIamConnectionConfigStatus::SUPPORT_NOT_COMPILED, "support_not_compiled",
		"uncompiled AWS IAM support is rejected before tuple validation");

	input = valid_input("instance.abcdef.us-east-1.rds.amazonaws.com", "");
	failure_status(input, AwsIamConnectionConfigStatus::MISSING_REGION, "missing_region",
		"missing IAM region is rejected");

	input = valid_input("instance.abcdef.us-west-2.rds.amazonaws.com", "us-east-1");
	failure_status(input, AwsIamConnectionConfigStatus::REGION_ENDPOINT_MISMATCH, "region_endpoint_mismatch",
		"endpoint region must equal IAM region");

	input = valid_input("", "us-east-1");
	failure_status(input, AwsIamConnectionConfigStatus::INVALID_ENDPOINT, "invalid_endpoint",
		"empty endpoint is rejected");
	input = valid_input("instance.abcdef.us-east-1.rds.amazonaws.com.", "us-east-1");
	failure_status(input, AwsIamConnectionConfigStatus::INVALID_ENDPOINT, "invalid_endpoint",
		"trailing-dot endpoint is rejected");
	input = valid_input("192.0.2.10", "us-east-1");
	failure_status(input, AwsIamConnectionConfigStatus::INVALID_ENDPOINT, "invalid_endpoint",
		"IPv4 endpoint is rejected");
	input = valid_input("2001:db8::1", "us-east-1");
	failure_status(input, AwsIamConnectionConfigStatus::INVALID_ENDPOINT, "invalid_endpoint",
		"IPv6 endpoint is rejected");
	input = valid_input("database.example.com", "us-east-1");
	failure_status(input, AwsIamConnectionConfigStatus::INVALID_ENDPOINT, "invalid_endpoint",
		"custom CNAME endpoint is rejected");
	const std::string label(63, 'a');
	const std::string endpoint_over_dns_limit = label + "." + label + "." + label + "." + label +
		".us-east-1.rds.amazonaws.com";
	input = valid_input(endpoint_over_dns_limit.c_str(), "us-east-1");
	failure_status(input, AwsIamConnectionConfigStatus::INVALID_ENDPOINT, "invalid_endpoint",
		"endpoint exceeding the DNS presentation limit is rejected");

	input = valid_input("instance.abcdef.us-east-1.rds.amazonaws.com", "us-east-1");
	input.port = 0;
	failure_status(input, AwsIamConnectionConfigStatus::UNIX_SOCKET_NOT_ALLOWED, "unix_socket_not_allowed",
		"Unix-socket IAM connection is rejected");

	input = valid_input("instance.abcdef.us-east-1.rds.amazonaws.com", "us-east-1");
	input.use_ssl = false;
	failure_status(input, AwsIamConnectionConfigStatus::TLS_REQUIRED, "tls_required",
		"IAM connection requires TLS");

	input = valid_input("instance.abcdef.us-east-1.rds.amazonaws.com", "us-east-1");
	input.ssl_ca.clear();
	input.ssl_capath.clear();
	failure_status(input, AwsIamConnectionConfigStatus::CA_TRUST_REQUIRED, "ca_trust_required",
		"IAM connection requires a CA file or CA path");
}

void test_malformed_hostgroup_settings_diagnostics_are_redacted() {
	MyHGC hostgroup(43);
	FILE* captured = tmpfile();
	if (captured == nullptr) {
		ok(false, "temporary stderr capture file is available");
		return;
	}
	fflush(stderr);
	const int saved_stderr = dup(STDERR_FILENO);
	if (saved_stderr < 0 || dup2(fileno(captured), STDERR_FILENO) < 0) {
		if (saved_stderr >= 0) {
			close(saved_stderr);
		}
		fclose(captured);
		ok(false, "stderr is redirected for malformed-settings diagnostics");
		return;
	}

	init_myhgc_hostgroup_settings("{\"aws_iam_region\":FAKE_AWS_SECRET}", &hostgroup);
	fflush(stderr);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stderr);

	std::string diagnostics;
	char buffer[256];
	rewind(captured);
	while (fgets(buffer, sizeof(buffer), captured) != nullptr) {
		diagnostics += buffer;
	}
	fclose(captured);
	ok(diagnostics.find("hostgroup_settings_parse_failed") != std::string::npos &&
		diagnostics.find("FAKE_AWS_SECRET") == std::string::npos,
		"malformed hostgroup settings diagnostics use a redacted parse failure category without sensitive tokens");
	ok(diagnostics.find("hostgroup 43") != std::string::npos,
		"malformed hostgroup settings diagnostics identify the hostgroup without payload details");
}

void test_hostgroup_region_parser_clears_rejected_values() {
	MyHGC hostgroup(42);
	init_myhgc_hostgroup_settings("{\"aws_iam_region\":\"us-east-1\"}", &hostgroup);
	ok(hostgroup.attributes.aws_iam_region != nullptr &&
		strcmp(hostgroup.attributes.aws_iam_region, "us-east-1") == 0,
		"valid hostgroup IAM region is owned by the hostgroup");

	const char* invalid_settings[] = {
		"{\"aws_iam_region\":1}",
		"{\"aws_iam_region\":\"\"}",
		"{\"aws_iam_region\":\"us east 1\"}",
	};
	for (const char* settings : invalid_settings) {
		init_myhgc_hostgroup_settings(settings, &hostgroup);
		ok(hostgroup.attributes.aws_iam_region == nullptr,
			"rejected hostgroup IAM region does not retain a previous value");
		init_myhgc_hostgroup_settings("{\"aws_iam_region\":\"us-east-1\"}", &hostgroup);
	}
}

} // namespace

int main() {
	plan(0);
	test_valid_rds_endpoint_shapes();
	test_validation_failures();
	test_hostgroup_region_parser_clears_rejected_values();
	test_malformed_hostgroup_settings_diagnostics_are_redacted();
	return exit_status();
}
