/**
 * @file azure_entra_connection_config_unit-t.cpp
 * @brief Backend connection validation for 'azure_entra' (issue #6649).
 */
#include "tap.h"

#include "MySQL_Backend_Auth.h"

#include <string>

namespace {

AwsIamConnectionConfigInput entra_input(const char *endpoint) {
	AwsIamConnectionConfigInput input;
	input.database_user = "entra_app";
	input.configured_endpoint = endpoint;
	input.port = 3306;
	input.use_ssl = true;
	input.ssl_ca = "/etc/ssl/azure-ca.pem";
	input.support_compiled = true;
	return input;
}

void expect_ok(const AwsIamConnectionConfigInput& input, const char *name) {
	const AwsIamConnectionConfigResult r = validate_mysql_azure_entra_connection(input);
	ok(r.status == AwsIamConnectionConfigStatus::OK &&
		r.key.endpoint == input.configured_endpoint && r.key.port == input.port &&
		r.key.region.empty() && r.key.database_user == input.database_user, "%s", name);
}

void expect_fail(const AwsIamConnectionConfigInput& input, AwsIamConnectionConfigStatus status,
	const char *code, const char *name) {
	const AwsIamConnectionConfigResult r = validate_mysql_azure_entra_connection(input);
	ok(r.status == status && r.failure_code == code, "%s", name);
}

void test_accepted_endpoints() {
	expect_ok(entra_input("app.mysql.database.azure.com"), "valid_public");
	expect_ok(entra_input("x.mysql.database.chinacloudapi.cn"), "valid_sovereign: China");
	expect_ok(entra_input("x.mysql.database.usgovcloudapi.net"), "valid_sovereign: US Gov");
	const AwsIamConnectionConfigResult upper = validate_mysql_azure_entra_connection(
		entra_input("App.PrivateLink.MySQL.Database.Azure.com"));
	ok(upper.status == AwsIamConnectionConfigStatus::OK &&
		upper.key.endpoint == "app.privatelink.mysql.database.azure.com",
		"uppercase_and_privatelink_accepted, keyed in lower case");
	AwsIamConnectionConfigInput with_region = entra_input("app.mysql.database.azure.com");
	with_region.region = "eu-west-1";
	expect_ok(with_region, "region_ignored");
}

void test_rejected_endpoints() {
	using S = AwsIamConnectionConfigStatus;
	for (const char *endpoint : { "db.cluster-x.us-east-1.rds.amazonaws.com", "10.0.0.5",
			"mysql.database.azure.com", "evil.mysql.database.azure.com.attacker.io",
			"app.mysql.database.azure.com.", "", "bad_label.mysql.database.azure.com" }) {
		expect_fail(entra_input(endpoint), S::INVALID_ENDPOINT, "invalid_endpoint",
			(std::string("rejected endpoint '") + endpoint + "'").c_str());
	}
}

void test_connection_requirements() {
	using S = AwsIamConnectionConfigStatus;
	AwsIamConnectionConfigInput input = entra_input("app.mysql.database.azure.com");
	input.support_compiled = false;
	expect_fail(input, S::SUPPORT_NOT_COMPILED, "support_not_compiled", "support_not_compiled");
	input = entra_input("app.mysql.database.azure.com");
	input.port = 0;
	expect_fail(input, S::UNIX_SOCKET_NOT_ALLOWED, "unix_socket_not_allowed", "unix_socket");
	input = entra_input("app.mysql.database.azure.com");
	input.use_ssl = false;
	expect_fail(input, S::TLS_REQUIRED, "tls_required", "tls_required");
	input = entra_input("app.mysql.database.azure.com");
	input.ssl_ca.clear();
	input.ssl_capath.clear();
	expect_fail(input, S::CA_TRUST_REQUIRED, "ca_trust_required", "ca_required");
	input.ssl_capath = "/etc/ssl/certs";
	expect_ok(input, "a CA path alone is enough");
}

void test_dispatch() {
	AwsIamConnectionConfigInput rds = entra_input("db.cluster-x.us-east-1.rds.amazonaws.com");
	rds.region = "us-east-1";
	const AwsIamConnectionConfigResult aws = validate_mysql_aws_iam_connection(rds);
	const AwsIamConnectionConfigResult via = validate_mysql_backend_token_connection(
		MySQLBackendAuthType::AWS_IAM, rds);
	ok(via.status == aws.status && via.key == aws.key, "dispatch: AWS_IAM uses the AWS check");
	const AwsIamConnectionConfigInput entra = entra_input("app.mysql.database.azure.com");
	ok(validate_mysql_backend_token_connection(MySQLBackendAuthType::AZURE_ENTRA, entra).status ==
		AwsIamConnectionConfigStatus::OK, "dispatch: AZURE_ENTRA uses the Entra check");
	const AwsIamConnectionConfigResult pw = validate_mysql_backend_token_connection(
		MySQLBackendAuthType::PASSWORD, entra);
	ok(pw.status == AwsIamConnectionConfigStatus::INVALID_ENDPOINT && pw.failure_code == "not_token_auth",
		"dispatch: a non-token type is refused");
}

} // namespace

int main() {
	plan(0);
	test_accepted_endpoints();
	test_rejected_endpoints();
	test_connection_requirements();
	test_dispatch();
	return exit_status();
}
