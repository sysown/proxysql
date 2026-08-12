#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "MySQL_Authentication.hpp"
#include "MySQL_Backend_Auth.h"

#include <cstring>
#include <string>

extern MySQL_Authentication *GloMyAuth;

static bool add_backend_user(const char *username, const char *password,
	const char *attributes) {
	return GloMyAuth->add(
		(char *)username, (char *)password, USERNAME_BACKEND,
		false, 0, (char *)"", false, false, false, 100,
		(char *)attributes, (char *)"");
}

static void test_password_defaults() {
	ok(parse_mysql_backend_auth_policy("db_user", "", false).type == MySQLBackendAuthType::PASSWORD,
		"empty attributes use password authentication");
	ok(parse_mysql_backend_auth_policy("db_user", "{}", false).type == MySQLBackendAuthType::PASSWORD,
		"empty attributes object uses password authentication");
}

static void test_aws_iam_policy() {
	const MySQLBackendAuthPolicy policy = parse_mysql_backend_auth_policy(
		"iam_user", "{\"backend_auth\":{\"type\":\"aws_iam\"}}", false);
	ok(policy.type == MySQLBackendAuthType::AWS_IAM,
		"aws_iam backend_auth type selects IAM authentication");
	ok(policy.database_user == "iam_user",
		"policy preserves the mapped backend username");
	ok(!policy.ignored_password,
		"IAM policy with an empty password does not mark a password ignored");

	const MySQLBackendAuthPolicy with_password = parse_mysql_backend_auth_policy(
		"iam_user", "{\"backend_auth\":{\"type\":\"aws_iam\"}}", true);
	ok(with_password.type == MySQLBackendAuthType::AWS_IAM && with_password.ignored_password,
		"IAM policy marks a configured backend password as ignored");
}

static void test_invalid_attribute_shapes() {
	const MySQLBackendAuthPolicy scalar = parse_mysql_backend_auth_policy("db_user", "\"value\"", false);
	ok(scalar.type == MySQLBackendAuthType::INVALID && scalar.failure_code == "attributes_not_object",
		"scalar attributes are rejected without parsing credentials");
	const MySQLBackendAuthPolicy array = parse_mysql_backend_auth_policy("db_user", "[]", false);
	ok(array.type == MySQLBackendAuthType::INVALID && array.failure_code == "attributes_not_object",
		"array attributes are rejected without parsing credentials");
	const MySQLBackendAuthPolicy malformed = parse_mysql_backend_auth_policy(
		"db_user", "{\"backend_auth\":FAKE_AWS_SECRET}", false);
	ok(malformed.type == MySQLBackendAuthType::INVALID && malformed.failure_code == "attributes_not_object",
		"malformed attributes are rejected without exposing their contents");
}

static void test_invalid_backend_auth_shapes() {
	const char *invalid_values[] = { "\"aws_iam\"", "[]", "null" };
	for (const char *value : invalid_values) {
		const std::string attributes = std::string("{\"backend_auth\":") + value + "}";
		const MySQLBackendAuthPolicy policy = parse_mysql_backend_auth_policy("db_user", attributes, false);
		ok(policy.type == MySQLBackendAuthType::INVALID && policy.failure_code == "backend_auth_not_object",
			"non-object backend_auth is rejected");
	}
}

static void test_invalid_type_values() {
	const MySQLBackendAuthPolicy missing = parse_mysql_backend_auth_policy("db_user", "{\"backend_auth\":{}}", false);
	ok(missing.type == MySQLBackendAuthType::INVALID && missing.failure_code == "type_missing",
		"backend_auth without type is rejected");
	const MySQLBackendAuthPolicy non_string = parse_mysql_backend_auth_policy(
		"db_user", "{\"backend_auth\":{\"type\":1}}", false);
	ok(non_string.type == MySQLBackendAuthType::INVALID && non_string.failure_code == "type_not_string",
		"non-string backend_auth type is rejected");
	const MySQLBackendAuthPolicy unknown = parse_mysql_backend_auth_policy(
		"db_user", "{\"backend_auth\":{\"type\":\"kerberos\"}}", false);
	ok(unknown.type == MySQLBackendAuthType::INVALID && unknown.failure_code == "type_unsupported",
		"unknown backend_auth type is rejected");
	const MySQLBackendAuthPolicy differently_cased = parse_mysql_backend_auth_policy(
		"db_user", "{\"backend_auth\":{\"type\":\"AWS_IAM\"}}", false);
	ok(differently_cased.type == MySQLBackendAuthType::INVALID && differently_cased.failure_code == "type_unsupported",
		"differently-cased backend_auth type is rejected");
}

static void test_diagnostics_do_not_leak_attributes() {
	const MySQLBackendAuthPolicy policy = parse_mysql_backend_auth_policy(
		"db_user", "{\"backend_auth\":FAKE_AWS_SECRET,\"token\":\"FAKE_SESSION_TOKEN\"}", false);
	ok(policy.failure_code.find("FAKE_AWS_SECRET") == std::string::npos,
		"diagnostics do not expose fake AWS secrets");
	ok(policy.failure_code.find("FAKE_SESSION_TOKEN") == std::string::npos,
		"diagnostics do not expose fake session tokens");
	ok(policy.failure_code.find("backend_auth") == std::string::npos,
		"diagnostics do not expose raw malformed JSON");
}

static void test_resolver_uses_backend_account_only() {
	ok(add_backend_user("iam_backend", "unused-password",
		"{\"backend_auth\":{\"type\":\"aws_iam\"}}"),
		"backend IAM user is added to the real authentication store");
	const MySQLBackendAuthPolicy policy = resolve_mysql_backend_auth_policy(*GloMyAuth, "iam_backend");
	ok(policy.type == MySQLBackendAuthType::AWS_IAM,
		"resolver reads IAM policy from the backend account");
	ok(policy.database_user == "iam_backend" && policy.ignored_password,
		"resolver preserves username and ignores the backend password for IAM");
}

static void test_resolver_rejects_missing_or_inactive_backend_account() {
	const MySQLBackendAuthPolicy missing = resolve_mysql_backend_auth_policy(*GloMyAuth, "missing_backend");
	ok(missing.type == MySQLBackendAuthType::INVALID && missing.failure_code == "backend_user_not_found",
		"resolver rejects a missing backend account");

	ok(add_backend_user("inactive_backend", "password", ""),
		"inactive backend fixture is added");
	GloMyAuth->set_all_inactive(USERNAME_BACKEND);
	GloMyAuth->remove_inactives(USERNAME_BACKEND);
	const MySQLBackendAuthPolicy inactive = resolve_mysql_backend_auth_policy(*GloMyAuth, "inactive_backend");
	ok(inactive.type == MySQLBackendAuthType::INVALID && inactive.failure_code == "backend_user_not_found",
		"resolver rejects an inactive backend account after runtime removal");
}

int main() {
	plan(25);
	test_init_minimal();
	test_init_auth();

	test_password_defaults();
	test_aws_iam_policy();
	test_invalid_attribute_shapes();
	test_invalid_backend_auth_shapes();
	test_invalid_type_values();
	test_diagnostics_do_not_leak_attributes();
	test_resolver_uses_backend_account_only();
	test_resolver_rejects_missing_or_inactive_backend_account();

	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
