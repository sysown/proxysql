#include "../deps/json/json.hpp"

#include "MySQL_Backend_Auth.h"
#include "MySQL_Authentication.hpp"

namespace {

MySQLBackendAuthPolicy invalid_policy(std::string_view database_user, const char* failure_code) {
	MySQLBackendAuthPolicy policy;
	policy.database_user = database_user;
	policy.failure_code = failure_code;
	return policy;
}

} // namespace

const char* mysql_backend_auth_type_name(MySQLBackendAuthType type) {
	switch (type) {
		case MySQLBackendAuthType::PASSWORD:
			return "password";
		case MySQLBackendAuthType::AWS_IAM:
			return "aws_iam";
		case MySQLBackendAuthType::INVALID:
			return "invalid";
	}
	return "invalid";
}

MySQLBackendAuthPolicy parse_mysql_backend_auth_policy(
	std::string_view database_user,
	std::string_view attributes,
	bool backend_password_is_nonempty)
{
	MySQLBackendAuthPolicy policy;
	policy.database_user = database_user;

	if (attributes.empty()) {
		policy.type = MySQLBackendAuthType::PASSWORD;
		return policy;
	}

	const nlohmann::json parsed = nlohmann::json::parse(
		attributes.data(), attributes.data() + attributes.size(), nullptr, false);
	if (parsed.is_discarded() || !parsed.is_object()) {
		return invalid_policy(database_user, "attributes_not_object");
	}

	const auto backend_auth = parsed.find("backend_auth");
	if (backend_auth == parsed.end()) {
		policy.type = MySQLBackendAuthType::PASSWORD;
		return policy;
	}
	if (!backend_auth->is_object()) {
		return invalid_policy(database_user, "backend_auth_not_object");
	}

	const auto type = backend_auth->find("type");
	if (type == backend_auth->end()) {
		return invalid_policy(database_user, "type_missing");
	}
	if (!type->is_string()) {
		return invalid_policy(database_user, "type_not_string");
	}
	if (type->get<std::string>() != "aws_iam") {
		return invalid_policy(database_user, "type_unsupported");
	}

	policy.type = MySQLBackendAuthType::AWS_IAM;
	policy.ignored_password = backend_password_is_nonempty;
	return policy;
}

MySQLBackendAuthPolicy resolve_mysql_backend_auth_policy(
	MySQL_Authentication& authentication,
	const char* mapped_backend_username)
{
	const std::string_view database_user =
		mapped_backend_username != nullptr ? mapped_backend_username : "";
	if (mapped_backend_username == nullptr) {
		return invalid_policy(database_user, "backend_user_not_found");
	}

	account_details_t account = authentication.lookup(
		const_cast<char*>(mapped_backend_username), USERNAME_BACKEND, { false, false, true });
	if (account.password == nullptr) {
		free_account_details(account);
		return invalid_policy(database_user, "backend_user_not_found");
	}

	const MySQLBackendAuthPolicy policy = parse_mysql_backend_auth_policy(
		database_user,
		account.attributes != nullptr ? account.attributes : "",
		account.password[0] != '\0');
	free_account_details(account);
	return policy;
}
