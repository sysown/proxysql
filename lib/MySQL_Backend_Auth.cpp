#include "../deps/json/json.hpp"

#include "MySQL_Backend_Auth.h"
#include "MySQL_Authentication.hpp"

#include <vector>

namespace {

MySQLBackendAuthPolicy invalid_policy(std::string_view database_user, const char* failure_code) {
	MySQLBackendAuthPolicy policy;
	policy.database_user = database_user;
	policy.failure_code = failure_code;
	return policy;
}

AwsIamConnectionConfigResult invalid_connection_config(
	AwsIamConnectionConfigStatus status, const char* failure_code) {
	AwsIamConnectionConfigResult result;
	result.status = status;
	result.failure_code = failure_code;
	return result;
}

bool is_dns_label(const std::string& label) {
	if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') {
		return false;
	}
	for (const unsigned char c : label) {
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-')) {
			return false;
		}
	}
	return true;
}

bool split_rds_endpoint(const std::string& endpoint, std::string& endpoint_region) {
	if (endpoint.empty() || endpoint.size() > 253 || endpoint.back() == '.') {
		return false;
	}

	std::vector<std::string> labels;
	size_t begin = 0;
	while (begin < endpoint.size()) {
		const size_t end = endpoint.find('.', begin);
		const std::string label = endpoint.substr(begin, end == std::string::npos ? end : end - begin);
		if (!is_dns_label(label)) {
			return false;
		}
		labels.push_back(label);
		if (end == std::string::npos) {
			break;
		}
		begin = end + 1;
	}

	static const std::vector<std::vector<std::string>> suffixes {
		{ "rds", "amazonaws", "com" },
		{ "rds", "amazonaws", "com", "cn" },
		{ "rds", "c2s", "ic", "gov" },
		{ "rds", "sc2s", "sgov", "gov" },
	};
	for (const auto& suffix : suffixes) {
		if (labels.size() <= suffix.size() + 1) {
			continue;
		}
		const size_t suffix_start = labels.size() - suffix.size();
		bool suffix_matches = true;
		for (size_t i = 0; i < suffix.size(); ++i) {
			if (labels[suffix_start + i] != suffix[i]) {
				suffix_matches = false;
				break;
			}
		}
		if (suffix_matches) {
			endpoint_region = labels[suffix_start - 1];
			return true;
		}
	}
	return false;
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

AwsIamConnectionConfigResult validate_mysql_aws_iam_connection(
	const AwsIamConnectionConfigInput& input)
{
	if (!input.support_compiled) {
		return invalid_connection_config(AwsIamConnectionConfigStatus::SUPPORT_NOT_COMPILED,
			"support_not_compiled");
	}
	if (input.region.empty()) {
		return invalid_connection_config(AwsIamConnectionConfigStatus::MISSING_REGION, "missing_region");
	}
	if (input.port == 0) {
		return invalid_connection_config(AwsIamConnectionConfigStatus::UNIX_SOCKET_NOT_ALLOWED,
			"unix_socket_not_allowed");
	}

	std::string endpoint_region;
	if (!split_rds_endpoint(input.configured_endpoint, endpoint_region)) {
		return invalid_connection_config(AwsIamConnectionConfigStatus::INVALID_ENDPOINT, "invalid_endpoint");
	}
	if (endpoint_region != input.region) {
		return invalid_connection_config(AwsIamConnectionConfigStatus::REGION_ENDPOINT_MISMATCH,
			"region_endpoint_mismatch");
	}
	if (!input.use_ssl) {
		return invalid_connection_config(AwsIamConnectionConfigStatus::TLS_REQUIRED, "tls_required");
	}
	if (input.ssl_ca.empty() && input.ssl_capath.empty()) {
		return invalid_connection_config(AwsIamConnectionConfigStatus::CA_TRUST_REQUIRED, "ca_trust_required");
	}

	AwsIamConnectionConfigResult result;
	result.status = AwsIamConnectionConfigStatus::OK;
	result.key = { input.configured_endpoint, input.port, input.region, input.database_user };
	return result;
}
