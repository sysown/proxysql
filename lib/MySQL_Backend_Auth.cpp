#include "../deps/json/json.hpp"

#include "MySQL_Backend_Auth.h"
#include "MySQL_Authentication.hpp"

#include <vector>

namespace {

MySQLBackendAuthPolicy invalid_backend_auth_policy(std::string_view database_user, const char* failure_code) {
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

/**
 * @brief Whether attributes text that nlohmann cannot parse mentions
 *   'backend_auth', also when spelled with JSON escapes.
 * @details The text cannot be parsed, so the check is lenient: besides the raw
 *   bytes, every string literal is decoded ('\uXXXX' and the short escapes)
 *   and searched. A key such as "backend\u005fauth" is therefore found too.
 *   Escapes outside ASCII cannot form 'backend_auth' and decode to a
 *   placeholder byte.
 */
bool attributes_text_mentions_backend_auth(std::string_view text) {
	static constexpr std::string_view key { "backend_auth" };
	if (text.find(key) != std::string_view::npos) {
		return true;
	}
	const auto hex_value = [](char c) -> int {
		if (c >= '0' && c <= '9') return c - '0';
		if (c >= 'a' && c <= 'f') return c - 'a' + 10;
		if (c >= 'A' && c <= 'F') return c - 'A' + 10;
		return -1;
	};
	size_t i = 0;
	while (i < text.size()) {
		if (text[i] != '"') {
			++i;
			continue;
		}
		++i;
		std::string decoded {};
		while (i < text.size() && text[i] != '"') {
			if (text[i] != '\\' || i + 1 >= text.size()) {
				decoded.push_back(text[i]);
				++i;
				continue;
			}
			const char escape = text[i + 1];
			i += 2;
			if (escape != 'u') {
				// '\"', '\\', '\/' decode to themselves; the control-character
				// escapes cannot be part of 'backend_auth'.
				decoded.push_back(escape);
				continue;
			}
			int code_point = 0;
			size_t digits = 0;
			for (; digits < 4 && i + digits < text.size(); ++digits) {
				const int v = hex_value(text[i + digits]);
				if (v < 0) {
					break;
				}
				code_point = code_point * 16 + v;
			}
			i += digits;
			decoded.push_back(digits == 4 && code_point < 0x80 ? static_cast<char>(code_point) : '\x80');
		}
		++i; // closing quote
		if (decoded.find(key) != std::string::npos) {
			return true;
		}
	}
	return false;
}

/**
 * @brief Policy for attributes text that is not a JSON object the policy can
 *   read: valid-but-non-object JSON, or text add() rejected.
 * @details 'mysql_users.attributes' only has to satisfy JSON_VALID(attributes)
 *   OR attributes='', so values such as '[]', '"x"', 'null', or text nlohmann
 *   rejects ('{"a":1e400}', a lone surrogate escape) are storable and were
 *   harmless before this policy existed: they select PASSWORD, as in v3.0.11.
 *   Only text that mentions 'backend_auth' (raw or JSON-escaped, see
 *   attributes_text_mentions_backend_auth()) fails closed, so that a policy the
 *   operator configured but that cannot be read never falls back to sending
 *   the password (issue #6413).
 */
MySQLBackendAuthPolicy unreadable_attributes_policy(
	std::string_view database_user, std::string_view attributes)
{
	if (!attributes_text_mentions_backend_auth(attributes)) {
		MySQLBackendAuthPolicy policy;
		policy.database_user = database_user;
		policy.type = MySQLBackendAuthType::PASSWORD;
		return policy;
	}
	return invalid_backend_auth_policy(database_user, "attributes_not_object");
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
		return unreadable_attributes_policy(database_user, attributes);
	}

	const auto backend_auth = parsed.find("backend_auth");
	if (backend_auth == parsed.end()) {
		policy.type = MySQLBackendAuthType::PASSWORD;
		return policy;
	}
	// A row that has 'backend_auth' asked for a non-password mode. If it is
	// malformed, the policy is INVALID and the connection fails closed. It
	// must NOT fall back to PASSWORD: that would send the frontend password
	// to a backend account the operator configured for another mode (e.g.
	// IAM). Maintainer decision, final (issue #6413); not a bug. The row is
	// reported when it is loaded (MySQL_Authentication::add()).
	if (!backend_auth->is_object()) {
		return invalid_backend_auth_policy(database_user, "backend_auth_not_object");
	}

	const auto type = backend_auth->find("type");
	if (type == backend_auth->end()) {
		return invalid_backend_auth_policy(database_user, "type_missing");
	}
	if (!type->is_string()) {
		return invalid_backend_auth_policy(database_user, "type_not_string");
	}
	if (type->get<std::string>() != "aws_iam") {
		return invalid_backend_auth_policy(database_user, "type_unsupported");
	}

	policy.type = MySQLBackendAuthType::AWS_IAM;
	policy.ignored_password = backend_password_is_nonempty;
	return policy;
}

MySQLBackendAuthPolicy mysql_backend_auth_policy_for_account(
	std::string_view database_user,
	const char* attributes,
	const char* rejected_attributes,
	bool backend_password_is_nonempty)
{
	if (rejected_attributes != nullptr) {
		// add() rejected the configured text (parse or validation error), so the
		// row has no readable attributes. Decide on the configured text exactly
		// like any other unreadable value. This also covers text that parses but
		// failed validation, e.g. a well-formed 'backend_auth' next to a bad
		// 'default-transaction_isolation': the row was rejected as a whole, so
		// IAM is not selected from it, and it does not fall back to PASSWORD.
		return unreadable_attributes_policy(database_user, rejected_attributes);
	}
	return parse_mysql_backend_auth_policy(
		database_user, attributes != nullptr ? attributes : "", backend_password_is_nonempty);
}

MySQLBackendAuthPolicy resolve_mysql_backend_auth_policy(
	MySQL_Authentication& authentication,
	const char* mapped_backend_username)
{
	const std::string_view database_user =
		mapped_backend_username != nullptr ? mapped_backend_username : "";
	if (mapped_backend_username == nullptr) {
		return invalid_backend_auth_policy(database_user, "backend_user_not_found");
	}
	if (!authentication.has_non_password_backend_auth()) {
		// No backend row has a non-PASSWORD policy: the lookup below can only
		// return PASSWORD, so skip it (and its read lock).
		MySQLBackendAuthPolicy policy;
		policy.database_user = database_user;
		policy.type = MySQLBackendAuthType::PASSWORD;
		return policy;
	}

	account_details_t account = authentication.lookup(
		const_cast<char*>(mapped_backend_username), USERNAME_BACKEND, { false, false, true });
	if (account.password == nullptr) {
		// No backend row: the 'frontend=1, backend=0' split-row user. As in
		// v3.0.11, the backend connection uses the credentials captured at
		// frontend authentication: plain PASSWORD mode, exactly like a row
		// without 'backend_auth' (issue #6413). AWS IAM is selected only by
		// 'backend_auth.type' on a backend row, never inferred.
		free_account_details(account);
		MySQLBackendAuthPolicy policy;
		policy.database_user = database_user;
		policy.type = MySQLBackendAuthType::PASSWORD;
		return policy;
	}

	const MySQLBackendAuthPolicy policy = mysql_backend_auth_policy_for_account(
		database_user,
		account.attributes,
		account.rejected_attributes,
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
