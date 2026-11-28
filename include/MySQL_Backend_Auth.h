#ifndef MYSQL_BACKEND_AUTH_H
#define MYSQL_BACKEND_AUTH_H

#include <cstdint>
#include <string>
#include <string_view>

#include "Aws_Iam_Provider.h"
#include "Aws_Iam_Types.h"

class MySQL_Authentication;

enum class MySQLBackendAuthType : uint8_t {
	PASSWORD,
	AWS_IAM,
	INVALID,
	AZURE_ENTRA, // after INVALID so existing values keep their numbers (#6649)
};

/** @brief Whether the type authenticates with a short-lived token instead of a password. */
bool mysql_backend_auth_uses_token(MySQLBackendAuthType type);

/** @brief "AWS IAM" or "Azure Entra" for log and error text; AWS text stays as before #6649. */
const char* backend_token_log_label(MySQLBackendAuthType type);

/** @brief The token-source slot of a token type; false for PASSWORD and INVALID. */
bool backend_token_provider_for(MySQLBackendAuthType type, BackendTokenProvider& out);
/**
 * @brief Lease the token source of a token auth type.
 * @param type The backend auth type.
 * @return The slot's lease; an empty lease for PASSWORD, INVALID or an empty slot (fails closed).
 */
AwsIamTokenSourceLease acquire_backend_token_source_for(MySQLBackendAuthType type);

struct MySQLBackendAuthPolicy {
	MySQLBackendAuthType type{MySQLBackendAuthType::INVALID};
	std::string database_user;
	std::string failure_code;
	bool ignored_password{false};
};

MySQLBackendAuthPolicy parse_mysql_backend_auth_policy(
	std::string_view database_user,
	std::string_view attributes,
	bool backend_password_is_nonempty);

/**
 * @brief Backend auth policy of a loaded 'mysql_users' backend row.
 * @param database_user The backend username.
 * @param attributes The effective attributes of the row ('' or nullptr if none).
 * @param rejected_attributes The configured attributes text if
 *   MySQL_Authentication::add() rejected it, nullptr otherwise. A rejected text
 *   selects PASSWORD unless it mentions 'backend_auth', in which case the
 *   policy is INVALID (fail closed, issue #6413).
 * @param backend_password_is_nonempty Whether the row has a backend password.
 * @return The resolved policy.
 */
MySQLBackendAuthPolicy mysql_backend_auth_policy_for_account(
	std::string_view database_user,
	const char* attributes,
	const char* rejected_attributes,
	bool backend_password_is_nonempty);

MySQLBackendAuthPolicy resolve_mysql_backend_auth_policy(
	MySQL_Authentication& authentication,
	const char* mapped_backend_username);

const char* mysql_backend_auth_type_name(MySQLBackendAuthType type);

enum class AwsIamConnectionConfigStatus : uint8_t {
	OK,
	SUPPORT_NOT_COMPILED,
	MISSING_REGION,
	REGION_ENDPOINT_MISMATCH,
	INVALID_ENDPOINT,
	UNIX_SOCKET_NOT_ALLOWED,
	TLS_REQUIRED,
	CA_TRUST_REQUIRED,
};

struct AwsIamConnectionConfigInput {
	std::string database_user;
	std::string configured_endpoint;
	uint16_t port;
	std::string region;
	bool use_ssl;
	std::string ssl_ca;
	std::string ssl_capath;
	bool support_compiled;
};

struct AwsIamConnectionConfigResult {
	AwsIamConnectionConfigStatus status;
	AwsIamTokenKey key;
	std::string failure_code;
};

AwsIamConnectionConfigResult validate_mysql_aws_iam_connection(
	const AwsIamConnectionConfigInput& input);

/**
 * @brief Validate a backend connection for 'azure_entra' (#6649).
 * @details Same rules as AWS IAM (TCP, TLS, CA trust) but no region; the endpoint
 *   must be an Azure Database for MySQL host name. The key has an empty region.
 */
AwsIamConnectionConfigResult validate_mysql_azure_entra_connection(
	const AwsIamConnectionConfigInput& input);

/** @brief Validate for the given token type; a non-token type gets "not_token_auth". */
AwsIamConnectionConfigResult validate_mysql_backend_token_connection(
	MySQLBackendAuthType type, const AwsIamConnectionConfigInput& input);

#endif // MYSQL_BACKEND_AUTH_H
