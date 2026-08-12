#ifndef MYSQL_BACKEND_AUTH_H
#define MYSQL_BACKEND_AUTH_H

#include <cstdint>
#include <string>
#include <string_view>

class MySQL_Authentication;

enum class MySQLBackendAuthType : uint8_t {
	PASSWORD,
	AWS_IAM,
	INVALID,
};

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

MySQLBackendAuthPolicy resolve_mysql_backend_auth_policy(
	MySQL_Authentication& authentication,
	const char* mapped_backend_username);

const char* mysql_backend_auth_type_name(MySQLBackendAuthType type);

#endif // MYSQL_BACKEND_AUTH_H
