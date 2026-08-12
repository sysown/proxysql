#ifndef PROXYSQL_MYSQL_USER_VARIABLES_H
#define PROXYSQL_MYSQL_USER_VARIABLES_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum class UserVariableSetStatus : uint8_t {
	NOT_USER_VARIABLE_SET,
	SUPPORTED,
	UNSUPPORTED,
	PARSE_ERROR
};

enum class UserVariableLiteralKind : uint8_t {
	STRING,
	INTEGER,
	DECIMAL,
	HEXADECIMAL,
	BIT,
	NULL_VALUE
};

enum class UserVariableUsage : uint8_t {
	NO_USER_VARIABLE,
	READ_ONLY,
	UNSAFE_OR_UNKNOWN
};

struct UserVariableAssignment {
	std::string canonical_name;
	std::string replay_target;
	std::string raw_literal;
	UserVariableLiteralKind kind;
	uint64_t hash;
};

struct UserVariableSetAnalysis {
	UserVariableSetStatus status { UserVariableSetStatus::NOT_USER_VARIABLE_SET };
	std::vector<UserVariableAssignment> assignments;
};

UserVariableSetAnalysis parsersql_analyze_user_variable_set_mysql(
	const char* query, size_t query_length);
UserVariableUsage parsersql_classify_user_variable_usage_mysql(
	const char* query, size_t query_length);

#endif
