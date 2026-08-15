#ifndef __CLASS_MYSQL_USER_VARIABLES_H
#define __CLASS_MYSQL_USER_VARIABLES_H

#include <cstddef>
#include <cstdint>
#include <map>
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
	bool is_set_statement { false };
	std::vector<UserVariableAssignment> assignments;
};

struct MySQL_User_Variable_Entry {
	std::string replay_target;
	std::string raw_literal;
	UserVariableLiteralKind kind;
	uint64_t hash;

	size_t stored_bytes() const;
	bool exactly_equals(const MySQL_User_Variable_Entry& other) const;
};

enum class MySQL_User_Variable_Apply_Result : uint8_t {
	OK,
	VARIABLE_LIMIT,
	BYTE_LIMIT
};

struct MySQL_User_Variable_Replay_Batch {
	std::string sql;
	std::vector<UserVariableAssignment> assignments;
};

enum class MySQL_User_Variable_Replay_Status : uint8_t {
	OK,
	ASSIGNMENT_TOO_LARGE
};

enum class MySQL_User_Variable_Replay_Packet_Budget_Status : uint8_t {
	OK,
	FALLBACK_TO_SERVER_MINIMUM,
	PACKET_LIMIT_TOO_SMALL
};

struct MySQL_User_Variable_Replay_Packet_Budget {
	MySQL_User_Variable_Replay_Packet_Budget_Status status {
		MySQL_User_Variable_Replay_Packet_Budget_Status::OK
	};
	size_t max_query_bytes { 0 };
};

constexpr uint32_t MYSQL_USER_VARIABLE_REPLAY_MINIMUM_SERVER_PACKET_BYTES = 1024;

struct MySQL_User_Variable_Replay_Plan {
	MySQL_User_Variable_Replay_Status status { MySQL_User_Variable_Replay_Status::OK };
	std::vector<MySQL_User_Variable_Replay_Batch> batches;
};

enum class MySQL_User_Variable_Replay_Completion : uint8_t {
	CONTINUE_SETTING_USER_VARIABLES,
	RESUME_SAVED_STATUS,
	FAIL_CLIENT_QUERY_AND_RETIRE_BACKEND
};

class MySQL_User_Variable_State {
public:
	static constexpr size_t MAX_VARIABLES = 128;
	static constexpr size_t MAX_STORED_BYTES = 64 * 1024;
	MySQL_User_Variable_State() = default;
	MySQL_User_Variable_State(const MySQL_User_Variable_State&) = default;
	MySQL_User_Variable_State& operator=(const MySQL_User_Variable_State&) = default;
	MySQL_User_Variable_State(MySQL_User_Variable_State&& other) noexcept;
	MySQL_User_Variable_State& operator=(MySQL_User_Variable_State&& other) noexcept;

	MySQL_User_Variable_Apply_Result stage(
		const std::vector<UserVariableAssignment>& assignments,
		MySQL_User_Variable_State& staged) const;
	void apply(const std::vector<UserVariableAssignment>& assignments);
	void clear();
	size_t size() const;
	size_t stored_bytes() const;
	bool has_names_absent_from(const MySQL_User_Variable_State& desired) const;
	unsigned int count_matches(
		const MySQL_User_Variable_State& desired,
		unsigned int& not_matching) const;
	MySQL_User_Variable_Replay_Plan build_replay_plan(
		const MySQL_User_Variable_State& actual,
		size_t max_query_bytes) const;
	std::string diagnostic_fingerprint() const;

private:
	std::map<std::string, MySQL_User_Variable_Entry> entries_;
	size_t stored_bytes_ { 0 };
};

MySQL_User_Variable_Replay_Completion mysql_user_variable_replay_complete(
	MySQL_User_Variable_State& backend,
	const std::vector<MySQL_User_Variable_Replay_Batch>& batches,
	size_t batch_index,
	bool batch_succeeded);

MySQL_User_Variable_Replay_Packet_Budget mysql_user_variable_replay_packet_budget(
	uint32_t max_allowed_pkt, size_t framing_bytes);

UserVariableSetAnalysis parsersql_analyze_user_variable_set_mysql(
	const char* query, size_t query_length);
UserVariableUsage parsersql_classify_user_variable_usage_mysql(
	const char* query, size_t query_length);

#endif
