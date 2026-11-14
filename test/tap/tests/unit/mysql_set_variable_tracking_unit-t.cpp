#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "MySQL_Variables.h"
#include "MySQL_User_Variables.h"

#include <algorithm>
#include <cstring>

int main() {
	plan(NO_PLAN);
	test_init_minimal();
	MySQL_Variables variables;
	// Exercise the production registry, including entries outside the two
	// timeout names from the original report. A new registry entry inherits
	// mixed-SET support without another variable-name list.
	for (int idx = 0; idx < SQL_NAME_LAST_HIGH_WM; ++idx) {
		const auto& variable = mysql_tracked_variables[idx];
		if (variable.status != SETTING_VARIABLE || idx == SQL_NAME_LAST_LOW_WM) continue;
		const char* input = variable.is_number ? "123" : variable.is_bool ? "off" : "example";
		std::string expected = input;
		if (variable.is_bool && !variable.is_number) expected = "OFF";
		if (idx == SQL_QUERY_CACHE_TYPE) { input = "DEMAND"; expected = "2"; }
		if (idx == SQL_TIME_ZONE) { input = "+1:23"; expected = "+01:23"; }
		if (idx == SQL_CHARACTER_SET_CLIENT || idx == SQL_CHARACTER_SET_CONNECTION ||
			idx == SQL_CHARACTER_SET_RESULTS || idx == SQL_CHARACTER_SET_DATABASE) {
			input = "utf8mb4"; expected = "45";
		}
		if (idx == SQL_COLLATION_CONNECTION) { input = "utf8mb4_bin"; expected = "46"; }
		MySQL_Session_Set_Plan plan;
		const bool accepted = variables.stage_set_variable(variable.set_variable_name, input, plan);
		const auto found = std::find(plan.values.begin(), plan.values.end(), std::make_pair(idx, expected));
		ok(accepted && found != plan.values.end(),
			"registry variable %s prepares its frontend value", variable.set_variable_name);
	}

	for (const auto& assignment : std::vector<std::pair<std::string, std::string>> {
		{"unknown_variable", "1"}, {"placeholder", "1"}, {"unique_checks", "sometimes"},
		{"sort_buffer_size", "1+2"}, {"sort_buffer_size", ""},
		{"character_set_client", "nonexistent_charset"}, {"time_zone", "@@time_zone"}
		, {"sql_mode", "ANSI',autocommit=0 #"}, {"optimizer_switch", "CONCAT('a','b')"},
		{"sql_safe_updates", std::string("ON\0garbage", 10)},
		{"autocommit", std::string("ON\0garbage", 10)},
		{"session_track_gtids", std::string("OFF\0garbage", 11)},
		{"character_set_client", std::string("utf8\0garbage", 12)}
	}) {
		MySQL_Session_Set_Plan plan;
		variables.stage_set_variable("group_concat_max_len", "4096", plan);
		const auto before = plan.values;
		ok(!variables.stage_set_variable(assignment.first, assignment.second, plan) && plan.values == before,
			"invalid %s leaves the prepared state unchanged", assignment.first.c_str());
	}

	MySQL_Session_Set_Plan plan;
	ok(variables.stage_set_variable("wait_timeout", "0", plan) && plan.wait_timeout_ms == 1000 &&
		variables.stage_set_variable("autocommit", "off", plan) && plan.autocommit == std::vector<bool>{false} &&
		variables.stage_set_variable("transaction_read_only", "1", plan) == false &&
		variables.stage_set_variable("tx_read_only", "1", plan) &&
		plan.values.back() == std::make_pair(static_cast<int>(SQL_TRANSACTION_READ), std::string("ONLY")),
		"special policies prepare frontend changes using the parser's normalized names");
	ok(variables.stage_set_variable("max_join_size", "10", plan) &&
		plan.values.back() == std::make_pair(static_cast<int>(SQL_SQL_BIG_SELECTS), std::string("OFF")) &&
		variables.stage_set_variable("sql_big_selects", "ON", plan) && plan.values.back().second == "ON",
		"coupled session effects retain assignment order");

	UserVariableAssignment escaped {"x", "@x", "'A\\n'", UserVariableLiteralKind::STRING, 7, {8, 8, false}};
	MySQL_User_Variable_State desired, empty;
	desired.apply({escaped});
	auto replay = desired.build_replay_plan(empty, 4096);
	ok(mysql_user_variable_literal_is_replayable(escaped) && replay.batches.size() == 1 &&
		replay.batches[0].sql == "SET @x=CONVERT(CONVERT(X'410A' USING latin1) USING latin1) COLLATE latin1_swedish_ci",
		"replay fixes the string's original bytes and collation independently of later SQL mode");
	escaped.context.no_backslash_escapes = true;
	MySQL_User_Variable_State literal_backslash;
	literal_backslash.apply({escaped});
	unsigned int not_matching = 0;
	ok(literal_backslash.count_matches(desired, not_matching) == 0 && not_matching == 1 &&
		literal_backslash.diagnostic_fingerprint() != desired.diagnostic_fingerprint(),
		"identical source text under different interpretation contexts is not the same tracked value");
	replay = literal_backslash.build_replay_plan(empty, 4096);
	ok(replay.batches.size() == 1 && replay.batches[0].sql ==
		"SET @x=CONVERT(CONVERT(X'415C6E' USING latin1) USING latin1) COLLATE latin1_swedish_ci",
		"NO_BACKSLASH_ESCAPES is captured at assignment time");
	ok(literal_backslash.build_replay_plan(empty, 20).status ==
		MySQL_User_Variable_Replay_Status::ASSIGNMENT_TOO_LARGE,
		"packet budgets include the rendered context-independent expression");
	escaped.raw_literal = "\"abc\"";
	escaped.context.ansi_quotes = true;
	ok(!mysql_user_variable_literal_is_replayable(escaped),
		"ANSI_QUOTES double-quoted identifiers cannot be accepted as user string literals");
	std::string decoded;
	ok(mysql_decode_set_string("'\\+01:00'", {8, 8, false}, decoded) && decoded == "+01:00",
		"session string escapes are decoded before any mixed SQL-mode assignment is applied");
	escaped.raw_literal = "'value'";
	escaped.context = {8, 0, false, false, true, "original_database"};
	desired.clear();
	desired.apply({escaped});
	UserVariableLiteralContext unresolved;
	ok(mysql_user_variable_literal_is_replayable(escaped) && desired.unresolved_context(unresolved) &&
		unresolved.database_schema == "original_database" && desired.build_replay_plan(empty, 4096).status ==
		MySQL_User_Variable_Replay_Status::UNRESOLVED_CONTEXT,
		"database-dependent literals remain tracked without guessing or rendering an unknown collation");
	auto other = unresolved;
	other.database_schema = "another_database";
	desired.resolve_context(other, 46);
	ok(desired.unresolved_context(unresolved), "resolving another schema does not alter the captured database");
	desired.resolve_context(unresolved, 46);
	replay = desired.build_replay_plan(empty, 4096);
	ok(!desired.unresolved_context(unresolved) && replay.status == MySQL_User_Variable_Replay_Status::OK &&
		replay.batches.size() == 1 && replay.batches[0].sql.find("USING utf8mb4) COLLATE utf8mb4_bin") != std::string::npos,
		"resolved database collation is retained in subsequent backend replay");
	ok(mysql_user_variable_capture_schema("\xe9") == std::optional<std::string>("\xe9") &&
		!mysql_user_variable_capture_schema(std::string(257, 'a').c_str()),
		"captured schema names retain their original bytes and reject oversized identifiers without copying");
	escaped.context.database_schema = std::string(MySQL_User_Variable_State::MAX_STORED_BYTES, 'a');
	escaped.context.resolve_database_collation = true;
	MySQL_User_Variable_State staged;
	ok(empty.stage({escaped}, staged) == MySQL_User_Variable_Apply_Result::BYTE_LIMIT && staged.size() == 0,
		"captured database names count toward the atomic tracked-state memory limit");
	test_cleanup_minimal();
	return exit_status();
}
