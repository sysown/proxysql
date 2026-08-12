#include "tap.h"

#include "MySQL_User_Variables.h"

#include <string>
#include <vector>

namespace {

UserVariableAssignment assignment(
	const std::string& name, const std::string& target, const std::string& literal,
	UserVariableLiteralKind kind = UserVariableLiteralKind::STRING, uint64_t hash = 1) {
	return { name, target, literal, kind, hash };
}

bool stage_and_apply(
	MySQL_User_Variable_State& state, const std::vector<UserVariableAssignment>& assignments) {
	MySQL_User_Variable_State staged;
	if (state.stage(assignments, staged) != MySQL_User_Variable_Apply_Result::OK) {
		return false;
	}
	state = staged;
	return true;
}

void test_staging_and_limits() {
	MySQL_User_Variable_State state;
	ok(state.size() == 0 && state.stored_bytes() == 0, "empty state has no entries or bytes");
	ok(stage_and_apply(state, { assignment("alpha", "@Alpha", "'one'") }), "first assignment stages");
	ok(state.size() == 1 && state.stored_bytes() == 11, "insertion tracks target and literal bytes");
	ok(stage_and_apply(state, { assignment("alpha", "@Alpha", "'x'") }), "replacement stages");
	ok(state.size() == 1 && state.stored_bytes() == 9, "replacement shrinks byte accounting");
	ok(stage_and_apply(state, {
		assignment("alpha", "@Alpha", "'old'"), assignment("alpha", "@Alpha", "'newer'")
	}), "repeated canonical name stages sequentially");
	ok(state.stored_bytes() == 13, "last repeated assignment determines stored bytes");
	state.apply({ assignment("beta", "@Beta", "2") });
	ok(state.size() == 2 && state.stored_bytes() == 19, "apply commits an in-limit assignment sequence");
	state.clear();
	ok(state.size() == 0 && state.stored_bytes() == 0, "clear removes every tracked entry and byte");

	MySQL_User_Variable_State names;
	std::vector<UserVariableAssignment> first_128;
	for (size_t i = 0; i < MySQL_User_Variable_State::kMaxVariables; ++i) {
		const std::string name = "n" + std::to_string(i);
		first_128.push_back(assignment(name, "@" + name, "0"));
	}
	ok(stage_and_apply(names, first_128) && names.size() == MySQL_User_Variable_State::kMaxVariables,
		"128 distinct names are accepted");
	MySQL_User_Variable_State unchanged;
	stage_and_apply(unchanged, { assignment("previous", "@previous", "0") });
	ok(names.stage({ assignment("n128", "@n128", "0") }, unchanged) ==
		MySQL_User_Variable_Apply_Result::VARIABLE_LIMIT,
		"129th distinct name is rejected");
	ok(unchanged.size() == 1 && names.size() == MySQL_User_Variable_State::kMaxVariables,
		"variable-limit failure leaves input and staged output unchanged");

	MySQL_User_Variable_State bytes;
	const std::string max_literal(MySQL_User_Variable_State::kMaxStoredBytes - 2, 'x');
	ok(stage_and_apply(bytes, { assignment("byte", "@x", max_literal) }) &&
		bytes.stored_bytes() == MySQL_User_Variable_State::kMaxStoredBytes,
		"exactly 64 KiB of target and literal bytes is accepted");
	MySQL_User_Variable_State byte_unchanged;
	stage_and_apply(byte_unchanged, { assignment("previous", "@previous", "0") });
	ok(bytes.stage({ assignment("next", "@y", "0") }, byte_unchanged) ==
		MySQL_User_Variable_Apply_Result::BYTE_LIMIT,
		"one byte beyond the stored-byte limit is rejected");
	ok(byte_unchanged.size() == 1 && bytes.stored_bytes() == MySQL_User_Variable_State::kMaxStoredBytes,
		"byte-limit failure leaves input and staged output unchanged");
}

void test_collision_safe_comparison() {
	MySQL_User_Variable_Entry one { "@a", "'one'", UserVariableLiteralKind::STRING, 42 };
	MySQL_User_Variable_Entry two { "@a", "'two'", UserVariableLiteralKind::STRING, 42 };
	ok(one.stored_bytes() == 7, "entry stored bytes exclude canonical name and hash");
	ok(!one.exactly_equals(two), "equal hashes do not make unequal entries equal");

	MySQL_User_Variable_State desired;
	MySQL_User_Variable_State actual;
	ok(stage_and_apply(desired, { assignment("same", "@same", "'one'", UserVariableLiteralKind::STRING, 99) }) &&
		stage_and_apply(actual, { assignment("same", "@same", "'two'", UserVariableLiteralKind::STRING, 99) }),
		"collision comparison states stage");
	unsigned int not_matching = 0;
	ok(actual.count_matches(desired, not_matching) == 0 && not_matching == 1,
		"matching checks exact values after equal hashes");
	ok(stage_and_apply(actual, { assignment("extra", "@extra", "1") }) &&
		actual.has_names_absent_from(desired), "backend extra canonical name is detected");
}

void test_replay_planning() {
	MySQL_User_Variable_State desired;
	MySQL_User_Variable_State actual;
	ok(stage_and_apply(desired, {
		assignment("bravo", "@Bravo", "'two'"),
		assignment("alpha", "@Alpha", "'one'"),
		assignment("charlie", "@Charlie", "3")
	}), "desired replay state stages");
	ok(stage_and_apply(actual, { assignment("alpha", "@Alpha", "'one'") }), "equal backend entry stages");

	const std::string bravo_sql = "SET @Bravo='two'";
	const std::string charlie_sql = "SET @Charlie=3";
	const std::string combined_sql = "SET @Bravo='two',@Charlie=3";
	const auto combined = desired.build_replay_plan(actual, combined_sql.size());
	ok(combined.status == MySQL_User_Variable_Replay_Status::OK && combined.batches.size() == 1 &&
		combined.batches[0].sql == combined_sql,
		"replay emits one raw-syntax-preserving batch when all assignments fit");
	const size_t max_batch_bytes = bravo_sql.size();
	const auto plan_result = desired.build_replay_plan(actual, max_batch_bytes);
	ok(plan_result.status == MySQL_User_Variable_Replay_Status::OK && plan_result.batches.size() == 2,
		"replay batches assignments without exceeding the maximum");
	ok(plan_result.batches[0].sql == bravo_sql && plan_result.batches[1].sql == charlie_sql,
		"replay follows canonical-name order and preserves raw target/literal text");
	ok(plan_result.batches[0].assignments.size() == 1 &&
		plan_result.batches[0].assignments[0].canonical_name == "bravo",
		"already-equal entries are omitted from replay assignments");

	const auto oversized = desired.build_replay_plan(actual, bravo_sql.size() - 1);
	ok(oversized.status == MySQL_User_Variable_Replay_Status::ASSIGNMENT_TOO_LARGE && oversized.batches.empty(),
		"one oversized assignment returns no partial replay plan");
}

void test_diagnostic_fingerprint() {
	MySQL_User_Variable_State state;
	ok(stage_and_apply(state, { assignment("secret_name", "@secret_target", "'secret_literal'") }),
		"fingerprint state stages");
	const std::string first = state.diagnostic_fingerprint();
	const std::string second = state.diagnostic_fingerprint();
	ok(!first.empty() && first == second, "fingerprint is stable within the process");
	ok(first.find("secret_name") == std::string::npos &&
		first.find("secret_target") == std::string::npos &&
		first.find("secret_literal") == std::string::npos,
		"fingerprint does not expose input text");
	ok(stage_and_apply(state, { assignment("secret_name", "@secret_target", "'changed'") }) &&
		state.diagnostic_fingerprint() != first, "fingerprint changes with state");
}

} // namespace

int main() {
	plan(31);
	test_staging_and_limits();
	test_collision_safe_comparison();
	test_replay_planning();
	test_diagnostic_fingerprint();
	return exit_status();
}
