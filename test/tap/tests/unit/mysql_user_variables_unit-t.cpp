#include "tap.h"

#include "MySQL_User_Variables.h"
#include "MySQL_Data_Stream.h"
#include "mysql_connection.h"

#include <string>
#include <utility>
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

void test_replay_completion_decisions() {
	MySQL_User_Variable_State desired;
	MySQL_User_Variable_State backend;
	ok(stage_and_apply(desired, {
		assignment("alpha", "@alpha", "'one'"),
		assignment("bravo", "@bravo", "2")
	}), "desired replay-completion state stages");

	const auto plan = desired.build_replay_plan(MySQL_User_Variable_State {}, std::string("SET @alpha='one'").size());
	ok(plan.status == MySQL_User_Variable_Replay_Status::OK && plan.batches.size() == 2,
		"replay-completion fixture has two batches");

	auto completion = mysql_user_variable_replay_complete(backend, plan.batches, 0, true);
	unsigned int not_matching = 0;
	ok(completion == MySQL_User_Variable_Replay_Completion::CONTINUE_SETTING_USER_VARIABLES &&
		backend.count_matches(desired, not_matching) == 1 && not_matching == 1,
		"acknowledging one batch applies only that batch and continues replay");

	completion = mysql_user_variable_replay_complete(backend, plan.batches, 1, true);
	not_matching = 0;
	ok(completion == MySQL_User_Variable_Replay_Completion::RESUME_SAVED_STATUS &&
		backend.count_matches(desired, not_matching) == 2 && not_matching == 0,
		"acknowledging the last batch applies it and resumes the saved client-query state");

	MySQL_User_Variable_State failed_backend;
	completion = mysql_user_variable_replay_complete(failed_backend, plan.batches, 0, false);
	not_matching = 0;
	ok(completion == MySQL_User_Variable_Replay_Completion::FAIL_CLIENT_QUERY_AND_RETIRE_BACKEND &&
		failed_backend.count_matches(desired, not_matching) == 0 && not_matching == 2 &&
		desired.size() == 2,
		"replay error applies nothing, retires the backend, and leaves frontend desired state intact");
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

void test_move_preserves_state_invariants() {
	MySQL_User_Variable_State source;
	const std::string max_literal(MySQL_User_Variable_State::kMaxStoredBytes - 2, 'x');
	ok(stage_and_apply(source, { assignment("full", "@x", max_literal) }),
		"full state stages before move");
	MySQL_User_Variable_State destination(std::move(source));
	ok(destination.size() == 1 &&
		destination.stored_bytes() == MySQL_User_Variable_State::kMaxStoredBytes,
		"move construction preserves destination entries and byte accounting");
	ok(source.size() == 0 && source.stored_bytes() == 0,
		"moved-from state is empty with zero stored bytes");
	ok(stage_and_apply(source, { assignment("new", "@new", "0") }) &&
		source.size() == 1 && source.stored_bytes() == 5,
		"moved-from state accepts a valid new assignment");
	MySQL_User_Variable_State assigned;
	stage_and_apply(assigned, { assignment("old", "@old", "0") });
	assigned = std::move(destination);
	ok(assigned.size() == 1 &&
		assigned.stored_bytes() == MySQL_User_Variable_State::kMaxStoredBytes &&
		destination.size() == 0 && destination.stored_bytes() == 0,
		"move assignment preserves destination accounting and clears its source");
	ok(stage_and_apply(destination, { assignment("newer", "@newer", "0") }),
		"move-assigned source accepts a valid new assignment");
}

void test_kind_and_empty_replay_edges() {
	MySQL_User_Variable_State desired;
	MySQL_User_Variable_State actual;
	ok(stage_and_apply(desired, { assignment("same", "@same", "1", UserVariableLiteralKind::INTEGER, 77) }) &&
		stage_and_apply(actual, { assignment("same", "@same", "1", UserVariableLiteralKind::DECIMAL, 77) }),
		"kind-only mismatch states stage");
	unsigned int not_matching = 0;
	ok(actual.count_matches(desired, not_matching) == 0 && not_matching == 1,
		"kind-only difference is an exact mismatch");
	ok(actual.diagnostic_fingerprint() != desired.diagnostic_fingerprint(),
		"kind-only difference changes the diagnostic fingerprint");

	MySQL_User_Variable_State empty_desired;
	MySQL_User_Variable_State nonempty_actual;
	ok(stage_and_apply(nonempty_actual, { assignment("extra", "@extra", "1") }),
		"nonempty actual state stages for empty desired replay");
	const auto empty_diff = empty_desired.build_replay_plan(nonempty_actual, 0);
	ok(empty_diff.status == MySQL_User_Variable_Replay_Status::OK && empty_diff.batches.empty(),
		"empty desired replay has no batches even with a zero byte limit");
	const auto zero_limit = desired.build_replay_plan(MySQL_User_Variable_State {}, 0);
	ok(zero_limit.status == MySQL_User_Variable_Replay_Status::ASSIGNMENT_TOO_LARGE && zero_limit.batches.empty(),
		"zero byte limit rejects a nonempty replay without partial batches");
}

void set_username(MySQL_Connection& connection, const char* username) {
	connection.userinfo->username = strdup(username);
}

void test_connection_state_integration() {
	MySQL_Connection frontend;
	MySQL_Connection backend;
	set_username(frontend, "user-variable-unit");
	set_username(backend, "user-variable-unit");
	ok(stage_and_apply(backend.user_variables, { assignment("backend_only", "@backend_only", "1") }),
		"backend-only user variable stages on connection");
	ok(backend.requires_CHANGE_USER(&frontend),
		"backend user-variable name absent from frontend requires CHANGE_USER");

	MySQL_Connection desired;
	MySQL_Connection actual;
	set_username(desired, "user-variable-unit");
	set_username(actual, "user-variable-unit");
	ok(stage_and_apply(desired.user_variables, { assignment("matching", "@matching", "'one'", UserVariableLiteralKind::STRING, 42) }) &&
		stage_and_apply(actual.user_variables, { assignment("matching", "@matching", "'one'", UserVariableLiteralKind::STRING, 42) }),
		"equal user variables stage on connection fixtures");
	unsigned int not_matching = 0;
	ok(actual.number_of_matching_session_variables(&desired, not_matching) == 1 && not_matching == 0,
		"exactly equal user variables count as matching session state");
	ok(stage_and_apply(actual.user_variables, { assignment("matching", "@matching", "'different'", UserVariableLiteralKind::STRING, 42) }),
		"same-hash different-value backend user variable stages");
	not_matching = 0;
	ok(actual.number_of_matching_session_variables(&desired, not_matching) == 0 && not_matching == 1,
		"same-hash different-value user variable is a mismatch");
	actual.reset();
	ok(actual.user_variables.size() == 0 && actual.user_variables.stored_bytes() == 0,
		"connection reset clears tracked user variables");

	MySQL_Data_Stream stream;
	stream.myds_type = MYDS_FRONTEND;
	stream.myconn = new MySQL_Connection();
	ok(stage_and_apply(stream.myconn->user_variables, {
		assignment("secret_name", "@secret_target", "'secret_literal'")
	}), "diagnostic user variable stages");
	nlohmann::json internal_session;
	stream.get_client_myds_info_json(internal_session);
	const nlohmann::json& user_variables = internal_session["conn"]["user_variables"];
	const std::string client_diagnostic = user_variables.dump();
	ok(user_variables["count"] == 1 &&
		user_variables["stored_bytes"] == stream.myconn->user_variables.stored_bytes(),
		"client diagnostics expose user-variable aggregate count and stored bytes");
	ok(client_diagnostic.find("secret_name") == std::string::npos &&
		client_diagnostic.find("secret_target") == std::string::npos &&
		client_diagnostic.find("secret_literal") == std::string::npos,
		"client diagnostics do not expose user-variable names, values, or replay syntax");
	if (user_variables.contains("fingerprint")) {
		ok(client_diagnostic.find(stream.myconn->user_variables.diagnostic_fingerprint()) != std::string::npos,
			"client diagnostics fingerprint is aggregate-only");
	} else {
		ok(true, "client diagnostics omit fingerprint when keyed initialization is unavailable");
	}

	nlohmann::json backend_json;
	backend.get_backend_conn_info_json(backend_json);
	const nlohmann::json& backend_user_variables = backend_json["user_variables"];
	const std::string backend_diagnostic = backend_user_variables.dump();
	ok(backend_user_variables["count"] == 1 &&
		backend_user_variables["stored_bytes"] == backend.user_variables.stored_bytes(),
		"backend diagnostics expose user-variable aggregate count and stored bytes");
	ok(backend_diagnostic.find("backend_only") == std::string::npos,
		"backend diagnostics do not expose user-variable names or values");
}

} // namespace

int main() {
	plan(61);
	test_staging_and_limits();
	test_collision_safe_comparison();
	test_replay_planning();
	test_replay_completion_decisions();
	test_diagnostic_fingerprint();
	test_move_preserves_state_invariants();
	test_kind_and_empty_replay_edges();
	test_connection_state_integration();
	return exit_status();
}
