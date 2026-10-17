#include "MySQL_User_Variables.h"

#include "SpookyV2.h"
#include "openssl/rand.h"
#include "proxysql.h"

#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <utility>

namespace {

struct Fingerprint_Keys {
	uint64_t first { 0 };
	uint64_t second { 0 };
	bool available { false };
};

Fingerprint_Keys& fingerprint_keys() {
	static Fingerprint_Keys keys;
	static std::once_flag initialized;
	std::call_once(initialized, []() {
		uint64_t seeds[2];
		if (RAND_bytes(reinterpret_cast<unsigned char*>(seeds), sizeof(seeds)) == 1) {
			keys.first = seeds[0];
			keys.second = seeds[1];
			keys.available = true;
		} else {
			proxy_warning("Unable to initialize MySQL user-variable diagnostic fingerprint key\n");
		}
	});
	return keys;
}

void append_u64(std::string& serialized, uint64_t value) {
	for (int shift = 56; shift >= 0; shift -= 8) {
		serialized.push_back(static_cast<char>((value >> shift) & 0xff));
	}
}

void append_string(std::string& serialized, const std::string& value) {
	append_u64(serialized, value.size());
	serialized.append(value);
}

MySQL_User_Variable_Entry entry_from(const UserVariableAssignment& assignment) {
	return { assignment.replay_target, assignment.raw_literal, assignment.kind, assignment.hash };
}

UserVariableAssignment assignment_from(
	const std::string& canonical_name, const MySQL_User_Variable_Entry& entry) {
	return { canonical_name, entry.replay_target, entry.raw_literal, entry.kind, entry.hash };
}

} // namespace

MySQL_User_Variable_State::MySQL_User_Variable_State(MySQL_User_Variable_State&& other) noexcept
	: entries_(std::move(other.entries_)), stored_bytes_(other.stored_bytes_) {
	other.clear();
}

MySQL_User_Variable_State& MySQL_User_Variable_State::operator=(MySQL_User_Variable_State&& other) noexcept {
	if (this != &other) {
		entries_ = std::move(other.entries_);
		stored_bytes_ = other.stored_bytes_;
		other.clear();
	}
	return *this;
}

size_t MySQL_User_Variable_Entry::stored_bytes() const {
	return replay_target.size() + raw_literal.size();
}

bool MySQL_User_Variable_Entry::exactly_equals(const MySQL_User_Variable_Entry& other) const {
	return hash == other.hash && kind == other.kind && replay_target == other.replay_target &&
		raw_literal == other.raw_literal;
}

MySQL_User_Variable_Apply_Result MySQL_User_Variable_State::stage(
	const std::vector<UserVariableAssignment>& assignments,
	MySQL_User_Variable_State& staged) const {
	MySQL_User_Variable_State candidate(*this);
	for (const UserVariableAssignment& assignment : assignments) {
		const MySQL_User_Variable_Entry replacement = entry_from(assignment);
		const size_t replacement_bytes = replacement.stored_bytes();
		auto existing = candidate.entries_.find(assignment.canonical_name);
		const size_t previous_bytes = existing == candidate.entries_.end() ? 0 : existing->second.stored_bytes();
		const size_t bytes_after_removal = candidate.stored_bytes_ - previous_bytes;

		if (existing == candidate.entries_.end() && candidate.entries_.size() == MAX_VARIABLES) {
			return MySQL_User_Variable_Apply_Result::VARIABLE_LIMIT;
		}
		if (replacement_bytes > MAX_STORED_BYTES - bytes_after_removal) {
			return MySQL_User_Variable_Apply_Result::BYTE_LIMIT;
		}

		candidate.stored_bytes_ = bytes_after_removal + replacement_bytes;
		candidate.entries_[assignment.canonical_name] = replacement;
	}
	staged = std::move(candidate);
	return MySQL_User_Variable_Apply_Result::OK;
}

void MySQL_User_Variable_State::apply(const std::vector<UserVariableAssignment>& assignments) {
	MySQL_User_Variable_State staged;
	if (stage(assignments, staged) == MySQL_User_Variable_Apply_Result::OK) {
		*this = staged;
	}
}

bool MySQL_User_Variable_State::remove_exact(const UserVariableAssignment& assignment) {
	const auto existing = entries_.find(assignment.canonical_name);
	if (existing == entries_.end() || !existing->second.exactly_equals(entry_from(assignment))) {
		return false;
	}
	stored_bytes_ -= existing->second.stored_bytes();
	entries_.erase(existing);
	return true;
}

void MySQL_User_Variable_State::clear() {
	entries_.clear();
	stored_bytes_ = 0;
}

size_t MySQL_User_Variable_State::size() const {
	return entries_.size();
}

size_t MySQL_User_Variable_State::stored_bytes() const {
	return stored_bytes_;
}

bool MySQL_User_Variable_State::has_names_absent_from(const MySQL_User_Variable_State& desired) const {
	for (const auto& item : entries_) {
		if (desired.entries_.find(item.first) == desired.entries_.end()) {
			return true;
		}
	}
	return false;
}

unsigned int MySQL_User_Variable_State::count_matches(
	const MySQL_User_Variable_State& desired, unsigned int& not_matching) const {
	unsigned int matches = 0;
	not_matching = 0;
	for (const auto& wanted : desired.entries_) {
		const auto actual = entries_.find(wanted.first);
		if (actual != entries_.end() && actual->second.exactly_equals(wanted.second)) {
			++matches;
		} else {
			++not_matching;
		}
	}
	return matches;
}

MySQL_User_Variable_Replay_Plan MySQL_User_Variable_State::build_replay_plan(
	const MySQL_User_Variable_State& actual, size_t max_query_bytes) const {
	const std::string replay_prefix("SET ");
	MySQL_User_Variable_Replay_Plan plan;
	MySQL_User_Variable_Replay_Batch batch;
	batch.sql = replay_prefix;

	for (const auto& desired : entries_) {
		const auto current = actual.entries_.find(desired.first);
		if (current != actual.entries_.end() && current->second.exactly_equals(desired.second)) {
			continue;
		}

		const std::string rendered = desired.second.replay_target + "=" + desired.second.raw_literal;
		if (replay_prefix.size() + rendered.size() > max_query_bytes) {
			return { MySQL_User_Variable_Replay_Status::ASSIGNMENT_TOO_LARGE, {} };
		}
		if (!batch.assignments.empty() && batch.sql.size() + 1 + rendered.size() > max_query_bytes) {
			plan.batches.push_back(batch);
			batch = MySQL_User_Variable_Replay_Batch {};
			batch.sql = replay_prefix;
		}
		batch.sql += batch.assignments.empty() ? rendered : "," + rendered;
		batch.assignments.push_back(assignment_from(desired.first, desired.second));
	}

	if (!batch.assignments.empty()) {
		plan.batches.push_back(batch);
	}
	return plan;
}

MySQL_User_Variable_Replay_Completion mysql_user_variable_replay_complete(
	MySQL_User_Variable_State& backend,
	const std::vector<MySQL_User_Variable_Replay_Batch>& batches,
	size_t batch_index,
	bool batch_succeeded) {
	if (!batch_succeeded || batch_index >= batches.size()) {
		return MySQL_User_Variable_Replay_Completion::FAIL_CLIENT_QUERY_AND_RETIRE_BACKEND;
	}

	MySQL_User_Variable_State staged;
	if (backend.stage(batches[batch_index].assignments, staged) !=
		MySQL_User_Variable_Apply_Result::OK) {
		return MySQL_User_Variable_Replay_Completion::FAIL_CLIENT_QUERY_AND_RETIRE_BACKEND;
	}
	backend = std::move(staged);
	return batch_index + 1 < batches.size()
		? MySQL_User_Variable_Replay_Completion::CONTINUE_SETTING_USER_VARIABLES
		: MySQL_User_Variable_Replay_Completion::RESUME_SAVED_STATUS;
}

MySQL_User_Variable_Replay_Packet_Budget mysql_user_variable_replay_packet_budget(
	uint32_t max_allowed_pkt, size_t framing_bytes) {
	// MySQL and MariaDB document 1024 bytes as the minimum server
	// max_allowed_packet value, so an unpopulated backend field can safely use it.
	const bool use_server_minimum = max_allowed_pkt == 0;
	const size_t packet_limit = use_server_minimum
		? MYSQL_USER_VARIABLE_REPLAY_MINIMUM_SERVER_PACKET_BYTES
		: max_allowed_pkt;
	if (packet_limit <= framing_bytes) {
		return { MySQL_User_Variable_Replay_Packet_Budget_Status::PACKET_LIMIT_TOO_SMALL, 0 };
	}
	return {
		use_server_minimum
			? MySQL_User_Variable_Replay_Packet_Budget_Status::FALLBACK_TO_SERVER_MINIMUM
			: MySQL_User_Variable_Replay_Packet_Budget_Status::OK,
		packet_limit - framing_bytes
	};
}

std::vector<MySQL_User_Variable_Replay_Batch> mysql_user_variable_split_replay_batch(
	const MySQL_User_Variable_Replay_Batch& batch) {
	std::vector<MySQL_User_Variable_Replay_Batch> singles;
	singles.reserve(batch.assignments.size());
	for (const UserVariableAssignment& assignment : batch.assignments) {
		MySQL_User_Variable_Replay_Batch single;
		single.sql = "SET " + assignment.replay_target + "=" + assignment.raw_literal;
		single.assignments.push_back(assignment);
		singles.push_back(std::move(single));
	}
	return singles;
}

bool mysql_user_variable_replay_error_rejects_value(unsigned int backend_error_code) {
	// Only errors that name the statement or its value. Any other error (about the
	// session, the server, or the connection) must not remove a tracked value.
	switch (backend_error_code) {
		case 1064: // ER_PARSE_ERROR
		case 1231: // ER_WRONG_VALUE_FOR_VAR
		case 1232: // ER_WRONG_TYPE_FOR_VAR
		case 1292: // ER_TRUNCATED_WRONG_VALUE
		case 1300: // ER_INVALID_CHARACTER_STRING
		case 1366: // ER_TRUNCATED_WRONG_VALUE_FOR_FIELD
		case 1367: // ER_ILLEGAL_VALUE_FOR_TYPE
		case 1406: // ER_DATA_TOO_LONG
		case 1690: // ER_DATA_OUT_OF_RANGE
			return true;
		default:
			return false;
	}
}

bool mysql_user_variable_literal_overflows_double(const UserVariableAssignment& assignment) {
	if (assignment.kind != UserVariableLiteralKind::DECIMAL) {
		return false;
	}
	const std::string& literal = assignment.raw_literal;
	if (literal.find_first_of("eE") == std::string::npos) {
		return false; // an exact DECIMAL literal: MySQL does not reject it as a double
	}
	// The numeric token ends the literal source; a unary sign, whitespace, or a
	// comment may precede it. Take the trailing run of number characters and drop
	// its leading signs: the sign does not change whether the magnitude overflows.
	size_t number_start = literal.size();
	while (number_start > 0 &&
		std::strchr("0123456789.eE+-", literal[number_start - 1]) != nullptr) {
		--number_start;
	}
	while (number_start < literal.size() &&
		(literal[number_start] == '+' || literal[number_start] == '-')) {
		++number_start;
	}
	if (number_start == literal.size()) {
		return false;
	}
	errno = 0;
	const double value = std::strtod(literal.c_str() + number_start, nullptr);
	return errno == ERANGE && std::isinf(value);
}

std::string MySQL_User_Variable_State::diagnostic_fingerprint() const {
	Fingerprint_Keys& keys = fingerprint_keys();
	if (!keys.available) {
		return {};
	}

	std::string serialized;
	append_u64(serialized, entries_.size());
	for (const auto& item : entries_) {
		append_string(serialized, item.first);
		append_string(serialized, item.second.replay_target);
		append_u64(serialized, static_cast<uint64_t>(item.second.kind));
		append_string(serialized, item.second.raw_literal);
	}
	uint64_t first = keys.first;
	uint64_t second = keys.second;
	SpookyHash::Hash128(serialized.data(), serialized.size(), &first, &second);
	std::ostringstream formatted;
	formatted << std::hex << std::setfill('0') << std::setw(16) << first << std::setw(16) << second;
	return formatted.str();
}
