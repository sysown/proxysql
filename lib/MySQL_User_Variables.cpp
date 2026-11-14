#include "MySQL_User_Variables.h"

#include "SpookyV2.h"
#include "openssl/rand.h"
#include "proxysql.h"
#include "proxysql_find_charset.h"

#include <iomanip>
#include <mutex>
#include <sstream>
#include <utility>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <algorithm>
#include <cstring>

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
	return { assignment.replay_target, assignment.raw_literal, assignment.kind, assignment.hash, assignment.context };
}

UserVariableAssignment assignment_from(
	const std::string& canonical_name, const MySQL_User_Variable_Entry& entry) {
	return { canonical_name, entry.replay_target, entry.raw_literal, entry.kind, entry.hash, entry.context };
}

bool decode_user_string(const std::string& raw, const UserVariableLiteralContext& context, std::string& bytes) {
	if (raw.size() < 2 || (raw[0] != '\'' && raw[0] != '"') || raw.back() != raw[0]) return false;
	if (raw[0] == '"' && context.ansi_quotes) return false;
	const auto* charset = proxysql_find_charset_nr(context.client_charset);
	if (!charset) return false;
	for (size_t i = 1; i + 1 < raw.size(); ++i) {
		// A multi-byte character may contain a byte equal to a quote or a
		// backslash. Only standalone bytes can be SQL escape characters.
		const unsigned int length = charset->mb_valid
			? charset->mb_valid(raw.data() + i, raw.data() + raw.size() - 1) : 0;
		if (length > 1) {
			bytes.append(raw, i, length);
			i += length - 1;
			continue;
		}
		char c = raw[i];
		if (c == raw[0]) {
			if (i + 2 >= raw.size() || raw[i + 1] != c) return false;
			++i;
		} else if (c == '\\' && !context.no_backslash_escapes) {
			if (++i + 1 >= raw.size()) return false;
			switch (raw[i]) {
			case '0': c = '\0'; break;
			case 'b': c = '\b'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			case 'Z': c = 26; break;
			case '%': case '_': bytes.push_back('\\'); [[fallthrough]];
			default: c = raw[i]; break;
			}
		}
		bytes.push_back(c);
	}
	return true;
}

std::string replay_user_literal(const MySQL_User_Variable_Entry& entry) {
	if (entry.kind != UserVariableLiteralKind::STRING || entry.context.client_charset == 0) return entry.raw_literal;
	std::string bytes;
	if (!decode_user_string(entry.raw_literal, entry.context, bytes)) return {};
	const auto* client = proxysql_find_charset_nr(entry.context.client_charset);
	const auto* connection = proxysql_find_charset_nr(entry.context.connection_collation);
	if (!client || !connection) return {};
	static constexpr char hex[] = "0123456789ABCDEF";
	std::string literal = "CONVERT(CONVERT(X'";
	for (unsigned char c : bytes) {
		literal.push_back(hex[c >> 4]);
		literal.push_back(hex[c & 15]);
	}
	literal += "' USING ";
	literal += client->csname;
	literal += ") USING ";
	literal += connection->csname;
	literal += ") COLLATE ";
	literal += connection->name;
	return literal;
}

} // namespace

std::optional<std::string> mysql_user_variable_capture_schema(const char* schema) {
	if (!schema || !*schema) return std::string{};
	// Database identifiers have at most 64 characters, each at most four bytes.
	if (strlen(schema) > 256) return std::nullopt;
	return std::string(schema);
}

bool mysql_decode_set_string(const std::string& raw, const UserVariableLiteralContext& context, std::string& bytes) {
	return decode_user_string(raw, context, bytes);
}

bool mysql_user_variable_literal_is_replayable(const UserVariableAssignment& assignment) {
	if (assignment.kind == UserVariableLiteralKind::STRING && assignment.context.client_charset != 0) {
		std::string bytes;
		return decode_user_string(assignment.raw_literal, assignment.context, bytes) &&
			(assignment.context.resolve_database_collation ||
				proxysql_find_charset_nr(assignment.context.connection_collation));
	}
	if (assignment.kind == UserVariableLiteralKind::DECIMAL) {
		// MySQL rejects an overflowing approximate numeric literal at parse
		// time. Do not accept a value that can never be materialized later.
		const size_t exponent = assignment.raw_literal.find_first_of("eE");
		if (exponent != std::string::npos) {
			const size_t begin = assignment.raw_literal.find_last_not_of("0123456789.eE+-");
			const char* number = assignment.raw_literal.c_str() + (begin == std::string::npos ? 0 : begin + 1);
			char* end = nullptr;
			const double value = std::strtod(number, &end);
			if (end != number && !std::isfinite(value)) return false;
		}
	}
	return true;
}

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
	return replay_target.size() + raw_literal.size() + (context.database_schema ? context.database_schema->size() : 0);
}

bool MySQL_User_Variable_Entry::exactly_equals(const MySQL_User_Variable_Entry& other) const {
	return hash == other.hash && kind == other.kind && replay_target == other.replay_target &&
		raw_literal == other.raw_literal && context == other.context;
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

bool MySQL_User_Variable_State::unresolved_context(UserVariableLiteralContext& context) const {
	for (const auto& entry : entries_) {
		if (entry.second.context.resolve_database_collation) {
			context = entry.second.context;
			return true;
		}
	}
	return false;
}

void MySQL_User_Variable_State::resolve_context(const UserVariableLiteralContext& source, uint32_t collation) {
	for (auto& entry : entries_) {
		auto& context = entry.second.context;
		if (context.resolve_database_collation && context.database_schema == source.database_schema &&
			context.database_charset == source.database_charset &&
			context.database_schema_charset == source.database_schema_charset) {
			context.connection_collation = collation;
			context.resolve_database_collation = false;
		}
	}
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
		if (desired.second.context.resolve_database_collation) {
			return { MySQL_User_Variable_Replay_Status::UNRESOLVED_CONTEXT, {} };
		}
		const auto current = actual.entries_.find(desired.first);
		if (current != actual.entries_.end() && current->second.exactly_equals(desired.second)) {
			continue;
		}

		const std::string rendered = desired.second.replay_target + "=" + replay_user_literal(desired.second);
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
		append_u64(serialized, item.second.context.client_charset);
		append_u64(serialized, item.second.context.connection_collation);
		append_u64(serialized, item.second.context.no_backslash_escapes);
		append_u64(serialized, item.second.context.ansi_quotes);
		append_u64(serialized, item.second.context.resolve_database_collation);
		append_u64(serialized, item.second.context.database_charset);
		append_u64(serialized, item.second.context.database_schema_charset);
		append_u64(serialized, item.second.context.database_schema.has_value());
		if (item.second.context.database_schema) append_string(serialized, *item.second.context.database_schema);
	}
	uint64_t first = keys.first;
	uint64_t second = keys.second;
	SpookyHash::Hash128(serialized.data(), serialized.size(), &first, &second);
	std::ostringstream formatted;
	formatted << std::hex << std::setfill('0') << std::setw(16) << first << std::setw(16) << second;
	return formatted.str();
}
