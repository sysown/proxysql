#include "PgSQL_LSN_Probe.h"
#include <charconv>
using namespace pgsql_lsn;

bool ProbeCadence::due(Micros now, Micros interval, bool demand) const {
	return demand && !active_ && (!last_start_ || (now >= *last_start_ && now - *last_start_ >= interval));
}
void ProbeCadence::started(Micros now) { last_start_ = now; active_ = true; }
void ProbeCadence::finished() { active_ = false; }

PgSQL_LSN_Probe::PgSQL_LSN_Probe(GroupId group, Generation generation, Endpoint endpoint, Role role,
	std::optional<Incarnation> expected, uint64_t connection_generation, Micros started_at,
	std::optional<History> preceding_identity) : expected_(expected), identity_(preceding_identity) {
	result_.server = {group, generation, std::move(endpoint), {}, role};
	result_.connection_generation = connection_generation;
	result_.sampled_at_us = started_at;
	if (identity_) stage_ = Stage::Sample;
}

std::optional<std::string> PgSQL_LSN_Probe::next_command() {
	if (awaiting_ || stage_ == Stage::Failed || stage_ == Stage::Complete) return {};
	awaiting_ = true;
	if (stage_ == Stage::InitialIdentity || stage_ == Stage::FinalIdentity) return "IDENTIFY_SYSTEM";
	const std::string prefix = "SELECT (EXTRACT(EPOCH FROM pg_catalog.pg_postmaster_start_time())*1000000)::bigint, "
		"pg_catalog.pg_is_in_recovery(), ";
	if (result_.server.role == Role::Writer)
		return prefix + "CASE WHEN NOT pg_catalog.pg_is_in_recovery() THEN pg_catalog.pg_current_wal_insert_lsn() END";
	return prefix + "pg_catalog.pg_last_wal_replay_lsn()";
}

namespace {
template <typename T> bool number(const std::optional<std::string>& text, T& value) {
	if (!text || text->empty()) return false;
	const auto parsed = std::from_chars(text->data(), text->data() + text->size(), value);
	return parsed.ec == std::errc() && parsed.ptr == text->data() + text->size() && value > 0;
}
}

bool PgSQL_LSN_Probe::consume_result(const ProbeRows& rows, std::string& error) {
	auto reject = [&](const char* message, Reason reason = Reason::NoSafeBackend) {
		error = message;
		fail(error, reason);
		return false;
	};
	if (!awaiting_ || stage_ == Stage::Failed || stage_ == Stage::Complete)
		return reject("Unexpected LSN probe result");
	awaiting_ = false;
	if (rows.size() != 1) return reject("LSN probe expected exactly one row");
	const auto& row = rows[0];
	if (stage_ == Stage::InitialIdentity || stage_ == Stage::FinalIdentity) {
		History history;
		if (row.size() != 4 || !number(row[0], history.system_id) || !number(row[1], history.timeline))
			return reject("Invalid IDENTIFY_SYSTEM result");
		if ((identity_ && !(*identity_ == history)) || (expected_ && !(expected_->history == history)))
			return reject("LSN_HISTORY_CHANGED: system identifier or timeline changed", Reason::HistoryChanged);
		identity_ = history;
		if (stage_ == Stage::InitialIdentity) stage_ = Stage::Sample;
		else {
			result_.server.incarnation.history = history;
			result_.valid = true;
			stage_ = Stage::Complete;
		}
	} else {
		int64_t start = 0;
		if (row.size() != 3 || !number(row[0], start) || !row[1])
			return reject("Invalid LSN sample: expected postmaster start, recovery role and position");
		if (*row[1] != "t" && *row[1] != "f") return reject("Invalid recovery role in LSN sample");
		const bool replica = *row[1] == "t";
		if (replica != (result_.server.role == Role::Replica) || (expected_ && expected_->postmaster_start_us != start))
			return reject("LSN_HISTORY_CHANGED: role or postmaster incarnation changed", Reason::HistoryChanged);
		auto position = row[2] ? parse_lsn(*row[2]) : std::nullopt;
		if (!position) return reject("Invalid WAL position in LSN sample");
		result_.server.incarnation.postmaster_start_us = start;
		if (replica) result_.replay_lsn = position;
		else result_.insert_lsn = position;
		stage_ = Stage::FinalIdentity;
	}
	error.clear();
	return true;
}

std::optional<Progress> PgSQL_LSN_Probe::finish() const {
	if (stage_ != Stage::Complete || !result_.valid) return {};
	return result_;
}
void PgSQL_LSN_Probe::fail(const std::string& error, Reason reason) {
	result_.valid = false;
	result_.error = error;
	failure_reason_ = reason;
	stage_ = Stage::Failed;
	awaiting_ = false;
}
