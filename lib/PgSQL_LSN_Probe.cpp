#include "PgSQL_LSN_Probe.h"
#ifdef PROXYSQL31
#include <charconv>
using namespace pgsql_lsn;
bool ProbeCadence::due(Micros now, Micros interval) const {
	return !active_ && (!last_start_ || (now >= *last_start_ && now - *last_start_ >= interval));
}
void ProbeCadence::started(Micros now) {
	last_start_ = now;
	active_ = true;
}
void ProbeCadence::finished() {
	active_ = false;
}
PgSQL_LSN_Probe::PgSQL_LSN_Probe(Endpoint endpoint, std::optional<History> identity,
								 std::optional<WalLayout> layout)
	: identity_(identity), layout_(layout) {
	result_.endpoint = std::move(endpoint);
	if (identity_)
		stage_ = layout_ ? Stage::Sample : Stage::Layout;
}
std::optional<std::string> PgSQL_LSN_Probe::next_command(Micros now) {
	if (awaiting_ || stage_ == Stage::Failed || stage_ == Stage::Complete)
		return {};
	awaiting_ = true;
	if (stage_ == Stage::InitialIdentity || stage_ == Stage::FinalIdentity)
		return "IDENTIFY_SYSTEM";
	if (stage_ == Stage::Layout)
		return "SELECT max_data_alignment, wal_block_size, bytes_per_wal_segment, "
			   "pg_catalog.current_setting('server_version_num') FROM "
			   "pg_catalog.pg_control_init()";
	result_.sample.started_at = now;
	return "SELECT (EXTRACT(EPOCH FROM "
		   "pg_catalog.pg_postmaster_start_time())*1000000)::bigint, "
		   "pg_catalog.pg_is_in_recovery(), CASE WHEN "
		   "pg_catalog.pg_is_in_recovery() "
		   "THEN pg_catalog.pg_last_wal_replay_lsn() ELSE "
		   "pg_catalog.pg_current_wal_insert_lsn() "
		   "END";
}
namespace {
template <typename T> bool number(const std::optional<std::string> &text, T &value) {
	if (!text || text->empty())
		return false;
	auto p = std::from_chars(text->data(), text->data() + text->size(), value);
	return p.ec == std::errc() && p.ptr == text->data() + text->size() && value > 0;
}
bool power_of_two(uint32_t n) {
	return n && !(n & (n - 1));
}
Lsn insertion_end(Lsn position, const WalLayout &layout) {
	// PostgreSQL 14–18 XLogBytePosToRecPtr points past the header when the
	// reserved WAL ends exactly at a page boundary. Replay reports the page
	// start (XLogBytePosToEndRecPtr). Match that conversion only at those two
	// exact offsets; all reserved record bytes, including async commits, remain
	// covered. XLogPageHeaderData is 20 bytes before trailing alignment; the
	// long form appends uint64 + uint32 + uint32 to the aligned short struct.
	const uint32_t major = layout.server_version / 10000;
	if (major < 14 || major > 18 || (layout.alignment != 4 && layout.alignment != 8))
		return position;
	const uint32_t short_header = (20 + layout.alignment - 1) & ~(layout.alignment - 1);
	const uint32_t long_header = short_header + 16;
	const Lsn offset = position % layout.segment_size;
	if (offset == long_header)
		return position - long_header;
	if (offset >= layout.block_size && offset % layout.block_size == short_header)
		return position - short_header;
	return position;
}
} // namespace
bool PgSQL_LSN_Probe::consume_result(const ProbeRows &rows, std::string &error) {
	auto reject = [&](const char *message) {
		error = message;
		fail(error);
		return false;
	};
	if (!awaiting_ || stage_ == Stage::Failed || stage_ == Stage::Complete)
		return reject("Unexpected LSN probe result");
	awaiting_ = false;
	if (rows.size() != 1)
		return reject("LSN probe expected exactly one row");
	const auto &row = rows[0];
	if (stage_ == Stage::InitialIdentity || stage_ == Stage::FinalIdentity) {
		History h;
		if (row.size() != 4 || !number(row[0], h.system_id) || !number(row[1], h.timeline))
			return reject("Invalid IDENTIFY_SYSTEM result");
		if (identity_ && !(*identity_ == h))
			return reject("LSN history changed during sampling");
		identity_ = h;
		if (stage_ == Stage::InitialIdentity)
			stage_ = layout_ ? Stage::Sample : Stage::Layout;
		else {
			result_.history = h;
			result_.valid = true;
			stage_ = Stage::Complete;
		}
	} else if (stage_ == Stage::Layout) {
		WalLayout layout;
		if (row.size() != 4 || !number(row[0], layout.alignment) ||
			!number(row[1], layout.block_size) || !number(row[2], layout.segment_size) ||
			!number(row[3], layout.server_version) || !power_of_two(layout.alignment) ||
			!power_of_two(layout.block_size) || layout.block_size < 1024 ||
			layout.block_size > 65536 || !power_of_two(layout.segment_size) ||
			layout.segment_size < 1048576 || layout.segment_size > 1073741824 ||
			layout.alignment > layout.block_size)
			return reject("Invalid WAL layout metadata");
		layout_ = layout;
		stage_ = Stage::Sample;
	} else {
		int64_t start = 0;
		if (row.size() != 3 || !number(row[0], start) || !row[1] ||
			(*row[1] != "t" && *row[1] != "f"))
			return reject("Invalid LSN sample identity or recovery state");
		auto position = row[2] ? parse_lsn(*row[2]) : std::nullopt;
		if (!position)
			return reject("Invalid WAL position in LSN sample");
		result_.postmaster_start_us = start;
		result_.sample.lsn =
			*row[1] == "f" && layout_ ? insertion_end(*position, *layout_) : *position;
		stage_ = Stage::FinalIdentity;
	}
	error.clear();
	return true;
}
std::optional<Observation> PgSQL_LSN_Probe::finish() const {
	return stage_ == Stage::Complete && result_.valid ? std::optional<Observation>{result_}
													  : std::nullopt;
}
void PgSQL_LSN_Probe::fail(const std::string &) {
	result_.valid = false;
	stage_ = Stage::Failed;
	awaiting_ = false;
}
#endif
