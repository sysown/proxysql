#include "duckdb_replica_binlog.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

std::string sql_literal(const std::string& value) {
	std::string out("'");
	for (char c : value) {
		out.push_back(c);
		if (c == '\'') out.push_back('\'');
	}
	out.push_back('\'');
	return out;
}

std::string hex_literal(const std::string& bytes) {
	static const char digits[] = "0123456789abcdef";
	std::string out("from_hex('");
	for (unsigned char c : bytes) {
		out.push_back(digits[c >> 4]);
		out.push_back(digits[c & 0x0f]);
	}
	out += "')";
	return out;
}

bool numeric_text_ok(const std::string& text) {
	if (text.empty()) return false;
	for (char c : text) {
		if ((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' || c == 'e' || c == 'E') continue;
		return false;
	}
	return true;
}

} // namespace

std::string duckdb_replica_value_literal(const DuckDBReplicaValue& value, std::string& err) {
	switch (value.kind) {
	case DuckDBReplicaValue::Kind::null:
		return "NULL";
	case DuckDBReplicaValue::Kind::integer:
		return std::to_string(value.integer);
	case DuckDBReplicaValue::Kind::real: {
		if (!std::isfinite(value.real)) {
			err = "non-finite floating-point value";
			return "";
		}
		char buf[64];
		std::snprintf(buf, sizeof(buf), "%.17g", value.real);
		return buf;
	}
	case DuckDBReplicaValue::Kind::decimal_text:
		if (!numeric_text_ok(value.text)) {
			err = "invalid numeric text";
			return "";
		}
		return value.text;
	case DuckDBReplicaValue::Kind::text:
		if (value.text.find('\0') != std::string::npos) {
			err = "VARCHAR value contains a NUL byte";
			return "";
		}
		return sql_literal(value.text);
	case DuckDBReplicaValue::Kind::binary:
		return hex_literal(value.text);
	case DuckDBReplicaValue::Kind::date:
	case DuckDBReplicaValue::Kind::datetime:
	case DuckDBReplicaValue::Kind::time:
		return sql_literal(value.text);
	}
	err = "unknown value kind";
	return "";
}

void DuckDBReplicaGtidSet::add(const std::string& uuid, uint64_t sequence) {
	add_interval(uuid, sequence, sequence);
}

void DuckDBReplicaGtidSet::add_interval(const std::string& uuid, uint64_t first, uint64_t last) {
	if (last < first) std::swap(first, last);
	auto& intervals = intervals_[uuid];
	intervals.emplace_back(first, last);
	std::sort(intervals.begin(), intervals.end());
	for (size_t i = 1; i < intervals.size();) {
		const bool adjacent = intervals[i].first <= intervals[i - 1].second ||
			(intervals[i - 1].second != UINT64_MAX &&
			 intervals[i].first == intervals[i - 1].second + 1);
		if (adjacent) {
			intervals[i - 1].second = std::max(intervals[i - 1].second, intervals[i].second);
			intervals.erase(intervals.begin() + static_cast<std::ptrdiff_t>(i));
		} else {
			++i;
		}
	}
}

bool DuckDBReplicaGtidSet::merge(const std::string& gtid_set, std::string& err) {
	return duckdb_replica_parse_gtid_set(gtid_set, *this, err);
}

void DuckDBReplicaGtidSet::merge(const DuckDBReplicaGtidSet& other) {
	for (const auto& item : other.intervals_) {
		for (const auto& interval : item.second) {
			add_interval(item.first, interval.first, interval.second);
		}
	}
}

std::string DuckDBReplicaGtidSet::to_string() const {
	std::string out;
	for (const auto& item : intervals_) {
		for (const auto& interval : item.second) {
			if (!out.empty()) out += ",";
			out += item.first + ":";
			out += std::to_string(interval.first);
			if (interval.second != interval.first) out += "-" + std::to_string(interval.second);
		}
	}
	return out;
}

bool DuckDBReplicaGtidSet::empty() const {
	return intervals_.empty();
}

bool duckdb_replica_parse_gtid_set(const std::string& text,
                                   DuckDBReplicaGtidSet& out,
                                   std::string& err) {
	size_t pos = 0;
	while (pos <= text.size() && !text.empty()) {
		const size_t comma = text.find(',', pos);
		const std::string entry = text.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
		if (!entry.empty()) {
			const size_t colon = entry.rfind(':');
			if (colon == std::string::npos || colon == 0 || colon + 1 >= entry.size()) {
				err = "malformed GTID set entry '" + entry + "'";
				return false;
			}
			const std::string uuid = entry.substr(0, colon);
			const std::string range = entry.substr(colon + 1);
			const size_t dash = range.find('-');
			char* end = nullptr;
			const uint64_t first = std::strtoull(range.c_str(), &end, 10);
			if (end == range.c_str() || end == nullptr) {
				err = "malformed GTID sequence in '" + entry + "'";
				return false;
			}
			uint64_t last = first;
			if (dash != std::string::npos) {
				const std::string second = range.substr(dash + 1);
				end = nullptr;
				last = std::strtoull(second.c_str(), &end, 10);
				if (end == second.c_str() || end == nullptr || last < first) {
					err = "malformed GTID range in '" + entry + "'";
					return false;
				}
			}
			out.add_interval(uuid, first, last);
		}
		if (comma == std::string::npos) break;
		pos = comma + 1;
	}
	return true;
}
