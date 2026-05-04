#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sstream>

#include "proxysql_gtid.h"

// Initializes a trxid interval from a range.
TrxId_Interval::TrxId_Interval(const trxid_t _start, const trxid_t _end) {
	start = _start;
	end = _end;

	if (start > end) {
		std::swap(start, end);
	}
}

TrxId_Interval::TrxId_Interval(const trxid_t trxid) : TrxId_Interval(trxid, trxid) {
}

static bool parse_trxid_component(const char*& p, trxid_t& out) {
	if (p == nullptr || !std::isdigit(static_cast<unsigned char>(*p))) {
		return false;
	}

	errno = 0;
	char* end = nullptr;
	long long parsed = strtoll(p, &end, 10);
	if (end == p || errno == ERANGE || parsed < 0) {
		return false;
	}

	out = static_cast<trxid_t>(parsed);
	p = end;
	return true;
}

bool TrxId_Interval::parse(const char* s, TrxId_Interval* out) {
	if (s == nullptr || out == nullptr) {
		return false;
	}

	const char* p = s;
	trxid_t _start = 0;
	trxid_t _end = 0;

	if (!parse_trxid_component(p, _start)) {
		return false;
	}

	_end = _start;
	if (*p == '-') {
		p++;
		if (!parse_trxid_component(p, _end)) {
			return false;
		}
	}

	if (*p != '\0') {
		return false;
	}

	*out = TrxId_Interval(_start, _end);
	return true;
}

// Initializes a trxid interval from a C string buffer, in [trxid]{-[trxid]} format.
TrxId_Interval::TrxId_Interval(const char *s) {
	start = 0;
	end = 0;

	TrxId_Interval iv(trxid_t(0));
	if (parse(s, &iv)) {
		start = iv.start;
		end = iv.end;
	}

	if (start > end) {
		std::swap(start, end);
	}
}

// Initializes a trxid interval from a string, in [trxid]{-[trxid]} format.
TrxId_Interval::TrxId_Interval(const std::string& s) : TrxId_Interval(s.c_str()) {
}

// Checks if another trxid interval is contained in this one,
const bool TrxId_Interval::contains(const TrxId_Interval& other) {
	return (other.start >= start && other.end <= end);
}

// Checks if a given trxid is contained in this interval.
const bool TrxId_Interval::contains(trxid_t trxid) {
	return (trxid >= start && trxid <= end);
}

// Yields a string representation for a trxid interval.
const std::string TrxId_Interval::to_string(void) {
	if (start == end) {
		return std::to_string(start);
	}
	return std::to_string(start) + "-" + std::to_string(end);
}

// Attempts to append a new interval to this interval's end. Returns true if the append succeded, false otherwise.
const bool TrxId_Interval::append(const TrxId_Interval& other) {
	if (other.start >= start && other.end >= end && other.start <= (end+1)) {
		// other overlaps interval at end
		end = other.end;
		return true;
	}

	return false;
}

// Attempts to merge two trxid intervals. Returns true if the intervals were merged (and potentially modified), false otherwise.
const bool TrxId_Interval::merge(const TrxId_Interval& other) {
	if (other.start >= start && other.end <= end) {
		// other is contained by interval
		return true;
	}
	if (other.start <= start && other.end >= end) {
		// other contains whole of existing interval
		start = other.start;
		end = other.end;
		return true;
	}
	if (other.start <= start && other.end >= (start-1)) {
		// other overlaps interval at start
		start = other.start;
		return true;
	}
	if (other.end >= end && other.start <= (end+1)) {
		// other overlaps interval at end
		end = other.end;
		return true;
	}

	return false;
}

// Compares two trxid intervals, by strict weak ordering.
int TrxId_Interval::cmp(const TrxId_Interval& other) const {
	if (start < other.start) {
		return -1;
	}
	if (start > other.start) {
		return 1;
	}
	if (end < other.end) {
		return -1;
	}
	if (end > other.end) {
		return 1;
	}
	return 0;
}

bool TrxId_Interval::operator<(const TrxId_Interval& other) const {
	return cmp(other) == -1;
}

bool TrxId_Interval::operator==(const TrxId_Interval& other) const {
	return cmp(other) == 0;
}

bool TrxId_Interval::operator!=(const TrxId_Interval& other) const {
	return cmp(other) != 0;
}

// Initializes a GTID set.
GTID_Set::GTID_Set() {}

// Creates a copy of this GTID set.
GTID_Set GTID_Set::copy() {
	GTID_Set cp;
	cp.map = map;
	return cp;
}

// Clears all GTID set entries.
void GTID_Set::clear() {
	map.clear();
}

// Adds a new trxid interval for a given UUID. Returns true if the set was modified, false otherwise.
bool GTID_Set::add(const std::string& uuid, const TrxId_Interval& iv) {
	auto it = map.find(uuid);
	if (it == map.end()) {
		// new UUID entry
		map[uuid].emplace_back(iv);
		return true;
	}

	if (!it->second.empty()) {
		auto& last = it->second.back();
		if (last.contains(iv)) {
			return false;
		}
		if (last.append(iv)) {
			return true;
		}
	}

	// insert/merge trxid interval...
	auto pos = it->second.begin();
	for (; pos != it->second.end(); ++pos) {
		if (pos->contains(iv)) {
			// trxid interval is already present, nothing to do
			return false;
		}
		if (pos->merge(iv))
			break;
	}
	if (pos == it->second.end()) {
		it->second.emplace_back(iv);
	}

	// ...and merge overlapping trxid ranges, if any
	it->second.sort();
	auto a = it->second.begin();
	while (a != it->second.end()) {
		auto b = std::next(a);
		if (b == it->second.end()) {
			break;
		}
		if (a->merge(*b)) {
				it->second.erase(b);
				continue;
		}
		a++;
	}

	return true;
}

// Adds a single trxid for a given UUID. Returns true if the set was modified, false otherwise.
bool GTID_Set::add(const std::string& uuid, const trxid_t& trxid) {
	return add(uuid, TrxId_Interval(trxid));
}

// Adds a new trxid range for a given UUID. Returns true if the set was modified, false otherwise.
bool GTID_Set::add(const std::string& uuid, const trxid_t& start, const trxid_t& end) {
	return add(uuid, TrxId_Interval(start, end));
}

// Adds a new trxid range for a given UUID, as a C string buffer. Returns true if the set was modified, false otherwise.
bool GTID_Set::add(const std::string& uuid, const char *s) {
	TrxId_Interval iv(trxid_t(0));
	if (!TrxId_Interval::parse(s, &iv)) {
		return false;
	}
	return add(uuid, iv);
}

// Adds a new trxid range for a given UUID, as a string. Returns true if the set was modified, false otherwise.
bool GTID_Set::add(const std::string& uuid, const std::string& s) {
	return add(uuid, TrxId_Interval(s));
}

// Evaluates whether a trxid is present in any of the intervals for a given UUID.
const bool GTID_Set::has_gtid(const std::string& uuid, const trxid_t trxid) {
	auto it = map.find(uuid);
	if (it == map.end()) {
		return false;
	}
	for (auto itr = it->second.begin(); itr != it->second.end(); ++itr) {
		if (itr->contains(trxid)) {
			return true;
		}
	}

	return false;
}

// Yields a string representation for a GTID set.
const std::string GTID_Set::to_string(void) {
	std::stringstream out;
	bool first_uuid = true;
	for (auto it=map.begin(); it!=map.end(); ++it) {
		if (!first_uuid) {
			out << ",";
		}
		std::string uuid = it->first;
		uuid.insert(8,"-");
		uuid.insert(13,"-");
		uuid.insert(18,"-");
		uuid.insert(23,"-");
		out << uuid;
		for (auto itr = it->second.begin(); itr != it->second.end(); ++itr) {
			out << ":" << itr->to_string();
		}
		first_uuid = false;
	}

	return out.str();
}
