#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sstream>

#include "proxysql_gtid.h"

// Initializes a UUID:GTID pair.
Uuid_Gtid::Uuid_Gtid(const std::string _uuid, const gtid_t _gtid) : uuid(_uuid), gtid(_gtid) {
}

// Copies a UUID:GTID pair.
Uuid_Gtid Uuid_Gtid::copy() {
	return Uuid_Gtid(uuid, gtid);

}

// Initializes a GTID interval from a range.
Gtid_Interval::Gtid_Interval(const gtid_t _start, const gtid_t _end) {
	start = _start;
	end = _end;

	if (start > end) {
		std::swap(start, end);
	}
}

Gtid_Interval::Gtid_Interval(const gtid_t gtid) : Gtid_Interval(gtid, gtid) {
}

// Initializes a GTID interval from a C string buffer, in [gtid]{-[gtid]} format.
Gtid_Interval::Gtid_Interval(const char *s) {
	gtid_t _start = 0, _end = 0;

	if (sscanf(s, "%ld-%ld", &_start, &_end) == 2) {
		start = _start;
		end = _end;
	} else if (sscanf(s, "%ld", &_start) == 1) {
		start = _start;
		end = _start;
	}

	if (start > end) {
		std::swap(start, end);
	}
}

// Initializes a GTID interval from a string, in [gtid]{-[gtid]} format.
Gtid_Interval::Gtid_Interval(const std::string& s) : Gtid_Interval(s.c_str()) {
}

// Checks if another GTID interval is contained in this one,
const bool Gtid_Interval::contains(const Gtid_Interval& other) {
	return (other.start >= start && other.end <= end);
}

// Checks if a given GTID is contained in this interval.
const bool Gtid_Interval::contains(gtid_t gtid) {
	return (gtid >= start && gtid <= end);
}

// Yields a string representation for a GTID interval.
const std::string Gtid_Interval::to_string(void) {
	if (start == end) {
		return std::to_string(start);
	}
	return std::to_string(start) + "-" + std::to_string(end);
}

// Attempts to append a new interval to this interval's end. Returns true if the append succeded, false otherwise.
const bool Gtid_Interval::append(const Gtid_Interval& other) {
	if (other.end >= end && other.start <= (end+1)) {
		// other overlaps interval at end
		end = other.end;
		return true;
	}

	return false;
}

// Attempts to merge two GTID intervals. Returns true if the intervals were merged (and potentially modified), false otherwise.
const bool Gtid_Interval::merge(const Gtid_Interval& other) {
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

// Compares two GTID intervals, by strict weak ordering.
const int Gtid_Interval::cmp(const Gtid_Interval& other) {
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

const bool Gtid_Interval::operator<(const Gtid_Interval& other) {
	return cmp(other) == -1;
}

const bool Gtid_Interval::operator==(const Gtid_Interval& other) {
	return cmp(other) == 0;
}

const bool Gtid_Interval::operator!=(const Gtid_Interval& other) {
	return cmp(other) != 0;
}

// Initializes a GTID interval set.
Gtid_Set::Gtid_Set() {}

// Creates a copy of this GTID interval set.
Gtid_Set Gtid_Set::copy() {
	auto cp = Gtid_Set();

	for (auto const& x : map) {
		for (auto const& iv : x.second) {
			cp.map[x.first].emplace_back(iv);
		}
	}

	return cp;
}

// Clears all GTID interval set entries.
void Gtid_Set::clear() {
	map.clear();
}

// Adds a new GTID interval for a given UUID. Returns true if the set was modified, false otherwise.
bool Gtid_Set::add(const std::string& uuid, const gtid_interval_t& iv) {
	auto it = map.find(uuid);
	if (it == map.end()) {
		// new UUID entry
		map[uuid].emplace_back(iv);
		return true;
	}

	if (!it->second.empty()) {
		if (it->second.back().append(iv)) {
			// if appending to the last GTID range succeded, gtid_executed was modified, but remains optimized - nothing else to do
			return true;
		}
	}

	// insert/merge GTID interval...
	auto pos = it->second.begin();
	for (; pos != it->second.end(); ++pos) {
		if (pos->contains(iv)) {
			// GTID interval is already present, nothing to do
			return false;
		}
		if (pos->merge(iv))
			break;
	}
	if (pos == it->second.end()) {
		it->second.emplace_back(iv);
	}

	// ...and merge overlapping GTID ranges, if any
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

// Adds a single GTID for a given UUID. Returns true if the set was modified, false otherwise.
bool Gtid_Set::add(const std::string& uuid, const gtid_t& gtid) {
	return add(uuid, gtid_interval_t(gtid));
}

// Adds a new GTID range for a given UUID. Returns true if the set was modified, false otherwise.
bool Gtid_Set::add(const std::string& uuid, const gtid_t& start, const gtid_t& end) {
	return add(uuid, gtid_interval_t(start, end));
}

// Adds a new GTID range for a given UUID, as a C string buffer. Returns true if the set was modified, false otherwise.
bool Gtid_Set::add(const std::string& uuid, const char *s) {
	return add(uuid, gtid_interval_t(s));
}

// Adds a new GTID range for a given UUID, as a string. Returns true if the set was modified, false otherwise.
bool Gtid_Set::add(const std::string& uuid, const std::string& s) {
	return add(uuid, gtid_interval_t(s));
}

// Evaluates whether a GTID is present in any of the intervals for a given UUID.
const bool Gtid_Set::has_gtid(const std::string& uuid, const gtid_t gtid) {
	auto it = map.find(uuid);
	if (it == map.end()) {
		return false;
	}
	for (auto itr = it->second.begin(); itr != it->second.end(); ++itr) {
		if (itr->contains(gtid)) {
			return true;
		}
	}

	return false;
}

// Yields a string representation for a GTID interval set.
const std::string Gtid_Set::to_string(void) {
	std::stringstream out;
	for (auto it=map.begin(); it!=map.end(); ++it) {
		std::string uuid = it->first;
		uuid.insert(8,"-");
		uuid.insert(13,"-");
		uuid.insert(18,"-");
		uuid.insert(23,"-");
		for (auto itr = it->second.begin(); itr != it->second.end(); ++itr) {
			if(itr != it->second.begin()) {
				out << ",";
			}
			out << uuid << ":" << itr->to_string();
		}
	}

	return out.str();
}