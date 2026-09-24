#include <cerrno>
#include <cctype>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
	cp.last_server_id = last_server_id;
	return cp;
}

// Clears all GTID set entries.
void GTID_Set::clear() {
	map.clear();
	last_server_id.clear();
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

void GTID_Set::set_server_id(const std::string& id, uint32_t server_id) {
	last_server_id[id] = server_id;
}

uint32_t GTID_Set::get_server_id(const std::string& id) {
	auto it = last_server_id.find(id);
	if (it == last_server_id.end()) {
		return 0;
	}
	return it->second;
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
		if (uuid.size() == 32) {
			uuid.insert(8,"-");
			uuid.insert(13,"-");
			uuid.insert(18,"-");
			uuid.insert(23,"-");
		}
		out << uuid;
		for (auto itr = it->second.begin(); itr != it->second.end(); ++itr) {
			out << ":" << itr->to_string();
		}
		first_uuid = false;
	}

	return out.str();
}

const std::string GTID_Set::to_display_string(void) {
	std::stringstream out;
	bool first = true;
	for (auto it = map.begin(); it != map.end(); ++it) {
		if (!first) {
			out << ",";
		}
		std::string uuid = it->first;
		if (uuid.size() == 32) {
			uuid.insert(8,"-");
			uuid.insert(13,"-");
			uuid.insert(18,"-");
			uuid.insert(23,"-");
			out << uuid;
			for (auto itr = it->second.begin(); itr != it->second.end(); ++itr) {
				out << ":" << itr->to_string();
			}
		} else {
			trxid_t max_end = 0;
			for (auto itr = it->second.begin(); itr != it->second.end(); ++itr) {
				if (itr->end > max_end) {
					max_end = itr->end;
				}
			}
			out << uuid << "-" << get_server_id(uuid) << "-" << max_end;
		}
		first = false;
	}

	return out.str();
}

static bool parse_uint_no_leading_zeros(const char*& p, unsigned long long& out) {
	if (p == nullptr || !std::isdigit(static_cast<unsigned char>(*p))) {
		return false;
	}
	if (*p == '0' && std::isdigit(static_cast<unsigned char>(p[1]))) {
		return false;
	}

	errno = 0;
	char* end = nullptr;
	unsigned long long parsed = strtoull(p, &end, 10);
	if (end == p || errno == ERANGE) {
		return false;
	}

	out = parsed;
	p = end;
	return true;
}

static bool normalize_mysql_uuid(const char* start, size_t len, std::string& id) {
	if (start == nullptr) {
		return false;
	}

	std::string uuid;
	uuid.reserve(32);
	for (size_t i = 0; i < len; i++) {
		unsigned char c = static_cast<unsigned char>(start[i]);
		if (c == '-') {
			continue;
		}
		if (!std::isxdigit(c)) {
			return false;
		}
		if (c >= 'A' && c <= 'F') {
			c = static_cast<unsigned char>(c - 'A' + 'a');
		}
		uuid.push_back(static_cast<char>(c));
	}
	if (uuid.size() != 32) {
		return false;
	}

	id = std::move(uuid);
	return true;
}

static bool parse_mysql_gtid(const char* s, ParsedGTID& out) {
	const char* colon = strrchr(s, ':');
	if (colon == nullptr || colon == s || colon[1] == '\0') {
		return false;
	}

	ParsedGTID tmp;
	if (!normalize_mysql_uuid(s, static_cast<size_t>(colon - s), tmp.id)) {
		return false;
	}

	if (!std::isdigit(static_cast<unsigned char>(colon[1]))) {
		return false;
	}

	errno = 0;
	char* end = nullptr;
	unsigned long long parsed = strtoull(colon + 1, &end, 10);
	if (errno == ERANGE || end == colon + 1 || *end != '\0' || parsed == 0 ||
			parsed > static_cast<unsigned long long>(LLONG_MAX)) {
		return false;
	}

	tmp.trxid = static_cast<trxid_t>(parsed);
	tmp.server_id = 0;
	tmp.mariadb = false;
	out = tmp;
	return true;
}

static bool parse_mariadb_gtid(const char* s, ParsedGTID& out) {
	const char* p = s;
	unsigned long long domain = 0;
	unsigned long long server = 0;
	unsigned long long seq = 0;

	if (!parse_uint_no_leading_zeros(p, domain)) {
		return false;
	}
	if (*p != '-') {
		return false;
	}
	p++;
	if (!parse_uint_no_leading_zeros(p, server)) {
		return false;
	}
	if (*p != '-') {
		return false;
	}
	p++;
	if (!parse_uint_no_leading_zeros(p, seq)) {
		return false;
	}
	if (*p != '\0' || seq == 0 || server > UINT32_MAX ||
			seq > static_cast<unsigned long long>(LLONG_MAX)) {
		return false;
	}

	ParsedGTID tmp;
	tmp.id = std::to_string(domain);
	tmp.trxid = static_cast<trxid_t>(seq);
	tmp.server_id = static_cast<uint32_t>(server);
	tmp.mariadb = true;
	out = tmp;
	return true;
}

bool parse_gtid(const char* s, ParsedGTID* out) {
	if (s == nullptr || out == nullptr) {
		return false;
	}

	ParsedGTID tmp;
	if (strchr(s, ':') != nullptr) {
		if (!parse_mysql_gtid(s, tmp)) {
			return false;
		}
	} else if (!parse_mariadb_gtid(s, tmp)) {
		return false;
	}

	*out = tmp;
	return true;
}

bool parse_gtid(const char* s, size_t len, ParsedGTID* out) {
	if (s == nullptr || out == nullptr || len == 0) {
		return false;
	}

	std::string bounded(s, len);
	if (bounded.find('\0') != std::string::npos) {
		return false;
	}
	return parse_gtid(bounded.c_str(), out);
}

bool parse_gtid_for_routing(const char* gtid, char* id_buf, size_t id_buf_len,
                            uint64_t* trxid) {
	if (gtid == nullptr || id_buf == nullptr || id_buf_len == 0 || trxid == nullptr) {
		return false;
	}

	ParsedGTID parsed;
	if (!parse_gtid(gtid, &parsed) || parsed.id.size() >= id_buf_len) {
		return false;
	}

	memcpy(id_buf, parsed.id.c_str(), parsed.id.size() + 1);
	*trxid = static_cast<uint64_t>(parsed.trxid);
	return true;
}

bool select_session_gtid(
	const char* session_track_gtids, size_t gtids_len,
	const std::unordered_map<std::string, std::string>& sysvars,
	char* buf, size_t buf_len) {
	if (buf == nullptr || buf_len == 0) {
		return false;
	}

	std::string selected;
	if (gtids_len > 0) {
		if (session_track_gtids == nullptr) {
			return false;
		}
		selected.assign(session_track_gtids, gtids_len);
	} else {
		auto binlog_pos = sysvars.find("gtid_binlog_pos");
		if (binlog_pos != sysvars.end() && !binlog_pos->second.empty()) {
			selected = binlog_pos->second;
		} else {
			auto current_pos = sysvars.find("gtid_current_pos");
			if (current_pos != sysvars.end() && !current_pos->second.empty()) {
				selected = current_pos->second;
			}
		}
	}

	if (selected.empty() || selected.size() >= buf_len) {
		return false;
	}
	if (strncmp(selected.c_str(), buf, selected.size()) == 0
			&& buf[selected.size()] == '\0') {
		return false;
	}

	memcpy(buf, selected.c_str(), selected.size() + 1);
	return true;
}

static bool add_mysql_gtid_token(GTID_Set& set, const char* token, size_t len) {
	if (token == nullptr || len == 0) {
		return false;
	}

	const char* colon = static_cast<const char*>(memchr(token, ':', len));
	if (colon == nullptr || colon == token) {
		return false;
	}

	std::string id;
	if (!normalize_mysql_uuid(token, static_cast<size_t>(colon - token), id)) {
		return false;
	}

	const char* p = colon + 1;
	const char* end = token + len;
	bool any = false;
	while (p < end) {
		const char* next = static_cast<const char*>(memchr(p, ':', static_cast<size_t>(end - p)));
		const char* iv_end = next ? next : end;
		if (iv_end == p) {
			return false;
		}
		std::string ivs(p, static_cast<size_t>(iv_end - p));
		TrxId_Interval iv(trxid_t(0));
		if (!TrxId_Interval::parse(ivs.c_str(), &iv)) {
			return false;
		}
		set.add(id, iv);
		any = true;
		if (next == nullptr) {
			break;
		}
		p = next + 1;
	}

	return any;
}

bool parse_gtid_set(const char* encoded, GTID_Set* out) {
	if (encoded == nullptr || out == nullptr || encoded[0] == '\0') {
		return false;
	}

	const bool mysql = strchr(encoded, ':') != nullptr;
	GTID_Set tmp;
	const char* p = encoded;
	while (*p) {
		const char* comma = strchr(p, ',');
		size_t len = comma ? static_cast<size_t>(comma - p) : strlen(p);
		if (len == 0) {
			return false;
		}
		if (mysql) {
			if (!add_mysql_gtid_token(tmp, p, len)) {
				return false;
			}
		} else {
			std::string token(p, len);
			ParsedGTID parsed;
			if (!parse_gtid(token.c_str(), &parsed) || !parsed.mariadb) {
				return false;
			}
			tmp.add(parsed.id, trxid_t(1), parsed.trxid);
			tmp.set_server_id(parsed.id, parsed.server_id);
		}
		if (comma == nullptr) {
			break;
		}
		p = comma + 1;
		if (*p == '\0') {
			return false;
		}
	}

	*out = tmp;
	return true;
}
