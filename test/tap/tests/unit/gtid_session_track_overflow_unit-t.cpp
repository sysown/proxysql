/**
 * @file gtid_session_track_overflow_unit-t.cpp
 * @brief A tracked OWN_GTID value that does not fit the 128-byte tracking
 *   buffer never leaves the previous GTID in place (#6465).
 *
 * select_session_gtid() used to return false for a value of 128 bytes or more
 * and leave the buffer untouched, so the backend kept the GTID of an EARLIER
 * write and causal reads were routed on it (stale reads). A single-UUID set is
 * now stored reduced to "uuid:<highest trxid>", the only part routing uses
 * (#6415); anything else becomes SESSION_GTID_UNTRACKABLE, which routing
 * rejects (fail closed).
 */

#include <cstring>
#include <string>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "proxysql_gtid.h"

namespace {

// The production buffers: the connection's and the backend's copy.
constexpr size_t kBuf = sizeof(MySQL_Connection::gtid_uuid);
static_assert(sizeof(MySQL_Backend::gtid_uuid) == kBuf, "backend and connection buffers differ");

const char kA[] = "aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa";
const char kB[] = "bbbbbbbb-0000-1111-2222-bbbbbbbbbbbb";
const char kPrevious[] = "aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:41";

/**
 * @brief Builds a single-UUID gap set ("uuid:1:3:5:...:1000...") of exactly
 *   @p len bytes, as concurrent commits inside one command produce.
 * @param max_out Receives the highest transaction id of the set.
 */
std::string gap_set(const char* uuid, size_t len, unsigned long long* max_out) {
	std::string s = std::string(uuid) + ":1";
	for (unsigned long long n = 3;; n += 2) {
		const std::string c = ":" + std::to_string(n);
		if (s.size() + c.size() + 8 > len) {
			break;
		}
		s += c;
	}
	const size_t digits = len - s.size() - 1;
	std::string last = "1" + std::string(digits - 1, '0');
	s += ":" + last;
	*max_out = std::stoull(last);
	return s;
}

struct Buf {
	char b[kBuf];
	Buf() { snprintf(b, sizeof(b), "%s", kPrevious); }
	bool select(const std::string& v) {
		return select_session_gtid(v.data(), v.size(), nullptr, 0, b, sizeof(b));
	}
};

bool routes_to(const char* v, const char* id, unsigned long long trx) {
	char got[64];
	uint64_t got_trx = 0;
	return parse_gtid_set_for_routing(v, got, sizeof(got), &got_trx) &&
		strcmp(got, id) == 0 && got_trx == trx;
}

bool not_routable(const char* v) {
	char got[64];
	uint64_t got_trx = 0;
	ParsedGTID p;
	return !parse_gtid_set_for_routing(v, got, sizeof(got), &got_trx) && !parse_gtid(v, &p);
}

const char kAId[] = "aaaaaaaa000011112222aaaaaaaaaaaa";

void test_single_uuid() {
	unsigned long long max = 0;
	std::string v = gap_set(kA, kBuf - 1, &max);
	Buf b;
	ok(v.size() == kBuf - 1 && b.select(v) && v == b.b, "127 bytes: stored verbatim");
	ok(routes_to(b.b, kAId, max), "127 bytes: routes on the highest trxid");

	v = gap_set(kA, kBuf, &max);
	const std::string reduced = std::string(kA) + ":" + std::to_string(max);
	Buf c;
	ok(v.size() == kBuf && c.select(v), "128 bytes: the buffer is updated");
	ok(strcmp(c.b, kPrevious) != 0, "128 bytes: the previous GTID is not kept");
	ok(reduced == c.b, "128 bytes: stored as uuid:<highest trxid>");
	ok(routes_to(c.b, kAId, max) && routes_to(v.c_str(), kAId, max),
		"128 bytes: the stored value routes exactly like the full set");

	v = gap_set(kA, 400, &max);
	Buf d;
	ok(v.size() == 400 && d.select(v) && std::string(kA) + ":" + std::to_string(max) == d.b,
		">128 bytes: stored as uuid:<highest trxid>");
	ok(!d.select(v), ">128 bytes: the same value again is reported unchanged");

	// A range ending below a later gap: the highest END wins, not the last.
	std::string ranges = std::string(kA) + ":1-900000";
	while (ranges.size() < 200) {
		ranges += ":5-6";
	}
	Buf e;
	ok(e.select(ranges) && std::string(kA) + ":900000" == e.b,
		">128 bytes: the highest interval end is kept, wherever it appears");

	// Uppercase input is stored canonical (lowercase, dashed).
	std::string upper = gap_set("AAAAAAAA-0000-1111-2222-AAAAAAAAAAAA", 200, &max);
	Buf f;
	ok(f.select(upper) && std::string(kA) + ":" + std::to_string(max) == f.b,
		">128 bytes: the reduced uuid is canonical");

	// Beyond the set parser's input cap the value cannot be parsed at all.
	v = gap_set(kA, 5000, &max);
	Buf g;
	ok(g.select(v) && strcmp(g.b, SESSION_GTID_UNTRACKABLE) == 0,
		"over the parser cap: stored as untrackable, not kept stale");
}

void test_unusable() {
	unsigned long long max = 0;
	// Multi-UUID: short ones are stored verbatim (routing fails closed on
	// them); long ones cannot be reduced to one (uuid, trxid).
	std::string multi = std::string(kA) + ":1-5,\n" + kB + ":1-3";
	Buf a;
	ok(a.select(multi) && multi == a.b, "multi-UUID under 128 bytes: stored verbatim");

	multi = gap_set(kA, 100, &max) + ",\n" + gap_set(kB, 100, &max);
	Buf b;
	ok(b.select(multi) && strcmp(b.b, SESSION_GTID_UNTRACKABLE) == 0,
		"multi-UUID over 128 bytes: stored as untrackable, not kept stale");
	ok(not_routable(b.b), "untrackable: every GTID parser rejects it, so routing fails closed");
	ok(!b.select(multi), "untrackable: a second untrackable value is reported unchanged");

	std::string tagged = std::string(kA) + ":tag:1";
	while (tagged.size() < 200) {
		tagged += ":7";
	}
	Buf c;
	ok(c.select(tagged) && strcmp(c.b, SESSION_GTID_UNTRACKABLE) == 0,
		"tagged GTID over 128 bytes: stored as untrackable");

	std::string garbage(300, 'x');
	Buf d;
	ok(d.select(garbage) && strcmp(d.b, SESSION_GTID_UNTRACKABLE) == 0,
		"garbage over 128 bytes: stored as untrackable");

	// A trackable value later replaces the marker.
	Buf e;
	e.select(multi);
	const std::string next = std::string(kA) + ":77";
	ok(e.select(next) && next == e.b, "a later trackable value replaces the marker");

	// MariaDB last_gtid is a single GTID and never this long; the list check
	// (#6335) still leaves the buffer untouched.
	Buf f;
	const char list[] = "0-1-5,1-2-7";
	ok(!select_session_gtid(nullptr, 0, list, sizeof(list) - 1, f.b, sizeof(f.b)) &&
		strcmp(f.b, kPrevious) == 0, "MariaDB multi-domain list: buffer untouched (unchanged, #6335)");
}

void test_reduce_helper() {
	char out[SESSION_GTID_REDUCED_MAX_LEN];
	const std::string max_trx = std::string(kA) + ":1-9223372036854775807";
	ok(reduce_gtid_set_to_highest(max_trx.data(), max_trx.size(), out, sizeof(out)) &&
		std::string(kA) + ":9223372036854775807" == out,
		"reduce: the largest trxid fits SESSION_GTID_REDUCED_MAX_LEN");
	ok(!reduce_gtid_set_to_highest("0-1-100", 7, out, sizeof(out)),
		"reduce: a MariaDB GTID is not a MySQL set");
	char tiny[16];
	ok(!reduce_gtid_set_to_highest(max_trx.data(), max_trx.size(), tiny, sizeof(tiny)),
		"reduce: a too-small output buffer is reported");
}

} // namespace

int main() {
	plan(22);
	if (test_init_minimal() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	test_single_uuid();
	test_unusable();
	test_reduce_helper();
	test_cleanup_minimal();
	return exit_status();
}
