#ifndef PROXYSQL_GTID
#define PROXYSQL_GTID
// highly inspired by libslave
// https://github.com/vozbu/libslave/
#include <cstddef>
#include <cstdint>
#include <list>
#include <locale>
#include <string>
#include <unordered_map>
#include <map>
#include <vector>

typedef int64_t trxid_t;

// Character classification goes through the <locale> ctype facet rather than
// the C <ctype.h> functions, whose argument is required to be representable as
// unsigned char and whose locale state is global. The classic locale is the
// process-wide "C" locale, so the classification does not depend on setlocale().
inline const std::ctype<char>& gtid_char_type() {
	static const std::locale classic(std::locale::classic());
	return std::use_facet<std::ctype<char> >(classic);
}

inline bool gtid_is_digit(unsigned char c) {
	return gtid_char_type().is(std::ctype_base::digit, c);
}

inline bool gtid_is_hex_digit(unsigned char c) {
	return gtid_char_type().is(std::ctype_base::xdigit, c);
}

// Encapsulates an interval of Transaction IDs.
class TrxId_Interval {
	public:
		trxid_t start;
		trxid_t end;

	public:
		explicit TrxId_Interval(const trxid_t _start, const trxid_t _end);
		explicit TrxId_Interval(const trxid_t trxid);
		explicit TrxId_Interval(const char* s);
		explicit TrxId_Interval(const std::string& s);
		static bool parse(const char* s, TrxId_Interval* out);

		const bool contains(const TrxId_Interval& other);
		const bool contains(trxid_t trxid);
		const std::string to_string(void);
		const bool append(const TrxId_Interval& other);
		const bool merge(const TrxId_Interval& other);

		int cmp(const TrxId_Interval& other) const;
bool operator<(const TrxId_Interval& other) const;
bool operator==(const TrxId_Interval& other) const;
bool operator!=(const TrxId_Interval& other) const;
};

// Encapsulates a map of UUID -> trxid intervals.
class GTID_Set {
	public:
		std::unordered_map<std::string, std::list<TrxId_Interval>> map;
		std::unordered_map<std::string, uint32_t> last_server_id;

	public:
		GTID_Set();

		GTID_Set copy();
		void clear();

		bool add(const std::string& uuid, const TrxId_Interval& iv);
		bool add(const std::string& uuid, const trxid_t& trxid);
		bool add(const std::string& uuid, const trxid_t& start, const trxid_t& end);
		bool add(const std::string& uuid, const char *s);
		bool add(const std::string& uuid, const std::string &s);

		void set_server_id(const std::string& id, uint32_t server_id);
		uint32_t get_server_id(const std::string& id) const;

		const bool has_gtid(const std::string& uuid, const trxid_t trxid);
		const std::string to_string(void);
		const std::string to_display_string(void);
};

struct ParsedGTID {
	std::string id;
	trxid_t trxid;
	uint32_t server_id;
	bool mariadb;
};

bool parse_gtid(const char* s, ParsedGTID* out);
bool parse_gtid(const char* s, size_t len, ParsedGTID* out);
bool parse_gtid_for_routing(const char* gtid, char* id_buf, size_t id_buf_len,
                            uint64_t* trxid);
/**
 * @brief Parses a MySQL GTID SET -- the grammar OWN_GTID tracking actually
 *   delivers -- into one ordered interval vector per UUID.
 *
 * MySQL's SESSION_TRACK_GTIDS payload accumulates every GTID the session has
 * committed until the server finishes answering the current command, so a
 * single OK packet can carry 'uuid:582-584' (stored procedures committing
 * more than once), 'uuid:636:638' (concurrent commits producing a gap) or
 * 'uuid:1-5:7-9', and 'Gtid_set::to_string' separates UUID blocks with
 * ",\n" (issue #6415). The strict single-GTID parser rejects all of those
 * trailing-set spellings, which used to silently drop the routing
 * predicate.
 *
 * Grammar per UUID block: normalize_mysql_uuid of the first ':' component,
 * then one or more TrxId_Interval components separated by ':'. Blocks are
 * separated by ',' or '\n'. Unexpected input -- tagged GTIDs ('uuid:tag:n'),
 * bare garbage, empty components -- fails and leaves @p out untouched.
 *
 * @param s     Raw tracked value; NUL bytes are rejected.
 * @param len   Length of the value.
 * @param out   Receives one interval vector per UUID, all intervals strictly
 *              validated. Multi-UUID sets are accepted here; CALLERS that can
 *              only honour a single UUID must fail closed on them (see
 *              parse_gtid_set_for_routing).
 * @return true when the whole value parsed.
 */
bool parse_gtid_set(const char* s, size_t len,
                    std::map<std::string, std::vector<TrxId_Interval>>* out);
/**
 * @brief Routing helper for a tracked OWN_GTID value: same grammar, single
 *   UUID block only, reporting the HIGHEST trxid of the block.
 *
 * Routing asks "has every transaction this session committed been applied
 * here": with commit-order-preserving appliers
 * (replica_preserve_commit_order=ON, the default since MySQL 8.0.27) a
 * replica holding the highest transaction id of the block holds every
 * earlier one as well, so one "(uuid, max trxid)" pair is sufficient and no
 * containment walk is needed. Without order preservation a multi-threaded
 * applier can hold the top id while missing a gap, which is the documented
 * limitation of the minimum-change variant chosen for #6415.
 *
 * Multi-UUID values (only possible via a manual gtl_next) and tagged GTIDs
 * fail: the caller must then fail closed instead of dropping the predicate.
 *
 * @return false leaves @p id_buf and @p trxid untouched.
 */
bool parse_gtid_set_for_routing(const char* gtid, char* id_buf, size_t id_buf_len,
                                uint64_t* trxid);
// Selects the GTID of the session's own last transaction from an OK packet:
// the SESSION_TRACK_GTIDS payload (MySQL), or else the tracked 'last_gtid'
// system variable (MariaDB). Global positions such as 'gtid_binlog_pos' are
// never used: they describe the whole server and can be multi-domain lists.
// `buf` is left untouched on failure, and also when the value is unchanged.
bool select_session_gtid(
	const char* session_track_gtids, size_t gtids_len,
	const char* last_gtid, size_t last_gtid_len,
	char* buf, size_t buf_len);

// Accepts only the canonical decimal spelling of a MariaDB domain id: digits
// only, no leading zero unless the id is exactly "0" (so that `0` and `00`
// cannot name the same domain), and a value representable as a uint32.
bool is_canonical_mariadb_domain_id(const char* id, size_t len);

#endif /* PROXYSQL_GTID */
