#ifndef PROXYSQL_GTID
#define PROXYSQL_GTID
// highly inspired by libslave
// https://github.com/vozbu/libslave/
#include <list>
#include <string>
#include <unordered_map>
#include <utility>

typedef int64_t gtid_t;

// Encapsulates a UUID:GTID pair.
class Uuid_Gtid {
	public:
		std::string uuid;
		gtid_t gtid;

	public:
		Uuid_Gtid(const std::string _uuid, const gtid_t _gtid);

		Uuid_Gtid copy();
};
typedef Uuid_Gtid ugtid_t;

// Encapsulates an interval of GTIDs.
class Gtid_Interval {
	public:
		gtid_t start;
		gtid_t end;

	public:
		explicit Gtid_Interval(const int64_t _start, const int64_t _end);
		explicit Gtid_Interval(const gtid_t gtid);
		explicit Gtid_Interval(const char* s);
		explicit Gtid_Interval(const std::string& s);

		const bool contains(const Gtid_Interval& other);
		const bool contains(gtid_t gtid);
		const std::string to_string(void);
		const bool append(const Gtid_Interval& other);
		const bool merge(const Gtid_Interval& other);

		const int cmp(const Gtid_Interval& other);
		const bool operator<(const Gtid_Interval& other);
		const bool operator==(const Gtid_Interval& other);
		const bool operator!=(const Gtid_Interval& other);
};
typedef Gtid_Interval gtid_interval_t;

// Encapsulates a map of UUID -> GTID intervals.
class Gtid_Set {
	public:
		std::unordered_map<std::string, std::list<gtid_interval_t>> map;

	public:
		Gtid_Set();

		Gtid_Set copy();
		void clear();

		bool add(const std::string& uuid, const gtid_interval_t& iv);
		bool add(const std::string& uuid, const gtid_t& gtid);
		bool add(const std::string& uuid, const gtid_t& start, const gtid_t& end);
		bool add(const std::string& uuid, const char *s);
		bool add(const std::string& uuid, const std::string &s);

		const bool has_gtid(const std::string& uuid, const gtid_t gtid);
		const std::string to_string(void);
};
typedef Gtid_Set gtid_set_t;

#endif /* PROXYSQL_GTID */