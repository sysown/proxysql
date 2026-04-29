#ifndef PROXYSQL_GTID
#define PROXYSQL_GTID
// highly inspired by libslave
// https://github.com/vozbu/libslave/
#include <list>
#include <string>
#include <unordered_map>

typedef int64_t trxid_t;

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

	public:
		GTID_Set();

		GTID_Set copy();
		void clear();

		bool add(const std::string& uuid, const TrxId_Interval& iv);
		bool add(const std::string& uuid, const trxid_t& trxid);
		bool add(const std::string& uuid, const trxid_t& start, const trxid_t& end);
		bool add(const std::string& uuid, const char *s);
		bool add(const std::string& uuid, const std::string &s);

		const bool has_gtid(const std::string& uuid, const trxid_t trxid);
		const std::string to_string(void);
};

#endif /* PROXYSQL_GTID */
