#ifndef PROXYSQL_GTID
#define PROXYSQL_GTID
// highly inspired by libslave
// https://github.com/vozbu/libslave/
#include <list>
#include <string>
#include <unordered_map>
#include <utility>

typedef std::pair<std::string, int64_t> gtid_t;

class Gtid_Interval {
	public:
		int64_t start;
		int64_t end;

	public:
		explicit Gtid_Interval(const int64_t gtid);
		explicit Gtid_Interval(const int64_t _start, const int64_t _end);
		explicit Gtid_Interval(const char* s);
		explicit Gtid_Interval(const std::string& s);

		const std::string to_string(void);
		const bool contains(const Gtid_Interval& other);
		const bool contains(int64_t gtid);
		const bool append(const Gtid_Interval& other);
		const bool merge(const Gtid_Interval& other);

		const int cmp(const Gtid_Interval& other);
		const bool operator<(const Gtid_Interval& other);
		const bool operator==(const Gtid_Interval& other);
};
typedef Gtid_Interval gtid_interval_t;

// TODO: make me a proper class.
typedef std::unordered_map<std::string, std::list<gtid_interval_t>> gtid_set_t;

/*
class Gtid_Server_Info {
	public:
	gtid_set_t executed_gtid_set;
	char *hostname;
	uint16_t mysql_port;
	uint16_t gtid_port;
	bool active;
	Gtid_Server_Info(char *_h, uint16_t _mp, uint16_t _gp) {
		hostname = strdup(_h);
		mysql_port = _mp;
		gtid_port = _gp;
		active = true;
	};
	~Gtid_Server_Info() {
		free(hostname);
	};
};
*/

#endif /* PROXYSQL_GTID */