#ifndef PROXYSQL_GTID
#define PROXYSQL_GTID
// highly inspired by libslave
// https://github.com/vozbu/libslave/
#include <unordered_map>
#include <list>
#include <utility>

typedef std::pair<std::string, int64_t> gtid_t;
typedef std::pair<int64_t, int64_t> gtid_interval_t;
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
