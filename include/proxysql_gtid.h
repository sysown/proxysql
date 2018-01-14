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

class Gtid_Server_Info {
	gtid_set_t executed_gtid_set;
	char *address;
	uint16_t mysql_port;
	uint16_t gtid_port;
	bool active;
};

#endif /* PROXYSQL_GTID */
