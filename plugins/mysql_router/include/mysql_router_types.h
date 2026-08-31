#ifndef PROXYSQL_MYSQL_ROUTER_TYPES_H
#define PROXYSQL_MYSQL_ROUTER_TYPES_H

#include <cstdint>
#include <string>

struct MysqlRouterStatus {
	std::string state {"loaded"};
	std::string last_error {};
	uint64_t topology_generation {0};
	uint64_t user_generation {0};
};

#endif
