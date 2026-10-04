#ifndef PGSQL_LSN_ROUTING_H
#define PGSQL_LSN_ROUTING_H
#ifdef PROXYSQL31
#include "PgSQL_LSN_Manager.h"
#include <cstdint>
#include <vector>

class SQLite3_result;

// Rule relationships expand physical monitor membership outside the query path.
struct PgSQL_LSN_Interest {
	uint32_t source_hostgroup = 0;
	std::vector<uint32_t> destination_hostgroups;
	bool any_destination = false;
};
std::vector<PgSQL_LSN_Interest> collect_pgsql_lsn_interests(
	const SQLite3_result& rules, const SQLite3_result& fast_routes);
#endif // PROXYSQL31
#endif
