#ifndef PROXYSQL_SERVER_HEALTH_H
#define PROXYSQL_SERVER_HEALTH_H
#include <set>
#include <string>
#include <tuple>
// Caller-owned keys are consulted synchronously during managed configuration commit.
using MySQL_ServerHealthPreservationKeys =
    std::set<std::tuple<unsigned int, std::string, unsigned int>>;
using PgSQL_ServerHealthPreservationKeys = MySQL_ServerHealthPreservationKeys;
#endif
