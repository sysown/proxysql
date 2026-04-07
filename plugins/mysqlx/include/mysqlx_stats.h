#ifndef PROXYSQL_MYSQLX_STATS_H
#define PROXYSQL_MYSQLX_STATS_H

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

struct MysqlxRouteStats {
	std::string name {};
	int destination_hostgroup { 0 };
	std::atomic<uint64_t> conn_ok { 0 };
	std::atomic<uint64_t> conn_err { 0 };
	std::atomic<uint64_t> conn_used { 0 };
	std::atomic<uint64_t> bytes_sent { 0 };
	std::atomic<uint64_t> bytes_recv { 0 };
};

class MysqlxStatsStore {
public:
	MysqlxStatsStore() = default;

	// Increment connection counters for a route.
	void record_conn_ok(const std::string& route_name);
	void record_conn_err(const std::string& route_name);

	// Flush stats into the stats SQLite DB.
	void flush_to_sqlite(class SQLite3DB& statsdb);

	// Get a snapshot for testing.
	uint64_t get_conn_ok(const std::string& route_name) const;
	uint64_t get_conn_err(const std::string& route_name) const;

private:
	mutable std::mutex mutex_ {};
	std::unordered_map<std::string, MysqlxRouteStats> route_stats_ {};

	MysqlxRouteStats& get_or_create(const std::string& route_name);
};

// Global stats store (owned by plugin context).
MysqlxStatsStore& mysqlx_stats();

#endif /* PROXYSQL_MYSQLX_STATS_H */
