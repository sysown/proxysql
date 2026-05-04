#ifndef PROXYSQL_MYSQLX_STATS_H
#define PROXYSQL_MYSQLX_STATS_H

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

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
	void record_conn_ok(const std::string& route_name, int destination_hostgroup);
	void record_conn_err(const std::string& route_name, int destination_hostgroup);
	void record_conn_used(const std::string& route_name, int destination_hostgroup);

	// Accumulate per-route data-plane payload bytes. The argument is the
	// X-Protocol *payload* size (excluding the 5-byte frame header) that
	// the proxy forwarded between client and backend; framing overhead is
	// intentionally not counted so the counter tracks operator-meaningful
	// query/result bytes rather than the wire-level total. Both directions
	// get their own counter so operators can spot asymmetric traffic.
	void record_bytes_sent(const std::string& route_name, int destination_hostgroup, uint64_t n);
	void record_bytes_recv(const std::string& route_name, int destination_hostgroup, uint64_t n);

	// Flush stats into the stats SQLite DB.
	void flush_to_sqlite(class SQLite3DB& statsdb);

	// Get a snapshot for testing.
	uint64_t get_conn_ok(const std::string& route_name) const;
	uint64_t get_conn_err(const std::string& route_name) const;

	// Test-only hooks. reset_for_test() clears all accumulated stats and the
	// last-error-recorded sentinel; get_last_conn_err_for_test() returns the
	// (route_name, destination_hostgroup) tuple passed to the most recent
	// record_conn_err() call since the last reset. These exist purely so unit
	// tests can assert that resolve_backend_target() records the right tuple
	// for each failure mode without having to plumb in a full stats SQLite
	// database. Not called by production code.
	void reset_for_test();
	std::optional<std::pair<std::string, int>> get_last_conn_err_for_test() const;

private:
	mutable std::mutex mutex_ {};
	std::unordered_map<std::string, MysqlxRouteStats> route_stats_ {};
	std::optional<std::pair<std::string, int>> last_conn_err_ {};

	MysqlxRouteStats& get_or_create(const std::string& route_name, int destination_hostgroup);
};

// Global stats store (owned by plugin context).
MysqlxStatsStore& mysqlx_stats();

#endif /* PROXYSQL_MYSQLX_STATS_H */
