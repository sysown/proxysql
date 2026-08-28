#include "mysqlx_stats.h"

#include "sqlite3db.h"

#include <algorithm>
#include <cinttypes>
#include <cstring>
#include <string>

namespace {

// Escape single quotes for safe SQLite string interpolation.
std::string sqlite_escape(const std::string& input) {
	std::string result;
	result.reserve(input.size());
	for (char c : input) {
		if (c == '\'') {
			result += "''";
		} else {
			result += c;
		}
	}
	return result;
}

} // namespace

MysqlxStatsStore& mysqlx_stats() {
	static MysqlxStatsStore store {};
	return store;
}

MysqlxRouteStats& MysqlxStatsStore::get_or_create(const std::string& route_name, int destination_hostgroup) {
	auto it = route_stats_.find(route_name);
	if (it == route_stats_.end()) {
		auto [inserted, _] = route_stats_.try_emplace(route_name);
		inserted->second.name = route_name;
		inserted->second.destination_hostgroup = destination_hostgroup;
		return inserted->second;
	}
	// Refresh the metadata so a route whose destination_hostgroup was
	// rebound (e.g. via LOAD MYSQLX ROUTES TO RUNTIME pointing the same
	// route at a different hostgroup) reports the current target, not
	// the hostgroup we first saw at the route's first traffic event.
	// Counters are NOT reset — only metadata is refreshed.
	it->second.destination_hostgroup = destination_hostgroup;
	return it->second;
}

void MysqlxStatsStore::record_conn_ok(const std::string& route_name, int destination_hostgroup) {
	std::lock_guard<std::mutex> lock(mutex_);
	get_or_create(route_name, destination_hostgroup).conn_ok.fetch_add(1, std::memory_order_relaxed);
}

void MysqlxStatsStore::record_conn_err(const std::string& route_name, int destination_hostgroup) {
	std::lock_guard<std::mutex> lock(mutex_);
	get_or_create(route_name, destination_hostgroup).conn_err.fetch_add(1, std::memory_order_relaxed);
	last_conn_err_ = std::make_pair(route_name, destination_hostgroup);
}

void MysqlxStatsStore::record_conn_used(const std::string& route_name, int destination_hostgroup) {
	std::lock_guard<std::mutex> lock(mutex_);
	get_or_create(route_name, destination_hostgroup).conn_used.fetch_add(1, std::memory_order_relaxed);
}

void MysqlxStatsStore::record_bytes_sent(const std::string& route_name, int destination_hostgroup, uint64_t n) {
	if (n == 0) return;
	std::lock_guard<std::mutex> lock(mutex_);
	get_or_create(route_name, destination_hostgroup).bytes_sent.fetch_add(n, std::memory_order_relaxed);
}

void MysqlxStatsStore::record_bytes_recv(const std::string& route_name, int destination_hostgroup, uint64_t n) {
	if (n == 0) return;
	std::lock_guard<std::mutex> lock(mutex_);
	get_or_create(route_name, destination_hostgroup).bytes_recv.fetch_add(n, std::memory_order_relaxed);
}

uint64_t MysqlxStatsStore::get_conn_ok(const std::string& route_name) const {
	std::lock_guard<std::mutex> lock(mutex_);
	auto it = route_stats_.find(route_name);
	if (it == route_stats_.end()) return 0;
	return it->second.conn_ok.load(std::memory_order_relaxed);
}

uint64_t MysqlxStatsStore::get_conn_err(const std::string& route_name) const {
	std::lock_guard<std::mutex> lock(mutex_);
	auto it = route_stats_.find(route_name);
	if (it == route_stats_.end()) return 0;
	return it->second.conn_err.load(std::memory_order_relaxed);
}

void MysqlxStatsStore::reset_for_test() {
	std::lock_guard<std::mutex> lock(mutex_);
	route_stats_.clear();
	last_conn_err_.reset();
}

std::optional<std::pair<std::string, int>> MysqlxStatsStore::get_last_conn_err_for_test() const {
	std::lock_guard<std::mutex> lock(mutex_);
	return last_conn_err_;
}

void MysqlxStatsStore::flush_to_sqlite(SQLite3DB& statsdb) {
	std::lock_guard<std::mutex> lock(mutex_);

	// Atomic rebuild: DELETE + INSERTs run in a single transaction so a
	// transient SQLite error during the loop rolls back to the previous
	// projection rather than leaving an empty stats_mysqlx_routes — which
	// would mislead operators into thinking no traffic flowed. Same shape
	// as mysqlx_populate_stats_processlist in mysqlx_plugin.cpp.
	if (!statsdb.execute("BEGIN")) return;
	if (!statsdb.execute("DELETE FROM stats_mysqlx_routes")) {
		statsdb.execute("ROLLBACK");
		return;
	}

	for (const auto& [name, stats] : route_stats_) {
		// Build with std::string so a long, escaped route name can never silently
		// truncate the SQL (the previous fixed 1024-byte snprintf buffer dropped
		// the row entirely on overflow).
		std::string sql = "INSERT INTO stats_mysqlx_routes "
			"(name, destination_hostgroup, ConnOK, ConnERR, ConnUsed, "
			"Bytes_data_sent, Bytes_data_recv) VALUES ('";
		sql += sqlite_escape(name);
		sql += "', ";
		sql += std::to_string(stats.destination_hostgroup);
		sql += ", ";
		sql += std::to_string(stats.conn_ok.load(std::memory_order_relaxed));
		sql += ", ";
		sql += std::to_string(stats.conn_err.load(std::memory_order_relaxed));
		sql += ", ";
		sql += std::to_string(stats.conn_used.load(std::memory_order_relaxed));
		sql += ", ";
		sql += std::to_string(stats.bytes_sent.load(std::memory_order_relaxed));
		sql += ", ";
		sql += std::to_string(stats.bytes_recv.load(std::memory_order_relaxed));
		sql += ")";
		if (!statsdb.execute(sql.c_str())) {
			statsdb.execute("ROLLBACK");
			return;
		}
	}
	statsdb.execute("COMMIT");
}
