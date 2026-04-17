#include "mysqlx_stats.h"

#include "sqlite3db.h"

#include <algorithm>
#include <cinttypes>
#include <cstring>

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

	statsdb.execute("DELETE FROM stats_mysqlx_routes");

	for (const auto& [name, stats] : route_stats_) {
		std::string escaped_name = sqlite_escape(name);
		char sql[1024];
		snprintf(sql, sizeof(sql),
			"INSERT INTO stats_mysqlx_routes "
			"(name, destination_hostgroup, ConnOK, ConnERR, ConnUsed, "
			"Bytes_data_sent, Bytes_data_recv) "
			"VALUES ('%s', %d, %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ")",
			escaped_name.c_str(),
			stats.destination_hostgroup,
			stats.conn_ok.load(std::memory_order_relaxed),
			stats.conn_err.load(std::memory_order_relaxed),
			stats.conn_used.load(std::memory_order_relaxed),
			stats.bytes_sent.load(std::memory_order_relaxed),
			stats.bytes_recv.load(std::memory_order_relaxed)
		);
		statsdb.execute(sql);
	}
}
