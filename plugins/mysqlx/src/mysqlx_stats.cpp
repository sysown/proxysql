#include "mysqlx_stats.h"

#include "sqlite3db.h"

#include <cstring>

MysqlxStatsStore& mysqlx_stats() {
	static MysqlxStatsStore store {};
	return store;
}

MysqlxRouteStats& MysqlxStatsStore::get_or_create(const std::string& route_name) {
	auto it = route_stats_.find(route_name);
	if (it == route_stats_.end()) {
		auto [new_it, _] = route_stats_.try_emplace(route_name);
		new_it->second.name = route_name;
		return new_it->second;
	}
	return it->second;
}

void MysqlxStatsStore::record_conn_ok(const std::string& route_name) {
	std::lock_guard<std::mutex> lock(mutex_);
	get_or_create(route_name).conn_ok.fetch_add(1, std::memory_order_relaxed);
}

void MysqlxStatsStore::record_conn_err(const std::string& route_name) {
	std::lock_guard<std::mutex> lock(mutex_);
	get_or_create(route_name).conn_err.fetch_add(1, std::memory_order_relaxed);
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

void MysqlxStatsStore::flush_to_sqlite(SQLite3DB& statsdb) {
	std::lock_guard<std::mutex> lock(mutex_);

	statsdb.execute("DELETE FROM stats_mysqlx_routes");

	for (const auto& [name, stats] : route_stats_) {
		char sql[1024];
		snprintf(sql, sizeof(sql),
			"INSERT INTO stats_mysqlx_routes "
			"(name, destination_hostgroup, ConnOK, ConnERR, ConnUsed, "
			"Bytes_data_sent, Bytes_data_recv) "
			"VALUES ('%s', %d, %lu, %lu, %lu, %lu, %lu)",
			name.c_str(),
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
