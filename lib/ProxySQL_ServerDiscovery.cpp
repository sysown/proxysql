#include "ProxySQL_ServerDiscovery.h"
#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"

#include <atomic>
#include <set>

namespace {
std::atomic<uint64_t> mysql_generation {0};
std::atomic<uint64_t> pgsql_generation {0};
}

bool proxysql_prepare_server_runtime_install(const ProxySQL_ServerRuntimeSnapshot& snapshot) {
#ifdef PROXYSQL40
	std::vector<ProxySQL_ServerHostgroupClaim> claims;
	std::string error;
	ProxySQL_ServerModuleSnapshot module_snapshot {};
	module_snapshot.runtime = snapshot;
	return proxysql_prepare_server_runtime_install(module_snapshot, claims, error);
#else
	(void)snapshot;
	return true;
#endif
}

bool proxysql_prepare_server_runtime_install(const ProxySQL_ServerModuleSnapshot& snapshot,
	std::vector<ProxySQL_ServerHostgroupClaim>& claims, std::string& error) {
#ifdef PROXYSQL40
	if (!proxysql_prepare_active_server_module_runtime(snapshot, claims, error)) return false;
	std::set<uint32_t> claimed_hostgroups;
	for (const auto& claim : claims) {
		if (claim.writer_hostgroup == 0 || claim.reader_hostgroup == 0 ||
			claim.writer_hostgroup == claim.reader_hostgroup) {
			error = "invalid server-module writer/reader hostgroup claim";
			return false;
		}
		if (!claimed_hostgroups.insert(claim.writer_hostgroup).second ||
			!claimed_hostgroups.insert(claim.reader_hostgroup).second) {
			error = "overlapping server-module hostgroup claim";
			return false;
		}
	}
	return true;
#else
	(void)snapshot;
	(void)claims;
	(void)error;
	return true;
#endif
}

uint64_t proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol protocol) {
	std::atomic<uint64_t>& generation = protocol == ProxySQL_ServerProtocol::mysql
		? mysql_generation : pgsql_generation;
	return generation.load(std::memory_order_relaxed) + 1;
}

void proxysql_commit_server_runtime_install(ProxySQL_ServerRuntimeSnapshot snapshot) {
#ifdef PROXYSQL40
	std::atomic<uint64_t>& generation = snapshot.protocol == ProxySQL_ServerProtocol::mysql
		? mysql_generation : pgsql_generation;
	// HGM's protocol write lock serializes normal callers.  Retain the CAS so
	// direct callers cannot publish a stale candidate if that invariant changes.
	if (snapshot.generation == 0) {
		snapshot.generation = generation.fetch_add(1, std::memory_order_relaxed) + 1;
	} else {
		uint64_t expected = snapshot.generation - 1;
		if (!generation.compare_exchange_strong(expected, snapshot.generation,
			std::memory_order_relaxed, std::memory_order_relaxed)) {
			snapshot.generation = generation.fetch_add(1, std::memory_order_relaxed) + 1;
		}
	}
	proxysql_commit_active_server_module_runtime(snapshot.protocol, snapshot.generation);
	proxysql_install_active_server_runtime_snapshot(std::move(snapshot));
#else
	(void)snapshot;
#endif
}

ProxySQL_ServerRuntimeSnapshot proxysql_server_runtime_snapshot_from_rows(
	ProxySQL_ServerProtocol protocol, uint64_t generation, const SQLite3_result& rows) {
	ProxySQL_ServerRuntimeSnapshot snapshot {};
	snapshot.protocol = protocol;
	snapshot.generation = generation;
	const bool mysql = protocol == ProxySQL_ServerProtocol::mysql;
	if (rows.columns != (mysql ? 12 : 11)) return snapshot;
	for (const auto* row : rows.rows) {
		if (row == nullptr || row->fields == nullptr) continue;
		ProxySQL_ServerRow server {};
		server.hostgroup_id = static_cast<uint32_t>(strtoul(row->fields[0] ? row->fields[0] : "0", nullptr, 10));
		server.hostname = row->fields[1] ? row->fields[1] : "";
		server.port = static_cast<uint16_t>(strtoul(row->fields[2] ? row->fields[2] : "0", nullptr, 10));
		const int offset = mysql ? 1 : 0;
		server.gtid_port = mysql ? atoi(row->fields[3] ? row->fields[3] : "0") : 0;
		server.status = row->fields[3 + offset] ? row->fields[3 + offset] : "";
		server.weight = atoll(row->fields[4 + offset] ? row->fields[4 + offset] : "0");
		server.compression = atoi(row->fields[5 + offset] ? row->fields[5 + offset] : "0");
		server.max_connections = atoll(row->fields[6 + offset] ? row->fields[6 + offset] : "0");
		server.max_replication_lag = atoll(row->fields[7 + offset] ? row->fields[7 + offset] : "0");
		server.use_ssl = atoi(row->fields[8 + offset] ? row->fields[8 + offset] : "0");
		server.max_latency_ms = atoll(row->fields[9 + offset] ? row->fields[9 + offset] : "0");
		server.comment = row->fields[10 + offset] ? row->fields[10 + offset] : "";
		snapshot.servers.push_back(std::move(server));
	}
	return snapshot;
}
