#include "ProxySQL_ServerDiscovery.h"
#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"

#include <atomic>
#include <limits>
#include <memory>
#include <mutex>
#include <set>

namespace {
std::atomic<uint64_t> mysql_generation {0};
std::atomic<uint64_t> pgsql_generation {0};
std::mutex mysql_install_mutex;
std::mutex pgsql_install_mutex;
thread_local bool install_reservation[2] {false, false};

int protocol_index(ProxySQL_ServerProtocol protocol) {
	return protocol == ProxySQL_ServerProtocol::mysql ? 0 :
		protocol == ProxySQL_ServerProtocol::pgsql ? 1 : -1;
}

std::mutex& install_mutex(ProxySQL_ServerProtocol protocol) {
	return protocol == ProxySQL_ServerProtocol::mysql ? mysql_install_mutex : pgsql_install_mutex;
}

std::atomic<uint64_t>& installed_generation(ProxySQL_ServerProtocol protocol) {
	return protocol == ProxySQL_ServerProtocol::mysql ? mysql_generation : pgsql_generation;
}

bool append_topology_rows(const SQLite3_result& rows, unsigned int fields,
	std::vector<uint32_t>& hostgroups, std::string& error) {
	if (rows.columns < fields) {
		error = "malformed built-in topology snapshot";
		return false;
	}
	for (const auto* row : rows.rows) {
		if (row == nullptr || row->fields == nullptr) {
			error = "malformed built-in topology row";
			return false;
		}
		for (unsigned int field = 0; field < fields; ++field) {
			if (row->fields[field] == nullptr) {
				error = "null built-in topology hostgroup";
				return false;
			}
			const unsigned long value = strtoul(row->fields[field], nullptr, 10);
			if (value == 0 || value > std::numeric_limits<uint32_t>::max()) {
				error = "invalid built-in topology hostgroup";
				return false;
			}
			hostgroups.push_back(static_cast<uint32_t>(value));
		}
	}
	return true;
}
}

struct ProxySQL_ServerRuntimeInstallTransaction::Impl {
	ProxySQL_ServerProtocol protocol;
	uint64_t candidate;
	int index;
	std::unique_lock<std::mutex> lock;
	bool prepared {false};
	bool reservation_owned {false};

	Impl(ProxySQL_ServerProtocol value_protocol, uint64_t value_candidate, int value_index,
		std::unique_lock<std::mutex>&& value_lock)
		: protocol(value_protocol), candidate(value_candidate), index(value_index), lock(std::move(value_lock)) {}
	~Impl() {
		if (reservation_owned) install_reservation[index] = false;
	}
};

ProxySQL_ServerRuntimeInstallTransaction::ProxySQL_ServerRuntimeInstallTransaction() noexcept = default;

ProxySQL_ServerRuntimeInstallTransaction::ProxySQL_ServerRuntimeInstallTransaction(
	ProxySQL_ServerProtocol protocol, std::string& error) {
	const int index = protocol_index(protocol);
	if (index < 0) {
		error = "invalid server runtime protocol";
		return;
	}
	if (install_reservation[index]) {
		error = "nested server runtime installation is not supported";
		return;
	}
	std::unique_lock<std::mutex> lock(install_mutex(protocol));
	const uint64_t current = installed_generation(protocol).load(std::memory_order_relaxed);
	if (current == std::numeric_limits<uint64_t>::max()) {
		error = "server runtime generation exhausted";
		return;
	}
	impl_.reset(new Impl(protocol, current + 1, index, std::move(lock)));
	install_reservation[index] = true;
	impl_->reservation_owned = true;
	error.clear();
}

ProxySQL_ServerRuntimeInstallTransaction::~ProxySQL_ServerRuntimeInstallTransaction() = default;
ProxySQL_ServerRuntimeInstallTransaction::ProxySQL_ServerRuntimeInstallTransaction(
	ProxySQL_ServerRuntimeInstallTransaction&&) noexcept = default;
ProxySQL_ServerRuntimeInstallTransaction& ProxySQL_ServerRuntimeInstallTransaction::operator=(
	ProxySQL_ServerRuntimeInstallTransaction&&) noexcept = default;

ProxySQL_ServerRuntimeInstallTransaction::operator bool() const noexcept { return impl_ != nullptr; }
uint64_t ProxySQL_ServerRuntimeInstallTransaction::generation() const noexcept {
	return impl_ == nullptr ? 0 : impl_->candidate;
}

bool ProxySQL_ServerRuntimeInstallTransaction::prepare(
	ProxySQL_ServerRuntimeSnapshot& snapshot, std::string& error) {
	ProxySQL_ServerModuleSnapshot module_snapshot {};
	module_snapshot.runtime = snapshot;
	std::vector<ProxySQL_ServerHostgroupClaim> claims;
	const bool ok = prepare(module_snapshot, claims, error);
	if (ok) snapshot = std::move(module_snapshot.runtime);
	return ok;
}

bool ProxySQL_ServerRuntimeInstallTransaction::prepare(ProxySQL_ServerModuleSnapshot& snapshot,
	std::vector<ProxySQL_ServerHostgroupClaim>& claims, std::string& error) {
#ifdef PROXYSQL40
	if (impl_ == nullptr) { error = "inactive server runtime transaction"; return false; }
	if (impl_->prepared) { error = "server runtime transaction already prepared"; return false; }
	if (snapshot.runtime.protocol != impl_->protocol) {
		error = "server runtime transaction protocol mismatch";
		abort();
		return false;
	}
	snapshot.runtime.generation = impl_->candidate;
	// Ordinary core server rows are seeds, not topology ownership claims. Only
	// active built-in topology mappings reserve hostgroups from plugins.
	std::set<uint32_t> claimed_hostgroups;
	for (uint32_t hostgroup_id : snapshot.runtime.topology_hostgroups) {
		claimed_hostgroups.insert(hostgroup_id);
	}
	if (!proxysql_prepare_active_server_module_runtime(snapshot, claims, error)) {
		abort();
		return false;
	}
	for (const auto& claim : claims) {
		if (claim.writer_hostgroup == 0 || claim.reader_hostgroup == 0 ||
			claim.writer_hostgroup == claim.reader_hostgroup) {
			error = "invalid server-module writer/reader hostgroup claim";
			abort();
			return false;
		}
		if (!claimed_hostgroups.insert(claim.writer_hostgroup).second ||
			!claimed_hostgroups.insert(claim.reader_hostgroup).second) {
			error = "overlapping server-module hostgroup claim";
			abort();
			return false;
		}
	}
	impl_->prepared = true;
	return true;
#else
	(void)snapshot;
	(void)claims;
	if (impl_ == nullptr) { error = "inactive server runtime transaction"; return false; }
	snapshot.runtime.generation = impl_->candidate;
	impl_->prepared = true;
	return true;
#endif
}

uint64_t proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol protocol) {
	std::atomic<uint64_t>& generation = protocol == ProxySQL_ServerProtocol::mysql
		? mysql_generation : pgsql_generation;
	return generation.load(std::memory_order_relaxed) + 1;
}

bool ProxySQL_ServerRuntimeInstallTransaction::commit(
	ProxySQL_ServerRuntimeSnapshot snapshot, bool commit_affiliated_module) {
	if (impl_ == nullptr || snapshot.protocol != impl_->protocol ||
		snapshot.generation != impl_->candidate || (commit_affiliated_module && !impl_->prepared))
		return false;
	uint64_t expected = impl_->candidate - 1;
	if (!installed_generation(impl_->protocol).compare_exchange_strong(expected, impl_->candidate,
		std::memory_order_relaxed, std::memory_order_relaxed)) {
		abort();
		return false;
	}
	std::unique_ptr<Impl> completed = std::move(impl_);
#ifdef PROXYSQL40
	if (commit_affiliated_module)
		proxysql_commit_and_install_active_server_runtime_snapshot(std::move(snapshot));
	else
		proxysql_install_active_server_runtime_snapshot(std::move(snapshot));
#else
	(void)snapshot;
	(void)commit_affiliated_module;
#endif
	return true;
}

void ProxySQL_ServerRuntimeInstallTransaction::abort() noexcept { impl_.reset(); }

bool proxysql_collect_active_builtin_server_topology(SQLite3DB& db,
	ProxySQL_ServerProtocol protocol, const ProxySQL_ServerBuiltinTopologyInputs& inputs,
	std::vector<uint32_t>& hostgroups, std::string& error) {
	hostgroups.clear();
	error.clear();
	auto append = [&](const SQLite3_result* supplied, const char* query, unsigned int fields) {
		std::unique_ptr<SQLite3_result> owned;
		if (supplied == nullptr) {
			char* sqlite_error = nullptr;
			int columns = 0, affected_rows = 0;
			SQLite3_result* raw_rows = nullptr;
			const bool ok = db.execute_statement(query, &sqlite_error, &columns, &affected_rows, &raw_rows);
			owned.reset(raw_rows);
			if (!ok || sqlite_error != nullptr || !owned) {
				const std::string message = sqlite_error ? sqlite_error : "topology query failed";
				if (sqlite_error) free(sqlite_error);
				if (message.find("no such table") != std::string::npos) return true;
				error = message;
				return false;
			}
			supplied = owned.get();
		}
		return append_topology_rows(*supplied, fields, hostgroups, error);
	};
	if (protocol == ProxySQL_ServerProtocol::mysql) {
		return append(inputs.mysql_replication,
			"SELECT a.writer_hostgroup,a.reader_hostgroup FROM mysql_replication_hostgroups a LEFT JOIN mysql_replication_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL ORDER BY a.writer_hostgroup", 2) &&
			append(inputs.mysql_group_replication,
			"SELECT a.writer_hostgroup,a.backup_writer_hostgroup,a.reader_hostgroup,a.offline_hostgroup FROM mysql_group_replication_hostgroups a LEFT JOIN mysql_group_replication_hostgroups b ON (a.writer_hostgroup=b.reader_hostgroup OR a.writer_hostgroup=b.backup_writer_hostgroup OR a.writer_hostgroup=b.offline_hostgroup) WHERE b.reader_hostgroup IS NULL AND b.backup_writer_hostgroup IS NULL AND b.offline_hostgroup IS NULL ORDER BY a.writer_hostgroup", 4) &&
			append(inputs.mysql_galera,
			"SELECT a.writer_hostgroup,a.backup_writer_hostgroup,a.reader_hostgroup,a.offline_hostgroup FROM mysql_galera_hostgroups a LEFT JOIN mysql_galera_hostgroups b ON (a.writer_hostgroup=b.reader_hostgroup OR a.writer_hostgroup=b.backup_writer_hostgroup OR a.writer_hostgroup=b.offline_hostgroup) WHERE b.reader_hostgroup IS NULL AND b.backup_writer_hostgroup IS NULL AND b.offline_hostgroup IS NULL ORDER BY a.writer_hostgroup", 4) &&
			append(inputs.mysql_aurora,
			"SELECT a.writer_hostgroup,a.reader_hostgroup FROM mysql_aws_aurora_hostgroups a LEFT JOIN mysql_aws_aurora_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL ORDER BY a.writer_hostgroup", 2) &&
			append(inputs.mysql_rds_blue_green,
			"SELECT a.writer_hostgroup,a.reader_hostgroup,a.green_writer_hostgroup,a.green_reader_hostgroup FROM mysql_aws_rds_bgd_hostgroups a LEFT JOIN mysql_aws_rds_bgd_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL ORDER BY a.writer_hostgroup", 4);
	}
	if (protocol == ProxySQL_ServerProtocol::pgsql)
		return append(inputs.pgsql_replication,
			"SELECT a.writer_hostgroup,a.reader_hostgroup FROM pgsql_replication_hostgroups a LEFT JOIN pgsql_replication_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL ORDER BY a.writer_hostgroup", 2);
	error = "invalid server runtime protocol";
	return false;
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
