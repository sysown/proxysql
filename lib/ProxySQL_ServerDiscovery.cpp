#include "ProxySQL_ServerDiscovery.h"
#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <deque>
#include <map>
#include <tuple>

#ifdef PROXYSQL40
bool proxysql_server_discovery_admin_available();
void proxysql_wake_server_discovery_admin();
bool proxysql_materialize_server_desired_set(const ProxySQL_ServerDesiredSet& desired_set);
extern "C" void proxysql_server_discovery_after_final_revalidation_for_test(
	ProxySQL_ServerProtocol) __attribute__((weak));
#endif

namespace {
std::atomic<uint64_t> mysql_generation {0};
std::atomic<uint64_t> pgsql_generation {0};
#ifdef PROXYSQL40
std::atomic<uint64_t> read_only_monitor_epochs[2] {{0}, {0}};
#endif
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

struct BuiltinTopologyTable {
	std::vector<unsigned int> nonnegative_hostgroups;
	std::vector<unsigned int> positive_hostgroups;
	std::vector<unsigned int> optional_hostgroups;
	int active_field {-1};
};

bool parse_topology_integer(const char* text, uint32_t& value) {
	if (text == nullptr || text[0] == '\0' || text[0] == '-') return false;
	errno = 0;
	char* end = nullptr;
	const unsigned long parsed = strtoul(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || parsed > std::numeric_limits<uint32_t>::max())
		return false;
	value = static_cast<uint32_t>(parsed);
	return true;
}

bool append_topology_rows(const SQLite3_result& rows, const BuiltinTopologyTable& table,
	std::vector<uint32_t>& hostgroups, std::string& error) {
	unsigned int required_columns = 0;
	for (unsigned int field : table.nonnegative_hostgroups) required_columns = std::max(required_columns, field + 1);
	for (unsigned int field : table.positive_hostgroups) required_columns = std::max(required_columns, field + 1);
	for (unsigned int field : table.optional_hostgroups) required_columns = std::max(required_columns, field + 1);
	if (table.active_field >= 0) required_columns = std::max(required_columns,
		static_cast<unsigned int>(table.active_field + 1));
	if (rows.columns < 0 || static_cast<unsigned int>(rows.columns) < required_columns) {
		error = "malformed built-in topology snapshot";
		return false;
	}
	for (const auto* row : rows.rows) {
		if (row == nullptr || row->fields == nullptr) {
			error = "malformed built-in topology row";
			return false;
		}
		if (table.active_field >= 0) {
			uint32_t active = 0;
			if (!parse_topology_integer(row->fields[table.active_field], active) || active > 1) {
				error = "invalid built-in topology active value";
				return false;
			}
			if (active == 0) continue;
		}
		for (unsigned int field : table.nonnegative_hostgroups) {
			uint32_t value = 0;
			if (!parse_topology_integer(row->fields[field], value)) {
				error = "invalid built-in topology hostgroup";
				return false;
			}
			hostgroups.push_back(value);
		}
		for (unsigned int field : table.positive_hostgroups) {
			uint32_t value = 0;
			if (!parse_topology_integer(row->fields[field], value) || value == 0) {
				error = "invalid positive built-in topology hostgroup";
				return false;
			}
			hostgroups.push_back(value);
		}
		for (unsigned int field : table.optional_hostgroups) {
			if (row->fields[field] == nullptr) continue;
			uint32_t value = 0;
			if (!parse_topology_integer(row->fields[field], value)) {
				error = "invalid optional built-in topology hostgroup";
				return false;
			}
			hostgroups.push_back(value);
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
	std::vector<ProxySQL_ServerHostgroupClaim> hostgroup_claims;

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
	impl_->hostgroup_claims = claims;
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

#ifdef PROXYSQL40
uint64_t proxysql_server_read_only_monitor_epoch(ProxySQL_ServerProtocol protocol) {
	const int index = protocol_index(protocol);
	return index < 0 ? 0 : read_only_monitor_epochs[index].load(std::memory_order_acquire);
}

static void request_server_read_only_monitor(ProxySQL_ServerProtocol protocol) {
	const int index = protocol_index(protocol);
	if (index >= 0) read_only_monitor_epochs[index].fetch_add(1, std::memory_order_release);
}
#endif

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
		proxysql_commit_and_install_active_server_runtime_snapshot(std::move(snapshot),
			std::move(completed->hostgroup_claims));
	else
		proxysql_install_active_server_runtime_snapshot(std::move(snapshot));
#else
	(void)snapshot;
	(void)commit_affiliated_module;
#endif
	return true;
}

void ProxySQL_ServerRuntimeInstallTransaction::abort() noexcept { impl_.reset(); }

static bool collect_active_builtin_server_topology(SQLite3DB* db,
	ProxySQL_ServerProtocol protocol, const ProxySQL_ServerBuiltinTopologyInputs& inputs,
	std::vector<uint32_t>& hostgroups, std::string& error) {
	hostgroups.clear();
	error.clear();
	auto append = [&](const SQLite3_result* supplied, const char* query,
		const BuiltinTopologyTable& table) {
		std::unique_ptr<SQLite3_result> owned;
		if (supplied == nullptr) {
			if (db == nullptr) {
				error = "incomplete installed built-in topology projection";
				return false;
			}
			char* sqlite_error = nullptr;
			int columns = 0, affected_rows = 0;
			SQLite3_result* raw_rows = nullptr;
			const bool ok = db->execute_statement(query, &sqlite_error, &columns, &affected_rows, &raw_rows);
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
		return append_topology_rows(*supplied, table, hostgroups, error);
	};
	const BuiltinTopologyTable replication {{0, 1}, {}, {}, -1};
	const BuiltinTopologyTable four_way_active {{0, 1, 3}, {2}, {}, 4};
	const BuiltinTopologyTable two_way_active {{0}, {1}, {}, 2};
	const BuiltinTopologyTable rds_active {{0}, {1}, {2, 3}, 4};
	if (protocol == ProxySQL_ServerProtocol::mysql) {
		return append(inputs.mysql_replication,
			"SELECT a.* FROM mysql_replication_hostgroups a LEFT JOIN mysql_replication_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL ORDER BY a.writer_hostgroup", replication) &&
			append(inputs.mysql_group_replication,
			"SELECT a.* FROM mysql_group_replication_hostgroups a LEFT JOIN mysql_group_replication_hostgroups b ON (a.writer_hostgroup=b.reader_hostgroup OR a.writer_hostgroup=b.backup_writer_hostgroup OR a.writer_hostgroup=b.offline_hostgroup) WHERE b.reader_hostgroup IS NULL AND b.backup_writer_hostgroup IS NULL AND b.offline_hostgroup IS NULL ORDER BY a.writer_hostgroup", four_way_active) &&
			append(inputs.mysql_galera,
			"SELECT a.* FROM mysql_galera_hostgroups a LEFT JOIN mysql_galera_hostgroups b ON (a.writer_hostgroup=b.reader_hostgroup OR a.writer_hostgroup=b.backup_writer_hostgroup OR a.writer_hostgroup=b.offline_hostgroup) WHERE b.reader_hostgroup IS NULL AND b.backup_writer_hostgroup IS NULL AND b.offline_hostgroup IS NULL ORDER BY a.writer_hostgroup", four_way_active) &&
			append(inputs.mysql_aurora,
			"SELECT a.* FROM mysql_aws_aurora_hostgroups a LEFT JOIN mysql_aws_aurora_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL ORDER BY a.writer_hostgroup", two_way_active) &&
			append(inputs.mysql_rds_blue_green,
			"SELECT a.* FROM mysql_aws_rds_bgd_hostgroups a LEFT JOIN mysql_aws_rds_bgd_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL ORDER BY a.writer_hostgroup", rds_active);
	}
	if (protocol == ProxySQL_ServerProtocol::pgsql)
		return append(inputs.pgsql_replication,
			"SELECT a.* FROM pgsql_replication_hostgroups a LEFT JOIN pgsql_replication_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL ORDER BY a.writer_hostgroup", replication);
	error = "invalid server runtime protocol";
	return false;
}

bool proxysql_collect_active_builtin_server_topology(SQLite3DB& db,
	ProxySQL_ServerProtocol protocol, const ProxySQL_ServerBuiltinTopologyInputs& inputs,
	std::vector<uint32_t>& hostgroups, std::string& error) {
	return collect_active_builtin_server_topology(&db, protocol, inputs, hostgroups, error);
}

bool proxysql_collect_active_builtin_server_topology(ProxySQL_ServerProtocol protocol,
	const ProxySQL_ServerBuiltinTopologyInputs& inputs,
	std::vector<uint32_t>& hostgroups, std::string& error) {
	return collect_active_builtin_server_topology(nullptr, protocol, inputs, hostgroups, error);
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

#ifdef PROXYSQL40
namespace {

using ServerKey = std::tuple<uint32_t, std::string, uint16_t>;
using EndpointKey = std::pair<std::string, uint16_t>;

bool valid_desired_server_row(ProxySQL_ServerProtocol protocol,
	const ProxySQL_ServerRow& row) {
	if (row.hostname.empty() || row.port == 0 || row.weight < 0 ||
		row.max_connections < 0 || row.max_replication_lag < 0 ||
		row.max_latency_ms < 0 || (row.compression != 0 && row.compression != 1) ||
		(row.use_ssl != 0 && row.use_ssl != 1)) return false;
	if (protocol == ProxySQL_ServerProtocol::pgsql && row.gtid_port != 0) return false;
	if (protocol == ProxySQL_ServerProtocol::mysql &&
		(row.gtid_port < 0 || row.gtid_port > std::numeric_limits<uint16_t>::max())) return false;
	return row.status == "ONLINE" || row.status == "SHUNNED" ||
		row.status == "OFFLINE_SOFT" || row.status == "OFFLINE_HARD";
}

bool server_row_less(const ProxySQL_ServerRow& lhs, const ProxySQL_ServerRow& rhs) {
	return std::tie(lhs.hostgroup_id, lhs.hostname, lhs.port) <
		std::tie(rhs.hostgroup_id, rhs.hostname, rhs.port);
}

constexpr size_t SERVER_DESIRED_SET_QUEUE_CAPACITY = 256;

struct QueuedServerDesiredSet {
	ProxySQL_ServerDesiredSet desired_set;
	std::shared_ptr<ProxySQL_ServerDesiredSetCompletion> completion;
};

struct ServerDesiredSetInbox {
	std::mutex mutex;
	std::deque<QueuedServerDesiredSet> queue;
	size_t outstanding {0};
	bool shutdown {true};
};

ServerDesiredSetInbox& server_desired_set_inbox() {
	static ServerDesiredSetInbox inbox;
	return inbox;
}

bool same_queue_key(const QueuedServerDesiredSet& queued,
	const ProxySQL_ServerDesiredSet& desired_set) {
	return queued.desired_set.protocol == desired_set.protocol &&
		queued.desired_set.delegated_hostgroups == desired_set.delegated_hostgroups;
}

void wake_admin_owner() {
	proxysql_wake_server_discovery_admin();
}

void release_accepted_server_desired_set() {
	ServerDesiredSetInbox& inbox = server_desired_set_inbox();
	std::lock_guard<std::mutex> lock(inbox.mutex);
	assert(inbox.outstanding > 0);
	--inbox.outstanding;
}

void complete_accepted_server_desired_set(
	const std::shared_ptr<ProxySQL_ServerDesiredSetCompletion>& completion,
	uint64_t generation, bool applied) {
	try {
		if (completion) completion->complete(generation, applied);
	} catch (...) {
		release_accepted_server_desired_set();
		throw;
	}
	release_accepted_server_desired_set();
}

} // namespace

bool proxysql_merge_server_desired_set(const ProxySQL_ServerRuntimeSnapshot& current,
	const ProxySQL_ServerDesiredSet& desired_set,
	std::vector<ProxySQL_ServerRow>& merged, std::string& error) {
	merged.clear();
	error.clear();
	if (current.protocol != desired_set.protocol ||
		(desired_set.protocol != ProxySQL_ServerProtocol::mysql &&
		 desired_set.protocol != ProxySQL_ServerProtocol::pgsql)) {
		error = "protocol mismatch";
		return false;
	}
	if (desired_set.persistence != ProxySQL_ServerPersistence::runtime_only &&
		desired_set.persistence != ProxySQL_ServerPersistence::memory &&
		desired_set.persistence != ProxySQL_ServerPersistence::memory_and_disk) {
		error = "invalid desired-set persistence mode";
		return false;
	}
	if (desired_set.delegated_hostgroups.empty()) {
		error = "empty delegated hostgroup set";
		return false;
	}
	std::set<uint32_t> delegated;
	for (uint32_t hostgroup : desired_set.delegated_hostgroups) {
		if (!delegated.insert(hostgroup).second) {
			error = "duplicate delegated hostgroup";
			return false;
		}
	}
	std::set<ServerKey> desired_keys;
	std::map<EndpointKey, std::vector<ProxySQL_ServerRow>> desired_by_endpoint;
	for (const auto& row : desired_set.servers) {
		if (delegated.count(row.hostgroup_id) == 0) {
			error = "desired row is outside delegated hostgroups";
			return false;
		}
		if (!valid_desired_server_row(desired_set.protocol, row)) {
			error = "malformed desired server row";
			return false;
		}
		const ServerKey key {row.hostgroup_id, row.hostname, row.port};
		if (!desired_keys.insert(key).second) {
			error = "duplicate desired server row";
			return false;
		}
		desired_by_endpoint[{row.hostname, row.port}].push_back(row);
	}

	std::map<EndpointKey, std::vector<ProxySQL_ServerRow>> current_by_endpoint;
	for (const auto& row : current.servers) {
		if (delegated.count(row.hostgroup_id) == 0) merged.push_back(row);
		else current_by_endpoint[{row.hostname, row.port}].push_back(row);
	}

	for (const auto& desired_entry : desired_by_endpoint) {
		const auto current_it = current_by_endpoint.find(desired_entry.first);
		const bool force_role = std::any_of(desired_entry.second.begin(), desired_entry.second.end(),
			[](const ProxySQL_ServerRow& row) { return row.force_topology_role; });
		if (current_it == current_by_endpoint.end() || force_role) {
			merged.insert(merged.end(), desired_entry.second.begin(), desired_entry.second.end());
			continue;
		}
		for (const auto& current_row : current_it->second) {
			const auto exact = std::find_if(desired_entry.second.begin(), desired_entry.second.end(),
				[&](const ProxySQL_ServerRow& row) {
					return row.hostgroup_id == current_row.hostgroup_id;
				});
			ProxySQL_ServerRow row = exact != desired_entry.second.end() ? *exact :
				desired_entry.second.front();
			row.hostgroup_id = current_row.hostgroup_id;
			row.hostname = current_row.hostname;
			row.port = current_row.port;
			row.status = current_row.status;
			row.topology_role_epoch = 0;
			row.force_topology_role = false;
			merged.push_back(std::move(row));
		}
	}
	std::sort(merged.begin(), merged.end(), server_row_less);
	return true;
}

ProxySQL_ServerDesiredSetPostResult proxysql_enqueue_server_desired_set(
	ProxySQL_ServerDesiredSet desired_set,
	std::shared_ptr<ProxySQL_ServerDesiredSetCompletion> completion) {
	if (!completion || !proxysql_server_discovery_admin_available())
		return ProxySQL_ServerDesiredSetPostResult::rejected;
	std::sort(desired_set.delegated_hostgroups.begin(), desired_set.delegated_hostgroups.end());
	ServerDesiredSetInbox& inbox = server_desired_set_inbox();
	std::shared_ptr<ProxySQL_ServerDesiredSetCompletion> replaced;
	uint64_t replaced_generation = 0;
	bool wake = false;
	{
		std::lock_guard<std::mutex> lock(inbox.mutex);
		if (inbox.shutdown) return ProxySQL_ServerDesiredSetPostResult::rejected;
		if (inbox.queue.size() == SERVER_DESIRED_SET_QUEUE_CAPACITY) {
			auto match = std::find_if(inbox.queue.rbegin(), inbox.queue.rend(),
				[&](const QueuedServerDesiredSet& queued) { return same_queue_key(queued, desired_set); });
			if (match == inbox.queue.rend()) return ProxySQL_ServerDesiredSetPostResult::rejected;
			replaced_generation = match->desired_set.generation;
			replaced = std::move(match->completion);
			*match = {std::move(desired_set), std::move(completion)};
			++inbox.outstanding;
		} else {
			wake = inbox.queue.empty();
			inbox.queue.push_back({std::move(desired_set), std::move(completion)});
			++inbox.outstanding;
		}
	}
	if (replaced) complete_accepted_server_desired_set(replaced, replaced_generation, false);
	if (wake) wake_admin_owner();
	return ProxySQL_ServerDesiredSetPostResult::accepted;
}

size_t proxysql_drain_server_desired_sets() {
	ServerDesiredSetInbox& inbox = server_desired_set_inbox();
	size_t drained = 0;
	for (;;) {
		QueuedServerDesiredSet queued;
		{
			std::lock_guard<std::mutex> lock(inbox.mutex);
			if (inbox.queue.empty()) break;
			queued = std::move(inbox.queue.front());
			inbox.queue.pop_front();
		}
		bool applied = false;
		if (queued.completion && queued.completion->revalidate(queued.desired_set)) {
			std::string error;
			try {
				{
					ScopedServerDiscoveryProtocolLock lock(queued.desired_set.protocol);
					if (queued.desired_set.protocol == ProxySQL_ServerProtocol::mysql &&
						queued.completion->begin_apply(queued.desired_set)) {
						if (proxysql_server_discovery_after_final_revalidation_for_test != nullptr)
							proxysql_server_discovery_after_final_revalidation_for_test(
								queued.desired_set.protocol);
						applied = proxysql_reconcile_mysql_server_desired_set(queued.desired_set, error);
						if (applied) applied = proxysql_materialize_server_desired_set(queued.desired_set);
					} else if (queued.desired_set.protocol == ProxySQL_ServerProtocol::pgsql &&
						queued.completion->begin_apply(queued.desired_set)) {
						if (proxysql_server_discovery_after_final_revalidation_for_test != nullptr)
							proxysql_server_discovery_after_final_revalidation_for_test(
								queued.desired_set.protocol);
						applied = proxysql_reconcile_pgsql_server_desired_set(queued.desired_set, error);
						if (applied) applied = proxysql_materialize_server_desired_set(queued.desired_set);
					}
				}
			} catch (const std::exception& exception) {
				applied = false;
				error = exception.what();
			} catch (...) {
				applied = false;
				error = "unknown reconciliation failure";
			}
		}
		if (applied && std::any_of(queued.desired_set.servers.begin(),
			queued.desired_set.servers.end(),
			[](const ProxySQL_ServerRow& row) { return row.force_topology_role; })) {
			request_server_read_only_monitor(queued.desired_set.protocol);
		}
		complete_accepted_server_desired_set(
			queued.completion, queued.desired_set.generation, applied);
		++drained;
	}
	return drained;
}

bool proxysql_reopen_server_desired_sets() {
	ServerDesiredSetInbox& inbox = server_desired_set_inbox();
	std::lock_guard<std::mutex> lock(inbox.mutex);
	if (!inbox.shutdown || inbox.outstanding != 0 || !inbox.queue.empty()) return false;
	inbox.shutdown = false;
	return true;
}

void proxysql_reject_queued_server_desired_sets(
	ProxySQL_ServerProtocol protocol, const void* controller_identity) {
	ServerDesiredSetInbox& inbox = server_desired_set_inbox();
	std::vector<QueuedServerDesiredSet> rejected;
	{
		std::lock_guard<std::mutex> lock(inbox.mutex);
		for (auto it = inbox.queue.begin(); it != inbox.queue.end();) {
			if (it->completion && it->completion->protocol() == protocol &&
				it->completion->controller_identity() == controller_identity) {
				rejected.push_back(std::move(*it));
				it = inbox.queue.erase(it);
			} else {
				++it;
			}
		}
	}
	for (auto& queued : rejected)
		complete_accepted_server_desired_set(
			queued.completion, queued.desired_set.generation, false);
}

void proxysql_shutdown_server_desired_sets() {
	ServerDesiredSetInbox& inbox = server_desired_set_inbox();
	std::deque<QueuedServerDesiredSet> rejected;
	{
		std::lock_guard<std::mutex> lock(inbox.mutex);
		inbox.shutdown = true;
		rejected.swap(inbox.queue);
	}
	for (auto& queued : rejected) {
		complete_accepted_server_desired_set(
			queued.completion, queued.desired_set.generation, false);
	}
}
#endif
