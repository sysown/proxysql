#include "ProxySQL_ClusterPluginHash.h"

#include <algorithm>
#include <mutex>
#include <tuple>

#include "SpookyV2.h"
#include "proxysql_utils.h"

namespace {

std::mutex local_hash_mutex;
std::string local_hash;

// Length-prefixed fields keep "ab"+"c" distinct from "a"+"bc".
void update_string(SpookyHash& hash, const std::string& value) {
	const uint64_t size = value.size();
	hash.Update(&size, sizeof(size));
	hash.Update(value.data(), value.size());
}

void update_u64(SpookyHash& hash, uint64_t value) {
	hash.Update(&value, sizeof(value));
}

} // namespace

std::string proxysql_cluster_plugin_set_hash(
	std::vector<ProxySQL_ClusterPluginIdentity> plugins,
	std::vector<ProxySQL_ServerModuleTable> module_tables) {
	std::sort(plugins.begin(), plugins.end(),
		[](const ProxySQL_ClusterPluginIdentity& left, const ProxySQL_ClusterPluginIdentity& right) {
			return std::tie(left.name, left.abi_version) < std::tie(right.name, right.abi_version);
		});
	std::sort(module_tables.begin(), module_tables.end(),
		[](const ProxySQL_ServerModuleTable& left, const ProxySQL_ServerModuleTable& right) {
			return std::tie(left.protocol, left.table_name, left.runtime_table_name, left.order_by) <
				std::tie(right.protocol, right.table_name, right.runtime_table_name, right.order_by);
		});

	SpookyHash hash;
	hash.Init(23, 7);
	update_u64(hash, plugins.size());
	for (const auto& plugin : plugins) {
		update_string(hash, plugin.name);
		update_u64(hash, plugin.abi_version);
	}
	update_u64(hash, module_tables.size());
	for (const auto& table : module_tables) {
		update_u64(hash, static_cast<uint64_t>(table.protocol));
		update_string(hash, table.table_name);
		update_string(hash, table.runtime_table_name);
		update_string(hash, table.order_by);
	}
	uint64_t first = 0;
	uint64_t second = 0;
	hash.Final(&first, &second);
	return get_checksum_from_hash(first);
}

void proxysql_cluster_set_local_plugin_set_hash(const std::string& hash) {
	std::lock_guard<std::mutex> lock(local_hash_mutex);
	local_hash = hash;
}

std::string proxysql_cluster_local_plugin_set_hash() {
	std::lock_guard<std::mutex> lock(local_hash_mutex);
	return local_hash;
}

bool proxysql_cluster_plugin_set_compatible(const std::string& local,
	bool peer_published, const std::string& peer) {
	return !local.empty() && peer_published && !peer.empty() && peer == local;
}
