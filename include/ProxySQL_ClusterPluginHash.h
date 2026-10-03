#ifndef __CLASS_PROXYSQL_CLUSTER_PLUGIN_HASH_H
#define __CLASS_PROXYSQL_CLUSTER_PLUGIN_HASH_H

/**
 * @file ProxySQL_ClusterPluginHash.h
 * @brief Plugin-set identity used by the ProxySQL Cluster peer guard.
 *
 * Cluster peers already refuse to sync unless they run the same ProxySQL
 * version. Nodes running the same build can still load different plugins, and
 * plugins register server-module tables that are synchronized through Cluster.
 * The plugin-set hash extends the guard: peers sync only when both version and
 * plugin-set hash match.
 *
 * The hash covers, in a canonical (sorted) order:
 * - each loaded plugin's descriptor name and ABI version;
 * - each registered server-module table (protocol, table, runtime table,
 *   order-by), which is what decides whether module-table sync is compatible.
 * It deliberately excludes host-specific data such as .so paths or file bytes,
 * so nodes running the same plugins agree regardless of install location.
 * A node without plugins hashes the empty set, so plugin-less nodes keep
 * clustering with each other.
 */

#include <cstdint>
#include <string>
#include <vector>

#include "ProxySQL_ServerDiscovery.h"

/**
 * @brief Peer identity query: version and plugin-set hash in one round trip.
 *
 * Admin matches "SELECT @@version" as a prefix, so an older peer answers this
 * query with the version column only; a missing hash column means the peer
 * does not publish one and is refused.
 */
#define PROXYSQL_CLUSTER_PEER_IDENTITY_QUERY "SELECT @@version, @@proxysql_plugin_set_hash"

struct ProxySQL_ClusterPluginIdentity {
	std::string name;
	uint32_t abi_version {0};
};

/**
 * @brief Computes the canonical plugin-set hash.
 * @return A non-empty checksum string (same format as Cluster checksums).
 *   The result does not depend on the order of either input.
 */
std::string proxysql_cluster_plugin_set_hash(
	std::vector<ProxySQL_ClusterPluginIdentity> plugins,
	std::vector<ProxySQL_ServerModuleTable> module_tables);

/** @brief Publishes this node's plugin-set hash; called once, after the plugin lifecycle. */
void proxysql_cluster_set_local_plugin_set_hash(const std::string& hash);

/** @brief This node's plugin-set hash, or an empty string before it is computed. */
std::string proxysql_cluster_local_plugin_set_hash();

/**
 * @brief Decides whether a peer's plugin set allows syncing with it.
 * @param local This node's hash; empty while not yet computed.
 * @param peer_published false when the peer did not return a hash (an older
 *   build, or a node that has not finished starting).
 * @param peer The peer's hash.
 * @return true only when both hashes are known and equal.
 */
bool proxysql_cluster_plugin_set_compatible(const std::string& local,
	bool peer_published, const std::string& peer);

#endif /* __CLASS_PROXYSQL_CLUSTER_PLUGIN_HASH_H */
