/**
 * @file cluster_plugin_set_hash_unit-t.cpp
 * @brief Cluster peer guard: peers sync only when they load the same plugin set.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_ClusterPluginHash.h"

#include <string>
#include <vector>

namespace {

ProxySQL_ServerModuleTable table(ProxySQL_ServerProtocol protocol, const char* name,
	const char* runtime_name, const char* order_by) {
	return {protocol, name, runtime_name, order_by};
}

} // namespace

int main() {
	plan(12);
	test_init_minimal();

	const std::vector<ProxySQL_ClusterPluginIdentity> plugins {
		{"aws", 0x4000000Bu}, {"mysqlx", 0x4000000Bu}};
	const std::vector<ProxySQL_ServerModuleTable> tables {
		table(ProxySQL_ServerProtocol::mysql, "mysql_aws_topology_policy",
			"runtime_mysql_aws_topology_policy", "writer_hostgroup"),
		table(ProxySQL_ServerProtocol::pgsql, "pgsql_aws_topology_policy",
			"runtime_pgsql_aws_topology_policy", "writer_hostgroup")};

	const std::string base = proxysql_cluster_plugin_set_hash(plugins, tables);
	ok(!base.empty(), "hash is a non-empty checksum string");
	ok(proxysql_cluster_plugin_set_hash(plugins, tables) == base, "hash is deterministic");
	ok(proxysql_cluster_plugin_set_hash({plugins[1], plugins[0]}, {tables[1], tables[0]}) == base,
		"hash does not depend on load or registration order");

	ok(proxysql_cluster_plugin_set_hash({plugins[0]}, tables) != base,
		"a missing plugin changes the hash");
	ok(proxysql_cluster_plugin_set_hash({plugins[0], {"mysqlx", 0x4000000Au}}, tables) != base,
		"a different plugin ABI version changes the hash");
	ok(proxysql_cluster_plugin_set_hash(plugins, {tables[0]}) != base,
		"a missing server-module table changes the hash");
	ok(proxysql_cluster_plugin_set_hash(plugins, {tables[0], table(ProxySQL_ServerProtocol::pgsql,
		"pgsql_aws_topology_policy", "runtime_pgsql_aws_topology_policy", "reader_hostgroup")}) != base,
		"a different server-module table definition changes the hash");

	const std::string empty = proxysql_cluster_plugin_set_hash({}, {});
	ok(!empty.empty() && empty == proxysql_cluster_plugin_set_hash({}, {}) && empty != base,
		"nodes without plugins share one well-defined hash, distinct from any plugin set");

	ok(proxysql_cluster_plugin_set_compatible(base, true, base),
		"peers with the same plugin set are compatible");
	ok(!proxysql_cluster_plugin_set_compatible(base, true, empty),
		"a peer with a different plugin set is refused");
	ok(!proxysql_cluster_plugin_set_compatible(base, false, "") &&
		!proxysql_cluster_plugin_set_compatible(base, true, ""),
		"a peer that does not publish a hash, or has not computed it yet, is refused");
	ok(!proxysql_cluster_plugin_set_compatible("", true, base),
		"a node refuses peers until its own hash is computed");

	return exit_status();
}
