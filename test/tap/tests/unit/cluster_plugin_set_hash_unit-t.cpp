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

int main() {
	plan(10);
	test_init_minimal();

	const std::vector<ProxySQL_ClusterPluginIdentity> plugins {
		{"aws", 0x4000000Bu}, {"mysqlx", 0x4000000Bu}};

	const std::string base = proxysql_cluster_plugin_set_hash(plugins);
	ok(!base.empty(), "hash is a non-empty checksum string");
	ok(proxysql_cluster_plugin_set_hash(plugins) == base, "hash is deterministic");
	ok(proxysql_cluster_plugin_set_hash({plugins[1], plugins[0]}) == base,
		"hash does not depend on load order");

	ok(proxysql_cluster_plugin_set_hash({plugins[0]}) != base,
		"a missing plugin changes the hash");
	ok(proxysql_cluster_plugin_set_hash({plugins[0], {"mysqlx", 0x4000000Au}}) != base,
		"a different plugin ABI version changes the hash");

	// The hash formerly also covered server-module tables (removed). Their
	// count is still hashed as zero so the value is the one published by
	// builds that had server modules but no module registered; pin it.
	const std::string empty = proxysql_cluster_plugin_set_hash({});
	ok(empty == "0xB7903C7C705E9675" && empty != base,
		"nodes without plugins share the same well-defined hash as before: %s", empty.c_str());

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
