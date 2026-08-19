#include "tap.h"
#include "ProxySQL_Cluster.hpp"
#include "ProxySQL_ServerModuleCluster.h"
#include "sqlite3db.h"

#include <memory>
#include <string>
#include <vector>

namespace {

std::unique_ptr<SQLite3_result> query(SQLite3DB& db, const std::string& sql) {
	char* error = nullptr;
	int columns = 0;
	int affected = 0;
	SQLite3_result* rows = nullptr;
	db.execute_statement(sql.c_str(), &error, &columns, &affected, &rows);
	if (error) free(error);
	return std::unique_ptr<SQLite3_result>(rows);
}

ProxySQL_ServerModuleClusterTable table(const char* name, const char* runtime,
	const char* order_by, std::unique_ptr<SQLite3_result> rows) {
	return {name, runtime, order_by, std::move(rows)};
}

} // namespace

int main() {
	plan(42);
	SQLite3DB source;
	SQLite3DB destination;
	source.open((char*)"file:module-cluster-source?mode=memory&cache=private", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI);
	destination.open((char*)"file:module-cluster-destination?mode=memory&cache=private", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI);
	source.execute("CREATE TABLE mysql_plugin_alpha (writer INTEGER, reader INTEGER, label TEXT)");
	source.execute("CREATE TABLE mysql_plugin_zeta (writer INTEGER, reader INTEGER, label TEXT)");
	destination.execute("CREATE TABLE mysql_plugin_alpha (writer INTEGER, reader INTEGER, label TEXT)");
	destination.execute("CREATE TABLE mysql_plugin_zeta (writer INTEGER, reader INTEGER, label TEXT)");
	source.execute("INSERT INTO mysql_plugin_alpha VALUES (10,11,'alpha')");
	source.execute("INSERT INTO mysql_plugin_zeta VALUES (20,21,'zeta')");
	destination.execute("INSERT INTO mysql_plugin_alpha VALUES (99,99,'stale')");
	destination.execute("INSERT INTO mysql_plugin_zeta VALUES (99,99,'stale')");

	std::vector<ProxySQL_ServerModuleClusterTable> advertised;
	advertised.push_back(table("mysql_plugin_zeta", "runtime_mysql_plugin_zeta", "writer,reader",
		query(source, "SELECT * FROM mysql_plugin_zeta ORDER BY writer,reader")));
	advertised.push_back(table("mysql_plugin_alpha", "runtime_mysql_plugin_alpha", "writer,reader",
		query(source, "SELECT * FROM mysql_plugin_alpha ORDER BY writer,reader")));
	std::string error;
	ok(proxysql_validate_server_module_cluster_tables(ProxySQL_ServerProtocol::mysql, advertised, error),
		"valid provider-neutral metadata is accepted");
	ok(advertised[0].table_name == "mysql_plugin_alpha" && advertised[1].table_name == "mysql_plugin_zeta",
		"metadata is normalized to lexical table order");
	const uint64_t hash = proxysql_server_module_cluster_checksum(advertised);
	ok(hash != 0, "checksum includes dynamic table identities and contents");
	std::swap(advertised[0], advertised[1]);
	ok(proxysql_server_module_cluster_checksum(advertised) != hash,
		"checksum detects a non-lexical transport order");
	std::swap(advertised[0], advertised[1]);

	ok(proxysql_apply_server_module_cluster_memory(destination, advertised, error),
		"v2 MEMORY payload applies transactionally");
	auto alpha = query(destination, "SELECT * FROM mysql_plugin_alpha");
	ok(alpha && alpha->rows_count == 1 && std::string(alpha->rows[0]->fields[2]) == "alpha",
		"v2 replaces destination content");
	advertised[0].rows = query(source, "SELECT * FROM mysql_plugin_alpha LIMIT 0");
	ok(proxysql_apply_server_module_cluster_memory(destination, advertised, error),
		"empty v2 payload is accepted");
	alpha = query(destination, "SELECT * FROM mysql_plugin_alpha");
	ok(alpha && alpha->rows_count == 0, "empty v2 payload clears destination");

	auto malformed = std::move(advertised);
	malformed.push_back(table("mysql_plugin_alpha", "runtime_duplicate", "writer", nullptr));
	ok(!proxysql_validate_server_module_cluster_tables(ProxySQL_ServerProtocol::mysql, malformed, error),
		"duplicate metadata is rejected");
	std::vector<ProxySQL_ServerModuleClusterTable> pgsql;
	pgsql.push_back(table("pgsql_plugin_alpha", "runtime_pgsql_plugin_alpha", "writer", nullptr));
	ok(!proxysql_validate_server_module_cluster_tables(ProxySQL_ServerProtocol::mysql, pgsql, error),
		"protocol isolation rejects a PGSQL payload on MySQL");

	std::vector<ProxySQL_ServerModuleClusterTable> broken;
	broken.push_back(table("mysql_plugin_alpha", "runtime_mysql_plugin_alpha", "writer,reader",
		query(source, "SELECT writer,reader FROM mysql_plugin_alpha")));
	destination.execute("INSERT INTO mysql_plugin_alpha VALUES (77,77,'preserve')");
	ok(!proxysql_apply_server_module_cluster_memory(destination, broken, error),
		"malformed row shape fails the v2 transaction");
	alpha = query(destination, "SELECT label FROM mysql_plugin_alpha WHERE writer=77");
	ok(alpha && alpha->rows_count == 1, "failed v2 apply rolls back destination state");
	std::vector<ProxySQL_ServerModuleClusterTable> null_snapshot;
	null_snapshot.push_back(table("mysql_plugin_alpha", "runtime_mysql_plugin_alpha",
		"writer,reader", nullptr));
	ok(!proxysql_apply_server_module_cluster_memory(destination, null_snapshot, error),
		"null runtime snapshot is a checked failure");
	alpha = query(destination, "SELECT label FROM mysql_plugin_alpha WHERE writer=77");
	ok(alpha && alpha->rows_count == 1,
		"null runtime snapshot never clears existing configuration");

	const std::string mysql_v1 = proxysql_server_module_cluster_metadata_query(
		ProxySQL_ServerProtocol::mysql, ProxySQL_ServerModuleClusterVersion::runtime_v1);
	const std::string mysql_v2 = proxysql_server_module_cluster_metadata_query(
		ProxySQL_ServerProtocol::mysql, ProxySQL_ServerModuleClusterVersion::memory_v2);
	const std::string pgsql_v2 = proxysql_server_module_cluster_metadata_query(
		ProxySQL_ServerProtocol::pgsql, ProxySQL_ServerModuleClusterVersion::memory_v2);
	ok(mysql_v1 != mysql_v2 && mysql_v2 != pgsql_v2,
		"v1/v2 and MySQL/PGSQL endpoint identities are isolated");
	std::unique_ptr<SQLite3_result> endpoint_rows;
	error.clear();
	bool all_empty_endpoints_supported = true;
	for (const auto protocol : {ProxySQL_ServerProtocol::mysql, ProxySQL_ServerProtocol::pgsql}) {
		for (const auto version : {ProxySQL_ServerModuleClusterVersion::runtime_v1,
			ProxySQL_ServerModuleClusterVersion::memory_v2}) {
			all_empty_endpoints_supported = all_empty_endpoints_supported &&
				proxysql_server_module_cluster_endpoint(
					proxysql_server_module_cluster_metadata_query(protocol, version), source,
					endpoint_rows, error) == ProxySQL_ServerModuleClusterEndpointResult::handled &&
				endpoint_rows && endpoint_rows->columns == 6 && endpoint_rows->rows_count == 1 &&
				endpoint_rows->rows[0]->fields[3] == nullptr;
		}
	}
	ok(all_empty_endpoints_supported,
		"new MySQL/PGSQL v1/v2 endpoints advertise supported-empty capability/checksum");
	ok(proxysql_server_module_cluster_endpoint("PROXY_SELECT legacy_only", source, endpoint_rows, error) ==
		ProxySQL_ServerModuleClusterEndpointResult::unsupported,
		"unsupported old-peer query remains an explicit legacy fallback");

	destination.execute("CREATE TABLE pgsql_plugin_policy (writer INTEGER, label TEXT)");
	destination.execute("INSERT INTO pgsql_plugin_policy VALUES (9,'stale')");
	std::vector<ProxySQL_ServerModuleClusterTable> pg_payload;
	pg_payload.push_back(table("pgsql_plugin_policy", "runtime_pgsql_plugin_policy", "writer",
		query(source, "SELECT 3 AS writer, 'pg' AS label")));
	ok(proxysql_validate_server_module_cluster_tables(ProxySQL_ServerProtocol::pgsql, pg_payload, error) &&
		proxysql_apply_server_module_cluster_memory(destination, pg_payload, error),
		"PGSQL v2 uses the same provider-neutral transport and apply path");
	auto pg_rows = query(destination, "SELECT writer,label FROM pgsql_plugin_policy");
	ok(pg_rows && pg_rows->rows_count == 1 && std::string(pg_rows->rows[0]->fields[1]) == "pg",
		"PGSQL v2 replaces configured MEMORY content");

	auto core = query(source,
		"SELECT 1 AS hostgroup_id,'db' AS hostname,3306 AS port,0 AS gtid_port,'ONLINE' AS status,1 AS weight,0 AS compression,100 AS max_connections,0 AS max_replication_lag,1 AS use_ssl,10 AS max_latency_ms,'core' AS comment");
	ok(core && proxysql_prepare_server_module_cluster_runtime(ProxySQL_ServerProtocol::mysql, 7,
		*core, std::vector<ProxySQL_ServerModuleClusterTable>{}, error),
		"v1 runtime preparation accepts the transported core snapshot without storing a projection");

	std::vector<ProxySQL_ServerModuleTable> local_registry {
		{ProxySQL_ServerProtocol::mysql, "mysql_plugin_alpha", "runtime_mysql_plugin_alpha", "writer,reader"},
		{ProxySQL_ServerProtocol::mysql, "mysql_plugin_zeta", "runtime_mysql_plugin_zeta", "writer,reader"},
	};
	std::vector<ProxySQL_ServerModuleTable> peer_registry = local_registry;
	ok(proxysql_server_module_cluster_registry_matches(ProxySQL_ServerProtocol::mysql,
		local_registry, peer_registry, error), "matching new-peer registries negotiate dynamic sync");
	peer_registry.pop_back();
	ok(!proxysql_server_module_cluster_registry_matches(ProxySQL_ServerProtocol::mysql,
		local_registry, peer_registry, error), "missing peer metadata rejects dynamic sync");
	peer_registry = local_registry;
	peer_registry[0].order_by = "reader,writer";
	ok(!proxysql_server_module_cluster_registry_matches(ProxySQL_ServerProtocol::mysql,
		local_registry, peer_registry, error), "order metadata mismatch rejects dynamic sync");
	peer_registry = local_registry;
	std::swap(peer_registry[0], peer_registry[1]);
	ok(!proxysql_server_module_cluster_registry_matches(ProxySQL_ServerProtocol::mysql,
		local_registry, peer_registry, error), "non-lexical peer metadata order rejects dynamic sync");
	ok(!proxysql_server_module_cluster_registry_matches(ProxySQL_ServerProtocol::mysql,
		{}, local_registry, error), "missing local registry cannot silently discard peer tables");
	ok(proxysql_server_module_cluster_registry_matches(ProxySQL_ServerProtocol::mysql,
		{}, {}, error), "supported-empty peers with empty local registry continue ordinary sync");

	const uint64_t legacy_core_checksum = core->raw_checksum();
	const uint64_t separate_module_checksum = proxysql_server_module_cluster_checksum(pg_payload);
	ok(legacy_core_checksum == core->raw_checksum() && separate_module_checksum != legacy_core_checksum,
		"new sender preserves the legacy field byte-for-byte for an old receiver");
	ok(!proxysql_server_module_cluster_checksum_matches(pg_payload, "0000000000000000", error),
		"new receiver rejects a separately negotiated module checksum mismatch");
	ok(proxysql_server_module_cluster_legacy_fallback_allowed(1045,
		"ProxySQL Admin Error: near \"PROXY_SELECT\": syntax error") &&
		!proxysql_server_module_cluster_legacy_fallback_allowed(1045, "Access denied"),
		"new receiver falls back to legacy core sync only for an old sender's exact endpoint syntax error");
	for (const auto protocol : {ProxySQL_ServerProtocol::mysql, ProxySQL_ServerProtocol::pgsql}) {
		for (const auto version : {ProxySQL_ServerModuleClusterVersion::runtime_v1,
			ProxySQL_ServerModuleClusterVersion::memory_v2}) {
			const uint64_t legacy_global_checksum = 42;
			const std::string legacy_server_checksum = "legacy-unchanged";
			ok(proxysql_cluster_monitor_should_query_checksums(false) &&
				proxysql_server_module_cluster_poll_should_schedule(protocol, version, true,
					"peer-module", true, "local-module", 2, 2) &&
				legacy_global_checksum == 42 && legacy_server_checksum == "legacy-unchanged",
				"actual light-check gate schedules a module-only protocol/version pull without legacy mutation");
		}
	}
	ok(proxysql_server_module_cluster_poll_next_diff(true, "peer-module", true,
		"local-module", false, 1) == 2,
		"null-result cycles advance a supported module mismatch to its threshold");
	ok(proxysql_server_module_cluster_poll_next_diff(true, "empty", true,
		"empty", false, 7) == 0,
		"unchanged supported-empty cycles reset the module diff counter");
	std::vector<std::pair<std::string, std::string>> partial_poll_snapshot {
		{"mysql-v1", "one"}, {"mysql-v2", "two"}, {"pgsql-v1", "three"}};
	std::vector<std::pair<std::string, std::string>> published_poll_snapshot {
		{"stale", "must-clear"}};
	ok(!proxysql_server_module_cluster_poll_snapshot_complete(
		partial_poll_snapshot, published_poll_snapshot) && published_poll_snapshot.empty(),
		"a failed local checksum atomically withholds the entire module side-channel snapshot");
	ok(!proxysql_server_module_cluster_poll_should_schedule(ProxySQL_ServerProtocol::mysql,
		ProxySQL_ServerModuleClusterVersion::runtime_v1, true, "empty", true, "empty", 0, 2),
		"supported-empty no-change does not schedule a pull");
	ok(!proxysql_server_module_cluster_poll_should_schedule(ProxySQL_ServerProtocol::pgsql,
		ProxySQL_ServerModuleClusterVersion::memory_v2, false, "", true, "empty", 99, 2),
		"unsupported old-peer side channel preserves legacy scheduling");
	ok(proxysql_server_module_cluster_poll_name(ProxySQL_ServerProtocol::mysql,
		ProxySQL_ServerModuleClusterVersion::runtime_v1) !=
		proxysql_server_module_cluster_poll_name(ProxySQL_ServerProtocol::mysql,
			ProxySQL_ServerModuleClusterVersion::memory_v2) &&
		proxysql_server_module_cluster_poll_name(ProxySQL_ServerProtocol::mysql,
			ProxySQL_ServerModuleClusterVersion::memory_v2) !=
		proxysql_server_module_cluster_poll_name(ProxySQL_ServerProtocol::pgsql,
			ProxySQL_ServerModuleClusterVersion::memory_v2),
		"periodic capability identities isolate protocol and transport version");

	std::vector<ProxySQL_ServerModuleTable> mysql_disk_registry {local_registry[0]};
	std::vector<ProxySQL_ServerModuleTable> pgsql_disk_registry {
		{ProxySQL_ServerProtocol::pgsql, "pgsql_plugin_policy", "runtime_pgsql_plugin_policy", "writer"}
	};
	ok(proxysql_verify_server_module_tables(destination, ProxySQL_ServerProtocol::mysql,
		mysql_disk_registry, error), "post-materialization disk verification preserves MySQL affiliated tables");
	ok(proxysql_verify_server_module_tables(destination, ProxySQL_ServerProtocol::pgsql,
		pgsql_disk_registry, error), "post-materialization disk verification preserves PGSQL affiliated tables");
	mysql_disk_registry[0].table_name = "mysql_plugin_missing";
	ok(!proxysql_verify_server_module_tables(destination, ProxySQL_ServerProtocol::mysql,
		mysql_disk_registry, error), "missing affiliated disk schema propagates upgrade failure");
	return exit_status();
}
