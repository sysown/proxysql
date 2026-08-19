#ifndef PROXYSQL_SERVER_MODULE_CLUSTER_H
#define PROXYSQL_SERVER_MODULE_CLUSTER_H

#ifdef PROXYSQL40

#include "ProxySQL_ServerDiscovery.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class SQLite3DB;
class SQLite3_result;

enum class ProxySQL_ServerModuleClusterVersion : uint8_t {
	runtime_v1 = 1,
	memory_v2 = 2,
};

struct ProxySQL_ServerModuleClusterTable {
	std::string table_name;
	std::string runtime_table_name;
	std::string order_by;
	std::unique_ptr<SQLite3_result> rows;
};

enum class ProxySQL_ServerModuleClusterEndpointResult : uint8_t {
	unsupported,
	handled,
	error,
};

std::string proxysql_server_module_cluster_metadata_query(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerModuleClusterVersion version);
std::string proxysql_server_module_cluster_table_query(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerModuleClusterVersion version,
	const std::string& table_name);
ProxySQL_ServerModuleClusterEndpointResult proxysql_server_module_cluster_endpoint(
	const std::string& query, SQLite3DB& db, std::unique_ptr<SQLite3_result>& result,
	std::string& error);
bool proxysql_active_server_module_cluster_tables(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerModuleClusterVersion version,
	SQLite3DB& db, std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	std::string& error);

bool proxysql_validate_server_module_cluster_tables(
	ProxySQL_ServerProtocol protocol,
	std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	std::string& error);
bool proxysql_validate_server_module_table_registry(ProxySQL_ServerProtocol protocol,
	std::vector<ProxySQL_ServerModuleTable>& tables, std::string& error);
bool proxysql_server_module_cluster_registry_matches(ProxySQL_ServerProtocol protocol,
	const std::vector<ProxySQL_ServerModuleTable>& local,
	const std::vector<ProxySQL_ServerModuleTable>& peer, std::string& error);
bool proxysql_server_module_cluster_legacy_fallback_allowed(unsigned int error_code,
	const std::string& error);

uint64_t proxysql_server_module_cluster_checksum(
	const std::vector<ProxySQL_ServerModuleClusterTable>& tables);
bool proxysql_server_module_cluster_checksum_matches(
	const std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	const std::string& expected, std::string& error);
bool proxysql_apply_server_module_cluster_memory(
	SQLite3DB& db,
	const std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	std::string& error);
bool proxysql_save_active_server_module_runtime_tables(SQLite3DB& db,
	ProxySQL_ServerProtocol protocol, std::string& error);
bool proxysql_verify_server_module_tables(SQLite3DB& db, ProxySQL_ServerProtocol protocol,
	const std::vector<ProxySQL_ServerModuleTable>& tables, std::string& error);

bool proxysql_prepare_server_module_cluster_runtime(
	ProxySQL_ServerProtocol protocol, uint64_t generation,
	const SQLite3_result& core_servers,
	const std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	std::string& error);

#endif /* PROXYSQL40 */
#endif /* PROXYSQL_SERVER_MODULE_CLUSTER_H */
