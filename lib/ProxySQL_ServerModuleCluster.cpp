#include "ProxySQL_ServerModuleCluster.h"

#ifdef PROXYSQL40

#include "SpookyV2.h"
#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>

namespace {

bool identifier(const std::string& value) {
	if (value.empty() || !(std::isalpha(static_cast<unsigned char>(value[0])) || value[0] == '_')) return false;
	return std::all_of(value.begin() + 1, value.end(), [](unsigned char c) {
		return std::isalnum(c) || c == '_';
	});
}

bool protocol_name(ProxySQL_ServerProtocol protocol, const std::string& value) {
	const char* prefix = protocol == ProxySQL_ServerProtocol::mysql ? "mysql_" : "pgsql_";
	return value.compare(0, std::strlen(prefix), prefix) == 0;
}

bool runtime_protocol_name(ProxySQL_ServerProtocol protocol, const std::string& value) {
	const char* prefix = protocol == ProxySQL_ServerProtocol::mysql ? "runtime_mysql_" : "runtime_pgsql_";
	return value.compare(0, std::strlen(prefix), prefix) == 0;
}

} // namespace

std::string proxysql_server_module_cluster_metadata_query(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerModuleClusterVersion version) {
	return std::string("PROXY_SELECT protocol, version, table_name, runtime_table_name, order_by FROM runtime_proxysql_server_module_tables WHERE protocol='") +
		(protocol == ProxySQL_ServerProtocol::mysql ? "mysql" : "pgsql") + "' AND version=" +
		std::to_string(static_cast<unsigned>(version)) + " ORDER BY table_name";
}

std::string proxysql_server_module_cluster_table_query(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerModuleClusterVersion version,
	const std::string& table_name) {
	return std::string("PROXY_SELECT * FROM runtime_proxysql_server_module_table WHERE protocol='") +
		(protocol == ProxySQL_ServerProtocol::mysql ? "mysql" : "pgsql") + "' AND version=" +
		std::to_string(static_cast<unsigned>(version)) + " AND table_name='" + table_name + "'";
}

ProxySQL_ServerModuleClusterEndpointResult proxysql_server_module_cluster_endpoint(
	const std::string& query, SQLite3DB& db, std::unique_ptr<SQLite3_result>& result,
	std::string& error) {
	result.reset();
	for (const auto protocol : {ProxySQL_ServerProtocol::mysql, ProxySQL_ServerProtocol::pgsql}) {
		for (const auto version : {ProxySQL_ServerModuleClusterVersion::runtime_v1,
			ProxySQL_ServerModuleClusterVersion::memory_v2}) {
			if (query == proxysql_server_module_cluster_metadata_query(protocol, version)) {
				const auto tables = proxysql_active_server_module_tables(protocol);
				auto metadata = std::make_unique<SQLite3_result>(5);
				metadata->add_column_definition(SQLITE_TEXT, "protocol");
				metadata->add_column_definition(SQLITE_TEXT, "version");
				metadata->add_column_definition(SQLITE_TEXT, "table_name");
				metadata->add_column_definition(SQLITE_TEXT, "runtime_table_name");
				metadata->add_column_definition(SQLITE_TEXT, "order_by");
				const char* protocol_text = protocol == ProxySQL_ServerProtocol::mysql ? "mysql" : "pgsql";
				const std::string version_text = std::to_string(static_cast<unsigned>(version));
				for (const auto& table : tables) {
					const char* row[] = {protocol_text, version_text.c_str(), table.table_name.c_str(),
						table.runtime_table_name.c_str(), table.order_by.c_str()};
					metadata->add_row(row);
				}
				result = std::move(metadata);
				error.clear();
				return ProxySQL_ServerModuleClusterEndpointResult::handled;
			}
			static const std::string table_query_prefix =
				"PROXY_SELECT * FROM runtime_proxysql_server_module_table WHERE protocol=";
			if (query.compare(0, table_query_prefix.size(), table_query_prefix) != 0) continue;
			const auto tables = proxysql_active_server_module_tables(protocol);
			for (const auto& table : tables) {
				if (query != proxysql_server_module_cluster_table_query(protocol, version, table.table_name)) continue;
				if (version == ProxySQL_ServerModuleClusterVersion::runtime_v1) {
					result.reset(proxysql_active_server_module_runtime_table_snapshot(
						protocol, table.runtime_table_name.c_str()));
					if (!result) {
						error = "runtime server-module projection unavailable";
						return ProxySQL_ServerModuleClusterEndpointResult::error;
					}
				} else {
					char* sqlite_error = nullptr;
					int columns = 0;
					int affected = 0;
					SQLite3_result* rows = nullptr;
					const std::string sql = "SELECT * FROM main." + table.table_name + " ORDER BY " + table.order_by;
					db.execute_statement(sql.c_str(), &sqlite_error, &columns, &affected, &rows);
					result.reset(rows);
					if (sqlite_error) {
						error = sqlite_error;
						free(sqlite_error);
						return ProxySQL_ServerModuleClusterEndpointResult::error;
					}
				}
				error.clear();
				return ProxySQL_ServerModuleClusterEndpointResult::handled;
			}
		}
	}
	return ProxySQL_ServerModuleClusterEndpointResult::unsupported;
}

bool proxysql_active_server_module_cluster_tables(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerModuleClusterVersion version,
	SQLite3DB& db, std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	std::string& error) {
	tables.clear();
	for (const auto& metadata : proxysql_active_server_module_tables(protocol)) {
		std::unique_ptr<SQLite3_result> rows;
		if (version == ProxySQL_ServerModuleClusterVersion::runtime_v1) {
			rows.reset(proxysql_active_server_module_runtime_table_snapshot(
				protocol, metadata.runtime_table_name.c_str()));
		} else {
			char* sqlite_error = nullptr;
			int columns = 0, affected = 0;
			SQLite3_result* raw_rows = nullptr;
			const std::string sql = "SELECT * FROM main." + metadata.table_name + " ORDER BY " + metadata.order_by;
			db.execute_statement(sql.c_str(), &sqlite_error, &columns, &affected, &raw_rows);
			rows.reset(raw_rows);
			if (sqlite_error) {
				error = sqlite_error;
				free(sqlite_error);
				return false;
			}
		}
		if (!rows) {
			error = "server-module table snapshot unavailable";
			return false;
		}
		tables.push_back({metadata.table_name, metadata.runtime_table_name,
			metadata.order_by, std::move(rows)});
	}
	return proxysql_validate_server_module_cluster_tables(protocol, tables, error);
}

bool proxysql_validate_server_module_cluster_tables(
	ProxySQL_ServerProtocol protocol,
	std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	std::string& error) {
	std::sort(tables.begin(), tables.end(), [](const auto& lhs, const auto& rhs) {
		return lhs.table_name < rhs.table_name;
	});
	std::set<std::string> names;
	std::set<std::string> runtime_names;
	for (const auto& table : tables) {
		if (!identifier(table.table_name) || !identifier(table.runtime_table_name) ||
			!protocol_name(protocol, table.table_name) || !runtime_protocol_name(protocol, table.runtime_table_name)) {
			error = "invalid or cross-protocol server-module table metadata";
			return false;
		}
		if (!names.insert(table.table_name).second) {
			error = "duplicate server-module table metadata";
			return false;
		}
		if (!runtime_names.insert(table.runtime_table_name).second) {
			error = "duplicate server-module runtime table metadata";
			return false;
		}
	}
	error.clear();
	return true;
}

uint64_t proxysql_server_module_cluster_checksum(
	const std::vector<ProxySQL_ServerModuleClusterTable>& tables) {
	if (tables.empty()) return 0;
	SpookyHash hash;
	hash.Init(19, 3);
	for (const auto& table : tables) {
		const uint64_t name_size = table.table_name.size();
		hash.Update(&name_size, sizeof(name_size));
		hash.Update(table.table_name.data(), table.table_name.size());
		const uint64_t rows_hash = table.rows ? table.rows->raw_checksum() : 0;
		hash.Update(&rows_hash, sizeof(rows_hash));
	}
	uint64_t first = 0;
	uint64_t second = 0;
	hash.Final(&first, &second);
	return first;
}

void proxysql_update_server_module_cluster_checksum(SpookyHash& hash, bool& initialized,
	const std::vector<ProxySQL_ServerModuleClusterTable>& tables) {
	for (const auto& table : tables) {
		if (!initialized) {
			initialized = true;
			hash.Init(19, 3);
		}
		const uint64_t name_size = table.table_name.size();
		hash.Update(&name_size, sizeof(name_size));
		hash.Update(table.table_name.data(), table.table_name.size());
		const uint64_t rows_hash = table.rows ? table.rows->raw_checksum() : 0;
		hash.Update(&rows_hash, sizeof(rows_hash));
	}
}

uint64_t proxysql_runtime_server_module_cluster_checksum(uint64_t core_hash,
	const std::vector<ProxySQL_ServerModuleClusterTable>& tables) {
	if (tables.empty()) return core_hash;
	SpookyHash hash;
	hash.Init(19, 3);
	hash.Update(&core_hash, sizeof(core_hash));
	bool initialized = true;
	proxysql_update_server_module_cluster_checksum(hash, initialized, tables);
	uint64_t first = 0, second = 0;
	hash.Final(&first, &second);
	return first;
}

bool proxysql_apply_server_module_cluster_memory(
	SQLite3DB& db,
	const std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	std::string& error) {
	if (!db.execute("BEGIN IMMEDIATE")) {
		error = "could not begin server-module table transaction";
		return false;
	}
	auto rollback = [&]() { db.execute("ROLLBACK"); };
	for (const auto& table : tables) {
		if (!identifier(table.table_name) || !table.rows) {
			error = "invalid server-module table payload";
			rollback();
			return false;
		}
		const std::string delete_sql = "DELETE FROM main." + table.table_name;
		auto [delete_rc, delete_stmt] = db.prepare_v2(delete_sql.c_str());
		if (delete_rc != SQLITE_OK || (*proxy_sqlite3_step)(delete_stmt.get()) != SQLITE_DONE) {
			error = "could not clear server-module table " + table.table_name;
			rollback();
			return false;
		}
		if (table.rows->rows_count == 0) continue;
		std::string placeholders;
		for (int column = 0; column < table.rows->columns; ++column) {
			if (column) placeholders += ',';
			placeholders += '?' + std::to_string(column + 1);
		}
		const std::string insert_sql = "INSERT INTO main." + table.table_name + " VALUES (" + placeholders + ')';
		auto [insert_rc, insert_stmt] = db.prepare_v2(insert_sql.c_str());
		if (insert_rc != SQLITE_OK) {
			error = "server-module table schema mismatch for " + table.table_name;
			rollback();
			return false;
		}
		for (const auto* row : table.rows->rows) {
			for (int column = 0; column < table.rows->columns; ++column) {
				const int rc = row->fields[column]
					? (*proxy_sqlite3_bind_text)(insert_stmt.get(), column + 1, row->fields[column], -1, SQLITE_TRANSIENT)
					: (*proxy_sqlite3_bind_null)(insert_stmt.get(), column + 1);
				if (rc != SQLITE_OK) {
					error = "could not bind server-module row";
					rollback();
					return false;
				}
			}
			if ((*proxy_sqlite3_step)(insert_stmt.get()) != SQLITE_DONE ||
				(*proxy_sqlite3_reset)(insert_stmt.get()) != SQLITE_OK ||
				(*proxy_sqlite3_clear_bindings)(insert_stmt.get()) != SQLITE_OK) {
				error = "could not insert server-module row";
				rollback();
				return false;
			}
		}
	}
	if (!db.execute("COMMIT")) {
		error = "could not commit server-module table transaction";
		rollback();
		return false;
	}
	error.clear();
	return true;
}

bool proxysql_prepare_server_module_cluster_runtime(
	ProxySQL_ServerProtocol protocol, uint64_t generation,
	const SQLite3_result& core_servers,
	const std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	std::string& error) {
	ProxySQL_ServerModuleSnapshot snapshot;
	snapshot.runtime.protocol = protocol;
	snapshot.runtime.generation = generation;
	const int expected_columns = protocol == ProxySQL_ServerProtocol::mysql ? 12 : 11;
	if (core_servers.columns != expected_columns) {
		error = "malformed core servers result for module runtime preparation";
		return false;
	}
	for (const auto* row : core_servers.rows) {
		const int offset = protocol == ProxySQL_ServerProtocol::mysql ? 1 : 0;
		ProxySQL_ServerRow server;
		server.hostgroup_id = static_cast<uint32_t>(strtoul(row->fields[0], nullptr, 10));
		server.hostname = row->fields[1] ? row->fields[1] : "";
		server.port = static_cast<uint16_t>(strtoul(row->fields[2], nullptr, 10));
		server.gtid_port = offset ? atoi(row->fields[3]) : 0;
		server.status = row->fields[3 + offset] ? row->fields[3 + offset] : "";
		server.weight = atoll(row->fields[4 + offset]);
		server.compression = atoi(row->fields[5 + offset]);
		server.max_connections = atoll(row->fields[6 + offset]);
		server.max_replication_lag = atoll(row->fields[7 + offset]);
		server.use_ssl = atoi(row->fields[8 + offset]);
		server.max_latency_ms = atoll(row->fields[9 + offset]);
		server.comment = row->fields[10 + offset] ? row->fields[10 + offset] : "";
		snapshot.runtime.servers.push_back(std::move(server));
	}
	for (const auto& table : tables) {
		if (!table.rows) {
			error = "missing runtime server-module table payload";
			return false;
		}
		snapshot.module_tables.push_back({table.table_name,
			std::unique_ptr<SQLite3_result>(new SQLite3_result(table.rows.get()))});
	}
	std::vector<ProxySQL_ServerHostgroupClaim> claims;
	return proxysql_prepare_active_server_module_runtime(snapshot, claims, error);
}

#endif /* PROXYSQL40 */
