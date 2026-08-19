#include "ProxySQL_ServerModuleCluster.h"

#ifdef PROXYSQL40

#include "SpookyV2.h"
#include "ProxySQL_PluginManager.h"
#include "proxysql_utils.h"
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

bool valid_order_by(const std::string& value) {
	if (value.empty()) return false;
	size_t begin = 0;
	while (begin < value.size()) {
		const size_t comma = value.find(',', begin);
		const size_t end = comma == std::string::npos ? value.size() : comma;
		size_t first = begin;
		while (first < end && std::isspace(static_cast<unsigned char>(value[first]))) ++first;
		size_t last = end;
		while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) --last;
		if (!identifier(value.substr(first, last - first))) return false;
		if (comma == std::string::npos) return true;
		begin = comma + 1;
		if (begin == value.size()) return false;
	}
	return false;
}

} // namespace

bool proxysql_validate_server_module_table_registry(ProxySQL_ServerProtocol protocol,
	std::vector<ProxySQL_ServerModuleTable>& tables, std::string& error) {
	std::sort(tables.begin(), tables.end(), [](const auto& lhs, const auto& rhs) {
		return lhs.table_name < rhs.table_name;
	});
	std::set<std::string> names;
	std::set<std::string> runtime_names;
	for (const auto& table : tables) {
		if (table.protocol != protocol || !identifier(table.table_name) ||
			!identifier(table.runtime_table_name) || !protocol_name(protocol, table.table_name) ||
			!runtime_protocol_name(protocol, table.runtime_table_name) || !valid_order_by(table.order_by)) {
			error = "invalid or cross-protocol server-module table metadata";
			return false;
		}
		if (!names.insert(table.table_name).second ||
			!runtime_names.insert(table.runtime_table_name).second) {
			error = "duplicate server-module table metadata";
			return false;
		}
	}
	error.clear();
	return true;
}

bool proxysql_server_module_cluster_registry_matches(ProxySQL_ServerProtocol protocol,
	const std::vector<ProxySQL_ServerModuleTable>& local_input,
	const std::vector<ProxySQL_ServerModuleTable>& peer_input, std::string& error) {
	auto lexical = [](const auto& lhs, const auto& rhs) {
		return lhs.table_name < rhs.table_name;
	};
	if (!std::is_sorted(local_input.begin(), local_input.end(), lexical) ||
		!std::is_sorted(peer_input.begin(), peer_input.end(), lexical)) {
		error = "server-module registry is not in lexical order";
		return false;
	}
	auto local = local_input;
	auto peer = peer_input;
	if (!proxysql_validate_server_module_table_registry(protocol, local, error) ||
		!proxysql_validate_server_module_table_registry(protocol, peer, error)) return false;
	if (local.size() != peer.size()) {
		error = "server-module registry size mismatch";
		return false;
	}
	for (size_t i = 0; i < local.size(); ++i) {
		if (local[i].protocol != peer[i].protocol || local[i].table_name != peer[i].table_name ||
			local[i].runtime_table_name != peer[i].runtime_table_name || local[i].order_by != peer[i].order_by) {
			error = "server-module registry metadata mismatch";
			return false;
		}
	}
	error.clear();
	return true;
}

bool proxysql_server_module_cluster_legacy_fallback_allowed(unsigned int error_code,
	const std::string& error) {
	return error_code == 1045 && error == "ProxySQL Admin Error: near \"PROXY_SELECT\": syntax error";
}

std::string proxysql_server_module_cluster_metadata_query(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerModuleClusterVersion version) {
	return std::string("PROXY_SELECT protocol, version, module_checksum, table_name, runtime_table_name, order_by FROM runtime_proxysql_server_module_tables WHERE protocol='") +
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

std::string proxysql_server_module_cluster_poll_name(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerModuleClusterVersion version) {
	return std::string("proxysql_server_module_") +
		(protocol == ProxySQL_ServerProtocol::mysql ? "mysql_" : "pgsql_") +
		(version == ProxySQL_ServerModuleClusterVersion::runtime_v1 ? "v1" : "v2");
}

bool proxysql_server_module_cluster_poll_should_schedule(
	ProxySQL_ServerProtocol, ProxySQL_ServerModuleClusterVersion,
	bool peer_supported, const std::string& peer_checksum,
	bool local_supported, const std::string& local_checksum,
	unsigned int diff_check, unsigned int diffs_before_sync) {
	return peer_supported && local_supported && !peer_checksum.empty() &&
		peer_checksum != local_checksum && diffs_before_sync != 0 &&
		diff_check >= diffs_before_sync;
}

unsigned int proxysql_server_module_cluster_poll_next_diff(
	bool peer_supported, const std::string& peer_checksum,
	bool local_supported, const std::string& local_checksum,
	bool peer_checksum_changed, unsigned int current_diff) {
	if (!peer_supported || (local_supported && peer_checksum == local_checksum)) return 0;
	if (peer_checksum_changed || current_diff == 0) return 1;
	return current_diff + 1;
}

bool proxysql_server_module_cluster_poll_snapshot_complete(
	const std::vector<std::pair<std::string, std::string>>& computed,
	std::vector<std::pair<std::string, std::string>>& publishable) {
	publishable.clear();
	if (computed.size() != 4) return false;
	std::set<std::string> expected;
	for (const auto protocol : {ProxySQL_ServerProtocol::mysql, ProxySQL_ServerProtocol::pgsql}) {
		for (const auto version : {ProxySQL_ServerModuleClusterVersion::runtime_v1,
			ProxySQL_ServerModuleClusterVersion::memory_v2}) {
			expected.insert(proxysql_server_module_cluster_poll_name(protocol, version));
		}
	}
	for (const auto& entry : computed) {
		if (entry.second.empty() || expected.erase(entry.first) != 1) return false;
	}
	if (!expected.empty()) return false;
	publishable = computed;
	return true;
}

ProxySQL_ServerModuleClusterEndpointResult proxysql_server_module_cluster_endpoint(
	const std::string& query, SQLite3DB& db, std::unique_ptr<SQLite3_result>& result,
	std::string& error) {
	result.reset();
	for (const auto protocol : {ProxySQL_ServerProtocol::mysql, ProxySQL_ServerProtocol::pgsql}) {
		for (const auto version : {ProxySQL_ServerModuleClusterVersion::runtime_v1,
			ProxySQL_ServerModuleClusterVersion::memory_v2}) {
			if (query == proxysql_server_module_cluster_metadata_query(protocol, version)) {
				std::vector<ProxySQL_ServerModuleClusterTable> tables;
				if (!proxysql_active_server_module_cluster_tables(protocol, version, db, tables, error)) {
					return ProxySQL_ServerModuleClusterEndpointResult::error;
				}
				auto metadata = std::make_unique<SQLite3_result>(6);
				metadata->add_column_definition(SQLITE_TEXT, "protocol");
				metadata->add_column_definition(SQLITE_TEXT, "version");
				metadata->add_column_definition(SQLITE_TEXT, "module_checksum");
				metadata->add_column_definition(SQLITE_TEXT, "table_name");
				metadata->add_column_definition(SQLITE_TEXT, "runtime_table_name");
				metadata->add_column_definition(SQLITE_TEXT, "order_by");
				const char* protocol_text = protocol == ProxySQL_ServerProtocol::mysql ? "mysql" : "pgsql";
				const std::string version_text = std::to_string(static_cast<unsigned>(version));
				const std::string checksum = get_checksum_from_hash(
					proxysql_server_module_cluster_checksum(tables));
				if (tables.empty()) {
					const char* row[] = {protocol_text, version_text.c_str(), checksum.c_str(),
						nullptr, nullptr, nullptr};
					metadata->add_row(row);
				}
				for (const auto& table : tables) {
					const char* row[] = {protocol_text, version_text.c_str(), checksum.c_str(), table.table_name.c_str(),
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

bool proxysql_server_module_cluster_poll_checksum(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerModuleClusterVersion version,
	SQLite3DB& db, std::string& checksum, std::string& error) {
	std::vector<ProxySQL_ServerModuleClusterTable> tables;
	if (!proxysql_active_server_module_cluster_tables(protocol, version, db, tables, error)) {
		checksum.clear();
		return false;
	}
	checksum = get_checksum_from_hash(proxysql_server_module_cluster_checksum(tables));
	error.clear();
	return true;
}

bool proxysql_validate_server_module_cluster_tables(
	ProxySQL_ServerProtocol protocol,
	std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	std::string& error) {
	std::sort(tables.begin(), tables.end(), [](const auto& lhs, const auto& rhs) {
		return lhs.table_name < rhs.table_name;
	});
	std::vector<ProxySQL_ServerModuleTable> registry;
	for (const auto& table : tables) {
		registry.push_back({protocol, table.table_name, table.runtime_table_name, table.order_by});
	}
	return proxysql_validate_server_module_table_registry(protocol, registry, error);
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
		const uint64_t runtime_name_size = table.runtime_table_name.size();
		hash.Update(&runtime_name_size, sizeof(runtime_name_size));
		hash.Update(table.runtime_table_name.data(), table.runtime_table_name.size());
		const uint64_t order_size = table.order_by.size();
		hash.Update(&order_size, sizeof(order_size));
		hash.Update(table.order_by.data(), table.order_by.size());
		const uint64_t rows_hash = table.rows ? table.rows->raw_checksum() : 0;
		hash.Update(&rows_hash, sizeof(rows_hash));
	}
	uint64_t first = 0;
	uint64_t second = 0;
	hash.Final(&first, &second);
	return first;
}

bool proxysql_server_module_cluster_checksum_matches(
	const std::vector<ProxySQL_ServerModuleClusterTable>& tables,
	const std::string& expected, std::string& error) {
	if (get_checksum_from_hash(proxysql_server_module_cluster_checksum(tables)) != expected) {
		error = "server-module checksum mismatch";
		return false;
	}
	error.clear();
	return true;
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

bool proxysql_save_active_server_module_runtime_tables(SQLite3DB& db,
	ProxySQL_ServerProtocol protocol, std::string& error) {
	const auto registry = proxysql_active_server_module_tables(protocol);
	if (registry.empty()) {
		error.clear();
		return true;
	}
	std::vector<ProxySQL_ServerModuleClusterTable> tables;
	for (const auto& metadata : registry) {
		std::unique_ptr<SQLite3_result> rows(
			proxysql_active_server_module_runtime_table_snapshot(
				protocol, metadata.runtime_table_name.c_str()));
		if (!rows) {
			error = "runtime server-module snapshot unavailable for " + metadata.runtime_table_name;
			return false;
		}
		tables.push_back({metadata.table_name, metadata.runtime_table_name,
			metadata.order_by, std::move(rows)});
	}
	if (!proxysql_validate_server_module_cluster_tables(protocol, tables, error)) return false;
	return proxysql_apply_server_module_cluster_memory(db, tables, error);
}

bool proxysql_verify_server_module_tables(SQLite3DB& db, ProxySQL_ServerProtocol protocol,
	const std::vector<ProxySQL_ServerModuleTable>& input, std::string& error) {
	auto tables = input;
	if (!proxysql_validate_server_module_table_registry(protocol, tables, error)) return false;
	for (const auto& table : tables) {
		char* sqlite_error = nullptr;
		int columns = 0, affected = 0;
		SQLite3_result* raw_rows = nullptr;
		const std::string sql = "SELECT * FROM main." + table.table_name + " ORDER BY " + table.order_by;
		const bool ok = db.execute_statement(sql.c_str(), &sqlite_error, &columns, &affected, &raw_rows);
		std::unique_ptr<SQLite3_result> rows(raw_rows);
		if (!ok || sqlite_error != nullptr || !rows) {
			error = sqlite_error ? sqlite_error : "affiliated server-module table unavailable";
			if (sqlite_error) free(sqlite_error);
			return false;
		}
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
