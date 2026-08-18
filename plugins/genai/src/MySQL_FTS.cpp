#ifdef PROXYSQL40

#include "MySQL_FTS.h"
#include "MySQL_Tool_Handler.h"
#include "cpp.h"
#include "proxysql.h"
#include <sstream>
#include <algorithm>
#include <cstring>
#include <unordered_set>

// JSON library
#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

MySQL_FTS::MySQL_FTS(const std::string& path)
	: db(NULL), db_path(path)
{
}

MySQL_FTS::~MySQL_FTS() {
	close();
}

int MySQL_FTS::init() {
	// Initialize database connection
	db = new SQLite3DB();
	std::string path_buf = db_path;
	int rc = db->open(&path_buf[0], SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	if (rc != SQLITE_OK) {
		proxy_error("Failed to open FTS database at %s: %d\n", db_path.c_str(), rc);
		delete db;
		db = NULL;
		return -1;
	}

	// Initialize schema
	return init_schema();
}

void MySQL_FTS::close() {
	if (db) {
		delete db;
		db = NULL;
	}
}

int MySQL_FTS::init_schema() {
	// Enable foreign keys and optimize
	db->execute("PRAGMA foreign_keys = ON");
	db->execute("PRAGMA journal_mode = WAL");
	db->execute("PRAGMA synchronous = NORMAL");

	// Create tables
	int rc = create_tables();
	if (rc) {
		proxy_error("Failed to create FTS tables\n");
		return -1;
	}

	proxy_info("MySQL FTS database initialized at %s\n", db_path.c_str());
	return 0;
}

int MySQL_FTS::create_tables() {
	// Main metadata table for indexes
	const char* create_indexes_table =
		"CREATE TABLE IF NOT EXISTS fts_indexes ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  schema_name TEXT NOT NULL,"
		"  table_name TEXT NOT NULL,"
		"  columns TEXT NOT NULL,"        // JSON array of column names
		"  primary_key TEXT NOT NULL,"
		"  where_clause TEXT,"
		"  row_count INTEGER DEFAULT 0,"
		"  indexed_at INTEGER DEFAULT (strftime('%s', 'now')),"
		"  UNIQUE(schema_name, table_name)"
		");";

	if (!db->execute(create_indexes_table)) {
		proxy_error("Failed to create fts_indexes table\n");
		return -1;
	}

	// Indexes for faster lookups
	db->execute("CREATE INDEX IF NOT EXISTS idx_fts_indexes_schema ON fts_indexes(schema_name)");
	db->execute("CREATE INDEX IF NOT EXISTS idx_fts_indexes_table ON fts_indexes(table_name)");

	return 0;
}

std::string MySQL_FTS::sanitize_name(const std::string& name) {
	const size_t MAX_NAME_LEN = 100;
	std::string sanitized;
	// Allowlist: only ASCII letters, digits, underscore
	for (char c : name) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '_') {
			sanitized.push_back(c);
		}
	}

	// Return fallback with unique suffix if empty or would be too short
	if (sanitized.empty()) {
		// Create unique suffix from hash of original name
		std::hash<std::string> hasher;
		size_t hash_value = hasher(name);
		char hash_suffix[16];
		snprintf(hash_suffix, sizeof(hash_suffix), "%08zx", hash_value & 0xFFFFFFFF);
		sanitized = "_unnamed_";
		sanitized += hash_suffix;
	}

	// Prevent leading digit (SQLite identifiers can't start with digit)
	if (sanitized[0] >= '0' && sanitized[0] <= '9') {
		sanitized.insert(sanitized.begin(), '_');
	}
	// Enforce maximum length
	if (sanitized.length() > MAX_NAME_LEN) sanitized = sanitized.substr(0, MAX_NAME_LEN);
	return sanitized;
}

std::string MySQL_FTS::escape_identifier(const std::string& identifier) {
	std::string escaped;
	escaped.reserve(identifier.length() * 2 + 2);
	escaped.push_back('`');
	for (char c : identifier) {
		escaped.push_back(c);
		if (c == '`') escaped.push_back('`');  // Double backticks
	}
	escaped.push_back('`');
	return escaped;
}

// Helper for escaping MySQL identifiers (double backticks)
static std::string escape_mysql_identifier(const std::string& id) {
	std::string escaped;
	escaped.reserve(id.length() * 2 + 2);
	escaped.push_back('`');
	for (char c : id) {
		escaped.push_back(c);
		if (c == '`') escaped.push_back('`');
	}
	escaped.push_back('`');
	return escaped;
}

std::string MySQL_FTS::escape_sql(const std::string& str) {
	std::string escaped;
	for (size_t i = 0; i < str.length(); i++) {
		if (str[i] == '\'') {
			escaped += "''";
		} else {
			escaped += str[i];
		}
	}
	return escaped;
}

std::string MySQL_FTS::get_data_table_name(const std::string& schema, const std::string& table) {
	return "fts_data_" + sanitize_name(schema) + "_" + sanitize_name(table);
}

std::string MySQL_FTS::get_fts_table_name(const std::string& schema, const std::string& table) {
	return "fts_search_" + sanitize_name(schema) + "_" + sanitize_name(table);
}

bool MySQL_FTS::index_exists(const std::string& schema, const std::string& table) {
	sqlite3_stmt* stmt = NULL;

	const char* check_sql =
		"SELECT COUNT(*) FROM fts_indexes "
		"WHERE schema_name = ?1 AND table_name = ?2";

	auto [rc, stmt_unique] = db->prepare_v2(check_sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) {
		proxy_error("Failed to prepare index check: %d\n", rc);
		return false;
	}

	(*proxy_sqlite3_bind_text)(stmt, 1, schema.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 2, table.c_str(), -1, SQLITE_TRANSIENT);

	rc = (*proxy_sqlite3_step)(stmt);
	bool exists = false;
	if (rc == SQLITE_ROW) {
		int count = (*proxy_sqlite3_column_int)(stmt, 0);
		exists = (count > 0);
	}

	return exists;
}

int MySQL_FTS::create_index_tables(const std::string& schema, const std::string& table) {
	std::string data_table = get_data_table_name(schema, table);
	std::string fts_table = get_fts_table_name(schema, table);
	std::string escaped_data = escape_identifier(data_table);
	std::string escaped_fts = escape_identifier(fts_table);

	// Create data table
	std::ostringstream create_data_sql;
	create_data_sql << "CREATE TABLE IF NOT EXISTS " << escaped_data << " ("
		"  rowid INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  schema_name TEXT NOT NULL,"
		"  table_name TEXT NOT NULL,"
		"  primary_key_value TEXT NOT NULL,"
		"  content TEXT NOT NULL,"
		"  metadata TEXT"
		");";

	if (!db->execute(create_data_sql.str().c_str())) {
		proxy_error("Failed to create data table %s\n", data_table.c_str());
		return -1;
	}

	// Create FTS5 virtual table with external content
	std::ostringstream create_fts_sql;
	create_fts_sql << "CREATE VIRTUAL TABLE IF NOT EXISTS " << escaped_fts << " USING fts5("
		"  content, metadata,"
		"  content=" << escaped_data << ","
		"  content_rowid='rowid',"
		"  tokenize='porter unicode61'"
		");";

	if (!db->execute(create_fts_sql.str().c_str())) {
		proxy_error("Failed to create FTS table %s\n", fts_table.c_str());
		return -1;
	}

	// Create triggers for automatic sync (populate the FTS table)
	std::string base_name = sanitize_name(schema) + "_" + sanitize_name(table);
	std::string escaped_base = escape_identifier(base_name);

	// Drop existing triggers if any
	db->execute(("DROP TRIGGER IF EXISTS " + escape_identifier("fts_ai_" + base_name)).c_str());
	db->execute(("DROP TRIGGER IF EXISTS " + escape_identifier("fts_ad_" + base_name)).c_str());
	db->execute(("DROP TRIGGER IF EXISTS " + escape_identifier("fts_au_" + base_name)).c_str());

	// AFTER INSERT trigger
	std::ostringstream ai_sql;
	ai_sql << "CREATE TRIGGER IF NOT EXISTS " << escape_identifier("fts_ai_" + base_name)
		<< " AFTER INSERT ON " << escaped_data << " BEGIN"
		<< "  INSERT INTO " << escaped_fts << "(rowid, content, metadata)"
		<< "  VALUES (new.rowid, new.content, new.metadata);"
		<< "END;";
	db->execute(ai_sql.str().c_str());

	// AFTER DELETE trigger
	std::ostringstream ad_sql;
	ad_sql << "CREATE TRIGGER IF NOT EXISTS " << escape_identifier("fts_ad_" + base_name)
		<< " AFTER DELETE ON " << escaped_data << " BEGIN"
		<< "  INSERT INTO " << escaped_fts << "(" << escaped_fts << ", rowid, content, metadata)"
		<< "  VALUES ('delete', old.rowid, old.content, old.metadata);"
		<< "END;";
	db->execute(ad_sql.str().c_str());

	// AFTER UPDATE trigger
	std::ostringstream au_sql;
	au_sql << "CREATE TRIGGER IF NOT EXISTS " << escape_identifier("fts_au_" + base_name)
		<< " AFTER UPDATE ON " << escaped_data << " BEGIN"
		<< "  INSERT INTO " << escaped_fts << "(" << escaped_fts << ", rowid, content, metadata)"
		<< "  VALUES ('delete', old.rowid, old.content, old.metadata);"
		<< "  INSERT INTO " << escaped_fts << "(rowid, content, metadata)"
		<< "  VALUES (new.rowid, new.content, new.metadata);"
		<< "END;";
	db->execute(au_sql.str().c_str());

	return 0;
}

std::string MySQL_FTS::index_table(
	const std::string& schema,
	const std::string& table,
	const std::string& columns,
	const std::string& primary_key,
	const std::string& where_clause,
	MySQL_Tool_Handler* mysql_handler
) {
	json result;
	result["success"] = false;

	std::string primary_key_lower = primary_key;
	std::transform(primary_key_lower.begin(), primary_key_lower.end(), primary_key_lower.begin(), ::tolower);

	// Validate parameters
	if (schema.empty() || table.empty() || columns.empty() || primary_key.empty()) {
		result["error"] = "Missing required parameters: schema, table, columns, primary_key";
		return result.dump();
	}

	if (!mysql_handler) {
		result["error"] = "MySQL handler not provided";
		return result.dump();
	}

	// Parse columns JSON
	try {
		json cols_json = json::parse(columns);
		if (!cols_json.is_array()) {
			result["error"] = "columns must be a JSON array";
			return result.dump();
		}
	} catch (const json::exception& e) {
		result["error"] = std::string("Invalid JSON in columns: ") + e.what();
		return result.dump();
	}

	// Check if index already exists
	if (index_exists(schema, table)) {
		result["error"] = "Index already exists for " + schema + "." + table + ". Use fts_reindex to update.";
		return result.dump();
	}

	// Create index tables
	if (create_index_tables(schema, table) != 0) {
		result["error"] = "Failed to create index tables";
		return result.dump();
	}

	// Parse columns and build query (ensure primary key is selected)
	std::vector<std::string> indexed_cols;
	std::vector<std::string> selected_cols;
	std::unordered_set<std::string> seen;

	try {
		json cols_json = json::parse(columns);
		if (!cols_json.is_array()) {
			result["error"] = "columns must be a JSON array";
			return result.dump();
		}
		for (const auto& col : cols_json) {
			std::string col_name = col.get<std::string>();
			std::string col_lower = col_name;
			std::transform(col_lower.begin(), col_lower.end(), col_lower.begin(), ::tolower);
			indexed_cols.push_back(col_lower);
			if (seen.insert(col_lower).second) {
				selected_cols.push_back(col_name);
			}
		}
	} catch (const json::exception& e) {
		result["error"] = std::string("Failed to parse columns: ") + e.what();
		return result.dump();
	}

	if (seen.find(primary_key_lower) == seen.end()) {
		selected_cols.push_back(primary_key);
		seen.insert(primary_key_lower);
	}

	// Build MySQL query to fetch data
	std::ostringstream mysql_query;
	mysql_query << "SELECT ";
	for (size_t i = 0; i < selected_cols.size(); i++) {
		if (i > 0) mysql_query << ", ";
		mysql_query << escape_mysql_identifier(selected_cols[i]);
	}

	mysql_query << " FROM " << escape_mysql_identifier(schema) << "." << escape_mysql_identifier(table);

	// Validate where_clause to prevent SQL injection
	if (!where_clause.empty()) {
		// Basic sanity check - reject obviously dangerous patterns
		std::string upper_where = where_clause;
		std::transform(upper_where.begin(), upper_where.end(), upper_where.begin(), ::toupper);
		if (upper_where.find("INTO OUTFILE") != std::string::npos ||
		    upper_where.find("LOAD_FILE") != std::string::npos ||
		    upper_where.find("DROP TABLE") != std::string::npos ||
		    upper_where.find("DROP DATABASE") != std::string::npos ||
		    upper_where.find("TRUNCATE") != std::string::npos ||
		    upper_where.find("DELETE FROM") != std::string::npos ||
		    upper_where.find("INSERT INTO") != std::string::npos ||
		    upper_where.find("UPDATE ") != std::string::npos) {
			result["error"] = "Dangerous pattern in where_clause - not allowed for security";
			return result.dump();
		}
		mysql_query << " WHERE " << where_clause;
	}

	proxy_info("FTS indexing: %s.%s with query: %s\n", schema.c_str(), table.c_str(), mysql_query.str().c_str());

	// Execute MySQL query
	std::string query_result = mysql_handler->execute_query(mysql_query.str());
	json query_json = json::parse(query_result);

	if (!query_json["success"].get<bool>()) {
		result["error"] = "MySQL query failed: " + query_json["error"].get<std::string>();
		return result.dump();
	}

	// Get data table name
	std::string data_table = get_data_table_name(schema, table);
	std::string escaped_data = escape_identifier(data_table);

	// Insert data in batches
	int row_count = 0;
	int batch_size = 100;

	db->wrlock();

	try {
		const json& rows = query_json["rows"];
		const json& cols_array = query_json["columns"];
		std::vector<std::string> col_names;
		for (const auto& c : cols_array) {
			std::string c_name = c.get<std::string>();
			std::transform(c_name.begin(), c_name.end(), c_name.begin(), ::tolower);
			col_names.push_back(c_name);
		}

		for (const auto& row : rows) {
			// Build content by concatenating column values
			std::ostringstream content;
			json metadata = json::object();

			for (size_t i = 0; i < col_names.size(); i++) {
				std::string col_name = col_names[i];
				if (row.contains(col_name) && !row[col_name].is_null()) {
					std::string val = row[col_name].get<std::string>();
					metadata[col_name] = val;
					if (std::find(indexed_cols.begin(), indexed_cols.end(), col_name) != indexed_cols.end()) {
						content << val << " ";
					}
				}
			}

			// Get primary key value
			std::string pk_value = "";
			if (row.contains(primary_key_lower) && !row[primary_key_lower].is_null()) {
				pk_value = row[primary_key_lower].get<std::string>();
			} else {
				pk_value = std::to_string(row_count);
			}

			// Insert into data table (triggers will sync to FTS)
			std::ostringstream insert_sql;
			insert_sql << "INSERT INTO " << escaped_data
				<< " (schema_name, table_name, primary_key_value, content, metadata) "
				<< "VALUES ('" << escape_sql(schema) << "', '"
				<< escape_sql(table) << "', '"
				<< escape_sql(pk_value) << "', '"
				<< escape_sql(content.str()) << "', '"
				<< escape_sql(metadata.dump()) << "');";

			if (!db->execute(insert_sql.str().c_str())) {
				proxy_error("Failed to insert row into FTS: %s\n", insert_sql.str().c_str());
			}

			row_count++;

			// Commit batch
			if (row_count % batch_size == 0) {
				proxy_debug(PROXY_DEBUG_GENERIC, 3, "FTS: Indexed %d rows so far\n", row_count);
			}
		}

		// Update metadata
		std::ostringstream metadata_sql;
		metadata_sql << "INSERT INTO fts_indexes "
			"(schema_name, table_name, columns, primary_key, where_clause, row_count, indexed_at) "
			"VALUES ('" << escape_sql(schema) << "', '"
			<< escape_sql(table) << "', '"
			<< escape_sql(columns) << "', '"
			<< escape_sql(primary_key) << "', '"
			<< escape_sql(where_clause) << "', "
			<< row_count << ", strftime('%s', 'now'));";

		db->execute(metadata_sql.str().c_str());

		db->wrunlock();

		result["success"] = true;
		result["schema"] = schema;
		result["table"] = table;
		result["row_count"] = row_count;
		result["indexed_at"] = (int)time(NULL);

		proxy_info("FTS index created for %s.%s: %d rows indexed\n", schema.c_str(), table.c_str(), row_count);

	} catch (const std::exception& e) {
		db->wrunlock();
		result["error"] = std::string("Exception during indexing: ") + e.what();
		proxy_error("FTS indexing exception: %s\n", e.what());
	}

	return result.dump();
}

std::string MySQL_FTS::search(
	const std::string& query,
	const std::string& schema,
	const std::string& table,
	int limit,
	int offset
) {
	json result;
	result["success"] = false;

	if (query.empty()) {
		result["error"] = "Search query cannot be empty";
		return result.dump();
	}

	// Get list of indexes to search
	std::string index_filter = "";
	if (!schema.empty() || !table.empty()) {
		index_filter = " WHERE 1=1";
		if (!schema.empty()) {
			index_filter += " AND schema_name = '" + escape_sql(schema) + "'";
		}
		if (!table.empty()) {
			index_filter += " AND table_name = '" + escape_sql(table) + "'";
		}
	}

	std::ostringstream indexes_sql;
	indexes_sql << "SELECT schema_name, table_name FROM fts_indexes" << index_filter;

	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* indexes_result = NULL;

	db->rdlock();
	indexes_result = db->execute_statement(indexes_sql.str().c_str(), &error, &cols, &affected);

	if (!indexes_result || indexes_result->rows.empty()) {
		db->rdunlock();
		if (indexes_result) delete indexes_result;
		result["success"] = true;
		result["query"] = query;
		result["total_matches"] = 0;
		result["results"] = json::array();
		return result.dump();
	}

	// Collect all results from each index
	json all_results = json::array();
	int total_matches = 0;

	for (std::vector<SQLite3_row*>::iterator it = indexes_result->rows.begin();
	     it != indexes_result->rows.end(); ++it) {
		SQLite3_row* row = *it;
		const char* idx_schema = row->fields[0];
		const char* idx_table = row->fields[1];

		if (!idx_schema || !idx_table) continue;

		std::string data_table = get_data_table_name(idx_schema, idx_table);
		std::string fts_table = get_fts_table_name(idx_schema, idx_table);
		std::string escaped_data = escape_identifier(data_table);
		std::string escaped_fts = escape_identifier(fts_table);

		// Escape query for FTS5 MATCH clause (wrap in double quotes, escape embedded quotes)
		std::string fts_literal = "\"";
		for (char c : query) {
			fts_literal.push_back(c);
			if (c == '"') fts_literal.push_back('"');  // Double quotes
		}
		fts_literal.push_back('"');

		// Search query for this index (use table name for MATCH/bm25)
		std::ostringstream search_sql;
		search_sql << "SELECT d.schema_name, d.table_name, d.primary_key_value, "
		    << "snippet(" << escaped_fts << ", 0, '<mark>', '</mark>', '...', 30) AS snippet, "
		    << "d.metadata "
		    << "FROM " << escaped_fts << " "
		    << "JOIN " << escaped_data << " d ON " << escaped_fts << ".rowid = d.rowid "
		    << "WHERE " << escaped_fts << " MATCH " << fts_literal << " "
		    << "ORDER BY bm25(" << escaped_fts << ") ASC "
		    << "LIMIT " << limit;

		SQLite3_result* idx_resultset = NULL;
		error = NULL;
		cols = 0;
		affected = 0;

		idx_resultset = db->execute_statement(search_sql.str().c_str(), &error, &cols, &affected);

		if (error) {
			proxy_error("FTS search error on %s.%s: %s\n", idx_schema, idx_table, error);
			(*proxy_sqlite3_free)(error);
		}

		if (idx_resultset) {
			for (std::vector<SQLite3_row*>::iterator row_it = idx_resultset->rows.begin();
			     row_it != idx_resultset->rows.end(); ++row_it) {
				SQLite3_row* res_row = *row_it;

				json match;
				match["schema"] = res_row->fields[0] ? res_row->fields[0] : "";
				match["table"] = res_row->fields[1] ? res_row->fields[1] : "";
				match["primary_key_value"] = res_row->fields[2] ? res_row->fields[2] : "";

				match["snippet"] = res_row->fields[3] ? res_row->fields[3] : "";

				// Parse metadata JSON
				try {
					if (res_row->fields[4]) {
						match["metadata"] = json::parse(res_row->fields[4]);
					} else {
						match["metadata"] = json::object();
					}
				} catch (const json::exception& e) {
					match["metadata"] = res_row->fields[4] ? res_row->fields[4] : "";
				}

				all_results.push_back(match);
				total_matches++;
			}
			delete idx_resultset;
		}
	}

	delete indexes_result;
	db->rdunlock();

	// Apply pagination to collected results
	int total_size = (int)all_results.size();
	int start_idx = offset;
	if (start_idx >= total_size) start_idx = total_size;
	int end_idx = start_idx + limit;
	if (end_idx > total_size) end_idx = total_size;

	json paginated_results = json::array();
	for (int i = start_idx; i < end_idx; i++) {
		paginated_results.push_back(all_results[i]);
	}

	result["success"] = true;
	result["query"] = query;
	result["total_matches"] = total_matches;
	result["results"] = paginated_results;

	return result.dump();
}

std::string MySQL_FTS::list_indexes() {
	json result;
	result["success"] = false;

	std::ostringstream sql;
	sql << "SELECT schema_name, table_name, columns, primary_key, where_clause, row_count, indexed_at "
	    << "FROM fts_indexes ORDER BY schema_name, table_name";

	db->rdlock();

	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	resultset = db->execute_statement(sql.str().c_str(), &error, &cols, &affected);

	db->rdunlock();

	if (error) {
		result["error"] = "Failed to list indexes: " + std::string(error);
		(*proxy_sqlite3_free)(error);
		return result.dump();
	}

	json indexes = json::array();

	if (resultset) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
		     it != resultset->rows.end(); ++it) {
			SQLite3_row* row = *it;

			json idx;
			idx["schema"] = row->fields[0] ? row->fields[0] : "";
			idx["table"] = row->fields[1] ? row->fields[1] : "";
			if (row->fields[2]) {
				try {
					idx["columns"] = json::parse(row->fields[2]);
				} catch (const json::exception&) {
					idx["columns"] = row->fields[2];
				}
			} else {
				idx["columns"] = json::array();
			}
			idx["primary_key"] = row->fields[3] ? row->fields[3] : "";
			idx["where_clause"] = row->fields[4] ? row->fields[4] : "";
			idx["row_count"] = row->fields[5] ? atoi(row->fields[5]) : 0;
			idx["indexed_at"] = row->fields[6] ? atoi(row->fields[6]) : 0;

			indexes.push_back(idx);
		}
		delete resultset;
	}

	result["success"] = true;
	result["indexes"] = indexes;

	return result.dump();
}

std::string MySQL_FTS::delete_index(const std::string& schema, const std::string& table) {
	json result;
	result["success"] = false;

	if (!index_exists(schema, table)) {
		result["error"] = "Index not found for " + schema + "." + table;
		return result.dump();
	}

	std::string base_name = sanitize_name(schema) + "_" + sanitize_name(table);

	db->wrlock();

	// Drop triggers
	db->execute(("DROP TRIGGER IF EXISTS " + escape_identifier("fts_ai_" + base_name)).c_str());
	db->execute(("DROP TRIGGER IF EXISTS " + escape_identifier("fts_ad_" + base_name)).c_str());
	db->execute(("DROP TRIGGER IF EXISTS " + escape_identifier("fts_au_" + base_name)).c_str());

	// Drop FTS table
	std::string fts_table = get_fts_table_name(schema, table);
	db->execute(("DROP TABLE IF EXISTS " + escape_identifier(fts_table)).c_str());

	// Drop data table
	std::string data_table = get_data_table_name(schema, table);
	db->execute(("DROP TABLE IF EXISTS " + escape_identifier(data_table)).c_str());

	// Remove metadata
	std::ostringstream metadata_sql;
	metadata_sql << "DELETE FROM fts_indexes "
		<< "WHERE schema_name = '" << escape_sql(schema) << "' "
		<< "AND table_name = '" << escape_sql(table) << "'";

	db->execute(metadata_sql.str().c_str());

	db->wrunlock();

	result["success"] = true;
	result["schema"] = schema;
	result["table"] = table;
	result["message"] = "Index deleted successfully";

	proxy_info("FTS index deleted for %s.%s\n", schema.c_str(), table.c_str());

	return result.dump();
}

std::string MySQL_FTS::reindex(
	const std::string& schema,
	const std::string& table,
	MySQL_Tool_Handler* mysql_handler
) {
	json result;
	result["success"] = false;

	if (!mysql_handler) {
		result["error"] = "MySQL handler not provided";
		return result.dump();
	}

	// Get existing index metadata
	std::ostringstream metadata_sql;
	metadata_sql << "SELECT columns, primary_key, where_clause FROM fts_indexes "
		<< "WHERE schema_name = '" << escape_sql(schema) << "' "
		<< "AND table_name = '" << escape_sql(table) << "'";

	db->rdlock();

	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	resultset = db->execute_statement(metadata_sql.str().c_str(), &error, &cols, &affected);

	db->rdunlock();

	if (error || !resultset || resultset->rows.empty()) {
		result["error"] = "Index not found for " + schema + "." + table;
		if (resultset) delete resultset;
		return result.dump();
	}

	SQLite3_row* row = resultset->rows[0];
	std::string columns = row->fields[0] ? row->fields[0] : "";
	std::string primary_key = row->fields[1] ? row->fields[1] : "";
	std::string where_clause = row->fields[2] ? row->fields[2] : "";

	delete resultset;

	// Delete existing index
	delete_index(schema, table);

	// Recreate index with stored metadata
	return index_table(schema, table, columns, primary_key, where_clause, mysql_handler);
}

std::string MySQL_FTS::rebuild_all(MySQL_Tool_Handler* mysql_handler) {
	json result;
	result["success"] = false;

	if (!mysql_handler) {
		result["error"] = "MySQL handler not provided";
		return result.dump();
	}

	// Get all indexes
	std::string list_result = list_indexes();
	json list_json = json::parse(list_result);

	if (!list_json["success"].get<bool>()) {
		result["error"] = "Failed to get index list";
		return result.dump();
	}

	const json& indexes = list_json["indexes"];
	int rebuilt_count = 0;
	json failed = json::array();

	for (const auto& idx : indexes) {
		std::string schema = idx["schema"].get<std::string>();
		std::string table = idx["table"].get<std::string>();

		proxy_info("FTS: Rebuilding index for %s.%s\n", schema.c_str(), table.c_str());

		std::string reindex_result = reindex(schema, table, mysql_handler);
		json reindex_json = json::parse(reindex_result);

		if (reindex_json["success"].get<bool>()) {
			rebuilt_count++;
		} else {
			json failed_item;
			failed_item["schema"] = schema;
			failed_item["table"] = table;
			failed_item["error"] = reindex_json.value("error", std::string("unknown error"));
			failed.push_back(failed_item);
		}
	}

	result["success"] = true;
	result["rebuilt_count"] = rebuilt_count;
	result["failed"] = failed;
	result["total_indexes"] = (int)indexes.size();

	proxy_info("FTS: Rebuild complete - %d succeeded, %d failed\n",
		rebuilt_count, (int)failed.size());

	return result.dump();
}

#endif /* PROXYSQL40 */
