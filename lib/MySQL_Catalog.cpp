#include "MySQL_Catalog.h"
#include "cpp.h"
#include "proxysql.h"
#include <sstream>
#include <algorithm>
#include "../deps/json/json.hpp"

MySQL_Catalog::MySQL_Catalog(const std::string& path)
	: db(NULL), db_path(path)
{
}

MySQL_Catalog::~MySQL_Catalog() {
	close();
}

int MySQL_Catalog::init() {
	// Initialize database connection
	db = new SQLite3DB();
	char path_buf[db_path.size() + 1];
	strcpy(path_buf, db_path.c_str());
	int rc = db->open(path_buf, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	if (rc != SQLITE_OK) {
		proxy_error("Failed to open catalog database at %s: %d\n", db_path.c_str(), rc);
		return -1;
	}

	// Initialize schema
	return init_schema();
}

void MySQL_Catalog::close() {
	if (db) {
		delete db;
		db = NULL;
	}
}

int MySQL_Catalog::init_schema() {
	// Enable foreign keys
	db->execute("PRAGMA foreign_keys = ON");

	// Create tables
	int rc = create_tables();
	if (rc) {
		proxy_error("Failed to create catalog tables\n");
		return -1;
	}

	proxy_info("MySQL Catalog database initialized at %s\n", db_path.c_str());
	return 0;
}

int MySQL_Catalog::create_tables() {
	// Main catalog table with schema column for isolation
	const char* create_catalog_table =
		"CREATE TABLE IF NOT EXISTS catalog ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT , "
		"  schema TEXT NOT NULL , "         // schema name (e.g., "sales" ,  "production")
		"  kind TEXT NOT NULL , "           // table, view, domain, metric, note
		"  key TEXT NOT NULL , "            // e.g., "orders" ,  "customer_summary"
		"  document TEXT NOT NULL , "       // JSON content
		"  tags TEXT , "                    // comma-separated tags
		"  links TEXT , "                   // comma-separated related keys
		"  created_at INTEGER DEFAULT (strftime('%s', 'now')) , "
		"  updated_at INTEGER DEFAULT (strftime('%s', 'now')) , "
		"  UNIQUE(schema, kind ,  key)"
		");";

	if (!db->execute(create_catalog_table)) {
		proxy_error("Failed to create catalog table\n");
		return -1;
	}

	// Indexes for search
	db->execute("CREATE INDEX IF NOT EXISTS idx_catalog_schema ON catalog(schema)");
	db->execute("CREATE INDEX IF NOT EXISTS idx_catalog_kind ON catalog(kind)");
	db->execute("CREATE INDEX IF NOT EXISTS idx_catalog_tags ON catalog(tags)");
	db->execute("CREATE INDEX IF NOT EXISTS idx_catalog_created ON catalog(created_at)");

	// Full-text search table for better search (optional enhancement)
	db->execute("CREATE VIRTUAL TABLE IF NOT EXISTS catalog_fts USING fts5("
		"  schema, kind, key, document, tags, content='catalog' ,  content_rowid='id'"
		");");

	// Triggers to keep FTS in sync
	db->execute("DROP TRIGGER IF EXISTS catalog_ai");
	db->execute("DROP TRIGGER IF EXISTS catalog_ad");

	db->execute("CREATE TRIGGER IF NOT EXISTS catalog_ai AFTER INSERT ON catalog BEGIN"
		"  INSERT INTO catalog_fts(rowid, schema, kind, key, document ,  tags)"
		"  VALUES (new.id, new.schema, new.kind, new.key, new.document ,  new.tags);"
		"END;");

	db->execute("CREATE TRIGGER IF NOT EXISTS catalog_ad AFTER DELETE ON catalog BEGIN"
		"  INSERT INTO catalog_fts(catalog_fts, rowid, schema, kind, key, document ,  tags)"
		"  VALUES ('delete', old.id, old.schema, old.kind, old.key, old.document ,  old.tags);"
		"END;");

	// Merge operations log
	const char* create_merge_log =
		"CREATE TABLE IF NOT EXISTS merge_log ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT , "
		"  target_key TEXT NOT NULL , "
		"  source_keys TEXT NOT NULL , "  // JSON array
		"  instructions TEXT , "
		"  created_at INTEGER DEFAULT (strftime('%s' ,  'now'))"
		");";

	db->execute(create_merge_log);

	return 0;
}

int MySQL_Catalog::upsert(
	const std::string& schema,
	const std::string& kind,
	const std::string& key,
	const std::string& document,
	const std::string& tags,
	const std::string& links
) {
	sqlite3_stmt* stmt = NULL;

	const char* upsert_sql =
		"INSERT INTO catalog(schema, kind, key, document, tags, links ,  updated_at) "
		"VALUES(?1, ?2, ?3, ?4, ?5, ?6, strftime('%s' ,  'now')) "
		"ON CONFLICT(schema, kind ,  key) DO UPDATE SET "
		"  document = ?4 , "
		"  tags = ?5 , "
		"  links = ?6 , "
		"  updated_at = strftime('%s' ,  'now')";

	int rc = db->prepare_v2(upsert_sql, &stmt);
	if (rc != SQLITE_OK) {
		proxy_error("Failed to prepare catalog upsert: %d\n", rc);
		return -1;
	}

	(*proxy_sqlite3_bind_text)(stmt, 1, schema.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 2, kind.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 3, key.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, document.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 5, tags.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 6, links.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);
	(*proxy_sqlite3_finalize)(stmt);

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Catalog upsert: schema=%s, kind=%s ,  key=%s\n", schema.c_str(), kind.c_str(), key.c_str());
	return 0;
}

int MySQL_Catalog::get(
	const std::string& schema,
	const std::string& kind,
	const std::string& key,
	std::string& document
) {
	sqlite3_stmt* stmt = NULL;

	const char* get_sql =
		"SELECT document FROM catalog "
		"WHERE schema = ?1 AND kind = ?2 AND key = ?3";

	int rc = db->prepare_v2(get_sql, &stmt);
	if (rc != SQLITE_OK) {
		proxy_error("Failed to prepare catalog get: %d\n", rc);
		return -1;
	}

	(*proxy_sqlite3_bind_text)(stmt, 1, schema.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 2, kind.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 3, key.c_str(), -1, SQLITE_TRANSIENT);

	rc = (*proxy_sqlite3_step)(stmt);

	if (rc == SQLITE_ROW) {
		const char* doc = (const char*)(*proxy_sqlite3_column_text)(stmt, 0);
		if (doc) {
			document = doc;
		}
		(*proxy_sqlite3_finalize)(stmt);
		return 0;
	}

	(*proxy_sqlite3_finalize)(stmt);
	return -1;
}

std::string MySQL_Catalog::search(
	const std::string& schema,
	const std::string& query,
	const std::string& kind,
	const std::string& tags,
	int limit,
	int offset
) {
	// FTS5 search requires a query
	if (query.empty()) {
		proxy_error("Catalog search requires a query parameter\n");
		return "[]";
	}

	// Helper lambda to escape single quotes for SQLite SQL literals
	auto escape_sql = [](const std::string& str) -> std::string {
		std::string result;
		result.reserve(str.length() * 2);  // Reserve space for potential escaping
		for (char c : str) {
			if (c == '\'') {
				result += '\'';  // Escape single quote by doubling it
			}
			result += c;
		}
		return result;
	};

	// Escape query for use in FTS5 MATCH (MATCH doesn't support parameter binding)
	std::string escaped_query = escape_sql(query);

	// Build SQL query with placeholders for parameters
	std::ostringstream sql;
	sql << "SELECT c.kind, c.key, c.document, c.tags, c.links "
	    << "FROM catalog c "
	    << "INNER JOIN catalog_fts f ON c.id = f.rowid "
	    << "WHERE catalog_fts MATCH '" << escaped_query << "'";

	int param_count = 1;  // Track parameter binding position

	// Add kind filter with parameter placeholder
	if (!kind.empty()) {
		sql << " AND c.kind = ?";
	}

	// Add tags filter with parameter placeholder
	if (!tags.empty()) {
		sql << " AND c.tags LIKE ?";
	}

	// Order by relevance (BM25) and recency
	sql << " ORDER BY bm25(f) ASC, c.updated_at DESC LIMIT ? OFFSET ?";

	// Prepare the statement
	sqlite3_stmt* stmt = NULL;
	int rc = db->prepare_v2(sql.str().c_str(), &stmt);
	if (rc != SQLITE_OK) {
		proxy_error("Catalog search: Failed to prepare statement: %d\n", rc);
		return "[]";
	}

	// Bind parameters
	param_count = 1;
	if (!kind.empty()) {
		(*proxy_sqlite3_bind_text)(stmt, param_count++, kind.c_str(), -1, SQLITE_TRANSIENT);
	}
	if (!tags.empty()) {
		// Add wildcards for LIKE search
		std::string tags_pattern = "%" + tags + "%";
		(*proxy_sqlite3_bind_text)(stmt, param_count++, tags_pattern.c_str(), -1, SQLITE_TRANSIENT);
	}
	(*proxy_sqlite3_bind_int)(stmt, param_count++, limit);
	(*proxy_sqlite3_bind_int)(stmt, param_count, offset);

	// Build JSON result using nlohmann::json (consistent with list() function)
	nlohmann::json results = nlohmann::json::array();

	while ((rc = (*proxy_sqlite3_step)(stmt)) == SQLITE_ROW) {
		nlohmann::json entry;

		const char* kind_val = (const char*)(*proxy_sqlite3_column_text)(stmt, 0);
		const char* key_val = (const char*)(*proxy_sqlite3_column_text)(stmt, 1);
		const char* doc_val = (const char*)(*proxy_sqlite3_column_text)(stmt, 2);
		const char* tags_val = (const char*)(*proxy_sqlite3_column_text)(stmt, 3);
		const char* links_val = (const char*)(*proxy_sqlite3_column_text)(stmt, 4);

		entry["kind"] = std::string(kind_val ? kind_val : "");
		entry["key"] = std::string(key_val ? key_val : "");

		// Parse the stored JSON document - nlohmann::json handles escaping
		if (doc_val) {
			try {
				entry["document"] = nlohmann::json::parse(doc_val);
			} catch (const nlohmann::json::parse_error& e) {
				// If document is not valid JSON, store as string
				entry["document"] = std::string(doc_val);
			}
		} else {
			entry["document"] = nullptr;
		}

		entry["tags"] = std::string(tags_val ? tags_val : "");
		entry["links"] = std::string(links_val ? links_val : "");

		results.push_back(entry);
	}

	(*proxy_sqlite3_finalize)(stmt);

	if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
		proxy_error("Catalog search: Error executing query: %d\n", rc);
	}

	return results.dump();
}

std::string MySQL_Catalog::list(
	const std::string& schema,
	const std::string& kind,
	int limit,
	int offset
) {
	std::ostringstream sql;
	sql << "SELECT schema, kind, key, document, tags ,  links FROM catalog WHERE 1=1";

	if (!schema.empty()) {
		sql << " AND schema = '" << schema << "'";
	}

	if (!kind.empty()) {
		sql << " AND kind = '" << kind << "'";
	}

	sql << " ORDER BY schema, kind ,  key ASC LIMIT " << limit << " OFFSET " << offset;

	// Get total count
	std::ostringstream count_sql;
	count_sql << "SELECT COUNT(*) FROM catalog WHERE 1=1";
	if (!schema.empty()) {
		count_sql << " AND schema = '" << schema << "'";
	}
	if (!kind.empty()) {
		count_sql << " AND kind = '" << kind << "'";
	}

	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;
	int total = 0;

	SQLite3_result* count_result = db->execute_statement(count_sql.str().c_str(), &error, &cols, &affected);
	if (count_result && !count_result->rows.empty()) {
		total = atoi(count_result->rows[0]->fields[0]);
	}
	delete count_result;

	resultset = NULL;
	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

	// Build JSON result using nlohmann::json
	nlohmann::json result;
	result["total"] = total;
	nlohmann::json results = nlohmann::json::array();

	if (resultset) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
		     it != resultset->rows.end(); ++it) {
			SQLite3_row* row = *it;

			nlohmann::json entry;
			entry["schema"] = std::string(row->fields[0] ? row->fields[0] : "");
			entry["kind"] = std::string(row->fields[1] ? row->fields[1] : "");
			entry["key"] = std::string(row->fields[2] ? row->fields[2] : "");

			// Parse the stored JSON document
			const char* doc_str = row->fields[3];
			if (doc_str) {
				try {
					entry["document"] = nlohmann::json::parse(doc_str);
				} catch (const nlohmann::json::parse_error& e) {
					entry["document"] = std::string(doc_str);
				}
			} else {
				entry["document"] = nullptr;
			}

			entry["tags"] = std::string(row->fields[4] ? row->fields[4] : "");
			entry["links"] = std::string(row->fields[5] ? row->fields[5] : "");

			results.push_back(entry);
		}
		delete resultset;
	}

	result["results"] = results;
	return result.dump();
}

int MySQL_Catalog::merge(
	const std::vector<std::string>& keys,
	const std::string& target_key,
	const std::string& kind,
	const std::string& instructions
) {
	// Fetch all source entries (empty schema for backward compatibility)
	std::string source_docs = "";
	for (const auto& key : keys) {
		std::string doc;
		// Try different kinds for flexible merging (empty schema searches all)
		if (get("" ,  "table", key ,  doc) == 0 || get("" ,  "view", key, doc) == 0) {
			source_docs += doc + "\n\n";
		}
	}

	// Create merged document
	std::string merged_doc = "{";
	merged_doc += "\"source_keys\":[";

	for (size_t i = 0; i < keys.size(); i++) {
		if (i > 0) merged_doc += " , ";
		merged_doc += "\"" + keys[i] + "\"";
	}
	merged_doc += "] , ";
	merged_doc += "\"instructions\":" + std::string(instructions.empty() ? "\"\"" : "\"" + instructions + "\"");
	merged_doc += "}";

	// Use empty schema for merged domain entries (backward compatibility)
	return upsert("", kind, target_key, merged_doc ,  "" ,  "");
}

int MySQL_Catalog::remove(
	const std::string& schema,
	const std::string& kind,
	const std::string& key
) {
	std::ostringstream sql;
	sql << "DELETE FROM catalog WHERE 1=1";

	if (!schema.empty()) {
		sql << " AND schema = '" << schema << "'";
	}
	sql << " AND kind = '" << kind << "' AND key = '" << key << "'";

	if (!db->execute(sql.str().c_str())) {
		proxy_error("Catalog remove error\n");
		return -1;
	}

	return 0;
}
