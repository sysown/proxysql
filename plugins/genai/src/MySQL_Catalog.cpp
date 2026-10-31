#ifdef PROXYSQL40

// ============================================================
// MySQL Catalog Implementation
//
// The MySQL Catalog provides a SQLite-based key-value store for
// MCP tool results, with schema isolation for multi-tenancy.
//
// Schema Isolation:
// All catalog entries are now scoped to a specific schema (database).
// The catalog table has a composite unique constraint on (schema, kind, key)
// to ensure entries from different schemas don't conflict.
//
// Functions accept a schema parameter to scope operations:
// - upsert(schema, kind, key, document, tags, links)
// - get(schema, kind, key, document)
// - search(schema, query, kind, tags, limit, offset)
// - list(schema, kind, limit, offset)
// - remove(schema, kind, key)
//
// Use empty schema "" for global/shared entries.
// ============================================================

#include "MySQL_Catalog.h"
#include "cpp.h"
#include "proxysql.h"
#include <sstream>
#include <algorithm>
#include <cstring>
#include "../deps/json/json.hpp"

// ============================================================
// Constructor / Destructor
// ============================================================

MySQL_Catalog::MySQL_Catalog(const std::string& path)
	: db(NULL), db_path(path)
{
}

MySQL_Catalog::~MySQL_Catalog() {
	close();
}

// ============================================================
// Database Initialization
// ============================================================

// Initialize the catalog database connection and schema.
//
// Opens (or creates) the SQLite database at db_path and initializes
// the catalog table with schema isolation support.
//
// Returns:
//   0 on success, -1 on error
int MySQL_Catalog::init() {
	// Initialize database connection
	db = new SQLite3DB();
	std::string path_buf = db_path;
	int rc = db->open(&path_buf[0], SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	if (rc != SQLITE_OK) {
		proxy_error("Failed to open catalog database at %s: %d\n", db_path.c_str(), rc);
		return -1;
	}

	// Initialize schema
	return init_schema();
}

// Close the catalog database connection.
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
	db->execute("DROP TRIGGER IF EXISTS catalog_au");

	db->execute("CREATE TRIGGER IF NOT EXISTS catalog_ai AFTER INSERT ON catalog BEGIN"
		"  INSERT INTO catalog_fts(rowid, schema, kind, key, document ,  tags)"
		"  VALUES (new.id, new.schema, new.kind, new.key, new.document ,  new.tags);"
		"END;");

	db->execute("CREATE TRIGGER IF NOT EXISTS catalog_ad AFTER DELETE ON catalog BEGIN"
		"  INSERT INTO catalog_fts(catalog_fts, rowid, schema, kind, key, document ,  tags)"
		"  VALUES ('delete', old.id, old.schema, old.kind, old.key, old.document ,  old.tags);"
		"END;");

	// AFTER UPDATE trigger to keep FTS in sync for upserts
	// When an upsert occurs (INSERT OR REPLACE ... ON CONFLICT ... DO UPDATE),
	// the UPDATE doesn't trigger INSERT/DELETE triggers, so we need to handle
	// updates explicitly to keep the FTS index current
	db->execute("CREATE TRIGGER IF NOT EXISTS catalog_au AFTER UPDATE ON catalog BEGIN"
		"  INSERT INTO catalog_fts(catalog_fts, rowid, schema, kind, key, document ,  tags)"
		"  VALUES ('delete', old.id, old.schema, old.kind, old.key, old.document ,  old.tags);"
		"  INSERT INTO catalog_fts(rowid, schema, kind, key, document ,  tags)"
		"  VALUES (new.id, new.schema, new.kind, new.key, new.document ,  new.tags);"
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

// ============================================================
// Catalog CRUD Operations
// ============================================================

// Insert or update a catalog entry with schema isolation.
//
// Uses INSERT OR REPLACE (UPSERT) semantics with schema scoping.
// The unique constraint is (schema, kind, key), so entries from
// different schemas won't conflict even if they have the same kind/key.
//
// Parameters:
//   schema   - Schema name for isolation (use "" for global entries)
//   kind     - Entry kind (table, view, domain, metric, note, etc.)
//   key      - Unique key within the schema/kind
//   document - JSON document content
//   tags     - Comma-separated tags
//   links    - Comma-separated related keys
//
// Returns:
//   0 on success, -1 on error
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

	auto [rc, stmt_unique] = db->prepare_v2(upsert_sql);
	stmt = stmt_unique.get();
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

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Catalog upsert: schema=%s, kind=%s ,  key=%s\n", schema.c_str(), kind.c_str(), key.c_str());
	return 0;
}

// Retrieve a catalog entry by schema, kind, and key.
//
// Parameters:
//   schema   - Schema name for isolation
//   kind     - Entry kind
//   key      - Unique key
//   document - Output: JSON document content
//
// Returns:
//   0 on success (entry found), -1 on error or not found
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

	auto [rc, stmt_unique] = db->prepare_v2(get_sql);
	stmt = stmt_unique.get();
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
		return 0;
	}

	return -1;
}

// Search catalog entries with optional filters.
//
// Parameters:
//   schema - Schema filter (empty string for all schemas)
//   query  - Full-text search query (matches key, document, tags)
//   kind   - Kind filter (empty string for all kinds)
//   tags   - Tag filter (partial match)
//   limit  - Maximum results to return
//   offset - Results offset for pagination
//
// Returns:
//   JSON array of matching entries with schema, kind, key, document, tags, links
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
		nlohmann::json error_result = {{"error", "Catalog search requires a query parameter"}};
		return error_result.dump();
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

	// Build SQL query with FTS5 - include schema column
	std::ostringstream sql;
	sql << "SELECT c.schema, c.kind, c.key, c.document, c.tags, c.links "
	    << "FROM catalog c "
	    << "INNER JOIN catalog_fts f ON c.id = f.rowid "
	    << "WHERE catalog_fts MATCH '" << escaped_query << "'";

	// Add schema filter
	if (!schema.empty()) {
		sql << " AND c.schema = ?";
	}

	// Add kind filter
	if (!kind.empty()) {
		sql << " AND c.kind = ?";
	}

	// Add tags filter
	if (!tags.empty()) {
		sql << " AND c.tags LIKE ?";
	}

	// Order by relevance (BM25) and recency
	sql << " ORDER BY bm25(f) ASC, c.updated_at DESC LIMIT ? OFFSET ?";

	// Prepare the statement
	sqlite3_stmt* stmt = NULL;
	auto [rc, stmt_unique] = db->prepare_v2(sql.str().c_str());
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) {
		proxy_error("Failed to prepare catalog search: %d\n", rc);
		return "[]";
	}

	// Bind parameters
	int param_idx = 1;
	if (!schema.empty()) {
		(*proxy_sqlite3_bind_text)(stmt, param_idx++, schema.c_str(), -1, SQLITE_TRANSIENT);
	}
	if (!kind.empty()) {
		(*proxy_sqlite3_bind_text)(stmt, param_idx++, kind.c_str(), -1, SQLITE_TRANSIENT);
	}
	if (!tags.empty()) {
		std::string tags_pattern = "%" + tags + "%";
		(*proxy_sqlite3_bind_text)(stmt, param_idx++, tags_pattern.c_str(), -1, SQLITE_TRANSIENT);
	}
	(*proxy_sqlite3_bind_int)(stmt, param_idx++, limit);
	(*proxy_sqlite3_bind_int)(stmt, param_idx++, offset);

	// Build JSON result using nlohmann::json
	nlohmann::json results = nlohmann::json::array();

	// Execute prepared statement and process results
	int step_rc;
	while ((step_rc = (*proxy_sqlite3_step)(stmt)) == SQLITE_ROW) {
		nlohmann::json entry;

		// Columns: 0=schema, 1=kind, 2=key, 3=document, 4=tags, 5=links
		entry["schema"] = std::string((const char*)(*proxy_sqlite3_column_text)(stmt, 0));
		entry["kind"] = std::string((const char*)(*proxy_sqlite3_column_text)(stmt, 1));
		entry["key"] = std::string((const char*)(*proxy_sqlite3_column_text)(stmt, 2));

		// Parse the stored JSON document - nlohmann::json handles escaping
		const char* doc_str = (const char*)(*proxy_sqlite3_column_text)(stmt, 3);
		if (doc_str) {
			try {
				entry["document"] = nlohmann::json::parse(doc_str);
			} catch (const nlohmann::json::parse_error& e) {
				// If document is not valid JSON, store as string
				entry["document"] = std::string(doc_str);
			}
		} else {
			entry["document"] = nullptr;
		}

		const char* tags_str = (const char*)(*proxy_sqlite3_column_text)(stmt, 4);
		entry["tags"] = tags_str ? std::string(tags_str) : nullptr;
		const char* links_str = (const char*)(*proxy_sqlite3_column_text)(stmt, 5);
		entry["links"] = links_str ? std::string(links_str) : nullptr;

		results.push_back(entry);
	}

	if (step_rc != SQLITE_DONE) {
		proxy_error("Catalog search error: step_rc=%d\n", step_rc);
	}

	return results.dump();
}

// List catalog entries with optional filters and pagination.
//
// Parameters:
//   schema - Schema filter (empty string for all schemas)
//   kind   - Kind filter (empty string for all kinds)
//   limit  - Maximum results to return
//   offset - Results offset for pagination
//
// Returns:
//   JSON object with "total" count and "results" array containing
//   entries with schema, kind, key, document, tags, links
std::string MySQL_Catalog::list(
	const std::string& schema,
	const std::string& kind,
	int limit,
	int offset
) {
	bool has_schema = !schema.empty();
	bool has_kind = !kind.empty();

	// Get total count using prepared statement to prevent SQL injection
	std::ostringstream count_sql;
	count_sql << "SELECT COUNT(*) FROM catalog WHERE 1=1";
	if (has_schema) {
		count_sql << " AND schema = ?";
	}
	if (has_kind) {
		count_sql << " AND kind = ?";
	}

	int total = 0;
	sqlite3_stmt* count_stmt = NULL;
	auto [count_rc, count_stmt_unique] = db->prepare_v2(count_sql.str().c_str());
	count_stmt = count_stmt_unique.get();
	if (count_rc == SQLITE_OK) {
		int param_idx = 1;
		if (has_schema) {
			(*proxy_sqlite3_bind_text)(count_stmt, param_idx++, schema.c_str(), -1, SQLITE_TRANSIENT);
		}
		if (has_kind) {
			(*proxy_sqlite3_bind_text)(count_stmt, param_idx++, kind.c_str(), -1, SQLITE_TRANSIENT);
		}

		if ((*proxy_sqlite3_step)(count_stmt) == SQLITE_ROW) {
			total = (*proxy_sqlite3_column_int)(count_stmt, 0);
		}
	}

	// Build main query with prepared statement to prevent SQL injection
	std::ostringstream sql;
	sql << "SELECT schema, kind, key, document, tags ,  links FROM catalog WHERE 1=1";
	if (has_schema) {
		sql << " AND schema = ?";
	}
	if (has_kind) {
		sql << " AND kind = ?";
	}
	sql << " ORDER BY schema, kind ,  key ASC LIMIT ? OFFSET ?";

	sqlite3_stmt* stmt = NULL;
	auto [rc, stmt_unique] = db->prepare_v2(sql.str().c_str());
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) {
		proxy_error("Failed to prepare catalog list: %d\n", rc);
		nlohmann::json result;
		result["total"] = total;
		result["results"] = nlohmann::json::array();
		return result.dump();
	}

	// Bind parameters
	int param_idx = 1;
	if (has_schema) {
		(*proxy_sqlite3_bind_text)(stmt, param_idx++, schema.c_str(), -1, SQLITE_TRANSIENT);
	}
	if (has_kind) {
		(*proxy_sqlite3_bind_text)(stmt, param_idx++, kind.c_str(), -1, SQLITE_TRANSIENT);
	}
	(*proxy_sqlite3_bind_int)(stmt, param_idx++, limit);
	(*proxy_sqlite3_bind_int)(stmt, param_idx++, offset);

	// Build JSON result using nlohmann::json
	nlohmann::json result;
	result["total"] = total;
	nlohmann::json results = nlohmann::json::array();

	// Execute prepared statement and process results
	int step_rc;
	while ((step_rc = (*proxy_sqlite3_step)(stmt)) == SQLITE_ROW) {
		nlohmann::json entry;
		entry["schema"] = std::string((const char*)(*proxy_sqlite3_column_text)(stmt, 0));
		entry["kind"] = std::string((const char*)(*proxy_sqlite3_column_text)(stmt, 1));
		entry["key"] = std::string((const char*)(*proxy_sqlite3_column_text)(stmt, 2));

		// Parse the stored JSON document
		const char* doc_str = (const char*)(*proxy_sqlite3_column_text)(stmt, 3);
		if (doc_str) {
			try {
				entry["document"] = nlohmann::json::parse(doc_str);
			} catch (const nlohmann::json::parse_error& e) {
				entry["document"] = std::string(doc_str);
			}
		} else {
			entry["document"] = nullptr;
		}

		const char* tags_str = (const char*)(*proxy_sqlite3_column_text)(stmt, 4);
		entry["tags"] = tags_str ? std::string(tags_str) : nullptr;
		const char* links_str = (const char*)(*proxy_sqlite3_column_text)(stmt, 5);
		entry["links"] = links_str ? std::string(links_str) : nullptr;

		results.push_back(entry);
	}

	if (step_rc != SQLITE_DONE) {
		proxy_error("Catalog list error: step_rc=%d\n", step_rc);
	}

	result["results"] = results;
	return result.dump();
}

// Merge multiple catalog entries into a single target entry.
//
// Fetches documents for the source keys and creates a merged document
// with source_keys and instructions fields. Uses empty schema for
// merged domain entries (backward compatibility).
//
// Parameters:
//   keys         - Vector of source keys to merge
//   target_key   - Key for the merged entry
//   kind         - Kind for the merged entry (e.g., "domain")
//   instructions - Optional instructions for the merge
//
// Returns:
//   0 on success, -1 on error
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

// Delete a catalog entry by schema, kind, and key.
//
// Parameters:
//   schema - Schema filter (empty string for all schemas)
//   kind   - Entry kind
//   key    - Unique key
//
// Returns:
//   0 on success, -1 on error
int MySQL_Catalog::remove(
	const std::string& schema,
	const std::string& kind,
	const std::string& key
) {
	// Use prepared statement to prevent SQL injection
	std::ostringstream sql;
	sql << "DELETE FROM catalog WHERE 1=1";

	bool has_schema = !schema.empty();
	if (has_schema) {
		sql << " AND schema = ?";
	}
	sql << " AND kind = ? AND key = ?";

	sqlite3_stmt* stmt = NULL;
	auto [rc, stmt_unique] = db->prepare_v2(sql.str().c_str());
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) {
		proxy_error("Failed to prepare catalog remove: %d\n", rc);
		return -1;
	}

	// Bind parameters
	int param_idx = 1;
	if (has_schema) {
		(*proxy_sqlite3_bind_text)(stmt, param_idx++, schema.c_str(), -1, SQLITE_TRANSIENT);
	}
	(*proxy_sqlite3_bind_text)(stmt, param_idx++, kind.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, param_idx++, key.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);

	return 0;
}

#endif /* PROXYSQL40 */
