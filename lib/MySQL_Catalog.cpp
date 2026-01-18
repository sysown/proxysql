#include "MySQL_Catalog.h"
#include "cpp.h"
#include "proxysql.h"
#include <sstream>
#include <algorithm>

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
	// Main catalog table
	const char* create_catalog_table =
		"CREATE TABLE IF NOT EXISTS catalog ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  kind TEXT NOT NULL,"           // table, view, domain, metric, note
		"  key TEXT NOT NULL,"            // e.g., "db.sales.orders"
		"  document TEXT NOT NULL,"       // JSON content
		"  tags TEXT,"                    // comma-separated tags
		"  links TEXT,"                   // comma-separated related keys
		"  created_at INTEGER DEFAULT (strftime('%s', 'now')),"
		"  updated_at INTEGER DEFAULT (strftime('%s', 'now')),"
		"  UNIQUE(kind, key)"
		");";

	if (!db->execute(create_catalog_table)) {
		proxy_error("Failed to create catalog table\n");
		return -1;
	}

	// Indexes for search
	db->execute("CREATE INDEX IF NOT EXISTS idx_catalog_kind ON catalog(kind)");
	db->execute("CREATE INDEX IF NOT EXISTS idx_catalog_tags ON catalog(tags)");
	db->execute("CREATE INDEX IF NOT EXISTS idx_catalog_created ON catalog(created_at)");

	// Full-text search table for better search (optional enhancement)
	db->execute("CREATE VIRTUAL TABLE IF NOT EXISTS catalog_fts USING fts5("
		"  kind, key, document, tags, content='catalog', content_rowid='id'"
		");");

	// Triggers to keep FTS in sync
	db->execute("DROP TRIGGER IF EXISTS catalog_ai");
	db->execute("DROP TRIGGER IF EXISTS catalog_ad");

	db->execute("CREATE TRIGGER IF NOT EXISTS catalog_ai AFTER INSERT ON catalog BEGIN"
		"  INSERT INTO catalog_fts(rowid, kind, key, document, tags)"
		"  VALUES (new.id, new.kind, new.key, new.document, new.tags);"
		"END;");

	db->execute("CREATE TRIGGER IF NOT EXISTS catalog_ad AFTER DELETE ON catalog BEGIN"
		"  INSERT INTO catalog_fts(catalog_fts, rowid, kind, key, document, tags)"
		"  VALUES ('delete', old.id, old.kind, old.key, old.document, old.tags);"
		"END;");

	// Merge operations log
	const char* create_merge_log =
		"CREATE TABLE IF NOT EXISTS merge_log ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  target_key TEXT NOT NULL,"
		"  source_keys TEXT NOT NULL,"  // JSON array
		"  instructions TEXT,"
		"  created_at INTEGER DEFAULT (strftime('%s', 'now'))"
		");";

	db->execute(create_merge_log);

	return 0;
}

int MySQL_Catalog::upsert(
	const std::string& kind,
	const std::string& key,
	const std::string& document,
	const std::string& tags,
	const std::string& links
) {
	sqlite3_stmt* stmt = NULL;

	const char* upsert_sql =
		"INSERT INTO catalog(kind, key, document, tags, links, updated_at) "
		"VALUES(?1, ?2, ?3, ?4, ?5, strftime('%s', 'now')) "
		"ON CONFLICT(kind, key) DO UPDATE SET "
		"  document = ?3,"
		"  tags = ?4,"
		"  links = ?5,"
		"  updated_at = strftime('%s', 'now')";

	int rc = db->prepare_v2(upsert_sql, &stmt);
	if (rc != SQLITE_OK) {
		proxy_error("Failed to prepare catalog upsert: %d\n", rc);
		return -1;
	}

	(*proxy_sqlite3_bind_text)(stmt, 1, kind.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 3, document.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, tags.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 5, links.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);
	(*proxy_sqlite3_finalize)(stmt);

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Catalog upsert: kind=%s, key=%s\n", kind.c_str(), key.c_str());
	return 0;
}

int MySQL_Catalog::get(
	const std::string& kind,
	const std::string& key,
	std::string& document
) {
	sqlite3_stmt* stmt = NULL;

	const char* get_sql =
		"SELECT document FROM catalog "
		"WHERE kind = ?1 AND key = ?2";

	int rc = db->prepare_v2(get_sql, &stmt);
	if (rc != SQLITE_OK) {
		proxy_error("Failed to prepare catalog get: %d\n", rc);
		return -1;
	}

	(*proxy_sqlite3_bind_text)(stmt, 1, kind.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);

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

	std::ostringstream sql;
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	// FTS5 search with BM25 ranking
	sql << "SELECT c.kind, c.key, c.document, c.tags, c.links "
	    << "FROM catalog c "
	    << "INNER JOIN catalog_fts f ON c.id = f.rowid "
	    << "WHERE catalog_fts MATCH '" << query << "'";

	// Add kind filter
	if (!kind.empty()) {
		sql << " AND c.kind = '" << kind << "'";
	}

	// Add tags filter
	if (!tags.empty()) {
		sql << " AND c.tags LIKE '%" << tags << "%'";
	}

	// Order by relevance (BM25) and recency
	sql << " ORDER BY bm25(f) ASC, c.updated_at DESC LIMIT " << limit << " OFFSET " << offset;

	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
	if (error) {
		proxy_error("Catalog search error: %s\n", error);
		return "[]";
	}

	// Build JSON result
	std::ostringstream json;
	json << "[";
	bool first = true;

	if (resultset) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
		     it != resultset->rows.end(); ++it) {
			SQLite3_row* row = *it;
			if (!first) json << ",";
			first = false;

			json << "{"
			     << "\"kind\":\"" << (row->fields[0] ? row->fields[0] : "") << "\","
			     << "\"key\":\"" << (row->fields[1] ? row->fields[1] : "") << "\","
			     << "\"document\":" << (row->fields[2] ? row->fields[2] : "null") << ","
			     << "\"tags\":\"" << (row->fields[3] ? row->fields[3] : "") << "\","
			     << "\"links\":\"" << (row->fields[4] ? row->fields[4] : "") << "\""
			     << "}";
		}
		delete resultset;
	}

	json << "]";
	return json.str();
}

std::string MySQL_Catalog::list(
	const std::string& kind,
	int limit,
	int offset
) {
	std::ostringstream sql;
	sql << "SELECT kind, key, document, tags, links FROM catalog";

	if (!kind.empty()) {
		sql << " WHERE kind = '" << kind << "'";
	}

	sql << " ORDER BY kind, key ASC LIMIT " << limit << " OFFSET " << offset;

	// Get total count
	std::ostringstream count_sql;
	count_sql << "SELECT COUNT(*) FROM catalog";
	if (!kind.empty()) {
		count_sql << " WHERE kind = '" << kind << "'";
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

	// Build JSON result with total count
	std::ostringstream json;
	json << "{\"total\":" << total << ",\"results\":[";

	bool first = true;
	if (resultset) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
		     it != resultset->rows.end(); ++it) {
			SQLite3_row* row = *it;
			if (!first) json << ",";
			first = false;

			json << "{"
			     << "\"kind\":\"" << (row->fields[0] ? row->fields[0] : "") << "\","
			     << "\"key\":\"" << (row->fields[1] ? row->fields[1] : "") << "\","
			     << "\"document\":" << (row->fields[2] ? row->fields[2] : "null") << ","
			     << "\"tags\":\"" << (row->fields[3] ? row->fields[3] : "") << "\","
			     << "\"links\":\"" << (row->fields[4] ? row->fields[4] : "") << "\""
			     << "}";
		}
		delete resultset;
	}

	json << "]}";
	return json.str();
}

int MySQL_Catalog::merge(
	const std::vector<std::string>& keys,
	const std::string& target_key,
	const std::string& kind,
	const std::string& instructions
) {
	// Fetch all source entries
	std::string source_docs = "";
	for (const auto& key : keys) {
		std::string doc;
		// Try different kinds for flexible merging
		if (get("table", key, doc) == 0 || get("view", key, doc) == 0) {
			source_docs += doc + "\n\n";
		}
	}

	// Create merged document
	std::string merged_doc = "{";
	merged_doc += "\"source_keys\":[";

	for (size_t i = 0; i < keys.size(); i++) {
		if (i > 0) merged_doc += ",";
		merged_doc += "\"" + keys[i] + "\"";
	}
	merged_doc += "],";
	merged_doc += "\"instructions\":" + std::string(instructions.empty() ? "\"\"" : "\"" + instructions + "\"");
	merged_doc += "}";

	return upsert(kind, target_key, merged_doc, "", "");
}

int MySQL_Catalog::remove(
	const std::string& kind,
	const std::string& key
) {
	std::ostringstream sql;
	sql << "DELETE FROM catalog WHERE kind = '" << kind << "' AND key = '" << key << "'";

	if (!db->execute(sql.str().c_str())) {
		proxy_error("Catalog remove error\n");
		return -1;
	}

	return 0;
}
