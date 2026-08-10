#ifdef PROXYSQL40

#include "Discovery_Schema.h"
#include "cpp.h"
#include "proxysql.h"
#include "re2/re2.h"
#include <sstream>
#include <algorithm>
#include <ctime>
#include <functional>
#include <cstring>
#include "../deps/json/json.hpp"

using json = nlohmann::json;

Discovery_Schema::Discovery_Schema(const std::string& path)
	: db(NULL), db_path(path), mcp_rules_version(0)
{
	pthread_rwlock_init(&mcp_rules_lock, NULL);
	pthread_rwlock_init(&mcp_digest_rwlock, NULL);
}

Discovery_Schema::~Discovery_Schema() {
	close();

	// Clean up MCP query rules
	for (auto rule : mcp_query_rules) {
		if (rule->regex_engine) {
			delete (re2::RE2*)rule->regex_engine;
		}
		free(rule->username);
		free(rule->target_id);
		free(rule->schemaname);
		free(rule->tool_name);
		free(rule->match_pattern);
		free(rule->replace_pattern);
		free(rule->error_msg);
		free(rule->ok_msg);
		free(rule->comment);
		delete rule;
	}
	mcp_query_rules.clear();

	// Clean up MCP digest statistics
	for (auto const& [key1, inner_map] : mcp_digest_umap) {
		for (auto const& [key2, stats] : inner_map) {
			delete (MCP_Query_Digest_Stats*)stats;
		}
	}
	mcp_digest_umap.clear();

	pthread_rwlock_destroy(&mcp_rules_lock);
	pthread_rwlock_destroy(&mcp_digest_rwlock);
}

int Discovery_Schema::init() {
	// Initialize database connection
	db = new SQLite3DB();
	std::string path_buf = db_path;
	int rc = db->open(&path_buf[0], SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	if (rc != SQLITE_OK) {
		proxy_error("Failed to open discovery catalog database at %s: %d\n", db_path.c_str(), rc);
		return -1;
	}

	// Initialize schema
	return init_schema();
}

void Discovery_Schema::close() {
	if (db) {
		delete db;
		db = NULL;
	}
}

int Discovery_Schema::resolve_run_id(const std::string& target_id, const std::string& run_id_or_schema) {
	if (target_id.empty()) {
		proxy_warning("resolve_run_id called without target_id\n");
		return -1;
	}

	int rc = SQLITE_OK;
	sqlite3_stmt* stmt = NULL;

	// If it's already a number (run_id), return it
	if (!run_id_or_schema.empty() && std::isdigit(run_id_or_schema[0])) {
		int run_id = std::stoi(run_id_or_schema);
		const char* sql = "SELECT 1 FROM runs WHERE run_id=?1 AND target_id=?2 LIMIT 1;";
		auto [prep_rc, stmt_unique] = db->prepare_v2(sql);
		stmt = stmt_unique.get();
		if (prep_rc != SQLITE_OK) {
			proxy_error("Failed to prepare statement for run_id validation\n");
			return -1;
		}
		(*proxy_sqlite3_bind_int64)(stmt, 1, run_id);
		(*proxy_sqlite3_bind_text)(stmt, 2, target_id.c_str(), -1, SQLITE_TRANSIENT);
		SAFE_SQLITE3_STEP2(stmt);
		bool found = (rc == SQLITE_ROW);
		return found ? run_id : -1;
	}

	// It's a schema name - find the latest run_id for this schema
	const char* sql =
		"SELECT r.run_id FROM runs r "
		"INNER JOIN schemas s ON s.run_id = r.run_id "
		"WHERE r.target_id = ?1 AND s.schema_name = ?2 "
		"ORDER BY r.started_at DESC LIMIT 1;";
	auto [prep_rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (prep_rc != SQLITE_OK) {
		proxy_error("Failed to prepare statement for schema resolution\n");
		return -1;
	}
	(*proxy_sqlite3_bind_text)(stmt, 1, target_id.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 2, run_id_or_schema.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);
	if (rc != SQLITE_ROW) {
		proxy_warning("No run found for schema '%s'\n", run_id_or_schema.c_str());
		return -1;
	}

	int run_id = (*proxy_sqlite3_column_int)(stmt, 0);
	return run_id;
}

int Discovery_Schema::init_schema() {
	// Enable foreign keys
	db->execute("PRAGMA foreign_keys = ON");

	// The prototype schema had MySQL-only runs metadata. Backward compatibility is intentionally
	// not preserved: if we detect legacy runs layout, rebuild catalog tables from scratch.
	{
		char* error = NULL;
		int cols = 0, affected = 0;
		SQLite3_result* resultset = NULL;
		db->execute_statement("PRAGMA table_info(runs);", &error, &cols, &affected, &resultset);
		if (error) {
			proxy_error("Discovery_Schema: failed reading runs table layout: %s\n", error);
			free(error);
			if (resultset) {
				delete resultset;
			}
			return -1;
		}

		bool has_rows = (resultset && !resultset->rows.empty());
		bool has_target_id = false;
		bool has_protocol = false;
		bool has_server_version = false;
		for (size_t i = 0; resultset && i < resultset->rows.size(); i++) {
			SQLite3_row* row = resultset->rows[i];
			const char* col_name = (row->cnt > 1 && row->fields[1]) ? row->fields[1] : "";
			if (!strcmp(col_name, "target_id")) {
				has_target_id = true;
			} else if (!strcmp(col_name, "protocol")) {
				has_protocol = true;
			} else if (!strcmp(col_name, "server_version")) {
				has_server_version = true;
			}
		}
		if (resultset) {
			delete resultset;
		}

		if (has_rows && (!has_target_id || !has_protocol || !has_server_version)) {
			proxy_warning("Discovery_Schema: legacy catalog schema detected, rebuilding catalog tables\n");
			db->execute("PRAGMA foreign_keys = OFF");
			db->execute("DROP TABLE IF EXISTS schema_docs");
			db->execute("DROP TABLE IF EXISTS query_tool_calls");
			db->execute("DROP TABLE IF EXISTS rag_search_log");
			db->execute("DROP TABLE IF EXISTS llm_search_log");
			db->execute("DROP TABLE IF EXISTS llm_notes");
			db->execute("DROP TABLE IF EXISTS llm_question_templates");
			db->execute("DROP TABLE IF EXISTS llm_metrics");
			db->execute("DROP TABLE IF EXISTS llm_domain_members");
			db->execute("DROP TABLE IF EXISTS llm_domains");
			db->execute("DROP TABLE IF EXISTS llm_relationships");
			db->execute("DROP TABLE IF EXISTS llm_object_summaries");
			db->execute("DROP TABLE IF EXISTS agent_events");
			db->execute("DROP TABLE IF EXISTS agent_runs");
			db->execute("DROP TABLE IF EXISTS stats_mcp_query_digest_reset");
			db->execute("DROP TABLE IF EXISTS stats_mcp_query_digest");
			db->execute("DROP TABLE IF EXISTS mcp_query_rules");
			db->execute("DROP TABLE IF EXISTS profiles");
			db->execute("DROP TABLE IF EXISTS inferred_relationships");
			db->execute("DROP TABLE IF EXISTS view_dependencies");
			db->execute("DROP TABLE IF EXISTS foreign_key_columns");
			db->execute("DROP TABLE IF EXISTS foreign_keys");
			db->execute("DROP TABLE IF EXISTS index_columns");
			db->execute("DROP TABLE IF EXISTS indexes");
			db->execute("DROP TABLE IF EXISTS columns");
			db->execute("DROP TABLE IF EXISTS objects");
			db->execute("DROP TABLE IF EXISTS schemas");
			db->execute("DROP TABLE IF EXISTS runs");
			db->execute("DROP TABLE IF EXISTS fts_objects");
			db->execute("DROP TABLE IF EXISTS fts_llm");
			db->execute("PRAGMA foreign_keys = ON");
		}
	}

	// Create all tables
	int rc = create_deterministic_tables();
	if (rc) {
		proxy_error("Failed to create deterministic tables\n");
		return -1;
	}

	rc = create_llm_tables();
	if (rc) {
		proxy_error("Failed to create LLM tables\n");
		return -1;
	}

	rc = create_fts_tables();
	if (rc) {
		proxy_error("Failed to create FTS tables\n");
		return -1;
	}

	create_digest_persist_table();
	load_persisted_digests();

	proxy_info("Discovery Schema database initialized at %s\n", db_path.c_str());
	return 0;
}

int Discovery_Schema::create_deterministic_tables() {
	// Documentation table
	db->execute(
		"CREATE TABLE IF NOT EXISTS schema_docs ("
		"  doc_key     TEXT PRIMARY KEY , "
		"  title       TEXT NOT NULL , "
		"  body        TEXT NOT NULL , "
		"  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))"
		");"
	);

	// Runs table
	db->execute(
		"CREATE TABLE IF NOT EXISTS runs ("
		"  run_id        INTEGER PRIMARY KEY , "
		"  target_id     TEXT NOT NULL , "
		"  protocol      TEXT NOT NULL CHECK(protocol IN ('mysql','pgsql')) , "
		"  started_at    TEXT NOT NULL DEFAULT (datetime('now')) , "
		"  finished_at   TEXT , "
		"  source_dsn    TEXT , "
		"  server_version TEXT , "
		"  notes         TEXT"
		");"
	);
	db->execute("CREATE INDEX IF NOT EXISTS idx_runs_target_started ON runs(target_id, started_at DESC);");

	// Schemas table
	db->execute(
		"CREATE TABLE IF NOT EXISTS schemas ("
		"  schema_id   INTEGER PRIMARY KEY , "
		"  run_id      INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  schema_name TEXT NOT NULL , "
		"  charset     TEXT , "
		"  collation   TEXT , "
		"  UNIQUE(run_id ,  schema_name)"
		");"
	);

	// Objects table
	db->execute(
		"CREATE TABLE IF NOT EXISTS objects ("
		"  object_id        INTEGER PRIMARY KEY , "
		"  run_id           INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  schema_name      TEXT NOT NULL , "
		"  object_name      TEXT NOT NULL , "
		"  object_type      TEXT NOT NULL CHECK(object_type IN ('table','view','routine','trigger')) , "
		"  engine           TEXT , "
		"  table_rows_est   INTEGER , "
		"  data_length      INTEGER , "
		"  index_length     INTEGER , "
		"  create_time      TEXT , "
		"  update_time      TEXT , "
		"  object_comment   TEXT , "
		"  definition_sql   TEXT , "
		"  has_primary_key  INTEGER NOT NULL DEFAULT 0 , "
		"  has_foreign_keys INTEGER NOT NULL DEFAULT 0 , "
		"  has_time_column  INTEGER NOT NULL DEFAULT 0 , "
		"  UNIQUE(run_id, schema_name, object_type ,  object_name)"
		");"
	);

	// Indexes for objects
	db->execute("CREATE INDEX IF NOT EXISTS idx_objects_run_schema ON objects(run_id ,  schema_name);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_objects_run_type ON objects(run_id ,  object_type);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_objects_rows_est ON objects(run_id ,  table_rows_est);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_objects_name ON objects(run_id, schema_name ,  object_name);");

	// Columns table
	db->execute(
		"CREATE TABLE IF NOT EXISTS columns ("
		"  column_id       INTEGER PRIMARY KEY , "
		"  object_id       INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  ordinal_pos     INTEGER NOT NULL , "
		"  column_name     TEXT NOT NULL , "
		"  data_type       TEXT NOT NULL , "
		"  column_type     TEXT , "
		"  is_nullable     INTEGER NOT NULL CHECK(is_nullable IN (0,1)) , "
		"  column_default  TEXT , "
		"  extra           TEXT , "
		"  charset         TEXT , "
		"  collation       TEXT , "
		"  column_comment  TEXT , "
		"  is_pk           INTEGER NOT NULL DEFAULT 0 , "
		"  is_unique       INTEGER NOT NULL DEFAULT 0 , "
		"  is_indexed      INTEGER NOT NULL DEFAULT 0 , "
		"  is_time         INTEGER NOT NULL DEFAULT 0 , "
		"  is_id_like      INTEGER NOT NULL DEFAULT 0 , "
		"  UNIQUE(object_id, column_name) , "
		"  UNIQUE(object_id ,  ordinal_pos)"
		");"
	);

	db->execute("CREATE INDEX IF NOT EXISTS idx_columns_object ON columns(object_id);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_columns_name ON columns(column_name);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_columns_obj_name ON columns(object_id ,  column_name);");

	// Indexes table
	db->execute(
		"CREATE TABLE IF NOT EXISTS indexes ("
		"  index_id      INTEGER PRIMARY KEY , "
		"  object_id     INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  index_name    TEXT NOT NULL , "
		"  is_unique     INTEGER NOT NULL CHECK(is_unique IN (0,1)) , "
		"  is_primary    INTEGER NOT NULL CHECK(is_primary IN (0,1)) , "
		"  index_type    TEXT , "
		"  cardinality   INTEGER , "
		"  UNIQUE(object_id ,  index_name)"
		");"
	);

	// Index columns table
	db->execute(
		"CREATE TABLE IF NOT EXISTS index_columns ("
		"  index_id      INTEGER NOT NULL REFERENCES indexes(index_id) ON DELETE CASCADE , "
		"  seq_in_index  INTEGER NOT NULL , "
		"  column_name   TEXT NOT NULL , "
		"  sub_part      INTEGER , "
		"  collation     TEXT , "
		"  PRIMARY KEY(index_id ,  seq_in_index)"
		");"
	);

	// Foreign keys table
	db->execute(
		"CREATE TABLE IF NOT EXISTS foreign_keys ("
		"  fk_id              INTEGER PRIMARY KEY , "
		"  run_id             INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  child_object_id    INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  fk_name            TEXT , "
		"  parent_schema_name TEXT NOT NULL , "
		"  parent_object_name TEXT NOT NULL , "
		"  on_update          TEXT , "
		"  on_delete          TEXT"
		");"
	);

	db->execute("CREATE INDEX IF NOT EXISTS idx_fk_child ON foreign_keys(run_id ,  child_object_id);");

	// Foreign key columns table
	db->execute(
		"CREATE TABLE IF NOT EXISTS foreign_key_columns ("
		"  fk_id          INTEGER NOT NULL REFERENCES foreign_keys(fk_id) ON DELETE CASCADE , "
		"  seq            INTEGER NOT NULL , "
		"  child_column   TEXT NOT NULL , "
		"  parent_column  TEXT NOT NULL , "
		"  PRIMARY KEY(fk_id ,  seq)"
		");"
	);

	// View dependencies table
	db->execute(
		"CREATE TABLE IF NOT EXISTS view_dependencies ("
		"  view_object_id    INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  depends_on_schema TEXT NOT NULL , "
		"  depends_on_name   TEXT NOT NULL , "
		"  PRIMARY KEY(view_object_id, depends_on_schema ,  depends_on_name)"
		");"
	);

	// Inferred relationships table (deterministic heuristics)
	db->execute(
		"CREATE TABLE IF NOT EXISTS inferred_relationships ("
		"  rel_id           INTEGER PRIMARY KEY , "
		"  run_id           INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  child_object_id  INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  child_column     TEXT NOT NULL , "
		"  parent_object_id INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  parent_column    TEXT NOT NULL , "
		"  confidence       REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0) , "
		"  evidence_json    TEXT , "
		"  UNIQUE(run_id, child_object_id, child_column, parent_object_id ,  parent_column)"
		");"
	);

	db->execute("CREATE INDEX IF NOT EXISTS idx_inferred_conf ON inferred_relationships(run_id ,  confidence);");

	// Profiles table
	db->execute(
		"CREATE TABLE IF NOT EXISTS profiles ("
		"  profile_id    INTEGER PRIMARY KEY , "
		"  run_id        INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  object_id     INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  profile_kind  TEXT NOT NULL , "
		"  profile_json  TEXT NOT NULL , "
		"  updated_at    TEXT NOT NULL DEFAULT (datetime('now')) , "
		"  UNIQUE(run_id, object_id ,  profile_kind)"
		");"
	);

	// Seed documentation
	db->execute(
		"INSERT OR IGNORE INTO schema_docs(doc_key, title ,  body) VALUES"
		"('table:objects', 'Discovered Objects', 'Tables, views, routines, triggers from INFORMATION_SCHEMA') , "
		"('table:columns', 'Column Metadata', 'Column details with derived hints (is_time, is_id_like, etc)') , "
		"('table:llm_object_summaries', 'LLM Object Summaries', 'Structured JSON summaries produced by the LLM agent') , "
		"('table:llm_domains', 'Domain Clusters', 'Semantic domain groupings (billing, sales, auth ,  etc)');"
	);

	// ============================================================
	// MCP QUERY RULES AND DIGEST TABLES
	// ============================================================

	// MCP query rules table
	db->execute(
		"CREATE TABLE IF NOT EXISTS mcp_query_rules ("
		"  rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL ,"
		"  active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 ,"
		"  tool_name VARCHAR ,"
		"  run_id INT ,"
		"  match_pattern VARCHAR ,"
		"  negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 ,"
		"  re_modifiers VARCHAR DEFAULT 'CASELESS' ,"
		"  flagIN INT NOT NULL DEFAULT 0 ,"
		"  flagOUT INT CHECK (flagOUT >= 0) ,"
		"  action VARCHAR CHECK (action IN ('allow','block','rewrite','timeout')) NOT NULL DEFAULT 'allow' ,"
		"  replace_pattern VARCHAR ,"
		"  timeout_ms INT CHECK (timeout_ms >= 0) ,"
		"  error_msg VARCHAR ,"
		"  OK_msg VARCHAR ,"
		"  log INT CHECK (log IN (0,1)) ,"
		"  apply INT CHECK (apply IN (0,1)) NOT NULL DEFAULT 1 ,"
		"  comment VARCHAR ,"
		"  hits INTEGER NOT NULL DEFAULT 0"
		");"
	);

	// MCP query digest statistics table
	db->execute(
		"CREATE TABLE IF NOT EXISTS stats_mcp_query_digest ("
		"  tool_name VARCHAR NOT NULL ,"
		"  run_id INT ,"
		"  digest VARCHAR NOT NULL ,"
		"  digest_text VARCHAR NOT NULL ,"
		"  count_star INTEGER NOT NULL ,"
		"  first_seen INTEGER NOT NULL ,"
		"  last_seen INTEGER NOT NULL ,"
		"  sum_time INTEGER NOT NULL ,"
		"  min_time INTEGER NOT NULL ,"
		"  max_time INTEGER NOT NULL ,"
		"  PRIMARY KEY(tool_name, run_id, digest)"
		");"
	);

	// MCP query digest reset table
	db->execute(
		"CREATE TABLE IF NOT EXISTS stats_mcp_query_digest_reset ("
		"  tool_name VARCHAR NOT NULL ,"
		"  run_id INT ,"
		"  digest VARCHAR NOT NULL ,"
		"  digest_text VARCHAR NOT NULL ,"
		"  count_star INTEGER NOT NULL ,"
		"  first_seen INTEGER NOT NULL ,"
		"  last_seen INTEGER NOT NULL ,"
		"  sum_time INTEGER NOT NULL ,"
		"  min_time INTEGER NOT NULL ,"
		"  max_time INTEGER NOT NULL ,"
		"  PRIMARY KEY(tool_name, run_id, digest)"
		");"
	);

	return 0;
}

int Discovery_Schema::create_llm_tables() {
	// Agent runs table
	db->execute(
		"CREATE TABLE IF NOT EXISTS agent_runs ("
		"  agent_run_id   INTEGER PRIMARY KEY , "
		"  run_id         INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  started_at     TEXT NOT NULL DEFAULT (datetime('now')) , "
		"  finished_at    TEXT , "
		"  model_name     TEXT , "
		"  prompt_hash    TEXT , "
		"  budget_json    TEXT , "
		"  status         TEXT NOT NULL DEFAULT 'running' , "
		"  error          TEXT"
		");"
	);

	db->execute("CREATE INDEX IF NOT EXISTS idx_agent_runs_run ON agent_runs(run_id);");

	// Agent events table
	db->execute(
		"CREATE TABLE IF NOT EXISTS agent_events ("
		"  event_id      INTEGER PRIMARY KEY , "
		"  agent_run_id  INTEGER NOT NULL REFERENCES agent_runs(agent_run_id) ON DELETE CASCADE , "
		"  ts            TEXT NOT NULL DEFAULT (datetime('now')) , "
		"  event_type    TEXT NOT NULL , "
		"  payload_json  TEXT NOT NULL"
		");"
	);

	db->execute("CREATE INDEX IF NOT EXISTS idx_agent_events_run ON agent_events(agent_run_id);");

	// LLM object summaries table
	db->execute(
		"CREATE TABLE IF NOT EXISTS llm_object_summaries ("
		"  summary_id     INTEGER PRIMARY KEY , "
		"  agent_run_id   INTEGER NOT NULL REFERENCES agent_runs(agent_run_id) ON DELETE CASCADE , "
		"  run_id         INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  object_id      INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  summary_json   TEXT NOT NULL , "
		"  confidence     REAL NOT NULL DEFAULT 0.5 CHECK(confidence >= 0.0 AND confidence <= 1.0) , "
		"  status         TEXT NOT NULL DEFAULT 'draft' , "
		"  sources_json   TEXT , "
		"  created_at     TEXT NOT NULL DEFAULT (datetime('now')) , "
		"  UNIQUE(agent_run_id ,  object_id)"
		");"
	);

	db->execute("CREATE INDEX IF NOT EXISTS idx_llm_summaries_obj ON llm_object_summaries(run_id ,  object_id);");

	// LLM relationships table
	db->execute(
		"CREATE TABLE IF NOT EXISTS llm_relationships ("
		"  llm_rel_id       INTEGER PRIMARY KEY , "
		"  agent_run_id     INTEGER NOT NULL REFERENCES agent_runs(agent_run_id) ON DELETE CASCADE , "
		"  run_id           INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  child_object_id  INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  child_column     TEXT NOT NULL , "
		"  parent_object_id INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  parent_column    TEXT NOT NULL , "
		"  rel_type         TEXT NOT NULL DEFAULT 'fk_like' , "
		"  confidence       REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0) , "
		"  evidence_json    TEXT , "
		"  created_at       TEXT NOT NULL DEFAULT (datetime('now')) , "
		"  UNIQUE(agent_run_id, child_object_id, child_column, parent_object_id, parent_column ,  rel_type)"
		");"
	);

	db->execute("CREATE INDEX IF NOT EXISTS idx_llm_rel_conf ON llm_relationships(run_id ,  confidence);");

	// LLM domains table
	db->execute(
		"CREATE TABLE IF NOT EXISTS llm_domains ("
		"  domain_id     INTEGER PRIMARY KEY , "
		"  agent_run_id  INTEGER NOT NULL REFERENCES agent_runs(agent_run_id) ON DELETE CASCADE , "
		"  run_id        INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  domain_key    TEXT NOT NULL , "
		"  title         TEXT , "
		"  description   TEXT , "
		"  confidence    REAL NOT NULL DEFAULT 0.6 CHECK(confidence >= 0.0 AND confidence <= 1.0) , "
		"  created_at    TEXT NOT NULL DEFAULT (datetime('now')) , "
		"  UNIQUE(agent_run_id ,  domain_key)"
		");"
	);

	// LLM domain members table
	db->execute(
		"CREATE TABLE IF NOT EXISTS llm_domain_members ("
		"  domain_id    INTEGER NOT NULL REFERENCES llm_domains(domain_id) ON DELETE CASCADE , "
		"  object_id    INTEGER NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  role         TEXT , "
		"  confidence   REAL NOT NULL DEFAULT 0.6 CHECK(confidence >= 0.0 AND confidence <= 1.0) , "
		"  PRIMARY KEY(domain_id ,  object_id)"
		");"
	);

	// LLM metrics table
	db->execute(
		"CREATE TABLE IF NOT EXISTS llm_metrics ("
		"  metric_id      INTEGER PRIMARY KEY , "
		"  agent_run_id   INTEGER NOT NULL REFERENCES agent_runs(agent_run_id) ON DELETE CASCADE , "
		"  run_id         INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  metric_key     TEXT NOT NULL , "
		"  title          TEXT NOT NULL , "
		"  description    TEXT , "
		"  domain_key     TEXT , "
		"  grain          TEXT , "
		"  unit           TEXT , "
		"  sql_template   TEXT , "
		"  depends_json   TEXT , "
		"  confidence     REAL NOT NULL DEFAULT 0.6 CHECK(confidence >= 0.0 AND confidence <= 1.0) , "
		"  created_at     TEXT NOT NULL DEFAULT (datetime('now')) , "
		"  UNIQUE(agent_run_id ,  metric_key)"
		");"
	);

	db->execute("CREATE INDEX IF NOT EXISTS idx_llm_metrics_domain ON llm_metrics(run_id ,  domain_key);");

	// LLM question templates table
	db->execute(
		"CREATE TABLE IF NOT EXISTS llm_question_templates ("
		"  template_id    INTEGER PRIMARY KEY , "
		"  agent_run_id   INTEGER NOT NULL REFERENCES agent_runs(agent_run_id) ON DELETE CASCADE , "
		"  run_id         INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  title          TEXT NOT NULL , "
		"  question_nl    TEXT NOT NULL , "
		"  template_json  TEXT NOT NULL , "
		"  example_sql    TEXT , "
		"  related_objects TEXT , "
		"  confidence     REAL NOT NULL DEFAULT 0.6 CHECK(confidence >= 0.0 AND confidence <= 1.0) , "
		"  created_at     TEXT NOT NULL DEFAULT (datetime('now'))"
		");"
	);

	db->execute("CREATE INDEX IF NOT EXISTS idx_llm_qtpl_run ON llm_question_templates(run_id);");

	// LLM notes table
	db->execute(
		"CREATE TABLE IF NOT EXISTS llm_notes ("
		"  note_id      INTEGER PRIMARY KEY , "
		"  agent_run_id INTEGER NOT NULL REFERENCES agent_runs(agent_run_id) ON DELETE CASCADE , "
		"  run_id       INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  scope        TEXT NOT NULL , "
		"  object_id    INTEGER REFERENCES objects(object_id) ON DELETE CASCADE , "
		"  domain_key   TEXT , "
		"  title        TEXT , "
		"  body         TEXT NOT NULL , "
		"  tags_json    TEXT , "
		"  created_at   TEXT NOT NULL DEFAULT (datetime('now'))"
		");"
	);

	db->execute("CREATE INDEX IF NOT EXISTS idx_llm_notes_scope ON llm_notes(run_id ,  scope);");

	// LLM search log table - tracks all searches performed
	db->execute(
		"CREATE TABLE IF NOT EXISTS llm_search_log ("
		"  log_id      INTEGER PRIMARY KEY , "
		"  run_id      INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE , "
		"  query       TEXT NOT NULL , "
		"  lmt         INTEGER NOT NULL DEFAULT 25 , "
		"  searched_at TEXT NOT NULL DEFAULT (datetime('now'))"
		");"
	);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Discovery_Schema: llm_search_log table created/verified\n");

	db->execute("CREATE INDEX IF NOT EXISTS idx_llm_search_log_run ON llm_search_log(run_id);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_llm_search_log_query ON llm_search_log(query);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_llm_search_log_time ON llm_search_log(searched_at);");

	// RAG FTS search log table - tracks rag.search_fts operations
	db->execute(
		"CREATE TABLE IF NOT EXISTS rag_search_log ("
		"  log_id      INTEGER PRIMARY KEY AUTOINCREMENT , "
		"  query       TEXT NOT NULL , "
		"  k           INTEGER NOT NULL , "
		"  filters     TEXT , "
		"  searched_at TEXT NOT NULL DEFAULT (datetime('now'))"
		");"
	);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Discovery_Schema: rag_search_log table created/verified\n");

	db->execute("CREATE INDEX IF NOT EXISTS idx_rag_search_log_query ON rag_search_log(query);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_rag_search_log_time ON rag_search_log(searched_at);");

	// Query endpoint tool invocation log - tracks all MCP tool calls via /mcp/query/
	db->execute(
		"CREATE TABLE IF NOT EXISTS query_tool_calls ("
		"  call_id        INTEGER PRIMARY KEY AUTOINCREMENT , "
		"  tool_name      TEXT NOT NULL , "
		"  schema         TEXT , "
		"  run_id         INTEGER , "
		"  start_time     INTEGER NOT NULL , "
		"  execution_time INTEGER NOT NULL , "
		"  error          TEXT , "
		"  called_at      TEXT NOT NULL DEFAULT (datetime('now'))"
		");"
	);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Discovery_Schema: query_tool_calls table created/verified\n");

	db->execute("CREATE INDEX IF NOT EXISTS idx_query_tool_calls_tool ON query_tool_calls(tool_name);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_query_tool_calls_schema ON query_tool_calls(schema);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_query_tool_calls_run ON query_tool_calls(run_id);");
	db->execute("CREATE INDEX IF NOT EXISTS idx_query_tool_calls_time ON query_tool_calls(called_at);");

	return 0;
}

int Discovery_Schema::create_fts_tables() {
	// FTS over objects (contentless)
	if (!db->execute(
		"CREATE VIRTUAL TABLE IF NOT EXISTS fts_objects USING fts5("
		"  object_key, schema_name, object_name, object_type, comment, columns_blob, definition_sql, tags , "
		"  content='' , "
		"  tokenize='unicode61 remove_diacritics 2'"
		");"
	)) {
		proxy_error("Failed to create fts_objects FTS5 table - FTS5 may not be enabled\n");
		return -1;
	}

	// FTS over LLM artifacts - store content directly in FTS table
	if (!db->execute(
		"CREATE VIRTUAL TABLE IF NOT EXISTS fts_llm USING fts5("
		"  kind, key, title, body, tags , "
		"  tokenize='unicode61 remove_diacritics 2'"
		");"
	)) {
		proxy_error("Failed to create fts_llm FTS5 table - FTS5 may not be enabled\n");
		return -1;
	}

	return 0;
}

// ============================================================================
// Run Management
// ============================================================================

int Discovery_Schema::create_run(
	const std::string& target_id,
	const std::string& protocol,
	const std::string& source_dsn,
	const std::string& server_version,
	const std::string& notes
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql = "INSERT INTO runs(target_id, protocol, source_dsn, server_version, notes) VALUES(?1, ?2, ?3, ?4, ?5);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_text)(stmt, 1, target_id.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 2, protocol.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 3, source_dsn.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, server_version.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 5, notes.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);
	int run_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	return run_id;
}

int Discovery_Schema::finish_run(int run_id, const std::string& notes) {
	sqlite3_stmt* stmt = NULL;
	const char* sql = "UPDATE runs SET finished_at = datetime('now') ,  notes = ?1 WHERE run_id = ?2;";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_text)(stmt, 1, notes.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int)(stmt, 2, run_id);

	SAFE_SQLITE3_STEP2(stmt);

	return 0;
}

std::string Discovery_Schema::get_run_info(int run_id) {
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	std::ostringstream sql;
	sql << "SELECT run_id, target_id, protocol, started_at, finished_at, source_dsn, server_version ,  notes "
	    << "FROM runs WHERE run_id = " << run_id << ";";

	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

	json result = json::object();
	if (resultset && !resultset->rows.empty()) {
		SQLite3_row* row = resultset->rows[0];
		result["run_id"] = run_id;
		result["target_id"] = std::string(row->fields[1] ? row->fields[1] : "");
		result["protocol"] = std::string(row->fields[2] ? row->fields[2] : "");
		result["started_at"] = std::string(row->fields[3] ? row->fields[3] : "");
		result["finished_at"] = std::string(row->fields[4] ? row->fields[4] : "");
		result["source_dsn"] = std::string(row->fields[5] ? row->fields[5] : "");
		result["server_version"] = std::string(row->fields[6] ? row->fields[6] : "");
		result["notes"] = std::string(row->fields[7] ? row->fields[7] : "");
	} else {
		result["error"] = "Run not found";
	}

	delete resultset;
	return result.dump();
}

// ============================================================================
// Agent Run Management
// ============================================================================

int Discovery_Schema::create_agent_run(
	int run_id,
	const std::string& model_name,
	const std::string& prompt_hash,
	const std::string& budget_json
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql = "INSERT INTO agent_runs(run_id, model_name, prompt_hash, budget_json) VALUES(?1, ?2, ?3 ,  ?4);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) {
		proxy_error("Failed to prepare agent_runs insert: %s\n", (*proxy_sqlite3_errstr)(rc));
		return -1;
	}

	(*proxy_sqlite3_bind_int)(stmt, 1, run_id);
	(*proxy_sqlite3_bind_text)(stmt, 2, model_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 3, prompt_hash.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, budget_json.c_str(), -1, SQLITE_TRANSIENT);

	// Execute with proper error checking
	int step_rc = SQLITE_OK;
	do {
		step_rc = (*proxy_sqlite3_step)(stmt);
		if (step_rc == SQLITE_LOCKED || step_rc == SQLITE_BUSY) {
			usleep(100);
		}
	} while (step_rc == SQLITE_LOCKED || step_rc == SQLITE_BUSY);

	if (step_rc != SQLITE_DONE) {
		proxy_error("Failed to insert into agent_runs (run_id=%d): %s\n", run_id, (*proxy_sqlite3_errstr)(step_rc));
		return -1;
	}

	int agent_run_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());
	proxy_info("Created agent_run_id=%d for run_id=%d\n", agent_run_id, run_id);
	return agent_run_id;
}

int Discovery_Schema::finish_agent_run(
	int agent_run_id,
	const std::string& status,
	const std::string& error
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql = "UPDATE agent_runs SET finished_at = datetime('now'), status = ?1 ,  error = ?2 WHERE agent_run_id = ?3;";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_text)(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 2, error.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int)(stmt, 3, agent_run_id);

	SAFE_SQLITE3_STEP2(stmt);

	return 0;
}

int Discovery_Schema::get_last_agent_run_id(int run_id) {
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	// First, try to get the last agent_run_id for this specific run_id
	std::ostringstream sql;
	sql << "SELECT agent_run_id FROM agent_runs WHERE run_id = " << run_id
	    << " ORDER BY agent_run_id DESC LIMIT 1;";

	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
	if (error) {
		proxy_error("Failed to get last agent_run_id for run_id %d: %s\n", run_id, error);
		free(error);
		return 0;
	}

	// If found for this run_id, return it
	if (resultset && !resultset->rows.empty()) {
		SQLite3_row* row = resultset->rows[0];
		int agent_run_id = atoi(row->fields[0] ? row->fields[0] : "0");
		delete resultset;
		proxy_info("Found agent_run_id=%d for run_id=%d\n", agent_run_id, run_id);
		return agent_run_id;
	}

	// Clean up first query result
	delete resultset;
	resultset = NULL;

	// Fallback: Get the most recent agent_run_id across ALL runs
	proxy_info("No agent_run found for run_id=%d, falling back to most recent across all runs\n", run_id);
	std::ostringstream fallback_sql;
	fallback_sql << "SELECT agent_run_id FROM agent_runs ORDER BY agent_run_id DESC LIMIT 1;";

	db->execute_statement(fallback_sql.str().c_str(), &error, &cols, &affected, &resultset);
	if (error) {
		proxy_error("Failed to get last agent_run_id (fallback): %s\n", error);
		free(error);
		return 0;
	}

	if (!resultset || resultset->rows.empty()) {
		delete resultset;
		return 0;
	}

	SQLite3_row* row = resultset->rows[0];
	int agent_run_id = atoi(row->fields[0] ? row->fields[0] : "0");
	delete resultset;

	proxy_info("Using fallback agent_run_id=%d (most recent across all runs)\n", agent_run_id);
	return agent_run_id;
}

// ============================================================================
// Schema Management
// ============================================================================

int Discovery_Schema::insert_schema(
	int run_id,
	const std::string& schema_name,
	const std::string& charset,
	const std::string& collation
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql = "INSERT INTO schemas(run_id, schema_name, charset, collation) VALUES(?1, ?2, ?3 ,  ?4);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, run_id);
	(*proxy_sqlite3_bind_text)(stmt, 2, schema_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 3, charset.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, collation.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);
	int schema_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	return schema_id;
}

// ============================================================================
// Object Management
// ============================================================================

int Discovery_Schema::insert_object(
	int run_id,
	const std::string& schema_name,
	const std::string& object_name,
	const std::string& object_type,
	const std::string& engine,
	long table_rows_est,
	long data_length,
	long index_length,
	const std::string& create_time,
	const std::string& update_time,
	const std::string& object_comment,
	const std::string& definition_sql
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO objects("
		"  run_id, schema_name, object_name, object_type, engine, table_rows_est , "
		"  data_length, index_length, create_time, update_time, object_comment ,  definition_sql"
		") VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11 ,  ?12);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, run_id);
	(*proxy_sqlite3_bind_text)(stmt, 2, schema_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 3, object_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, object_type.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 5, engine.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int64)(stmt, 6, (sqlite3_int64)table_rows_est);
	(*proxy_sqlite3_bind_int64)(stmt, 7, (sqlite3_int64)data_length);
	(*proxy_sqlite3_bind_int64)(stmt, 8, (sqlite3_int64)index_length);
	(*proxy_sqlite3_bind_text)(stmt, 9, create_time.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 10, update_time.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 11, object_comment.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 12, definition_sql.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);
	int object_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	return object_id;
}

int Discovery_Schema::insert_column(
	int object_id,
	int ordinal_pos,
	const std::string& column_name,
	const std::string& data_type,
	const std::string& column_type,
	int is_nullable,
	const std::string& column_default,
	const std::string& extra,
	const std::string& charset,
	const std::string& collation,
	const std::string& column_comment,
	int is_pk,
	int is_unique,
	int is_indexed,
	int is_time,
	int is_id_like
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO columns("
		"  object_id, ordinal_pos, column_name, data_type, column_type, is_nullable , "
		"  column_default, extra, charset, collation, column_comment, is_pk, is_unique , "
		"  is_indexed, is_time ,  is_id_like"
		") VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15 ,  ?16);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, object_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, ordinal_pos);
	(*proxy_sqlite3_bind_text)(stmt, 3, column_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, data_type.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 5, column_type.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int)(stmt, 6, is_nullable);
	(*proxy_sqlite3_bind_text)(stmt, 7, column_default.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 8, extra.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 9, charset.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 10, collation.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 11, column_comment.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int)(stmt, 12, is_pk);
	(*proxy_sqlite3_bind_int)(stmt, 13, is_unique);
	(*proxy_sqlite3_bind_int)(stmt, 14, is_indexed);
	(*proxy_sqlite3_bind_int)(stmt, 15, is_time);
	(*proxy_sqlite3_bind_int)(stmt, 16, is_id_like);

	SAFE_SQLITE3_STEP2(stmt);
	int column_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	return column_id;
}

int Discovery_Schema::insert_index(
	int object_id,
	const std::string& index_name,
	int is_unique,
	int is_primary,
	const std::string& index_type,
	long cardinality
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO indexes(object_id, index_name, is_unique, is_primary, index_type ,  cardinality) "
		"VALUES(?1, ?2, ?3, ?4, ?5 ,  ?6);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, object_id);
	(*proxy_sqlite3_bind_text)(stmt, 2, index_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int)(stmt, 3, is_unique);
	(*proxy_sqlite3_bind_int)(stmt, 4, is_primary);
	(*proxy_sqlite3_bind_text)(stmt, 5, index_type.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int64)(stmt, 6, (sqlite3_int64)cardinality);

	SAFE_SQLITE3_STEP2(stmt);
	int index_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	return index_id;
}

int Discovery_Schema::insert_index_column(
	int index_id,
	int seq_in_index,
	const std::string& column_name,
	int sub_part,
	const std::string& collation
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO index_columns(index_id, seq_in_index, column_name, sub_part ,  collation) "
		"VALUES(?1, ?2, ?3, ?4 ,  ?5);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, index_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, seq_in_index);
	(*proxy_sqlite3_bind_text)(stmt, 3, column_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int)(stmt, 4, sub_part);
	(*proxy_sqlite3_bind_text)(stmt, 5, collation.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);

	return 0;
}

int Discovery_Schema::insert_foreign_key(
	int run_id,
	int child_object_id,
	const std::string& fk_name,
	const std::string& parent_schema_name,
	const std::string& parent_object_name,
	const std::string& on_update,
	const std::string& on_delete
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO foreign_keys(run_id, child_object_id, fk_name, parent_schema_name, parent_object_name, on_update ,  on_delete) "
		"VALUES(?1, ?2, ?3, ?4, ?5, ?6 ,  ?7);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, run_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, child_object_id);
	(*proxy_sqlite3_bind_text)(stmt, 3, fk_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, parent_schema_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 5, parent_object_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 6, on_update.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 7, on_delete.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);
	int fk_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	return fk_id;
}

int Discovery_Schema::insert_foreign_key_column(
	int fk_id,
	int seq,
	const std::string& child_column,
	const std::string& parent_column
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO foreign_key_columns(fk_id, seq, child_column ,  parent_column) "
		"VALUES(?1, ?2, ?3 ,  ?4);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, fk_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, seq);
	(*proxy_sqlite3_bind_text)(stmt, 3, child_column.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, parent_column.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);

	return 0;
}

int Discovery_Schema::update_object_flags(int run_id) {
	// Update has_primary_key
	db->execute(
		"UPDATE objects SET has_primary_key = 1 "
		"WHERE run_id = ?1 AND object_id IN (SELECT DISTINCT object_id FROM indexes WHERE is_primary = 1);"
	);

	// Update has_foreign_keys
	db->execute(
		"UPDATE objects SET has_foreign_keys = 1 "
		"WHERE run_id = ?1 AND object_id IN (SELECT DISTINCT child_object_id FROM foreign_keys WHERE run_id = ?1);"
	);

	// Update has_time_column
	db->execute(
		"UPDATE objects SET has_time_column = 1 "
		"WHERE run_id = ?1 AND object_id IN (SELECT DISTINCT object_id FROM columns WHERE is_time = 1);"
	);

	return 0;
}

int Discovery_Schema::upsert_profile(
	int run_id,
	int object_id,
	const std::string& profile_kind,
	const std::string& profile_json
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO profiles(run_id, object_id, profile_kind ,  profile_json) "
		"VALUES(?1, ?2, ?3 ,  ?4) "
		"ON CONFLICT(run_id, object_id ,  profile_kind) DO UPDATE SET "
		"  profile_json = ?4 ,  updated_at = datetime('now');";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, run_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, object_id);
	(*proxy_sqlite3_bind_text)(stmt, 3, profile_kind.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, profile_json.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);

	return 0;
}

int Discovery_Schema::rebuild_fts_index(int run_id) {
	// Check if FTS table exists first
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	db->execute_statement(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='fts_objects';",
		&error, &cols, &affected, &resultset
	);

	bool fts_exists = (resultset && !resultset->rows.empty());
	if (resultset) delete resultset;

	if (!fts_exists) {
		proxy_warning("FTS table fts_objects does not exist - skipping FTS rebuild\n");
		return 0;  // Non-fatal - harvest can continue without FTS
	}

	// Clear existing FTS index for this run only
	std::ostringstream delete_sql;
	delete_sql << "DELETE FROM fts_objects WHERE object_key IN ("
	    << "SELECT schema_name || '.' || object_name FROM objects WHERE run_id = " << run_id
	    << ");";
	if (!db->execute(delete_sql.str().c_str())) {
		proxy_warning("Failed to clear FTS index (non-critical)\n");
		return 0;  // Non-fatal
	}

	// Fetch all objects for the run
	std::ostringstream sql;
	sql << "SELECT object_id, schema_name, object_name, object_type, object_comment ,  definition_sql "
	    << "FROM objects WHERE run_id = " << run_id << ";";

	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
	if (error) {
		proxy_error("FTS rebuild fetch error: %s\n", error);
		return -1;
	}

	// Insert each object into FTS
	if (resultset) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
		     it != resultset->rows.end(); ++it) {
			SQLite3_row* row = *it;

			int object_id = atoi(row->fields[0]);
			std::string schema_name = row->fields[1] ? row->fields[1] : "";
			std::string object_name = row->fields[2] ? row->fields[2] : "";
			std::string object_type = row->fields[3] ? row->fields[3] : "";
			std::string comment = row->fields[4] ? row->fields[4] : "";
			std::string definition = row->fields[5] ? row->fields[5] : "";

			std::string object_key = schema_name + "." + object_name;

			// Build columns blob
			std::ostringstream cols_blob;
			char* error2 = NULL;
			int cols2 = 0, affected2 = 0;
			SQLite3_result* col_result = NULL;

			std::ostringstream col_sql;
			col_sql << "SELECT column_name, data_type ,  column_comment FROM columns "
			        << "WHERE object_id = " << object_id << " ORDER BY ordinal_pos;";

			db->execute_statement(col_sql.str().c_str(), &error2, &cols2, &affected2, &col_result);

			if (col_result) {
				for (std::vector<SQLite3_row*>::iterator cit = col_result->rows.begin();
				     cit != col_result->rows.end(); ++cit) {
					SQLite3_row* col_row = *cit;
					std::string cn = col_row->fields[0] ? col_row->fields[0] : "";
					std::string dt = col_row->fields[1] ? col_row->fields[1] : "";
					std::string cc = col_row->fields[2] ? col_row->fields[2] : "";
					cols_blob << cn << ":" << dt;
					if (!cc.empty()) {
						cols_blob << " " << cc;
					}
					cols_blob << " ";
				}
				delete col_result;
			}

			// Get tags from profile if present
			std::string tags = "";
			std::ostringstream profile_sql;
			profile_sql << "SELECT profile_json FROM profiles "
			            << "WHERE run_id = " << run_id << " AND object_id = " << object_id
			            << " AND profile_kind = 'table_quick';";

			SQLite3_result* prof_result = NULL;
			db->execute_statement(profile_sql.str().c_str(), &error2, &cols2, &affected2, &prof_result);
			if (prof_result && !prof_result->rows.empty()) {
				try {
					json pj = json::parse(prof_result->rows[0]->fields[0]);
					if (pj.contains("guessed_kind")) {
						tags = pj["guessed_kind"].get<std::string>();
					}
				} catch (...) {
					// Ignore parse errors
				}
				delete prof_result;
			}

			// Insert into FTS
			sqlite3_stmt* fts_stmt = NULL;
			const char* fts_sql =
				"INSERT INTO fts_objects(object_key, schema_name, object_name, object_type, comment, columns_blob, definition_sql ,  tags) "
				"VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7 ,  ?8);";

			auto [rc, fts_stmt_unique] = db->prepare_v2(fts_sql);
			fts_stmt = fts_stmt_unique.get();
			if (rc == SQLITE_OK) {
				(*proxy_sqlite3_bind_text)(fts_stmt, 1, object_key.c_str(), -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_text)(fts_stmt, 2, schema_name.c_str(), -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_text)(fts_stmt, 3, object_name.c_str(), -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_text)(fts_stmt, 4, object_type.c_str(), -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_text)(fts_stmt, 5, comment.c_str(), -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_text)(fts_stmt, 6, cols_blob.str().c_str(), -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_text)(fts_stmt, 7, definition.c_str(), -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_text)(fts_stmt, 8, tags.c_str(), -1, SQLITE_TRANSIENT);

				SAFE_SQLITE3_STEP2(fts_stmt);
			}
		}
		delete resultset;
	}

	return 0;
}

std::string Discovery_Schema::fts_search(
	int run_id,
	const std::string& query,
	int limit,
	const std::string& object_type,
	const std::string& schema_name
) {
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	std::ostringstream sql;
	sql << "SELECT object_key, schema_name, object_name, object_type, tags ,  bm25(fts_objects) AS score "
	    << "FROM fts_objects WHERE fts_objects MATCH '" << query << "'";

	if (!object_type.empty()) {
		sql << " AND object_type = '" << object_type << "'";
	}
	if (!schema_name.empty()) {
		sql << " AND schema_name = '" << schema_name << "'";
	}

	sql << " ORDER BY score LIMIT " << limit << ";";

	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

	json results = json::array();
	if (resultset) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
		     it != resultset->rows.end(); ++it) {
			SQLite3_row* row = *it;

			json item;
			item["object_key"] = std::string(row->fields[0] ? row->fields[0] : "");
			item["schema_name"] = std::string(row->fields[1] ? row->fields[1] : "");
			item["object_name"] = std::string(row->fields[2] ? row->fields[2] : "");
			item["object_type"] = std::string(row->fields[3] ? row->fields[3] : "");
			item["tags"] = std::string(row->fields[4] ? row->fields[4] : "");
			item["score"] = atof(row->fields[5] ? row->fields[5] : "0");

			results.push_back(item);
		}
		delete resultset;
	}

	return results.dump();
}

std::string Discovery_Schema::get_object(
	int run_id,
	int object_id,
	const std::string& schema_name,
	const std::string& object_name,
	bool include_definition,
	bool include_profiles
) {
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	std::ostringstream sql;
	sql << "SELECT o.object_id, o.schema_name, o.object_name, o.object_type, o.engine ,  "
	    << "o.table_rows_est, o.data_length, o.index_length, o.create_time, o.update_time ,  "
	    << "o.object_comment, o.has_primary_key, o.has_foreign_keys ,  o.has_time_column "
	    << "FROM objects o WHERE o.run_id = " << run_id;

	if (object_id > 0) {
		sql << " AND o.object_id = " << object_id;
	} else {
		sql << " AND o.schema_name = '" << schema_name << "' AND o.object_name = '" << object_name << "'";
	}

	sql << ";";

	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
	if (!resultset || resultset->rows.empty()) {
		delete resultset;
		return "null";
	}

	SQLite3_row* row = resultset->rows[0];

	json result;
	result["object_id"] = atoi(row->fields[0]);
	result["schema_name"] = std::string(row->fields[1] ? row->fields[1] : "");
	result["object_name"] = std::string(row->fields[2] ? row->fields[2] : "");
	result["object_type"] = std::string(row->fields[3] ? row->fields[3] : "");
	result["engine"] = row->fields[4] ? std::string(row->fields[4]) : "";
	result["table_rows_est"] = row->fields[5] ? atol(row->fields[5]) : 0;
	result["data_length"] = row->fields[6] ? atol(row->fields[6]) : 0;
	result["index_length"] = row->fields[7] ? atol(row->fields[7]) : 0;
	result["create_time"] = row->fields[8] ? std::string(row->fields[8]) : "";
	result["update_time"] = row->fields[9] ? std::string(row->fields[9]) : "";
	result["object_comment"] = row->fields[10] ? std::string(row->fields[10]) : "";
	result["has_primary_key"] = atoi(row->fields[11]);
	result["has_foreign_keys"] = atoi(row->fields[12]);
	result["has_time_column"] = atoi(row->fields[13]);

	delete resultset;
	resultset = NULL;

	int obj_id = result["object_id"];

	// Get columns
	int cols2 = 0, affected2 = 0;
	SQLite3_result* col_result = NULL;
	std::ostringstream col_sql;
	col_sql << "SELECT column_name, data_type, column_type, is_nullable, column_default, extra ,  "
	        << "charset, collation, column_comment, is_pk, is_unique, is_indexed, is_time ,  is_id_like "
	        << "FROM columns WHERE object_id = " << obj_id << " ORDER BY ordinal_pos;";

	db->execute_statement(col_sql.str().c_str(), &error, &cols2, &affected2, &col_result);
	if (col_result) {
		json columns = json::array();
		for (std::vector<SQLite3_row*>::iterator cit = col_result->rows.begin();
		     cit != col_result->rows.end(); ++cit) {
			SQLite3_row* col = *cit;
			json c;
			c["column_name"] = std::string(col->fields[0] ? col->fields[0] : "");
			c["data_type"] = std::string(col->fields[1] ? col->fields[1] : "");
			c["column_type"] = col->fields[2] ? std::string(col->fields[2]) : "";
			c["is_nullable"] = atoi(col->fields[3]);
			c["column_default"] = col->fields[4] ? std::string(col->fields[4]) : "";
			c["extra"] = col->fields[5] ? std::string(col->fields[5]) : "";
			c["charset"] = col->fields[6] ? std::string(col->fields[6]) : "";
			c["collation"] = col->fields[7] ? std::string(col->fields[7]) : "";
			c["column_comment"] = col->fields[8] ? std::string(col->fields[8]) : "";
			c["is_pk"] = atoi(col->fields[9]);
			c["is_unique"] = atoi(col->fields[10]);
			c["is_indexed"] = atoi(col->fields[11]);
			c["is_time"] = atoi(col->fields[12]);
			c["is_id_like"] = atoi(col->fields[13]);
			columns.push_back(c);
		}
		result["columns"] = columns;
		delete col_result;
	}

	// Get indexes
	std::ostringstream idx_sql;
	idx_sql << "SELECT i.index_name, i.is_unique, i.is_primary, i.index_type, i.cardinality ,  "
	        << "ic.seq_in_index, ic.column_name, ic.sub_part ,  ic.collation "
	        << "FROM indexes i LEFT JOIN index_columns ic ON i.index_id = ic.index_id "
	        << "WHERE i.object_id = " << obj_id << " ORDER BY i.index_name ,  ic.seq_in_index;";

	SQLite3_result* idx_result = NULL;
	db->execute_statement(idx_sql.str().c_str(), &error, &cols, &affected, &idx_result);
	if (idx_result) {
		json indexes = json::array();
		std::string last_idx_name = "";
		json current_idx;
		json columns;

		for (std::vector<SQLite3_row*>::iterator iit = idx_result->rows.begin();
		     iit != idx_result->rows.end(); ++iit) {
			SQLite3_row* idx_row = *iit;
			std::string idx_name = std::string(idx_row->fields[0] ? idx_row->fields[0] : "");

			if (idx_name != last_idx_name) {
				if (!last_idx_name.empty()) {
					current_idx["columns"] = columns;
					indexes.push_back(current_idx);
					columns = json::array();
				}
				current_idx = json::object();
				current_idx["index_name"] = idx_name;
				current_idx["is_unique"] = atoi(idx_row->fields[1]);
				current_idx["is_primary"] = atoi(idx_row->fields[2]);
				current_idx["index_type"] = std::string(idx_row->fields[3] ? idx_row->fields[3] : "");
				current_idx["cardinality"] = atol(idx_row->fields[4] ? idx_row->fields[4] : "0");
				last_idx_name = idx_name;
			}

			json col;
			col["seq_in_index"] = atoi(idx_row->fields[5]);
			col["column_name"] = std::string(idx_row->fields[6] ? idx_row->fields[6] : "");
			col["sub_part"] = atoi(idx_row->fields[7] ? idx_row->fields[7] : "0");
			col["collation"] = std::string(idx_row->fields[8] ? idx_row->fields[8] : "");
			columns.push_back(col);
		}

		if (!last_idx_name.empty()) {
			current_idx["columns"] = columns;
			indexes.push_back(current_idx);
		}

		result["indexes"] = indexes;
		delete idx_result;
	}

	// Get profiles
	if (include_profiles) {
		std::ostringstream prof_sql;
		prof_sql << "SELECT profile_kind ,  profile_json FROM profiles "
		         << "WHERE run_id = " << run_id << " AND object_id = " << obj_id << ";";

		SQLite3_result* prof_result = NULL;
		db->execute_statement(prof_sql.str().c_str(), &error, &cols, &affected, &prof_result);
		if (prof_result) {
			json profiles = json::object();
			for (std::vector<SQLite3_row*>::iterator pit = prof_result->rows.begin();
			     pit != prof_result->rows.end(); ++pit) {
				SQLite3_row* prof = *pit;
				std::string kind = std::string(prof->fields[0] ? prof->fields[0] : "");
				std::string pj = std::string(prof->fields[1] ? prof->fields[1] : "");
				try {
					profiles[kind] = json::parse(pj);
				} catch (...) {
					profiles[kind] = pj;
				}
			}
			result["profiles"] = profiles;
			delete prof_result;
		}
	}

	return result.dump();
}

std::string Discovery_Schema::list_objects(
	int run_id,
	const std::string& schema_name,
	const std::string& object_type,
	const std::string& order_by,
	int page_size,
	const std::string& page_token
) {
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	std::ostringstream sql;
	sql << "SELECT object_id, schema_name, object_name, object_type, engine, table_rows_est ,  "
	    << "data_length, index_length, has_primary_key, has_foreign_keys ,  has_time_column "
	    << "FROM objects WHERE run_id = " << run_id;

	if (!schema_name.empty()) {
		sql << " AND schema_name = '" << schema_name << "'";
	}
	if (!object_type.empty()) {
		sql << " AND object_type = '" << object_type << "'";
	}

	// Order by
	if (order_by == "rows_est_desc") {
		sql << " ORDER BY table_rows_est DESC";
	} else if (order_by == "size_desc") {
		sql << " ORDER BY (data_length + index_length) DESC";
	} else {
		sql << " ORDER BY schema_name ,  object_name";
	}

	// Pagination
	int offset = 0;
	if (!page_token.empty()) {
		offset = atoi(page_token.c_str());
	}

	sql << " LIMIT " << page_size << " OFFSET " << offset << ";";

	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

	json results = json::array();
	if (resultset) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
		     it != resultset->rows.end(); ++it) {
			SQLite3_row* row = *it;

			json item;
			item["object_id"] = atoi(row->fields[0]);
			item["schema_name"] = std::string(row->fields[1] ? row->fields[1] : "");
			item["object_name"] = std::string(row->fields[2] ? row->fields[2] : "");
			item["object_type"] = std::string(row->fields[3] ? row->fields[3] : "");
			item["engine"] = row->fields[4] ? std::string(row->fields[4]) : "";
			item["table_rows_est"] = row->fields[5] ? atol(row->fields[5]) : 0;
			item["data_length"] = row->fields[6] ? atol(row->fields[6]) : 0;
			item["index_length"] = row->fields[7] ? atol(row->fields[7]) : 0;
			item["has_primary_key"] = atoi(row->fields[8]);
			item["has_foreign_keys"] = atoi(row->fields[9]);
			item["has_time_column"] = atoi(row->fields[10]);

			results.push_back(item);
		}
		delete resultset;
	}

	json response;
	response["results"] = results;

	// Next page token
	if ((int)results.size() >= page_size) {
		response["next_page_token"] = std::to_string(offset + page_size);
	} else {
		response["next_page_token"] = "";
	}

	return response.dump();
}

std::string Discovery_Schema::get_relationships(
	int run_id,
	int object_id,
	bool include_inferred,
	double min_confidence
) {
	json result;
	result["foreign_keys"] = json::array();
	result["view_dependencies"] = json::array();
	result["inferred_relationships"] = json::array();

	// Get foreign keys (child FKs)
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	std::ostringstream fk_sql;
	fk_sql << "SELECT fk.fk_name, fk.parent_schema_name, fk.parent_object_name, fk.on_update, fk.on_delete ,  "
	        << "fkc.seq, fkc.child_column ,  fkc.parent_column "
	        << "FROM foreign_keys fk JOIN foreign_key_columns fkc ON fk.fk_id = fkc.fk_id "
	        << "WHERE fk.run_id = " << run_id << " AND fk.child_object_id = " << object_id << " "
	        << "ORDER BY fk.fk_name ,  fkc.seq;";

	db->execute_statement(fk_sql.str().c_str(), &error, &cols, &affected, &resultset);
	if (resultset) {
		std::string last_fk_name = "";
		json current_fk;
		json columns;

		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
		     it != resultset->rows.end(); ++it) {
			SQLite3_row* row = *it;
			std::string fk_name = std::string(row->fields[0] ? row->fields[0] : "");

			if (fk_name != last_fk_name) {
				if (!last_fk_name.empty()) {
					current_fk["columns"] = columns;
					result["foreign_keys"].push_back(current_fk);
					columns = json::array();
				}
				current_fk = json::object();
				current_fk["fk_name"] = fk_name;
				current_fk["parent_schema_name"] = std::string(row->fields[1] ? row->fields[1] : "");
				current_fk["parent_object_name"] = std::string(row->fields[2] ? row->fields[2] : "");
				current_fk["on_update"] = row->fields[3] ? std::string(row->fields[3]) : "";
				current_fk["on_delete"] = row->fields[4] ? std::string(row->fields[4]) : "";
				last_fk_name = fk_name;
			}

			json col;
			col["child_column"] = std::string(row->fields[6] ? row->fields[6] : "");
			col["parent_column"] = std::string(row->fields[7] ? row->fields[7] : "");
			columns.push_back(col);
		}

		if (!last_fk_name.empty()) {
			current_fk["columns"] = columns;
			result["foreign_keys"].push_back(current_fk);
		}

		delete resultset;
	}

	// Get inferred relationships if requested
	if (include_inferred) {
		std::ostringstream inf_sql;
		inf_sql << "SELECT ir.child_column, o2.schema_name, o2.object_name, ir.parent_column ,  "
		        << "ir.confidence ,  ir.evidence_json "
		        << "FROM inferred_relationships ir "
		        << "JOIN objects o2 ON ir.parent_object_id = o2.object_id "
		        << "WHERE ir.run_id = " << run_id << " AND ir.child_object_id = " << object_id
		        << " AND ir.confidence >= " << min_confidence << ";";

		resultset = NULL;
		db->execute_statement(inf_sql.str().c_str(), &error, &cols, &affected, &resultset);
		if (resultset) {
			for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
			     it != resultset->rows.end(); ++it) {
				SQLite3_row* row = *it;

				json rel;
				rel["child_column"] = std::string(row->fields[0] ? row->fields[0] : "");
				rel["parent_schema_name"] = std::string(row->fields[1] ? row->fields[1] : "");
				rel["parent_object_name"] = std::string(row->fields[2] ? row->fields[2] : "");
				rel["parent_column"] = std::string(row->fields[3] ? row->fields[3] : "");
				rel["confidence"] = atof(row->fields[4] ? row->fields[4] : "0");

				try {
					rel["evidence"] = json::parse(row->fields[5] ? row->fields[5] : "{}");
				} catch (...) {
					rel["evidence"] = {};
				}

				result["inferred_relationships"].push_back(rel);
			}
			delete resultset;
		}
	}

	return result.dump();
}

int Discovery_Schema::append_agent_event(
	int agent_run_id,
	const std::string& event_type,
	const std::string& payload_json
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql = "INSERT INTO agent_events(agent_run_id, event_type, payload_json) VALUES(?1, ?2 ,  ?3);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, agent_run_id);
	(*proxy_sqlite3_bind_text)(stmt, 2, event_type.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 3, payload_json.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);
	int event_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	return event_id;
}

int Discovery_Schema::upsert_llm_summary(
	int agent_run_id,
	int run_id,
	int object_id,
	const std::string& summary_json,
	double confidence,
	const std::string& status,
	const std::string& sources_json
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO llm_object_summaries(agent_run_id, run_id, object_id, summary_json, confidence, status ,  sources_json) "
		"VALUES(?1, ?2, ?3, ?4, ?5, ?6 ,  ?7) "
		"ON CONFLICT(agent_run_id ,  object_id) DO UPDATE SET "
		"  summary_json = ?4, confidence = ?5, status = ?6 ,  sources_json = ?7;";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, agent_run_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, run_id);
	(*proxy_sqlite3_bind_int)(stmt, 3, object_id);
	(*proxy_sqlite3_bind_text)(stmt, 4, summary_json.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_double)(stmt, 5, confidence);
	(*proxy_sqlite3_bind_text)(stmt, 6, status.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 7, sources_json.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);

	// Insert into FTS index (use INSERT OR REPLACE for upsert semantics)
	stmt = NULL;
	sql = "INSERT OR REPLACE INTO fts_llm(rowid, kind, key, title, body, tags) VALUES(?1, 'summary', ?2, 'Object Summary', ?3, '');";
	auto [fts_rc, fts_stmt_unique] = db->prepare_v2(sql);
	stmt = fts_stmt_unique.get();
	if (fts_rc == SQLITE_OK) {
		// Create composite key for unique identification
		char key_buf[64];
		snprintf(key_buf, sizeof(key_buf), "summary_%d_%d", agent_run_id, object_id);
		// Use hash of composite key as rowid
		int rowid = agent_run_id * 100000 + object_id;

		(*proxy_sqlite3_bind_int)(stmt, 1, rowid);
		(*proxy_sqlite3_bind_text)(stmt, 2, key_buf, -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 3, summary_json.c_str(), -1, SQLITE_TRANSIENT);
		SAFE_SQLITE3_STEP2(stmt);
	}

	return 0;
}

std::string Discovery_Schema::get_llm_summary(
	int run_id,
	int object_id,
	int agent_run_id,
	bool latest
) {
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	std::ostringstream sql;
	sql << "SELECT summary_json, confidence, status ,  sources_json FROM llm_object_summaries "
	    << "WHERE run_id = " << run_id << " AND object_id = " << object_id;

	if (agent_run_id > 0) {
		sql << " AND agent_run_id = " << agent_run_id;
	} else if (latest) {
		sql << " ORDER BY created_at DESC LIMIT 1";
	}

	sql << ";";

	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

	if (!resultset || resultset->rows.empty()) {
		delete resultset;
		return "null";
	}

	SQLite3_row* row = resultset->rows[0];

	json result;
	result["summary_json"] = std::string(row->fields[0] ? row->fields[0] : "");
	result["confidence"] = atof(row->fields[1] ? row->fields[1] : "0");
	result["status"] = std::string(row->fields[2] ? row->fields[2] : "");
	result["sources_json"] = row->fields[3] ? std::string(row->fields[3]) : "";

	delete resultset;
	return result.dump();
}

int Discovery_Schema::upsert_llm_relationship(
	int agent_run_id,
	int run_id,
	int child_object_id,
	const std::string& child_column,
	int parent_object_id,
	const std::string& parent_column,
	const std::string& rel_type,
	double confidence,
	const std::string& evidence_json
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO llm_relationships(agent_run_id, run_id, child_object_id, child_column, parent_object_id, parent_column, rel_type, confidence ,  evidence_json) "
		"VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 ,  ?9) "
		"ON CONFLICT(agent_run_id, child_object_id, child_column, parent_object_id, parent_column ,  rel_type) "
		"DO UPDATE SET confidence = ?8 ,  evidence_json = ?9;";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, agent_run_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, run_id);
	(*proxy_sqlite3_bind_int)(stmt, 3, child_object_id);
	(*proxy_sqlite3_bind_text)(stmt, 4, child_column.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int)(stmt, 5, parent_object_id);
	(*proxy_sqlite3_bind_text)(stmt, 6, parent_column.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 7, rel_type.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_double)(stmt, 8, confidence);
	(*proxy_sqlite3_bind_text)(stmt, 9, evidence_json.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);

	return 0;
}

int Discovery_Schema::upsert_llm_domain(
	int agent_run_id,
	int run_id,
	const std::string& domain_key,
	const std::string& title,
	const std::string& description,
	double confidence
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO llm_domains(agent_run_id, run_id, domain_key, title, description ,  confidence) "
		"VALUES(?1, ?2, ?3, ?4, ?5 ,  ?6) "
		"ON CONFLICT(agent_run_id ,  domain_key) DO UPDATE SET "
		"  title = ?4, description = ?5 ,  confidence = ?6;";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, agent_run_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, run_id);
	(*proxy_sqlite3_bind_text)(stmt, 3, domain_key.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, title.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 5, description.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_double)(stmt, 6, confidence);

	SAFE_SQLITE3_STEP2(stmt);
	int domain_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	// Insert into FTS index (use INSERT OR REPLACE for upsert semantics)
	stmt = NULL;
	sql = "INSERT OR REPLACE INTO fts_llm(rowid, kind, key, title, body, tags) VALUES(?1, 'domain', ?2, ?3, ?4, '');";
	auto [fts_rc, fts_stmt_unique] = db->prepare_v2(sql);
	stmt = fts_stmt_unique.get();
	if (fts_rc == SQLITE_OK) {
		// Use domain_id or a hash of domain_key as rowid
		int rowid = domain_id > 0 ? domain_id : std::hash<std::string>{}(domain_key) % 1000000000;
		(*proxy_sqlite3_bind_int)(stmt, 1, rowid);
		(*proxy_sqlite3_bind_text)(stmt, 2, domain_key.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 3, title.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 4, description.c_str(), -1, SQLITE_TRANSIENT);
		SAFE_SQLITE3_STEP2(stmt);
	}

	return domain_id;
}

int Discovery_Schema::set_domain_members(
	int agent_run_id,
	int run_id,
	const std::string& domain_key,
	const std::string& members_json
) {
	// First, get the domain_id
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	std::ostringstream sql;
	sql << "SELECT domain_id FROM llm_domains "
	    << "WHERE agent_run_id = " << agent_run_id << " AND domain_key = '" << domain_key << "';";

	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
	if (!resultset || resultset->rows.empty()) {
		delete resultset;
		return -1;
	}

	int domain_id = atoi(resultset->rows[0]->fields[0]);
	delete resultset;

	// Delete existing members
	std::ostringstream del_sql;
	del_sql << "DELETE FROM llm_domain_members WHERE domain_id = " << domain_id << ";";
	db->execute(del_sql.str().c_str());

	// Insert new members
	try {
		json members = json::parse(members_json);
		for (json::iterator it = members.begin(); it != members.end(); ++it) {
			json member = *it;
			int object_id = member["object_id"];
			std::string role = member.value("role" ,  "");
			double confidence = member.value("confidence", 0.6);

			sqlite3_stmt* stmt = NULL;
			const char* ins_sql = "INSERT INTO llm_domain_members(domain_id, object_id, role, confidence) VALUES(?1, ?2, ?3 ,  ?4);";

			auto [rc, stmt_unique] = db->prepare_v2(ins_sql);
			stmt = stmt_unique.get();
			if (rc == SQLITE_OK) {
				(*proxy_sqlite3_bind_int)(stmt, 1, domain_id);
				(*proxy_sqlite3_bind_int)(stmt, 2, object_id);
				(*proxy_sqlite3_bind_text)(stmt, 3, role.c_str(), -1, SQLITE_TRANSIENT);
				(*proxy_sqlite3_bind_double)(stmt, 4, confidence);

				SAFE_SQLITE3_STEP2(stmt);
			}
		}
	} catch (...) {
		return -1;
	}

	return 0;
}

int Discovery_Schema::upsert_llm_metric(
	int agent_run_id,
	int run_id,
	const std::string& metric_key,
	const std::string& title,
	const std::string& description,
	const std::string& domain_key,
	const std::string& grain,
	const std::string& unit,
	const std::string& sql_template,
	const std::string& depends_json,
	double confidence
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO llm_metrics(agent_run_id, run_id, metric_key, title, description, domain_key, grain, unit, sql_template, depends_json ,  confidence) "
		"VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10 ,  ?11) "
		"ON CONFLICT(agent_run_id ,  metric_key) DO UPDATE SET "
		"  title = ?4, description = ?5, domain_key = ?6, grain = ?7, unit = ?8, sql_template = ?9, depends_json = ?10 ,  confidence = ?11;";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, agent_run_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, run_id);
	(*proxy_sqlite3_bind_text)(stmt, 3, metric_key.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, title.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 5, description.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 6, domain_key.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 7, grain.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 8, unit.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 9, sql_template.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 10, depends_json.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_double)(stmt, 11, confidence);

	SAFE_SQLITE3_STEP2(stmt);
	int metric_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	// Insert into FTS index (use INSERT OR REPLACE for upsert semantics)
	stmt = NULL;
	sql = "INSERT OR REPLACE INTO fts_llm(rowid, kind, key, title, body, tags) VALUES(?1, 'metric', ?2, ?3, ?4, ?5);";
	auto [fts_rc, fts_stmt_unique] = db->prepare_v2(sql);
	stmt = fts_stmt_unique.get();
	if (fts_rc == SQLITE_OK) {
		// Use metric_id or a hash of metric_key as rowid
		int rowid = metric_id > 0 ? metric_id : std::hash<std::string>{}(metric_key) % 1000000000;
		(*proxy_sqlite3_bind_int)(stmt, 1, rowid);
		(*proxy_sqlite3_bind_text)(stmt, 2, metric_key.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 3, title.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 4, description.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 5, domain_key.c_str(), -1, SQLITE_TRANSIENT);
		SAFE_SQLITE3_STEP2(stmt);
	}

	return metric_id;
}

int Discovery_Schema::add_question_template(
	int agent_run_id,
	int run_id,
	const std::string& title,
	const std::string& question_nl,
	const std::string& template_json,
	const std::string& example_sql,
	const std::string& related_objects,
	double confidence
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO llm_question_templates(agent_run_id, run_id, title, question_nl, template_json, example_sql, related_objects, confidence) "
		"VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, agent_run_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, run_id);
	(*proxy_sqlite3_bind_text)(stmt, 3, title.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 4, question_nl.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 5, template_json.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 6, example_sql.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 7, related_objects.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_double)(stmt, 8, confidence);

	SAFE_SQLITE3_STEP2(stmt);
	int template_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	// Insert into FTS index
	stmt = NULL;
	sql = "INSERT INTO fts_llm(rowid, kind, key, title, body, tags) VALUES(?1, 'question_template', ?2, ?3, ?4, '');";
	auto [fts_rc, fts_stmt_unique] = db->prepare_v2(sql);
	stmt = fts_stmt_unique.get();
	if (fts_rc == SQLITE_OK) {
		std::string key_str = std::to_string(template_id);
		(*proxy_sqlite3_bind_int)(stmt, 1, template_id);
		(*proxy_sqlite3_bind_text)(stmt, 2, key_str.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 3, title.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 4, question_nl.c_str(), -1, SQLITE_TRANSIENT);
		SAFE_SQLITE3_STEP2(stmt);
	}

	return template_id;
}

int Discovery_Schema::add_llm_note(
	int agent_run_id,
	int run_id,
	const std::string& scope,
	int object_id,
	const std::string& domain_key,
	const std::string& title,
	const std::string& body,
	const std::string& tags_json
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql =
		"INSERT INTO llm_notes(agent_run_id, run_id, scope, object_id, domain_key, title, body ,  tags_json) "
		"VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7 ,  ?8);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK) return -1;

	(*proxy_sqlite3_bind_int)(stmt, 1, agent_run_id);
	(*proxy_sqlite3_bind_int)(stmt, 2, run_id);
	(*proxy_sqlite3_bind_text)(stmt, 3, scope.c_str(), -1, SQLITE_TRANSIENT);
	if (object_id > 0) {
		(*proxy_sqlite3_bind_int)(stmt, 4, object_id);
	} else {
		(*proxy_sqlite3_bind_null)(stmt, 4);
	}
	(*proxy_sqlite3_bind_text)(stmt, 5, domain_key.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 6, title.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 7, body.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 8, tags_json.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);
	int note_id = (int)(*proxy_sqlite3_last_insert_rowid)(db->get_db());

	// Insert into FTS index
	stmt = NULL;
	sql = "INSERT INTO fts_llm(rowid, kind, key, title, body, tags) VALUES(?1, 'note', ?2, ?3, ?4, ?5);";
	auto [fts_rc, fts_stmt_unique] = db->prepare_v2(sql);
	stmt = fts_stmt_unique.get();
	if (fts_rc == SQLITE_OK) {
		std::string key_str = std::to_string(note_id);
		(*proxy_sqlite3_bind_int)(stmt, 1, note_id);
		(*proxy_sqlite3_bind_text)(stmt, 2, key_str.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 3, title.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 4, body.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 5, tags_json.c_str(), -1, SQLITE_TRANSIENT);
		SAFE_SQLITE3_STEP2(stmt);
	}

	return note_id;
}

std::string Discovery_Schema::fts_search_llm(
	int run_id,
	const std::string& query,
	int limit,
	bool include_objects
) {
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	std::ostringstream sql;
	// Empty query returns all results (list mode), otherwise search
	// LEFT JOIN with llm_question_templates to get complete question template data
	if (query.empty()) {
		sql << "SELECT f.kind, f.key, f.title, f.body, 0.0 AS score, "
		    << "qt.example_sql, qt.related_objects, qt.template_json, qt.confidence "
		    << "FROM fts_llm f "
		    << "LEFT JOIN llm_question_templates qt ON CAST(f.key AS INT) = qt.template_id "
		    << "ORDER BY f.kind, f.title LIMIT " << limit << ";";
	} else {
		sql << "SELECT f.kind, f.key, f.title, f.body, bm25(fts_llm) AS score, "
		    << "qt.example_sql, qt.related_objects, qt.template_json, qt.confidence "
		    << "FROM fts_llm f "
		    << "LEFT JOIN llm_question_templates qt ON CAST(f.key AS INT) = qt.template_id "
		    << "WHERE f.fts_llm MATCH '" << query << "' ORDER BY score LIMIT " << limit << ";";
	}

	db->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
	if (error) {
		proxy_error("FTS search error: %s\n", error);
		free(error);
		return "[]";
	}

	json results = json::array();
	if (resultset) {
		// Collect unique object names for fetching details
		std::set<std::string> objects_to_fetch;

		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
		     it != resultset->rows.end(); ++it) {
			SQLite3_row* row = *it;

			json item;
			item["kind"] = std::string(row->fields[0] ? row->fields[0] : "");
			item["key"] = std::string(row->fields[1] ? row->fields[1] : "");
			item["title"] = std::string(row->fields[2] ? row->fields[2] : "");
			item["body"] = std::string(row->fields[3] ? row->fields[3] : "");
			item["score"] = atof(row->fields[4] ? row->fields[4] : "0");

			// Question template fields (may be NULL for non-templates)
			if (row->fields[5] && row->fields[5][0]) {
				item["example_sql"] = std::string(row->fields[5]);
			} else {
				item["example_sql"] = json();
			}

			if (row->fields[6] && row->fields[6][0]) {
				try {
					item["related_objects"] = json::parse(row->fields[6]);
				} catch (...) {
					item["related_objects"] = json::array();
				}
			} else {
				item["related_objects"] = json::array();
			}

			if (row->fields[7] && row->fields[7][0]) {
				try {
					item["template_json"] = json::parse(row->fields[7]);
				} catch (...) {
					item["template_json"] = json();
				}
			} else {
				item["template_json"] = json();
			}

			item["confidence"] = (row->fields[8]) ? atof(row->fields[8]) : 0.0;

			// Collect objects to fetch if include_objects
			if (include_objects && item.contains("related_objects") &&
			    item["related_objects"].is_array()) {
				for (const auto& obj : item["related_objects"]) {
					if (obj.is_string()) {
						objects_to_fetch.insert(obj.get<std::string>());
					}
				}
			}

			results.push_back(item);
		}
		delete resultset;

		// If include_objects AND query is not empty (search mode), fetch object details
		// For list mode (empty query), we don't include objects to avoid huge responses
		if (include_objects && !query.empty()) {
			proxy_info("FTS search: include_objects=true (search mode), objects_to_fetch size=%zu\n", objects_to_fetch.size());
		}

		if (include_objects && !query.empty() && !objects_to_fetch.empty()) {
			proxy_info("FTS search: Fetching object details for %zu objects\n", objects_to_fetch.size());

			// First, build a map of object_name -> schema_name by querying the objects table
			std::map<std::string, std::string> object_to_schema;
			{
				std::ostringstream obj_sql;
				obj_sql << "SELECT DISTINCT object_name, schema_name FROM objects WHERE run_id = " << run_id << " AND object_name IN (";
				bool first = true;
				for (const auto& obj_name : objects_to_fetch) {
					if (!first) obj_sql << ", ";
					obj_sql << "'" << obj_name << "'";
					first = false;
				}
				obj_sql << ");";

				proxy_info("FTS search: object lookup SQL: %s\n", obj_sql.str().c_str());

				SQLite3_result* obj_resultset = NULL;
				char* obj_error = NULL;
				db->execute_statement(obj_sql.str().c_str(), &obj_error, &cols, &affected, &obj_resultset);
				if (obj_error) {
					proxy_error("FTS search: object lookup query failed: %s\n", obj_error);
					free(obj_error);
				}
				if (obj_resultset) {
					proxy_info("FTS search: found %zu rows in objects table\n", obj_resultset->rows.size());
					for (std::vector<SQLite3_row*>::iterator oit = obj_resultset->rows.begin();
					     oit != obj_resultset->rows.end(); ++oit) {
						SQLite3_row* obj_row = *oit;
						if (obj_row->fields[0] && obj_row->fields[1]) {
							object_to_schema[obj_row->fields[0]] = obj_row->fields[1];
							proxy_info("FTS search: mapped '%s' -> '%s'\n", obj_row->fields[0], obj_row->fields[1]);
						}
					}
					delete obj_resultset;
				}
			}

			for (size_t i = 0; i < results.size(); i++) {
				json& item = results[i];
				json objects_details = json::array();
				if (item.contains("related_objects") &&
				    item["related_objects"].is_array()) {
					proxy_info("FTS search: processing item '%s' with %zu related_objects\n",
						item["title"].get<std::string>().c_str(), item["related_objects"].size());

					for (const auto& obj_name : item["related_objects"]) {
						if (obj_name.is_string()) {
							std::string name = obj_name.get<std::string>();
							// Look up schema_name from our map
							std::string schema_name = "";
							std::map<std::string, std::string>::iterator it = object_to_schema.find(name);
							if (it != object_to_schema.end()) {
								schema_name = it->second;
							}

							if (schema_name.empty()) {
								proxy_warning("FTS search: no schema found for object '%s'\n", name.c_str());
								continue;
							}

							proxy_info("FTS search: fetching object '%s.%s'\n", schema_name.c_str(), name.c_str());

							// Fetch object schema - pass schema_name and object_name separately
							std::string obj_details = get_object(
								run_id, -1, schema_name, name,
								true, false
							);

							proxy_info("FTS search: get_object returned %zu bytes\n", obj_details.length());

							try {
								json obj_json = json::parse(obj_details);
								if (!obj_json.is_null()) {
									objects_details.push_back(obj_json);
									proxy_info("FTS search: successfully added object '%s' to details (size=%zu)\n",
										name.c_str(), obj_json.dump().length());
								} else {
									proxy_warning("FTS search: object '%s' returned null\n", name.c_str());
								}
							} catch (const std::exception& e) {
								proxy_warning("FTS search: failed to parse object details for '%s': %s\n",
									name.c_str(), e.what());
							} catch (...) {
								proxy_warning("FTS search: failed to parse object details for '%s'\n", name.c_str());
							}
						}
					}
				}

				proxy_info("FTS search: adding %zu objects to item '%s'\n",
					objects_details.size(), item["title"].get<std::string>().c_str());

				item["objects"] = objects_details;
			}
		}
	}

	return results.dump();
}

int Discovery_Schema::log_llm_search(
	int run_id,
	const std::string& query,
	int lmt
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql = "INSERT INTO llm_search_log(run_id, query, lmt) VALUES(?1, ?2 ,  ?3);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK || !stmt) {
		proxy_error("Failed to prepare llm_search_log insert: %d\n", rc);
		return -1;
	}

	(*proxy_sqlite3_bind_int)(stmt, 1, run_id);
	(*proxy_sqlite3_bind_text)(stmt, 2, query.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int)(stmt, 3, lmt);

	rc = (*proxy_sqlite3_step)(stmt);

	if (rc != SQLITE_DONE) {
		proxy_error("Failed to insert llm_search_log: %d\n", rc);
		return -1;
	}

	return 0;
}

int Discovery_Schema::log_rag_search_fts(
	const std::string& query,
	int k,
	const std::string& filters
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql = "INSERT INTO rag_search_log(query, k, filters) VALUES(?1, ?2 ,  ?3);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK || !stmt) {
		proxy_error("Failed to prepare rag_search_log insert: %d\n", rc);
		return -1;
	}

	(*proxy_sqlite3_bind_text)(stmt, 1, query.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int)(stmt, 2, k);
	(*proxy_sqlite3_bind_text)(stmt, 3, filters.c_str(), -1, SQLITE_TRANSIENT);

	rc = (*proxy_sqlite3_step)(stmt);

	if (rc != SQLITE_DONE) {
		proxy_error("Failed to insert rag_search_log: %d\n", rc);
		return -1;
	}

	return 0;
}

int Discovery_Schema::log_query_tool_call(
	const std::string& tool_name,
	const std::string& schema,
	int run_id,
	unsigned long long start_time,
	unsigned long long execution_time,
	const std::string& error
) {
	sqlite3_stmt* stmt = NULL;
	const char* sql = "INSERT INTO query_tool_calls(tool_name, schema, run_id, start_time, execution_time, error) VALUES(?1, ?2, ?3, ?4, ?5, ?6);";

	auto [rc, stmt_unique] = db->prepare_v2(sql);
	stmt = stmt_unique.get();
	if (rc != SQLITE_OK || !stmt) {
		proxy_error("Failed to prepare query_tool_calls insert: %d\n", rc);
		return -1;
	}

	(*proxy_sqlite3_bind_text)(stmt, 1, tool_name.c_str(), -1, SQLITE_TRANSIENT);
	if (!schema.empty()) {
		(*proxy_sqlite3_bind_text)(stmt, 2, schema.c_str(), -1, SQLITE_TRANSIENT);
	} else {
		(*proxy_sqlite3_bind_null)(stmt, 2);
	}
	if (run_id > 0) {
		(*proxy_sqlite3_bind_int)(stmt, 3, run_id);
	} else {
		(*proxy_sqlite3_bind_null)(stmt, 3);
	}
	(*proxy_sqlite3_bind_int64)(stmt, 4, start_time);
	(*proxy_sqlite3_bind_int64)(stmt, 5, execution_time);
	if (!error.empty()) {
		(*proxy_sqlite3_bind_text)(stmt, 6, error.c_str(), -1, SQLITE_TRANSIENT);
	} else {
		(*proxy_sqlite3_bind_null)(stmt, 6);
	}

	rc = (*proxy_sqlite3_step)(stmt);

	if (rc != SQLITE_DONE) {
		proxy_error("Failed to insert query_tool_calls: %d\n", rc);
		return -1;
	}

	return 0;
}

// ============================================================
// MCP QUERY RULES
// ============================================================
// Load MCP query rules from database into memory
//
// This function replaces all in-memory MCP query rules with the rules
// from the provided resultset. It compiles regex patterns for each rule
// and initializes all rule properties.
//
// Args:
//   resultset: SQLite result set containing rule definitions from the database
//               Must contain 18 columns in the correct order:
//               rule_id, active, username, target_id, schemaname, tool_name, match_pattern,
//               negate_match_pattern, re_modifiers, flagIN, flagOUT, replace_pattern,
//               timeout_ms, error_msg, OK_msg, log, apply, comment
//
// Thread Safety:
//   Uses write lock on mcp_rules_lock during update
//
// Side Effects:
//   - Increments mcp_rules_version (triggers runtime cache invalidation)
//   - Clears and rebuilds mcp_query_rules vector
//   - Compiles regex engines for all match_pattern fields
// ============================================================

void Discovery_Schema::load_mcp_query_rules(SQLite3_result* resultset) {
	if (!resultset || resultset->rows_count == 0) {
		proxy_info("No MCP query rules to load\n");
		return;
	}

	pthread_rwlock_wrlock(&mcp_rules_lock);

	// Clear existing rules
	for (auto rule : mcp_query_rules) {
		if (rule->regex_engine) {
			delete (re2::RE2*)rule->regex_engine;
		}
		free(rule->username);
		free(rule->target_id);
		free(rule->schemaname);
		free(rule->tool_name);
		free(rule->match_pattern);
		free(rule->replace_pattern);
		free(rule->error_msg);
		free(rule->ok_msg);
		free(rule->comment);
		delete rule;
	}
	mcp_query_rules.clear();

	// Load new rules from resultset
	// Column order: rule_id, active, username, target_id, schemaname, tool_name, match_pattern,
	//               negate_match_pattern, re_modifiers, flagIN, flagOUT, replace_pattern,
	//               timeout_ms, error_msg, OK_msg, log, apply, comment
	// Expected: 18 columns (fields[0] through fields[17])
	for (int i = 0; i < resultset->rows_count; i++) {
		SQLite3_row* row = resultset->rows[i];

		// Validate column count before accessing fields
		if (row->cnt < 18) {
			proxy_error("Invalid row format in mcp_query_rules: expected 18 columns, got %d. Skipping row %u.\n",
				row->cnt, i);
			continue;
		}

		MCP_Query_Rule* rule = new MCP_Query_Rule();

		rule->rule_id = atoi(row->fields[0]);           // rule_id
		rule->active = atoi(row->fields[1]) != 0;       // active
		rule->username = row->fields[2] ? strdup(row->fields[2]) : NULL;  // username
		rule->target_id = row->fields[3] ? strdup(row->fields[3]) : NULL;  // target_id
		rule->schemaname = row->fields[4] ? strdup(row->fields[4]) : NULL;  // schemaname
		rule->tool_name = row->fields[5] ? strdup(row->fields[5]) : NULL;  // tool_name
		rule->match_pattern = row->fields[6] ? strdup(row->fields[6]) : NULL;  // match_pattern
		rule->negate_match_pattern = row->fields[7] ? atoi(row->fields[7]) != 0 : false;  // negate_match_pattern
		// re_modifiers: Parse VARCHAR value - "CASELESS" maps to 1, otherwise parse as int
		if (row->fields[8]) {
			std::string mod = row->fields[8];
			if (mod == "CASELESS") {
				rule->re_modifiers = 1;
			} else if (mod == "0") {
				rule->re_modifiers = 0;
			} else {
				rule->re_modifiers = atoi(mod.c_str());
			}
		} else {
			rule->re_modifiers = 1;  // default CASELESS
		}
		rule->flagIN = row->fields[9] ? atoi(row->fields[9]) : 0;  // flagIN
		rule->flagOUT = row->fields[10] ? atoi(row->fields[10]) : -1;  // flagOUT: -1 = NULL/unset
		rule->replace_pattern = row->fields[11] ? strdup(row->fields[11]) : NULL;  // replace_pattern
		rule->timeout_ms = row->fields[12] ? atoi(row->fields[12]) : -1;  // timeout_ms: -1 = NULL/unset
		rule->error_msg = row->fields[13] ? strdup(row->fields[13]) : NULL;  // error_msg
		rule->ok_msg = row->fields[14] ? strdup(row->fields[14]) : NULL;  // OK_msg
		rule->log = row->fields[15] ? atoi(row->fields[15]) : -1;  // log: -1 = NULL/unset
		rule->apply = row->fields[16] ? atoi(row->fields[16]) != 0 : true;  // apply
		rule->comment = row->fields[17] ? strdup(row->fields[17]) : NULL;  // comment
		// Note: hits is in-memory only, not loaded from table

		// Compile regex if match_pattern exists
		if (rule->match_pattern) {
			re2::RE2::Options opts;
			opts.set_log_errors(false);
			if (rule->re_modifiers & 1) {
				opts.set_case_sensitive(false);
			}
			rule->regex_engine = new re2::RE2(rule->match_pattern, opts);
			if (!((re2::RE2*)rule->regex_engine)->ok()) {
				proxy_warning("Failed to compile regex for MCP rule %d: %s\n",
					rule->rule_id, rule->match_pattern);
				delete (re2::RE2*)rule->regex_engine;
				rule->regex_engine = NULL;
			}
		}

		mcp_query_rules.push_back(rule);
	}

	mcp_rules_version++;
	pthread_rwlock_unlock(&mcp_rules_lock);

	proxy_info("Loaded %zu MCP query rules\n", mcp_query_rules.size());
}

// Evaluate MCP query rules against an incoming query
//
// This function processes the query through all active MCP query rules in order,
// applying matching rules and collecting their actions. Multiple actions from
// different rules can be combined.
//
// Rule Actions (not mutually exclusive):
//   - error_msg: Block the query with the specified error message
//   - replace_pattern: Rewrite the query using regex substitution
//   - timeout_ms: Set a timeout for query execution
//   - OK_msg: Return success immediately with the specified message
//   - log: Enable logging for this query
//
// Rule Processing Flow:
//   1. Skip inactive rules
//   2. Check flagIN match
//   3. Check username match
//   4. Check target_id match
//   5. Check schemaname match
//   6. Check tool_name match
//   7. Check match_pattern against the query (regex)
//   8. If match: increment hits, apply actions, set flagOUT, and stop if apply=true
//
// Args:
//   tool_name: The name of the MCP tool being called
//   username: Backend username resolved from target auth profile
//   target_id: Resolved logical target identifier
//   schemaname: The schema/database context for the query
//   arguments: The JSON arguments passed to the tool
//   original_query: The original SQL query string
//
// Returns:
//   MCP_Query_Processor_Output*: Output object containing all actions to apply
//   - error_msg: If set, query should be blocked
//   - OK_msg: If set, return success immediately
//   - new_query: Rewritten query if replace_pattern was applied
//   - timeout_ms: Timeout in milliseconds if set
//   - log: Whether to log this query
//   - next_query_flagIN: The flagOUT value for chaining rules
//
// Thread Safety:
//   Uses read lock on mcp_rules_lock during evaluation
//
// Memory Ownership:
//   Returns a newly allocated MCP_Query_Processor_Output object.
//   The caller assumes ownership and MUST delete the returned pointer
//   when done to avoid memory leaks.
//
MCP_Query_Processor_Output* Discovery_Schema::evaluate_mcp_query_rules(
	const std::string& tool_name,
	const std::string& username,
	const std::string& target_id,
	const std::string& schemaname,
	const nlohmann::json& arguments,
	const std::string& original_query
) {
	MCP_Query_Processor_Output* qpo = new MCP_Query_Processor_Output();
	qpo->init();

	std::string current_query = original_query;
	int current_flag = 0;

	pthread_rwlock_rdlock(&mcp_rules_lock);

	for (auto rule : mcp_query_rules) {
		// Skip inactive rules
		if (!rule->active) continue;

		// Check flagIN
		if (rule->flagIN != current_flag) continue;

		// Check username match
		if (rule->username) {
			if (username.empty() || strcmp(rule->username, username.c_str()) != 0) continue;
		}

		// Check target_id match
		if (rule->target_id) {
			if (target_id.empty() || strcmp(rule->target_id, target_id.c_str()) != 0) continue;
		}

		// Check schemaname match
		if (rule->schemaname) {
			if (schemaname.empty() || strcmp(rule->schemaname, schemaname.c_str()) != 0) {
				continue;
			}
		}

		// Check tool_name match
		if (rule->tool_name) {
			if (strcmp(rule->tool_name, tool_name.c_str()) != 0) continue;
		}

		// Check match_pattern against the query
		bool matches = false;
		if (rule->regex_engine && rule->match_pattern) {
			re2::RE2* regex = (re2::RE2*)rule->regex_engine;
			re2::StringPiece piece(current_query);
			matches = re2::RE2::PartialMatch(piece, *regex);
			if (rule->negate_match_pattern) {
				matches = !matches;
			}
		} else {
			// No pattern means match all
			matches = true;
		}

		if (matches) {
			// Increment hit counter
			__sync_add_and_fetch((unsigned long long*)&rule->hits, 1);

			// Collect rule actions in output object
			if (!rule->apply) {
				// Log-only rule, continue processing
				if (rule->log > 0) {
					proxy_info("MCP query rule %d logged: tool=%s schema=%s\n",
						rule->rule_id, tool_name.c_str(), schemaname.c_str());
				}
				if (rule->log >= 0 && qpo->log == -1) {
					qpo->log = rule->log;
				}
				continue;
			}

			// Set flagOUT for next rules
			if (rule->flagOUT >= 0) {
				current_flag = rule->flagOUT;
			}

			// Collect all actions from this rule in the output object
			// Actions are NOT mutually exclusive - a single rule can:
			// rewrite + timeout + block all at once

			// 1. Rewrite action (if replace_pattern is set)
			if (rule->replace_pattern && rule->regex_engine) {
				std::string rewritten = current_query;
				if (re2::RE2::Replace(&rewritten, *(re2::RE2*)rule->regex_engine, rule->replace_pattern)) {
					// Update current_query for subsequent rule matching
					current_query = rewritten;
					// Store in output object
					if (qpo->new_query) {
						delete qpo->new_query;
					}
					qpo->new_query = new std::string(rewritten);
				}
			}

			// 2. Timeout action (if timeout_ms > 0)
			if (rule->timeout_ms > 0) {
				qpo->timeout_ms = rule->timeout_ms;
			}

			// 3. Error message (block action)
			if (rule->error_msg) {
				std::string q_preview = current_query;
				if (q_preview.length() > 256) {
					q_preview = q_preview.substr(0, 256) + "...";
				}
				proxy_info(
					"MCP query rule %d BLOCK matched: tool=%s target_id=%s schema=%s error_msg='%s' query='%s'\n",
					rule->rule_id,
					tool_name.c_str(),
					target_id.c_str(),
					schemaname.c_str(),
					rule->error_msg,
					q_preview.c_str()
				);
				if (qpo->error_msg) {
					free(qpo->error_msg);
				}
				qpo->error_msg = strdup(rule->error_msg);
			}

			// 4. OK message (allow with response)
			if (rule->ok_msg) {
				proxy_info(
					"MCP query rule %d OK_MSG matched: tool=%s target_id=%s schema=%s ok_msg='%s'\n",
					rule->rule_id,
					tool_name.c_str(),
					target_id.c_str(),
					schemaname.c_str(),
					rule->ok_msg
				);
				if (qpo->OK_msg) {
					free(qpo->OK_msg);
				}
				qpo->OK_msg = strdup(rule->ok_msg);
			}

			// 5. Log flag
			if (rule->log > 0 && qpo->log == -1) {
				qpo->log = 1;
			}

			// 6. next_query_flagIN
			if (rule->flagOUT >= 0) {
				qpo->next_query_flagIN = rule->flagOUT;
			}

			// If apply is true and not a log-only rule, stop processing further rules
			if (rule->apply) {
				break;
			}
		}
	}

	pthread_rwlock_unlock(&mcp_rules_lock);
	return qpo;
}

// Get all MCP query rules from memory
//
// Returns all MCP query rules currently loaded in memory.
// This is used to populate both mcp_query_rules and runtime_mcp_query_rules tables.
// Note: The hits counter is NOT included (use get_stats_mcp_query_rules() for that).
//
// Returns:
//   SQLite3_result*: Result set with 18 columns (no hits column)
//
// Thread Safety:
//   Uses read lock on mcp_rules_lock
//
SQLite3_result* Discovery_Schema::get_mcp_query_rules() {
	SQLite3_result* result = new SQLite3_result(18);

	// Define columns (18 columns - same for mcp_query_rules and runtime_mcp_query_rules)
	result->add_column_definition(SQLITE_TEXT, "rule_id");
	result->add_column_definition(SQLITE_TEXT, "active");
	result->add_column_definition(SQLITE_TEXT, "username");
	result->add_column_definition(SQLITE_TEXT, "target_id");
	result->add_column_definition(SQLITE_TEXT, "schemaname");
	result->add_column_definition(SQLITE_TEXT, "tool_name");
	result->add_column_definition(SQLITE_TEXT, "match_pattern");
	result->add_column_definition(SQLITE_TEXT, "negate_match_pattern");
	result->add_column_definition(SQLITE_TEXT, "re_modifiers");
	result->add_column_definition(SQLITE_TEXT, "flagIN");
	result->add_column_definition(SQLITE_TEXT, "flagOUT");
	result->add_column_definition(SQLITE_TEXT, "replace_pattern");
	result->add_column_definition(SQLITE_TEXT, "timeout_ms");
	result->add_column_definition(SQLITE_TEXT, "error_msg");
	result->add_column_definition(SQLITE_TEXT, "OK_msg");
	result->add_column_definition(SQLITE_TEXT, "log");
	result->add_column_definition(SQLITE_TEXT, "apply");
	result->add_column_definition(SQLITE_TEXT, "comment");

	pthread_rwlock_rdlock(&mcp_rules_lock);

	for (size_t i = 0; i < mcp_query_rules.size(); i++) {
		MCP_Query_Rule* rule = mcp_query_rules[i];
		char** pta = (char**)malloc(sizeof(char*) * 18);

		pta[0] = strdup(std::to_string(rule->rule_id).c_str());           // rule_id
		pta[1] = strdup(std::to_string(rule->active ? 1 : 0).c_str());    // active
		pta[2] = rule->username ? strdup(rule->username) : NULL;         // username
		pta[3] = rule->target_id ? strdup(rule->target_id) : NULL;        // target_id
		pta[4] = rule->schemaname ? strdup(rule->schemaname) : NULL;      // schemaname
		pta[5] = rule->tool_name ? strdup(rule->tool_name) : NULL;        // tool_name
		pta[6] = rule->match_pattern ? strdup(rule->match_pattern) : NULL;  // match_pattern
		pta[7] = strdup(std::to_string(rule->negate_match_pattern ? 1 : 0).c_str());  // negate_match_pattern
		// re_modifiers: reverse map bitmask back to string (matching MySQL pattern)
		if (rule->re_modifiers & 1) {  // CASELESS bitmask
			pta[8] = strdup("CASELESS");
		} else {
			pta[8] = strdup(std::to_string(rule->re_modifiers).c_str());
		}
		pta[9] = strdup(std::to_string(rule->flagIN).c_str());            // flagIN
		pta[10] = (rule->flagOUT == -1) ? NULL : strdup(std::to_string(rule->flagOUT).c_str());  // flagOUT: -1 = NULL
		pta[11] = rule->replace_pattern ? strdup(rule->replace_pattern) : NULL;  // replace_pattern
		pta[12] = (rule->timeout_ms == -1) ? NULL : strdup(std::to_string(rule->timeout_ms).c_str());  // timeout_ms: -1 = NULL
		pta[13] = rule->error_msg ? strdup(rule->error_msg) : NULL;       // error_msg
		pta[14] = rule->ok_msg ? strdup(rule->ok_msg) : NULL;             // OK_msg
		pta[15] = (rule->log == -1) ? NULL : strdup(std::to_string(rule->log).c_str());  // log: -1 = NULL
		pta[16] = strdup(std::to_string(rule->apply ? 1 : 0).c_str());    // apply
		pta[17] = rule->comment ? strdup(rule->comment) : NULL;           // comment

		result->add_row(pta);

		// Free the row data
		for (int j = 0; j < 18; j++) {
			if (pta[j]) {
				free(pta[j]);
			}
		}
		free(pta);
	}

	pthread_rwlock_unlock(&mcp_rules_lock);
	return result;
}

// Get MCP query rules statistics (hit counters)
//
// Returns the hit counter for each MCP query rule.
// The hit counter increments each time a rule matches during query processing.
// This is used to populate the stats_mcp_query_rules table.
//
// Returns:
//   SQLite3_result*: Result set with 4 columns (rule_id, username, target_id, hits)
//
// Thread Safety:
//   Uses read lock on mcp_rules_lock
//
SQLite3_result* Discovery_Schema::get_stats_mcp_query_rules() {
	SQLite3_result* result = new SQLite3_result(4);

	// Define columns
	result->add_column_definition(SQLITE_TEXT, "rule_id");
	result->add_column_definition(SQLITE_TEXT, "username");
	result->add_column_definition(SQLITE_TEXT, "target_id");
	result->add_column_definition(SQLITE_TEXT, "hits");

	pthread_rwlock_rdlock(&mcp_rules_lock);

	for (size_t i = 0; i < mcp_query_rules.size(); i++) {
		MCP_Query_Rule* rule = mcp_query_rules[i];
		char** pta = (char**)malloc(sizeof(char*) * 4);

		pta[0] = strdup(std::to_string(rule->rule_id).c_str());
		pta[1] = rule->username ? strdup(rule->username) : NULL;
		pta[2] = rule->target_id ? strdup(rule->target_id) : NULL;
		pta[3] = strdup(std::to_string(rule->hits).c_str());

		result->add_row(pta);

		// Free the row data
		for (int j = 0; j < 4; j++) {
			if (pta[j]) {
				free(pta[j]);
			}
		}
		free(pta);
	}

	pthread_rwlock_unlock(&mcp_rules_lock);
	return result;
}

// ============================================================
// MCP QUERY DIGEST
// ============================================================

// Update MCP query digest statistics after a tool call completes.
//
// This function is called after each successful MCP tool execution to
// record performance and frequency statistics. Similar to MySQL's query
// digest tracking, this aggregates statistics for "similar" queries
// (queries with the same fingerprinted structure).
//
// Parameters:
//   tool_name    - Name of the MCP tool that was called (e.g., "run_sql_readonly")
//   run_id       - Discovery run identifier (0 if no schema context)
//   digest       - Computed digest hash (lower 64 bits of SpookyHash)
//   digest_text  - Fingerprinted JSON arguments with literals replaced by '?'
//   duration_us  - Query execution time in microseconds
//   timestamp    - Unix timestamp of when the query completed
//
// Statistics Updated:
//   - count_star: Incremented for each execution
//   - sum_time: Accumulates total execution time
//   - min_time: Tracks minimum execution time
//   - max_time: Tracks maximum execution time
//   - first_seen: Set once on first occurrence (not updated)
//   - last_seen: Updated to current timestamp on each execution
//
// Thread Safety:
//   Acquires write lock on mcp_digest_rwlock for the entire operation.
//   Nested map structure: mcp_digest_umap["tool_name|run_id"][digest]
//
// Note: Digest statistics are currently kept in memory only. Persistence
// to SQLite is planned (TODO at line 2775).
void Discovery_Schema::update_mcp_query_digest(
	const std::string& tool_name,
	int run_id,
	uint64_t digest,
	const std::string& digest_text,
	unsigned long long duration_us,
	time_t timestamp
) {
	// Create composite key: tool_name + run_id
	std::string key = tool_name + "|" + std::to_string(run_id);

	pthread_rwlock_wrlock(&mcp_digest_rwlock);

	// Find or create digest stats entry
	auto& tool_map = mcp_digest_umap[key];
	auto it = tool_map.find(digest);

	MCP_Query_Digest_Stats* stats = NULL;
	if (it != tool_map.end()) {
		stats = (MCP_Query_Digest_Stats*)it->second;
	} else {
		stats = new MCP_Query_Digest_Stats();
		stats->tool_name = tool_name;
		stats->run_id = run_id;
		stats->digest = digest;
		stats->digest_text = digest_text;
		tool_map[digest] = stats;
	}

	// Update statistics
	stats->add_timing(duration_us, timestamp);

	pthread_rwlock_unlock(&mcp_digest_rwlock);

	// Periodically persist to SQLite (every 100 updates or so)
	static thread_local unsigned int update_count = 0;
	if (++update_count % 100 == 0) {
		flush_digest_to_sqlite();
	}
}

// Get MCP query digest statistics from the in-memory digest map.
//
// Returns all accumulated digest statistics for MCP tool calls that have been
// processed. This includes execution counts, timing information, and the
// fingerprinted query text.
//
// Parameters:
//   reset - If true, clears all in-memory digest statistics after returning them.
//           This is used for the stats_mcp_query_digest_reset table.
//           If false, statistics remain in memory (stats_mcp_query_digest table).
//
// Returns:
//   SQLite3_result* - Result set containing digest statistics with columns:
//     - tool_name: Name of the MCP tool that was called
//     - run_id: Discovery run identifier
//     - digest: 128-bit hash (lower 64 bits) identifying the query fingerprint
//     - digest_text: Fingerprinted JSON with literals replaced by '?'
//     - count_star: Number of times this digest was seen
//     - first_seen: Unix timestamp of first occurrence
//     - last_seen: Unix timestamp of most recent occurrence
//     - sum_time: Total execution time in microseconds
//     - min_time: Minimum execution time in microseconds
//     - max_time: Maximum execution time in microseconds
//
// Thread Safety:
//   Uses read-write lock (mcp_digest_rwlock) for concurrent access.
//   Reset operation acquires write lock to clear the digest map.
//
// Note: The caller is responsible for freeing the returned SQLite3_result.
SQLite3_result* Discovery_Schema::get_mcp_query_digest(bool reset) {
	SQLite3_result* result = new SQLite3_result(10);

	// Define columns for MCP query digest statistics
	result->add_column_definition(SQLITE_TEXT, "tool_name");
	result->add_column_definition(SQLITE_TEXT, "run_id");
	result->add_column_definition(SQLITE_TEXT, "digest");
	result->add_column_definition(SQLITE_TEXT, "digest_text");
	result->add_column_definition(SQLITE_TEXT, "count_star");
	result->add_column_definition(SQLITE_TEXT, "first_seen");
	result->add_column_definition(SQLITE_TEXT, "last_seen");
	result->add_column_definition(SQLITE_TEXT, "sum_time");
	result->add_column_definition(SQLITE_TEXT, "min_time");
	result->add_column_definition(SQLITE_TEXT, "max_time");

	// Use appropriate lock based on reset flag to prevent TOCTOU race condition
	// If reset is true, we need a write lock from the start to prevent new data
	// from being added between the read and write lock operations
	if (reset) {
		pthread_rwlock_wrlock(&mcp_digest_rwlock);
	} else {
		pthread_rwlock_rdlock(&mcp_digest_rwlock);
	}

	for (auto const& [key1, inner_map] : mcp_digest_umap) {
		for (auto const& [digest, stats_ptr] : inner_map) {
			MCP_Query_Digest_Stats* stats = (MCP_Query_Digest_Stats*)stats_ptr;
			char** pta = (char**)malloc(sizeof(char*) * 10);

			pta[0] = strdup(stats->tool_name.c_str());                         // tool_name
			pta[1] = strdup(std::to_string(stats->run_id).c_str());            // run_id
			pta[2] = strdup(std::to_string(stats->digest).c_str());            // digest
			pta[3] = strdup(stats->digest_text.c_str());                       // digest_text
			pta[4] = strdup(std::to_string(stats->count_star).c_str());        // count_star
			pta[5] = strdup(std::to_string(stats->first_seen).c_str());        // first_seen
			pta[6] = strdup(std::to_string(stats->last_seen).c_str());         // last_seen
			pta[7] = strdup(std::to_string(stats->sum_time).c_str());          // sum_time
			pta[8] = strdup(std::to_string(stats->min_time).c_str());          // min_time
			pta[9] = strdup(std::to_string(stats->max_time).c_str());          // max_time

			result->add_row(pta);

			// Free the row data
			for (int j = 0; j < 10; j++) {
				if (pta[j]) {
					free(pta[j]);
				}
			}
			free(pta);
		}
	}

	if (reset) {
		for (auto const& [key1, inner_map] : mcp_digest_umap) {
			for (auto const& [key2, stats] : inner_map) {
				delete (MCP_Query_Digest_Stats*)stats;
			}
		}
		mcp_digest_umap.clear();

		db->execute("DELETE FROM mcp_query_digest_persist");
	}

	pthread_rwlock_unlock(&mcp_digest_rwlock);

	return result;
}

// Compute a unique digest hash for an MCP tool call.
//
// Creates a deterministic hash value that identifies similar MCP queries
// by normalizing the arguments (fingerprinting) and hashing the result.
// Queries with the same tool name and argument structure (but different
// literal values) will produce the same digest.
//
// This is analogous to MySQL query digest computation, which fingerprints
// SQL queries by replacing literal values with placeholders.
//
// Parameters:
//   tool_name - Name of the MCP tool being called (e.g., "run_sql_readonly")
//   arguments - JSON object containing the tool's arguments
//
// Returns:
//   uint64_t - Lower 64 bits of the 128-bit SpookyHash digest value
//
// Digest Computation:
//   1. Arguments are fingerprinted (literals replaced with '?' placeholders)
//   2. Tool name and fingerprint are combined: "tool_name:{fingerprint}"
//   3. SpookyHash 128-bit hash is computed on the combined string
//   4. Lower 64 bits (hash1) are returned as the digest
//
// Example:
//   Input: tool_name="run_sql_readonly", arguments={"sql": "SELECT * FROM users WHERE id = 123"}
//   Fingerprint: {"sql":"?"}
//   Combined: "run_sql_readonly:{"sql":"?"}"
//   Digest: (uint64_t hash value)
//
// Note: Uses SpookyHash for fast, non-cryptographic hashing with good
// distribution properties. The same algorithm is used for MySQL query digests.
uint64_t Discovery_Schema::compute_mcp_digest(
	const std::string& tool_name,
	const nlohmann::json& arguments
) {
	std::string fingerprint = fingerprint_mcp_args(arguments);

	// Combine tool_name and fingerprint for hashing
	std::string combined = tool_name + ":" + fingerprint;

	// Use SpookyHash to compute digest
	uint64_t hash1 = SpookyHash::Hash64(combined.data(), combined.length(), 0);

	return hash1;
}

static options get_def_mysql_opts() {
	options opts {};

	opts.lowercase = false;
	opts.replace_null = true;
	opts.replace_number = false;
	opts.grouping_limit = 3;
	opts.groups_grouping_limit = 1;
	opts.keep_comment = false;
	opts.max_query_length = 65000;

	return opts;
}

// Generate a fingerprint of MCP tool arguments by replacing literals with placeholders.
//
// Converts a JSON arguments structure into a normalized form where all
// literal values (strings, numbers, booleans) are replaced with '?' placeholders.
// This allows similar queries to be grouped together for statistics and analysis.
//
// Parameters:
//   arguments - JSON object/array containing the tool's arguments
//
// Returns:
//   std::string - Fingerprinted JSON string with literals replaced by '?'
//
// Fingerprinting Rules:
//   - String values: replaced with "?"
//   - Number values: replaced with "?"
//   - Boolean values: replaced with "?"
//   - Objects: recursively fingerprinted (keys preserved, values replaced)
//   - Arrays: replaced with "[?]" (entire array is a placeholder)
//   - Null values: preserved as "null"
//
// Example:
//   Input: {"sql": "SELECT * FROM users WHERE id = 123", "timeout": 5000}
//   Output: {"sql":"<digest_of_sql>","timeout":"?"}
//
//   Input: {"filters": {"status": "active", "age": 25}}
//   Output: {"filters":{"?":"?","?":"?"}}
//
// Note: Object keys (field names) are preserved as-is, only values are replaced.
// This ensures that queries with different parameter structures produce different
// fingerprints, while queries with the same structure but different values produce
// the same fingerprint.
//
// SQL Handling: For arguments where key is "sql", the value is replaced by a
// digest generated using mysql_query_digest_and_first_comment instead of "?".
// This normalizes SQL queries (removes comments, extra whitespace, etc.) so that
// semantically equivalent queries produce the same fingerprint.
std::string Discovery_Schema::fingerprint_mcp_args(const nlohmann::json& arguments) {
	// Serialize JSON with literals replaced by placeholders
	std::string result;

	if (arguments.is_object()) {
		result += "{";
		bool first = true;
		for (auto it = arguments.begin(); it != arguments.end(); ++it) {
			if (!first) result += ",";
			first = false;
			result += "\"" + it.key() + "\":";

			if (it.value().is_string()) {
				// Special handling for "sql" key - generate digest instead of "?"
				if (it.key() == "sql") {
					std::string sql_value = it.value().get<std::string>();
					const options def_opts { get_def_mysql_opts() };
					char* first_comment = nullptr;  // Will be allocated by the function if needed
					char* digest = mysql_query_digest_and_first_comment(
						sql_value.c_str(),
						sql_value.length(),
						&first_comment,
						NULL,  // buffer - not needed
						&def_opts
					);
					if (first_comment) {
						free(first_comment);
					}
					// Escape the digest for JSON and add it to result
					result += "\"";
					if (digest) {
						// Full JSON escaping - handle all control characters
						for (const char* p = digest; *p; p++) {
							unsigned char c = (unsigned char)*p;
							if (c == '\\') result += "\\\\";
							else if (c == '"') result += "\\\"";
							else if (c == '\n') result += "\\n";
							else if (c == '\r') result += "\\r";
							else if (c == '\t') result += "\\t";
							else if (c < 0x20) {
								char buf[8];
								snprintf(buf, sizeof(buf), "\\u%04x", c);
								result += buf;
							}
							else result += *p;
						}
						free(digest);
					}
					result += "\"";
				} else {
					result += "\"?\"";
				}
			} else if (it.value().is_number() || it.value().is_boolean()) {
				result += "\"?\"";
			} else if (it.value().is_object()) {
				result += fingerprint_mcp_args(it.value());
			} else if (it.value().is_array()) {
				result += "[\"?\"]";
			} else {
				result += "null";
			}
		}
		result += "}";
	} else if (arguments.is_array()) {
		result += "[\"?\"]";
	} else {
		result += "\"?\"";
	}

	return result;
}

void Discovery_Schema::create_digest_persist_table() {
	if (!db) return;
	db->execute(
		"CREATE TABLE IF NOT EXISTS mcp_query_digest_persist ("
		"tool_name VARCHAR NOT NULL,"
		"run_id INTEGER NOT NULL,"
		"digest VARCHAR NOT NULL,"
		"digest_text VARCHAR NOT NULL,"
		"count_star INTEGER NOT NULL,"
		"first_seen INTEGER NOT NULL,"
		"last_seen INTEGER NOT NULL,"
		"sum_time INTEGER NOT NULL,"
		"min_time INTEGER NOT NULL,"
		"max_time INTEGER NOT NULL,"
		"PRIMARY KEY(tool_name, run_id, digest))");
}

void Discovery_Schema::flush_digest_to_sqlite() {
	if (!db) return;

	pthread_rwlock_rdlock(&mcp_digest_rwlock);

	db->execute("BEGIN IMMEDIATE");
	for (auto const& [key1, inner_map] : mcp_digest_umap) {
		for (auto const& [digest, stats_ptr] : inner_map) {
			MCP_Query_Digest_Stats* stats = (MCP_Query_Digest_Stats*)stats_ptr;
			char* sql = sqlite3_mprintf(
				"INSERT OR REPLACE INTO mcp_query_digest_persist "
				"(tool_name, run_id, digest, digest_text, count_star, "
				"first_seen, last_seen, sum_time, min_time, max_time) "
				"VALUES (%Q, %d, '%llu', %Q, %llu, %ld, %ld, %llu, %llu, %llu)",
				stats->tool_name.c_str(), stats->run_id,
				(unsigned long long)stats->digest, stats->digest_text.c_str(),
				(unsigned long long)stats->count_star,
				(long)stats->first_seen, (long)stats->last_seen,
				(unsigned long long)stats->sum_time,
				(unsigned long long)stats->min_time,
				(unsigned long long)stats->max_time);
			if (sql) {
				db->execute(sql);
				sqlite3_free(sql);
			}
		}
	}
	db->execute("COMMIT");

	pthread_rwlock_unlock(&mcp_digest_rwlock);
}

void Discovery_Schema::load_persisted_digests() {
	if (!db) return;

	char* errmsg = NULL;
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(db->get_db(),
		"SELECT tool_name, run_id, digest, digest_text, count_star, "
		"first_seen, last_seen, sum_time, min_time, max_time "
		"FROM mcp_query_digest_persist", -1, &stmt, NULL);
	if (rc != SQLITE_OK) return;

	pthread_rwlock_wrlock(&mcp_digest_rwlock);

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		std::string tool_name = (const char*)sqlite3_column_text(stmt, 0);
		int run_id = sqlite3_column_int(stmt, 1);
		uint64_t dgst = (uint64_t)sqlite3_column_int64(stmt, 2);
		std::string digest_text = (const char*)sqlite3_column_text(stmt, 3);

		std::string key = tool_name + "|" + std::to_string(run_id);
		auto& tool_map = mcp_digest_umap[key];

		MCP_Query_Digest_Stats* stats = new MCP_Query_Digest_Stats();
		stats->tool_name = tool_name;
		stats->run_id = run_id;
		stats->digest = dgst;
		stats->digest_text = digest_text;
		stats->count_star = (unsigned int)sqlite3_column_int64(stmt, 4);
		stats->first_seen = (time_t)sqlite3_column_int64(stmt, 5);
		stats->last_seen = (time_t)sqlite3_column_int64(stmt, 6);
		stats->sum_time = (unsigned long long)sqlite3_column_int64(stmt, 7);
		stats->min_time = (unsigned long long)sqlite3_column_int64(stmt, 8);
		stats->max_time = (unsigned long long)sqlite3_column_int64(stmt, 9);

		tool_map[dgst] = stats;
	}

	pthread_rwlock_unlock(&mcp_digest_rwlock);
	sqlite3_finalize(stmt);
}

#endif /* PROXYSQL40 */
