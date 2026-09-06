/**
 * @file genai_discovery_schema_unit-t.cpp
 * @brief Unit tests for Discovery_Schema catalog manager
 *
 * Tests the Discovery_Schema class which manages a SQLite-based discovery
 * catalog for database metadata. Uses an in-memory SQLite database (:memory:)
 * so no running daemon or backend servers are required.
 *
 * Tested functions:
 * - Constructor + init() with in-memory SQLite
 * - create_run() / finish_run() / get_run_info()
 * - resolve_run_id() (numeric and schema-based)
 * - insert_schema()
 * - insert_object() / insert_column() / insert_index() / insert_index_column()
 * - insert_foreign_key() / insert_foreign_key_column()
 * - create_agent_run() / finish_agent_run() / get_last_agent_run_id()
 * - upsert_profile()
 * - upsert_llm_summary() / get_llm_summary()
 * - upsert_llm_domain()
 * - upsert_llm_metric()
 * - add_question_template()
 * - add_llm_note()
 * - append_agent_event()
 * - log_llm_search() / log_rag_search_fts() / log_query_tool_call()
 * - list_objects() with pagination and ordering
 * - get_object() with columns, indexes, and profiles
 * - get_relationships()
 * - rebuild_fts_index() / fts_search()
 * - fingerprint_mcp_args() (static, pure)
 * - compute_mcp_digest() (static, pure)
 * - MCP_Query_Digest_Stats::add_timing()
 * - MCP_Query_Processor_Output init/destroy
 *
 * @note Requires PROXYSQL40=1 build (includes genai plugin; auto-detected from libproxysql.a).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

#ifdef PROXYSQL40

#include "Discovery_Schema.h"
#include <string>
#include <cstring>

using json = nlohmann::json;

// ============================================================
// Helper: create an initialized Discovery_Schema with :memory: db
// ============================================================

static Discovery_Schema* create_test_schema() {
	Discovery_Schema* ds = new Discovery_Schema(":memory:");
	int rc = ds->init();
	if (rc != 0) {
		delete ds;
		return nullptr;
	}
	return ds;
}

// Helper: create a run and return its run_id
static int create_test_run(Discovery_Schema* ds, const std::string& target = "test-target") {
	return ds->create_run(target, "mysql", "mysql://localhost:3306/", "8.0.35");
}

// ============================================================
// 1. Construction and initialization
// ============================================================

static void test_init_in_memory() {
	Discovery_Schema ds(":memory:");
	int rc = ds.init();
	ok(rc == 0, "init() succeeds with :memory: database");
	ok(ds.get_db() != nullptr, "get_db() returns non-null after init");
	ok(ds.get_db_path() == ":memory:", "get_db_path() returns :memory:");
}

static void test_double_close() {
	Discovery_Schema ds(":memory:");
	ds.init();
	ds.close();
	ds.close();  // Should not crash
	ok(ds.get_db() == nullptr, "get_db() returns null after close");
}

// ============================================================
// 2. Run management
// ============================================================

static void test_create_run() {
	Discovery_Schema* ds = create_test_schema();
	ok(ds != nullptr, "test schema created");

	int run_id = ds->create_run("target1", "mysql", "mysql://host:3306/", "8.0.35", "test run");
	ok(run_id > 0, "create_run returns positive run_id (got %d)", run_id);

	// Second run should get a different ID
	int run_id2 = ds->create_run("target1", "pgsql", "pgsql://host:5432/", "16.1");
	ok(run_id2 > run_id, "second run gets higher run_id (got %d > %d)", run_id2, run_id);

	delete ds;
}

static void test_finish_run() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	int rc = ds->finish_run(run_id, "completed successfully");
	ok(rc == 0, "finish_run returns 0");

	// Verify via get_run_info
	std::string info_str = ds->get_run_info(run_id);
	json info = json::parse(info_str);
	ok(!info.contains("error"), "get_run_info returns valid run (no error field)");
	ok(info["run_id"] == run_id, "get_run_info run_id matches");
	ok(!info["finished_at"].get<std::string>().empty(), "finished_at is set after finish_run");

	delete ds;
}

static void test_get_run_info_not_found() {
	Discovery_Schema* ds = create_test_schema();

	std::string info_str = ds->get_run_info(99999);
	json info = json::parse(info_str);
	ok(info.contains("error"), "get_run_info for nonexistent run returns error");

	delete ds;
}

static void test_get_run_info_fields() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = ds->create_run("tgt-a", "mysql", "mysql://h:3306/", "8.0.35", "my notes");

	std::string info_str = ds->get_run_info(run_id);
	json info = json::parse(info_str);
	ok(info["target_id"] == "tgt-a", "run info target_id correct");
	ok(info["protocol"] == "mysql", "run info protocol correct");
	ok(info["source_dsn"] == "mysql://h:3306/", "run info source_dsn correct");
	ok(info["server_version"] == "8.0.35", "run info server_version correct");
	ok(info["notes"] == "my notes", "run info notes correct");

	delete ds;
}

// ============================================================
// 3. resolve_run_id
// ============================================================

static void test_resolve_run_id_numeric() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds, "tgt-resolve");

	int resolved = ds->resolve_run_id("tgt-resolve", std::to_string(run_id));
	ok(resolved == run_id, "resolve_run_id returns same numeric run_id (%d == %d)", resolved, run_id);

	// Wrong target_id should fail
	int bad = ds->resolve_run_id("wrong-target", std::to_string(run_id));
	ok(bad == -1, "resolve_run_id fails with wrong target_id");

	delete ds;
}

static void test_resolve_run_id_by_schema() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds, "tgt-schema");
	ds->insert_schema(run_id, "mydb", "utf8mb4", "utf8mb4_general_ci");

	int resolved = ds->resolve_run_id("tgt-schema", "mydb");
	ok(resolved == run_id, "resolve_run_id by schema name returns correct run_id");

	// Nonexistent schema
	int bad = ds->resolve_run_id("tgt-schema", "nonexistent_db");
	ok(bad == -1, "resolve_run_id returns -1 for nonexistent schema");

	delete ds;
}

static void test_resolve_run_id_empty_target() {
	Discovery_Schema* ds = create_test_schema();

	int result = ds->resolve_run_id("", "something");
	ok(result == -1, "resolve_run_id returns -1 when target_id is empty");

	delete ds;
}

// ============================================================
// 4. Schema management
// ============================================================

static void test_insert_schema() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	int schema_id = ds->insert_schema(run_id, "test_db", "utf8mb4", "utf8mb4_unicode_ci");
	ok(schema_id > 0, "insert_schema returns positive schema_id (got %d)", schema_id);

	// Duplicate should fail (returns -1 due to UNIQUE constraint)
	int dup = ds->insert_schema(run_id, "test_db", "utf8mb4", "utf8mb4_unicode_ci");
	ok(dup == -1 || dup == schema_id, "duplicate insert_schema handled (got %d)", dup);

	delete ds;
}

// ============================================================
// 5. Object management
// ============================================================

static void test_insert_object() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	int obj_id = ds->insert_object(run_id, "mydb", "users", "table", "InnoDB",
		1000, 65536, 16384, "2024-01-01", "2024-06-15", "Main users table");
	ok(obj_id > 0, "insert_object returns positive object_id (got %d)", obj_id);

	// Insert a view
	int view_id = ds->insert_object(run_id, "mydb", "active_users", "view",
		"", 0, 0, 0, "", "", "Active users view",
		"SELECT * FROM users WHERE active = 1");
	ok(view_id > obj_id, "insert view gets different object_id");

	delete ds;
}

static void test_insert_column() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int obj_id = ds->insert_object(run_id, "mydb", "users", "table");

	int col_id = ds->insert_column(obj_id, 1, "id", "int", "int(11)", 0,
		"", "auto_increment", "", "", "Primary key", 1, 1, 1, 0, 1);
	ok(col_id > 0, "insert_column returns positive column_id (got %d)", col_id);

	int col_id2 = ds->insert_column(obj_id, 2, "name", "varchar", "varchar(255)", 1,
		"", "", "utf8mb4", "utf8mb4_general_ci", "User name", 0, 0, 0, 0, 0);
	ok(col_id2 > col_id, "second column gets higher id");

	int col_id3 = ds->insert_column(obj_id, 3, "created_at", "datetime", "datetime", 1,
		"CURRENT_TIMESTAMP", "", "", "", "Creation timestamp", 0, 0, 0, 1, 0);
	ok(col_id3 > col_id2, "third column gets higher id");

	delete ds;
}

static void test_insert_index() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int obj_id = ds->insert_object(run_id, "mydb", "users", "table");

	int idx_id = ds->insert_index(obj_id, "PRIMARY", 1, 1, "BTREE", 1000);
	ok(idx_id > 0, "insert_index returns positive index_id (got %d)", idx_id);

	int rc = ds->insert_index_column(idx_id, 1, "id", 0, "A");
	ok(rc == 0, "insert_index_column returns 0");

	// Insert a composite index
	int idx_id2 = ds->insert_index(obj_id, "idx_name_email", 0, 0, "BTREE", 500);
	ok(idx_id2 > idx_id, "second index gets higher id");

	int rc2 = ds->insert_index_column(idx_id2, 1, "name");
	ok(rc2 == 0, "insert_index_column for composite index col 1");
	int rc3 = ds->insert_index_column(idx_id2, 2, "email");
	ok(rc3 == 0, "insert_index_column for composite index col 2");

	delete ds;
}

static void test_insert_foreign_key() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int parent_id = ds->insert_object(run_id, "mydb", "users", "table");
	int child_id = ds->insert_object(run_id, "mydb", "orders", "table");

	int fk_id = ds->insert_foreign_key(run_id, child_id, "fk_orders_user",
		"mydb", "users", "CASCADE", "RESTRICT");
	ok(fk_id > 0, "insert_foreign_key returns positive fk_id (got %d)", fk_id);

	int rc = ds->insert_foreign_key_column(fk_id, 1, "user_id", "id");
	ok(rc == 0, "insert_foreign_key_column returns 0");

	// Suppress unused variable warning
	(void)parent_id;

	delete ds;
}

// ============================================================
// 6. Agent run management
// ============================================================

static void test_agent_run_lifecycle() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	int agent_run_id = ds->create_agent_run(run_id, "claude-3.5-sonnet", "abc123", "{\"max_tokens\":4096}");
	ok(agent_run_id > 0, "create_agent_run returns positive id (got %d)", agent_run_id);

	int last = ds->get_last_agent_run_id(run_id);
	ok(last == agent_run_id, "get_last_agent_run_id returns correct id");

	int rc = ds->finish_agent_run(agent_run_id, "success");
	ok(rc == 0, "finish_agent_run returns 0");

	delete ds;
}

static void test_get_last_agent_run_no_runs() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	int last = ds->get_last_agent_run_id(run_id);
	ok(last == 0, "get_last_agent_run_id returns 0 when no agent runs exist");

	delete ds;
}

static void test_get_last_agent_run_fallback() {
	Discovery_Schema* ds = create_test_schema();
	int run_id1 = create_test_run(ds, "target1");
	int run_id2 = create_test_run(ds, "target2");

	// Create agent run only for run_id1
	int agent_id = ds->create_agent_run(run_id1, "claude-3.5-sonnet");

	// Query for run_id2 which has no agent runs - should fallback to most recent
	int last = ds->get_last_agent_run_id(run_id2);
	ok(last == agent_id, "get_last_agent_run_id falls back to most recent across all runs");

	delete ds;
}

// ============================================================
// 7. Profile management
// ============================================================

static void test_upsert_profile() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int obj_id = ds->insert_object(run_id, "mydb", "users", "table");

	json profile;
	profile["row_count"] = 1000;
	profile["guessed_kind"] = "entity";

	int rc = ds->upsert_profile(run_id, obj_id, "table_quick", profile.dump());
	ok(rc == 0, "upsert_profile returns 0 on insert");

	// Upsert (update) same profile kind
	profile["row_count"] = 2000;
	int rc2 = ds->upsert_profile(run_id, obj_id, "table_quick", profile.dump());
	ok(rc2 == 0, "upsert_profile returns 0 on update");

	delete ds;
}

// ============================================================
// 8. LLM layer: summaries
// ============================================================

static void test_upsert_and_get_llm_summary() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int obj_id = ds->insert_object(run_id, "mydb", "users", "table");
	int agent_run_id = ds->create_agent_run(run_id, "claude-3.5-sonnet");

	json summary;
	summary["purpose"] = "Stores user accounts";
	summary["patterns"] = json::array({"SCD Type 2", "soft delete"});

	int rc = ds->upsert_llm_summary(agent_run_id, run_id, obj_id,
		summary.dump(), 0.85, "draft", "{\"source\":\"schema\"}");
	ok(rc == 0, "upsert_llm_summary returns 0");

	std::string result_str = ds->get_llm_summary(run_id, obj_id);
	ok(result_str != "null", "get_llm_summary returns non-null");

	json result = json::parse(result_str);
	ok(result["confidence"].get<double>() > 0.8, "confidence is preserved (%.2f)",
		result["confidence"].get<double>());
	ok(result["status"] == "draft", "status is preserved");

	delete ds;
}

static void test_get_llm_summary_not_found() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	std::string result = ds->get_llm_summary(run_id, 99999);
	ok(result == "null", "get_llm_summary returns null for nonexistent object");

	delete ds;
}

// ============================================================
// 9. LLM domains
// ============================================================

static void test_upsert_llm_domain() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int agent_run_id = ds->create_agent_run(run_id, "claude-3.5-sonnet");

	int domain_id = ds->upsert_llm_domain(agent_run_id, run_id,
		"billing", "Billing Domain", "Tables related to billing and payments", 0.8);
	ok(domain_id > 0, "upsert_llm_domain returns positive domain_id (got %d)", domain_id);

	// Upsert same domain key should succeed
	int domain_id2 = ds->upsert_llm_domain(agent_run_id, run_id,
		"billing", "Billing Domain Updated", "Updated description", 0.9);
	// domain_id2 might be same or different depending on SQLite behavior
	ok(domain_id2 > 0 || domain_id2 == domain_id,
		"upsert_llm_domain handles update (got %d)", domain_id2);

	delete ds;
}

// ============================================================
// 10. LLM metrics
// ============================================================

static void test_upsert_llm_metric() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int agent_run_id = ds->create_agent_run(run_id, "claude-3.5-sonnet");

	int metric_id = ds->upsert_llm_metric(agent_run_id, run_id,
		"orders.count", "Order Count", "Total number of orders",
		"billing", "day", "count",
		"SELECT COUNT(*) FROM orders WHERE date >= ?", "", 0.75);
	ok(metric_id > 0, "upsert_llm_metric returns positive metric_id (got %d)", metric_id);

	delete ds;
}

// ============================================================
// 11. Question templates
// ============================================================

static void test_add_question_template() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int agent_run_id = ds->create_agent_run(run_id, "claude-3.5-sonnet");

	json template_json;
	template_json["type"] = "aggregate";
	template_json["tables"] = json::array({"orders"});

	int tpl_id = ds->add_question_template(agent_run_id, run_id,
		"Order Count", "How many orders were placed last month?",
		template_json.dump(),
		"SELECT COUNT(*) FROM orders WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 MONTH)",
		"[\"orders\"]", 0.7);
	ok(tpl_id > 0, "add_question_template returns positive id (got %d)", tpl_id);

	delete ds;
}

// ============================================================
// 12. LLM notes
// ============================================================

static void test_add_llm_note() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int agent_run_id = ds->create_agent_run(run_id, "claude-3.5-sonnet");

	int note_id = ds->add_llm_note(agent_run_id, run_id, "global", -1, "",
		"Schema Design Pattern", "Uses soft-delete pattern widely", "[\"pattern\",\"design\"]");
	ok(note_id > 0, "add_llm_note returns positive note_id (got %d)", note_id);

	delete ds;
}

// ============================================================
// 13. Agent events
// ============================================================

static void test_append_agent_event() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int agent_run_id = ds->create_agent_run(run_id, "claude-3.5-sonnet");

	json payload;
	payload["tool"] = "list_tables";
	payload["args"] = json::object();

	int event_id = ds->append_agent_event(agent_run_id, "tool_call", payload.dump());
	ok(event_id > 0, "append_agent_event returns positive event_id (got %d)", event_id);

	// Append a second event
	json result_payload;
	result_payload["tables"] = json::array({"users", "orders"});
	int event_id2 = ds->append_agent_event(agent_run_id, "tool_result", result_payload.dump());
	ok(event_id2 > event_id, "second event gets higher id");

	delete ds;
}

// ============================================================
// 14. Logging functions
// ============================================================

static void test_log_llm_search() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	int rc = ds->log_llm_search(run_id, "users table with email", 10);
	ok(rc == 0, "log_llm_search returns 0");

	delete ds;
}

static void test_log_rag_search_fts() {
	Discovery_Schema* ds = create_test_schema();

	Discovery_Schema* ds2 = create_test_schema();
	int rc = ds2->log_rag_search_fts("billing tables", 5, "{\"type\":\"table\"}");
	ok(rc == 0, "log_rag_search_fts returns 0");

	delete ds;
	delete ds2;
}

static void test_log_query_tool_call() {
	Discovery_Schema* ds = create_test_schema();

	int rc = ds->log_query_tool_call("list_schemas", "mydb", 1, 1000000, 5000, "");
	ok(rc == 0, "log_query_tool_call returns 0 on success");

	int rc2 = ds->log_query_tool_call("run_sql", "mydb", 1, 2000000, 15000, "syntax error");
	ok(rc2 == 0, "log_query_tool_call returns 0 with error message");

	delete ds;
}

// ============================================================
// 15. list_objects with pagination and ordering
// ============================================================

static void test_list_objects_empty() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	std::string result_str = ds->list_objects(run_id);
	json result = json::parse(result_str);
	ok(result["results"].is_array(), "list_objects returns results array");
	ok(result["results"].size() == 0, "list_objects returns empty array for empty run");
	ok(result["next_page_token"] == "", "next_page_token is empty when no results");

	delete ds;
}

static void test_list_objects_with_data() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	ds->insert_object(run_id, "mydb", "users", "table", "InnoDB", 1000);
	ds->insert_object(run_id, "mydb", "orders", "table", "InnoDB", 5000);
	ds->insert_object(run_id, "mydb", "active_users", "view");

	std::string result_str = ds->list_objects(run_id);
	json result = json::parse(result_str);
	ok(result["results"].size() == 3, "list_objects returns all 3 objects (got %zu)",
		result["results"].size());

	// Filter by type
	std::string tables_str = ds->list_objects(run_id, "", "table");
	json tables = json::parse(tables_str);
	ok(tables["results"].size() == 2, "list_objects with type=table returns 2");

	// Filter by schema
	std::string schema_str = ds->list_objects(run_id, "mydb");
	json schema_res = json::parse(schema_str);
	ok(schema_res["results"].size() == 3, "list_objects with schema=mydb returns 3");

	delete ds;
}

static void test_list_objects_pagination() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	// Insert 5 objects
	for (int i = 0; i < 5; i++) {
		std::string name = "table_" + std::to_string(i);
		ds->insert_object(run_id, "mydb", name, "table", "InnoDB", i * 100);
	}

	// Page 1: 2 items
	std::string page1_str = ds->list_objects(run_id, "", "", "name", 2, "");
	json page1 = json::parse(page1_str);
	ok(page1["results"].size() == 2, "page 1 returns 2 items");
	ok(!page1["next_page_token"].get<std::string>().empty(), "page 1 has next_page_token");

	// Page 2
	std::string page2_str = ds->list_objects(run_id, "", "", "name", 2,
		page1["next_page_token"].get<std::string>());
	json page2 = json::parse(page2_str);
	ok(page2["results"].size() == 2, "page 2 returns 2 items");

	// Page 3 (last)
	std::string page3_str = ds->list_objects(run_id, "", "", "name", 2,
		page2["next_page_token"].get<std::string>());
	json page3 = json::parse(page3_str);
	ok(page3["results"].size() == 1, "page 3 returns 1 item (last page)");
	ok(page3["next_page_token"] == "", "last page has empty next_page_token");

	delete ds;
}

static void test_list_objects_ordering() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	ds->insert_object(run_id, "mydb", "small_table", "table", "InnoDB", 100, 1000, 500);
	ds->insert_object(run_id, "mydb", "big_table", "table", "InnoDB", 10000, 50000, 20000);
	ds->insert_object(run_id, "mydb", "medium_table", "table", "InnoDB", 1000, 10000, 5000);

	// Order by rows_est_desc
	std::string result_str = ds->list_objects(run_id, "", "", "rows_est_desc");
	json result = json::parse(result_str);
	ok(result["results"][0]["object_name"] == "big_table",
		"rows_est_desc: biggest table first");

	// Order by size_desc
	std::string size_str = ds->list_objects(run_id, "", "", "size_desc");
	json size_result = json::parse(size_str);
	ok(size_result["results"][0]["object_name"] == "big_table",
		"size_desc: largest by data+index first");

	delete ds;
}

// ============================================================
// 16. get_object — detailed object retrieval
// ============================================================

static void test_get_object_not_found() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	std::string result = ds->get_object(run_id, 99999);
	ok(result == "null", "get_object returns null for nonexistent object_id");

	std::string result2 = ds->get_object(run_id, -1, "nonexistent", "notable");
	ok(result2 == "null", "get_object returns null for nonexistent schema.object");

	delete ds;
}

static void test_get_object_with_columns_and_indexes() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	int obj_id = ds->insert_object(run_id, "mydb", "users", "table", "InnoDB", 1000);
	ds->insert_column(obj_id, 1, "id", "int", "int(11)", 0, "", "auto_increment",
		"", "", "", 1, 1, 1, 0, 1);
	ds->insert_column(obj_id, 2, "name", "varchar", "varchar(255)", 1);
	ds->insert_column(obj_id, 3, "created_at", "datetime", "datetime", 1,
		"CURRENT_TIMESTAMP", "", "", "", "", 0, 0, 0, 1, 0);

	int idx_id = ds->insert_index(obj_id, "PRIMARY", 1, 1, "BTREE", 1000);
	ds->insert_index_column(idx_id, 1, "id");

	// Get by object_id
	std::string result_str = ds->get_object(run_id, obj_id);
	json result = json::parse(result_str);

	ok(result["object_name"] == "users", "get_object name correct");
	ok(result["object_type"] == "table", "get_object type correct");
	ok(result["engine"] == "InnoDB", "get_object engine correct");
	ok(result["table_rows_est"] == 1000, "get_object rows_est correct");
	ok(result["columns"].is_array(), "get_object has columns array");
	ok(result["columns"].size() == 3, "get_object has 3 columns");
	ok(result["columns"][0]["column_name"] == "id", "first column is id (by ordinal)");
	ok(result["columns"][0]["is_pk"] == 1, "id column is_pk=1");
	ok(result["columns"][2]["is_time"] == 1, "created_at is_time=1");
	ok(result["indexes"].is_array(), "get_object has indexes array");
	ok(result["indexes"].size() == 1, "get_object has 1 index");
	ok(result["indexes"][0]["index_name"] == "PRIMARY", "index name is PRIMARY");
	ok(result["indexes"][0]["is_primary"] == 1, "index is_primary=1");

	delete ds;
}

static void test_get_object_by_name() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	ds->insert_object(run_id, "mydb", "orders", "table", "InnoDB", 5000);

	std::string result_str = ds->get_object(run_id, -1, "mydb", "orders");
	json result = json::parse(result_str);
	ok(result["object_name"] == "orders", "get_object by name returns correct object");
	ok(result["table_rows_est"] == 5000, "get_object by name has correct row count");

	delete ds;
}

static void test_get_object_with_profiles() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int obj_id = ds->insert_object(run_id, "mydb", "users", "table");

	json profile;
	profile["row_count"] = 1000;
	profile["guessed_kind"] = "entity";
	ds->upsert_profile(run_id, obj_id, "table_quick", profile.dump());

	std::string result_str = ds->get_object(run_id, obj_id, "", "", false, true);
	json result = json::parse(result_str);
	ok(result.contains("profiles"), "get_object includes profiles");
	ok(result["profiles"].contains("table_quick"), "profiles has table_quick");
	ok(result["profiles"]["table_quick"]["guessed_kind"] == "entity",
		"profile guessed_kind correct");

	// Without profiles
	std::string no_prof_str = ds->get_object(run_id, obj_id, "", "", false, false);
	json no_prof = json::parse(no_prof_str);
	ok(!no_prof.contains("profiles"), "get_object without profiles flag excludes profiles");

	delete ds;
}

// ============================================================
// 17. get_relationships
// ============================================================

static void test_get_relationships() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int parent_id = ds->insert_object(run_id, "mydb", "users", "table");
	int child_id = ds->insert_object(run_id, "mydb", "orders", "table");

	int fk_id = ds->insert_foreign_key(run_id, child_id, "fk_orders_user",
		"mydb", "users", "CASCADE", "RESTRICT");
	ds->insert_foreign_key_column(fk_id, 1, "user_id", "id");

	std::string result_str = ds->get_relationships(run_id, child_id);
	json result = json::parse(result_str);

	ok(result["foreign_keys"].is_array(), "relationships has foreign_keys array");
	ok(result["foreign_keys"].size() == 1, "has 1 foreign key");
	ok(result["foreign_keys"][0]["fk_name"] == "fk_orders_user", "FK name correct");
	ok(result["foreign_keys"][0]["parent_object_name"] == "users", "FK parent correct");
	ok(result["foreign_keys"][0]["columns"].size() == 1, "FK has 1 column mapping");
	ok(result["foreign_keys"][0]["columns"][0]["child_column"] == "user_id", "FK child_column correct");
	ok(result["foreign_keys"][0]["columns"][0]["parent_column"] == "id", "FK parent_column correct");

	// Suppress unused variable warning
	(void)parent_id;

	delete ds;
}

static void test_get_relationships_empty() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int obj_id = ds->insert_object(run_id, "mydb", "standalone", "table");

	std::string result_str = ds->get_relationships(run_id, obj_id);
	json result = json::parse(result_str);
	ok(result["foreign_keys"].size() == 0, "standalone table has no foreign keys");
	ok(result["inferred_relationships"].size() == 0, "standalone table has no inferred relationships");

	delete ds;
}

// ============================================================
// 18. FTS: rebuild and search
// ============================================================

static void test_rebuild_fts_index() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	int obj1 = ds->insert_object(run_id, "mydb", "users", "table", "InnoDB", 1000,
		0, 0, "", "", "User accounts table");
	ds->insert_column(obj1, 1, "id", "int");
	ds->insert_column(obj1, 2, "email", "varchar");

	int obj2 = ds->insert_object(run_id, "mydb", "orders", "table", "InnoDB", 5000,
		0, 0, "", "", "Customer orders");
	ds->insert_column(obj2, 1, "order_id", "int");
	ds->insert_column(obj2, 2, "user_id", "int");

	int rc = ds->rebuild_fts_index(run_id);
	ok(rc == 0, "rebuild_fts_index returns 0");

	delete ds;
}

static void test_fts_search() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);

	ds->insert_object(run_id, "mydb", "users", "table", "InnoDB", 1000,
		0, 0, "", "", "User accounts and authentication");
	ds->insert_object(run_id, "mydb", "orders", "table", "InnoDB", 5000,
		0, 0, "", "", "Customer purchase orders");
	ds->insert_object(run_id, "mydb", "payments", "table", "InnoDB", 3000,
		0, 0, "", "", "Payment transactions");

	ds->rebuild_fts_index(run_id);

	// Search for "users"
	std::string results_str = ds->fts_search(run_id, "users");
	json results = json::parse(results_str);
	ok(results.is_array(), "fts_search returns array");
	ok(results.size() >= 1, "fts_search for 'users' returns at least 1 result (got %zu)",
		results.size());

	// Search for "orders"
	std::string orders_str = ds->fts_search(run_id, "orders");
	json orders = json::parse(orders_str);
	ok(orders.size() >= 1, "fts_search for 'orders' returns results");

	delete ds;
}

// ============================================================
// 19. fingerprint_mcp_args (static, pure function)
// ============================================================

static void test_fingerprint_simple_object() {
	json args;
	args["sql"] = "SELECT * FROM users WHERE id = 42";
	args["timeout"] = 5000;

	std::string fp = Discovery_Schema::fingerprint_mcp_args(args);
	ok(fp.find("\"timeout\":\"?\"") != std::string::npos,
		"fingerprint replaces numeric with ?");
	ok(fp.find("42") == std::string::npos,
		"fingerprint does not contain original number 42");
	// sql key should have a digest, not "?"
	ok(fp.find("\"sql\":\"") != std::string::npos,
		"fingerprint has sql key with digest value");
}

static void test_fingerprint_nested_object() {
	json args;
	args["filters"]["status"] = "active";
	args["filters"]["age"] = 25;

	std::string fp = Discovery_Schema::fingerprint_mcp_args(args);
	ok(fp.find("\"filters\":{") != std::string::npos,
		"fingerprint preserves nested object structure");
	ok(fp.find("active") == std::string::npos,
		"fingerprint replaces nested string literal");
}

static void test_fingerprint_array() {
	json args;
	args["ids"] = json::array({1, 2, 3});

	std::string fp = Discovery_Schema::fingerprint_mcp_args(args);
	ok(fp.find("\"ids\":[\"?\"]") != std::string::npos,
		"fingerprint replaces array with [\"?\"]");
}

static void test_fingerprint_null() {
	json args;
	args["value"] = nullptr;

	std::string fp = Discovery_Schema::fingerprint_mcp_args(args);
	ok(fp.find("null") != std::string::npos,
		"fingerprint preserves null as null");
}

static void test_fingerprint_boolean() {
	json args;
	args["active"] = true;
	args["deleted"] = false;

	std::string fp = Discovery_Schema::fingerprint_mcp_args(args);
	ok(fp.find("\"active\":\"?\"") != std::string::npos,
		"fingerprint replaces boolean with ?");
}

static void test_fingerprint_empty_object() {
	json args = json::object();
	std::string fp = Discovery_Schema::fingerprint_mcp_args(args);
	ok(fp == "{}", "fingerprint of empty object is {}");
}

static void test_fingerprint_non_object() {
	// Array at top level
	json arr = json::array({1, 2, 3});
	std::string fp = Discovery_Schema::fingerprint_mcp_args(arr);
	ok(fp == "[\"?\"]", "fingerprint of top-level array is [\"?\"]");

	// Scalar at top level
	json scalar = "hello";
	std::string fp2 = Discovery_Schema::fingerprint_mcp_args(scalar);
	ok(fp2 == "\"?\"", "fingerprint of top-level scalar is \"?\"");
}

// ============================================================
// 20. compute_mcp_digest (static, deterministic)
// ============================================================

static void test_compute_mcp_digest_deterministic() {
	json args;
	args["sql"] = "SELECT 1";

	uint64_t hash1 = Discovery_Schema::compute_mcp_digest("test_tool", args);
	uint64_t hash2 = Discovery_Schema::compute_mcp_digest("test_tool", args);
	ok(hash1 == hash2, "compute_mcp_digest is deterministic");
	ok(hash1 != 0, "compute_mcp_digest returns non-zero hash");
}

static void test_compute_mcp_digest_different_tools() {
	json args;
	args["sql"] = "SELECT 1";

	uint64_t hash1 = Discovery_Schema::compute_mcp_digest("tool_a", args);
	uint64_t hash2 = Discovery_Schema::compute_mcp_digest("tool_b", args);
	ok(hash1 != hash2, "different tool names produce different digests");
}

static void test_compute_mcp_digest_different_args() {
	json args1;
	args1["schema"] = "db1";
	json args2;
	args2["schema"] = "db2";

	uint64_t hash1 = Discovery_Schema::compute_mcp_digest("same_tool", args1);
	uint64_t hash2 = Discovery_Schema::compute_mcp_digest("same_tool", args2);
	// Both have same structure so fingerprints are the same -> same digest
	ok(hash1 == hash2, "same structure different values produce same digest (fingerprint-based)");
}

// ============================================================
// 21. MCP_Query_Digest_Stats struct
// ============================================================

static void test_mcp_query_digest_stats() {
	MCP_Query_Digest_Stats stats;
	ok(stats.count_star == 0, "initial count_star is 0");
	ok(stats.sum_time == 0, "initial sum_time is 0");
	ok(stats.min_time == 0, "initial min_time is 0");
	ok(stats.max_time == 0, "initial max_time is 0");

	stats.add_timing(100, 1000);
	ok(stats.count_star == 1, "after 1st add: count_star=1");
	ok(stats.sum_time == 100, "after 1st add: sum_time=100");
	ok(stats.min_time == 100, "after 1st add: min_time=100");
	ok(stats.max_time == 100, "after 1st add: max_time=100");
	ok(stats.first_seen == 1000, "after 1st add: first_seen=1000");
	ok(stats.last_seen == 1000, "after 1st add: last_seen=1000");

	stats.add_timing(50, 2000);
	ok(stats.count_star == 2, "after 2nd add: count_star=2");
	ok(stats.sum_time == 150, "after 2nd add: sum_time=150");
	ok(stats.min_time == 50, "after 2nd add: min_time=50");
	ok(stats.max_time == 100, "after 2nd add: max_time=100");
	ok(stats.first_seen == 1000, "after 2nd add: first_seen unchanged");
	ok(stats.last_seen == 2000, "after 2nd add: last_seen=2000");

	stats.add_timing(200, 3000);
	ok(stats.count_star == 3, "after 3rd add: count_star=3");
	ok(stats.sum_time == 350, "after 3rd add: sum_time=350");
	ok(stats.min_time == 50, "after 3rd add: min_time unchanged");
	ok(stats.max_time == 200, "after 3rd add: max_time=200");
}

// ============================================================
// 22. MCP_Query_Processor_Output
// ============================================================

static void test_mcp_query_processor_output() {
	MCP_Query_Processor_Output output;
	ok(output.new_query == nullptr, "init: new_query is null");
	ok(output.timeout_ms == -1, "init: timeout_ms is -1");
	ok(output.error_msg == nullptr, "init: error_msg is null");
	ok(output.OK_msg == nullptr, "init: OK_msg is null");
	ok(output.log == -1, "init: log is -1");
	ok(output.next_query_flagIN == -1, "init: next_query_flagIN is -1");

	// Set values and destroy
	output.new_query = new std::string("SELECT 1");
	output.error_msg = strdup("test error");
	output.OK_msg = strdup("test ok");
	output.destroy();
	ok(output.new_query == nullptr, "destroy: new_query is null");
	ok(output.error_msg == nullptr, "destroy: error_msg is null");
	ok(output.OK_msg == nullptr, "destroy: OK_msg is null");
}

// ============================================================
// 23. MCP_Query_Rule struct defaults
// ============================================================

static void test_mcp_query_rule_defaults() {
	MCP_Query_Rule rule;
	ok(rule.rule_id == 0, "default rule_id is 0");
	ok(rule.active == false, "default active is false");
	ok(rule.username == nullptr, "default username is null");
	ok(rule.target_id == nullptr, "default target_id is null");
	ok(rule.match_pattern == nullptr, "default match_pattern is null");
	ok(rule.negate_match_pattern == false, "default negate_match_pattern is false");
	ok(rule.re_modifiers == 1, "default re_modifiers is 1 (CASELESS)");
	ok(rule.flagIN == 0, "default flagIN is 0");
	ok(rule.flagOUT == -1, "default flagOUT is -1");
	ok(rule.replace_pattern == nullptr, "default replace_pattern is null");
	ok(rule.timeout_ms == -1, "default timeout_ms is -1");
	ok(rule.error_msg == nullptr, "default error_msg is null");
	ok(rule.ok_msg == nullptr, "default ok_msg is null");
	ok(rule.log == -1, "default log is -1");
	ok(rule.apply == true, "default apply is true");
	ok(rule.comment == nullptr, "default comment is null");
	ok(rule.hits == 0, "default hits is 0");
	ok(rule.regex_engine == nullptr, "default regex_engine is null");
}

// ============================================================
// 24. upsert_llm_relationship
// ============================================================

static void test_upsert_llm_relationship() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int obj1 = ds->insert_object(run_id, "mydb", "orders", "table");
	int obj2 = ds->insert_object(run_id, "mydb", "users", "table");
	int agent_run_id = ds->create_agent_run(run_id, "claude-3.5-sonnet");

	int rc = ds->upsert_llm_relationship(agent_run_id, run_id,
		obj1, "user_id", obj2, "id", "fk_like", 0.9, "{\"evidence\":\"naming convention\"}");
	ok(rc == 0, "upsert_llm_relationship returns 0");

	// Upsert same relationship should succeed (update confidence)
	int rc2 = ds->upsert_llm_relationship(agent_run_id, run_id,
		obj1, "user_id", obj2, "id", "fk_like", 0.95, "{\"evidence\":\"confirmed\"}");
	ok(rc2 == 0, "upsert_llm_relationship update returns 0");

	delete ds;
}

// ============================================================
// 25. set_domain_members
// ============================================================

static void test_set_domain_members() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int agent_run_id = ds->create_agent_run(run_id, "claude-3.5-sonnet");

	int obj1 = ds->insert_object(run_id, "mydb", "invoices", "table");
	int obj2 = ds->insert_object(run_id, "mydb", "payments", "table");

	// Create domain first
	ds->upsert_llm_domain(agent_run_id, run_id, "billing", "Billing", "Billing tables");

	json members = json::array();
	json m1;
	m1["object_id"] = obj1;
	m1["role"] = "core";
	m1["confidence"] = 0.9;
	members.push_back(m1);
	json m2;
	m2["object_id"] = obj2;
	m2["role"] = "supporting";
	m2["confidence"] = 0.7;
	members.push_back(m2);

	int rc = ds->set_domain_members(agent_run_id, run_id, "billing", members.dump());
	ok(rc == 0, "set_domain_members returns 0");

	delete ds;
}

static void test_set_domain_members_nonexistent_domain() {
	Discovery_Schema* ds = create_test_schema();
	int run_id = create_test_run(ds);
	int agent_run_id = ds->create_agent_run(run_id, "claude-3.5-sonnet");

	int rc = ds->set_domain_members(agent_run_id, run_id, "nonexistent", "[]");
	ok(rc == -1, "set_domain_members returns -1 for nonexistent domain");

	delete ds;
}

// ============================================================
// Main
// ============================================================

int main() {
	plan(172);
	test_init_minimal();

	// 1. Construction and initialization (4 tests)
	test_init_in_memory();
	test_double_close();

	// 2. Run management (11 tests)
	test_create_run();
	test_finish_run();
	test_get_run_info_not_found();
	test_get_run_info_fields();

	// 3. resolve_run_id (5 tests)
	test_resolve_run_id_numeric();
	test_resolve_run_id_by_schema();
	test_resolve_run_id_empty_target();

	// 4. Schema management (2 tests)
	test_insert_schema();

	// 5. Object management (7 tests)
	test_insert_object();
	test_insert_column();
	test_insert_index();
	test_insert_foreign_key();

	// 6. Agent run management (5 tests)
	test_agent_run_lifecycle();
	test_get_last_agent_run_no_runs();
	test_get_last_agent_run_fallback();

	// 7. Profile management (2 tests)
	test_upsert_profile();

	// 8. LLM summaries (4 tests)
	test_upsert_and_get_llm_summary();
	test_get_llm_summary_not_found();

	// 9. LLM domains (2 tests)
	test_upsert_llm_domain();

	// 10. LLM metrics (1 test)
	test_upsert_llm_metric();

	// 11. Question templates (1 test)
	test_add_question_template();

	// 12. LLM notes (1 test)
	test_add_llm_note();

	// 13. Agent events (2 tests)
	test_append_agent_event();

	// 14. Logging (4 tests)
	test_log_llm_search();
	test_log_rag_search_fts();
	test_log_query_tool_call();

	// 15. list_objects (10 tests)
	test_list_objects_empty();
	test_list_objects_with_data();
	test_list_objects_pagination();
	test_list_objects_ordering();

	// 16. get_object (17 tests)
	test_get_object_not_found();
	test_get_object_with_columns_and_indexes();
	test_get_object_by_name();
	test_get_object_with_profiles();

	// 17. Relationships (9 tests)
	test_get_relationships();
	test_get_relationships_empty();

	// 18. FTS (4 tests)
	test_rebuild_fts_index();
	test_fts_search();

	// 19. fingerprint_mcp_args (8 tests)
	test_fingerprint_simple_object();
	test_fingerprint_nested_object();
	test_fingerprint_array();
	test_fingerprint_null();
	test_fingerprint_boolean();
	test_fingerprint_empty_object();
	test_fingerprint_non_object();

	// 20. compute_mcp_digest (3 tests)
	test_compute_mcp_digest_deterministic();
	test_compute_mcp_digest_different_tools();
	test_compute_mcp_digest_different_args();

	// 21. MCP_Query_Digest_Stats (19 tests)
	test_mcp_query_digest_stats();

	// 22. MCP_Query_Processor_Output (9 tests)
	test_mcp_query_processor_output();

	// 23. MCP_Query_Rule defaults (18 tests)
	test_mcp_query_rule_defaults();

	// 24. LLM relationships (2 tests)
	test_upsert_llm_relationship();

	// 25. Domain members (2 tests)
	test_set_domain_members();
	test_set_domain_members_nonexistent_domain();

	test_cleanup_minimal();
	return exit_status();
}

#else /* !PROXYSQL40 */

int main() {
	plan(1);
	ok(1, "PROXYSQL40 not enabled — skipping Discovery_Schema tests");
	return exit_status();
}

#endif /* PROXYSQL40 */
