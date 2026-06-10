/**
 * @file genai_rag_fetch_from_source_unit-t.cpp
 * @brief Unit tests for rag.fetch_from_source.
 *
 * This test exercises the shipping-critical fetch path without a live
 * backend by seeding the local RAG metadata tables and pointing the
 * source at an unused localhost port. That verifies:
 *   - tool discovery includes rag.fetch_from_source
 *   - document metadata is looked up from vector_db
 *   - backend connection failures are surfaced to the caller
 *   - missing document IDs are reported per-row
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "RAG_Tool_Handler.h"
#include "sqlite3db.h"

#include <cstdlib>
#include <string>

namespace {

struct RagFixture {
	RagFixture() {
		db = new SQLite3DB();
		ok(db->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX) == 0,
		   "open in-memory RAG vector db");

		ok(db->execute("CREATE TABLE rag_sources ("
		              " source_id INTEGER PRIMARY KEY,"
		              " name TEXT NOT NULL UNIQUE,"
		              " enabled INTEGER NOT NULL DEFAULT 1,"
		              " backend_type TEXT NOT NULL,"
		              " backend_host TEXT NOT NULL,"
		              " backend_port INTEGER NOT NULL,"
		              " backend_user TEXT NOT NULL,"
		              " backend_pass TEXT NOT NULL,"
		              " backend_db TEXT NOT NULL,"
		              " table_name TEXT NOT NULL,"
		              " pk_column TEXT NOT NULL,"
		              " where_sql TEXT,"
		              " doc_map_json TEXT NOT NULL,"
		              " chunking_json TEXT NOT NULL,"
		              " embedding_json TEXT,"
		              " created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
		              " updated_at INTEGER NOT NULL DEFAULT (unixepoch()))"),
		   "create rag_sources table");

		ok(db->execute("CREATE TABLE rag_documents ("
		              " doc_id TEXT PRIMARY KEY,"
		              " source_id INTEGER NOT NULL,"
		              " source_name TEXT NOT NULL,"
		              " pk_json TEXT NOT NULL,"
		              " title TEXT,"
		              " body TEXT,"
		              " metadata_json TEXT NOT NULL DEFAULT '{}',"
		              " updated_at INTEGER NOT NULL DEFAULT (unixepoch()),"
		              " deleted INTEGER NOT NULL DEFAULT 0)"),
		   "create rag_documents table");

		ok(db->execute("INSERT INTO rag_sources ("
		              "source_id, name, enabled, backend_type, backend_host, backend_port,"
		              "backend_user, backend_pass, backend_db, table_name, pk_column,"
		              "doc_map_json, chunking_json)"
		              " VALUES (1, 'mysql_source', 1, 'mysql', '127.0.0.1', 65000,"
		              "'root', 'root', 'test_db', 'source_table', 'id',"
		              "'{\"doc_id\":{\"format\":\"doc:{id}\"}}',"
		              "'{\"enabled\":false,\"unit\":\"chars\",\"chunk_size\":4000,\"overlap\":400}' )"),
		   "insert rag source");

		ok(db->execute("INSERT INTO rag_documents ("
		              "doc_id, source_id, source_name, pk_json, title, metadata_json, deleted)"
		              " VALUES ('doc:1', 1, 'mysql_source', '{\"id\":1}',"
		              " 'First Document', '{}', 0)"),
		   "insert rag document");
	}

	~RagFixture() {
		delete db;
		db = nullptr;
	}

	SQLite3DB* db { nullptr };
};

} // namespace

int main() {
	plan(17);

	test_init_minimal();

	RagFixture fixture;
	RAG_Tool_Handler handler(nullptr);
	handler.set_vector_db(fixture.db);

	const json tools = handler.get_tool_list();
	bool found_fetch = false;
	for (const auto& tool : tools["tools"]) {
		if (tool.value("name", "") == "rag.fetch_from_source") {
			found_fetch = true;
			break;
		}
	}
	ok(found_fetch, "tool list includes rag.fetch_from_source");

	const json resp = handler.execute_tool(
		"rag.fetch_from_source",
		json{{"doc_ids", json::array({"doc:1", "missing:2"})}, {"columns", json::array({"id"})}}
	);

	ok(resp.value("success", false), "fetch_from_source returns success envelope");
	const json& result = resp["result"];
	ok(result["rows"].is_array() && result["rows"].size() == 2,
	   "fetch_from_source returns one row per requested doc");

	ok(result["rows"][0]["doc_id"] == "doc:1", "first row keeps the doc_id");
	ok(result["rows"][0]["source_name"] == "mysql_source", "first row includes source name");
	ok(result["rows"][0]["backend_type"] == "mysql", "backend type is normalized to lowercase");
	ok(result["rows"][0]["error"].is_string() &&
	   result["rows"][0]["error"].get<std::string>().find("mysql_real_connect failed") != std::string::npos,
	   "backend connection failure is surfaced");

	ok(result["rows"][1]["doc_id"] == "missing:2", "missing doc_id is echoed back");
	ok(result["rows"][1]["error"].is_string() &&
	   result["rows"][1]["error"].get<std::string>().find("Document not found") != std::string::npos,
	   "missing doc_id produces a lookup error");

	ok(result.value("truncated", true) == false, "result is not truncated");
	ok(result.contains("stats"), "result includes timing stats");
	ok(result["stats"].contains("ms"), "timing stats include milliseconds");

	test_cleanup_minimal();
	return exit_status();
}
