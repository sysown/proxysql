/**
 * @file genai_config_query_unit-t.cpp
 * @brief Unit tests for the /mcp/config query tool.
 *
 * This test exercises the new constrained SQL shell exposed by
 * Config_Tool_Handler. It uses a raw, zero-initialized ProxySQL_Admin
 * instance with an in-memory admin database so the handler can run
 * against a real SQLite database without needing the full daemon
 * bootstrap sequence.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "Config_Tool_Handler.h"
#include "proxysql_admin.h"
#include "sqlite3db.h"

#include <cstdlib>
#include <cstring>

extern ProxySQL_Admin *GloAdmin;

namespace {

struct AdminFixture {
	AdminFixture() {
		void* mem = calloc(1, sizeof(ProxySQL_Admin));
		admin = reinterpret_cast<ProxySQL_Admin*>(mem);
		pthread_mutex_init(&admin->sql_query_global_mutex, nullptr);

		admin->admindb = new SQLite3DB();
		admin->admindb->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		admin->admindb->execute("CREATE TABLE global_variables ("
		                       " variable_name TEXT PRIMARY KEY,"
		                       " variable_value TEXT NOT NULL)");
		admin->admindb->execute("INSERT INTO global_variables VALUES ('mcp-port', '6032')");

		GloAdmin = admin;
	}

	~AdminFixture() {
		if (admin) {
			if (admin->admindb) {
				delete admin->admindb;
				admin->admindb = nullptr;
			}
			pthread_mutex_destroy(&admin->sql_query_global_mutex);
			free(admin);
			admin = nullptr;
		}
		GloAdmin = nullptr;
	}

	ProxySQL_Admin* admin { nullptr };
};

static void expect_query_value(const json& resp, int expected) {
	ok(resp.value("success", false), "query succeeds");
	ok(resp["result"].value("row_count", 0) == 1, "query returns one row");
	ok(resp["result"]["columns"].is_array() && resp["result"]["columns"].size() == 1,
	   "query returns one column");
	const auto& rows = resp["result"]["rows"];
	ok(rows.is_array() && rows.size() == 1, "query returns one row");
	ok(rows[0]["variable_value"] == expected, "query returns expected value");
}

} // namespace

int main() {
	plan(31);

	test_init_minimal();

	{
		AdminFixture fixture;
		Config_Tool_Handler handler(nullptr);

		const json tool_list = handler.get_tool_list();
		bool found_query = false;
		for (const auto& tool : tool_list["tools"]) {
			if (tool.value("name", "") == "query") {
				found_query = true;
				break;
			}
		}
		ok(found_query, "tool list includes query");

		json select_resp = handler.execute_tool("query", json{{"sql", "SELECT variable_value FROM global_variables WHERE variable_name='mcp-port'"}} );
		expect_query_value(select_resp, 6032);

		json update_resp = handler.execute_tool("query", json{{"sql", "UPDATE global_variables SET variable_value='6040' WHERE variable_name='mcp-port'"}} );
		ok(update_resp.value("success", false), "update succeeds");
		ok(update_resp["result"].value("rows_affected", 0) == 1, "update reports one affected row");

		json verify_resp = handler.execute_tool("query", json{{"sql", "SELECT variable_value FROM global_variables WHERE variable_name='mcp-port'"}} );
		expect_query_value(verify_resp, 6040);

		json with_resp = handler.execute_tool("query", json{{"sql", "WITH one(v) AS (SELECT 1) SELECT v FROM one"}} );
		ok(with_resp.value("success", false), "WITH query succeeds");
		ok(with_resp["result"].value("row_count", 0) == 1, "WITH query returns one row");
		ok(with_resp["result"]["rows"][0]["v"] == 1, "WITH query returns expected value");

		json literal_resp = handler.execute_tool("query", json{{"sql", "SELECT 'load_extension' AS literal"}} );
		ok(literal_resp.value("success", false), "string literal containing forbidden token is allowed");
		ok(literal_resp["result"].value("row_count", 0) == 1, "string literal query returns one row");
		ok(literal_resp["result"]["rows"][0]["literal"] == "load_extension",
		   "string literal query returns expected value");

		json comment_resp = handler.execute_tool("query", json{{"sql", "SELECT 1 /* create table */"}} );
		ok(comment_resp.value("success", false), "comment containing forbidden token is allowed");
		ok(comment_resp["result"].value("row_count", 0) == 1, "comment query returns one row");

		json pragma_resp = handler.execute_tool("query", json{{"sql", "PRAGMA user_version"}} );
		ok(!pragma_resp.value("success", true), "PRAGMA is rejected");
		ok(pragma_resp.value("error", "").find("not allowed") != std::string::npos,
		   "PRAGMA rejection explains the policy");

		json ddl_resp = handler.execute_tool("query", json{{"sql", "CREATE TABLE blocked(id INT)"}} );
		ok(!ddl_resp.value("success", true), "DDL is rejected");
		ok(ddl_resp.value("error", "").find("not allowed") != std::string::npos, "DDL rejection explains the policy");

		json attach_resp = handler.execute_tool("query", json{{"sql", "ATTACH ':memory:' AS aux"}} );
		ok(!attach_resp.value("success", true), "ATTACH is rejected");
		ok(attach_resp.value("error", "").find("not allowed") != std::string::npos,
		   "ATTACH rejection explains the policy");

		json extension_resp = handler.execute_tool("query", json{{"sql", "SELECT load_extension('/tmp/x')"}} );
		ok(!extension_resp.value("success", true), "load_extension is rejected");
		ok(extension_resp.value("error", "").find("forbidden SQL token") != std::string::npos,
		   "load_extension rejection explains the policy");

		json multi_resp = handler.execute_tool("query", json{{"sql", "SELECT 1; SELECT 2"}} );
		ok(!multi_resp.value("success", true), "multi-statement SQL is rejected");
		ok(multi_resp.value("error", "").find("single SQL statement") != std::string::npos,
		   "multi-statement rejection explains the policy");
	}

	test_cleanup_minimal();
	return exit_status();
}
