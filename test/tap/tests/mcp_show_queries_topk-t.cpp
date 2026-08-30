/**
 * @file mcp_show_queries_topk-t.cpp
 * @brief TAP validation for in-memory MCP `stats.show_queries` Top-K pipeline.
 *
 * This test validates the end-to-end behavior of the new in-memory
 * implementation used by `Stats_Tool_Handler::handle_show_queries()`:
 *
 * 1. Populate digest in-memory structures using `PROXYSQLTEST 1`.
 * 2. Optionally run DEBUG-only internal validator `PROXYSQLTEST 56`.
 * 3. Query MCP `stats.show_queries`.
 * 4. Verify pagination cap metadata and descending sort semantics.
 * 5. Verify `match_digest_text` substring filtering.
 *
 * The DEBUG internal validator is optional. On non-DEBUG builds, ProxySQL
 * returns "Invalid test" for `PROXYSQLTEST 56`; this test skips that check.
 */

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mcp_client.h"

using json = nlohmann::json;

namespace {

/** Configured MCP cap used by this TAP. */
static const int k_show_queries_cap = 25;

/**
 * @brief Execute an admin SQL statement and consume any result set.
 *
 * @param admin Open admin connection.
 * @param query SQL statement to execute.
 * @param context Diagnostic label used on failure.
 * @return true on success, false on failure.
 */
bool run_admin_stmt(MYSQL* admin, const std::string& query, const char* context) {
	if (!admin) {
		diag("%s: admin connection is null", context);
		return false;
	}
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("%s failed: %s", context, mysql_error(admin));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (res) {
		mysql_free_result(res);
	}
	return true;
}

std::string escape_sql_literal(const char* input) {
	std::string escaped = input ? input : "";
	size_t pos = 0;
	while ((pos = escaped.find('\'', pos)) != std::string::npos) {
		escaped.insert(pos, 1, '\'');
		pos += 2;
	}
	return escaped;
}

/**
 * @brief Configure MCP stats endpoint and runtime cap for show_queries.
 *
 * @param admin Open admin connection.
 * @param cl TAP command-line configuration.
 * @return true if all setup statements succeeded.
 */
bool configure_mcp_stats(MYSQL* admin, const CommandLine& cl) {
	const std::string auth_token = escape_sql_literal(cl.mcp_auth_token);
	const std::vector<std::string> statements = {
		"SET mcp-port=" + std::to_string(cl.mcp_port),
		"SET mcp-use_ssl=false",
		"SET mcp-enabled=true",
		"SET mcp-config_endpoint_auth='" + auth_token + "'",
		"SET mcp-stats_endpoint_auth='" + auth_token + "'",
		"SET mcp-stats_show_queries_max_rows=" + std::to_string(k_show_queries_cap),
		"LOAD MCP VARIABLES TO RUNTIME"
	};
	for (const auto& stmt : statements) {
		if (!run_admin_stmt(admin, stmt, "MCP show_queries setup")) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Parse successful `stats.show_queries` payload.
 *
 * Supported response shapes:
 * 1. Direct tool result object:
 *    `{ "queries": [...], ... }`
 * 2. Legacy wrapped object:
 *    `{ "success": true, "result": { "queries": [...], ... } }`
 *
 * @param response MCP tool response.
 * @param result_obj Output `result` object.
 * @param error Output error text on failure.
 * @return true when payload is well-formed and tool-level success is true.
 */
bool extract_show_queries_result(const MCPResponse& response, json& result_obj, std::string& error) {
	if (!response.is_success()) {
		error = response.get_error_message();
		return false;
	}
	const json& payload = response.get_result();
	if (!payload.is_object()) {
		error = "show_queries payload is not an object";
		return false;
	}

	// Current MCP implementation returns direct tool result object.
	// Keep backward compatibility with older wrapped format used by prior tests.
	if (!payload.contains("success") && !payload.contains("result")) {
		result_obj = payload;
		return true;
	}

	if (!payload.value("success", false)) {
		error = payload.value("error", std::string("show_queries returned tool error"));
		return false;
	}
	if (!payload.contains("result") || !payload["result"].is_object()) {
		error = "show_queries payload missing object field 'result'";
		return false;
	}
	result_obj = payload["result"];
	return true;
}

/**
 * @brief Internal validator execution status.
 */
enum class topk_internal_status_t {
	passed,
	unsupported,
	failed
};

/**
 * @brief Run DEBUG-only internal Top-K validator (`PROXYSQLTEST 56`).
 *
 * @param admin Open admin connection.
 * @param error Output diagnostic text for failed/unsupported cases.
 * @return status describing execution outcome.
 */
topk_internal_status_t run_internal_topk_validator(MYSQL* admin, std::string& error) {
	if (mysql_query(admin, "PROXYSQLTEST 56 20 80 80") == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		if (res) {
			mysql_free_result(res);
		}
		return topk_internal_status_t::passed;
	}

	error = mysql_error(admin) ? mysql_error(admin) : "unknown admin error";
	if (error.find("Invalid test") != std::string::npos) {
		return topk_internal_status_t::unsupported;
	}
	return topk_internal_status_t::failed;
}

/**
 * @brief Case-insensitive substring check.
 *
 * @param haystack Candidate text.
 * @param needle Search token.
 * @return true when @p needle appears in @p haystack ignoring case.
 */
bool contains_icase(const std::string& haystack, const std::string& needle) {
	if (needle.empty()) {
		return true;
	}
	for (size_t p = 0; p < haystack.size(); ++p) {
		size_t i = 0;
		while (i < needle.size() && (p + i) < haystack.size()) {
			const unsigned char lhs = static_cast<unsigned char>(haystack[p + i]);
			const unsigned char rhs = static_cast<unsigned char>(needle[i]);
			if (std::tolower(lhs) != std::tolower(rhs)) {
				break;
			}
			++i;
		}
		if (i == needle.size()) {
			return true;
		}
	}
	return false;
}

/**
 * @brief Derive a short filter token from digest text.
 *
 * @param digest_text Source digest text.
 * @return Token suitable for `match_digest_text`.
 */
std::string derive_match_token(const std::string& digest_text) {
	std::string token {};
	for (char c : digest_text) {
		const unsigned char uc = static_cast<unsigned char>(c);
		if (std::isalnum(uc) || c == '_') {
			token.push_back(c);
			if (token.size() >= 10) {
				break;
			}
		} else if (!token.empty()) {
			break;
		}
	}
	if (token.empty()) {
		const size_t fallback = std::min<size_t>(8, digest_text.size());
		token = digest_text.substr(0, fallback);
	}
	return token;
}

} // namespace

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;

	plan(12);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to load TAP environment");
		return exit_status();
	}

	diag("=== MCP Stats show_queries Top-K Validation ===");
	diag("This test validates the in-memory implementation used by stats.show_queries.");
	diag("It populates digest in-memory structures using PROXYSQLTEST 1, optionally");
	diag("runs the DEBUG-only internal validator (PROXYSQLTEST 56), then queries MCP");
	diag("show_queries to verify pagination cap metadata, descending sort semantics,");
	diag("and match_digest_text substring filtering behavior.");
	diag("================================================");

	MYSQL* admin = nullptr;
	MCPClient* mcp = nullptr;
	bool can_continue = true;

	admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	ok(admin != nullptr, "Admin connection established");
	if (!admin) {
		skip(11, "Cannot continue without admin connection");
		can_continue = false;
	}

	if (can_continue) {
		const bool configured = configure_mcp_stats(admin, cl);
		ok(configured, "Configured MCP stats endpoint and show_queries cap");
		if (!configured) {
			skip(10, "Cannot continue without MCP setup");
			can_continue = false;
		}
	}

	if (can_continue) {
		mcp = new MCPClient(cl.admin_host, cl.mcp_port);
		if (strlen(cl.mcp_auth_token) > 0) {
			mcp->set_auth_token(cl.mcp_auth_token);
		}

		const bool mcp_reachable = mcp->check_server();
		ok(mcp_reachable, "MCP server reachable at %s", mcp->get_connection_info().c_str());
		if (!mcp_reachable) {
			skip(9, "Cannot continue without MCP connectivity");
			can_continue = false;
		}
	}

	if (can_continue) {
		const bool generated = run_admin_stmt(admin, "PROXYSQLTEST 1 1000", "Generate digest rows for Top-K TAP");
		ok(generated, "Generated in-memory digest rows via PROXYSQLTEST 1");
		if (!generated) {
			skip(8, "Cannot continue without digest data");
			can_continue = false;
		}
	}

	if (can_continue) {
		std::string debug_error;
		const topk_internal_status_t status = run_internal_topk_validator(admin, debug_error);
		if (status == topk_internal_status_t::passed) {
			ok(true, "DEBUG internal validator PROXYSQLTEST 56 passed");
		} else if (status == topk_internal_status_t::unsupported) {
			skip(1, "PROXYSQLTEST 56 available only in DEBUG builds");
		} else {
			ok(false, "DEBUG internal validator PROXYSQLTEST 56 failed: %s", debug_error.c_str());
		}

		const MCPResponse show_resp = mcp->call_tool(
			"stats",
			"show_queries",
			json{{"db_type", "mysql"}, {"sort_by", "count"}, {"limit", 200}}
		);
		ok(show_resp.is_success(), "MCP stats.show_queries transport/protocol success");

		json show_result = json::object();
		std::string show_error;
		const bool payload_ok = extract_show_queries_result(show_resp, show_result, show_error);
		ok(payload_ok, "stats.show_queries payload valid%s%s",
			payload_ok ? "" : ": ", payload_ok ? "" : show_error.c_str());

		if (!payload_ok) {
			skip(5, "Skipping response-content checks due to invalid show_queries payload");
		} else {
			const int requested_limit = show_result.value("requested_limit", -1);
			const int effective_limit = show_result.value("effective_limit", -1);
			const int limit_cap = show_result.value("limit_cap", -1);
			ok(
				requested_limit == 200 && effective_limit == k_show_queries_cap && limit_cap == k_show_queries_cap,
				"show_queries limit cap metadata is consistent (requested=%d effective=%d cap=%d)",
				requested_limit, effective_limit, limit_cap
			);

			const bool queries_present = show_result.contains("queries") && show_result["queries"].is_array();
			ok(queries_present, "show_queries result contains queries array");
			if (!queries_present) {
				skip(3, "Cannot validate sorting and text matching without queries array");
			} else {
				const json& queries = show_result["queries"];
				if (queries.empty()) {
					skip(3, "No query digest rows available for sorting/matching checks");
				} else {
					ok(true, "show_queries returned at least one row");

					// Print top queries for visual confirmation
					diag("Top %zu queries (showing first 5):", queries.size());
					for (size_t i = 0; i < queries.size() && i < 5; ++i) {
						const auto& q = queries[i];
						diag("  [%zu] count=%llu rows=%llu bytes=%llu \"%s\"",
							i + 1,
							static_cast<unsigned long long>(q.value("count_star", static_cast<uint64_t>(0))),
							static_cast<unsigned long long>(q.value("rows_sent", static_cast<uint64_t>(0))),
							static_cast<unsigned long long>(q.value("sum_rows_affected", static_cast<uint64_t>(0))),
							q.value("digest_text", std::string("")).substr(0, 80).c_str());
					}

					bool sorted_desc = true;
					uint64_t prev = std::numeric_limits<uint64_t>::max();
					for (const auto& row : queries) {
						const uint64_t count_star = row.value("count_star", static_cast<uint64_t>(0));
						if (count_star > prev) {
							sorted_desc = false;
							break;
						}
						prev = count_star;
					}
					ok(sorted_desc, "show_queries rows are sorted by count_star DESC");

					const std::string first_digest_text = queries[0].value("digest_text", std::string(""));
					const std::string match_token = derive_match_token(first_digest_text);
					const MCPResponse filtered_resp = mcp->call_tool(
						"stats",
						"show_queries",
						json{
							{"db_type", "mysql"},
							{"sort_by", "count"},
							{"limit", 20},
							{"match_digest_text", match_token}
						}
					);

					json filtered_result = json::object();
					std::string filtered_error;
					const bool filtered_ok = extract_show_queries_result(filtered_resp, filtered_result, filtered_error);
					bool filter_match_ok = false;
					if (filtered_ok && filtered_result.contains("queries") && filtered_result["queries"].is_array()) {
						filter_match_ok = true;
						for (const auto& row : filtered_result["queries"]) {
							const std::string digest_text = row.value("digest_text", std::string(""));
							if (!contains_icase(digest_text, match_token)) {
								filter_match_ok = false;
								break;
							}
						}
					}

					ok(
						filtered_ok && filter_match_ok,
						"match_digest_text filters rows by digest_text substring token '%s'%s%s",
						match_token.c_str(),
						filtered_ok ? "" : ": ",
						filtered_ok ? "" : filtered_error.c_str()
					);
				}
			}
		}
	}

	if (admin) {
		run_q(admin, "PROXYSQLTEST 4");
		run_q(admin, "LOAD MCP VARIABLES FROM DISK");
		mysql_close(admin);
	}
	if (mcp) {
		delete mcp;
	}

	return exit_status();
}
