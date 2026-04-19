/**
 * @file genai_live_validation-t.cpp
 * @brief Live TAP validation for GenAI embed/rerank async pipeline.
 *
 * This test uses real provider endpoints configured via environment variables.
 * It validates:
 * 1) Embedding vector integrity (row count + vector dimension)
 * 2) Rerank semantic correctness (relevant document receives top score)
 * 3) Concurrency stress (20 requests over 5 client connections)
 */

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using json = nlohmann::json;

namespace {

static const int k_total_tests = 12;

struct query_result_t {
	bool success = false;
	unsigned int mysql_errno = 0;
	std::string sqlstate {};
	std::string error {};
	std::vector<std::string> columns {};
	std::vector<std::vector<std::string>> rows {};
};

std::string env_or_empty(const char* name) {
	const char* value = std::getenv(name);
	return value ? value : "";
}

std::string sql_escape(const std::string& value) {
	std::string out;
	out.reserve(value.size());
	for (char c : value) {
		out.push_back(c);
		if (c == '\'') {
			out.push_back('\'');
		}
	}
	return out;
}

std::string join_row(const std::vector<std::string>& row) {
	std::ostringstream oss;
	for (size_t i = 0; i < row.size(); ++i) {
		if (i) {
			oss << " | ";
		}
		oss << row[i];
	}
	return oss.str();
}

MYSQL* connect_with_retry(char* host, int port, char* user, char* pass, const char* label, int attempts = 5) {
	for (int attempt = 1; attempt <= attempts; ++attempt) {
		MYSQL* conn = init_mysql_conn(host, port, user, pass);
		if (conn) {
			diag("%s connected on attempt %d", label, attempt);
			return conn;
		}
		diag("%s connection attempt %d/%d failed", label, attempt, attempts);
		if (attempt < attempts) {
			sleep(1);
		}
	}
	return nullptr;
}

bool run_admin_sql(MYSQL* admin, const std::string& sql) {
	diag("Admin SQL: %s", sql.c_str());
	if (mysql_query(admin, sql.c_str()) != 0) {
		diag("Admin error: %s", mysql_error(admin));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (res) {
		mysql_free_result(res);
	}
	return true;
}

bool execute_and_capture(MYSQL* conn, const std::string& sql, query_result_t& out) {
	out = query_result_t{};
	diag("Client SQL: %s", sql.c_str());

	if (mysql_query(conn, sql.c_str()) != 0) {
		out.mysql_errno = mysql_errno(conn);
		out.sqlstate = mysql_sqlstate(conn) ? mysql_sqlstate(conn) : "";
		out.error = mysql_error(conn) ? mysql_error(conn) : "unknown MySQL error";
		diag("Client ERROR errno=%u sqlstate=%s message=%s",
			out.mysql_errno,
			out.sqlstate.c_str(),
			out.error.c_str());
		return false;
	}

	MYSQL_RES* res = mysql_store_result(conn);
	if (!res) {
		if (mysql_field_count(conn) > 0) {
			out.mysql_errno = mysql_errno(conn);
			out.sqlstate = mysql_sqlstate(conn) ? mysql_sqlstate(conn) : "";
			out.error = mysql_error(conn) ? mysql_error(conn) : "expected resultset but got none";
			diag("Client ERROR errno=%u sqlstate=%s message=%s",
				out.mysql_errno,
				out.sqlstate.c_str(),
				out.error.c_str());
			return false;
		}
		out.success = true;
		diag("Client response: no resultset");
		return true;
	}

	const unsigned int field_count = mysql_num_fields(res);
	MYSQL_FIELD* fields = mysql_fetch_fields(res);
	out.columns.reserve(field_count);
	for (unsigned int i = 0; i < field_count; ++i) {
		out.columns.push_back(fields[i].name ? fields[i].name : "");
	}
	diag("Client columns (%zu): %s", out.columns.size(), join_row(out.columns).c_str());

	MYSQL_ROW row = nullptr;
	while ((row = mysql_fetch_row(res)) != nullptr) {
		unsigned long* lengths = mysql_fetch_lengths(res);
		std::vector<std::string> parsed_row;
		parsed_row.reserve(field_count);
		for (unsigned int i = 0; i < field_count; ++i) {
			if (!row[i]) {
				parsed_row.emplace_back("NULL");
			} else {
				parsed_row.emplace_back(row[i], lengths ? lengths[i] : std::strlen(row[i]));
			}
		}
		out.rows.push_back(std::move(parsed_row));
	}

	for (size_t i = 0; i < out.rows.size(); ++i) {
		diag("Client row[%zu]: %s", i, join_row(out.rows[i]).c_str());
	}

	mysql_free_result(res);
	out.success = true;
	return true;
}

size_t embedding_dimensions_from_csv(const std::string& csv) {
	if (csv.empty()) {
		return 0;
	}
	bool has_non_space = false;
	size_t dims = 1;
	for (char c : csv) {
		if (c == ',') {
			dims++;
		}
		if (!std::isspace(static_cast<unsigned char>(c))) {
			has_non_space = true;
		}
	}
	return has_non_space ? dims : 0;
}

bool to_int64(const std::string& value, int64_t& out) {
	char* end = nullptr;
	long long parsed = strtoll(value.c_str(), &end, 10);
	if (!end || *end != '\0') {
		return false;
	}
	out = static_cast<int64_t>(parsed);
	return true;
}

bool to_double(const std::string& value, double& out) {
	char* end = nullptr;
	double parsed = strtod(value.c_str(), &end);
	if (!end || *end != '\0') {
		return false;
	}
	out = parsed;
	return true;
}

bool configure_genai_runtime(
	MYSQL* admin,
	const std::string& embed_url,
	const std::string& embed_model,
	const std::string& rerank_url
) {
	const std::vector<std::string> setup_queries = {
		"UPDATE global_variables SET variable_value='./ai_features.db' WHERE variable_name='genai-vector_db_path'",
		"UPDATE global_variables SET variable_value='true' WHERE variable_name='genai-enabled'",
		"UPDATE global_variables SET variable_value='" + sql_escape(embed_url) + "' WHERE variable_name='genai-embedding_uri'",
		"UPDATE global_variables SET variable_value='" + sql_escape(embed_model) + "' WHERE variable_name='genai-embedding_model'",
		"UPDATE global_variables SET variable_value='" + sql_escape(rerank_url) + "' WHERE variable_name='genai-rerank_uri'",
		"LOAD GENAI VARIABLES TO RUNTIME"
	};

	for (const auto& query : setup_queries) {
		if (!run_admin_sql(admin, query)) {
			return false;
		}
	}

	diag("Waiting 2 seconds for GenAI runtime to settle");
	sleep(2);
	return true;
}

} // namespace

int main() {
	plan(k_total_tests);

	CommandLine cl;
	if (cl.getEnv()) {
		skip(k_total_tests, "Failed to load TAP environment");
		return exit_status();
	}

	const std::string embed_url = env_or_empty("TAP_EMBED_URL");
	const std::string embed_type = env_or_empty("TAP_EMBED_TYPE");
	const std::string embed_model = env_or_empty("TAP_EMBED_MODEL");
	const std::string embed_dim_str = env_or_empty("TAP_EMBED_DIMENSION");
	const std::string rerank_url = env_or_empty("TAP_RERANK_URL");
	const std::string rerank_model = env_or_empty("TAP_RERANK_MODEL");

	int64_t expected_dim_i64 = 0;
	const bool expected_dim_valid = to_int64(embed_dim_str, expected_dim_i64) && expected_dim_i64 > 0;
	const bool have_required_env =
		!embed_url.empty() &&
		!embed_type.empty() &&
		!embed_model.empty() &&
		expected_dim_valid &&
		!rerank_url.empty() &&
		!rerank_model.empty();

	if (!have_required_env) {
		skip(
			k_total_tests,
			"Missing required TAP_EMBED_* / TAP_RERANK_* environment variables "
			"(need TAP_EMBED_URL,TAP_EMBED_TYPE,TAP_EMBED_MODEL,TAP_EMBED_DIMENSION,TAP_RERANK_URL,TAP_RERANK_MODEL)"
		);
		return exit_status();
	}

	const size_t expected_dim = static_cast<size_t>(expected_dim_i64);
	ok(true, "Required embedding/rerank environment variables are present");

	diag("Env TAP_EMBED_URL=%s", embed_url.c_str());
	diag("Env TAP_EMBED_TYPE=%s", embed_type.c_str());
	diag("Env TAP_EMBED_MODEL=%s", embed_model.c_str());
	diag("Env TAP_EMBED_DIMENSION=%s", embed_dim_str.c_str());
	diag("Env TAP_RERANK_URL=%s", rerank_url.c_str());
	diag("Env TAP_RERANK_MODEL=%s (informational; current GENAI rerank path does not send model)", rerank_model.c_str());

	MYSQL* admin = connect_with_retry(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password, "Admin connection");
	ok(admin != nullptr, "Admin connection established with retry");
	if (!admin) {
		skip(k_total_tests - 2, "Cannot continue without admin connection");
		return exit_status();
	}

	MYSQL* client = connect_with_retry(cl.host, cl.port, cl.username, cl.password, "Client connection");
	ok(client != nullptr, "Client connection established with retry");
	if (!client) {
		skip(k_total_tests - 3, "Cannot continue without client connection");
		mysql_close(admin);
		return exit_status();
	}

	const bool configured = configure_genai_runtime(admin, embed_url, embed_model, rerank_url);
	ok(configured, "Configured GenAI runtime (vector_db_path, embed/rerank endpoints, model, enabled)");
	if (!configured) {
		skip(k_total_tests - 4, "Cannot continue without GenAI runtime configuration");
		mysql_close(client);
		mysql_close(admin);
		return exit_status();
	}

	const std::vector<std::string> embed_docs = {
		"customer profile with purchase history",
		"index design for order lookup",
		"shipping delays and support ticket escalation"
	};
	json embed_payload = {
		{"type", "embed"},
		{"documents", embed_docs}
	};
	query_result_t embed_result;
	const bool embed_query_ok = execute_and_capture(client, "GENAI: " + embed_payload.dump(), embed_result);
	ok(embed_query_ok, "GENAI embed request succeeds");

	const bool embed_count_ok = embed_query_ok && (embed_result.rows.size() == embed_docs.size());
	ok(embed_count_ok, "Embedding row count matches input documents (%zu)", embed_docs.size());

	bool embed_dim_ok = embed_query_ok;
	if (embed_query_ok) {
		for (size_t i = 0; i < embed_result.rows.size(); ++i) {
			if (embed_result.rows[i].empty()) {
				embed_dim_ok = false;
				break;
			}
			const size_t dims = embedding_dimensions_from_csv(embed_result.rows[i][0]);
			if (dims != expected_dim) {
				diag("Embedding row %zu has dimension %zu, expected %zu", i, dims, expected_dim);
				embed_dim_ok = false;
				break;
			}
		}
	}
	ok(embed_dim_ok, "Embedding dimensions match TAP_EMBED_DIMENSION=%zu", expected_dim);

	const std::vector<std::string> rerank_docs = {
		"Customer index tuning guide: best indexing strategy for customer_id searches.",
		"Cloud cost report for detached GPU training jobs.",
		"Office kitchen inventory and coffee refill schedule."
	};
	const int relevant_doc_index = 0;
	json rerank_payload = {
		{"type", "rerank"},
		{"query", "Which document is most relevant for customer index optimization?"},
		{"documents", rerank_docs},
		{"top_n", 3},
		{"columns", 3}
	};
	query_result_t rerank_result;
	const bool rerank_query_ok = execute_and_capture(client, "GENAI: " + rerank_payload.dump(), rerank_result);
	ok(rerank_query_ok, "GENAI rerank request succeeds");

	const bool rerank_rows_ok = rerank_query_ok && !rerank_result.rows.empty();
	ok(rerank_rows_ok, "Rerank returns at least one scored row");

	bool rerank_semantic_ok = false;
	if (rerank_rows_ok) {
		double best_score = std::numeric_limits<double>::lowest();
		int best_index = -1;
		for (const auto& row : rerank_result.rows) {
			if (row.size() < 2) {
				continue;
			}
			int64_t idx = -1;
			double score = 0.0;
			if (!to_int64(row[0], idx) || !to_double(row[1], score)) {
				continue;
			}
			if (score > best_score) {
				best_score = score;
				best_index = static_cast<int>(idx);
			}
		}
		rerank_semantic_ok = (best_index == relevant_doc_index);
		diag("Rerank best_index=%d expected=%d best_score=%.6f", best_index, relevant_doc_index, best_score);
	}
	ok(rerank_semantic_ok, "Relevant document receives highest rerank score");

	const int stress_connections = 5;
	const int requests_per_connection = 4;
	const int total_requests = stress_connections * requests_per_connection;

	std::vector<MYSQL*> stress_conns;
	stress_conns.reserve(stress_connections);
	bool stress_setup_ok = true;
	for (int i = 0; i < stress_connections; ++i) {
		MYSQL* conn = connect_with_retry(cl.host, cl.port, cl.username, cl.password, "Stress client connection");
		if (!conn) {
			stress_setup_ok = false;
			break;
		}
		stress_conns.push_back(conn);
	}

	std::atomic<int> success_count {0};
	std::atomic<int> failure_count {0};

	if (stress_setup_ok) {
		std::vector<std::thread> workers;
		workers.reserve(stress_connections);
		for (int c = 0; c < stress_connections; ++c) {
			workers.emplace_back([&, c]() {
				for (int r = 0; r < requests_per_connection; ++r) {
					json stress_payload = {
						{"type", "embed"},
						{"documents", json::array({
							"stress-conn-" + std::to_string(c) + "-req-" + std::to_string(r)
						})}
					};
					query_result_t stress_result;
					const bool ok = execute_and_capture(stress_conns[c], "GENAI: " + stress_payload.dump(), stress_result);
					if (ok && stress_result.rows.size() == 1) {
						success_count.fetch_add(1);
					} else {
						failure_count.fetch_add(1);
					}
				}
			});
		}
		for (auto& worker : workers) {
			worker.join();
		}
	}

	for (MYSQL* conn : stress_conns) {
		mysql_close(conn);
	}

	const bool stress_total_ok = stress_setup_ok && (success_count.load() == total_requests);
	ok(
		stress_total_ok,
		"Stress phase completed with %d/%d successful requests across %d connections",
		success_count.load(),
		total_requests,
		stress_connections
	);

	const bool stress_error_free = stress_setup_ok && (failure_count.load() == 0);
	ok(
		stress_error_free,
		"Stress phase reports zero failures (failures=%d)",
		failure_count.load()
	);

	mysql_close(client);
	mysql_close(admin);
	return exit_status();
}
