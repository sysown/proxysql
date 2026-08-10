/**
 * @file test_prepare_statement_memory_usage-t.cpp
 * @brief Examines the memory consumption of the prepared statement cache.. 
 * @details This test assesses the memory utilization of prepared statement metadata/backend cache memory.
 */

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <unistd.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "proxysql_utils.h"
#include "utils.h"

struct PreparedStatementInfo {
	std::string schemaname;
	std::string username;
	std::string digest;
	uint64_t ref_count_client {0};
	uint64_t ref_count_server {0};
	uint64_t num_columns {0};
	uint64_t num_params {0};
	std::string query;

	bool operator==(const PreparedStatementInfo& rhs) const {
		return schemaname == rhs.schemaname && username == rhs.username && digest == rhs.digest &&
			ref_count_client == rhs.ref_count_client && ref_count_server == rhs.ref_count_server &&
			num_columns == rhs.num_columns && num_params == rhs.num_params && query == rhs.query;
	}
};

using StatementSnapshot = std::map<uint64_t, PreparedStatementInfo>;

struct MemoryUsage {
	uint64_t metadata {0};
	uint64_t backend {0};
};

struct StableSample {
	MemoryUsage memory;
	StatementSnapshot statements;
};

namespace {

constexpr uint64_t kStableSampleTimeoutUs {5ULL * 1000ULL * 1000ULL};
constexpr useconds_t kPollIntervalUs {10U * 1000U};

bool parse_uint64(const std::string& text, const std::string& field, uint64_t& value, std::string& error) {
	if (text.empty() || !std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
		error = "invalid numeric value for " + field + ": '" + text + "'";
		return false;
	}

	try {
		size_t consumed {0};
		const unsigned long long parsed {std::stoull(text, &consumed, 10)};
		if (consumed != text.size()) {
			error = "invalid numeric value for " + field + ": '" + text + "'";
			return false;
		}
		value = static_cast<uint64_t>(parsed);
		return true;
	} catch (const std::invalid_argument&) {
		error = "invalid numeric value for " + field + ": '" + text + "'";
	} catch (const std::out_of_range&) {
		error = "numeric value out of range for " + field + ": '" + text + "'";
	}
	return false;
}

bool read_query_rows(MYSQL* admin, const std::string& query, std::vector<mysql_res_row>& rows, std::string& error) {
	auto result {mysql_query_ext_rows(admin, query)};
	if (result.first != EXIT_SUCCESS) {
		error = "Admin query failed (error " + std::to_string(result.first) + "): " + mysql_error(admin);
		return false;
	}
	rows = std::move(result.second);
	return true;
}

StatementSnapshot without_target_query(const StatementSnapshot& snapshot, const std::string& target_query) {
	StatementSnapshot filtered {snapshot};
	for (auto it {filtered.begin()}; it != filtered.end();) {
		if (it->second.query == target_query) {
			it = filtered.erase(it);
		} else {
			++it;
		}
	}
	return filtered;
}

} // namespace

int read_statement_snapshot(MYSQL* admin, StatementSnapshot& snapshot, std::string& error) {
	static const std::string query {
		"SELECT global_stmt_id, schemaname, username, digest, "
		"ref_count_client, ref_count_server, num_columns, num_params, query "
		"FROM stats_mysql_prepared_statements_info "
		"ORDER BY global_stmt_id"
	};

	std::vector<mysql_res_row> rows;
	if (!read_query_rows(admin, query, rows, error)) {
		return EXIT_FAILURE;
	}

	StatementSnapshot parsed;
	for (const auto& row : rows) {
		if (row.size() != 9) {
			error = "prepared-statement snapshot row has " + std::to_string(row.size()) + " fields; expected 9";
			return EXIT_FAILURE;
		}

		PreparedStatementInfo info;
		uint64_t global_stmt_id {0};
		if (!parse_uint64(row[0], "global_stmt_id", global_stmt_id, error) ||
			!parse_uint64(row[4], "ref_count_client", info.ref_count_client, error) ||
			!parse_uint64(row[5], "ref_count_server", info.ref_count_server, error) ||
			!parse_uint64(row[6], "num_columns", info.num_columns, error) ||
			!parse_uint64(row[7], "num_params", info.num_params, error)) {
			return EXIT_FAILURE;
		}

		info.schemaname = row[1];
		info.username = row[2];
		info.digest = row[3];
		info.query = row[8];
		if (!parsed.emplace(global_stmt_id, std::move(info)).second) {
			error = "prepared-statement snapshot contains duplicate global_stmt_id " + std::to_string(global_stmt_id);
			return EXIT_FAILURE;
		}
	}

	snapshot = std::move(parsed);
	return EXIT_SUCCESS;
}

int read_memory_usage(MYSQL* admin, MemoryUsage& memory, std::string& error) {
	static const std::string query {
		"SELECT variable_name, variable_value FROM stats_memory_metrics WHERE "
		"variable_name IN ('prepare_statement_metadata_memory', 'prepare_statement_backend_memory')"
	};

	std::vector<mysql_res_row> rows;
	if (!read_query_rows(admin, query, rows, error)) {
		return EXIT_FAILURE;
	}

	MemoryUsage parsed;
	bool found_metadata {false};
	bool found_backend {false};
	for (const auto& row : rows) {
		if (row.size() != 2) {
			error = "memory metrics row has " + std::to_string(row.size()) + " fields; expected 2";
			return EXIT_FAILURE;
		}

		uint64_t value {0};
		if (row[0] == "prepare_statement_metadata_memory") {
			if (found_metadata) {
				error = "duplicate prepare_statement_metadata_memory metric";
				return EXIT_FAILURE;
			}
			if (!parse_uint64(row[1], row[0], value, error)) {
				return EXIT_FAILURE;
			}
			parsed.metadata = value;
			found_metadata = true;
		} else if (row[0] == "prepare_statement_backend_memory") {
			if (found_backend) {
				error = "duplicate prepare_statement_backend_memory metric";
				return EXIT_FAILURE;
			}
			if (!parse_uint64(row[1], row[0], value, error)) {
				return EXIT_FAILURE;
			}
			parsed.backend = value;
			found_backend = true;
		} else {
			error = "unknown memory metric: '" + row[0] + "'";
			return EXIT_FAILURE;
		}
	}

	if (!found_metadata || !found_backend || rows.size() != 2) {
		error = "memory metrics result must contain exactly the metadata and backend metrics";
		return EXIT_FAILURE;
	}

	memory = parsed;
	return EXIT_SUCCESS;
}

int read_stable_sample(MYSQL* admin, StableSample& sample, std::string& error) {
	const uint64_t deadline {monotonic_time() + kStableSampleTimeoutUs};
	StatementSnapshot before;
	StatementSnapshot after;
	while (monotonic_time() < deadline) {
		if (read_statement_snapshot(admin, before, error) != EXIT_SUCCESS ||
			read_memory_usage(admin, sample.memory, error) != EXIT_SUCCESS ||
			read_statement_snapshot(admin, after, error) != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}
		if (before == after) {
			sample.statements = std::move(after);
			return EXIT_SUCCESS;
		}
		usleep(kPollIntervalUs);
	}

	error = "stable prepared-statement sample could not be obtained before the deadline";
	return EXIT_FAILURE;
}

bool same_unrelated_statements(
	const StatementSnapshot& before, const StatementSnapshot& after, const std::string& target_query
) {
	return without_target_query(before, target_query) == without_target_query(after, target_query);
}

std::string describe_unrelated_statement_changes(
	const StatementSnapshot& before, const StatementSnapshot& after, const std::string& target_query
) {
	const StatementSnapshot before_unrelated {without_target_query(before, target_query)};
	const StatementSnapshot after_unrelated {without_target_query(after, target_query)};
	std::ostringstream diagnostic;
	bool first {true};
	const auto append_change {[&](const std::string& description) {
		if (!first) {
			diagnostic << ", ";
		}
		diagnostic << description;
		first = false;
	}};

	for (const auto& [global_stmt_id, info] : after_unrelated) {
		const auto before_it {before_unrelated.find(global_stmt_id)};
		if (before_it == before_unrelated.end()) {
			append_change("added global_stmt_id " + std::to_string(global_stmt_id));
		} else if (!(before_it->second == info)) {
			append_change("changed global_stmt_id " + std::to_string(global_stmt_id));
		}
	}
	for (const auto& [global_stmt_id, info] : before_unrelated) {
		if (after_unrelated.find(global_stmt_id) == after_unrelated.end()) {
			append_change("removed global_stmt_id " + std::to_string(global_stmt_id));
		}
	}

	return first ? "no unrelated statement changes" : diagnostic.str();
}

enum class MeasurementStatus {
	kAccepted,
	kContaminated,
	kError
};

struct MeasurementResult {
	MeasurementStatus status {MeasurementStatus::kError};
	std::string query;
	MemoryUsage before;
	MemoryUsage after;
	std::string error;
};

int wait_for_client_release(MYSQL* admin, const std::string& target_query, std::string& error) {
	const uint64_t deadline {monotonic_time() + kStableSampleTimeoutUs};
	while (monotonic_time() < deadline) {
		StatementSnapshot snapshot;
		if (read_statement_snapshot(admin, snapshot, error) != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		bool target_found {false};
		bool released {true};
		for (const auto& [global_stmt_id, info] : snapshot) {
			(void)global_stmt_id;
			if (info.query == target_query) {
				target_found = true;
				if (info.ref_count_client != 0) {
					released = false;
					break;
				}
			}
		}
		if (!target_found || released) {
			return EXIT_SUCCESS;
		}
		usleep(kPollIntervalUs);
	}

	error = "client prepared-statement reference did not reach zero before the deadline for query: " + target_query;
	return EXIT_FAILURE;
}

MeasurementResult measure_once(MYSQL* admin, MYSQL* frontend, const std::string& query) {
	MeasurementResult result;
	result.query = query;

	StableSample before;
	if (read_stable_sample(admin, before, result.error) != EXIT_SUCCESS) {
		return result;
	}
	result.before = before.memory;

	MYSQL_STMT* stmt {mysql_stmt_init(frontend)};
	if (!stmt) {
		result.error = "mysql_stmt_init failed: " + std::string(mysql_error(frontend));
		return result;
	}
	if (mysql_stmt_prepare(stmt, query.c_str(), query.size()) != 0) {
		result.error = "mysql_stmt_prepare failed: " + std::string(mysql_error(frontend));
		mysql_stmt_close(stmt);
		return result;
	}

	StableSample after;
	const bool after_sampled {read_stable_sample(admin, after, result.error) == EXIT_SUCCESS};
	if (after_sampled) {
		result.after = after.memory;
	}
	const bool uncontaminated {after_sampled && same_unrelated_statements(before.statements, after.statements, query)};
	const std::string contamination {
		after_sampled ? describe_unrelated_statement_changes(before.statements, after.statements, query) : ""
	};

	if (mysql_stmt_close(stmt) != 0) {
		result.error = "mysql_stmt_close failed: " + std::string(mysql_error(frontend));
		return result;
	}
	if (!after_sampled) {
		return result;
	}
	if (wait_for_client_release(admin, query, result.error) != EXIT_SUCCESS) {
		return result;
	}
	if (!uncontaminated) {
		result.status = MeasurementStatus::kContaminated;
		result.error = "unrelated prepared-statement rows changed: " + contamination;
		diag("Contaminated prepared-statement measurement for %s: %s", query.c_str(), result.error.c_str());
		return result;
	}

	result.status = MeasurementStatus::kAccepted;
	return result;
}

MeasurementResult measure_new_statement(MYSQL* admin, MYSQL* frontend, uint64_t& sequence) {
	const uint64_t deadline {monotonic_time() + kStableSampleTimeoutUs};
	MeasurementResult result;
	do {
		const std::string query {
			"SELECT 1 AS test_prepare_statement_memory_usage_" +
			std::to_string(getpid()) + "_" + std::to_string(sequence++)
		};
		result = measure_once(admin, frontend, query);
		if (result.status != MeasurementStatus::kContaminated) {
			return result;
		}
	} while (monotonic_time() < deadline);

	result.error = "measurement deadline expired after contaminated samples: " + result.error;
	return result;
}

MeasurementResult measure_existing_statement(MYSQL* admin, MYSQL* frontend, const std::string& query) {
	const uint64_t deadline {monotonic_time() + kStableSampleTimeoutUs};
	MeasurementResult result;
	do {
		result = measure_once(admin, frontend, query);
		if (result.status != MeasurementStatus::kContaminated) {
			return result;
		}
	} while (monotonic_time() < deadline);

	result.error = "measurement deadline expired after contaminated samples: " + result.error;
	return result;
}

MeasurementResult failed_dependent_reuse(const MeasurementResult& new_measurement) {
	MeasurementResult result;
	result.query = new_measurement.query;
	result.error = "dependent reuse was not attempted because new-statement measurement failed: " + new_measurement.error;
	return result;
}

void report_measurement(const MeasurementResult& result, bool expect_backend_equal) {
	const bool accepted {result.status == MeasurementStatus::kAccepted};
	const char* backend_expectation {expect_backend_equal ? "unchanged" : "did not decrease"};
	ok(accepted, "Prepare succeeded with an uncontaminated sample: %s", result.query.c_str());
	ok(accepted && result.after.metadata > result.before.metadata,
		"Prepared-statement metadata memory increased: %lu -> %lu",
		static_cast<unsigned long>(result.before.metadata), static_cast<unsigned long>(result.after.metadata));
	ok(accepted && (expect_backend_equal
		? result.after.backend == result.before.backend
		: result.after.backend >= result.before.backend),
		"Prepared-statement backend memory %s: %lu -> %lu", backend_expectation,
		static_cast<unsigned long>(result.before.backend), static_cast<unsigned long>(result.after.backend));
}

int main(int argc, char** argv) {

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(4 * // query
		 3 // checks
	);

	// Initialize Admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	// Connnect to ProxySQL Admin
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	// Initialize ProxySQL connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}

	// Connect to ProxySQL
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}

	uint64_t sequence {0};
	const MeasurementResult first_new {measure_new_statement(proxysql_admin, proxysql, sequence)};
	const MeasurementResult second_new {measure_new_statement(proxysql_admin, proxysql, sequence)};
	report_measurement(first_new, false);
	report_measurement(second_new, false);

	const MeasurementResult first_reuse {
		first_new.status == MeasurementStatus::kAccepted
			? measure_existing_statement(proxysql_admin, proxysql, first_new.query)
			: failed_dependent_reuse(first_new)
	};
	const MeasurementResult second_reuse {
		second_new.status == MeasurementStatus::kAccepted
			? measure_existing_statement(proxysql_admin, proxysql, second_new.query)
			: failed_dependent_reuse(second_new)
	};
	report_measurement(first_reuse, true);
	report_measurement(second_reuse, true);

__cleanup:
	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
