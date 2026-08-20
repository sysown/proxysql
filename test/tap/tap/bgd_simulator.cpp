#include "bgd_simulator.h"

#include <cerrno>
#include <cstdlib>
#include <utility>
#include <unistd.h>

#include "tap.h"

using namespace std;

namespace {

/**
 * @brief Convert a topology probe kind to its simulator log value.
 * @param kind Probe kind to convert.
 * @return Stable simulator log string.
 */
const char* probe_kind_string(BGD_Probe_Kind kind) {
	return kind == BGD_Probe_Kind::table_check ? "table_check" : "metadata";
}

/**
 * @brief Parse a topology probe kind from a simulator log row.
 * @param value Stored probe kind.
 * @return Result code and parsed kind.
 */
rc_t<BGD_Probe_Kind> parse_probe_kind(string value) {
	if (value == "table_check") {
		return { EXIT_SUCCESS, BGD_Probe_Kind::table_check };
	}
	if (value == "metadata") {
		return { EXIT_SUCCESS, BGD_Probe_Kind::metadata };
	}
	return { EXIT_FAILURE, BGD_Probe_Kind::table_check };
}

/**
 * @brief Convert an Aurora probe kind to its simulator log value.
 * @param kind Probe kind to convert.
 * @return Stable simulator log string.
 */
const char* replica_probe_kind_string(Aurora_Replica_Probe_Kind kind) {
	return kind == Aurora_Replica_Probe_Kind::ordinary ? "ordinary" : "bgd_membership";
}

/**
 * @brief Parse an Aurora probe kind from a simulator log row.
 * @param value Stored probe kind.
 * @return Result code and parsed kind.
 */
rc_t<Aurora_Replica_Probe_Kind> parse_replica_probe_kind(string value) {
	if (value == "ordinary") {
		return { EXIT_SUCCESS, Aurora_Replica_Probe_Kind::ordinary };
	}
	if (value == "bgd_membership") {
		return { EXIT_SUCCESS, Aurora_Replica_Probe_Kind::bgd_membership };
	}
	return { EXIT_FAILURE, Aurora_Replica_Probe_Kind::ordinary };
}

}  // namespace

/**
 * @brief Replace the topology rows served by a set of backends.
 * @param backends Backends that should serve the topology.
 * @param rows Topology rows returned by those backends.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int BGD_Simulator::topology_update(vector<Endpoint> backends, vector<BGD_Topology_Row> rows) {
	if (backends.empty()) {
		return EXIT_FAILURE;
	}

	vector<string> statements {};
	for (Endpoint& backend : backends) {
		string predicate { backend_predicate(backend) };
		statements.push_back("DELETE FROM AWS_BGD_TOPOLOGY WHERE " + predicate);
		statements.push_back(
			"INSERT OR REPLACE INTO AWS_BGD_CONTROL"
			"(backend_ip,backend_port,topology_present,error_code,error_msg) VALUES (" +
			sql_quote(backend.host) + "," + to_string(backend.port) + ",1,0,'')");

		for (size_t row_order = 0; row_order < rows.size(); ++row_order) {
			BGD_Topology_Row& row = rows[row_order];
			statements.push_back(
				"INSERT INTO AWS_BGD_TOPOLOGY"
				"(backend_ip,backend_port,row_order,id,endpoint,topology_port,role,status) VALUES (" +
				sql_quote(backend.host) + "," + to_string(backend.port) + "," +
				to_string(row_order) + "," + sql_quote(row.id) + "," +
				sql_quote(row.endpoint) + "," + to_string(row.port) + "," +
				sql_quote(row.role) + "," + sql_quote(row.status) + ")");
		}
	}

	return execute_transaction(statements);
}

/**
 * @brief Publish an empty topology table on a set of backends.
 * @param backends Backends that should return an empty table.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int BGD_Simulator::topology_delete(vector<Endpoint> backends) {
	if (backends.empty()) {
		return EXIT_FAILURE;
	}

	vector<string> statements {};
	for (Endpoint& backend : backends) {
		statements.push_back(
			"DELETE FROM AWS_BGD_TOPOLOGY WHERE " + backend_predicate(backend));
		statements.push_back(
			"INSERT OR REPLACE INTO AWS_BGD_CONTROL"
			"(backend_ip,backend_port,topology_present,error_code,error_msg) VALUES (" +
			sql_quote(backend.host) + "," + to_string(backend.port) + ",1,0,'')");
	}
	return execute_transaction(statements);
}

/**
 * @brief Simulate an absent topology table on a set of backends.
 * @param backends Backends that should report the table as absent.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int BGD_Simulator::topology_drop(vector<Endpoint> backends) {
	return topology_error(backends, 1146, "Table 'mysql.rds_topology' doesn't exist");
}

/**
 * @brief Make topology probes return a selected MySQL error.
 * @param backends Backends that should return the error.
 * @param error_code Nonzero MySQL error code.
 * @param error_msg MySQL error text.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int BGD_Simulator::topology_error(vector<Endpoint> backends, int error_code, string error_msg) {
	if (backends.empty() || error_code == 0) {
		return EXIT_FAILURE;
	}

	bool topology_present = error_code != 1146;
	vector<string> statements {};
	for (Endpoint& backend : backends) {
		if (!topology_present) {
			statements.push_back(
				"DELETE FROM AWS_BGD_TOPOLOGY WHERE " + backend_predicate(backend));
		}
		statements.push_back(
			"INSERT OR REPLACE INTO AWS_BGD_CONTROL"
			"(backend_ip,backend_port,topology_present,error_code,error_msg) VALUES (" +
			sql_quote(backend.host) + "," + to_string(backend.port) + "," +
			(topology_present ? "1" : "0") + "," + to_string(error_code) + "," +
			sql_quote(error_msg) + ")");
	}
	return execute_transaction(statements);
}

/**
 * @brief Replace one Aurora membership set and its serving backends.
 * @param replica_set_id Stable simulator membership identity.
 * @param rows Replica rows returned for the set.
 * @param backends Backends that should serve the set.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int BGD_Simulator::replica_update(
	string replica_set_id,
	vector<Aurora_Replica_Row> rows,
	vector<Endpoint> backends)
{
	if (replica_set_id.empty() || backends.empty()) {
		return EXIT_FAILURE;
	}

	vector<string> statements {
		"DELETE FROM REPLICA_HOST_STATUS WHERE REPLICA_SET_ID=" +
			sql_quote(replica_set_id),
		"DELETE FROM AWS_AURORA_REPLICA_CONTROL WHERE replica_set_id=" +
			sql_quote(replica_set_id),
	};
	for (Aurora_Replica_Row& row : rows) {
		statements.push_back(
			"INSERT INTO REPLICA_HOST_STATUS"
			"(REPLICA_SET_ID,SERVER_ID,SESSION_ID,CPU,LAST_UPDATE_TIMESTAMP,"
				"REPLICA_LAG_IN_MILLISECONDS,IS_CURRENT) VALUES (" +
			sql_quote(replica_set_id) + "," + sql_quote(row.server_id) + "," +
			sql_quote(row.session_id) + "," + to_string(row.cpu) + "," +
			sql_quote(row.last_update_timestamp) + "," +
			to_string(row.replica_lag_in_milliseconds) + "," +
			(row.is_current ? "1" : "0") + ")");
	}
	for (Endpoint& backend : backends) {
		statements.push_back(
			"INSERT OR REPLACE INTO AWS_AURORA_REPLICA_CONTROL"
			"(backend_ip,backend_port,replica_set_id,replica_table_present,error_code,error_msg) "
			"VALUES (" + sql_quote(backend.host) + "," + to_string(backend.port) + "," +
			sql_quote(replica_set_id) + ",1,0,'')");
	}

	return execute_transaction(statements);
}

/**
 * @brief Remove one Aurora membership set and its backend controls.
 * @param replica_set_id Stable simulator membership identity.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int BGD_Simulator::replica_delete(string replica_set_id) {
	if (replica_set_id.empty()) {
		return EXIT_FAILURE;
	}
	vector<string> statements {
		"DELETE FROM AWS_AURORA_REPLICA_CONTROL WHERE replica_set_id=" +
			sql_quote(replica_set_id),
		"DELETE FROM REPLICA_HOST_STATUS WHERE REPLICA_SET_ID=" +
			sql_quote(replica_set_id),
	};
	return execute_transaction(statements);
}

/**
 * @brief Simulate an absent REPLICA_HOST_STATUS table on selected backends.
 * @param backends Backends that should report the table as absent.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int BGD_Simulator::replica_drop(vector<Endpoint> backends) {
	return replica_error(
		backends, 1146,
		"Table 'information_schema.REPLICA_HOST_STATUS' doesn't exist");
}

/**
 * @brief Make Aurora membership probes return a selected MySQL error.
 * @param backends Backends that should return the error.
 * @param error_code Nonzero MySQL error code.
 * @param error_msg MySQL error text.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int BGD_Simulator::replica_error(
	vector<Endpoint> backends, int error_code, string error_msg)
{
	if (backends.empty() || error_code == 0) {
		return EXIT_FAILURE;
	}

	const bool table_present = error_code != 1146;
	vector<string> statements {};
	for (Endpoint& backend : backends) {
		const string predicate { backend_predicate(backend) };
		statements.push_back(
			"INSERT OR REPLACE INTO AWS_AURORA_REPLICA_CONTROL"
			"(backend_ip,backend_port,replica_set_id,replica_table_present,error_code,error_msg) "
			"VALUES (" + sql_quote(backend.host) + "," + to_string(backend.port) + "," +
			"COALESCE((SELECT replica_set_id FROM AWS_AURORA_REPLICA_CONTROL WHERE " +
			predicate + "),'')," + (table_present ? "1" : "0") + "," +
			to_string(error_code) + "," + sql_quote(error_msg) + ")");
	}
	return execute_transaction(statements);
}

/**
 * @brief Remove all shared topology, replica, control, and probe-log state.
 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int BGD_Simulator::cleanup() {
	vector<string> statements {
		"DELETE FROM READONLY_STATUS",
		"DELETE FROM AWS_BGD_TOPOLOGY",
		"DELETE FROM AWS_BGD_CONTROL",
		"DELETE FROM AWS_BGD_PROBE_LOG",
	};

	if (connection() == nullptr) {
		return EXIT_FAILURE;
	}
	auto [rc, rows] = mysql_query_ext_rows(
		connection(),
		"SELECT name FROM sqlite_master WHERE type='table' AND name IN ("
			"'AWS_AURORA_REPLICA_CONTROL','AWS_AURORA_REPLICA_PROBE_LOG',"
			"'REPLICA_HOST_STATUS')");
	if (rc != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	for (mysql_res_row& row : rows) {
		if (row.size() != 1) {
			return EXIT_FAILURE;
		}
		statements.push_back("DELETE FROM " + row.front());
	}
	return execute_transaction(statements);
}

/**
 * @brief Read the last topology-probe sequence.
 * @return Result code and the current sequence number.
 */
rc_t<uint64_t> BGD_Simulator::probe_log_last_sequence() {
	if (connection() == nullptr) {
		return { EXIT_FAILURE, 0 };
	}

	auto [rc, rows] = mysql_query_ext_rows(
		connection(), "SELECT COALESCE(MAX(sequence_id),0) FROM AWS_BGD_PROBE_LOG");
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows.front().size() != 1) {
		return { EXIT_FAILURE, 0 };
	}

	return {
		EXIT_SUCCESS,
		static_cast<uint64_t>(strtoull(rows.front().front().c_str(), nullptr, 10))
	};
}

/**
 * @brief Read topology probes recorded after a sequence.
 * @param sequence_id Exclusive lower sequence bound.
 * @return Result code and ordered probe records.
 */
rc_t<vector<BGD_Probe_Log>> BGD_Simulator::probe_log_since(uint64_t sequence_id) {
	if (connection() == nullptr) {
		return { EXIT_FAILURE, {} };
	}

	string query {
		"SELECT sequence_id,backend_ip,backend_port,probe_kind,encrypted "
		"FROM AWS_BGD_PROBE_LOG WHERE sequence_id>" + to_string(sequence_id) +
		" ORDER BY sequence_id"
	};
	auto [rc, rows] = mysql_query_ext_rows(connection(), query);
	if (rc != EXIT_SUCCESS) {
		return { EXIT_FAILURE, {} };
	}

	vector<BGD_Probe_Log> logs {};
	for (mysql_res_row& row : rows) {
		if (row.size() != 5) {
			return { EXIT_FAILURE, {} };
		}
		auto [kind_rc, kind] = parse_probe_kind(row[3]);
		if (kind_rc != EXIT_SUCCESS) {
			return { EXIT_FAILURE, {} };
		}
		logs.push_back({
			static_cast<uint64_t>(strtoull(row[0].c_str(), nullptr, 10)),
			{ row[1], atoi(row[2].c_str()) },
			kind,
			atoi(row[4].c_str()) != 0,
		});
	}

	return { EXIT_SUCCESS, move(logs) };
}

/**
 * @brief Wait for a matching topology probe.
 * @param sequence_id Exclusive lower sequence bound.
 * @param backend Expected backend.
 * @param probe_kind Expected topology query form.
 * @param timeout_ms Maximum wait in milliseconds.
 * @param encrypted Expected TLS state, or -1 to accept either.
 * @return Result code and the matching probe record.
 */
rc_t<BGD_Probe_Log> BGD_Simulator::wait_for_probe_log(
	uint64_t sequence_id,
	Endpoint backend,
	BGD_Probe_Kind probe_kind,
	uint32_t timeout_ms,
	int encrypted)
{
	uint64_t deadline = monotonic_time() + static_cast<uint64_t>(timeout_ms) * 1000;
	do {
		auto [rc, logs] = probe_log_since(sequence_id);
		if (rc != EXIT_SUCCESS) {
			return { EXIT_FAILURE, {} };
		}
		for (BGD_Probe_Log& log : logs) {
			if (log.backend.host == backend.host && log.backend.port == backend.port &&
				log.probe_kind == probe_kind &&
				(encrypted < 0 || log.encrypted == (encrypted != 0))) {
				return { EXIT_SUCCESS, log };
			}
		}
		usleep(50000);
	} while (monotonic_time() < deadline);

	auto [rc, logs] = probe_log_since(sequence_id);
	if (rc == EXIT_SUCCESS) {
		for (BGD_Probe_Log& log : logs) {
			diag(
				"Observed BGD probe sequence=%llu backend=%s:%d kind=%s encrypted=%d",
				static_cast<unsigned long long>(log.sequence_id),
				log.backend.host.c_str(), log.backend.port,
				probe_kind_string(log.probe_kind), log.encrypted ? 1 : 0);
		}
	}
	diag(
		"Timed out waiting for BGD probe backend=%s:%d kind=%s encrypted=%d",
		backend.host.c_str(), backend.port, probe_kind_string(probe_kind), encrypted);
	return { ETIMEDOUT, {} };
}

/**
 * @brief Read the last Aurora replica-probe sequence.
 * @return Result code and the current sequence number.
 */
rc_t<uint64_t> BGD_Simulator::replica_probe_log_last_sequence() {
	if (connection() == nullptr) {
		return { EXIT_FAILURE, 0 };
	}
	auto [rc, rows] = mysql_query_ext_rows(
		connection(),
		"SELECT COALESCE(MAX(sequence_id),0) FROM AWS_AURORA_REPLICA_PROBE_LOG");
	if (rc != EXIT_SUCCESS || rows.size() != 1 || rows.front().size() != 1) {
		return { EXIT_FAILURE, 0 };
	}
	return {
		EXIT_SUCCESS,
		static_cast<uint64_t>(strtoull(rows.front().front().c_str(), nullptr, 10))
	};
}

/**
 * @brief Read Aurora replica probes recorded after a sequence.
 * @param sequence_id Exclusive lower sequence bound.
 * @return Result code and ordered probe records.
 */
rc_t<vector<Aurora_Replica_Probe_Log>> BGD_Simulator::replica_probe_log_since(
	uint64_t sequence_id)
{
	if (connection() == nullptr) {
		return { EXIT_FAILURE, {} };
	}
	string query {
		"SELECT sequence_id,backend_ip,backend_port,probe_kind,"
			"COALESCE(replica_set_id,''),encrypted "
		"FROM AWS_AURORA_REPLICA_PROBE_LOG WHERE sequence_id>" +
		to_string(sequence_id) + " ORDER BY sequence_id"
	};
	auto [rc, rows] = mysql_query_ext_rows(connection(), query);
	if (rc != EXIT_SUCCESS) {
		return { EXIT_FAILURE, {} };
	}

	vector<Aurora_Replica_Probe_Log> logs {};
	for (mysql_res_row& row : rows) {
		if (row.size() != 6) {
			return { EXIT_FAILURE, {} };
		}
		auto [kind_rc, probe_kind] = parse_replica_probe_kind(row[3]);
		if (kind_rc != EXIT_SUCCESS) {
			return { EXIT_FAILURE, {} };
		}
		logs.push_back({
			static_cast<uint64_t>(strtoull(row[0].c_str(), nullptr, 10)),
			{ row[1], atoi(row[2].c_str()) },
			probe_kind,
			row[4],
			atoi(row[5].c_str()) != 0,
		});
	}
	return { EXIT_SUCCESS, move(logs) };
}

/**
 * @brief Wait for a matching Aurora replica probe.
 * @param sequence_id Exclusive lower sequence bound.
 * @param backend Expected backend.
 * @param probe_kind Expected Aurora query path.
 * @param timeout_ms Maximum wait in milliseconds.
 * @param encrypted Expected TLS state, or -1 to accept either.
 * @param replica_set_id Expected set identity, or empty to accept any set.
 * @return Result code and the matching probe record.
 */
rc_t<Aurora_Replica_Probe_Log> BGD_Simulator::wait_for_replica_probe_log(
	uint64_t sequence_id,
	Endpoint backend,
	Aurora_Replica_Probe_Kind probe_kind,
	uint32_t timeout_ms,
	int encrypted,
	string replica_set_id)
{
	uint64_t deadline = monotonic_time() + static_cast<uint64_t>(timeout_ms) * 1000;
	do {
		auto [rc, logs] = replica_probe_log_since(sequence_id);
		if (rc != EXIT_SUCCESS) {
			return { EXIT_FAILURE, {} };
		}
		for (Aurora_Replica_Probe_Log& log : logs) {
			if (log.backend.host == backend.host && log.backend.port == backend.port &&
				log.probe_kind == probe_kind &&
				(replica_set_id.empty() || log.replica_set_id == replica_set_id) &&
				(encrypted < 0 || log.encrypted == (encrypted != 0))) {
				return { EXIT_SUCCESS, log };
			}
		}
		usleep(50000);
	} while (monotonic_time() < deadline);

	auto [rc, logs] = replica_probe_log_since(sequence_id);
	if (rc == EXIT_SUCCESS) {
		for (Aurora_Replica_Probe_Log& log : logs) {
			diag(
				"Observed Aurora replica probe sequence=%llu backend=%s:%d kind=%s set=%s encrypted=%d",
				static_cast<unsigned long long>(log.sequence_id),
				log.backend.host.c_str(), log.backend.port,
				replica_probe_kind_string(log.probe_kind),
				log.replica_set_id.c_str(), log.encrypted ? 1 : 0);
		}
	}
	diag(
		"Timed out waiting for Aurora replica probe backend=%s:%d kind=%s set=%s encrypted=%d",
		backend.host.c_str(), backend.port, replica_probe_kind_string(probe_kind),
		replica_set_id.c_str(), encrypted);
	return { ETIMEDOUT, {} };
}

/**
 * @brief Execute simulator state changes as one transaction.
 * @param statements SQL statements to execute in order.
 * @return EXIT_SUCCESS after commit, otherwise EXIT_FAILURE after rollback.
 */
int BGD_Simulator::execute_transaction(vector<string>& statements) {
	if (execute("START TRANSACTION") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	for (string& statement : statements) {
		if (execute(statement) != EXIT_SUCCESS) {
			(void)execute("ROLLBACK");
			return EXIT_FAILURE;
		}
	}
	if (execute("COMMIT") != EXIT_SUCCESS) {
		(void)execute("ROLLBACK");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * @brief Build a SQL predicate identifying one simulator backend.
 * @param backend Backend address and port.
 * @return SQL predicate for simulator control tables.
 */
string BGD_Simulator::backend_predicate(Endpoint backend) {
	return "backend_ip=" + sql_quote(backend.host) +
		" AND backend_port=" + to_string(backend.port);
}
