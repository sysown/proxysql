#include "bgd_simulator.h"

#include <cerrno>
#include <cstdlib>
#include <utility>
#include <unistd.h>

#include "tap.h"

using namespace std;

namespace {

const char* probe_kind_string(BGD_Probe_Kind kind) {
	return kind == BGD_Probe_Kind::table_check ? "table_check" : "metadata";
}

rc_t<BGD_Probe_Kind> parse_probe_kind(string value) {
	if (value == "table_check") {
		return { EXIT_SUCCESS, BGD_Probe_Kind::table_check };
	}
	if (value == "metadata") {
		return { EXIT_SUCCESS, BGD_Probe_Kind::metadata };
	}
	return { EXIT_FAILURE, BGD_Probe_Kind::table_check };
}

}  // namespace

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

int BGD_Simulator::topology_drop(vector<Endpoint> backends) {
	return topology_error(backends, 1146, "Table 'mysql.rds_topology' doesn't exist");
}

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

int BGD_Simulator::cleanup() {
	vector<string> statements {
		"DELETE FROM READONLY_STATUS",
		"DELETE FROM AWS_BGD_TOPOLOGY",
		"DELETE FROM AWS_BGD_CONTROL",
		"DELETE FROM AWS_BGD_PROBE_LOG",
	};
	return execute_transaction(statements);
}

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

string BGD_Simulator::backend_predicate(Endpoint backend) {
	return "backend_ip=" + sql_quote(backend.host) +
		" AND backend_port=" + to_string(backend.port);
}
