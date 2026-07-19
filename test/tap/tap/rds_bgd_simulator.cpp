#include "rds_bgd_simulator.h"

#include <cerrno>
#include <cstdlib>
#include <utility>
#include <unistd.h>

#include "tap.h"

namespace {

const char* probe_kind_string(RDS_BGD_Probe_Kind kind) {
	return kind == RDS_BGD_Probe_Kind::table_check ? "table_check" : "metadata";
}

rc_t<RDS_BGD_Probe_Kind> parse_probe_kind(const std::string& value) {
	if (value == "table_check") {
		return { EXIT_SUCCESS, RDS_BGD_Probe_Kind::table_check };
	}
	if (value == "metadata") {
		return { EXIT_SUCCESS, RDS_BGD_Probe_Kind::metadata };
	}
	return { EXIT_FAILURE, RDS_BGD_Probe_Kind::table_check };
}

}  // namespace

Simulator_Endpoint RDS_BGD_Host::endpoint() const {
	return { ip, port };
}

RDS_BGD_Cluster::RDS_BGD_Cluster()
	: blue_writer_ {
		"db-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.11", 3306 },
	  green_writer_ {
		"db-1-green-iqu47r.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.14", 3306 },
	  blue_readers_ {
		{ "db-1-reader-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.12", 3306 },
		{ "db-1-reader-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.13", 3306 },
	  },
	  green_readers_ {
		{ "db-1-reader-1-green-dlzky7.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.15", 3306 },
		{ "db-1-reader-2-green-3fpjuu.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com", "127.10.0.16", 3306 },
	  }
{}

const RDS_BGD_Host& RDS_BGD_Cluster::blue_writer() const {
	return blue_writer_;
}

const RDS_BGD_Host& RDS_BGD_Cluster::green_writer() const {
	return green_writer_;
}

const std::vector<RDS_BGD_Host>& RDS_BGD_Cluster::blue_readers() const {
	return blue_readers_;
}

const std::vector<RDS_BGD_Host>& RDS_BGD_Cluster::green_readers() const {
	return green_readers_;
}

std::vector<Simulator_Endpoint> RDS_BGD_Cluster::get_writers() const {
	return { blue_writer_.endpoint(), green_writer_.endpoint() };
}

std::vector<RDS_BGD_Topology_Row> RDS_BGD_Cluster::get_topology(
	const std::string& status) const
{
	return {
		{ blue_writer_.hostname, blue_writer_.hostname, blue_writer_.port, "SOURCE", status },
		{ green_writer_.hostname, green_writer_.hostname, green_writer_.port, "TARGET", status },
	};
}

const RDS_BGD_Cluster& rds_bgd_test_cluster() {
	static const RDS_BGD_Cluster cluster {};
	return cluster;
}

int RDS_BGD_Simulator::topology_update(
	const std::vector<Simulator_Endpoint>& backends,
	const std::vector<RDS_BGD_Topology_Row>& rows)
{
	if (backends.empty()) {
		return EXIT_FAILURE;
	}

	std::vector<std::string> statements {};
	for (const Simulator_Endpoint& backend : backends) {
		const std::string predicate { backend_predicate(backend) };
		statements.push_back("DELETE FROM RDS_BGD_TOPOLOGY WHERE " + predicate);
		statements.push_back(
			"INSERT OR REPLACE INTO RDS_BGD_CONTROL"
			"(backend_ip,backend_port,topology_present,error_code,error_msg) VALUES (" +
			sql_quote(backend.host) + "," + std::to_string(backend.port) + ",1,0,'')");

		for (std::size_t row_order = 0; row_order < rows.size(); ++row_order) {
			const RDS_BGD_Topology_Row& row = rows[row_order];
			statements.push_back(
				"INSERT INTO RDS_BGD_TOPOLOGY"
				"(backend_ip,backend_port,row_order,id,endpoint,topology_port,role,status) VALUES (" +
				sql_quote(backend.host) + "," + std::to_string(backend.port) + "," +
				std::to_string(row_order) + "," + sql_quote(row.id) + "," +
				sql_quote(row.endpoint) + "," + std::to_string(row.port) + "," +
				sql_quote(row.role) + "," + sql_quote(row.status) + ")");
		}
	}

	return execute_transaction(statements);
}

int RDS_BGD_Simulator::topology_delete(
	const std::vector<Simulator_Endpoint>& backends)
{
	if (backends.empty()) {
		return EXIT_FAILURE;
	}

	std::vector<std::string> statements {};
	for (const Simulator_Endpoint& backend : backends) {
		statements.push_back(
			"DELETE FROM RDS_BGD_TOPOLOGY WHERE " + backend_predicate(backend));
		statements.push_back(
			"INSERT OR REPLACE INTO RDS_BGD_CONTROL"
			"(backend_ip,backend_port,topology_present,error_code,error_msg) VALUES (" +
			sql_quote(backend.host) + "," + std::to_string(backend.port) + ",1,0,'')");
	}
	return execute_transaction(statements);
}

int RDS_BGD_Simulator::topology_drop(
	const std::vector<Simulator_Endpoint>& backends)
{
	return topology_error(
		backends, 1146, "Table 'mysql.rds_topology' doesn't exist");
}

int RDS_BGD_Simulator::topology_error(
	const std::vector<Simulator_Endpoint>& backends,
	unsigned int error_code,
	const std::string& error_msg)
{
	if (backends.empty() || error_code == 0) {
		return EXIT_FAILURE;
	}

	const bool topology_present = error_code != 1146;
	std::vector<std::string> statements {};
	for (const Simulator_Endpoint& backend : backends) {
		if (!topology_present) {
			statements.push_back(
				"DELETE FROM RDS_BGD_TOPOLOGY WHERE " + backend_predicate(backend));
		}
		statements.push_back(
			"INSERT OR REPLACE INTO RDS_BGD_CONTROL"
			"(backend_ip,backend_port,topology_present,error_code,error_msg) VALUES (" +
			sql_quote(backend.host) + "," + std::to_string(backend.port) + "," +
			(topology_present ? "1" : "0") + "," + std::to_string(error_code) + "," +
			sql_quote(error_msg) + ")");
	}
	return execute_transaction(statements);
}

rc_t<uint64_t> RDS_BGD_Simulator::probe_log_last_sequence() {
	if (connection() == nullptr) {
		return { EXIT_FAILURE, 0 };
	}

	const rc_t<std::vector<mysql_res_row>> result {
		mysql_query_ext_rows(
			connection(), "SELECT COALESCE(MAX(sequence_id),0) FROM RDS_BGD_PROBE_LOG")
	};
	if (result.first != EXIT_SUCCESS || result.second.size() != 1 ||
		result.second.front().size() != 1) {
		return { EXIT_FAILURE, 0 };
	}

	return {
		EXIT_SUCCESS,
		static_cast<uint64_t>(std::strtoull(result.second.front().front().c_str(), nullptr, 10))
	};
}

rc_t<std::vector<RDS_BGD_Probe_Log>> RDS_BGD_Simulator::probe_log_since(
	uint64_t sequence_id)
{
	if (connection() == nullptr) {
		return { EXIT_FAILURE, {} };
	}

	const std::string query {
		"SELECT sequence_id,backend_ip,backend_port,probe_kind,encrypted "
		"FROM RDS_BGD_PROBE_LOG WHERE sequence_id>" + std::to_string(sequence_id) +
		" ORDER BY sequence_id"
	};
	const rc_t<std::vector<mysql_res_row>> result {
		mysql_query_ext_rows(connection(), query)
	};
	if (result.first != EXIT_SUCCESS) {
		return { EXIT_FAILURE, {} };
	}

	std::vector<RDS_BGD_Probe_Log> logs {};
	for (const mysql_res_row& row : result.second) {
		if (row.size() != 5) {
			return { EXIT_FAILURE, {} };
		}
		const rc_t<RDS_BGD_Probe_Kind> kind { parse_probe_kind(row[3]) };
		if (kind.first != EXIT_SUCCESS) {
			return { EXIT_FAILURE, {} };
		}
		logs.push_back({
			static_cast<uint64_t>(std::strtoull(row[0].c_str(), nullptr, 10)),
			{ row[1], std::atoi(row[2].c_str()) },
			kind.second,
			std::atoi(row[4].c_str()) != 0,
		});
	}

	return { EXIT_SUCCESS, std::move(logs) };
}

rc_t<RDS_BGD_Probe_Log> RDS_BGD_Simulator::wait_for_probe_log(
	uint64_t sequence_id,
	const Simulator_Endpoint& backend,
	RDS_BGD_Probe_Kind probe_kind,
	uint32_t timeout_ms,
	int encrypted)
{
	const uint64_t deadline = monotonic_time() + static_cast<uint64_t>(timeout_ms) * 1000;
	do {
		const rc_t<std::vector<RDS_BGD_Probe_Log>> logs { probe_log_since(sequence_id) };
		if (logs.first != EXIT_SUCCESS) {
			return { EXIT_FAILURE, {} };
		}
		for (const RDS_BGD_Probe_Log& log : logs.second) {
			if (log.backend.host == backend.host && log.backend.port == backend.port &&
				log.probe_kind == probe_kind &&
				(encrypted < 0 || log.encrypted == (encrypted != 0))) {
				return { EXIT_SUCCESS, log };
			}
		}
		usleep(50000);
	} while (monotonic_time() < deadline);

	const rc_t<std::vector<RDS_BGD_Probe_Log>> logs { probe_log_since(sequence_id) };
	if (logs.first == EXIT_SUCCESS) {
		for (const RDS_BGD_Probe_Log& log : logs.second) {
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

int RDS_BGD_Simulator::execute_transaction(
	const std::vector<std::string>& statements)
{
	if (execute("START TRANSACTION") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	for (const std::string& statement : statements) {
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

std::string RDS_BGD_Simulator::backend_predicate(
	const Simulator_Endpoint& backend)
{
	return "backend_ip=" + sql_quote(backend.host) +
		" AND backend_port=" + std::to_string(backend.port);
}
