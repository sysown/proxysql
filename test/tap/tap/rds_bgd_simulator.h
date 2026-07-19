#ifndef TAP_RDS_BGD_SIMULATOR_H
#define TAP_RDS_BGD_SIMULATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "cluster_simulator.h"
#include "utils.h"

struct RDS_BGD_Topology_Row {
	std::string id;
	std::string endpoint;
	int port;
	std::string role;
	std::string status;
};

struct RDS_BGD_Host {
	std::string hostname;
	std::string ip;
	int port;

	Simulator_Endpoint endpoint() const;
};

class RDS_BGD_Cluster {
public:
	const RDS_BGD_Host& blue_writer() const;
	const RDS_BGD_Host& green_writer() const;
	const std::vector<RDS_BGD_Host>& blue_readers() const;
	const std::vector<RDS_BGD_Host>& green_readers() const;
	std::vector<Simulator_Endpoint> get_writers() const;
	std::vector<RDS_BGD_Topology_Row> get_topology(
		const std::string& status) const;

private:
	friend const RDS_BGD_Cluster& rds_bgd_test_cluster();
	RDS_BGD_Cluster();

	RDS_BGD_Host blue_writer_;
	RDS_BGD_Host green_writer_;
	std::vector<RDS_BGD_Host> blue_readers_;
	std::vector<RDS_BGD_Host> green_readers_;
};

const RDS_BGD_Cluster& rds_bgd_test_cluster();

enum class RDS_BGD_Probe_Kind {
	table_check,
	metadata,
};

struct RDS_BGD_Probe_Log {
	uint64_t sequence_id;
	Simulator_Endpoint backend;
	RDS_BGD_Probe_Kind probe_kind;
	bool encrypted;
};

class RDS_BGD_Simulator : public Cluster_Simulator {
public:
	int topology_update(
		const std::vector<Simulator_Endpoint>& backends,
		const std::vector<RDS_BGD_Topology_Row>& rows);
	int topology_delete(const std::vector<Simulator_Endpoint>& backends);
	int topology_drop(const std::vector<Simulator_Endpoint>& backends);
	int topology_error(
		const std::vector<Simulator_Endpoint>& backends,
		unsigned int error_code,
		const std::string& error_msg);

	rc_t<uint64_t> probe_log_last_sequence();
	rc_t<std::vector<RDS_BGD_Probe_Log>> probe_log_since(uint64_t sequence_id);
	rc_t<RDS_BGD_Probe_Log> wait_for_probe_log(
		uint64_t sequence_id,
		const Simulator_Endpoint& backend,
		RDS_BGD_Probe_Kind probe_kind,
		uint32_t timeout_ms,
		int encrypted = -1);

private:
	static std::string backend_predicate(const Simulator_Endpoint& backend);
	int execute_transaction(const std::vector<std::string>& statements);
};

#endif  // TAP_RDS_BGD_SIMULATOR_H
