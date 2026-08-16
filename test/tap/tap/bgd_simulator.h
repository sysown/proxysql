#ifndef TAP_BGD_SIMULATOR_H
#define TAP_BGD_SIMULATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "cluster_simulator.h"
#include "utils.h"

using std::string;
using std::vector;

/** One row returned by the simulated mysql.rds_topology table. */
struct BGD_Topology_Row {
	string id;
	string endpoint;
	int port;
	string role;
	string status;
};

/** Identifies a topology query recorded by the shared AWS BGD simulator. */
enum class BGD_Probe_Kind {
	table_check,
	metadata,
};

/** One topology query observed by the shared AWS BGD simulator. */
struct BGD_Probe_Log {
	uint64_t sequence_id;
	Endpoint backend;
	BGD_Probe_Kind probe_kind;
	bool encrypted;
};

/** One row returned by the simulated Aurora replica-status service. */
struct Aurora_Replica_Row {
	string server_id;
	string session_id;
	double cpu;
	string last_update_timestamp;
	double replica_lag_in_milliseconds;
	bool is_current;
};

/** Identifies which Aurora replica-status query reached the simulator. */
enum class Aurora_Replica_Probe_Kind {
	ordinary,
	bgd_membership,
};

/** One Aurora replica-status query observed by the shared AWS simulator. */
struct Aurora_Replica_Probe_Log {
	uint64_t sequence_id;
	Endpoint backend;
	Aurora_Replica_Probe_Kind probe_kind;
	string replica_set_id;
	bool encrypted;
};

/** Controls shared AWS BGD topology and Aurora replica simulator responses. */
class BGD_Simulator : public Cluster_Simulator {
public:
	int topology_update(vector<Endpoint> backends, vector<BGD_Topology_Row> rows);
	int topology_delete(vector<Endpoint> backends);
	int topology_drop(vector<Endpoint> backends);
	int topology_error(vector<Endpoint> backends, int error_code, string error_msg);
	int replica_update(
		string replica_set_id,
		vector<Aurora_Replica_Row> rows,
		vector<Endpoint> backends
	);
	int replica_delete(string replica_set_id);
	int replica_drop(vector<Endpoint> backends);
	int replica_error(vector<Endpoint> backends, int error_code, string error_msg);
	int cleanup();

	rc_t<uint64_t> probe_log_last_sequence();
	rc_t<vector<BGD_Probe_Log>> probe_log_since(uint64_t sequence_id);
	rc_t<BGD_Probe_Log> wait_for_probe_log(
		uint64_t sequence_id,
		Endpoint backend,
		BGD_Probe_Kind probe_kind,
		uint32_t timeout_ms,
		int encrypted = -1
	);
	rc_t<uint64_t> replica_probe_log_last_sequence();
	rc_t<vector<Aurora_Replica_Probe_Log>> replica_probe_log_since(uint64_t sequence_id);
	rc_t<Aurora_Replica_Probe_Log> wait_for_replica_probe_log(
		uint64_t sequence_id,
		Endpoint backend,
		Aurora_Replica_Probe_Kind probe_kind,
		uint32_t timeout_ms,
		int encrypted = -1,
		string replica_set_id = ""
	);

protected:
	static string backend_predicate(Endpoint backend);
	int execute_transaction(vector<string>& statements);
};

#endif  // TAP_BGD_SIMULATOR_H
