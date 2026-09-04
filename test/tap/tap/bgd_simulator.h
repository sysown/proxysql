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
	string id;        ///< Topology deployment member identifier.
	string endpoint;  ///< Endpoint reported by the topology row.
	int port;         ///< Endpoint port.
	string role;      ///< SOURCE or TARGET role reported by AWS.
	string status;    ///< Switchover status reported by AWS.
};

/** Identifies a topology query recorded by the shared AWS BGD simulator. */
enum class BGD_Probe_Kind {
	table_check,  ///< Probe checking whether the topology table contains rows.
	metadata,     ///< Probe fetching the complete topology metadata.
};

/** One topology query observed by the shared AWS BGD simulator. */
struct BGD_Probe_Log {
	uint64_t sequence_id;       ///< Monotonic simulator log sequence.
	Endpoint backend;           ///< Backend that received the query.
	BGD_Probe_Kind probe_kind;  ///< Form of topology query observed.
	bool encrypted;             ///< Whether the simulated connection used TLS.
};

/** One row returned by the simulated Aurora replica-status service. */
struct Aurora_Replica_Row {
	string server_id;                     ///< Aurora member identifier.
	string session_id;                    ///< Aurora writer or reader session identity.
	double cpu;                            ///< CPU value returned by the simulator.
	string last_update_timestamp;         ///< Row timestamp returned by the simulator.
	double replica_lag_in_milliseconds;    ///< Replica lag returned by the simulator.
	bool is_current;                       ///< Whether the row belongs to current membership.
};

/** Identifies which Aurora replica-status query reached the simulator. */
enum class Aurora_Replica_Probe_Kind {
	ordinary,        ///< Ordinary Aurora monitor membership query.
	bgd_membership,  ///< BGD target-membership query.
};

/** One Aurora replica-status query observed by the shared AWS simulator. */
struct Aurora_Replica_Probe_Log {
	uint64_t sequence_id;                  ///< Monotonic simulator log sequence.
	Endpoint backend;                      ///< Backend that received the query.
	Aurora_Replica_Probe_Kind probe_kind;  ///< Aurora query path observed.
	string replica_set_id;                 ///< Membership set served by the backend.
	bool encrypted;                        ///< Whether the simulated connection used TLS.
};

/** Controls shared AWS BGD topology and Aurora replica simulator responses. */
class BGD_Simulator : public Cluster_Simulator {
public:
	/**
	 * @brief Replace the topology rows served by a set of backends.
	 * @param backends Backends that should serve the topology.
	 * @param rows Topology rows returned by those backends.
	 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
	 */
	int topology_update(vector<Endpoint> backends, vector<BGD_Topology_Row> rows);
	/**
	 * @brief Publish an empty topology table on a set of backends.
	 * @param backends Backends that should return an empty table.
	 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
	 */
	int topology_delete(vector<Endpoint> backends);
	/**
	 * @brief Simulate an absent topology table on a set of backends.
	 * @param backends Backends that should report the table as absent.
	 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
	 */
	int topology_drop(vector<Endpoint> backends);
	/**
	 * @brief Make topology probes return a selected MySQL error.
	 * @param backends Backends that should return the error.
	 * @param error_code Nonzero MySQL error code.
	 * @param error_msg MySQL error text.
	 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
	 */
	int topology_error(vector<Endpoint> backends, int error_code, string error_msg);
	/**
	 * @brief Replace one Aurora membership set and its serving backends.
	 * @param replica_set_id Stable simulator membership identity.
	 * @param rows Replica rows returned for the set.
	 * @param backends Backends that should serve the set.
	 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
	 */
	int replica_update(
		string replica_set_id,
		vector<Aurora_Replica_Row> rows,
		vector<Endpoint> backends
	);
	/**
	 * @brief Remove one Aurora membership set and its backend controls.
	 * @param replica_set_id Stable simulator membership identity.
	 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
	 */
	int replica_delete(string replica_set_id);
	/**
	 * @brief Simulate an absent REPLICA_HOST_STATUS table on selected backends.
	 * @param backends Backends that should report the table as absent.
	 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
	 */
	int replica_drop(vector<Endpoint> backends);
	/**
	 * @brief Make Aurora membership probes return a selected MySQL error.
	 * @param backends Backends that should return the error.
	 * @param error_code Nonzero MySQL error code.
	 * @param error_msg MySQL error text.
	 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
	 */
	int replica_error(vector<Endpoint> backends, int error_code, string error_msg);
	/**
	 * @brief Remove all shared topology, replica, control, and probe-log state.
	 * @return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
	 */
	int cleanup();

	/**
	 * @brief Read the last topology-probe sequence.
	 * @return Result code and the current sequence number.
	 */
	rc_t<uint64_t> probe_log_last_sequence();
	/**
	 * @brief Read topology probes recorded after a sequence.
	 * @param sequence_id Exclusive lower sequence bound.
	 * @return Result code and ordered probe records.
	 */
	rc_t<vector<BGD_Probe_Log>> probe_log_since(uint64_t sequence_id);
	/**
	 * @brief Wait for a matching topology probe.
	 * @param sequence_id Exclusive lower sequence bound.
	 * @param backend Expected backend.
	 * @param probe_kind Expected topology query form.
	 * @param timeout_ms Maximum wait in milliseconds.
	 * @param encrypted Expected TLS state, or -1 to accept either.
	 * @return Result code and the matching probe record.
	 */
	rc_t<BGD_Probe_Log> wait_for_probe_log(
		uint64_t sequence_id,
		Endpoint backend,
		BGD_Probe_Kind probe_kind,
		uint32_t timeout_ms,
		int encrypted = -1
	);
	/**
	 * @brief Read the last Aurora replica-probe sequence.
	 * @return Result code and the current sequence number.
	 */
	rc_t<uint64_t> replica_probe_log_last_sequence();
	/**
	 * @brief Read Aurora replica probes recorded after a sequence.
	 * @param sequence_id Exclusive lower sequence bound.
	 * @return Result code and ordered probe records.
	 */
	rc_t<vector<Aurora_Replica_Probe_Log>> replica_probe_log_since(uint64_t sequence_id);
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
	rc_t<Aurora_Replica_Probe_Log> wait_for_replica_probe_log(
		uint64_t sequence_id,
		Endpoint backend,
		Aurora_Replica_Probe_Kind probe_kind,
		uint32_t timeout_ms,
		int encrypted = -1,
		string replica_set_id = ""
	);

protected:
	/**
	 * @brief Build a SQL predicate identifying one simulator backend.
	 * @param backend Backend address and port.
	 * @return SQL predicate for simulator control tables.
	 */
	static string backend_predicate(Endpoint backend);
	/**
	 * @brief Execute simulator state changes as one transaction.
	 * @param statements SQL statements to execute in order.
	 * @return EXIT_SUCCESS after commit, otherwise EXIT_FAILURE after rollback.
	 */
	int execute_transaction(vector<string>& statements);
};

#endif  // TAP_BGD_SIMULATOR_H
