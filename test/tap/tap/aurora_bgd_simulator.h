#ifndef TAP_AURORA_BGD_SIMULATOR_H
#define TAP_AURORA_BGD_SIMULATOR_H

#include <string>
#include <vector>

#include "bgd_simulator.h"

using namespace std;

/**
 * @brief An AWS-style Aurora hostname and its fixed simulator backend address.
 */
struct Aurora_BGD_Endpoint {
	string hostname;  ///< Hostname presented to ProxySQL.
	string ip;        ///< Simulator backend address assigned to hostname.
	int port;         ///< Backend port used by both endpoint forms.

	/**
	 * @brief Return the address reached by the test network.
	 *
	 * @return Endpoint containing the fixed simulator IP and port.
	 */
	Endpoint backend();

	/**
	 * @brief Return the hostname configured in ProxySQL.
	 *
	 * @return Endpoint containing the Aurora hostname and port.
	 */
	Endpoint host_endpoint();
};

/**
 * @brief One Aurora cluster member published through REPLICA_HOST_STATUS.
 */
struct Aurora_BGD_Member {
	string server_id;              ///< Aurora member identifier.
	string session_id;             ///< MASTER_SESSION_ID for the writer; stable id for a reader.
	Aurora_BGD_Endpoint endpoint;  ///< Member hostname and simulator backend mapping.
	double cpu { 0 };              ///< CPU value returned by the simulated row.
	string last_update_timestamp;  ///< Timestamp returned by the simulated row.
	double replica_lag_in_milliseconds { 0 };  ///< Replica lag returned by the simulated row.
	bool is_current { true };      ///< Whether the row belongs to the current membership snapshot.

	/**
	 * @brief Convert this fixture member to a simulator replica row.
	 *
	 * @return REPLICA_HOST_STATUS row containing the member fields.
	 */
	Aurora_Replica_Row replica_row();
};

/**
 * @brief A membership snapshot and every backend allowed to return it.
 */
struct Aurora_BGD_Membership_Set {
	string replica_set_id;                       ///< Simulator identity for this cluster membership.
	vector<Aurora_BGD_Member> members;           ///< Rows returned for the replica set.
	vector<Aurora_BGD_Endpoint> serving_endpoints;  ///< Backends allowed to serve the rows.

	/**
	 * @brief Convert every fixture member to a simulator replica row.
	 *
	 * @return REPLICA_HOST_STATUS rows in fixture order.
	 */
	vector<Aurora_Replica_Row> replica_rows();

	/**
	 * @brief Convert serving endpoints to simulator backend addresses.
	 *
	 * @return Fixed simulator endpoints in fixture order.
	 */
	vector<Endpoint> backends();
};

/**
 * @brief Stable identity used to describe an AWS member rename during switchover.
 */
struct Aurora_BGD_Rename {
	string production_server_id;  ///< Member identifier before the AWS rename.
	string target_server_id;      ///< Member identifier in the target cluster.
	string session_id;            ///< Stable Aurora role or reader identity.
	string cached_target_ip;      ///< Address resolved for the target member before rename.
};

#endif  // TAP_AURORA_BGD_SIMULATOR_H
