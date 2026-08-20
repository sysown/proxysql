#include "aurora_bgd_simulator.h"

using namespace std;

/**
 * @brief Return the address reached by the test network.
 *
 * @return Endpoint containing the fixed simulator IP and port.
 */
Endpoint Aurora_BGD_Endpoint::backend() {
	return { ip, port };
}

/**
 * @brief Return the hostname configured in ProxySQL.
 *
 * @return Endpoint containing the Aurora hostname and port.
 */
Endpoint Aurora_BGD_Endpoint::host_endpoint() {
	return { hostname, port };
}

/**
 * @brief Convert this fixture member to a simulator replica row.
 *
 * @return REPLICA_HOST_STATUS row containing the member fields.
 */
Aurora_Replica_Row Aurora_BGD_Member::replica_row() {
	return {
		server_id,
		session_id,
		cpu,
		last_update_timestamp,
		replica_lag_in_milliseconds,
		is_current,
	};
}

/**
 * @brief Convert every fixture member to a simulator replica row.
 *
 * @return REPLICA_HOST_STATUS rows in fixture order.
 */
vector<Aurora_Replica_Row> Aurora_BGD_Membership_Set::replica_rows() {
	vector<Aurora_Replica_Row> rows {};
	rows.reserve(members.size());
	for (Aurora_BGD_Member& member : members) {
		rows.push_back(member.replica_row());
	}
	return rows;
}

/**
 * @brief Convert serving endpoints to simulator backend addresses.
 *
 * @return Fixed simulator endpoints in fixture order.
 */
vector<Endpoint> Aurora_BGD_Membership_Set::backends() {
	vector<Endpoint> endpoints {};
	endpoints.reserve(serving_endpoints.size());
	for (Aurora_BGD_Endpoint& endpoint : serving_endpoints) {
		endpoints.push_back(endpoint.backend());
	}
	return endpoints;
}
