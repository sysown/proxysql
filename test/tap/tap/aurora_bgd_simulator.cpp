#include "aurora_bgd_simulator.h"

using namespace std;

Endpoint Aurora_BGD_Endpoint::backend() {
	return { ip, port };
}

Endpoint Aurora_BGD_Endpoint::host_endpoint() {
	return { hostname, port };
}

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

vector<Aurora_Replica_Row> Aurora_BGD_Membership_Set::replica_rows() {
	vector<Aurora_Replica_Row> rows {};
	rows.reserve(members.size());
	for (Aurora_BGD_Member& member : members) {
		rows.push_back(member.replica_row());
	}
	return rows;
}

vector<Endpoint> Aurora_BGD_Membership_Set::backends() {
	vector<Endpoint> endpoints {};
	endpoints.reserve(serving_endpoints.size());
	for (Aurora_BGD_Endpoint& endpoint : serving_endpoints) {
		endpoints.push_back(endpoint.backend());
	}
	return endpoints;
}
