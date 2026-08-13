#ifndef TAP_AURORA_BGD_SIMULATOR_H
#define TAP_AURORA_BGD_SIMULATOR_H

#include <string>
#include <vector>

#include "bgd_simulator.h"

using namespace std;

/** An AWS-style Aurora hostname and its fixed simulator backend address. */
struct Aurora_BGD_Endpoint {
	string hostname;
	string ip;
	int port;

	Endpoint backend();
	Endpoint host_endpoint();
};

/** One Aurora cluster member published through REPLICA_HOST_STATUS. */
struct Aurora_BGD_Member {
	string server_id;
	string session_id;
	Aurora_BGD_Endpoint endpoint;
	double cpu { 0 };
	string last_update_timestamp;
	double replica_lag_in_milliseconds { 0 };
	bool is_current { true };

	Aurora_Replica_Row replica_row();
};

/** A membership snapshot and every backend allowed to return it. */
struct Aurora_BGD_Membership_Set {
	string replica_set_id;
	vector<Aurora_BGD_Member> members;
	vector<Aurora_BGD_Endpoint> serving_endpoints;

	vector<Aurora_Replica_Row> replica_rows();
	vector<Endpoint> backends();
};

/** Stable identity used to describe an AWS member rename during switchover. */
struct Aurora_BGD_Rename {
	string production_server_id;
	string target_server_id;
	string session_id;
	string cached_target_ip;
};

#endif  // TAP_AURORA_BGD_SIMULATOR_H
