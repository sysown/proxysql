#ifndef TAP_RDS_BGD_SIMULATOR_H
#define TAP_RDS_BGD_SIMULATOR_H

#include <string>
#include <vector>

#include "bgd_simulator.h"

using namespace std;

/** Describes one RDS BGD host and its fixed simulator address. */
struct RDS_BGD_Host {
	string hostname;
	string ip;
	int port;

	Endpoint endpoint();
	Endpoint host_endpoint();
};

/** Holds the blue and green hosts in one simulated RDS BGD deployment. */
class RDS_BGD_Cluster {
public:
	RDS_BGD_Host blue_writer;
	RDS_BGD_Host green_writer;
	vector<RDS_BGD_Host> blue_readers;
	vector<RDS_BGD_Host> green_readers;

	vector<Endpoint> get_writers();
	vector<Endpoint> get_blue_endpoints();
	vector<Endpoint> get_green_endpoints();
	vector<Endpoint> get_endpoints();
	vector<BGD_Topology_Row> get_topology(string status);
};

#endif  // TAP_RDS_BGD_SIMULATOR_H
