#include "rds_bgd_simulator.h"

using namespace std;

Endpoint RDS_BGD_Host::endpoint() {
	return { ip, port };
}

Endpoint RDS_BGD_Host::host_endpoint() {
	return { hostname, port };
}

vector<Endpoint> RDS_BGD_Cluster::get_writers() {
	return { blue_writer.endpoint(), green_writer.endpoint() };
}

vector<Endpoint> RDS_BGD_Cluster::get_blue_endpoints() {
	vector<Endpoint> endpoints { blue_writer.endpoint() };
	for (RDS_BGD_Host& host : blue_readers) endpoints.push_back(host.endpoint());
	return endpoints;
}

vector<Endpoint> RDS_BGD_Cluster::get_green_endpoints() {
	vector<Endpoint> endpoints { green_writer.endpoint() };
	for (RDS_BGD_Host& host : green_readers) endpoints.push_back(host.endpoint());
	return endpoints;
}

vector<Endpoint> RDS_BGD_Cluster::get_endpoints() {
	vector<Endpoint> endpoints = get_blue_endpoints();
	vector<Endpoint> green_endpoints = get_green_endpoints();
	endpoints.insert(endpoints.end(), green_endpoints.begin(), green_endpoints.end());
	return endpoints;
}

vector<BGD_Topology_Row> RDS_BGD_Cluster::get_topology(string status) {
	return {
		{ blue_writer.hostname, blue_writer.hostname, blue_writer.port,
			"BLUE_GREEN_DEPLOYMENT_SOURCE", status },
		{ green_writer.hostname, green_writer.hostname, green_writer.port,
			"BLUE_GREEN_DEPLOYMENT_TARGET", status },
	};
}
