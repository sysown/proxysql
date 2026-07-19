#ifndef TAP_CLUSTER_SIMULATOR_H
#define TAP_CLUSTER_SIMULATOR_H

#include <string>

#include "mysql.h"

struct Simulator_Endpoint {
	std::string host;
	int port;
};

class Cluster_Simulator {
public:
	Cluster_Simulator();
	virtual ~Cluster_Simulator();

	Cluster_Simulator(const Cluster_Simulator&) = delete;
	Cluster_Simulator& operator=(const Cluster_Simulator&) = delete;

	int connect(
		const char* host,
		int port,
		const char* username,
		const char* password,
		bool use_ssl = false);

	int read_only_update(const Simulator_Endpoint& backend, bool read_only);

protected:
	MYSQL* connection() const;
	int execute(const std::string& query);
	static std::string sql_quote(const std::string& value);

private:
	MYSQL* mysql_;
};

#endif  // TAP_CLUSTER_SIMULATOR_H
