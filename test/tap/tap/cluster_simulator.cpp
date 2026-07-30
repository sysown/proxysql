#include "cluster_simulator.h"

#include <cstdlib>

#include "tap.h"

using namespace std;

int Cluster_Simulator::connect(char* host, int port, char* username, char* password, bool use_ssl) {
	if (mysql_ != nullptr) {
		mysql_close(mysql_);
		mysql_ = nullptr;
	}

	mysql_ = mysql_init(nullptr);
	if (mysql_ == nullptr) {
		diag("Failed to initialize the cluster simulator connection");
		return EXIT_FAILURE;
	}

	unsigned long client_flags = 0;
	if (use_ssl) {
		mysql_ssl_set(mysql_, nullptr, nullptr, nullptr, nullptr, nullptr);
		client_flags |= CLIENT_SSL;
	}

	auto ret = mysql_real_connect(mysql_, host, username, password, nullptr, port, nullptr, client_flags);
	if (ret == nullptr) {
		diag("Failed to connect to cluster simulator at %s:%d: %s", host, port, mysql_error(mysql_));
		mysql_close(mysql_);
		mysql_ = nullptr;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int Cluster_Simulator::read_only_update(Endpoint backend, bool read_only) {
	string query {
		"INSERT OR REPLACE INTO READONLY_STATUS(hostname,port,read_only) VALUES (" +
		sql_quote(backend.host) + "," + to_string(backend.port) + "," +
		(read_only ? "1" : "0") + ")"
	};
	return execute(query);
}

int Cluster_Simulator::execute(string query) {
	if (mysql_ == nullptr) {
		diag("Cluster simulator connection is not open");
		return EXIT_FAILURE;
	}

	if (mysql_query(mysql_, query.c_str()) != 0) {
		diag(
			"Cluster simulator query failed (%u): %s; query: %s",
			mysql_errno(mysql_), mysql_error(mysql_), query.c_str()
		);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

string Cluster_Simulator::sql_quote(string value) {
	string quoted { "'" };
	for (char c : value) {
		quoted += c;
		if (c == '\'') {
			quoted += '\'';
		}
	}
	quoted += '\'';
	return quoted;
}
