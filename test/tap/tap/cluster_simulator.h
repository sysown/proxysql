#ifndef TAP_CLUSTER_SIMULATOR_H
#define TAP_CLUSTER_SIMULATOR_H

#include <string>

#include "mysql.h"

using namespace std;

/**
 * @brief Identifies a simulated backend by address and listener port.
 */
struct Endpoint {
	string host;  ///< Hostname or IP address used to identify the simulated backend.
	int port;     ///< MySQL listener port of the simulated backend.
};

/**
 * @brief Provides common control operations for TAP-driven cluster simulators.
 *
 * @details Owns the MySQL control connection to the SQLite3-server simulator and exposes
 *   backend state updates shared by technology-specific simulators.
 */
class Cluster_Simulator {
public:
	Cluster_Simulator() : mysql_(nullptr) {}
	virtual ~Cluster_Simulator() {
		if (mysql_ != nullptr) {
			mysql_close(mysql_);
			mysql_ = nullptr;
		}
	}

	Cluster_Simulator(const Cluster_Simulator&) = delete;
	Cluster_Simulator& operator=(const Cluster_Simulator&) = delete;

	/**
	 * @brief Opens the simulator control connection.
	 *
	 * @details Replaces any existing control connection, optionally enables MySQL client
	 *   TLS, and reports connection failures through TAP diagnostics.
	 *
	 * @param host Simulator hostname or IP address.
	 * @param port Simulator MySQL listener port.
	 * @param username MySQL username used by the control connection.
	 * @param password MySQL password used by the control connection.
	 * @param use_ssl Whether the control connection must use TLS.
	 *
	 * @return EXIT_SUCCESS when the connection is established; EXIT_FAILURE otherwise.
	 */
	int connect(char* host, int port, char* username, char* password, bool use_ssl = false);

	/**
	 * @brief Sets the simulated read-only state for a backend.
	 *
	 * @details Upserts `READONLY_STATUS` using the endpoint as its key. The state is
	 *   consumed through the hostname-suffixed monitor-query path shared with
	 *   `TEST_READONLY`.
	 *
	 * @param backend Hostname and port identifying the backend.
	 * @param read_only Whether the backend must report itself as read-only.
	 *
	 * @return EXIT_SUCCESS when the state is updated; EXIT_FAILURE otherwise.
	 */
	int read_only_update(Endpoint backend, bool read_only);

protected:
	MYSQL* connection() { return mysql_; }

	/**
	 * @brief Executes a query on the simulator control connection.
	 *
	 * @param query SQL statement to execute.
	 *
	 * @return EXIT_SUCCESS when the query succeeds; EXIT_FAILURE otherwise.
	 */
	int execute(string query);

	/**
	 * @brief Quotes a string value for use in simulator control SQL.
	 *
	 * @param value String value to quote.
	 *
	 * @return Single-quoted SQL literal with embedded quotes escaped.
	 */
	static string sql_quote(string value);

private:
	MYSQL* mysql_;
};

#endif  // TAP_CLUSTER_SIMULATOR_H
