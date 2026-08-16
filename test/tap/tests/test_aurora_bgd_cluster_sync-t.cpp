/**
 * @file test_aurora_bgd_cluster_sync-t.cpp
 * @brief Aurora BGD configuration sync preserves worker-owned status per node.
 *
 * Steps:
 *
 * 1. Start two ProxySQL nodes with independent simulator endpoints.
 * 2. Publish AVAILABLE on the primary and INITIATED on the replica.
 * 3. Synchronize the configured Aurora hostgroup row from primary to replica.
 * 4. Verify configured fields synchronize while runtime status remains node-local.
 */

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "aurora_bgd_tap.h"
#include "command_line.h"
#include "utils.h"

using namespace std;
namespace fs = std::filesystem;

const uint32_t kWaitSeconds = 10;
const int kReplicaAdminPort = 16062;
const int kReplicaMySQLPort = 16063;
const char kReplicaHost[] = "127.0.0.1";
const char kSQLiteInterfaces[] = "0.0.0.0:3306;0.0.0.0:3307";

struct Replica_Process {
	pid_t pid = -1;
	string directory;
	string config_path;
	string stderr_path;
};

Aurora_BGD_Test_Deployment peer_deployment();

struct TestState {
	MYSQL* primary_admin { nullptr };
	MYSQL* replica_admin { nullptr };
	Replica_Process replica_process {};
	string primary_sqlite_interfaces;
	BGD_Simulator primary_simulator {};
	BGD_Simulator replica_simulator {};
	Aurora_BGD_Test_Deployment deployment { peer_deployment() };
	bool primary_simulator_connected { false };
	bool replica_simulator_connected { false };
};

string config_quote(const string& value) {
	string quoted;
	for (char c : value) {
		if (c == '\\' || c == '"') {
			quoted += '\\';
		}
		quoted += c;
	}
	return quoted;
}

int prepare_replica_config(const CommandLine& cl, Replica_Process& process) {
	char directory_template[] = "/tmp/proxysql-aurora-bgd-sync-XXXXXX";
	char* directory = mkdtemp(directory_template); // NOSONAR: mkdtemp creates an owner-only directory.
	if (directory == nullptr) {
		diag("mkdtemp failed: %s", strerror(errno));
		return EXIT_FAILURE;
	}
	process.directory = directory;
	process.config_path = process.directory + "/proxysql.cnf";
	process.stderr_path = process.directory + "/proxysql.stderr";

	ofstream config(process.config_path);
	if (!config.is_open()) {
		diag("failed to create replica config: %s", process.config_path.c_str());
		return EXIT_FAILURE;
	}
	config
		<< "datadir=\"" << config_quote(process.directory) << "\"\n"
		<< "admin_variables={\n"
		<< " admin_credentials=\"" << config_quote(cl.admin_username) << ":"
		<< config_quote(cl.admin_password) << ";radmin:radmin\"\n"
		<< " mysql_ifaces=\"0.0.0.0:" << kReplicaAdminPort << "\"\n"
		<< " cluster_username=\"radmin\"\n"
		<< " cluster_password=\"radmin\"\n"
		<< " cluster_check_interval_ms=200\n"
		<< " cluster_check_status_frequency=100\n"
		<< " cluster_admin_variables_diffs_before_sync=0\n"
		<< " cluster_mysql_servers_diffs_before_sync=1\n"
		<< " cluster_mysql_servers_save_to_disk=false\n"
		<< " cluster_mysql_servers_sync_algorithm=3\n"
		<< "}\n"
		<< "mysql_variables={\n"
		<< " interfaces=\"0.0.0.0:" << kReplicaMySQLPort << "\"\n"
		<< " monitor_username=\"aurora1\"\n"
		<< " monitor_password=\"pass1\"\n"
		<< " monitor_connect_timeout=500\n"
		<< " monitor_ping_interval=10000\n"
		<< "}\n"
		<< "proxysql_servers=()\n";
	config.close();
	return config.fail() ? EXIT_FAILURE : EXIT_SUCCESS;
}

int launch_replica(const CommandLine& cl, Replica_Process& process) {
	if (prepare_replica_config(cl, process) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	const string binary = string(cl.workdir) + "../../../src/proxysql";
	process.pid = fork();
	if (process.pid == -1) {
		diag("fork failed: %s", strerror(errno));
		return EXIT_FAILURE;
	}
	if (process.pid == 0) {
		int stderr_fd = open(process.stderr_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (stderr_fd >= 0) {
			dup2(stderr_fd, STDOUT_FILENO);
			dup2(stderr_fd, STDERR_FILENO);
			close(stderr_fd);
		}
		execl(
			binary.c_str(), "proxysql", "--sqlite3-server", "-f", "-c",
			process.config_path.c_str(), static_cast<char*>(nullptr));
		_exit(127);
	}
	return EXIT_SUCCESS;
}

void stop_replica(MYSQL*& admin, Replica_Process& process, bool preserve_log) {
	if (admin != nullptr) {
		mysql_query(admin, "PROXYSQL SHUTDOWN");
		mysql_close(admin);
		admin = nullptr;
	}
	if (process.pid > 0) {
		bool exited = false;
		for (int i = 0; i < 50; ++i) {
			pid_t rc = waitpid(process.pid, nullptr, WNOHANG);
			if (rc == process.pid || rc == -1) {
				exited = true;
				break;
			}
			usleep(100000);
		}
		if (!exited) {
			kill(process.pid, SIGKILL);
			waitpid(process.pid, nullptr, 0);
		}
	}
	if (!preserve_log && !process.directory.empty()) {
		fs::remove_all(process.directory);
	} else if (preserve_log) {
		diag("replica ProxySQL log retained at %s", process.stderr_path.c_str());
	}
}

Aurora_BGD_Test_Deployment peer_deployment() {
	Aurora_BGD_Test_Deployment deployment;
	deployment.name = "Aurora BGD peer-local status";
	deployment.domain_name = ".localhost";
	deployment.blue_replica_set = "aurora-bgd-peer-blue";
	deployment.target_replica_set = "aurora-bgd-peer-target";
	deployment.source_topology_id = "aurora-bgd-peer-source";
	deployment.target_topology_id = "aurora-bgd-peer-target";
	deployment.target_cluster_endpoint = {
		"aurora-peer-writer-green-sync.localhost", "127.0.0.1", 3307
	};
	deployment.production = {
		deployment.blue_replica_set,
		{aurora_bgd_member(
			"aurora-peer-writer", "MASTER_SESSION_ID",
			{"aurora-peer-writer.localhost", "127.0.0.1", 3306})},
		{}
	};
	deployment.production.serving_endpoints.push_back(
		deployment.production.members.front().endpoint);
	deployment.target = {
		deployment.target_replica_set,
		{aurora_bgd_member(
			"aurora-peer-writer-green-sync", "MASTER_SESSION_ID",
			{"aurora-peer-writer-green-sync.localhost", "127.0.0.1", 3307})},
		{deployment.target_cluster_endpoint}
	};
	deployment.target.serving_endpoints.push_back(
		deployment.target.members.front().endpoint);
	return deployment;
}

int configure_sqlite_interfaces(MYSQL* admin, const string& interfaces) {
	return aurora_bgd_execute_all(admin, {
		"SET sqliteserver-mysql_ifaces=" + aurora_bgd_sql_quote(interfaces),
		"LOAD SQLITESERVER VARIABLES TO RUNTIME",
	});
}

int configure_peer(
	MYSQL* admin, BGD_Simulator& simulator, Aurora_BGD_Test_Deployment& deployment,
	const string& status
) {
	return simulator.cleanup() == EXIT_SUCCESS
		&& aurora_bgd_publish(simulator, deployment) == EXIT_SUCCESS
		&& simulator.topology_update(
			aurora_bgd_topology_backends(deployment), aurora_bgd_topology(deployment, status))
			== EXIT_SUCCESS
		&& aurora_bgd_admin_cleanup(admin) == EXIT_SUCCESS
		&& aurora_bgd_admin_setup(admin, deployment, 1800, 1801, 1802, 1803, false)
			== EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

int setup(CommandLine& cl, TestState& state) {
	if (cl.getEnv()) {
		diag("failed to load TAP environment");
		return EXIT_FAILURE;
	}

	state.primary_admin = init_mysql_conn(
		cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (state.primary_admin == nullptr
		|| get_variable_value(
			state.primary_admin, "sqliteserver-mysql_ifaces",
			state.primary_sqlite_interfaces) != EXIT_SUCCESS
		|| configure_sqlite_interfaces(
			state.primary_admin, kSQLiteInterfaces) != EXIT_SUCCESS
		|| launch_replica(cl, state.replica_process) != EXIT_SUCCESS) {
		diag("failed to prepare the two ProxySQL nodes");
		return EXIT_FAILURE;
	}

	state.replica_admin = wait_for_proxysql(
		{kReplicaHost, cl.admin_username, cl.admin_password, kReplicaAdminPort},
		kWaitSeconds);
	if (state.replica_admin == nullptr
		|| configure_sqlite_interfaces(
			state.replica_admin, kSQLiteInterfaces) != EXIT_SUCCESS) {
		diag("failed to start the replica ProxySQL node");
		return EXIT_FAILURE;
	}

	char username[] = "aurora1";
	char password[] = "pass1";
	state.primary_simulator_connected = state.primary_simulator.connect(
		cl.host, 3306, username, password) == EXIT_SUCCESS;
	state.replica_simulator_connected = state.replica_simulator.connect(
		const_cast<char*>(kReplicaHost), 3306, username, password) == EXIT_SUCCESS;
	if (!state.primary_simulator_connected || !state.replica_simulator_connected
		|| configure_peer(
			state.primary_admin, state.primary_simulator,
			state.deployment, "AVAILABLE") != EXIT_SUCCESS
		|| configure_peer(
			state.replica_admin, state.replica_simulator,
			state.deployment, "SWITCHOVER_INITIATED") != EXIT_SUCCESS) {
		diag("failed to publish the two node-local Aurora observations");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * Synchronize configured Aurora fields without synchronizing worker-owned status.
 *
 * - Verify each node publishes its local topology observation.
 * - Synchronize the primary's configured hostgroup comment to the replica.
 * - Verify AVAILABLE and INITIATED remain local to their respective workers.
 */
int test_configuration_sync_preserves_local_status(CommandLine& cl, TestState& state) {
	ok(aurora_bgd_wait_for_status(
		state.primary_admin, 1800, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"primary worker publishes its local AVAILABLE observation");
	ok(aurora_bgd_wait_for_status(
		state.replica_admin, 1800, "SWITCHOVER_INITIATED", kWaitSeconds) == EXIT_SUCCESS,
		"replica worker publishes its local SWITCHOVER_INITIATED observation");

	if (aurora_bgd_execute_all(state.replica_admin, {
		"DELETE FROM proxysql_servers",
		"INSERT INTO proxysql_servers(hostname,port,weight,comment) VALUES (" +
			aurora_bgd_sql_quote(cl.admin_host) + "," + to_string(cl.admin_port) +
			",0,'Aurora BGD sync primary')",
		"LOAD PROXYSQL SERVERS TO RUNTIME",
	}) != EXIT_SUCCESS
		|| aurora_bgd_execute_all(state.primary_admin, {
			"UPDATE mysql_aws_aurora_hostgroups SET comment='peer-config-synced' "
				"WHERE writer_hostgroup=1800",
			"LOAD MYSQL SERVERS TO RUNTIME",
		}) != EXIT_SUCCESS) {
		diag("failed to initiate Aurora configuration synchronization");
		return EXIT_FAILURE;
	}

	ok(wait_for_cond(
		state.replica_admin,
		"SELECT COUNT(*)=1 FROM mysql_aws_aurora_hostgroups "
		"WHERE writer_hostgroup=1800 AND comment='peer-config-synced'",
		kWaitSeconds) == EXIT_SUCCESS,
		"Aurora BGD configured fields synchronize to the peer");
	ok(aurora_bgd_wait_for_status(
		state.primary_admin, 1800, "AVAILABLE", kWaitSeconds) == EXIT_SUCCESS,
		"configuration sync preserves the primary's local status");
	ok(aurora_bgd_wait_for_status(
		state.replica_admin, 1800, "SWITCHOVER_INITIATED", kWaitSeconds) == EXIT_SUCCESS,
		"configuration sync preserves the replica's local status");
	return EXIT_SUCCESS;
}

int cleanup(TestState& state) {
	if (state.primary_simulator_connected) {
		state.primary_simulator.cleanup();
	}
	if (state.replica_simulator_connected) {
		state.replica_simulator.cleanup();
	}
	if (state.replica_admin != nullptr) {
		aurora_bgd_admin_cleanup(state.replica_admin);
	}
	if (state.primary_admin != nullptr) {
		aurora_bgd_admin_cleanup(state.primary_admin);
		if (!state.primary_sqlite_interfaces.empty()) {
			configure_sqlite_interfaces(
				state.primary_admin, state.primary_sqlite_interfaces);
		}
		mysql_close(state.primary_admin);
		state.primary_admin = nullptr;
	}
	stop_replica(
		state.replica_admin, state.replica_process, tests_failed() != 0);
	return EXIT_SUCCESS;
}

int main() {
	plan(5);

	CommandLine cl {};
	TestState state {};

	if (setup(cl, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

	// Simulator: publish different Aurora states to two real ProxySQL nodes.
	// ProxySQL: synchronize the configured Aurora hostgroup row between them.
	// Verify: configured fields synchronize while runtime status remains node-local.
	if (test_configuration_sync_preserves_local_status(cl, state) != EXIT_SUCCESS) {
		goto exit_cleanup;
	}

exit_cleanup:
	if (cleanup(state) != EXIT_SUCCESS) {
		diag("failed to clean the Aurora BGD cluster-sync state");
		return EXIT_FAILURE;
	}
	return exit_status();
}
