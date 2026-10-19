/**
 * @file test_cluster_admin_lock_order-t.cpp
 * @brief Admin statements that touch the Cluster nodes must not deadlock with
 *        a concurrent Cluster query rules or servers pull.
 *
 * A Cluster peer thread holds ProxySQL_Cluster_Nodes::mutex across
 * ProxySQL_Node_Entry::set_checksums(); the mysql/pgsql query rules pulls
 * started from there take the Admin global SQL mutex after fetching from the
 * peer, on every tier (they write the rules in a transaction). On v4.0 the
 * servers pulls take it too (d759171fa, limited to v4.0 by e5591776c). Two
 * Admin statements used to take the same two
 * locks in the opposite order, with the global SQL mutex held for the whole
 * statement:
 *  - SHOW PROMETHEUS METRICS, whose update callback refreshes the Cluster
 *    node metrics under the nodes mutex;
 *  - LOAD ADMIN VARIABLES TO RUNTIME re-enabling a
 *    admin-cluster_*_diffs_before_sync from 0, which reset the per-peer
 *    global checksums under the nodes mutex.
 * When they met, the Admin interface and every Cluster sync thread hung until
 * the process was killed.
 *
 * The test keeps a core peer changing its mysql_query_rules and mysql_servers
 * (so this node keeps pulling both from it) while two Admin connections on
 * this node run the two statements above in a loop. The query rules churn is
 * what reaches the lock inversion on every tier; the servers churn adds the
 * v4.0 path. Every statement has a read timeout: a
 * deadlock shows up as a timed out statement instead of a hung test.
 *
 * Cluster layout: the same as test_cluster1-t (this node on the admin port,
 * core nodes on 26001-26003, or the nodes listed in TAP_CLUSTER_NODES).
 * Group: legacy-g5 (and the other groups that run test_cluster1-t).
 */

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

namespace {

constexpr int RUN_SECONDS = 40;
constexpr unsigned int READ_TIMEOUT_S = 20;
constexpr int DUMMY_HOSTGROUP = 4242;
constexpr int DUMMY_RULE_ID = 424242;

MYSQL* admin_connect(const CommandLine& cl, const string& host, int port) {
	MYSQL* conn = mysql_init(NULL);
	if (conn == NULL) return NULL;
	unsigned int timeout = READ_TIMEOUT_S;
	mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &timeout);
	mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
	if (!mysql_real_connect(conn, host.c_str(), cl.admin_username, cl.admin_password, NULL, port, NULL, 0)) {
		diag("Connection to %s:%d failed: %s", host.c_str(), port, mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}
	return conn;
}

// Runs one statement and drains any result. Records the first failure.
bool run(MYSQL* conn, const string& q, string& first_error) {
	if (mysql_query(conn, q.c_str())) {
		if (first_error.empty()) {
			first_error = q + " -> " + std::to_string(mysql_errno(conn)) + ": " + mysql_error(conn);
		}
		return false;
	}
	MYSQL_RES* res = mysql_store_result(conn);
	if (res) mysql_free_result(res);
	return true;
}

std::pair<string, int> pick_core_peer(const CommandLine& cl) {
	if (cl.cluster_nodes && strlen(cl.cluster_nodes) > 0) {
		std::vector<std::pair<string, int>> nodes;
		string all { cl.cluster_nodes };
		size_t start = 0;
		while (start <= all.size()) {
			size_t end = all.find(',', start);
			string tok = all.substr(start, end == string::npos ? string::npos : end - start);
			size_t colon = tok.find(':');
			if (!tok.empty()) {
				if (colon == string::npos) nodes.push_back({ tok, 6032 });
				else nodes.push_back({ tok.substr(0, colon), atoi(tok.c_str() + colon + 1) });
			}
			if (end == string::npos) break;
			start = end + 1;
		}
		// As in test_cluster1-t, the first entry is this node and the next
		// three are core nodes.
		if (nodes.size() > 1) return nodes[1];
	}
	return { cl.host, 26001 };
}

} // namespace

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}
	plan(5);

	const std::pair<string, int> peer = pick_core_peer(cl);
	MYSQL* local_admin = admin_connect(cl, cl.host, cl.admin_port);
	MYSQL* local_metrics = admin_connect(cl, cl.host, cl.admin_port);
	MYSQL* local_vars = admin_connect(cl, cl.host, cl.admin_port);
	MYSQL* peer_admin = admin_connect(cl, peer.first, peer.second);
	if (!local_admin || !local_metrics || !local_vars || !peer_admin) {
		BAIL_OUT("Unable to open the Admin connections (this node and core peer %s:%d)",
			peer.first.c_str(), peer.second);
	}

	// Values restored at the end.
	const std::vector<string> touched_vars {
		"admin-cluster_mysql_servers_save_to_disk",
		"admin-cluster_mysql_servers_diffs_before_sync",
		"admin-cluster_mysql_query_rules_save_to_disk",
		"admin-cluster_mysql_query_rules_diffs_before_sync",
		"admin-cluster_mysql_users_diffs_before_sync",
	};
	std::vector<std::pair<string, string>> saved_vars {};
	for (const string& name : touched_vars) {
		string value;
		if (get_variable_value(local_admin, name, value) == EXIT_SUCCESS) {
			saved_vars.push_back({ name, value });
		}
	}

	string setup_error;
	// Keep the pulled servers and query rules in memory only, as test_cluster1-t
	// does, and make sure this node does sync both from its peers.
	run(local_admin, "SET admin-cluster_mysql_servers_save_to_disk='false'", setup_error);
	run(local_admin, "SET admin-cluster_mysql_servers_diffs_before_sync=1", setup_error);
	run(local_admin, "SET admin-cluster_mysql_query_rules_save_to_disk='false'", setup_error);
	run(local_admin, "SET admin-cluster_mysql_query_rules_diffs_before_sync=1", setup_error);
	run(local_admin, "LOAD ADMIN VARIABLES TO RUNTIME", setup_error);
	ok(setup_error.empty(), "Setup on this node succeeded %s", setup_error.c_str());

	std::atomic<bool> stop { false };
	string peer_error, metrics_error, vars_error;
	int peer_loads = 0, metrics_runs = 0, vars_runs = 0;

	// Peer: every change of its mysql_query_rules or mysql_servers makes this
	// node pull them. The dummy rule is inactive and matches no traffic.
	std::thread peer_thread([&] {
		for (int i = 1; !stop.load(); ++i) {
			const string r =
				"REPLACE INTO mysql_query_rules (rule_id, active, username, match_digest, comment) VALUES ("
				+ std::to_string(DUMMY_RULE_ID) + ", 0, 'cluster_admin_lock_order', '^SELECT "
				+ std::to_string(i) + "$', 'cluster_admin_lock_order')";
			if (!run(peer_admin, r, peer_error)) break;
			if (!run(peer_admin, "LOAD MYSQL QUERY RULES TO RUNTIME", peer_error)) break;
			const string q =
				"REPLACE INTO mysql_servers (hostgroup_id, hostname, port, status, weight, comment) VALUES ("
				+ std::to_string(DUMMY_HOSTGROUP) + ", '127.0.0.2', 3306, 'OFFLINE_HARD', "
				+ std::to_string(i) + ", 'cluster_admin_lock_order')";
			if (!run(peer_admin, q, peer_error)) break;
			if (!run(peer_admin, "LOAD MYSQL SERVERS TO RUNTIME", peer_error)) break;
			++peer_loads;
			std::this_thread::sleep_for(std::chrono::milliseconds(300));
		}
	});

	// This node: SHOW PROMETHEUS METRICS takes the nodes mutex.
	std::thread metrics_thread([&] {
		while (!stop.load()) {
			if (!run(local_metrics, "SHOW PROMETHEUS METRICS", metrics_error)) break;
			++metrics_runs;
		}
	});

	// This node: re-enabling a disabled diffs_before_sync resets the per-peer
	// global checksums. Users sync is toggled so that query rules and servers
	// sync stay enabled.
	std::thread vars_thread([&] {
		while (!stop.load()) {
			if (!run(local_vars, "SET admin-cluster_mysql_users_diffs_before_sync=0", vars_error)) break;
			if (!run(local_vars, "LOAD ADMIN VARIABLES TO RUNTIME", vars_error)) break;
			if (!run(local_vars, "SET admin-cluster_mysql_users_diffs_before_sync=3", vars_error)) break;
			if (!run(local_vars, "LOAD ADMIN VARIABLES TO RUNTIME", vars_error)) break;
			++vars_runs;
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
	});

	std::this_thread::sleep_for(std::chrono::seconds(RUN_SECONDS));
	stop.store(true);
	peer_thread.join();
	metrics_thread.join();
	vars_thread.join();

	diag("peer loads=%d, SHOW PROMETHEUS METRICS=%d, LOAD ADMIN VARIABLES cycles=%d",
		peer_loads, metrics_runs, vars_runs);
	ok(peer_error.empty() && peer_loads > 0, "Peer kept changing mysql_query_rules and mysql_servers %s",
		peer_error.c_str());
	ok(metrics_error.empty() && metrics_runs > 0,
		"SHOW PROMETHEUS METRICS never timed out during the Cluster pulls %s", metrics_error.c_str());
	ok(vars_error.empty() && vars_runs > 0,
		"LOAD ADMIN VARIABLES TO RUNTIME never timed out during the Cluster pulls %s", vars_error.c_str());

	// Cleanup: drop the dummy rule and server on the peer (the removals sync
	// back) and check that this node still answers.
	string cleanup_error;
	run(peer_admin, "DELETE FROM mysql_query_rules WHERE rule_id=" + std::to_string(DUMMY_RULE_ID), cleanup_error);
	run(peer_admin, "LOAD MYSQL QUERY RULES TO RUNTIME", cleanup_error);
	run(peer_admin, "DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(DUMMY_HOSTGROUP), cleanup_error);
	run(peer_admin, "LOAD MYSQL SERVERS TO RUNTIME", cleanup_error);
	for (const auto& var : saved_vars) {
		run(local_admin, "SET " + var.first + "='" + var.second + "'", cleanup_error);
	}
	run(local_admin, "LOAD ADMIN VARIABLES TO RUNTIME", cleanup_error);
	run(local_admin, "SELECT 1", cleanup_error);
	ok(cleanup_error.empty(), "Admin on this node is responsive after the run %s", cleanup_error.c_str());

	mysql_close(peer_admin);
	mysql_close(local_vars);
	mysql_close(local_metrics);
	mysql_close(local_admin);

	return exit_status();
}
