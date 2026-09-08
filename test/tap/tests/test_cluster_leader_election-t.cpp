/**
 * @file test_cluster_leader_election-t.cpp
 * @brief E2E test for ProxySQL Cluster leader election (PROXYSQL31 feature).
 *
 * Spawns a self-contained 3-node ProxySQL cluster on 127.0.0.1 (bespoke
 * configs, weights 300/200/100), then verifies: convergence to a single
 * leader, follower write refusal (SQL + LOAD TO RUNTIME + SAVE TO DISK),
 * FORCED_RW stickiness, leader failover on kill, leadership retake on
 * rejoin, and full-RW behavior with election disabled.
 * Skips (plan 1) on non-PROXYSQL31 builds where the master switch is absent.
 */

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

struct node_t {
	int idx;            // 1..3
	int admin_port;     // 16062/16072/16082
	int weight;         // 300/200/100
	string datadir;
	string cnf_path;
	std::atomic<pid_t> pid { -1 };
	std::thread* runner = nullptr;
};

static node_t nodes_def[3];

static string workdir_path;

static void write_node_config(node_t& n) {
	FILE* f = fopen(n.cnf_path.c_str(), "w");
	if (f == NULL) {
		// A config write failure here is unrecoverable pre-plan: fail loudly
		// and immediately instead of leaving the caller to time out opaquely
		// ~15s later waiting for a node that never started.
		fprintf(stderr, "FATAL: cannot write %s: %s\n", n.cnf_path.c_str(), strerror(errno));
		exit(1);
	}
	fprintf(f, "datadir=\"%s\"\n", n.datadir.c_str());
	fprintf(f, "admin_variables = {\n");
	fprintf(f, "\tadmin_credentials=\"admin:admin;cluster1:secret1pass\"\n");
	fprintf(f, "\tmysql_ifaces=\"0.0.0.0:%d\"\n", n.admin_port);
	fprintf(f, "\tcluster_username=\"cluster1\"\n");
	fprintf(f, "\tcluster_password=\"secret1pass\"\n");
	fprintf(f, "\tcluster_check_interval_ms=200\n");
	fprintf(f, "\tcluster_leader_election=\"true\"\n");
	fprintf(f, "\tcluster_leader_node_timeout_ms=1000\n");
	fprintf(f, "\tcluster_leader_grace_ms=500\n");
	fprintf(f, "}\n");
	fprintf(f, "mysql_variables = {\n");
	fprintf(f, "\tthreads=2\n");
	fprintf(f, "\tinterfaces=\"0.0.0.0:%d\"\n", n.admin_port + 1);
	fprintf(f, "}\n");
	fprintf(f, "proxysql_servers = (\n");
	for (int i = 0; i < 3; i++) {
		fprintf(f, "\t{ hostname=\"127.0.0.1\"; port=%d; weight=%d; comment=\"node%d\"; }%s\n",
			nodes_def[i].admin_port, nodes_def[i].weight, nodes_def[i].idx, (i < 2 ? "," : ""));
	}
	fprintf(f, ")\n");
	fclose(f);
}

static void spawn_node(node_t& n, bool initial) {
	const string binary = workdir_path + "../../../src/proxysql";
	const string stderr_f = n.datadir + "/node_stderr.txt";
	// 'exec' is load-bearing: without it /bin/sh forks the command (because of
	// the redirections) and the pid recorded below is the shell wrapper, not
	// proxysql - so the SIGKILL in the failover scenario would kill only the
	// wrapper and leave the node alive (and the teardown would leak the node).
	string cmd = "exec " + binary + " -f -M -c " + n.cnf_path + " -D " + n.datadir;
	if (initial) { cmd += " --initial"; }
	cmd += " >> " + stderr_f + " 2>&1";
	n.runner = new std::thread([&n, cmd]() {
		pid_t p = fork();
		if (p == 0) { execl("/bin/sh", "sh", "-c", cmd.c_str(), (char*)nullptr); _exit(127); }
		n.pid.store(p);
		int status = 0;
		waitpid(p, &status, 0);
	});
	// give fork+exec a moment before callers start polling the admin port
	usleep(500 * 1000);
}

static void join_node(node_t& n) {
	if (n.runner) { n.runner->join(); delete n.runner; n.runner = nullptr; }
	n.pid.store(-1);
}

static MYSQL* admin_conn(int port) {
	conn_opts_t opts {};
	opts.host = "127.0.0.1";
	opts.user = "admin";
	opts.pass = "admin";
	opts.port = port;
	return wait_for_proxysql(opts, 15);
}

// Returns the admin_port of the row with master='YES' as seen by `conn`,
// or -1 if there is not exactly one leader row.
static int observed_leader(MYSQL* conn) {
	if (mysql_query(conn, "SELECT port, master FROM stats_proxysql_servers_status")) { return -1; }
	MYSQL_RES* res = mysql_store_result(conn);
	if (res == NULL) { return -1; }
	int leader = -1; int leaders = 0;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(res))) {
		if (row[1] && strcasecmp(row[1], "YES") == 0) { leaders++; leader = atoi(row[0]); }
	}
	mysql_free_result(res);
	return (leaders == 1 ? leader : -1);
}

// Polls until `conn` observes `expected_port` as the unique leader.
static bool wait_leader(MYSQL* conn, int expected_port, int timeout_s) {
	for (int i = 0; i < timeout_s * 2; i++) {
		if (observed_leader(conn) == expected_port) { return true; }
		usleep(500 * 1000);
	}
	return false;
}

static bool query_ok(MYSQL* conn, const char* q) {
	return mysql_query(conn, q) == 0;
}

// true if the query FAILED (as expected for a follower); stores the error.
static bool query_refused(MYSQL* conn, const char* q, string& err) {
	if (mysql_query(conn, q) == 0) { err = ""; return false; }
	err = mysql_error(conn);
	return true;
}

static const char* Q_INSERT = "INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (9999, '127.0.0.1', 13306)";
static const char* Q_DELETE = "DELETE FROM mysql_servers WHERE hostgroup_id=9999";
static const char* Q_LOAD   = "LOAD MYSQL SERVERS TO RUNTIME";
static const char* Q_SAVE   = "SAVE MYSQL SERVERS TO DISK";

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("Failed to get the required environmental variables."); return -1; }
	workdir_path = cl.workdir;

	const string base = workdir_path + "test_cluster_leader_election_config";
	mkdir(base.c_str(), 0700);
	// Pass 1: fully populate all 3 node_t entries first. write_node_config()
	// reads the WHOLE nodes_def[] array (to emit every node as a peer in
	// each other's proxysql_servers list), so it must not run until every
	// entry is initialized - otherwise not-yet-reached slots are read back
	// as zero-valued (port=0/weight=0), corrupting the peer list.
	for (int i = 0; i < 3; i++) {
		nodes_def[i].idx = i + 1;
		nodes_def[i].admin_port = 16062 + i * 10;
		nodes_def[i].weight = 300 - i * 100;
		nodes_def[i].datadir = base + "/node" + std::to_string(i + 1);
		nodes_def[i].cnf_path = nodes_def[i].datadir + "/node.cnf";
	}
	// Pass 2: now that nodes_def[] is fully populated, write configs and spawn.
	for (int i = 0; i < 3; i++) {
		mkdir(nodes_def[i].datadir.c_str(), 0700);
		write_node_config(nodes_def[i]);
		spawn_node(nodes_def[i], true);
	}

	MYSQL* a1 = admin_conn(nodes_def[0].admin_port);
	MYSQL* a2 = admin_conn(nodes_def[1].admin_port);
	MYSQL* a3 = admin_conn(nodes_def[2].admin_port);
	if (a1 == NULL || a2 == NULL || a3 == NULL) {
		fprintf(stderr, "File %s, line %d, Error: failed to start the 3 cluster nodes\n", __FILE__, __LINE__);
		for (int i = 0; i < 3; i++) {
			pid_t p = nodes_def[i].pid.load();
			if (p > 0) { kill(p, SIGKILL); }
			join_node(nodes_def[i]);
		}
		return -1;
	}

	// Feature detection: skip everything on non-PROXYSQL31 builds.
	bool feature = false;
	if (mysql_query(a1, "SELECT count(*) FROM global_variables WHERE variable_name='admin-cluster_leader_election'") == 0) {
		MYSQL_RES* res = mysql_store_result(a1);
		MYSQL_ROW row = mysql_fetch_row(res);
		feature = (row && row[0] && atoi(row[0]) == 1);
		mysql_free_result(res);
	}
	if (feature == false) {
		plan(1);
		ok(1, "admin-cluster_leader_election not present (non-PROXYSQL31 build) - skipping");
	} else {
		plan(32);
		string err;

		// --- Convergence: all 3 nodes agree node1 (16062) is leader --- (3)
		ok(wait_leader(a1, 16062, 15), "node1 observes node1 as the unique leader");
		ok(wait_leader(a2, 16062, 15), "node2 observes node1 as the unique leader");
		ok(wait_leader(a3, 16062, 15), "node3 observes node1 as the unique leader");

		// --- Leader accepts writes --- (3)
		ok(query_ok(a1, Q_INSERT), "leader accepts INSERT: %s", mysql_error(a1));
		ok(query_ok(a1, Q_LOAD), "leader accepts LOAD TO RUNTIME: %s", mysql_error(a1));
		ok(query_ok(a1, Q_SAVE), "leader accepts SAVE TO DISK: %s", mysql_error(a1));
		query_ok(a1, Q_DELETE); query_ok(a1, Q_LOAD); query_ok(a1, Q_SAVE); // cleanup

		// --- Leader survives LOAD ADMIN VARIABLES TO RUNTIME --- (1)
		// Regression check: flush_GENERIC_variables__process__database_to_runtime
		// re-applies every admin variable (including cluster_leader_election) on
		// every admin-vars reload, e.g. on every cluster sync. set_variable()
		// must only call set_cluster_follower(true) on the false->true
		// transition, otherwise the current leader gets kicked to
		// effective-RO on every such reload. No sleep: the check must catch
		// the state right after the reload, before the next election tick
		// would self-correct it.
		query_ok(a1, "LOAD ADMIN VARIABLES TO RUNTIME");
		ok(query_ok(a1, Q_INSERT) && query_ok(a1, Q_DELETE),
			"leader stays RW immediately after LOAD ADMIN VARIABLES TO RUNTIME: %s", mysql_error(a1));

		// --- Follower refuses writes --- (3 + 1 + 2 + 2)
		// NOTE: query_refused() mutates 'err', so it must be sequenced before
		// err.c_str() (C++ leaves argument evaluation order unspecified; the
		// one-liner form read a stale/freed buffer for the diag text).
		bool refused = query_refused(a2, Q_INSERT, err);
		ok(refused, "follower refuses INSERT (%s)", err.c_str());
		refused = query_refused(a2, Q_LOAD, err);
		ok(refused, "follower refuses LOAD TO RUNTIME (%s)", err.c_str());
		ok(strstr(err.c_str(), "16062") != NULL, "refusal error names the leader: %s", err.c_str());
		refused = query_refused(a2, Q_SAVE, err);
		ok(refused, "follower refuses SAVE TO DISK (%s)", err.c_str());
		// Abbreviated alias spellings must be refused too (Finding 1):
		// "TO RUN" == "TO RUNTIME" and "FROM MEM" == "FROM MEMORY".
		refused = query_refused(a2, "LOAD MYSQL SERVERS TO RUN", err);
		ok(refused, "follower refuses LOAD ... TO RUN (%s)", err.c_str());
		refused = query_refused(a2, "LOAD MYSQL SERVERS FROM MEM", err);
		ok(refused, "follower refuses LOAD ... FROM MEM (%s)", err.c_str());
		// Memory-tier-mutating forms bypass PRAGMA query_only via C++ flush
		// functions and must be refused explicitly (bot-review finding).
		refused = query_refused(a2, "LOAD MYSQL SERVERS FROM DISK", err);
		ok(refused, "follower refuses LOAD ... FROM DISK (%s)", err.c_str());
		refused = query_refused(a2, "SAVE MYSQL SERVERS FROM RUNTIME", err);
		ok(refused, "follower refuses SAVE ... FROM RUNTIME (%s)", err.c_str());

		// --- FORCED_RW override is sticky across election ticks --- (6)
		ok(query_ok(a2, "PROXYSQL READWRITE"), "PROXYSQL READWRITE accepted on follower");
		ok(query_ok(a2, Q_INSERT), "FORCED_RW follower accepts INSERT: %s", mysql_error(a2));
		ok(query_ok(a2, Q_LOAD), "FORCED_RW follower accepts LOAD TO RUNTIME: %s", mysql_error(a2));
		sleep(3); // several election ticks + grace periods
		ok(query_ok(a2, "DELETE FROM mysql_servers WHERE hostgroup_id=9999"), "FORCED_RW sticks across election ticks: %s", mysql_error(a2));
		query_ok(a2, Q_LOAD); // cleanup runtime on node2
		ok(query_ok(a2, "PROXYSQL READONLY AUTO"), "PROXYSQL READONLY AUTO accepted");
		refused = query_refused(a2, Q_INSERT, err);
		ok(refused, "AUTO follower refuses INSERT again (%s)", err.c_str());

		// --- Leader failover on kill --- (3)
		{
			pid_t p1 = nodes_def[0].pid.load();
			if (p1 > 0) { kill(p1, SIGKILL); }
			join_node(nodes_def[0]);
			mysql_close(a1); a1 = NULL;
		}
		ok(wait_leader(a2, 16072, 15), "after leader kill, node2 observes node2 as leader");
		ok(wait_leader(a3, 16072, 15), "after leader kill, node3 observes node2 as leader");
		ok(query_ok(a2, Q_INSERT), "new leader accepts INSERT: %s", mysql_error(a2));
		query_ok(a2, Q_DELETE); query_ok(a2, Q_LOAD); // cleanup

		// --- Ex-leader rejoins and retakes leadership (highest weight) --- (5)
		spawn_node(nodes_def[0], false); // keep datadir: same uuid, config from db
		a1 = admin_conn(nodes_def[0].admin_port);
		ok(a1 != NULL, "ex-leader restarted and reachable");
		ok(a1 != NULL && wait_leader(a1, 16062, 20), "rejoined node1 observes itself as leader again");
		ok(wait_leader(a2, 16062, 20), "node2 observes node1 as leader again");
		ok(wait_leader(a3, 16062, 20), "node3 observes node1 as leader again");
		refused = query_refused(a2, Q_INSERT, err);
		ok(refused, "node2 is follower again (%s)", err.c_str());

		// --- Election disabled: everyone read-write --- (3)
		MYSQL* conns[3] = { a1, a2, a3 };
		for (int i = 0; i < 3; i++) {
			if (conns[i] == NULL) { continue; }
			query_ok(conns[i], "PROXYSQL READWRITE");
			query_ok(conns[i], "SET admin-cluster_leader_election='false'");
			query_ok(conns[i], "LOAD ADMIN VARIABLES TO RUNTIME");
			query_ok(conns[i], "PROXYSQL READONLY AUTO");
		}
		sleep(2); // let ticks observe the disable
		ok(query_ok(a1, Q_INSERT), "election disabled: node1 accepts writes: %s", mysql_error(a1));
		ok(query_ok(a2, Q_INSERT), "election disabled: node2 accepts writes: %s", mysql_error(a2));
		ok(query_ok(a3, Q_INSERT), "election disabled: node3 accepts writes: %s", mysql_error(a3));
	}

	// Teardown: shut all nodes down.
	MYSQL* conns[3] = { a1, a2, a3 };
	for (int i = 0; i < 3; i++) {
		if (conns[i]) {
			mysql_query(conns[i], "PROXYSQL SHUTDOWN");
			mysql_close(conns[i]);
		}
		pid_t p = nodes_def[i].pid.load();
		if (p > 0) {
			for (int w = 0; w < 10 && kill(p, 0) == 0; w++) { usleep(500 * 1000); }
			if (kill(p, 0) == 0) { kill(p, SIGKILL); }
		}
		join_node(nodes_def[i]);
	}
	return exit_status();
}
