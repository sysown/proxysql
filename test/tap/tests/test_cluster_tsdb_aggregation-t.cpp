/**
 * @file test_cluster_tsdb_aggregation-t.cpp
 * @brief E2E test for TSDB cluster aggregation (leader pulls peers' tsdb_metrics).
 *
 * Spawns a self-contained 3-node cluster (127.0.0.1:16162/16172/16182,
 * weights 300/200/100), seeds 6h of synthetic history per node, then
 * verifies: leader-only aggregation of all 3 nodes (incl. itself),
 * backfill-horizon trimming, multi-cycle batch-cap catch-up, per-node
 * exactness, /api/tsdb/nodes, failover backfill from peers' retention,
 * and watermark resume after the old leader rejoins.
 * Skips (plan 1) on builds without TSDB or leader election.
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

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

struct node_t {
	int idx;
	int admin_port;
	int restapi_port;
	int weight;
	string datadir;
	string cnf_path;
	std::atomic<pid_t> pid { -1 };
	std::thread* runner = nullptr;
};

static node_t nodes_def[3];
static string workdir_path;

static const int SEED_METRICS = 3;
static const long SEED_SPAN_S = 6 * 3600;   // 6h of history
static const long SEED_STEP_S = 5;          // 5s grid
static const int BACKFILL_HOURS = 2;        // horizon << seeded span

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
	fprintf(f, "\trestapi_enabled=\"true\"\n");
	fprintf(f, "\trestapi_port=%d\n", n.restapi_port);
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
	// 'exec' is load-bearing: without it sh forks and the recorded pid is the
	// shell, so SIGKILL would not kill proxysql (see test_cluster_leader_election-t).
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

static bool query_ok(MYSQL* conn, const char* q) {
	return mysql_query(conn, q) == 0;
}

static long long single_ll(MYSQL* conn, const string& q, long long defval = -1) {
	if (mysql_query(conn, q.c_str())) { return defval; }
	MYSQL_RES* res = mysql_store_result(conn);
	if (res == NULL) { return defval; }
	MYSQL_ROW row = mysql_fetch_row(res);
	long long v = (row && row[0]) ? atoll(row[0]) : defval;
	mysql_free_result(res);
	return v;
}

static bool var_exists(MYSQL* conn, const char* name) {
	string q = "SELECT count(*) FROM global_variables WHERE variable_name='" + string(name) + "'";
	return single_ll(conn, q, 0) == 1;
}

// Seeds SEED_METRICS synthetic series covering [now-SEED_SPAN_S, now] on the
// node behind `conn`. Values encode the node index for cross-checks.
static bool seed_synthetic(MYSQL* conn, int node_idx, long now) {
	const int rows_per_stmt = 500;
	for (int m = 1; m <= SEED_METRICS; m++) {
		long n_rows = SEED_SPAN_S / SEED_STEP_S;
		long done = 0;
		while (done < n_rows) {
			string q = "INSERT INTO stats_history.tsdb_metrics (timestamp, metric_name, labels, value) VALUES ";
			int in_stmt = 0;
			while (in_stmt < rows_per_stmt && done < n_rows) {
				long ts = now - SEED_SPAN_S + done * SEED_STEP_S;
				if (in_stmt) { q += ","; }
				q += "(" + std::to_string(ts) + ",'synthetic_metric_" + std::to_string(m)
					+ "','{}'," + std::to_string(node_idx * 1000000 + done) + ")";
				in_stmt++;
				done++;
			}
			if (mysql_query(conn, q.c_str())) {
				diag("seed failed on node %d metric %d: %s", node_idx, m, mysql_error(conn));
				return false;
			}
		}
	}
	return true;
}

static string node_id(int i) {
	return "127.0.0.1:" + std::to_string(nodes_def[i].admin_port);
}

static long long cluster_count(MYSQL* conn, const string& node, const string& metric) {
	return single_ll(conn,
		"SELECT COUNT(*) FROM stats_history.tsdb_metrics_cluster WHERE node='" + node
		+ "' AND metric_name='" + metric + "'", -1);
}

// Aggregation runs on a fixed timer (tsdb-cluster_interval=5s here) and
// tsdb-cluster_batch_rows caps rows fetched PER PEER PER CYCLE, so the
// count can sit flat for up to ~cluster_interval seconds *between* cycles
// while more cycles are still needed to catch up. Sampling once a second and
// declaring "stable" after just two equal reads would false-positive on that
// inter-cycle plateau. Require the count to stay unchanged for a window
// longer than one cluster cycle before declaring convergence.
static const int CLUSTER_INTERVAL_S = 5;
static const int STABLE_WINDOW_S = CLUSTER_INTERVAL_S + 2;

// Polls until the count is stable (unchanged for STABLE_WINDOW_S consecutive
// seconds) or timeout.
static long long wait_stable_count(MYSQL* conn, const string& node, const string& metric, int timeout_s) {
	long long prev = -2;
	int stable_for = 0;
	for (int i = 0; i < timeout_s; i++) {
		long long c = cluster_count(conn, node, metric);
		if (c >= 0 && c == prev) {
			stable_for++;
			if (stable_for >= STABLE_WINDOW_S) { return c; }
		} else {
			stable_for = 0;
		}
		prev = c;
		sleep(1);
	}
	return prev;
}

// Total replicated row count for a node across ALL metrics (not just the
// one-time synthetic backfill): node3 keeps producing genuine per-second
// samples of its own internal metrics for as long as it is alive, so this
// total keeps growing while a live leader is actively pulling from it.
static long long node_total_count(MYSQL* conn, const string& node) {
	return single_ll(conn, "SELECT COUNT(*) FROM stats_history.tsdb_metrics_cluster WHERE node='" + node + "'", -1);
}

// Polls node_total_count() until it strictly exceeds `floor` or times out.
// Used to confirm the leader's aggregator is actually running and pulling
// fresh data, as opposed to sitting on an unchanged, pre-restart count.
static long long wait_count_above(MYSQL* conn, const string& node, long long floor, int timeout_s) {
	long long c = floor;
	for (int i = 0; i < timeout_s; i++) {
		c = node_total_count(conn, node);
		if (c > floor) { return c; }
		sleep(1);
	}
	return c;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("Failed to get the required environmental variables."); return -1; }
	workdir_path = cl.workdir;

	const string base = workdir_path + "test_cluster_tsdb_aggregation_config";
	// Wipe any datadir left over from a prior run: node datadirs persist
	// stats_history.db across invocations, and both the synthetic seed
	// (fixed epoch timestamps under a UNIQUE(timestamp,metric_name,labels)
	// constraint) and the cluster-table emptiness checks are only valid
	// against a clean start.
	{ string rm_cmd = "rm -rf " + base; int rc = system(rm_cmd.c_str()); (void)rc; }
	mkdir(base.c_str(), 0700);
	for (int i = 0; i < 3; i++) {
		nodes_def[i].idx = i + 1;
		nodes_def[i].admin_port = 16162 + i * 10;
		nodes_def[i].restapi_port = 16165 + i * 10;
		nodes_def[i].weight = 300 - i * 100;
		nodes_def[i].datadir = base + "/node" + std::to_string(i + 1);
		nodes_def[i].cnf_path = nodes_def[i].datadir + "/node.cnf";
	}
	for (int i = 0; i < 3; i++) {
		mkdir(nodes_def[i].datadir.c_str(), 0700);
		write_node_config(nodes_def[i]);
		spawn_node(nodes_def[i], true);
	}

	MYSQL* a[3] = { admin_conn(nodes_def[0].admin_port), admin_conn(nodes_def[1].admin_port), admin_conn(nodes_def[2].admin_port) };
	if (a[0] == NULL || a[1] == NULL || a[2] == NULL) {
		fprintf(stderr, "File %s, line %d, Error: failed to start the 3 cluster nodes\n", __FILE__, __LINE__);
		for (int i = 0; i < 3; i++) {
			pid_t p = nodes_def[i].pid.load();
			if (p > 0) { kill(p, SIGKILL); }
			join_node(nodes_def[i]);
		}
		return -1;
	}

	bool feature = var_exists(a[0], "admin-cluster_leader_election") && var_exists(a[0], "tsdb-enabled");
	if (feature == false) {
		plan(1);
		ok(1, "TSDB or leader election not compiled in this build - skipping");
	} else {
		plan(27);
		long seed_now = (long)time(NULL);

		// --- Setup under FORCED_RW: tsdb vars + synthetic seed --- (3+3+3)
		for (int i = 0; i < 3; i++) {
			ok(query_ok(a[i], "PROXYSQL READWRITE"), "node%d: PROXYSQL READWRITE", i + 1);
		}
		for (int i = 0; i < 3; i++) {
			bool vars_ok =
				query_ok(a[i], "SET tsdb-enabled='1'") &&
				query_ok(a[i], "SET tsdb-sample_interval='1'") &&
				query_ok(a[i], "SET tsdb-cluster_interval='5'") &&
				query_ok(a[i], "SET tsdb-cluster_batch_rows='1000'") &&
				query_ok(a[i], ("SET tsdb-cluster_backfill_hours='" + std::to_string(BACKFILL_HOURS) + "'").c_str()) &&
				query_ok(a[i], "LOAD TSDB VARIABLES TO RUNTIME") &&
				// Persist to disk: node1 is later SIGKILLed and restarted
				// *without* --initial, so it reloads config from its on-disk
				// sqlite config db, not from node.cnf. Without this, it would
				// come back with tsdb-enabled=0 (default), its aggregator
				// would never restart, and the resume assertion below would
				// pass trivially on an unchanged count.
				query_ok(a[i], "SAVE TSDB VARIABLES TO DISK");
			ok(vars_ok, "node%d: tsdb variables configured: %s", i + 1, mysql_error(a[i]));
		}
		for (int i = 0; i < 3; i++) {
			ok(seed_synthetic(a[i], i + 1, seed_now), "node%d: synthetic history seeded (%ld rows)",
				i + 1, (long)SEED_METRICS * (SEED_SPAN_S / SEED_STEP_S));
		}

		// --- Release to election --- (3 + 1)
		for (int i = 0; i < 3; i++) {
			ok(query_ok(a[i], "PROXYSQL READONLY AUTO"), "node%d: PROXYSQL READONLY AUTO", i + 1);
		}
		bool leader_ok = false;
		for (int i = 0; i < 30; i++) {
			if (single_ll(a[0], "SELECT COUNT(*) FROM stats_proxysql_servers_status WHERE master='YES' AND port=16162", 0) == 1) { leader_ok = true; break; }
			usleep(500 * 1000);
		}
		ok(leader_ok, "node1 (highest weight) becomes leader");

		// --- Incremental catch-up (batch cap forces multiple cycles) --- (1)
		long long c1 = -1, c2 = -1;
		for (int i = 0; i < 60; i++) {
			long long c = cluster_count(a[0], node_id(1), "synthetic_metric_1");
			if (c > 0 && c1 < 0) { c1 = c; }
			else if (c1 >= 0 && c > c1) { c2 = c; break; }
			sleep(1);
		}
		ok(c1 > 0 && c2 > c1, "replication progresses incrementally across cycles (%lld -> %lld)", c1, c2);

		// --- Exactness within the horizon --- (3)
		// EXACT computation, not a fudge-factor range: a batch-boundary gap (the
		// class of bug this fix addresses) leaves specific timestamps within the
		// replicated range missing while their neighbors are present, which a
		// generous ~1440 range check can't detect. Instead, once the count is
		// stable, compute the number of 5s-grid points the replicated range
		// [MIN(replicated ts), source's own true MAX(ts)] must contain and require
		// an EXACT match. The upper bound is read from the node's own
		// stats_history.tsdb_metrics (never from what was replicated), so a
		// dropped trailing group can't silently shrink `expected` along with `c`.
		// Any gap anywhere in the range makes count < expected.
		for (int i = 0; i < 3; i++) {
			long long c = wait_stable_count(a[0], node_id(i), "synthetic_metric_1", 90);
			long long min_ts = single_ll(a[0],
				"SELECT MIN(timestamp) FROM stats_history.tsdb_metrics_cluster WHERE node='" + node_id(i)
				+ "' AND metric_name='synthetic_metric_1'", -1);
			long long src_max_ts = single_ll(a[i],
				"SELECT MAX(timestamp) FROM stats_history.tsdb_metrics WHERE metric_name='synthetic_metric_1'", -1);
			long long expected = (min_ts >= 0 && src_max_ts >= 0) ? ((src_max_ts - min_ts) / SEED_STEP_S + 1) : -1;
			ok(c == expected, "node%d synthetic rows within horizon replicated exactly (got %lld, expected %lld from range [%lld, %lld])",
				i + 1, c, expected, min_ts, src_max_ts);
		}

		// --- Horizon trim: nothing older than ~2h replicated --- (1)
		long long min_ts = single_ll(a[0],
			"SELECT MIN(timestamp) FROM stats_history.tsdb_metrics_cluster WHERE metric_name LIKE 'synthetic_%'", -1);
		ok(min_ts >= seed_now - SEED_SPAN_S + 3 * 3600,
			"backfill horizon trimmed 6h of history to ~2h (min replicated ts %lld)", min_ts);

		// --- Followers do not aggregate --- (2)
		ok(single_ll(a[1], "SELECT COUNT(*) FROM stats_history.tsdb_metrics_cluster", -1) == 0, "node2 (follower) cluster table empty");
		ok(single_ll(a[2], "SELECT COUNT(*) FROM stats_history.tsdb_metrics_cluster", -1) == 0, "node3 (follower) cluster table empty");

		// --- REST /api/tsdb/nodes on the leader --- (1)
		{
			string curl_cmd = "curl -s --max-time 5 http://127.0.0.1:" + std::to_string(nodes_def[0].restapi_port) + "/api/tsdb/nodes";
			FILE* p = popen(curl_cmd.c_str(), "r");
			string out;
			if (p) {
				char buf[4096]; size_t n;
				while ((n = fread(buf, 1, sizeof(buf), p)) > 0) { out.append(buf, n); }
				int rc = pclose(p);
				if (rc != 0 && out.empty()) {
					skip(1, "curl unavailable in the runner");
				} else {
					ok(out.find(node_id(0)) != string::npos && out.find(node_id(1)) != string::npos && out.find(node_id(2)) != string::npos,
						"/api/tsdb/nodes lists all three nodes: %s", out.substr(0, 200).c_str());
				}
			} else {
				skip(1, "popen failed for curl");
			}
		}

		// Storage sizing diagnostic (spec: defaults are placeholders until sized)
		{
			long long rows = single_ll(a[0], "SELECT COUNT(*) FROM stats_history.tsdb_metrics_cluster", -1);
			long long pc = single_ll(a[0], "PRAGMA stats_history.page_count", -1);
			long long ps = single_ll(a[0], "PRAGMA stats_history.page_size", -1);
			diag("SIZING: tsdb_metrics_cluster rows=%lld stats_db_bytes=%lld", rows, (pc > 0 && ps > 0) ? pc * ps : -1);
		}

		// --- Failover: node2 takes over and backfills history it never observed --- (3)
		// Total count (not just synthetic_metric_1): the synthetic backfill is a
		// one-time seed that stops growing once fully replicated, so it can't be
		// used to prove the *resumed* leader is actually pulling fresh data below.
		// node3's own live, ever-growing per-second metrics can.
		long long node3_hist_before = node_total_count(a[0], node_id(2));
		{
			pid_t p1 = nodes_def[0].pid.load();
			if (p1 > 0) { kill(p1, SIGKILL); }
			join_node(nodes_def[0]);
			mysql_close(a[0]); a[0] = NULL;
		}
		bool failover_ok = false;
		for (int i = 0; i < 30; i++) {
			if (single_ll(a[1], "SELECT COUNT(*) FROM stats_proxysql_servers_status WHERE master='YES' AND port=16172", 0) == 1) { failover_ok = true; break; }
			usleep(500 * 1000);
		}
		ok(failover_ok, "after leader kill, node2 becomes leader");
		long long c_n3 = wait_stable_count(a[1], node_id(2), "synthetic_metric_1", 90);
		ok(c_n3 >= 1380, "new leader backfilled node3 synthetic history predating its leadership (got %lld)", c_n3);
		long long c_self = wait_stable_count(a[1], node_id(1), "synthetic_metric_1", 60);
		ok(c_self >= 1380, "new leader backfilled its own synthetic history (got %lld)", c_self);

		// --- Old leader rejoins, retakes leadership, resumes from its table --- (3)
		spawn_node(nodes_def[0], false);
		a[0] = admin_conn(nodes_def[0].admin_port);
		ok(a[0] != NULL, "node1 restarted and reachable");
		bool retake_ok = false;
		for (int i = 0; i < 40; i++) {
			if (a[0] && single_ll(a[0], "SELECT COUNT(*) FROM stats_proxysql_servers_status WHERE master='YES' AND port=16162", 0) == 1) { retake_ok = true; break; }
			usleep(500 * 1000);
		}
		ok(retake_ok, "rejoined node1 retakes leadership (highest weight)");
		// Strict increase, not >=: node1 must actually re-elect, restart its
		// aggregator (requires tsdb-enabled to have survived the restart via the
		// SAVE...TO DISK above), and pull node3's post-kill live samples. A node1
		// that came back with tsdb-enabled=0 would leave its on-disk cluster table
		// exactly where it was pre-kill, making a >= check pass trivially.
		long long c_resume = wait_count_above(a[0], node_id(2), node3_hist_before, 90);
		ok(a[0] != NULL && c_resume > node3_hist_before, "node1 resumed aggregation from its surviving watermarks (%lld > %lld)", c_resume, node3_hist_before);
	}

	// Teardown
	for (int i = 0; i < 3; i++) {
		if (a[i]) {
			mysql_query(a[i], "PROXYSQL SHUTDOWN");
			mysql_close(a[i]);
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
