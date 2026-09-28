#include <atomic>
#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <unistd.h>

#include <mysql.h>
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

static MYSQL* mk() {
	MYSQL* c = mysql_init(NULL);
	unsigned t = 20;
	mysql_options(c, MYSQL_OPT_CONNECT_TIMEOUT, &t);
	mysql_options(c, MYSQL_OPT_READ_TIMEOUT, &t);
	mysql_options(c, MYSQL_OPT_WRITE_TIMEOUT, &t);
	if (!mysql_real_connect(c, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		mysql_close(c);
		return NULL;
	}
	return c;
}

static bool select1(MYSQL* c, const char* query = "SELECT 1") {
	if (!c) return false;
	if (mysql_query(c, query)) return false;
	MYSQL_RES* r = mysql_store_result(c);
	const bool ok = r && mysql_num_rows(r) == 1;
	if (r) mysql_free_result(r);
	return ok;
}

static MYSQL* admin_connect() {
	MYSQL* conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, cl.admin_host, cl.admin_username, cl.admin_password,
	                        NULL, cl.admin_port, NULL, 0)) {
		diag("admin connect failed: %s", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}
	return conn;
}

static bool admin_exec(MYSQL* a, const char* q) {
	if (mysql_query(a, q)) {
		diag("admin query failed: '%s' : %s", q, mysql_error(a));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(a);
	if (!r && mysql_field_count(a) != 0) {
		diag("admin result failed: '%s' : %s", q, mysql_error(a));
		return false;
	}
	if (r) mysql_free_result(r);
	return true;
}

static std::string admin_scalar(MYSQL* a, const char* q) {
	std::string v;
	if (mysql_query(a, q)) {
		diag("admin query failed: '%s' : %s", q, mysql_error(a));
		return v;
	}
	MYSQL_RES* r = mysql_store_result(a);
	if (r) {
		MYSQL_ROW row = mysql_fetch_row(r);
		if (row && row[0]) v = row[0];
		mysql_free_result(r);
	}
	return v;
}

static std::vector<std::pair<std::string, std::string>> admin_rows2(MYSQL* a, const char* q) {
	std::vector<std::pair<std::string, std::string>> out;
	if (mysql_query(a, q)) {
		diag("admin query failed: '%s' : %s", q, mysql_error(a));
		return out;
	}
	MYSQL_RES* r = mysql_store_result(a);
	if (r) {
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(r))) {
			out.emplace_back(row[0] ? row[0] : "", row[1] ? row[1] : "");
		}
		mysql_free_result(r);
	}
	return out;
}

static std::string sql_quote(const char* value) {
	std::string out = "'";
	for (const char* p = value; *p; ++p) {
		out += *p;
		if (*p == '\'') out += '\'';
	}
	return out + "'";
}

template <typename Predicate>
static bool wait_until(Predicate predicate, int timeout_ms = 5000) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	do {
		if (predicate()) return true;
		usleep(10 * 1000);
	} while (std::chrono::steady_clock::now() < deadline);
	return false;
}

static bool wait_scalar(MYSQL* admin, const std::string& query, const std::string& expected) {
	std::string value;
	const bool matched = wait_until([&] {
		value = admin_scalar(admin, query.c_str());
		return value.empty() || value == expected;
	});
	if (!matched || value != expected) {
		diag("predicate failed: %s (expected=%s actual=%s)",
			query.c_str(), expected.c_str(), value.c_str());
		return false;
	}
	return true;
}

static bool restore_config(MYSQL* admin,
                          const std::vector<std::pair<std::string, std::string>>& orig,
                          const std::string& orig_maxfe) {
	bool restored = true;
	for (const auto& row : orig) {
		std::string q = "UPDATE mysql_servers SET max_connections=" + row.second +
		                " WHERE " + row.first;
		// Execute every restoration step, including both LOADs, after any error.
		if (!admin_exec(admin, q.c_str())) restored = false;
	}
	if (!admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME")) restored = false;
	if (!admin_exec(admin, ("SET mysql-max_connections=" + orig_maxfe).c_str())) restored = false;
	if (!admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) restored = false;
	return restored;
}

int main(int argc, char** argv) {
	if (cl.getEnv()) return exit_status();
	plan(15);

	MYSQL* admin = admin_connect();
	ok(admin != nullptr, "admin connected");
	if (admin == nullptr) {
		return exit_status();
	}

	auto orig_maxconn = admin_rows2(admin,
		"SELECT 'hostgroup_id=' || hostgroup_id || ' AND hostname=' || quote(hostname) || ' AND port=' || port, "
		"max_connections FROM mysql_servers ORDER BY hostgroup_id, hostname, port");
	std::string orig_maxfe = admin_scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-max_connections'");
	const std::string hostgroup = admin_scalar(admin,
		("SELECT default_hostgroup FROM runtime_mysql_users WHERE username=" +
		 sql_quote(cl.username) + " AND frontend=1 AND active=1 LIMIT 1").c_str());
	if (orig_maxconn.empty() || orig_maxfe.empty() || hostgroup.empty()) {
		mysql_close(admin);
		BAIL_OUT("cannot snapshot connection limits before changing test configuration");
	}
	const bool configured = admin_exec(admin, "SET mysql-max_connections=20000") &&
		admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME") &&
		admin_exec(admin, "UPDATE mysql_servers SET max_connections=20") &&
		admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	if (!configured) {
		const bool restored = restore_config(admin, orig_maxconn, orig_maxfe);
		mysql_close(admin);
		BAIL_OUT("test configuration failed; restoration %s", restored ? "succeeded" : "failed");
	}
	const std::string capacity = admin_scalar(admin,
		("SELECT COALESCE(SUM(max_connections),0) FROM runtime_mysql_servers WHERE hostgroup_id=" +
		 hostgroup + " AND status='ONLINE'").c_str());
	const int holder_count = std::atoi(capacity.c_str());
	if (holder_count <= 0 || holder_count > 400) {
		const bool restored = restore_config(admin, orig_maxconn, orig_maxfe);
		mysql_close(admin);
		BAIL_OUT("expected 1..400 backend slots in test hostgroup; restoration %s",
			restored ? "succeeded" : "failed");
	}

	{
		const int nthreads = 400;
		const int nqueries = 10;
		std::atomic<int> oks{0};
		std::atomic<int> errs{0};
		std::vector<int> per(nthreads, 0);
		std::atomic<bool> hammer{true};
		std::atomic<int> admin_fail{0};
		std::thread admin_thr([&admin_fail, &hammer] {
			MYSQL* a2 = admin_connect();
			if (!a2) {
				admin_fail++;
				return;
			}
			while (hammer.load()) {
				if (!admin_exec(a2, "SELECT 1")) admin_fail++;
				usleep(50 * 1000);
			}
			mysql_close(a2);
		});
		std::vector<std::thread> ts;
		ts.reserve(nthreads);
		for (int i = 0; i < nthreads; i++) {
			ts.emplace_back([&errs, &oks, &per, i] {
				MYSQL* c = mk();
				if (!c) {
					errs++;
					return;
				}
				for (int q = 0; q < nqueries; q++) {
					if (select1(c)) {
						oks++;
						per[i]++;
					} else {
						errs++;
					}
				}
				mysql_close(c);
			});
		}
		for (auto& t : ts) t.join();
		hammer.store(false);
		admin_thr.join();
		ok(errs.load() == 0 && oks.load() == nthreads * nqueries,
			"contention: %d clients x %d SELECT 1 max_connections=20 (ok=%d err=%d)",
			nthreads, nqueries, oks.load(), errs.load());
		int starved = 0;
		for (int n : per) if (n == 0) starved++;
		ok(starved == 0, "contention fairness: every client got results (starved=%d)", starved);
		ok(admin_fail.load() == 0, "admin answered during contention (fails=%d)", admin_fail.load());
	}

	{
		const int nthreads = 400;
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		std::atomic<int> oks{0};
		std::atomic<int> errs{0};
		std::atomic<int> reconnects{0};
		std::atomic<int> inflight_aborts{0};
		std::vector<std::thread> ts;
		ts.reserve(nthreads);
		for (int i = 0; i < nthreads; i++) {
			ts.emplace_back([deadline, &errs, &reconnects, &oks, &inflight_aborts, i] {
				unsigned rng = 1103515245u * (unsigned)i + 12345u;
				while (std::chrono::steady_clock::now() < deadline) {
					MYSQL* c = mk();
					if (!c) {
						errs++;
						continue;
					}
					reconnects++;
					const int burst = 4 + (int)((rng / 65536u) % 8);
					rng = rng * 1103515245u + 12345u;
					bool abort_inflight = ((rng / 65536u) % 5) == 0;
					rng = rng * 1103515245u + 12345u;
					for (int q = 0; q < burst; q++) {
						if (select1(c)) oks++;
						else {
							errs++;
							break;
						}
					}
					if (abort_inflight) {
						(void)mysql_send_query(c, "SELECT 1", 8);
						inflight_aborts++;
					}
					mysql_close(c);
				}
			});
		}
		for (auto& t : ts) t.join();
		ok(errs.load() == 0,
			"churn: 400 clients, 5s, 0 errors (ok=%d reconnects=%d inflight_abort=%d err=%d)",
			oks.load(), reconnects.load(), inflight_aborts.load(), errs.load());
		ok(reconnects.load() > nthreads,
			"churn reconnected more than once per thread (reconnects=%d)", reconnects.load());
	}

	{
		std::atomic<int> holder_ready{0};
		std::atomic<int> holder_ok{0};
		std::atomic<int> waiter_ok{0};
		std::atomic<int> waiter_err{0};
		std::atomic<int> aborted{0};
		std::atomic<bool> release_holders{false};
		std::atomic<bool> abort_waiters{false};
		// Route all participants to the same pool, independent of SELECT routing rules.
		const std::string route = "/* hostgroup=" + hostgroup + " */ ";
		const std::string begin = route + "BEGIN";
		const std::string query = route + "SELECT 1";
		const std::string pool_query =
			"SELECT COALESCE(SUM(ConnUsed),0) FROM stats_mysql_connection_pool WHERE hostgroup=" + hostgroup;
		// With every backend held, Connect sessions are waiting for a pool connection.
		const std::string waiters_query =
			"SELECT COUNT(*) FROM stats_mysql_processlist WHERE hostgroup=" + hostgroup +
			" AND user=" + sql_quote(cl.username) + " AND command='Connect'";
		const bool initially_drained = wait_scalar(admin, waiters_query, "0");
		std::vector<std::thread> holders;
		for (int i = 0; i < holder_count; i++) {
			holders.emplace_back([&] {
				MYSQL* c = mk();
				if (!c) return;
				if (mysql_query(c, begin.c_str()) == 0 && select1(c, query.c_str())) {
					holder_ready++;
					// An open transaction pins the backend until the coordinator releases it.
					const bool released = wait_until([&] { return release_holders.load(); }, 30000);
					if (mysql_query(c, "ROLLBACK") == 0 && released) holder_ok++;
				}
				mysql_close(c);
			});
		}
		const bool ready = wait_until([&] { return holder_ready.load() == holder_count; });
		const bool saturated = initially_drained && ready && wait_scalar(admin, pool_query, capacity);
		ok(saturated, "%d transaction holders saturated hostgroup %s (ready=%d)",
			holder_count, hostgroup.c_str(), holder_ready.load());
		std::vector<std::thread> waiters;
		if (saturated) for (int i = 0; i < 40; i++) {
			const bool abort = i < 20;
			waiters.emplace_back([&, abort] {
				MYSQL* c = mk();
				if (!c) {
					waiter_err++;
					return;
				}
				if (abort) {
					if (mysql_send_query(c, query.c_str(), query.size()) != 0) waiter_err++;
					if (!wait_until([&] { return abort_waiters.load(); }, 15000)) waiter_err++;
					mysql_close(c);
					aborted++;
					return;
				}
				if (select1(c, query.c_str())) waiter_ok++;
				else waiter_err++;
				mysql_close(c);
			});
		}
		const bool queued = saturated && wait_scalar(admin, waiters_query, "40");
		ok(queued, "all 40 waiters were queued before aborting any frontend");
		abort_waiters.store(true);
		const bool closed = saturated && wait_until([&] { return aborted.load() == 20; });
		const bool survivors_queued = queued && closed && wait_scalar(admin, waiters_query, "20");
		ok(survivors_queued, "20 survivors remained queued after 20 frontends aborted");
		// Always release and join clients, including when a synchronization assertion fails.
		release_holders.store(true);
		for (auto& t : holders) t.join();
		for (auto& t : waiters) t.join();
		ok(holder_ok.load() == holder_count, "%d holders released their transactions (ok=%d)",
			holder_count, holder_ok.load());
		ok(waiter_ok.load() == 20 && waiter_err.load() == 0,
			"20 surviving waiters completed after 20 aborted (ok=%d err=%d)",
			waiter_ok.load(), waiter_err.load());
	}

	ok(admin_exec(admin, "SELECT 1"), "admin still answers after waiter contention and churn");

	{
		MYSQL* c = mk();
		ok(c && select1(c), "new session works after storms");
		if (c) mysql_close(c);
	}

	bool drained = false;
	std::string q = "SELECT COUNT(*) FROM stats_mysql_processlist WHERE user=" + sql_quote(cl.username);
	for (int i = 0; i < 100; i++) {
		std::string n = admin_scalar(admin, q.c_str());
		if (n == "0") {
			drained = true;
			break;
		}
		usleep(100 * 1000);
	}
	ok(drained, "frontend processlist drained after clients closed");

	ok(restore_config(admin, orig_maxconn, orig_maxfe), "all original connection limits restored");
	mysql_close(admin);
	return exit_status();
}
