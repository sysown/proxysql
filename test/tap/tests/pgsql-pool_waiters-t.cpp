#include <atomic>
#include <chrono>
#include <memory>
#include <poll.h>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <unistd.h>

#include "libpq-fe.h"
#include <mysql.h>
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr mk() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username
	   << " sslmode=disable connect_timeout=5";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool select1(PGconn* c) {
	if (!c || PQstatus(c) != CONNECTION_OK) return false;
	PGresult* r = PQexec(c, "SELECT 1");
	const bool ok = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0
		&& std::string(PQgetvalue(r, 0, 0)) == "1";
	PQclear(r);
	return ok;
}

static bool wait_select1(PGconn* c, int timeout_ms) {
	if (!c || PQstatus(c) != CONNECTION_OK) return false;
	if (!PQsendQuery(c, "SELECT 1")) return false;
	auto start = std::chrono::steady_clock::now();
	while (PQisBusy(c)) {
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - start).count();
		if (elapsed > timeout_ms) return false;
		pollfd fd{PQsocket(c), POLLIN, 0};
		poll(&fd, 1, 50);
		if (!PQconsumeInput(c)) return false;
	}
	bool ok = false;
	for (;;) {
		PGresult* r = PQgetResult(c);
		if (!r) break;
		if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0
			&& std::string(PQgetvalue(r, 0, 0)) == "1") {
			ok = true;
		}
		PQclear(r);
	}
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

static void restore_maxconn(MYSQL* admin, const std::vector<std::pair<std::string, std::string>>& orig) {
	if (orig.empty()) {
		admin_exec(admin, "UPDATE pgsql_servers SET max_connections=50");
	} else {
		for (const auto& row : orig) {
			std::string q = "UPDATE pgsql_servers SET max_connections=" + row.second +
			                " WHERE hostgroup_id=" + row.first;
			admin_exec(admin, q.c_str());
		}
	}
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

int main(int argc, char** argv) {
	if (cl.getEnv()) return exit_status();
	plan(11);

	MYSQL* admin = admin_connect();
	if (!ok(admin != nullptr, "admin connected")) {
		return exit_status();
	}

	auto orig_maxconn = admin_rows2(admin,
		"SELECT hostgroup_id, max_connections FROM pgsql_servers ORDER BY hostgroup_id");
	std::string orig_maxfe = admin_scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-max_connections'");
	admin_exec(admin, "SET pgsql-max_connections=20000");
	admin_exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	admin_exec(admin, "UPDATE pgsql_servers SET max_connections=20");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	{
		const int nthreads = 400;
		const int nqueries = 10;
		std::atomic<int> oks{0};
		std::atomic<int> errs{0};
		std::vector<int> per(nthreads, 0);
		std::atomic<bool> hammer{true};
		std::atomic<int> admin_fail{0};
		std::thread admin_thr([&] {
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
			ts.emplace_back([&, i] {
				PGConnPtr c = mk();
				if (!c || PQstatus(c.get()) != CONNECTION_OK) {
					errs++;
					return;
				}
				for (int q = 0; q < nqueries; q++) {
					if (select1(c.get())) {
						oks++;
						per[i]++;
					} else {
						errs++;
					}
				}
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
			ts.emplace_back([&, i] {
				unsigned rng = 1103515245u * (unsigned)i + 12345u;
				while (std::chrono::steady_clock::now() < deadline) {
					PGConnPtr c = mk();
					if (!c || PQstatus(c.get()) != CONNECTION_OK) {
						errs++;
						continue;
					}
					reconnects++;
					const int burst = 4 + (int)((rng / 65536u) % 8);
					rng = rng * 1103515245u + 12345u;
					bool abort_inflight = ((rng / 65536u) % 5) == 0;
					rng = rng * 1103515245u + 12345u;
					for (int q = 0; q < burst; q++) {
						if (select1(c.get())) oks++;
						else {
							errs++;
							break;
						}
					}
					if (abort_inflight && c && PQstatus(c.get()) == CONNECTION_OK) {
						(void)PQsendQuery(c.get(), "SELECT 1");
						(void)PQflush(c.get());
						inflight_aborts++;
					}
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
		std::atomic<int> holder_ok{0};
		std::atomic<int> waiter_ok{0};
		std::atomic<int> waiter_err{0};
		std::vector<std::thread> holders;
		for (int i = 0; i < 20; i++) {
			holders.emplace_back([&] {
				PGConnPtr c = mk();
				if (!c || PQstatus(c.get()) != CONNECTION_OK) return;
				PGresult* r = PQexec(c.get(), "SELECT pg_sleep(1.2)");
				if (PQresultStatus(r) == PGRES_TUPLES_OK) holder_ok++;
				PQclear(r);
			});
		}
		usleep(400 * 1000);
		std::vector<std::thread> waiters;
		for (int i = 0; i < 40; i++) {
			const bool abort = i < 20;
			waiters.emplace_back([&, abort] {
				PGConnPtr c = mk();
				if (!c || PQstatus(c.get()) != CONNECTION_OK) {
					waiter_err++;
					return;
				}
				if (abort) {
					(void)PQsendQuery(c.get(), "SELECT 1");
					(void)PQflush(c.get());
					usleep(400 * 1000);
					return;
				}
				if (wait_select1(c.get(), 15000)) waiter_ok++;
				else waiter_err++;
			});
		}
		for (auto& t : waiters) t.join();
		for (auto& t : holders) t.join();
		ok(holder_ok.load() == 20, "20 pg_sleep holders filled the pool (ok=%d)", holder_ok.load());
		ok(waiter_ok.load() == 20 && waiter_err.load() == 0,
			"20 surviving waiters completed after 20 aborted (ok=%d err=%d)",
			waiter_ok.load(), waiter_err.load());
	}

	ok(admin_exec(admin, "SELECT 1"), "admin still answers after waiter contention and churn");

	{
		PGConnPtr c = mk();
		ok(c && PQstatus(c.get()) == CONNECTION_OK && select1(c.get()),
			"new session works after storms");
	}

	bool drained = false;
	std::string q = std::string("SELECT COUNT(*) FROM stats_pgsql_processlist WHERE user='")
		+ cl.pgsql_username + "'";
	for (int i = 0; i < 100; i++) {
		std::string n = admin_scalar(admin, q.c_str());
		if (n == "0") {
			drained = true;
			break;
		}
		usleep(100 * 1000);
	}
	ok(drained, "frontend processlist drained after clients closed");

	restore_maxconn(admin, orig_maxconn);
	if (!orig_maxfe.empty()) {
		admin_exec(admin, (std::string("SET pgsql-max_connections=") + orig_maxfe).c_str());
		admin_exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	mysql_close(admin);
	return exit_status();
}
