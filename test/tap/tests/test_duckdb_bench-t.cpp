#include "mysql.h"
#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"
#include "duckdb.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

const int kPlan = 12;
const int kSqlite3Port = 6030;
const int kDuckdbMysqlPort = 6031;
const char* kDuckdbPgsqlPort = "6034";
const int kInsertBatch = 100;

enum class Target { native, plugin_mysql, plugin_pgsql, sqlite3 };
enum class Workload { connect, point, agg };

const char* target_name(Target t) {
	switch (t) {
		case Target::native: return "native";
		case Target::plugin_mysql: return "plugin-mysql";
		case Target::plugin_pgsql: return "plugin-pgsql";
		case Target::sqlite3: return "sqlite3";
	}
	return "?";
}

const char* target_table_tag(Target t) {
	switch (t) {
		case Target::native: return "native";
		case Target::plugin_mysql: return "mysql";
		case Target::plugin_pgsql: return "pgsql";
		case Target::sqlite3: return "sqlite3";
	}
	return "x";
}

const char* workload_name(Workload w) {
	switch (w) {
		case Workload::connect: return "connect";
		case Workload::point: return "point";
		case Workload::agg: return "agg";
	}
	return "?";
}

struct Config {
	int warmup = 50;
	int iters = 500;
	int rows = 10000;
	int threads = 1;
	std::string table[4];
};

struct CellResult {
	const char* target = "";
	const char* workload = "";
	int threads = 1;
	int iters = 0;
	double ops_s = 0;
	double p50_us = 0;
	double p99_us = 0;
	int errors = 0;
	int n_success = 0;
	bool have_pct = false;
	bool ran = false;
};

double now_us() {
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

int cmp_double(const void* a, const void* b) {
	const double da = *static_cast<const double*>(a);
	const double db = *static_cast<const double*>(b);
	return (da > db) - (da < db);
}

double percentile(double* sorted, int n, double p) {
	int idx = static_cast<int>(n * p);
	if (idx >= n) idx = n - 1;
	return sorted[idx];
}

int env_positive_int(const char* name, int def) {
	const char* v = getenv(name);
	if (v == nullptr || v[0] == '\0') return def;
	errno = 0;
	char* end = nullptr;
	const long x = std::strtol(v, &end, 10);
	if (errno == ERANGE || end == v || *end != '\0' || x < 1 || x > INT_MAX) {
		BAIL_OUT("%s must be a positive integer (got '%s')", name, v);
	}
	return static_cast<int>(x);
}

int target_index(Target t) {
	return static_cast<int>(t);
}

struct Session {
	virtual ~Session() {}
	virtual bool connect() = 0;
	virtual bool exec_drain(const char* sql) = 0;
	virtual void close() = 0;
};

struct NativeSession : Session {
	duckdb_database* db = nullptr;
	duckdb_connection conn = nullptr;

	bool connect() override {
		return duckdb_connect(*db, &conn) == DuckDBSuccess && conn != nullptr;
	}
	bool exec_drain(const char* sql) override {
		duckdb_result res;
		if (duckdb_query(conn, sql, &res) != DuckDBSuccess) {
			duckdb_destroy_result(&res);
			return false;
		}
		const idx_t rows = duckdb_row_count(&res);
		const idx_t cols = duckdb_column_count(&res);
		for (idx_t r = 0; r < rows; r++) {
			for (idx_t c = 0; c < cols; c++) {
				if (duckdb_value_is_null(&res, c, r)) continue;
				char* s = duckdb_value_varchar(&res, c, r);
				if (s) duckdb_free(s);
			}
		}
		duckdb_destroy_result(&res);
		return true;
	}
	void close() override {
		if (conn) duckdb_disconnect(&conn);
		conn = nullptr;
	}
};

struct MysqlSession : Session {
	const char* host = nullptr;
	const char* user = nullptr;
	const char* pass = nullptr;
	int port = 0;
	MYSQL* c = nullptr;

	bool connect() override {
		c = mysql_init(nullptr);
		if (c == nullptr) return false;
		if (!mysql_real_connect(c, host, user, pass, nullptr, port, nullptr, 0)) {
			mysql_close(c);
			c = nullptr;
			return false;
		}
		return true;
	}
	bool exec_drain(const char* sql) override {
		if (mysql_query(c, sql) != 0) return false;
		MYSQL_RES* r = mysql_store_result(c);
		if (r) {
			while (mysql_fetch_row(r)) {
			}
			mysql_free_result(r);
			return true;
		}
		return mysql_errno(c) == 0;
	}
	void close() override {
		if (c) mysql_close(c);
		c = nullptr;
	}
};

struct PgsqlSession : Session {
	std::string conninfo;
	PGconn* c = nullptr;

	bool connect() override {
		c = PQconnectdb(conninfo.c_str());
		if (c == nullptr) return false;
		if (PQstatus(c) != CONNECTION_OK) {
			PQfinish(c);
			c = nullptr;
			return false;
		}
		return true;
	}
	bool exec_drain(const char* sql) override {
		PGresult* r = PQexec(c, sql);
		if (r == nullptr) return false;
		const ExecStatusType st = PQresultStatus(r);
		const bool ok = (st == PGRES_TUPLES_OK || st == PGRES_COMMAND_OK);
		if (st == PGRES_TUPLES_OK) {
			const int n = PQntuples(r);
			const int cols = PQnfields(r);
			for (int i = 0; i < n; i++) {
				for (int j = 0; j < cols; j++) {
					(void)PQgetvalue(r, i, j);
				}
			}
		}
		PQclear(r);
		return ok;
	}
	void close() override {
		if (c) PQfinish(c);
		c = nullptr;
	}
};

Session* make_session(Target t, CommandLine& cl, duckdb_database* db) {
	switch (t) {
		case Target::native: {
			auto* s = new NativeSession();
			s->db = db;
			return s;
		}
		case Target::plugin_mysql: {
			auto* s = new MysqlSession();
			s->host = cl.host;
			s->user = cl.username;
			s->pass = cl.password;
			s->port = kDuckdbMysqlPort;
			return s;
		}
		case Target::sqlite3: {
			auto* s = new MysqlSession();
			s->host = cl.host;
			s->user = cl.username;
			s->pass = cl.password;
			s->port = kSqlite3Port;
			return s;
		}
		case Target::plugin_pgsql: {
			auto* s = new PgsqlSession();
			s->conninfo = std::string("host=") + cl.host +
				" port=" + kDuckdbPgsqlPort +
				" user=" + cl.username + " password=" + cl.password +
				" dbname=main connect_timeout=10";
			return s;
		}
	}
	return nullptr;
}

std::string insert_batch_sql(const std::string& table, int start, int count) {
	std::string sql = "INSERT INTO " + table + " VALUES ";
	for (int i = 0; i < count; i++) {
		const int v = start + i;
		if (i) sql += ',';
		sql += '(';
		sql += std::to_string(v % 10);
		sql += ',';
		sql += std::to_string(v);
		sql += ')';
	}
	return sql;
}

bool setup_agg(Session* s, const std::string& table, int rows) {
	const std::string drop = "DROP TABLE IF EXISTS " + table;
	const std::string create = "CREATE TABLE " + table + " (k INTEGER, v INTEGER)";
	if (!s->exec_drain(drop.c_str())) return false;
	if (!s->exec_drain(create.c_str())) return false;
	int done = 0;
	while (done < rows) {
		const int n = std::min(kInsertBatch, rows - done);
		const std::string ins = insert_batch_sql(table, done, n);
		if (!s->exec_drain(ins.c_str())) return false;
		done += n;
	}
	return true;
}

void teardown_agg(Session* s, const std::string& table) {
	const std::string drop = "DROP TABLE IF EXISTS " + table;
	(void)s->exec_drain(drop.c_str());
}

struct WorkerArg {
	Target target;
	Workload workload;
	CommandLine* cl;
	duckdb_database* db;
	const std::string* table;
	int warmup;
	int iters;
	std::vector<double> samples;
	int errors = 0;
	int warmup_logged = 0;
};

void* worker(void* varg) {
	WorkerArg* arg = static_cast<WorkerArg*>(varg);
	if (arg->target == Target::plugin_mysql || arg->target == Target::sqlite3) {
		mysql_thread_init();
	}

	Session* persistent = nullptr;
	if (arg->workload != Workload::connect) {
		persistent = make_session(arg->target, *arg->cl, arg->db);
		if (persistent == nullptr || !persistent->connect()) {
			arg->errors = arg->iters;
			delete persistent;
			if (arg->target == Target::plugin_mysql || arg->target == Target::sqlite3) {
				mysql_thread_end();
			}
			return nullptr;
		}
	}

	auto one_iter = [&]() -> bool {
		if (arg->workload == Workload::connect) {
			Session* s = make_session(arg->target, *arg->cl, arg->db);
			const bool ok = s && s->connect();
			if (s) {
				s->close();
				delete s;
			}
			return ok;
		}
		const char* sql = (arg->workload == Workload::point)
			? "SELECT 1 AS x"
			: nullptr;
		std::string agg;
		if (arg->workload == Workload::agg) {
			agg = "SELECT k, SUM(v) FROM " + *arg->table + " GROUP BY k";
			sql = agg.c_str();
		}
		return persistent->exec_drain(sql);
	};

	for (int i = 0; i < arg->warmup; i++) {
		if (!one_iter() && arg->warmup_logged < 3) {
			diag("%s %s warmup failed", target_name(arg->target), workload_name(arg->workload));
			arg->warmup_logged++;
		}
	}

	arg->samples.reserve(arg->iters);
	for (int i = 0; i < arg->iters; i++) {
		const double t0 = now_us();
		const bool ok = one_iter();
		const double dt = now_us() - t0;
		if (ok) arg->samples.push_back(dt);
		else arg->errors++;
	}

	if (persistent) {
		persistent->close();
		delete persistent;
	}
	if (arg->target == Target::plugin_mysql || arg->target == Target::sqlite3) {
		mysql_thread_end();
	}
	return nullptr;
}

CellResult measure(Target t, Workload w, CommandLine& cl, duckdb_database* db,
                   const Config& cfg) {
	CellResult out;
	out.target = target_name(t);
	out.workload = workload_name(w);
	out.iters = cfg.iters;
	out.threads = (w == Workload::agg) ? 1 : cfg.threads;
	out.ran = true;

	const int nthreads = out.threads;
	std::vector<WorkerArg> args(nthreads);
	std::vector<pthread_t> tids(nthreads);

	timespec wall0, wall1;
	clock_gettime(CLOCK_MONOTONIC, &wall0);
	for (int i = 0; i < nthreads; i++) {
		args[i].target = t;
		args[i].workload = w;
		args[i].cl = &cl;
		args[i].db = db;
		args[i].table = &cfg.table[target_index(t)];
		args[i].warmup = cfg.warmup;
		args[i].iters = cfg.iters;
		if (pthread_create(&tids[i], nullptr, worker, &args[i]) != 0) {
			BAIL_OUT("pthread_create failed");
		}
	}
	for (int i = 0; i < nthreads; i++) pthread_join(tids[i], nullptr);
	clock_gettime(CLOCK_MONOTONIC, &wall1);

	std::vector<double> all;
	for (int i = 0; i < nthreads; i++) {
		out.errors += args[i].errors;
		all.insert(all.end(), args[i].samples.begin(), args[i].samples.end());
	}
	out.n_success = static_cast<int>(all.size());
	const double wall_s = (wall1.tv_sec - wall0.tv_sec) +
		(wall1.tv_nsec - wall0.tv_nsec) / 1e9;
	const double denom = wall_s > 1e-9 ? wall_s : 1e-9;
	out.ops_s = out.n_success / denom;
	if (out.n_success > 0) {
		qsort(all.data(), all.size(), sizeof(double), cmp_double);
		out.p50_us = percentile(all.data(), out.n_success, 0.50);
		out.p99_us = percentile(all.data(), out.n_success, 0.99);
		out.have_pct = true;
	}
	return out;
}

void fail_remaining(CellResult* cells, int start, int n, int wl0, const char* target, const char* why) {
	diag("%s: %s", target, why);
	for (int i = 0; i < n; i++) {
		cells[start + i].target = target;
		cells[start + i].workload = workload_name(static_cast<Workload>(wl0 + i));
		cells[start + i].ran = true;
		cells[start + i].errors = 1;
	}
}

void print_table(const CellResult* cells, int n) {
	diag("fairness: native = DuckDB C API in the test-runner (no wire, no auth).");
	diag("          plugin-* = DuckDB in the ProxySQL container, all-text SQLite3_result.");
	diag("          sqlite3  = different engine, same MySQL wire path as plugin-mysql.");
	diag("target        workload  threads  iters  ops/s     p50_us    p99_us    errors");
	for (int i = 0; i < n; i++) {
		const CellResult& c = cells[i];
		if (!c.ran) continue;
		if (c.have_pct) {
			diag("%-13s %-8s %7d %6d %8.1f %9.1f %9.1f %7d",
			     c.target, c.workload, c.threads, c.iters,
			     c.ops_s, c.p50_us, c.p99_us, c.errors);
		} else {
			diag("%-13s %-8s %7d %6d %8.1f %9s %9s %7d",
			     c.target, c.workload, c.threads, c.iters,
			     c.ops_s, "-", "-", c.errors);
		}
	}
}

} // namespace

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environment variables");
		return -1;
	}

	plan(kPlan);

	const char* run = getenv("RUN_DUCKDB_BENCH");
	if (run == nullptr || std::strcmp(run, "1") != 0) {
		skip(kPlan, "set RUN_DUCKDB_BENCH=1 to run the DuckDB bench");
		return exit_status();
	}

	Config cfg;
	cfg.warmup = env_positive_int("BENCH_WARMUP", 50);
	cfg.iters = env_positive_int("BENCH_ITERS", 500);
	cfg.rows = env_positive_int("BENCH_ROWS", 10000);
	cfg.threads = env_positive_int("BENCH_THREADS", 1);
	const pid_t pid = getpid();
	const Target targets[4] = {
		Target::native, Target::plugin_mysql, Target::plugin_pgsql, Target::sqlite3
	};
	for (int i = 0; i < 4; i++) {
		cfg.table[i] = std::string("bench_") + target_table_tag(targets[i]) +
			"_" + std::to_string(pid);
	}

	duckdb_database db = nullptr;
	if (duckdb_open(":memory:", &db) != DuckDBSuccess || db == nullptr) {
		BAIL_OUT("duckdb_open(:memory:) failed");
	}

	mysql_library_init(0, nullptr, nullptr);

	CellResult cells[kPlan];
	const Workload workloads[3] = { Workload::connect, Workload::point, Workload::agg };

	for (int ti = 0; ti < 4; ti++) {
		const Target t = targets[ti];
		const int base = ti * 3;

		Session* probe = make_session(t, cl, &db);
		const bool reachable = probe && probe->connect();
		if (!reachable) {
			diag("%s setup connect failed", target_name(t));
			delete probe;
			fail_remaining(cells, base, 3, 0, target_name(t), "connect failed at setup");
			continue;
		}

		bool agg_ok = true;
		if (!setup_agg(probe, cfg.table[ti], cfg.rows)) {
			diag("%s aggregation setup SQL failed", target_name(t));
			agg_ok = false;
		}
		probe->close();
		delete probe;

		if (!agg_ok) {
			cells[base] = measure(t, Workload::connect, cl, &db, cfg);
			cells[base + 1] = measure(t, Workload::point, cl, &db, cfg);
			fail_remaining(cells, base + 2, 1, 2, target_name(t), "aggregation setup SQL failed");
			continue;
		}

		for (int wi = 0; wi < 3; wi++) {
			cells[base + wi] = measure(t, workloads[wi], cl, &db, cfg);
		}

		Session* drop = make_session(t, cl, &db);
		if (drop && drop->connect()) {
			teardown_agg(drop, cfg.table[ti]);
			drop->close();
		}
		delete drop;
	}

	print_table(cells, kPlan);

	for (int i = 0; i < kPlan; i++) {
		ok(cells[i].ran && cells[i].errors == 0,
		   "%s %s errors=0", cells[i].target, cells[i].workload);
	}

	mysql_library_end();
	duckdb_close(&db);
	return exit_status();
}
