#include "mysqlx_plugin.h"
#include "mysqlx_config_store.h"
#include "sqlite3db.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace {

// Phase B: declare admin-schema tables only.  Runs BEFORE the admin
// module is initialized, so `services` has register_table live but the
// DB handle getters return nullptr.  mysqlx_register_admin_schema only
// touches services->register_table / register_command / register_command_alias,
// so this is a clean split.
bool mysqlx_register_schemas(ProxySQL_PluginServices* services) {
	if (services == nullptr) {
		return false;
	}
	return mysqlx_register_admin_schema(*services);
}

// Phase D: plugin-context setup with full services (live DB handles).
// Runs after admin bootstrap materializes the schemas registered in
// Phase B, so any future DB queries from init() see a schema that
// already contains the mysqlx_* tables.
bool mysqlx_init(ProxySQL_PluginServices* services) {
	if (services == nullptr) {
		return false;
	}

	MysqlxPluginContext& ctx = mysqlx_context();
	ctx.services = services;
	ctx.config_store = std::make_unique<MysqlxConfigStore>();
	ctx.started = false;
	return true;
}

bool parse_bind_addr(const std::string& bind, std::string& host, int& port) {
	if (!bind.empty() && bind[0] == '[') {
		auto closing = bind.find(']');
		if (closing != std::string::npos) {
			host = bind.substr(1, closing - 1);
			port = 33060;
			if (closing + 1 < bind.size() && bind[closing + 1] == ':') {
				port = std::atoi(bind.substr(closing + 2).c_str());
			}
			return true;
		}
	}
	auto pos = bind.rfind(':');
	if (pos == std::string::npos || pos == 0 || pos == bind.size() - 1) {
		host = bind;
		port = 33060;
		return true;
	}

	host = bind.substr(0, pos);
	port = std::atoi(bind.substr(pos + 1).c_str());
	if (port <= 0 || port > 65535) {
		port = 33060;
	}
	return true;
}

// Atomically replace `dest` with the rows from `source`. Every admindb.execute()
// return value is checked: on any failure we ROLLBACK (defensively, even after a
// failed BEGIN) and skip the table. Returns false if any step for this table
// failed. The transaction wrap is what makes this safe — without the return
// checks, a failed INSERT between a successful DELETE and an unconditional
// COMMIT would silently wipe the destination.
bool replace_table_atomically(SQLite3DB& admindb,
                              ProxySQL_PluginServices* services,
                              const char* dest,
                              const char* source) {
	auto log_err = [services](const char* msg) {
		if (services != nullptr && services->log_message != nullptr) {
			services->log_message(3, msg);
		}
	};

	if (!admindb.execute("BEGIN")) {
		std::string m = "mysqlx sync: BEGIN failed for ";
		m += dest;
		log_err(m.c_str());
		return false;
	}

	std::string q = "DELETE FROM ";
	q += dest;
	if (!admindb.execute(q.c_str())) {
		std::string m = "mysqlx sync: DELETE failed for ";
		m += dest;
		log_err(m.c_str());
		admindb.execute("ROLLBACK");
		return false;
	}

	q = "INSERT INTO ";
	q += dest;
	q += " SELECT * FROM ";
	q += source;
	if (!admindb.execute(q.c_str())) {
		std::string m = "mysqlx sync: INSERT failed for ";
		m += dest;
		log_err(m.c_str());
		admindb.execute("ROLLBACK");
		return false;
	}

	if (!admindb.execute("COMMIT")) {
		std::string m = "mysqlx sync: COMMIT failed for ";
		m += dest;
		log_err(m.c_str());
		// Defensive — COMMIT may have partially succeeded; best-effort ROLLBACK.
		admindb.execute("ROLLBACK");
		return false;
	}
	return true;
}

bool sync_disk_to_memory(SQLite3DB& admindb, ProxySQL_PluginServices* services) {
	const char* tables[] = {
		"mysqlx_users",
		"mysqlx_routes",
		"mysqlx_backend_endpoints",
		"mysqlx_variables",
	};
	bool all_ok = true;
	for (const char* tbl : tables) {
		std::string dest = "main.";
		dest += tbl;
		std::string source = "disk.";
		source += tbl;
		if (!replace_table_atomically(admindb, services, dest.c_str(), source.c_str())) {
			all_ok = false;
		}
	}
	return all_ok;
}

bool mysqlx_start() {
	MysqlxPluginContext& ctx = mysqlx_context();

	if (ctx.services != nullptr && ctx.services->get_admindb != nullptr) {
		SQLite3DB* admindb = ctx.services->get_admindb();
		if (admindb != nullptr) {
			// Disk -> memory: keep the editable tables in sync with disk
			// on startup, same as the canonical proxysql_admin path does
			// for mysql_users / mysql_servers / etc. This is admin-tier
			// persistence and is legitimate.
			sync_disk_to_memory(*admindb, ctx.services);

			// Memory -> module: the editable mysqlx_* tables now drive
			// the in-memory store directly. Each install_*_from_admin
			// SELECTs the editable table (and the relevant cross-module
			// runtime_mysql_* projections), builds a new local map, and
			// atomically swaps it into MysqlxConfigStore. We deliberately
			// do NOT replicate this data into runtime_mysqlx_* admin
			// tables -- those are projected on demand via the chassis
			// register_runtime_view() refresh callbacks declared below.
			std::string err;
			auto report_err = [&](const char* what) {
				if (ctx.services->log_message != nullptr) {
					std::string msg = "mysqlx: ";
					msg += what;
					msg += ": ";
					msg += err;
					ctx.services->log_message(3, msg.c_str());
				}
				err.clear();
			};
			if (!ctx.config_store->install_users_from_admin(*admindb, err))     report_err("install_users_from_admin failed");
			if (!ctx.config_store->install_routes_from_admin(*admindb, err))    report_err("install_routes_from_admin failed");
			if (!ctx.config_store->install_endpoints_from_admin(*admindb, err)) report_err("install_endpoints_from_admin failed");
			if (!ctx.config_store->install_variables_from_admin(*admindb, err)) report_err("install_variables_from_admin failed");
		}
	}

	int pool_size = ctx.config_store->get_thread_pool_size();
	if (pool_size < 1) pool_size = 1;
	if (pool_size > 64) pool_size = 64;

	int max_cached = ctx.config_store->get_max_cached_connections();

	for (int i = 0; i < pool_size; i++) {
		auto thr = std::make_unique<Mysqlx_Thread>();
		thr->init(i);
		thr->set_max_cached_connections(static_cast<size_t>(max_cached));
		thr->set_config_store(ctx.config_store.get());
		ctx.threads.push_back(std::move(thr));
	}

	// Startup binds listeners via the same desired-state reconciliation used
	// by LOAD MYSQLX ROUTES TO RUNTIME, so both paths agree on round-robin
	// distribution and the `route_to_thread` map is populated identically.
	if (ctx.services != nullptr && ctx.services->get_admindb != nullptr) {
		SQLite3DB* admindb = ctx.services->get_admindb();
		if (admindb != nullptr) {
			mysqlx_reconcile_listeners(*admindb);
		}
	}

	for (auto& thr : ctx.threads) {
		thr->start();
	}

	ctx.started = true;
	return true;
}

bool mysqlx_stop() {
	MysqlxPluginContext& ctx = mysqlx_context();

	for (auto& thr : ctx.threads) {
		thr->stop();
	}
	ctx.threads.clear();

	{
		std::lock_guard<std::mutex> lock(ctx.route_to_thread_mutex);
		ctx.route_to_thread.clear();
		ctx.next_rr_index = 0;
	}

	ctx.started = false;
	return true;
}

const char* mysqlx_status_json() {
	const MysqlxPluginContext& ctx = mysqlx_context();
	if (ctx.started) {
		return "{\"name\":\"mysqlx\",\"state\":\"running\"}";
	}
	return "{\"name\":\"mysqlx\",\"state\":\"stopped\"}";
}

const ProxySQL_PluginDescriptor mysqlx_descriptor = {
	"mysqlx",
	PROXYSQL_PLUGIN_ABI_VERSION,
	&mysqlx_init,
	&mysqlx_start,
	&mysqlx_stop,
	&mysqlx_status_json,
	&mysqlx_register_schemas,
};

} // namespace

MysqlxPluginContext& mysqlx_context() {
	static MysqlxPluginContext ctx {};
	return ctx;
}

void mysqlx_reconcile_listeners(SQLite3DB& admindb) {
	(void)admindb; // no longer consulted; kept in the public signature
	               // so the weak hook surface is stable for callers.
	MysqlxPluginContext& ctx = mysqlx_context();
	if (!ctx.config_store) {
		return;
	}
	mysqlx_reconcile_listeners_impl(
		*ctx.config_store,
		ctx.threads,
		ctx.route_to_thread,
		ctx.route_to_thread_mutex,
		ctx.next_rr_index
	);
}

namespace {

// Local copy of the SQLite single-quote escape used by mysqlx_stats.cpp;
// duplicating one tiny function is cheaper than introducing a shared
// header just for it. If a third caller appears, lift to mysqlx_util.h.
std::string sqlite_escape_local(const std::string& input) {
	std::string result;
	result.reserve(input.size());
	for (char c : input) {
		if (c == '\'') result += "''";
		else result += c;
	}
	return result;
}

uint64_t monotonic_time_ms_local() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL;
}

} // namespace

void mysqlx_populate_stats_processlist(SQLite3DB& statsdb) {
	MysqlxPluginContext& ctx = mysqlx_context();

	uint64_t now_ms = monotonic_time_ms_local();
	std::vector<MysqlxSessionSnapshot> rows;
	for (const auto& thr : ctx.threads) {
		if (thr) thr->snapshot_sessions_for_stats(rows, now_ms);
	}

	// Atomic rebuild: DELETE + INSERTs run in a single transaction so a
	// failure in any INSERT rolls everything back, leaving the previous
	// projection in place rather than a half-populated (or empty) table.
	// Reviewer feedback (CodeRabbit / Gemini on PR #5704) flagged that the
	// previous bare DELETE-then-loop-INSERTs would leave operators staring
	// at "no sessions" right after a transient SQLite error, which is far
	// more misleading than "stale-but-recent" data.
	if (!statsdb.execute("BEGIN")) return;
	if (!statsdb.execute("DELETE FROM stats_mysqlx_processlist")) {
		statsdb.execute("ROLLBACK");
		return;
	}
	for (const auto& r : rows) {
		std::string sql = "INSERT INTO stats_mysqlx_processlist "
			"(username, route, worker_id, backend_host, backend_port, "
			" auth_mode, connection_state, bytes_in, bytes_out, "
			" session_age_ms) VALUES ('";
		sql += sqlite_escape_local(r.username);
		sql += "', '"; sql += sqlite_escape_local(r.route);
		sql += "', "; sql += std::to_string(r.worker_id);
		sql += ", '"; sql += sqlite_escape_local(r.backend_host);
		sql += "', "; sql += std::to_string(r.backend_port);
		sql += ", '"; sql += sqlite_escape_local(r.auth_mode);
		sql += "', '"; sql += sqlite_escape_local(r.connection_state);
		sql += "', "; sql += std::to_string(r.bytes_in);
		sql += ", "; sql += std::to_string(r.bytes_out);
		sql += ", "; sql += std::to_string(r.session_age_ms);
		sql += ")";
		if (!statsdb.execute(sql.c_str())) {
			statsdb.execute("ROLLBACK");
			return;
		}
	}
	statsdb.execute("COMMIT");
}

// Default visibility is required because the plugin .so is built with
// -fvisibility=hidden (see plugins/mysqlx/Makefile). Without an explicit
// override the dlopen consumer cannot resolve this symbol via dlsym, and
// ProxySQL_PluginManager::load() fails with "undefined symbol:
// proxysql_plugin_descriptor_v1".
extern "C" __attribute__((visibility("default")))
const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	return &mysqlx_descriptor;
}
