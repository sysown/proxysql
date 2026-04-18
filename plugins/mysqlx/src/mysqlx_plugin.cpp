#include "mysqlx_plugin.h"
#include "mysqlx_config_store.h"
#include "sqlite3db.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace {

bool mysqlx_init(ProxySQL_PluginServices* services) {
	if (services == nullptr) {
		return false;
	}

	MysqlxPluginContext& ctx = mysqlx_context();
	ctx.services = services;
	ctx.config_store = std::make_unique<MysqlxConfigStore>();
	ctx.started = false;
	return mysqlx_register_admin_schema(*services);
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

bool copy_to_runtime(SQLite3DB& admindb, ProxySQL_PluginServices* services) {
	const char* pairs[][2] = {
		{"mysqlx_users", "runtime_mysqlx_users"},
		{"mysqlx_routes", "runtime_mysqlx_routes"},
		{"mysqlx_backend_endpoints", "runtime_mysqlx_backend_endpoints"},
		{"mysqlx_variables", "runtime_mysqlx_variables"},
	};
	bool all_ok = true;
	for (const auto& p : pairs) {
		std::string dest = "main.";
		dest += p[1];
		std::string source = "main.";
		source += p[0];
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
			sync_disk_to_memory(*admindb, ctx.services);
			copy_to_runtime(*admindb, ctx.services);

			std::string err;
			if (!ctx.config_store->load_from_runtime(*admindb, err)) {
				if (ctx.services->log_message != nullptr) {
					ctx.services->log_message(3, err.c_str());
				}
			}
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

	if (ctx.services != nullptr && ctx.services->get_admindb != nullptr) {
		SQLite3DB* admindb = ctx.services->get_admindb();
		if (admindb != nullptr) {
			char* error = nullptr;
			std::unique_ptr<SQLite3_result> result(
				admindb->execute_statement(
					"SELECT name, bind FROM runtime_mysqlx_routes WHERE active=1",
					&error
				)
			);
			std::unique_ptr<char, void(*)(void*)> error_guard(error, &free);
			if (result && !result->rows.empty()) {
				int ti = 0;
				for (auto* row : result->rows) {
					if (row == nullptr || row->fields[0] == nullptr || row->fields[1] == nullptr) {
						continue;
					}
					std::string bind_str = row->fields[1];
					std::string host {};
					int port = 33060;
					parse_bind_addr(bind_str, host, port);

					if (ti < static_cast<int>(ctx.threads.size())) {
						Mysqlx_Thread* thr = ctx.threads[ti % pool_size].get();
						thr->add_listener(host.c_str(), port);
					}
					ti++;
				}
			}
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
	1,
	&mysqlx_init,
	&mysqlx_start,
	&mysqlx_stop,
	&mysqlx_status_json,
};

} // namespace

MysqlxPluginContext& mysqlx_context() {
	static MysqlxPluginContext ctx {};
	return ctx;
}

extern "C" const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	return &mysqlx_descriptor;
}
