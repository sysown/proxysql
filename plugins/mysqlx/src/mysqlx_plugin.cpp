#include "mysqlx_plugin.h"
#include "mysqlx_config_store.h"
#include "sqlite3db.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace {

// Phase B: declare admin-schema tables only. Runs BEFORE the admin
// module is initialized, so `services` has register_table live but the
// DB handle getters return nullptr. mysqlx_register_admin_schema only
// touches services->register_table, so this is a clean split.
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

bool sync_disk_to_memory(SQLite3DB& admindb) {
	const char* tables[] = {
		"mysqlx_users",
		"mysqlx_routes",
		"mysqlx_backend_endpoints",
		"mysqlx_variables",
	};
	for (const char* tbl : tables) {
		char* err = nullptr;
		std::string q = "SELECT COUNT(*) FROM disk.";
		q += tbl;
		std::unique_ptr<SQLite3_result> disk_res(admindb.execute_statement(q.c_str(), &err));
		std::unique_ptr<char, void(*)(void*)> err_guard(err, &free);
		if (err) continue;
		if (!disk_res || disk_res->rows.empty() || !disk_res->rows[0] || !disk_res->rows[0]->fields[0]) {
			continue;
		}
		int disk_cnt = atoi(disk_res->rows[0]->fields[0]);
		disk_res.reset();
		err_guard.reset();
		if (disk_cnt == 0) continue;

		admindb.execute("BEGIN");
		q = "DELETE FROM main.";
		q += tbl;
		admindb.execute(q.c_str());

		q = "INSERT INTO main.";
		q += tbl;
		q += " SELECT * FROM disk.";
		q += tbl;
		admindb.execute(q.c_str());
		admindb.execute("COMMIT");
	}
	return true;
}

bool copy_to_runtime(SQLite3DB& admindb) {
	const char* pairs[][2] = {
		{"mysqlx_users", "runtime_mysqlx_users"},
		{"mysqlx_routes", "runtime_mysqlx_routes"},
		{"mysqlx_backend_endpoints", "runtime_mysqlx_backend_endpoints"},
		{"mysqlx_variables", "runtime_mysqlx_variables"},
	};
	for (const auto& p : pairs) {
		char* err = nullptr;
		std::string q = "SELECT COUNT(*) FROM main.";
		q += p[0];
		std::unique_ptr<SQLite3_result> res(admindb.execute_statement(q.c_str(), &err));
		std::unique_ptr<char, void(*)(void*)> err_guard(err, &free);
		if (err) continue;
		if (!res || res->rows.empty() || !res->rows[0] || !res->rows[0]->fields[0]) {
			continue;
		}
		int cnt = atoi(res->rows[0]->fields[0]);
		res.reset();
		err_guard.reset();
		if (cnt == 0) continue;

		admindb.execute("BEGIN");
		q = "DELETE FROM main.";
		q += p[1];
		admindb.execute(q.c_str());

		q = "INSERT INTO main.";
		q += p[1];
		q += " SELECT * FROM main.";
		q += p[0];
		admindb.execute(q.c_str());
		admindb.execute("COMMIT");
	}
	return true;
}

bool mysqlx_start() {
	MysqlxPluginContext& ctx = mysqlx_context();

	if (ctx.services != nullptr && ctx.services->get_admindb != nullptr) {
		SQLite3DB* admindb = ctx.services->get_admindb();
		if (admindb != nullptr) {
			sync_disk_to_memory(*admindb);
			copy_to_runtime(*admindb);

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
	&mysqlx_register_schemas,
};

} // namespace

MysqlxPluginContext& mysqlx_context() {
	static MysqlxPluginContext ctx {};
	return ctx;
}

extern "C" const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	return &mysqlx_descriptor;
}
