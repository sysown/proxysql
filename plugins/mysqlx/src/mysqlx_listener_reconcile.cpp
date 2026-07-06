#include "mysqlx_plugin.h"
#include "mysqlx_config_store.h"
#include "sqlite3db.h"
#include "proxysql.h"
#include "proxysql_debug.h"

#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

// Parse a "host:port" / "[host]:port" bind spec into host and port. Mirrors
// the logic used at plugin startup — kept local to this translation unit so
// the reconciliation helper does not depend on plugin.cpp internals.
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

struct DesiredRoute {
	std::string name;
	std::string host;
	int port;
};

} // namespace

void mysqlx_reconcile_listeners_impl(
	const MysqlxConfigStore& store,
	std::vector<std::unique_ptr<Mysqlx_Thread>>& threads,
	std::map<std::string, int>& route_to_thread,
	std::mutex& route_to_thread_mutex,
	int& next_rr_index
) {
	proxy_info("mysqlx: reconcile_listeners entered: threads=%zu route_to_thread=%zu\n",
	           threads.size(), route_to_thread.size());
	if (threads.empty()) {
		proxy_error("mysqlx: reconcile_listeners: threads empty — bailing out without binding\n");
		return;
	}

	// Invariant: this function is only ever called from the admin thread
	// (startup or LOAD MYSQLX ROUTES TO RUNTIME). The store snapshot below is
	// taken outside of route_to_thread_mutex on the assumption that no second
	// reconcile can run concurrently. If ProxySQL ever gains a parallel admin
	// execution path, move the mutex acquisition above the snapshot.

	// 1. Snapshot the desired route set from MysqlxConfigStore directly.
	//    We deliberately do NOT read runtime_mysqlx_routes — that table is an
	//    on-demand projection of the store, only populated when admin runs a
	//    SELECT against it. Reading it here would see empty/stale data on
	//    every startup and every LOAD MYSQLX ROUTES TO RUNTIME call (the LOAD
	//    callback writes the store and then calls this reconciler before any
	//    SELECT has triggered the projection).
	std::vector<DesiredRoute> desired;
	std::map<std::string, const DesiredRoute*> desired_by_name;
	{
		auto routes = store.snapshot_active_routes();
		proxy_info("mysqlx: reconcile_listeners: store has %zu active routes\n", routes.size());
		desired.reserve(routes.size());
		for (auto& r : routes) {
			DesiredRoute dr;
			dr.name = std::move(r.first);
			dr.port = 33060;
			parse_bind_addr(r.second, dr.host, dr.port);
			proxy_info("mysqlx: reconcile_listeners: desired route name='%s' host='%s' port=%d (raw bind='%s')\n",
			           dr.name.c_str(), dr.host.c_str(), dr.port, r.second.c_str());
			desired.push_back(std::move(dr));
		}
		for (const auto& dr : desired) {
			desired_by_name[dr.name] = &dr;
		}
	}

	std::lock_guard<std::mutex> lock(route_to_thread_mutex);

	// 2. Remove listeners for routes that are no longer desired OR whose bind
	//    address has changed. A bind-address change is treated as remove+add:
	//    the old listener fd is closed and step 3 rebinds under the new spec.
	for (auto it = route_to_thread.begin(); it != route_to_thread.end(); ) {
		bool needs_removal = false;
		auto d_it = desired_by_name.find(it->first);
		if (d_it == desired_by_name.end()) {
			needs_removal = true;
		} else {
			int tidx = it->second;
			if (tidx >= 0 && tidx < static_cast<int>(threads.size()) && threads[tidx]) {
				std::string current = threads[tidx]->get_listener_addr_for_route(it->first);
				std::string desired_addr = d_it->second->host + ":" +
					std::to_string(d_it->second->port);
				if (current != desired_addr) {
					needs_removal = true;
				}
			}
		}
		if (needs_removal) {
			int tidx = it->second;
			if (tidx >= 0 && tidx < static_cast<int>(threads.size()) && threads[tidx]) {
				threads[tidx]->remove_listener_for_route(it->first.c_str());
			}
			it = route_to_thread.erase(it);
		} else {
			++it;
		}
	}

	// 3. Add listeners for routes that are desired but not yet mapped.
	int pool = static_cast<int>(threads.size());
	for (const auto& dr : desired) {
		if (route_to_thread.find(dr.name) != route_to_thread.end()) {
			continue; // already mapped; leave untouched
		}
		int tidx = ((next_rr_index % pool) + pool) % pool;
		next_rr_index = (next_rr_index + 1) % pool;
		if (threads[tidx]) {
			int rc = threads[tidx]->add_listener(
				dr.host.c_str(), dr.port, dr.name.c_str()
			);
			if (rc == 0) {
				route_to_thread[dr.name] = tidx;
			} else {
				proxy_error("mysqlx: reconcile_listeners: add_listener failed for route '%s' on thread %d\n",
				            dr.name.c_str(), tidx);
			}
		} else {
			proxy_error("mysqlx: reconcile_listeners: thread %d is null, cannot add listener for route '%s'\n",
			            tidx, dr.name.c_str());
		}
	}
}
