#include "mysqlx_plugin.h"
#include "sqlite3db.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <set>
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
	SQLite3DB& admindb,
	std::vector<std::unique_ptr<Mysqlx_Thread>>& threads,
	std::map<std::string, int>& route_to_thread,
	std::mutex& route_to_thread_mutex,
	int& next_rr_index
) {
	if (threads.empty()) {
		return;
	}

	// 1. Snapshot the desired route set from runtime_mysqlx_routes.
	std::vector<DesiredRoute> desired;
	std::set<std::string> desired_names;
	{
		char* error = nullptr;
		std::unique_ptr<SQLite3_result> result(
			admindb.execute_statement(
				"SELECT name, bind FROM runtime_mysqlx_routes WHERE active=1",
				&error
			)
		);
		std::unique_ptr<char, void(*)(void*)> error_guard(error, &free);
		if (result) {
			for (auto* row : result->rows) {
				if (row == nullptr ||
				    row->fields[0] == nullptr ||
				    row->fields[1] == nullptr) {
					continue;
				}
				DesiredRoute dr;
				dr.name = row->fields[0];
				std::string bind_str = row->fields[1];
				dr.port = 33060;
				parse_bind_addr(bind_str, dr.host, dr.port);
				desired.push_back(std::move(dr));
				desired_names.insert(desired.back().name);
			}
		}
	}

	std::lock_guard<std::mutex> lock(route_to_thread_mutex);

	// 2. Remove listeners for routes that are no longer desired.
	for (auto it = route_to_thread.begin(); it != route_to_thread.end(); ) {
		if (desired_names.find(it->first) == desired_names.end()) {
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
			}
		}
	}
}
