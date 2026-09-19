#include "mysql_router_compiler.h"

#include "sqlite3db.h"

#include <charconv>
#include <memory>
#include <stdexcept>

namespace {

std::unique_ptr<SQLite3_result> query(SQLite3DB& db, const std::string& sql) {
	char* raw_error = nullptr;
	std::unique_ptr<SQLite3_result> result(db.execute_statement(sql.c_str(), &raw_error));
	if (raw_error != nullptr) {
		std::string error(raw_error);
		sqlite3_free(raw_error);
		throw std::runtime_error(error);
	}
	if (!result) throw std::runtime_error("hostgroup allocation query failed");
	return result;
}

std::string quote(std::string_view value) {
	char* raw = sqlite3_mprintf("%Q", std::string(value).c_str());
	if (raw == nullptr) throw std::bad_alloc();
	std::string result(raw);
	sqlite3_free(raw);
	return result;
}

int parse_id(const char* text) {
	if (text == nullptr) throw std::runtime_error("hostgroup ID is NULL");
	int value = 0;
	const char* end = text + std::char_traits<char>::length(text);
	auto parsed = std::from_chars(text, end, value);
	if (parsed.ec != std::errc() || parsed.ptr != end || value < 1) {
		throw std::runtime_error("hostgroup ID is invalid");
	}
	return value;
}

ManagedHostgroups load_mapping(SQLite3DB& db, std::string_view scope_uuid) {
	ManagedHostgroups mapping;
	// Routing Guideline route hostgroups ("rg:<route>:<pool>") are managed by
	// load_or_allocate_guideline() and are not part of the baseline mapping.
	auto rows = query(db, "SELECT role,hostgroup_id FROM mysql_router_hostgroups WHERE scope_uuid=" +
		quote(scope_uuid) + " AND role NOT LIKE 'rg:%' ORDER BY role");
	for (auto* row : rows->rows) {
		if (row->fields[0] == nullptr) throw std::runtime_error("hostgroup role is NULL");
		if (!mapping.by_role.emplace(row->fields[0], parse_id(row->fields[1])).second) {
			throw std::runtime_error("duplicate persisted hostgroup role");
		}
	}
	return mapping;
}

void rollback(SQLite3DB& db) noexcept {
	try { db.execute("ROLLBACK"); } catch (...) {}
}

} // namespace

ManagedHostgroups HostgroupAllocator::load_or_allocate(SQLite3DB& configdb,
	std::string_view scope_uuid, const HostgroupAllocationInput& input) {
	if (scope_uuid.empty()) throw std::invalid_argument("hostgroup allocation scope is empty");
	if (!configdb.execute("BEGIN IMMEDIATE")) {
		throw std::runtime_error("cannot begin hostgroup allocation transaction");
	}
	try {
		ManagedHostgroups persisted = load_mapping(configdb, scope_uuid);
		const auto& roles = mysql_router_hostgroup_roles();
		if (!persisted.by_role.empty() && persisted.by_role.size() != roles.size()) {
			throw std::runtime_error("persisted hostgroup mapping is incomplete");
		}
		std::set<int> used = input.occupied_hostgroups;
		auto all_mappings = query(configdb,
			"SELECT hostgroup_id FROM mysql_router_hostgroups WHERE role NOT LIKE 'rg:%'");
		for (auto* row : all_mappings->rows) used.insert(parse_id(row->fields[0]));
		for (const auto& ownership : input.ownership) {
			if (ownership.second != "mysql_router") used.insert(ownership.first);
		}
		auto ledger = query(configdb,
			"SELECT owner,object_key FROM proxysql_plugin_owned_objects WHERE object_type='hostgroup'");
		std::map<int, std::set<std::string>> ledger_owners;
		for (auto* row : ledger->rows) {
			if (row->fields[0] == nullptr) throw std::runtime_error("hostgroup owner is NULL");
			ledger_owners[parse_id(row->fields[1])].insert(row->fields[0]);
			if (std::string_view(row->fields[0]) != "mysql_router") used.insert(parse_id(row->fields[1]));
		}
		if (!persisted.by_role.empty()) {
			std::set<int> unique;
			for (const std::string& role : roles) {
				const int id = persisted.at(role);
				if (id < 8000 || id > 8999 || !unique.insert(id).second) {
					throw std::runtime_error("persisted hostgroup mapping is invalid");
				}
				auto external = input.ownership.find(id);
				if ((external != input.ownership.end() && external->second != "mysql_router") ||
					(ledger_owners.count(id) &&
						(ledger_owners[id].size() != 1 || !ledger_owners[id].count("mysql_router")))) {
					throw std::runtime_error("persisted hostgroup is owned by another plugin");
				}
			}
			if (!configdb.execute("COMMIT")) throw std::runtime_error("cannot commit hostgroup reuse");
			return persisted;
		}

		ManagedHostgroups allocated;
		int candidate = 8000;
		for (const std::string& role : roles) {
			while (candidate <= 8999 && used.count(candidate)) ++candidate;
			if (candidate > 8999) throw std::runtime_error("fewer than eight managed hostgroups are available");
			allocated.by_role.emplace(role, candidate);
			used.insert(candidate++);
		}
		for (const auto& item : allocated.by_role) {
			const std::string insert = "INSERT INTO mysql_router_hostgroups(role,scope_uuid,hostgroup_id) VALUES(" +
				quote(item.first) + "," + quote(scope_uuid) + "," + std::to_string(item.second) + ")";
			if (!configdb.execute(insert.c_str())) throw std::runtime_error("cannot persist managed hostgroup mapping");
		}
		if (!configdb.execute("COMMIT")) throw std::runtime_error("cannot commit managed hostgroup mapping");
		return allocated;
	} catch (...) {
		rollback(configdb);
		throw;
	}
}

ManagedHostgroups HostgroupAllocator::load_or_allocate_guideline(SQLite3DB& configdb,
	std::string_view scope_uuid, const std::set<std::string>& roles,
	const HostgroupAllocationInput& input) {
	if (scope_uuid.empty()) throw std::invalid_argument("hostgroup allocation scope is empty");
	for (const std::string& role : roles) {
		if (role.rfind("rg:", 0) != 0) throw std::invalid_argument("guideline hostgroup role must start with rg:");
	}
	if (!configdb.execute("BEGIN IMMEDIATE")) {
		throw std::runtime_error("cannot begin guideline hostgroup allocation transaction");
	}
	try {
		ManagedHostgroups result;
		// IDs this allocation must never take over: other owners and the baseline roles.
		std::set<int> reserved;
		for (const auto& ownership : input.ownership) {
			if (ownership.second != "mysql_router") reserved.insert(ownership.first);
		}
		auto ledger = query(configdb,
			"SELECT owner,object_key FROM proxysql_plugin_owned_objects WHERE object_type='hostgroup'");
		for (auto* row : ledger->rows) {
			if (row->fields[0] == nullptr) throw std::runtime_error("hostgroup owner is NULL");
			if (std::string_view(row->fields[0]) != "mysql_router") reserved.insert(parse_id(row->fields[1]));
		}
		auto baseline = query(configdb,
			"SELECT hostgroup_id FROM mysql_router_hostgroups WHERE role NOT LIKE 'rg:%' OR scope_uuid<>" +
			quote(scope_uuid));
		for (auto* row : baseline->rows) reserved.insert(parse_id(row->fields[0]));
		// Live inventory may contain the route hostgroups published by the previous
		// generation, so it only restricts new allocations.
		std::set<int> used = input.occupied_hostgroups;
		used.insert(reserved.begin(), reserved.end());
		auto existing = query(configdb, "SELECT role,hostgroup_id FROM mysql_router_hostgroups WHERE scope_uuid=" +
			quote(scope_uuid) + " AND role LIKE 'rg:%' ORDER BY role");
		std::set<int> kept;
		for (auto* row : existing->rows) {
			if (row->fields[0] == nullptr) throw std::runtime_error("hostgroup role is NULL");
			const std::string role(row->fields[0]);
			const int id = parse_id(row->fields[1]);
			if (roles.count(role) && id >= 8000 && id <= 8999 && !reserved.count(id) && kept.insert(id).second) {
				result.by_role.emplace(role, id);
				used.insert(id);
			} else {
				const std::string deletion = "DELETE FROM mysql_router_hostgroups WHERE scope_uuid=" +
					quote(scope_uuid) + " AND role=" + quote(role);
				if (!configdb.execute(deletion.c_str())) {
					throw std::runtime_error("cannot release a stale guideline hostgroup");
				}
			}
		}
		int candidate = 8000;
		for (const std::string& role : roles) {
			if (result.by_role.count(role)) continue;
			while (candidate <= 8999 && used.count(candidate)) ++candidate;
			if (candidate > 8999) {
				throw std::runtime_error("not enough free hostgroups in 8000-8999 for the Routing Guideline routes");
			}
			const std::string insert = "INSERT INTO mysql_router_hostgroups(role,scope_uuid,hostgroup_id) VALUES(" +
				quote(role) + "," + quote(scope_uuid) + "," + std::to_string(candidate) + ")";
			if (!configdb.execute(insert.c_str())) {
				throw std::runtime_error("cannot persist a guideline hostgroup mapping");
			}
			result.by_role.emplace(role, candidate);
			used.insert(candidate++);
		}
		if (!configdb.execute("COMMIT")) throw std::runtime_error("cannot commit guideline hostgroup mapping");
		return result;
	} catch (...) {
		rollback(configdb);
		throw;
	}
}
