#include "tap.h"

#include "mysql_router_compiler.h"
#include "sqlite3db.h"

#include <set>
#include <stdexcept>

namespace {

void create_schema(SQLite3DB& db) {
	db.execute("CREATE TABLE mysql_router_hostgroups (role TEXT NOT NULL,scope_uuid TEXT NOT NULL,"
		"hostgroup_id INTEGER NOT NULL UNIQUE,PRIMARY KEY(role,scope_uuid))");
	db.execute("CREATE TABLE proxysql_plugin_owned_objects (owner TEXT NOT NULL,object_type TEXT NOT NULL,"
		"object_key TEXT NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(owner,object_type,object_key))");
}

long long mapping_count(SQLite3DB& db, const char* scope) {
	char* error = nullptr;
	const std::string sql = std::string("SELECT COUNT(*) FROM mysql_router_hostgroups WHERE scope_uuid='") +
		scope + "'";
	auto* result = db.execute_statement(sql.c_str(), &error);
	long long count = result && !result->rows.empty() ? std::stoll(result->rows[0]->fields[0]) : -1;
	delete result;
	free(error);
	return count;
}

} // namespace

int main() {
	plan(8);

	SQLite3DB db;
	db.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	create_schema(db);
	db.execute("INSERT INTO mysql_router_hostgroups VALUES('route_writer','other-cluster',8000)");
	HostgroupAllocationInput input;
	input.occupied_hostgroups = {8002, 8005, 8123};
	auto first = HostgroupAllocator::load_or_allocate(db, "cluster-1", input);
	ok(first.by_role.size() == 8, "all eight InnoDB Cluster hostgroup roles are allocated");
	ok(first.at("route_writer") == 8001 && first.at("route_reader") == 8003,
	   "allocation deterministically skips occupied hostgroups");
	std::set<int> unique;
	for (const auto& item : first.by_role) unique.insert(item.second);
	ok(unique.size() == 8 && *unique.begin() >= 8000 && *unique.rbegin() <= 8999,
	   "allocated hostgroups are unique and remain inside the managed range");
	ok(mapping_count(db, "cluster-1") == 8, "the complete mapping is persisted atomically");

	HostgroupAllocationInput changed;
	changed.occupied_hostgroups = {8999};
	auto second = HostgroupAllocator::load_or_allocate(db, "cluster-1", changed);
	ok(second.by_role == first.by_role,
	   "a later run reuses the persisted mapping even when lower IDs become free");

	db.execute(("INSERT INTO proxysql_plugin_owned_objects VALUES"
		"('other_plugin','hostgroup','" + std::to_string(first.at("route_writer")) + "',1)").c_str());
	bool collision = false;
	try { (void)HostgroupAllocator::load_or_allocate(db, "cluster-1", changed); }
	catch (const std::exception&) { collision = true; }
	ok(collision, "a persisted mapping owned by another plugin is rejected");

	SQLite3DB exhausted;
	exhausted.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	create_schema(exhausted);
	HostgroupAllocationInput full;
	for (int id = 8000; id <= 8992; ++id) full.occupied_hostgroups.insert(id);
	bool unavailable = false;
	try { (void)HostgroupAllocator::load_or_allocate(exhausted, "cluster-2", full); }
	catch (const std::exception&) { unavailable = true; }
	ok(unavailable, "allocation fails when fewer than eight managed IDs remain");
	ok(mapping_count(exhausted, "cluster-2") == 0, "failed allocation writes no partial mapping");

	return exit_status();
}
