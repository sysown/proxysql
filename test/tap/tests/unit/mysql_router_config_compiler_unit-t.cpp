#include "tap.h"

#include "mysql_router_compiler.h"

#include <algorithm>
#include <map>
#include <set>

namespace {

DesiredInstance instance(const char* uuid, const char* host, InstanceKind kind) {
	DesiredInstance value;
	value.server_uuid = uuid;
	value.cluster_uuid = "cluster-1";
	value.label = uuid;
	value.classic = {host, 3306};
	value.kind = kind;
	return value;
}

const CompiledRule* rule(const CompiledMysqlConfig& config, const char* suffix) {
	const std::string comment = std::string("mysql_router:") + suffix;
	auto found = std::find_if(config.rules.begin(), config.rules.end(),
		[&](const auto& row) { return row.comment == comment; });
	return found == config.rules.end() ? nullptr : &*found;
}

size_t server_count(const CompiledMysqlConfig& config, int hostgroup, const char* hostname) {
	return std::count_if(config.servers.begin(), config.servers.end(), [&](const auto& row) {
		return row.hostgroup_id == hostgroup && row.hostname == hostname;
	});
}

} // namespace

int main() {
	plan(19);

	DesiredTopology topology;
	topology.topology_uuid = "cluster-1";
	topology.instances = {
		instance("writer", "db-w", InstanceKind::gr_member),
		instance("reader", "db-r", InstanceKind::gr_member),
		instance("async", "db-a", InstanceKind::read_replica),
		instance("offline-gr", "db-x", InstanceKind::gr_member),
		instance("offline-async", "db-y", InstanceKind::read_replica),
	};
	EffectiveTopology effective;
	effective.writer = "writer";
	effective.readers = {"reader", "async"};
	effective.excluded = {"offline-gr", "offline-async"};
	ManagedHostgroups hostgroups;
	int id = 8100;
	for (const std::string& role : mysql_router_hostgroup_roles()) hostgroups.by_role[role] = id++;

	ConfigCompileInput input;
	input.generation = 1;
	input.listeners = {"0.0.0.0", 6446, 6447, 6450, false, false};
	input.operator_interfaces = {"0.0.0.0:6033", "127.0.0.1:7000"};
	input.occupied_rule_ids = {900000, 900002};
	ManagedMysqlUser imported;
	imported.username = "app";
	imported.password = "$A$005$app";
	imported.default_hostgroup = hostgroups.at("route_writer");
	imported.comment = "mysql_router:cluster-1:app";
	ManagedMysqlUser released = imported;
	released.username = "released";
	released.password = "$A$005$local";
	released.comment = "operator-preserved";
	released.release = true;
	input.users = {imported, released};
	auto compiled = ConfigCompiler::compile_topology(topology, effective, hostgroups, input);

	ok(compiled.owned_hostgroups.size() == 8,
	   "the plan owns exactly the eight persisted Router hostgroups");
	ok(server_count(compiled, hostgroups.at("route_writer"), "db-w") == 1 &&
	   server_count(compiled, hostgroups.at("gr_writer"), "db-w") == 1,
	   "the eligible writer is duplicated into stable and internal writer groups");
	ok(server_count(compiled, hostgroups.at("route_reader"), "db-r") == 1 &&
	   server_count(compiled, hostgroups.at("gr_reader"), "db-r") == 1,
	   "a GR reader is duplicated only into stable and GR reader groups");
	ok(server_count(compiled, hostgroups.at("route_reader"), "db-a") == 1 &&
	   server_count(compiled, hostgroups.at("async_reader"), "db-a") == 1 &&
	   server_count(compiled, hostgroups.at("gr_reader"), "db-a") == 0,
	   "an asynchronous replica never enters a GR mapping");
	ok(server_count(compiled, hostgroups.at("gr_offline"), "db-x") == 1 &&
	   server_count(compiled, hostgroups.at("async_offline"), "db-y") == 1,
	   "excluded GR and asynchronous instances remain in separate offline groups");
	ok(compiled.group_replication.size() == 1 &&
	   compiled.group_replication[0].writer_hostgroup == hostgroups.at("gr_writer") &&
	   compiled.group_replication[0].backup_writer_hostgroup == hostgroups.at("gr_backup_writer") &&
	   compiled.group_replication[0].reader_hostgroup == hostgroups.at("gr_reader") &&
	   compiled.group_replication[0].offline_hostgroup == hostgroups.at("gr_offline"),
	   "only the four internal GR hostgroups form the monitor mapping");

	ok(compiled.interfaces == std::vector<std::string>({"0.0.0.0:6446", "0.0.0.0:6447", "0.0.0.0:6450"}),
	   "the plan adds the three standard Classic interfaces");
	ok(input.operator_interfaces == std::vector<std::string>({"0.0.0.0:6033", "127.0.0.1:7000"}),
	   "unrelated operator interfaces remain outside plugin ownership");
	ok(compiled.rules.size() == 5, "the compiler emits exactly five baseline rules");
	ok(compiled.users.size() == 2 && compiled.users[0].username == "app" &&
	   compiled.users[1].username == "released",
	   "the compiler carries the normalized application-user generation");
	const auto* rw = rule(compiled, "classic-rw");
	const auto* ro = rule(compiled, "classic-ro");
	const auto* locking = rule(compiled, "split-locking");
	const auto* unsafe = rule(compiled, "split-unsafe-read");
	const auto* read = rule(compiled, "split-read");
	ok(rw && rw->proxy_port == 6446 && rw->destination_hostgroup == hostgroups.at("route_writer") && rw->apply,
	   "port 6446 terminates in the stable writer hostgroup");
	ok(ro && ro->proxy_port == 6447 && ro->destination_hostgroup == hostgroups.at("route_reader") && ro->apply,
	   "port 6447 terminates in the stable reader hostgroup");
	ok(locking && unsafe && read && locking->rule_id < unsafe->rule_id && unsafe->rule_id < read->rule_id,
	   "locking and unsafe guards precede the broad split read rule");
	ok(locking && locking->match_digest == "^SELECT.*(?:FOR UPDATE|FOR SHARE|LOCK IN SHARE MODE)(?:\\s|$)" &&
	   locking->re_modifiers == "CASELESS",
	   "the locking guard is anchored and case-insensitive");
	ok(unsafe && unsafe->match_digest.find("INTO") != std::string::npos &&
	   unsafe->match_digest.find(":=") != std::string::npos,
	   "the unsafe-read guard covers SELECT INTO and user-variable assignment");
	ok(read && read->match_digest == "^(?:SELECT|SHOW|DESCRIBE|DESC|EXPLAIN|WITH)(?:\\s|$)" && read->apply,
	   "the final split rule accepts only the conservative read grammar");

	ConfigCompileInput retry = input;
	retry.occupied_rule_ids.clear();
	retry.owned_rule_ids = compiled.rule_ids;
	auto stable = ConfigCompiler::compile_topology(topology, effective, hostgroups, retry);
	ok(stable.rule_ids == compiled.rule_ids,
	   "owned rule IDs remain stable even when lower IDs become free");
	ok(compiled.plan().generation == 1 && compiled.plan().owner == std::string("mysql_router"),
	   "the ABI plan carries the exact owner and topology generation");
	ok(compiled.plan().user_count == 2 &&
	   std::string(compiled.plan().users[0].comment) == "mysql_router:cluster-1:app" &&
	   std::string(compiled.plan().users[1].comment).find("@proxysql:release-user:") == 0,
	   "the ABI plan preserves explicit user ownership-release intent");

	return exit_status();
}
