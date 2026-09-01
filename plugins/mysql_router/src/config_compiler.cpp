#include "mysql_router_compiler.h"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {

struct RuleIntent {
	const char* name;
	int port;
	const char* digest;
	const char* destination_role;
	const char* attributes;
};

const std::array<RuleIntent, 5> kRuleIntents {{
	{"classic-rw", 6446, "^", "route_writer", "{\"switch_to_fast_forward\":true}"},
	{"classic-ro", 6447, "^", "route_reader", "{\"switch_to_fast_forward\":true}"},
	{"split-locking", 6450, "^SELECT.*(?:FOR UPDATE|FOR SHARE|LOCK IN SHARE MODE)(?:\\s|$)", "route_writer", ""},
	{"split-unsafe-read", 6450, "^SELECT.*(?:\\sINTO(?:\\s|$)|@[A-Za-z0-9_]+\\s*:=)", "route_writer", ""},
	{"split-read", 6450, "^(?:SELECT|SHOW|DESCRIBE|DESC|EXPLAIN|WITH)(?:\\s|$)", "route_reader", ""},
}};

std::string managed_comment(const DesiredTopology& topology, uint64_t generation,
	std::string_view role) {
	return "mysql_router:topology=" + topology.topology_uuid + ";role=" +
		std::string(role) + ";generation=" + std::to_string(generation);
}

const DesiredInstance& find_instance(const DesiredTopology& topology, std::string_view uuid) {
	auto found = std::find_if(topology.instances.begin(), topology.instances.end(),
		[&](const DesiredInstance& item) { return item.server_uuid == uuid; });
	if (found == topology.instances.end()) {
		throw std::runtime_error("effective topology references an unknown instance");
	}
	return *found;
}

void add_server(CompiledMysqlConfig& config, const DesiredTopology& topology,
	uint64_t generation, int hostgroup, std::string_view role,
	const DesiredInstance& instance) {
	CompiledServer row;
	row.hostgroup_id = hostgroup;
	row.hostname = instance.classic.host;
	row.port = instance.classic.port;
	row.comment = managed_comment(topology, generation, role);
	config.servers.push_back(std::move(row));
}

std::map<std::string, int> allocate_rule_ids(const ConfigCompileInput& input) {
	std::map<std::string, int> result;
	std::set<int> assigned;
	int previous = 0;
	for (const auto& intent : kRuleIntents) {
		auto found = input.owned_rule_ids.find(intent.name);
		if (found == input.owned_rule_ids.end()) continue;
		if (found->second <= previous || !assigned.insert(found->second).second) {
			throw std::runtime_error("persisted baseline rule ordering is invalid");
		}
		result.emplace(intent.name, found->second);
		previous = found->second;
	}
	if (!result.empty() && result.size() != kRuleIntents.size()) {
		throw std::runtime_error("persisted baseline rule mapping is incomplete");
	}
	if (!result.empty()) return result;

	int candidate = 900000;
	for (const auto& intent : kRuleIntents) {
		while (candidate <= 900999 && input.occupied_rule_ids.count(candidate)) ++candidate;
		if (candidate > 900999) throw std::runtime_error("no baseline query rule IDs are available");
		result.emplace(intent.name, candidate++);
	}
	return result;
}

} // namespace

CompiledMysqlConfig ConfigCompiler::compile_topology(const DesiredTopology& topology,
	const EffectiveTopology& effective, const ManagedHostgroups& hostgroups,
	const ConfigCompileInput& input) {
	if (topology.topology_uuid.empty()) throw std::invalid_argument("topology UUID is empty");
	if (input.generation == 0) throw std::invalid_argument("configuration generation is zero");
	CompiledMysqlConfig config;
	config.generation = input.generation;
	config.users = input.users;
	for (const std::string& role : mysql_router_hostgroup_roles()) {
		config.owned_hostgroups.push_back(hostgroups.at(role));
		config.hostgroup_attributes.push_back({hostgroups.at(role),
			managed_comment(topology, input.generation, role)});
	}

	if (effective.writer) {
		const auto& writer = find_instance(topology, *effective.writer);
		if (writer.kind != InstanceKind::gr_member) {
			throw std::runtime_error("InnoDB Cluster writer is not a GR member");
		}
		add_server(config, topology, input.generation, hostgroups.at("route_writer"), "route_writer", writer);
		add_server(config, topology, input.generation, hostgroups.at("gr_writer"), "gr_writer", writer);
	}
	for (const std::string& uuid : effective.readers) {
		const auto& reader = find_instance(topology, uuid);
		add_server(config, topology, input.generation, hostgroups.at("route_reader"), "route_reader", reader);
		const char* role = reader.kind == InstanceKind::gr_member ? "gr_reader" : "async_reader";
		add_server(config, topology, input.generation, hostgroups.at(role), role, reader);
	}
	for (const std::string& uuid : effective.excluded) {
		const auto& excluded = find_instance(topology, uuid);
		const char* role = excluded.kind == InstanceKind::gr_member ? "gr_offline" : "async_offline";
		add_server(config, topology, input.generation, hostgroups.at(role), role, excluded);
	}
	config.group_replication.push_back({hostgroups.at("gr_writer"),
		hostgroups.at("gr_backup_writer"), hostgroups.at("gr_reader"),
		hostgroups.at("gr_offline"), managed_comment(topology, input.generation, "gr_mapping")});

	if (!input.listeners.skip_tcp) {
		config.interfaces = {
			input.listeners.bind_address + ":" + std::to_string(input.listeners.rw_port),
			input.listeners.bind_address + ":" + std::to_string(input.listeners.ro_port),
			input.listeners.bind_address + ":" + std::to_string(input.listeners.rw_split_port),
		};
	}
	config.rule_ids = allocate_rule_ids(input);
	for (const auto& intent : kRuleIntents) {
		CompiledRule row;
		row.rule_id = config.rule_ids.at(intent.name);
		row.proxy_port = intent.port == 6446 ? input.listeners.rw_port :
			intent.port == 6447 ? input.listeners.ro_port : input.listeners.rw_split_port;
		row.match_digest = intent.digest;
		row.destination_hostgroup = hostgroups.at(intent.destination_role);
		row.comment = std::string("mysql_router:") + intent.name;
		row.attributes = intent.attributes;
		config.rules.push_back(std::move(row));
	}
	return config;
}

const ProxySQL_PluginMysqlConfigPlan& CompiledMysqlConfig::plan() const {
	server_rows_.clear();
	for (const auto& row : servers) {
		server_rows_.push_back({row.hostgroup_id, row.hostname.c_str(), row.port, 0,
			row.status, row.weight, 0, row.max_connections, 0, row.use_ssl, 0, row.comment.c_str()});
	}
	gr_rows_.clear();
	for (const auto& row : group_replication) {
		gr_rows_.push_back({row.writer_hostgroup, row.backup_writer_hostgroup,
			row.reader_hostgroup, row.offline_hostgroup, true, 1, 0, 0, row.comment.c_str()});
	}
	attribute_rows_.clear();
	for (const auto& row : hostgroup_attributes) {
		attribute_rows_.push_back({row.hostgroup_id, 1000, -1, 10, "", true, false,
			1000, "{}", "{}", "{}", row.comment.c_str()});
	}
	rule_rows_.clear();
	for (const auto& row : rules) {
		rule_rows_.push_back({row.rule_id, true, row.proxy_port, row.match_digest.c_str(),
			nullptr, false, row.re_modifiers.c_str(), row.destination_hostgroup,
			row.apply, row.comment.c_str()});
	}
	user_rows_.clear();
	user_wire_comments_.clear();
	user_wire_comments_.reserve(users.size());
	for (const auto& row : users) {
		user_wire_comments_.push_back(row.release
			? proxysql_plugin_release_user_comment(row.comment) : row.comment);
	}
	for (size_t i = 0; i < users.size(); ++i) {
		const auto& row = users[i];
		user_rows_.push_back({row.username.c_str(), row.password.c_str(), row.active,
			row.use_ssl, row.default_hostgroup, row.default_schema.c_str(), row.schema_locked,
			row.transaction_persistent, row.fast_forward, row.frontend, row.backend,
			row.max_connections, row.attributes.c_str(), user_wire_comments_[i].c_str()});
	}
	interface_rows_.clear();
	for (const std::string& value : interfaces) interface_rows_.push_back(value.c_str());
	plan_ = {"mysql_router", generation,
		owned_hostgroups.data(), owned_hostgroups.size(),
		server_rows_.data(), server_rows_.size(), nullptr, 0,
		gr_rows_.data(), gr_rows_.size(), attribute_rows_.data(), attribute_rows_.size(),
		user_rows_.data(), user_rows_.size(), rule_rows_.data(), rule_rows_.size(),
		interface_rows_.data(), interface_rows_.size()};
	return plan_;
}

const ProxySQL_PluginMysqlConfigPlanV2& CompiledMysqlConfig::plan_v2() const {
	const ProxySQL_PluginMysqlConfigPlan& base = plan();
	rule_attribute_rows_.clear();
	for (const auto& row : rules) {
		if (!row.attributes.empty()) {
			rule_attribute_rows_.push_back({row.rule_id, row.attributes.c_str()});
		}
	}
	plan_v2_ = {base, rule_attribute_rows_.data(), rule_attribute_rows_.size()};
	return plan_v2_;
}
