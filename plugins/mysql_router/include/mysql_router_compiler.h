#ifndef PROXYSQL_MYSQL_ROUTER_COMPILER_H
#define PROXYSQL_MYSQL_ROUTER_COMPILER_H

#include "ProxySQL_PluginConfig.h"
#include "mysql_router_bootstrap.h"
#include "mysql_router_types.h"
#include "mysql_router_users.h"

#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

class SQLite3DB;

inline const std::vector<std::string>& mysql_router_hostgroup_roles() {
	static const std::vector<std::string> roles {
		"route_writer", "route_reader", "gr_writer", "gr_backup_writer",
		"gr_reader", "gr_offline", "async_reader", "async_offline",
	};
	return roles;
}

inline const std::vector<std::string>& mysql_router_rule_intents() {
	static const std::vector<std::string> intents {
		"classic-rw", "classic-ro", "split-locking", "split-unsafe-read", "split-read",
	};
	return intents;
}

struct ManagedHostgroups {
	std::map<std::string, int> by_role;
	int at(std::string_view role) const {
		auto found = by_role.find(std::string(role));
		if (found == by_role.end()) throw std::out_of_range("managed hostgroup role is absent");
		return found->second;
	}
};

struct HostgroupAllocationInput {
	std::set<int> occupied_hostgroups;
	std::map<int, std::string> ownership;
};

class HostgroupAllocator {
public:
	static ManagedHostgroups load_or_allocate(SQLite3DB& configdb,
		std::string_view scope_uuid, const HostgroupAllocationInput& input);
};

struct CompiledServer {
	int hostgroup_id {0};
	std::string hostname;
	uint16_t port {0};
	int status {0};
	int weight {1};
	int max_connections {1000};
	bool use_ssl {false};
	std::string comment;
};

struct CompiledGroupReplication {
	int writer_hostgroup {0};
	int backup_writer_hostgroup {0};
	int reader_hostgroup {0};
	int offline_hostgroup {0};
	std::string comment;
};

struct CompiledHostgroupAttributes {
	int hostgroup_id {0};
	std::string comment;
};

struct CompiledRule {
	int rule_id {0};
	int proxy_port {0};
	std::string match_digest;
	std::string re_modifiers {"CASELESS"};
	int destination_hostgroup {0};
	bool apply {true};
	std::string comment;
	std::string attributes;
};

struct ConfigCompileInput {
	uint64_t generation {1};
	ListenerProfile listeners;
	std::vector<std::string> operator_interfaces;
	std::set<int> occupied_rule_ids;
	std::map<std::string, int> owned_rule_ids;
	std::vector<ManagedMysqlUser> users;
};

class CompiledMysqlConfig {
public:
	std::vector<int> owned_hostgroups;
	std::vector<CompiledServer> servers;
	std::vector<CompiledGroupReplication> group_replication;
	std::vector<CompiledHostgroupAttributes> hostgroup_attributes;
	std::vector<CompiledRule> rules;
	std::vector<ManagedMysqlUser> users;
	std::map<std::string, int> rule_ids;
	std::vector<std::string> interfaces;
	uint64_t generation {0};

	const ProxySQL_PluginMysqlConfigPlan& plan() const;
	const ProxySQL_PluginMysqlConfigPlanV2& plan_v2() const;

private:
	mutable std::vector<ProxySQL_PluginMysqlServerRow> server_rows_;
	mutable std::vector<ProxySQL_PluginMysqlGroupReplicationHostgroupRow> gr_rows_;
	mutable std::vector<ProxySQL_PluginMysqlHostgroupAttributesRow> attribute_rows_;
	mutable std::vector<ProxySQL_PluginMysqlRuleRow> rule_rows_;
	mutable std::vector<ProxySQL_PluginMysqlRuleAttributesRow> rule_attribute_rows_;
	mutable std::vector<ProxySQL_PluginMysqlUserRow> user_rows_;
	mutable std::vector<std::string> user_wire_comments_;
	mutable std::vector<const char*> interface_rows_;
	mutable ProxySQL_PluginMysqlConfigPlan plan_ {};
	mutable ProxySQL_PluginMysqlConfigPlanV2 plan_v2_ {};
};

class ConfigCompiler {
public:
	static CompiledMysqlConfig compile_topology(const DesiredTopology& topology,
		const EffectiveTopology& effective, const ManagedHostgroups& hostgroups,
		const ConfigCompileInput& input);
};

#endif
