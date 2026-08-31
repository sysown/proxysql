#ifndef PROXYSQL_MYSQL_ROUTER_TYPES_H
#define PROXYSQL_MYSQL_ROUTER_TYPES_H

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

struct MysqlRouterStatus {
	std::string state {"loaded"};
	std::string last_error {};
	uint64_t topology_generation {0};
	uint64_t user_generation {0};
};

struct MetadataVersion {
	int major {0};
	int minor {0};
	int patch {0};

	bool operator==(const MetadataVersion& rhs) const {
		return major == rhs.major && minor == rhs.minor && patch == rhs.patch;
	}
};

enum class TopologyType { innodb_cluster };
enum class InstanceKind { gr_member, read_replica };
enum class DesiredRole { writer, reader };
enum class HealthState { online, recovering, offline, unreachable };
enum class ReadOnlyTargets { secondaries, read_replicas, all };
enum class QuorumTraffic { none, read, all };

struct MysqlEndpoint {
	std::string host;
	uint16_t port {0};
};

struct RouterOptions {
	ReadOnlyTargets read_only_targets {ReadOnlyTargets::secondaries};
	QuorumTraffic quorum_traffic {QuorumTraffic::none};
	std::optional<uint64_t> stats_updates_frequency;
};

struct DesiredInstance {
	std::string server_uuid;
	std::string cluster_uuid;
	std::string label;
	MysqlEndpoint classic;
	InstanceKind kind {InstanceKind::gr_member};
	std::string attributes;
};

struct DesiredTopology {
	MetadataVersion metadata_version;
	TopologyType type {TopologyType::innodb_cluster};
	std::string topology_uuid;
	std::string topology_name;
	std::string group_name;
	std::vector<DesiredInstance> instances;
	RouterOptions options;
};

struct ObservedMember {
	std::string server_uuid;
	std::string host;
	uint16_t port {0};
	HealthState state {HealthState::unreachable};
	DesiredRole role {DesiredRole::reader};
};

struct ObservedHealth {
	std::map<std::string, ObservedMember> members;
	bool single_primary_mode {false};
	bool quorum {false};
	bool read_only {true};
	bool super_read_only {true};
};

struct EffectiveTopology {
	std::optional<std::string> writer;
	std::vector<std::string> readers;
	std::vector<std::string> excluded;
};

#endif
