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
	std::string topology_type {"innodb_cluster"};
	std::string topology_uuid {};
	std::string metadata_version {};
	std::string advertised_contract {"8.4.0"};
	std::string router_label {};
	std::string writer_uuid {};
	std::map<std::string, int> managed_hostgroups;
	uint64_t router_id {0};
	uint64_t topology_generation {0};
	uint64_t user_generation {0};
	uint64_t topology_last_success {0};
	uint64_t user_last_success {0};
	uint64_t metadata_last_success {0};
	uint64_t stale_seconds {0};
	uint64_t user_collisions {0};
	uint64_t unsupported_auth_plugins {0};
	bool metadata_available {false};
	bool registration_exists {false};
	bool gates_ready {false};
	bool unsupported_router_options {false};
};

struct MysqlRouterRuntimeTopologyRow {
	std::string cluster_uuid;
	std::string instance_uuid;
	std::string endpoint;
	std::string instance_kind;
	std::string desired_role;
	std::string observed_state;
	std::string effective_role;
	uint64_t last_observed_at {0};
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
	// A guideline option is set but the metadata cannot provide guidelines (< 2.3).
	bool routing_guideline_unsupported {false};
	// guideline_id selected by router_options (router > clusterset > cluster), if any.
	std::optional<std::string> guideline_id;
};

// Active Routing Guideline document as stored in the metadata (#6145).
struct RoutingGuidelineSource {
	std::string guideline_id;
	std::string name;
	std::string document;
};

// $.router.* values from mysql_innodb_cluster_metadata.v2_routers.
struct RouterMetadataInfo {
	std::string hostname;
	std::string name;
	std::string local_cluster;
	// tag name -> JSON text of the value
	std::map<std::string, std::string> tags;
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
	bool routing_guidelines_capable {false};
	std::optional<RoutingGuidelineSource> guideline;
	RouterMetadataInfo router;
};

struct ObservedMember {
	std::string server_uuid;
	std::string host;
	uint16_t port {0};
	HealthState state {HealthState::unreachable};
	DesiredRole role {DesiredRole::reader};
	std::string version;
};

struct ObservedHealth {
	std::map<std::string, ObservedMember> members;
	std::string session_server_uuid;
	bool single_primary_mode {false};
	bool quorum {false};
	bool read_only {true};
	bool super_read_only {true};
};

struct EffectiveTopology {
	std::optional<std::string> writer;
	std::vector<std::string> readers;
	std::vector<std::string> excluded;
	// server_uuid -> MEMBER_VERSION ("8.4.8") when reported by Group Replication
	std::map<std::string, std::string> versions;
	// Routing Guidelines view, independent of read_only_targets (which has no
	// effect while a guideline is active): usable GR members and read replicas.
	std::vector<std::string> guideline_candidates;
};

#endif
