#include "mysql_router_metadata.h"

#include <json.hpp>

#include <charconv>
#include <set>
#include <stdexcept>

namespace {

constexpr const char* kThisInstance =
	"SELECT cluster_id, instance_id, instance_type, cluster_name, cluster_type "
	"FROM mysql_innodb_cluster_metadata.v2_this_instance";
constexpr const char* kInstances =
	"SELECT c.cluster_id, c.cluster_name, c.group_name, i.instance_id, "
	"i.mysql_server_uuid, i.label, i.endpoint, i.attributes, i.instance_type "
	"FROM mysql_innodb_cluster_metadata.v2_gr_clusters AS c "
	"JOIN mysql_innodb_cluster_metadata.v2_instances AS i ON i.cluster_id=c.cluster_id "
	"WHERE c.cluster_id=?";
constexpr const char* kRouterOptions =
	"SELECT router_options FROM mysql_innodb_cluster_metadata.v2_router_options "
	"WHERE router_id=?";

const std::string& required(const QueryRow& row, const char* column) {
	auto it = row.find(column);
	if (it == row.end() || !it->second || it->second->empty()) {
		throw std::runtime_error(std::string("metadata column is missing: ") + column);
	}
	return *it->second;
}

uint16_t port_value(std::string_view text) {
	unsigned value = 0;
	auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
	if (parsed.ec != std::errc() || parsed.ptr != text.data() + text.size() ||
		value == 0 || value > 65535) {
		throw std::runtime_error("invalid metadata endpoint port");
	}
	return static_cast<uint16_t>(value);
}

MysqlEndpoint parse_endpoint(const std::string& endpoint) {
	MysqlEndpoint result;
	std::string_view port;
	if (!endpoint.empty() && endpoint.front() == '[') {
		auto close = endpoint.find(']');
		if (close == std::string::npos || close + 1 >= endpoint.size() || endpoint[close + 1] != ':') {
			throw std::runtime_error("invalid bracketed metadata endpoint");
		}
		result.host = endpoint.substr(1, close - 1);
		port = std::string_view(endpoint).substr(close + 2);
	} else {
		auto colon = endpoint.rfind(':');
		if (colon == std::string::npos || endpoint.find(':') != colon) {
			throw std::runtime_error("invalid metadata endpoint");
		}
		result.host = endpoint.substr(0, colon);
		port = std::string_view(endpoint).substr(colon + 1);
	}
	if (result.host.empty()) throw std::runtime_error("metadata endpoint host is missing");
	result.port = port_value(port);
	return result;
}

RouterOptions parse_options(const std::string& value) {
	RouterOptions options;
	nlohmann::json json;
	try { json = nlohmann::json::parse(value); }
	catch (const std::exception&) { throw std::runtime_error("invalid router_options JSON"); }
	if (!json.is_object()) throw std::runtime_error("router_options must be an object");
	if (json.contains("read_only_targets")) {
		if (!json["read_only_targets"].is_string()) {
			throw std::runtime_error("invalid read_only_targets");
		}
		auto mode = json["read_only_targets"].get<std::string>();
		if (mode == "all") options.read_only_targets = ReadOnlyTargets::all;
		else if (mode == "secondaries") options.read_only_targets = ReadOnlyTargets::secondaries;
		else if (mode == "read_replicas") options.read_only_targets = ReadOnlyTargets::read_replicas;
		else throw std::runtime_error("invalid read_only_targets");
	}
	if (json.contains("unreachable_quorum_allowed_traffic")) {
		if (!json["unreachable_quorum_allowed_traffic"].is_string()) {
			throw std::runtime_error("invalid quorum traffic policy");
		}
		auto mode = json["unreachable_quorum_allowed_traffic"].get<std::string>();
		if (mode == "none") options.quorum_traffic = QuorumTraffic::none;
		else if (mode == "read") options.quorum_traffic = QuorumTraffic::read;
		else if (mode == "all") options.quorum_traffic = QuorumTraffic::all;
		else throw std::runtime_error("invalid quorum traffic policy");
	}
	if (json.contains("stats_updates_frequency")) {
		if (!json["stats_updates_frequency"].is_number_integer()) {
			throw std::runtime_error("invalid stats update frequency");
		}
		auto frequency = json["stats_updates_frequency"].get<int64_t>();
		if (frequency < 0) throw std::runtime_error("invalid stats update frequency");
		options.stats_updates_frequency = static_cast<uint64_t>(frequency);
	}
	return options;
}

} // namespace

DesiredTopology MetadataV2_2::read_innodb_cluster(
	IMetadataSession& session, std::string_view cluster_uuid, int64_t router_id) {
	DesiredTopology topology;
	topology.metadata_version = probe_metadata(session).version;
	QueryResult current = session.query(kThisInstance, {});
	if (current.rows.size() != 1) throw std::runtime_error("metadata this_instance row is missing");
	const QueryRow& this_instance = current.rows[0];
	if (required(this_instance, "cluster_id") != cluster_uuid) {
		throw std::runtime_error("requested cluster does not match this metadata instance");
	}
	if (required(this_instance, "cluster_type") != "gr") {
		throw std::runtime_error("metadata cluster type is not Group Replication");
	}
	topology.type = TopologyType::innodb_cluster;
	topology.topology_uuid = std::string(cluster_uuid);
	topology.topology_name = required(this_instance, "cluster_name");

	QueryResult instances = session.query(kInstances, {std::string(cluster_uuid)});
	if (instances.rows.empty()) throw std::runtime_error("metadata cluster has no instances");
	std::set<std::string> uuids;
	std::set<std::string> endpoints;
	for (const QueryRow& row : instances.rows) {
		if (required(row, "cluster_id") != cluster_uuid) {
			throw std::runtime_error("cross-cluster metadata instance row");
		}
		DesiredInstance instance;
		instance.cluster_uuid = std::string(cluster_uuid);
		instance.server_uuid = required(row, "mysql_server_uuid");
		instance.label = required(row, "label");
		const std::string& endpoint = required(row, "endpoint");
		instance.classic = parse_endpoint(endpoint);
		const std::string& type = required(row, "instance_type");
		if (type == "group-member") instance.kind = InstanceKind::gr_member;
		else if (type == "read-replica") instance.kind = InstanceKind::read_replica;
		else throw std::runtime_error("invalid instance_type in metadata");
		instance.attributes = required(row, "attributes");
		try {
			if (!nlohmann::json::parse(instance.attributes).is_object()) {
				throw std::runtime_error("attributes must be an object");
			}
		} catch (const nlohmann::json::exception&) {
			throw std::runtime_error("invalid instance attributes JSON");
		}
		if (!uuids.insert(instance.server_uuid).second || !endpoints.insert(endpoint).second) {
			throw std::runtime_error("duplicate metadata instance UUID or endpoint");
		}
		if (topology.group_name.empty()) topology.group_name = required(row, "group_name");
		else if (topology.group_name != required(row, "group_name")) {
			throw std::runtime_error("inconsistent metadata group name");
		}
		topology.instances.push_back(std::move(instance));
	}

	QueryResult options = session.query(kRouterOptions, {router_id});
	if (options.rows.size() > 1) throw std::runtime_error("duplicate router_options rows");
	if (!options.rows.empty()) topology.options = parse_options(required(options.rows[0], "router_options"));
	return topology;
}
