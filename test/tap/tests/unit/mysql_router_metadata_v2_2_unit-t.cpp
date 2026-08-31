#include "tap.h"

#include "mysql_router_metadata.h"

#include <deque>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

QueryRow row(std::initializer_list<std::pair<const std::string, SqlCell>> cells) {
	return QueryRow(cells);
}

struct ExpectedQuery {
	std::string sql;
	std::vector<SqlValue> params;
	QueryResult result;
};

class ScriptedMetadataSession final : public IMetadataSession {
public:
	std::deque<ExpectedQuery> expected;

	QueryResult query(std::string_view sql, const std::vector<SqlValue>& params) override {
		if (expected.empty()) throw std::runtime_error("unexpected metadata query");
		ExpectedQuery next = std::move(expected.front());
		expected.pop_front();
		if (next.sql != sql) throw std::runtime_error("metadata SQL mismatch");
		if (next.params != params) throw std::runtime_error("metadata parameter mismatch");
		return std::move(next.result);
	}

	ExecResult execute(std::string_view, const std::vector<SqlValue>&) override {
		return {true, 0, {}};
	}

	ServerVersion server_version() const override { return {8, 4, 6}; }
};

const char* kSchemaVersion =
	"SELECT major, minor, patch FROM mysql_innodb_cluster_metadata.schema_version";
const char* kCapabilityColumns =
	"SELECT SUM(TABLE_NAME='v2_this_instance' AND COLUMN_NAME='cluster_id') AS this_instance_cluster_id, "
	"SUM(TABLE_NAME='v2_gr_clusters' AND COLUMN_NAME='group_name') AS gr_clusters_group_name, "
	"SUM(TABLE_NAME='v2_instances' AND COLUMN_NAME='mysql_server_uuid') AS instances_server_uuid, "
	"SUM(TABLE_NAME='v2_instances' AND COLUMN_NAME='endpoint') AS instances_endpoint, "
	"SUM(TABLE_NAME='v2_router_options' AND COLUMN_NAME='router_options') AS router_options "
	"FROM information_schema.columns WHERE TABLE_SCHEMA='mysql_innodb_cluster_metadata'";
const char* kThisInstance =
	"SELECT cluster_id, instance_id, instance_type, cluster_name, cluster_type "
	"FROM mysql_innodb_cluster_metadata.v2_this_instance";
const char* kInstances =
	"SELECT c.cluster_id, c.cluster_name, c.group_name, i.instance_id, "
	"i.mysql_server_uuid, i.label, i.endpoint, i.attributes, i.instance_type "
	"FROM mysql_innodb_cluster_metadata.v2_gr_clusters AS c "
	"JOIN mysql_innodb_cluster_metadata.v2_instances AS i ON i.cluster_id=c.cluster_id "
	"WHERE c.cluster_id=?";
const char* kRouterOptions =
	"SELECT router_options FROM mysql_innodb_cluster_metadata.v2_router_options "
	"WHERE router_id=?";

ScriptedMetadataSession valid_session() {
	ScriptedMetadataSession session;
	session.expected.push_back({kSchemaVersion, {}, {{row({
		{"major", "2"}, {"minor", "2"}, {"patch", "0"}})}}});
	session.expected.push_back({kCapabilityColumns, {}, {{row({
		{"this_instance_cluster_id", "1"}, {"gr_clusters_group_name", "1"},
		{"instances_server_uuid", "1"}, {"instances_endpoint", "1"},
		{"router_options", "1"}})}}});
	session.expected.push_back({kThisInstance, {}, {{row({
		{"cluster_id", "cluster-1"}, {"instance_id", "instance-1"},
		{"instance_type", "group-member"}, {"cluster_name", "prod"},
		{"cluster_type", "gr"}})}}});
	session.expected.push_back({kInstances, {std::string("cluster-1")}, {{
		row({{"cluster_id", "cluster-1"}, {"cluster_name", "prod"},
			{"group_name", "group-uuid"}, {"instance_id", "instance-1"},
			{"mysql_server_uuid", "server-1"}, {"label", "db1"},
			{"endpoint", "db1.example:3306"}, {"attributes", "{}"},
			{"instance_type", "group-member"}}),
		row({{"cluster_id", "cluster-1"}, {"cluster_name", "prod"},
			{"group_name", "group-uuid"}, {"instance_id", "instance-2"},
			{"mysql_server_uuid", "server-2"}, {"label", "rr1"},
			{"endpoint", "[2001:db8::20]:3307"},
			{"attributes", "{\"tags\":{\"hidden\":false}}"},
			{"instance_type", "read-replica"}})
	}}});
	session.expected.push_back({kRouterOptions, {int64_t(42)}, {{row({
		{"router_options", "{\"read_only_targets\":\"all\","
			"\"unreachable_quorum_allowed_traffic\":\"read\","
			"\"stats_updates_frequency\":5,\"guideline\":\"rg-main\"}"}})}}});
	return session;
}

bool read_throws(ScriptedMetadataSession session, const char* needle) {
	try {
		(void)MetadataV2_2::read_innodb_cluster(session, "cluster-1", 42);
	} catch (const std::exception& error) {
		return std::string(error.what()).find(needle) != std::string::npos;
	}
	return false;
}

} // namespace

int main() {
	plan(27);

	ScriptedMetadataSession probe;
	probe.expected.push_back({kSchemaVersion, {}, {{row({
		{"major", "2"}, {"minor", "2"}, {"patch", "3"}})}}});
	probe.expected.push_back({kCapabilityColumns, {}, {{row({
		{"this_instance_cluster_id", "1"}, {"gr_clusters_group_name", "1"},
		{"instances_server_uuid", "1"}, {"instances_endpoint", "1"},
		{"router_options", "1"}})}}});
	auto capabilities = probe_metadata(probe);
	ok(capabilities.version == MetadataVersion{2, 2, 3}, "metadata 2.2 is accepted exactly");
	ok(capabilities.router_options_view && !capabilities.router_stats &&
	   !capabilities.routing_guidelines, "2.2 capability flags are explicit");
	ok(probe.expected.empty(), "the version probe is consumed exactly once");

	auto session = valid_session();
	auto topology = MetadataV2_2::read_innodb_cluster(session, "cluster-1", 42);
	ok(session.expected.empty(), "every scripted metadata query is consumed exactly once");
	ok(topology.metadata_version == MetadataVersion{2, 2, 0}, "the topology retains metadata version 2.2.0");
	ok(topology.type == TopologyType::innodb_cluster, "the topology is an InnoDB Cluster");
	ok(topology.topology_uuid == "cluster-1" && topology.topology_name == "prod",
	   "cluster identity and name are retained");
	ok(topology.instances.size() == 2, "group members and read replicas are retained");
	ok(topology.instances[0].kind == InstanceKind::gr_member &&
	   topology.instances[0].classic.host == "db1.example" &&
	   topology.instances[0].classic.port == 3306,
	   "a group-member endpoint is parsed");
	ok(topology.instances[1].kind == InstanceKind::read_replica &&
	   topology.instances[1].classic.host == "2001:db8::20" &&
	   topology.instances[1].classic.port == 3307,
	   "a bracketed IPv6 read-replica endpoint is parsed");
	ok(topology.options.read_only_targets == ReadOnlyTargets::all,
	   "read_only_targets=all is parsed");
	ok(topology.options.quorum_traffic == QuorumTraffic::read,
	   "unreachable quorum read traffic is parsed");
	ok(topology.options.stats_updates_frequency &&
	   *topology.options.stats_updates_frequency == 5,
	   "a nonnegative stats update frequency is retained");
	ok(topology.options.routing_guideline_unsupported,
	   "a non-null Routing Guideline is retained as an explicitly unsupported option");

	ScriptedMetadataSession old;
	old.expected.push_back({kSchemaVersion, {}, {{row({
		{"major", "1"}, {"minor", "0"}, {"patch", "2"}})}}});
	bool old_rejected = false;
	try { (void)probe_metadata(old); } catch (const std::exception& e) {
		old_rejected = std::string(e.what()).find("2.2") != std::string::npos;
	}
	ok(old_rejected, "metadata 1.x is rejected");
	ScriptedMetadataSession future;
	future.expected.push_back({kSchemaVersion, {}, {{row({
		{"major", "2"}, {"minor", "3"}, {"patch", "0"}})}}});
	bool future_rejected = false;
	try { (void)probe_metadata(future); } catch (const std::exception& e) {
		future_rejected = std::string(e.what()).find("2.2") != std::string::npos;
	}
	ok(future_rejected, "metadata 2.3 is rejected until its adapter exists");

	auto missing_endpoint = valid_session();
	missing_endpoint.expected[3].result.rows[0]["endpoint"] = std::nullopt;
	ok(read_throws(std::move(missing_endpoint), "endpoint"), "a missing endpoint is rejected");
	auto duplicate_uuid = valid_session();
	duplicate_uuid.expected[3].result.rows[1]["mysql_server_uuid"] = "server-1";
	ok(read_throws(std::move(duplicate_uuid), "duplicate"), "duplicate server UUIDs are rejected");
	auto duplicate_endpoint = valid_session();
	duplicate_endpoint.expected[3].result.rows[1]["endpoint"] = "db1.example:3306";
	ok(read_throws(std::move(duplicate_endpoint), "duplicate"), "duplicate endpoints are rejected");
	auto wrong_cluster = valid_session();
	wrong_cluster.expected[3].result.rows[1]["cluster_id"] = "cluster-2";
	ok(read_throws(std::move(wrong_cluster), "cluster"), "cross-cluster instance rows are rejected");
	auto invalid_port = valid_session();
	invalid_port.expected[3].result.rows[0]["endpoint"] = "db1.example:70000";
	ok(read_throws(std::move(invalid_port), "port"), "invalid instance ports are rejected");
	auto invalid_type = valid_session();
	invalid_type.expected[3].result.rows[0]["instance_type"] = "async-member";
	ok(read_throws(std::move(invalid_type), "instance_type"), "unknown instance types are rejected");
	auto invalid_options = valid_session();
	invalid_options.expected[4].result.rows[0]["router_options"] =
		"{\"read_only_targets\":\"followers\"}";
	ok(read_throws(std::move(invalid_options), "read_only_targets"),
	   "unknown read_only_targets fail closed");
	auto invalid_quorum = valid_session();
	invalid_quorum.expected[4].result.rows[0]["router_options"] =
		"{\"unreachable_quorum_allowed_traffic\":\"write\"}";
	ok(read_throws(std::move(invalid_quorum), "quorum"), "unknown quorum traffic fails closed");
	auto invalid_frequency = valid_session();
	invalid_frequency.expected[4].result.rows[0]["router_options"] =
		"{\"stats_updates_frequency\":-1}";
	ok(read_throws(std::move(invalid_frequency), "frequency"),
	   "negative stats update frequency is rejected");
	auto missing_capability = valid_session();
	missing_capability.expected[1].result.rows[0]["instances_endpoint"] = "0";
	ok(read_throws(std::move(missing_capability), "required metadata"),
	   "missing metadata 2.2 columns fail closed");
	auto read_replicas = valid_session();
	read_replicas.expected[4].result.rows[0]["router_options"] =
		"{\"read_only_targets\":\"read_replicas\"}";
	auto read_replica_topology = MetadataV2_2::read_innodb_cluster(read_replicas, "cluster-1", 42);
	ok(read_replica_topology.options.read_only_targets == ReadOnlyTargets::read_replicas,
	   "read_only_targets=read_replicas is parsed distinctly");

	return exit_status();
}
