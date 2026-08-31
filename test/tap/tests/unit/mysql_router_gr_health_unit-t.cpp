#include "tap.h"

#include "mysql_router_metadata.h"

#include <deque>
#include <stdexcept>

namespace {

QueryRow row(std::initializer_list<std::pair<const std::string, SqlCell>> cells) {
	return QueryRow(cells);
}

class GrSession final : public IMetadataSession {
public:
	std::deque<QueryResult> results;
	std::vector<std::string> sql;
	QueryResult query(std::string_view query, const std::vector<SqlValue>& params) override {
		if (!params.empty() || results.empty()) throw std::runtime_error("unexpected GR query");
		sql.emplace_back(query);
		QueryResult result = std::move(results.front());
		results.pop_front();
		return result;
	}
	ExecResult execute(std::string_view, const std::vector<SqlValue>&) override {
		return {true, 0, {}};
	}
	ServerVersion server_version() const override { return {8, 4, 6}; }
};

DesiredTopology desired() {
	DesiredTopology topology;
	topology.metadata_version = {2, 2, 0};
	topology.type = TopologyType::innodb_cluster;
	topology.topology_uuid = "cluster-1";
	topology.topology_name = "prod";
	topology.instances = {
		{"server-1", "cluster-1", "primary", {"db1", 3306}, InstanceKind::gr_member, {}},
		{"server-2", "cluster-1", "secondary", {"db2", 3306}, InstanceKind::gr_member, {}},
		{"server-3", "cluster-1", "recovering", {"db3", 3306}, InstanceKind::gr_member, {}},
		{"server-4", "cluster-1", "read-replica", {"rr1", 3306}, InstanceKind::read_replica, {}}
	};
	topology.options.read_only_targets = ReadOnlyTargets::all;
	return topology;
}

GrSession healthy_session(bool primary_super_read_only = false) {
	GrSession session;
	session.results.push_back({{
		row({{"member_id", "server-1"}, {"member_host", "db1"}, {"member_port", "3306"},
			{"member_state", "ONLINE"}, {"member_role", "PRIMARY"}, {"single_primary", "ON"}}),
		row({{"member_id", "server-2"}, {"member_host", "db2"}, {"member_port", "3306"},
			{"member_state", "ONLINE"}, {"member_role", "SECONDARY"}, {"single_primary", "ON"}}),
		row({{"member_id", "server-3"}, {"member_host", "db3"}, {"member_port", "3306"},
			{"member_state", "RECOVERING"}, {"member_role", "SECONDARY"}, {"single_primary", "ON"}})
	}});
	session.results.push_back({{row({{"read_only", "0"},
		{"super_read_only", primary_super_read_only ? "1" : "0"}})}});
	return session;
}

} // namespace

int main() {
	plan(21);

	auto session = healthy_session();
	auto observed = GrHealthReader::read(session);
	ok(session.results.empty() && session.sql.size() == 2,
	   "GR members and writable globals are queried exactly once");
	ok(session.sql[0].find("replication_group_members") != std::string::npos,
	   "live health reads performance_schema replication_group_members");
	ok(observed.members.size() == 3, "all observed GR members are retained");
	ok(observed.members.at("server-1").state == HealthState::online &&
	   observed.members.at("server-1").role == DesiredRole::writer,
	   "an ONLINE PRIMARY is observed as writer-capable");
	ok(observed.members.at("server-2").state == HealthState::online &&
	   observed.members.at("server-2").role == DesiredRole::reader,
	   "an ONLINE SECONDARY is observed as reader-capable");
	ok(observed.members.at("server-3").state == HealthState::recovering,
	   "a RECOVERING member is retained but not marked online");
	ok(observed.single_primary_mode, "single-primary mode is retained");
	ok(observed.quorum, "two ONLINE members out of three provide quorum");

	auto topology = desired();
	auto effective = evaluate_innodb_cluster(topology, observed);
	ok(effective.writer && *effective.writer == "server-1",
	   "the writable ONLINE PRIMARY is selected as writer");
	ok(effective.readers.size() == 2 && effective.readers[0] == "server-2" &&
	   effective.readers[1] == "server-4",
	   "ONLINE SECONDARY and asynchronous read replica are readers");
	ok(effective.excluded.size() == 1 && effective.excluded[0] == "server-3",
	   "RECOVERING members are excluded from traffic");

	auto super_read_only_session = healthy_session(true);
	auto super_read_only = GrHealthReader::read(super_read_only_session);
	auto no_writer = evaluate_innodb_cluster(topology, super_read_only);
	ok(!no_writer.writer, "super_read_only prevents writer selection");

	auto no_quorum = observed;
	no_quorum.members["server-2"].state = HealthState::unreachable;
	no_quorum.quorum = calculate_gr_quorum(no_quorum.members);
	ok(!no_quorum.quorum, "one ONLINE member out of three has no quorum");
	topology.options.quorum_traffic = QuorumTraffic::none;
	auto blocked = evaluate_innodb_cluster(topology, no_quorum);
	ok(!blocked.writer && blocked.readers.empty(), "quorum loss blocks all traffic by default");
	topology.options.quorum_traffic = QuorumTraffic::read;
	auto read_during_quorum_loss = evaluate_innodb_cluster(topology, no_quorum);
	ok(!read_during_quorum_loss.writer && read_during_quorum_loss.readers.size() == 1 &&
	   read_during_quorum_loss.readers[0] == "server-4",
	   "read policy permits only the asynchronous read replica without quorum");
	topology.options.quorum_traffic = QuorumTraffic::all;
	auto all_during_quorum_loss = evaluate_innodb_cluster(topology, no_quorum);
	ok(all_during_quorum_loss.writer && *all_during_quorum_loss.writer == "server-1",
	   "all policy permits the writable primary without quorum");

	ObservedHealth unreachable;
	unreachable.members["server-1"] = {"server-1", "db1", 3306,
		HealthState::unreachable, DesiredRole::writer};
	unreachable.members["server-2"] = {"server-2", "db2", 3306,
		HealthState::offline, DesiredRole::reader};
	unreachable.members["server-3"] = {"server-3", "db3", 3306,
		HealthState::recovering, DesiredRole::reader};
	unreachable.quorum = calculate_gr_quorum(unreachable.members);
	ok(!unreachable.quorum, "unreachable, offline, and recovering members never count toward quorum");

	auto missing = observed;
	missing.members.erase("server-2");
	auto missing_effective = evaluate_innodb_cluster(desired(), missing);
	ok(missing_effective.excluded.size() == 2,
	   "a metadata GR member absent from observation is excluded");
	ok(missing_effective.readers.size() == 1 && missing_effective.readers[0] == "server-4",
	   "read replicas are never mistaken for missing GR members");

	bool invalid_member_rejected = false;
	try {
		GrSession invalid;
		invalid.results.push_back({{row({{"member_id", "server-1"}, {"member_host", "db1"},
			{"member_port", "3306"}, {"member_state", "BROKEN"},
			{"member_role", "PRIMARY"}, {"single_primary", "1"}})}});
		invalid.results.push_back({{row({{"read_only", "0"}, {"super_read_only", "0"}})}});
		(void)GrHealthReader::read(invalid);
	} catch (const std::exception&) { invalid_member_rejected = true; }
	ok(invalid_member_rejected, "unknown GR member states are rejected");
	ok(topology.instances[3].kind == InstanceKind::read_replica,
	   "asynchronous read-replica identity remains distinct from GR health");

	return exit_status();
}
