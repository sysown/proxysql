#include "mysql_router_metadata.h"

#include <charconv>
#include <stdexcept>

namespace {

constexpr const char* kMembers =
	"SELECT MEMBER_ID AS member_id, MEMBER_HOST AS member_host, "
	"MEMBER_PORT AS member_port, MEMBER_STATE AS member_state, "
	"MEMBER_ROLE AS member_role, @@global.group_replication_single_primary_mode AS single_primary "
	"FROM performance_schema.replication_group_members "
	"WHERE CHANNEL_NAME='group_replication_applier'";
constexpr const char* kWritableGlobals =
	"SELECT @@server_uuid AS server_uuid, @@global.read_only AS read_only, "
	"@@global.super_read_only AS super_read_only";

const std::string& required(const QueryRow& row, const char* column) {
	auto it = row.find(column);
	if (it == row.end() || !it->second || it->second->empty()) {
		throw std::runtime_error(std::string("GR health column is missing: ") + column);
	}
	return *it->second;
}

uint16_t port_value(const QueryRow& row) {
	const std::string& text = required(row, "member_port");
	unsigned value = 0;
	auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
	if (parsed.ec != std::errc() || parsed.ptr != text.data() + text.size() ||
		value == 0 || value > 65535) throw std::runtime_error("invalid GR member port");
	return static_cast<uint16_t>(value);
}

bool bool_value(const QueryRow& row, const char* column) {
	const std::string& value = required(row, column);
	if (value == "0" || value == "OFF") return false;
	if (value == "1" || value == "ON") return true;
	throw std::runtime_error(std::string("invalid GR boolean: ") + column);
}

} // namespace

bool calculate_gr_quorum(const std::map<std::string, ObservedMember>& members) {
	if (members.empty()) return false;
	size_t online = 0;
	for (const auto& entry : members) {
		if (entry.second.state == HealthState::online ||
			entry.second.state == HealthState::recovering) ++online;
	}
	return online > members.size() / 2;
}

ObservedHealth GrHealthReader::read(IMetadataSession& session) {
	ObservedHealth observed;
	QueryResult members = session.query(kMembers, {});
	for (const QueryRow& row : members.rows) {
		ObservedMember member;
		member.server_uuid = required(row, "member_id");
		member.host = required(row, "member_host");
		member.port = port_value(row);
		const std::string& state = required(row, "member_state");
		if (state == "ONLINE") member.state = HealthState::online;
		else if (state == "RECOVERING") member.state = HealthState::recovering;
		else if (state == "OFFLINE") member.state = HealthState::offline;
		else if (state == "UNREACHABLE") member.state = HealthState::unreachable;
		else if (state == "ERROR") member.state = HealthState::offline;
		else throw std::runtime_error("invalid GR member state");
		const std::string& role = required(row, "member_role");
		if (role == "PRIMARY") member.role = DesiredRole::writer;
		else if (role == "SECONDARY") member.role = DesiredRole::reader;
		else throw std::runtime_error("invalid GR member role");
		bool single_primary = bool_value(row, "single_primary");
		if (!observed.members.empty() && observed.single_primary_mode != single_primary) {
			throw std::runtime_error("inconsistent GR single-primary mode");
		}
		observed.single_primary_mode = single_primary;
		if (!observed.members.emplace(member.server_uuid, member).second) {
			throw std::runtime_error("duplicate GR member UUID");
		}
	}
	QueryResult globals = session.query(kWritableGlobals, {});
	if (globals.rows.size() != 1) throw std::runtime_error("GR writable globals row is missing");
	observed.session_server_uuid = required(globals.rows[0], "server_uuid");
	observed.read_only = bool_value(globals.rows[0], "read_only");
	observed.super_read_only = bool_value(globals.rows[0], "super_read_only");
	observed.quorum = calculate_gr_quorum(observed.members);
	return observed;
}

EffectiveTopology evaluate_innodb_cluster(
	const DesiredTopology& desired, const ObservedHealth& observed) {
	EffectiveTopology effective;
	if (!observed.single_primary_mode) {
		throw std::runtime_error("multi-primary Group Replication is unsupported");
	}
	if (!observed.quorum && desired.options.quorum_traffic == QuorumTraffic::none) return effective;
	for (const DesiredInstance& instance : desired.instances) {
		if (instance.kind == InstanceKind::read_replica) {
			if (desired.options.read_only_targets != ReadOnlyTargets::secondaries) {
				effective.readers.push_back(instance.server_uuid);
			}
			continue;
		}
		auto found = observed.members.find(instance.server_uuid);
		if (found == observed.members.end() || found->second.state != HealthState::online) {
			effective.excluded.push_back(instance.server_uuid);
			continue;
		}
		if (!observed.quorum && desired.options.quorum_traffic == QuorumTraffic::read) continue;
		if (found->second.role == DesiredRole::writer) {
			const bool polled_primary = observed.session_server_uuid == instance.server_uuid;
			if (!polled_primary || (!observed.read_only && !observed.super_read_only)) {
				effective.writer = instance.server_uuid;
			}
		} else {
			if (desired.options.read_only_targets != ReadOnlyTargets::read_replicas) {
				effective.readers.push_back(instance.server_uuid);
			}
		}
	}
	return effective;
}
