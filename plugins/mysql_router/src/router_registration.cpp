#include "mysql_router_bootstrap.h"

#include "mysql_router_metadata.h"

#include <charconv>
#include <stdexcept>

namespace {

constexpr const char* kLookup =
	"SELECT router_id,options FROM mysql_innodb_cluster_metadata.v2_routers "
	"WHERE LOWER(address)=LOWER(?) AND router_name=?";
constexpr const char* kInsert =
	"INSERT INTO mysql_innodb_cluster_metadata.v2_routers"
	"(address,router_name,product_name,version,cluster_id,clusterset_id,attributes) "
	"VALUES(?,?,?,?,?,NULL,JSON_OBJECT())";
constexpr const char* kLastInsertId = "SELECT LAST_INSERT_ID() AS router_id";
constexpr const char* kUpdate =
	"UPDATE mysql_innodb_cluster_metadata.v2_routers SET "
	"product_name=?,version=?,cluster_id=?,clusterset_id=NULL,"
	"attributes=JSON_SET(COALESCE(attributes,JSON_OBJECT()),"
	"'$.RWEndpoint',?,'$.ROEndpoint',?,'$.RWSplitEndpoint',?,"
	"'$.bootstrapTargetType',?,'$.MetadataUser',?,'$.ProxySQLVersion',?,"
	"'$.ProxySQLPluginVersion',?,'$.ProxySQLTopologyUUID',?) "
	"WHERE router_id=?";

const std::string& required(const QueryRow& row, const char* column) {
	auto found = row.find(column);
	if (found == row.end() || !found->second || found->second->empty()) {
		throw std::runtime_error(std::string("Router registration column is missing: ") + column);
	}
	return *found->second;
}

int64_t router_id(const QueryRow& row) {
	const std::string& text = required(row, "router_id");
	int64_t value = 0;
	auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
	if (parsed.ec != std::errc() || parsed.ptr != text.data() + text.size() || value <= 0) {
		throw std::runtime_error("Router registration returned an invalid router_id");
	}
	return value;
}

QueryResult lookup(IMetadataSession& session, std::string_view address,
	std::string_view router_name) {
	return session.query(kLookup,
		{std::string(address), std::string(router_name)});
}

} // namespace

RouterRegistration register_or_adopt_router(
	IMetadataSession& session, const DesiredTopology& topology,
	const BootstrapOptions& options, std::string_view address,
	std::string_view metadata_user) {
	if (topology.topology_uuid.empty()) throw std::invalid_argument("topology UUID is empty");
	if (options.router_name.empty()) throw std::invalid_argument("router name is empty");
	if (address.empty()) throw std::invalid_argument("router address is empty");

	QueryResult existing = lookup(session, address, options.router_name);
	if (existing.rows.size() > 1) {
		throw std::runtime_error("multiple Router registrations match address and name");
	}
	int64_t id = 0;
	if (existing.rows.empty()) {
		ExecResult inserted = session.execute(kInsert, {std::string(address), options.router_name,
			std::string("ProxySQL"), std::string("8.4.0"), topology.topology_uuid});
		if (!inserted.ok) {
			existing = lookup(session, address, options.router_name);
			if (existing.rows.size() != 1) {
				throw std::runtime_error("Router registration insert failed: " + inserted.error);
			}
			id = router_id(existing.rows[0]);
		} else {
			QueryResult assigned = session.query(kLastInsertId, {});
			if (assigned.rows.size() != 1) {
				throw std::runtime_error("Router registration did not return an assigned id");
			}
			id = router_id(assigned.rows[0]);
		}
	} else {
		id = router_id(existing.rows[0]);
	}

	RouterRegistration registration;
	registration.router_id = id;
	registration.product_name = "ProxySQL";
	registration.version = "8.4.0";
	registration.attributes = {
		{"RWEndpoint", std::to_string(options.listeners.rw_port)},
		{"ROEndpoint", std::to_string(options.listeners.ro_port)},
		{"RWSplitEndpoint", std::to_string(options.listeners.rw_split_port)},
		{"bootstrapTargetType", "cluster"},
		{"MetadataUser", std::string(metadata_user)},
		{"ProxySQLVersion", GITVERSION},
		{"ProxySQLPluginVersion", "0.1.0"},
		{"ProxySQLTopologyUUID", topology.topology_uuid},
	};
	ExecResult updated = session.execute(kUpdate, {
		registration.product_name, registration.version, topology.topology_uuid,
		registration.attributes["RWEndpoint"].get<std::string>(),
		registration.attributes["ROEndpoint"].get<std::string>(),
		registration.attributes["RWSplitEndpoint"].get<std::string>(),
		registration.attributes["bootstrapTargetType"].get<std::string>(),
		registration.attributes["MetadataUser"].get<std::string>(),
		registration.attributes["ProxySQLVersion"].get<std::string>(),
		registration.attributes["ProxySQLPluginVersion"].get<std::string>(),
		registration.attributes["ProxySQLTopologyUUID"].get<std::string>(), id});
	if (!updated.ok) throw std::runtime_error("Router registration update failed: " + updated.error);
	return registration;
}
