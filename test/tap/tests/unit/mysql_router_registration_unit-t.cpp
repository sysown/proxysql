#include "tap.h"

#include "mysql_router_bootstrap.h"
#include "mysql_router_metadata.h"

#include <deque>
#include <stdexcept>

namespace {

class RegistrationSession final : public IMetadataSession {
public:
	std::deque<QueryResult> results;
	std::vector<std::string> queries;
	std::vector<std::vector<SqlValue>> query_params;
	std::vector<std::string> executions;
	std::vector<std::vector<SqlValue>> execute_params;
	uint64_t affected_rows {1};

	QueryResult query(std::string_view sql, const std::vector<SqlValue>& params) override {
		if (results.empty()) throw std::runtime_error("unexpected registration query");
		queries.emplace_back(sql);
		query_params.push_back(params);
		QueryResult result = std::move(results.front());
		results.pop_front();
		return result;
	}
	ExecResult execute(std::string_view sql, const std::vector<SqlValue>& params) override {
		executions.emplace_back(sql);
		execute_params.push_back(params);
		return {true, affected_rows, {}};
	}
	ServerVersion server_version() const override { return {8, 4, 6}; }
	std::string quote_sql_string(std::string_view value) const override {
		return "'" + std::string(value) + "'";
	}
};

QueryRow row(std::initializer_list<std::pair<const std::string, SqlCell>> cells) {
	return QueryRow(cells);
}

DesiredTopology topology() {
	DesiredTopology value;
	value.metadata_version = {2, 2, 0};
	value.topology_uuid = "cluster-1";
	value.topology_name = "production";
	return value;
}

BootstrapOptions options() {
	BootstrapOptions value;
	value.router_name = "proxysql-east";
	value.listeners.rw_port = 6446;
	value.listeners.ro_port = 6447;
	value.listeners.rw_split_port = 6450;
	return value;
}

} // namespace

int main() {
	plan(18);

	RegistrationSession created;
	created.results.push_back(QueryResult {});
	created.results.push_back({{row({{"router_id", "17"}})}});
	auto registration = register_or_adopt_router(
		created, topology(), options(), "proxy.example", "router_account");
	ok(registration.router_id == 17, "a newly inserted Router registration returns its assigned id");
	ok(registration.product_name == "ProxySQL" && registration.version == "8.4.0",
	   "Shell-visible product and feature-gate version are exact");
	ok(registration.attributes["RWEndpoint"] == "6446" &&
	   registration.attributes["ROEndpoint"] == "6447" &&
	   registration.attributes["RWSplitEndpoint"] == "6450",
	   "all implemented Classic endpoints are advertised");
	ok(!registration.attributes.contains("RWXEndpoint") &&
	   !registration.attributes.contains("ROXEndpoint"),
	   "unimplemented X endpoints are not advertised");
	ok(!registration.attributes.contains("SupportedRoutingGuidelinesVersion"),
	   "Routing Guidelines capability is not advertised");
	ok(registration.attributes["bootstrapTargetType"] == "cluster" &&
	   registration.attributes["MetadataUser"] == "router_account",
	   "bootstrap target type and metadata account are Shell-visible");
	ok(registration.attributes["ProxySQLTopologyUUID"] == "cluster-1" &&
	   registration.attributes.contains("ProxySQLVersion") &&
	   registration.attributes.contains("ProxySQLPluginVersion"),
	   "ProxySQL identity attributes are recorded");
	ok(created.executions.size() == 2 &&
	   created.executions[0].find("INSERT INTO mysql_innodb_cluster_metadata.v2_routers") != std::string::npos,
	   "an absent registration is inserted once");
	ok(created.executions[1].find("JSON_SET(COALESCE(attributes,JSON_OBJECT())") != std::string::npos,
	   "registration attributes are merged instead of replacing the document");
	ok(created.executions[1].find("options=") == std::string::npos,
	   "Shell-owned Router options are never updated");

	RegistrationSession adopted;
	adopted.results.push_back({{row({{"router_id", "17"}, {"options", "{\"shell\":true}"}})}});
	auto adoption_options = options();
	adoption_options.force = true;
	auto existing = register_or_adopt_router(
		adopted, topology(), adoption_options, "PROXY.EXAMPLE", "router_account");
	ok(existing.router_id == 17 && adopted.executions.size() == 1,
	   "an existing address/name registration is adopted without reinsertion");
	ok(adopted.queries[0].find("LOWER(address)=LOWER(?)") != std::string::npos &&
	   adopted.query_params[0] == std::vector<SqlValue>({std::string("PROXY.EXAMPLE"),
		std::string("proxysql-east")}),
	   "registration lookup is case-insensitive only for address and binds both values");
	ok(adopted.executions[0].find("clusterset_id=NULL") != std::string::npos &&
	   adopted.execute_params[0].back() == SqlValue(int64_t(17)),
	   "an adopted row is retargeted to the exact cluster by bound router id");

	RegistrationSession replaced;
	replaced.results.push_back(QueryResult {});
	replaced.results.push_back({{row({{"router_id", "19"}})}});
	auto replacement = register_or_adopt_router(
		replaced, topology(), adoption_options, "new-proxy.example", "router_account");
	ok(replacement.router_id == 19 && replaced.executions.size() == 1 &&
	   replaced.executions[0].find("address=?,router_name=?") != std::string::npos &&
	   replaced.execute_params[0][0] == SqlValue(std::string("new-proxy.example")),
	   "--force retargets one conflicting Router registration instead of inserting a duplicate");

	bool force_required = false;
	try {
		RegistrationSession unforced;
		unforced.results.push_back({{row({{"router_id", "17"}})}});
		(void)register_or_adopt_router(unforced, topology(), options(),
			"proxy.example", "router_account");
	} catch (const std::exception& error) {
		force_required = std::string(error.what()).find("--force") != std::string::npos;
	}
	ok(force_required, "an existing unowned registration requires explicit --force adoption");

	RegistrationSession unchanged;
	unchanged.affected_rows = 0;
	unchanged.results.push_back({{row({{"router_id", "17"}})}});
	unchanged.results.push_back({{row({{"router_id", "17"}})}});
	auto retained = register_or_adopt_router(unchanged, topology(), adoption_options,
		"proxy.example", "router_account");
	ok(retained.router_id == 17,
	   "an unchanged registration update is accepted after exact identity revalidation");

	bool vanished_rejected = false;
	try {
		RegistrationSession vanished;
		vanished.affected_rows = 0;
		vanished.results.push_back({{row({{"router_id", "17"}})}});
		vanished.results.push_back(QueryResult {});
		(void)register_or_adopt_router(vanished, topology(), adoption_options,
			"proxy.example", "router_account");
	} catch (const std::exception& error) {
		vanished_rejected = std::string(error.what()).find("disappeared") != std::string::npos;
	}
	ok(vanished_rejected, "a registration deleted before its update fails closed");

	bool duplicates_rejected = false;
	try {
		RegistrationSession duplicate;
		duplicate.results.push_back({{row({{"router_id", "17"}}), row({{"router_id", "18"}})}});
		(void)register_or_adopt_router(duplicate, topology(), options(),
			"proxy.example", "router_account");
	} catch (const std::exception&) { duplicates_rejected = true; }
	ok(duplicates_rejected, "ambiguous existing Router registrations fail closed");

	return exit_status();
}
