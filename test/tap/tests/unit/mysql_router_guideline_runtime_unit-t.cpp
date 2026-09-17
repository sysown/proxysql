#include "tap.h"

#include "ProxySQL_Plugin.h"
#include "mysql_router_compiler.h"
#include "mysql_router_guideline_runtime.h"

#include <string>
#include <vector>

// Routing Guidelines runtime (#6145): pools per route, documented strategy
// equivalence, rw_split pools, precedence of operator rules, session cookie reuse,
// last valid generation on invalid updates.

namespace {

const char* kDefaultGuideline = R"json({
 "name":"default","version":"1.1",
 "destinations":[
  {"name":"Primary","match":"$.server.memberRole = PRIMARY"},
  {"name":"Secondary","match":"$.server.memberRole = SECONDARY"},
  {"name":"ReadReplica","match":"$.server.memberRole = READ_REPLICA"}],
 "routes":[
  {"name":"rw","enabled":true,"connectionSharingAllowed":true,
   "match":"$.session.targetPort = $.router.port.rw",
   "destinations":[{"classes":["Primary"],"strategy":"round-robin","priority":0}]},
  {"name":"ro","enabled":true,"connectionSharingAllowed":true,
   "match":"$.session.targetPort = $.router.port.ro",
   "destinations":[{"classes":["Secondary"],"strategy":"round-robin","priority":0},
                   {"classes":["Primary"],"strategy":"round-robin","priority":1}]}]})json";

const char* kCustomGuideline = R"json({
 "name":"custom","version":"1.1",
 "destinations":[
  {"name":"Primary","match":"$.server.memberRole = PRIMARY"},
  {"name":"EU","match":"$.server.tags.region = 'eu'"},
  {"name":"Replicas","match":"$.server.memberRole = READ_REPLICA"},
  {"name":"Any","match":"$.server.memberRole IN (PRIMARY, SECONDARY, READ_REPLICA)"}],
 "routes":[
  {"name":"reporting","match":"$.session.user = 'report' AND $.session.connectAttrs.program_name = 'bi'",
   "destinations":[{"classes":["Replicas"],"strategy":"first-available","priority":0},
                   {"classes":["Primary"],"strategy":"round-robin","priority":1}]},
  {"name":"disabled","enabled":false,"match":"TRUE",
   "destinations":[{"classes":["Primary"],"strategy":"round-robin","priority":0}]},
  {"name":"split","match":"$.session.targetPort = $.router.port.rw_split",
   "destinations":[{"classes":["Any"],"strategy":"round-robin","priority":0}]},
  {"name":"office","match":"NETWORK($.session.sourceIP, 24) = '10.1.2.0'",
   "destinations":[{"classes":["EU"],"strategy":"first-available","priority":0}]}]})json";

DesiredTopology topology(const std::string& document) {
	DesiredTopology desired;
	desired.topology_uuid = "cluster-1";
	desired.topology_name = "prod";
	desired.routing_guidelines_capable = true;
	desired.instances = {
		{"s1", "cluster-1", "db1", {"db1", 3306}, InstanceKind::gr_member, "{}"},
		{"s2", "cluster-1", "db2", {"db2", 3306}, InstanceKind::gr_member, "{\"tags\":{\"region\":\"eu\"}}"},
		{"s3", "cluster-1", "db3", {"db3", 3306}, InstanceKind::gr_member, "{\"tags\":{\"region\":\"eu\"}}"},
		{"s4", "cluster-1", "rr1", {"rr1", 3306}, InstanceKind::read_replica, "{}"},
	};
	desired.options.guideline_id = "rg-1";
	desired.guideline = RoutingGuidelineSource{"rg-1", "rg", document};
	return desired;
}

EffectiveTopology effective(bool with_secondaries = true) {
	EffectiveTopology result;
	result.writer = "s1";
	result.guideline_candidates = {"s1"};
	if (with_secondaries) {
		result.guideline_candidates.push_back("s2");
		result.guideline_candidates.push_back("s3");
	}
	result.guideline_candidates.push_back("s4");
	result.versions = {{"s1", "8.4.8"}};
	return result;
}

const GuidelineRoutePlan* plan(const CompiledGuideline& compiled, const std::string& name) {
	for (const auto& item : compiled.routes) {
		if (item.name == name) return &item;
	}
	return nullptr;
}

std::vector<std::string> hosts(const GuidelinePool& pool) {
	std::vector<std::string> result;
	for (const auto& member : pool.members) result.push_back(member.host);
	return result;
}

// Snapshot with deterministic hostgroups: route index i -> 100+10*i (+1 writer, +2 reader).
std::shared_ptr<GuidelineRoutingSnapshot> snapshot_for(std::shared_ptr<const CompiledGuideline> compiled) {
	auto snapshot = std::make_shared<GuidelineRoutingSnapshot>();
	snapshot->generation = 7;
	snapshot->compiled = compiled;
	snapshot->bind_address = "0.0.0.0";
	snapshot->rw_port = 6446;
	snapshot->ro_port = 6447;
	snapshot->rw_split_port = 6450;
	snapshot->route_writer_hostgroup = 8000;
	snapshot->route_reader_hostgroup = 8001;
	const size_t routes = compiled->guideline->routes().size();
	snapshot->hostgroups.assign(routes, std::nullopt);
	snapshot->plan_index.assign(routes, std::nullopt);
	for (size_t i = 0; i < compiled->routes.size(); ++i) {
		const size_t index = compiled->routes[i].route_index;
		snapshot->hostgroups[index] = GuidelineRouteHostgroups{
			static_cast<int>(100 + 10 * index), static_cast<int>(101 + 10 * index), static_cast<int>(102 + 10 * index)};
		snapshot->plan_index[index] = i;
	}
	return snapshot;
}

GuidelineSessionRequest request(uint16_t port, int destination, const std::string& user = "app") {
	GuidelineSessionRequest result;
	result.user = user;
	result.client_ip = "192.168.0.10";
	result.proxy_port = port;
	result.destination_hostgroup = destination;
	return result;
}

} // namespace

int main() {
	plan(49);
	const ListenerProfile listeners;

	// Shell default guideline.
	GuidelineCompiler compiler;
	auto outcome = compiler.compile(topology(kDefaultGuideline), effective(), listeners);
	ok(outcome.state == "active" && outcome.compiled && outcome.error_kind.empty(),
	   "the Shell default guideline is active (%s %s)", outcome.state.c_str(), outcome.error_message.c_str());
	if (!outcome.compiled) {
		BAIL_OUT("default guideline did not compile");
		return exit_status();
	}
	const CompiledGuideline& defaults = *outcome.compiled;
	ok(defaults.destinations.size() == 4, "every candidate is classified");
	ok(defaults.destinations[0].member_role == "PRIMARY" && defaults.destinations[0].classes == "Primary",
	   "the effective writer is PRIMARY");
	ok(defaults.destinations[1].member_role == "SECONDARY" && defaults.destinations[1].classes == "Secondary",
	   "other GR members are SECONDARY");
	ok(defaults.destinations[3].member_role == "READ_REPLICA" && defaults.destinations[3].classes == "ReadReplica",
	   "read replicas are READ_REPLICA");
	const GuidelineRoutePlan* rw = plan(defaults, "rw");
	const GuidelineRoutePlan* ro = plan(defaults, "ro");
	ok(rw && hosts(rw->all) == std::vector<std::string>{"db1"} && rw->all.strategy == "round-robin",
	   "rw route pool holds the primary");
	ok(ro && hosts(ro->all) == std::vector<std::string>({"db2", "db3"}) && ro->all.priority == 0u,
	   "ro route pool uses the secondaries (priority 0)");
	ok(ro && ro->all.members[0].weight == 1 && ro->all.members[1].weight == 1,
	   "round-robin members have equal weights");
	ok(ro && ro->connection_sharing_allowed && *ro->connection_sharing_allowed &&
	   ro->notes.find("connectionSharingAllowed") != std::string::npos,
	   "connectionSharingAllowed is reported as not applied");

	auto fallback = compiler.compile(topology(kDefaultGuideline), effective(false), listeners);
	const GuidelineRoutePlan* ro_fallback = fallback.compiled ? plan(*fallback.compiled, "ro") : nullptr;
	ok(ro_fallback && hosts(ro_fallback->all) == std::vector<std::string>{"db1"} &&
	   ro_fallback->all.priority == 1u, "without secondaries the ro route falls back to the priority 1 group");
	ok(fallback.compiled && outcome.compiled->fingerprint != fallback.compiled->fingerprint,
	   "a pool change changes the guideline fingerprint");

	// Custom guideline: tags, disabled routes, first-available, rw_split pools.
	GuidelineCompiler custom_compiler;
	auto custom = custom_compiler.compile(topology(kCustomGuideline), effective(), listeners);
	ok(custom.state == "active" && custom.compiled, "the custom guideline is active (%s)", custom.error_message.c_str());
	if (!custom.compiled) {
		BAIL_OUT("custom guideline did not compile");
		return exit_status();
	}
	ok(!plan(*custom.compiled, "disabled"), "disabled routes get no pools");
	const GuidelineRoutePlan* reporting = plan(*custom.compiled, "reporting");
	ok(reporting && hosts(reporting->all) == std::vector<std::string>{"rr1"} &&
	   reporting->all.strategy == "first-available", "reporting route uses the read replica group");
	const GuidelineRoutePlan* office = plan(*custom.compiled, "office");
	ok(office && hosts(office->all) == std::vector<std::string>({"db2", "db3"}), "server tags select EU members");
	ok(office && office->all.members[0].weight == 10000000 && office->all.members[1].weight == 100000,
	   "first-available is emulated with decreasing weights");
	const GuidelineRoutePlan* split = plan(*custom.compiled, "split");
	ok(split && hosts(split->writer) == std::vector<std::string>{"db1"},
	   "rw_split writer pool holds the PRIMARY members");
	ok(split && hosts(split->reader) == std::vector<std::string>({"db2", "db3", "rr1"}),
	   "rw_split reader pool holds the non-PRIMARY members");
	ok(reporting && hosts(reporting->writer) == std::vector<std::string>{"db1"} &&
	   hosts(reporting->reader) == std::vector<std::string>{"rr1"},
	   "writer and reader pools pick the first group that has the needed role");

	// Route decisions.
	auto snapshot = snapshot_for(custom.compiled);
	auto reporting_request = request(6446, 8000, "report");
	reporting_request.connect_attrs["program_name"] = "bi";
	auto decision = mysql_router_decide_route(snapshot.get(), reporting_request, 0.5);
	ok(decision.action == GuidelineRouteDecision::Action::set_hostgroup && decision.hostgroup == 100,
	   "matching session attributes select the first matching route");
	ok(decision.session_cookie == ((uint64_t(7) << 32) | 1u), "the selected route is cached in the session cookie");
	auto cached = request(6446, 8000, "someone-else");
	cached.session_cookie = decision.session_cookie;
	auto cached_decision = mysql_router_decide_route(snapshot.get(), cached, 0.5);
	ok(cached_decision.action == GuidelineRouteDecision::Action::set_hostgroup && cached_decision.hostgroup == 100,
	   "a valid cookie reuses the route without re-evaluation");
	cached.session_cookie = (uint64_t(6) << 32) | 1u;
	auto stale_cookie = mysql_router_decide_route(snapshot.get(), cached, 0.5);
	ok(stale_cookie.action == GuidelineRouteDecision::Action::deny,
	   "a cookie from an older generation is re-evaluated (no route matches now)");

	auto split_write = mysql_router_decide_route(snapshot.get(), request(6450, 8000), 0.5);
	ok(split_write.action == GuidelineRouteDecision::Action::set_hostgroup && split_write.hostgroup == 121,
	   "rw_split writes go to the route writer hostgroup (%d)", split_write.hostgroup);
	auto split_read = mysql_router_decide_route(snapshot.get(), request(6450, 8001), 0.5);
	ok(split_read.action == GuidelineRouteDecision::Action::set_hostgroup && split_read.hostgroup == 122,
	   "rw_split reads go to the route reader hostgroup (%d)", split_read.hostgroup);

	auto office_request = request(6447, 8001);
	office_request.client_ip = "10.1.2.77";
	auto office_decision = mysql_router_decide_route(snapshot.get(), office_request, 0.5);
	ok(office_decision.action == GuidelineRouteDecision::Action::set_hostgroup && office_decision.hostgroup == 130,
	   "NETWORK() over sourceIP selects the office route (%d)", office_decision.hostgroup);

	auto no_route = mysql_router_decide_route(snapshot.get(), request(6447, 8001), 0.5);
	ok(no_route.action == GuidelineRouteDecision::Action::deny && no_route.session_cookie == 0 &&
	   no_route.message.find("no Routing Guideline route") != std::string::npos,
	   "a session matching no route is denied");

	auto operator_rule = mysql_router_decide_route(snapshot.get(), request(6446, 42, "report"), 0.5);
	ok(operator_rule.action == GuidelineRouteDecision::Action::unchanged,
	   "destinations chosen by operator query rules are never remapped");
	auto other_listener = mysql_router_decide_route(snapshot.get(), request(6033, 8000, "report"), 0.5);
	ok(other_listener.action == GuidelineRouteDecision::Action::unchanged,
	   "sessions on non-Router listeners are not remapped");
	auto no_snapshot = mysql_router_decide_route(nullptr, request(6446, 8000), 0.5);
	ok(no_snapshot.action == GuidelineRouteDecision::Action::unchanged && no_snapshot.session_cookie == 0,
	   "without an active guideline the hook is a no-op");

	auto empty_effective = effective();
	empty_effective.guideline_candidates = {"s2", "s3"};
	empty_effective.writer.reset();
	auto no_primary = custom_compiler.compile(topology(kCustomGuideline), empty_effective, listeners);
	auto no_primary_snapshot = snapshot_for(no_primary.compiled);
	auto write_without_primary = mysql_router_decide_route(no_primary_snapshot.get(), request(6450, 8000), 0.5);
	ok(write_without_primary.action == GuidelineRouteDecision::Action::deny &&
	   write_without_primary.message.find("no available PRIMARY") != std::string::npos,
	   "rw_split writes without a PRIMARY are denied");

	// ABI hook adapter.
	mysql_router_set_guideline_snapshot(snapshot_for(custom.compiled));
	auto active = mysql_router_guideline_snapshot();
	ok(active && active->generation != 0, "publishing a snapshot assigns a generation");
	const ProxySQL_PluginConnectAttr attrs[] {{"program_name", "bi"}};
	ProxySQL_PluginRouteHookPayload payload {"report", "", "192.168.0.10", 5000, "0.0.0.0", 6446,
		attrs, 1, 8000, 0};
	ProxySQL_PluginRouteHookResult hook = mysql_router_route_hook(payload);
	ok(hook.action == ProxySQL_PluginRouteHookAction::set_hostgroup && hook.hostgroup == 100 &&
	   (hook.session_cookie >> 32) == active->generation, "the ABI hook maps to the route hostgroup");
	mysql_router_set_guideline_snapshot(nullptr);
	payload.session_cookie = hook.session_cookie;
	hook = mysql_router_route_hook(payload);
	ok(hook.action == ProxySQL_PluginRouteHookAction::unchanged && hook.session_cookie == 0,
	   "clearing the snapshot disables the hook and resets the cookie");

	// Invalid updates keep the last valid generation; removal clears it.
	auto invalid_desired = topology(R"json({"version":"1.1","destinations":[{"name":"A","match":"$.server.nope = 1"}],"routes":[]})json");
	auto stale = compiler.compile(invalid_desired, effective(), listeners);
	ok(stale.state == "stale" && stale.compiled && stale.compiled->stale,
	   "an invalid update keeps the last valid guideline (%s)", stale.state.c_str());
	ok(stale.error_kind == "guideline_parse" && !stale.error_message.empty(),
	   "the parse error is reported: %s", stale.error_message.c_str());
	ok(stale.compiled && stale.compiled->source.name == "rg" && plan(*stale.compiled, "rw"),
	   "the stale generation still routes with the previous document");
	GuidelineCompiler fresh;
	auto invalid = fresh.compile(invalid_desired, effective(), listeners);
	ok(invalid.state == "invalid" && !invalid.compiled, "an invalid first guideline is not applied");
	auto missing_desired = topology("");
	auto missing = fresh.compile(missing_desired, effective(), listeners);
	ok(missing.state == "invalid" && missing.error_kind == "guideline_validation",
	   "an option referencing a missing guideline is reported");
	auto route_name_desired = topology(R"json({"version":"1.1","destinations":[{"name":"A","match":"$.router.routeName = 'x'"}],
		"routes":[{"name":"r","match":"TRUE","destinations":[{"classes":["A"],"strategy":"round-robin","priority":0}]}]})json");
	auto route_name = fresh.compile(route_name_desired, effective(), listeners);
	ok(route_name.state == "invalid" && route_name.error_message.find("routeName") != std::string::npos,
	   "$.router.routeName in destinations fails closed");
	auto removed_desired = topology(kDefaultGuideline);
	removed_desired.guideline.reset();
	removed_desired.options.guideline_id.reset();
	auto removed = compiler.compile(removed_desired, effective(), listeners);
	ok(removed.state == "none" && !removed.compiled, "removing the guideline option clears the guideline");
	auto after_removal = compiler.compile(invalid_desired, effective(), listeners);
	ok(after_removal.state == "invalid", "after removal an invalid guideline has no previous generation to keep");

	// Destination evaluation errors never publish partial pools (#6211 review).
	const char* kNetworkGuideline = R"json({"version":"1.1",
		"destinations":[{"name":"Lan","match":"NETWORK($.server.address, 24) = '10.0.0.0'"}],
		"routes":[{"name":"lan","match":"TRUE","destinations":[{"classes":["Lan"],"strategy":"round-robin","priority":0}]}]})json";
	auto ip_topology = topology(kNetworkGuideline);
	for (auto& instance : ip_topology.instances) instance.classic.host = "10.0.0." + instance.label.substr(instance.label.size() - 1);
	GuidelineCompiler network_compiler;
	auto network_ok = network_compiler.compile(ip_topology, effective(), listeners);
	ok(network_ok.state == "active" && network_ok.compiled && plan(*network_ok.compiled, "lan") &&
	   plan(*network_ok.compiled, "lan")->all.members.size() == 4,
	   "NETWORK() destinations classify IPv4 members (%s)", network_ok.error_message.c_str());
	auto network_error = network_compiler.compile(topology(kNetworkGuideline), effective(), listeners);
	ok(network_error.state == "stale" && network_error.error_kind == "guideline_evaluation" &&
	   network_error.compiled && network_error.compiled->fingerprint == network_ok.compiled->fingerprint + "|evaluation-stale" &&
	   plan(*network_error.compiled, "lan")->all.members.size() == 4,
	   "an evaluation error keeps the last pools computed without errors (%s)", network_error.error_message.c_str());
	GuidelineCompiler network_fresh;
	auto network_invalid = network_fresh.compile(topology(kNetworkGuideline), effective(), listeners);
	ok(network_invalid.state == "invalid" && !network_invalid.compiled &&
	   network_invalid.error_kind == "guideline_evaluation",
	   "an evaluation error without previous pools applies nothing");

	// Configuration append.
	CompiledMysqlConfig config;
	ManagedHostgroups baseline;
	baseline.by_role = {{"route_writer", 8000}, {"route_reader", 8001}};
	ManagedHostgroups routes;
	int next = 8100;
	for (const auto& role : mysql_router_guideline_roles(*custom.compiled)) routes.by_role[role] = next++;
	auto appended = mysql_router_append_guideline_config(config, custom.compiled, routes, baseline,
		topology(kCustomGuideline), listeners, 5);
	ok(appended && config.owned_hostgroups.size() == 9 && config.hostgroup_attributes.size() == 9,
	   "three hostgroups are owned per enabled route");
	size_t office_servers = 0;
	int office_hostgroup = routes.by_role[mysql_router_guideline_hostgroup_role("office", "all")];
	for (const auto& server : config.servers) {
		if (server.hostgroup_id == office_hostgroup) {
			++office_servers;
			ok(server.comment.find("route=office;pool=all") != std::string::npos, "server rows carry ownership comments");
		}
	}
	ok(office_servers == 2, "route servers are published with their pools");

	return exit_status();
}
