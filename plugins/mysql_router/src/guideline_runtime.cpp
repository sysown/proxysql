#include "mysql_router_guideline_runtime.h"

#include "mysql_router_compiler.h"

#include "ProxySQL_Plugin.h"

#include <json.hpp>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <random>
#include <set>
#include <sstream>

namespace rg = mysql_router::rg;

namespace {

std::shared_ptr<GuidelineRoutingSnapshot> g_snapshot;
std::shared_ptr<const CompiledGuideline> g_pending;
std::atomic<uint32_t> g_snapshot_generation {0};

const DesiredInstance* find_instance(const DesiredTopology& desired, const std::string& uuid) {
	for (const auto& instance : desired.instances) {
		if (instance.server_uuid == uuid) return &instance;
	}
	return nullptr;
}

// "8.4.8" -> 80408 (MMmmpp), 0 when unknown.
uint32_t version_number(const std::string& text) {
	uint32_t parts[3] {0, 0, 0};
	size_t index = 0;
	const char* begin = text.data();
	const char* end = text.data() + text.size();
	while (begin < end && index < 3) {
		uint32_t value = 0;
		auto parsed = std::from_chars(begin, end, value);
		if (parsed.ec != std::errc()) break;
		parts[index++] = value;
		begin = parsed.ptr;
		if (begin < end && *begin == '.') ++begin;
		else break;
	}
	if (index == 0) return 0;
	return parts[0] * 10000 + parts[1] * 100 + parts[2];
}

std::map<std::string, std::string> instance_tags(const DesiredInstance& instance) {
	std::map<std::string, std::string> tags;
	try {
		const nlohmann::json attributes = nlohmann::json::parse(instance.attributes);
		if (attributes.is_object() && attributes.contains("tags") && attributes["tags"].is_object()) {
			for (auto it = attributes["tags"].begin(); it != attributes["tags"].end(); ++it) {
				tags.emplace(it.key(), it.value().dump());
			}
		}
	} catch (const std::exception&) {
		// metadata_v2_2 already validated the attributes object; tags are optional.
	}
	return tags;
}

const char* member_role_name(rg::MemberRole role) {
	switch (role) {
		case rg::MemberRole::primary: return "PRIMARY";
		case rg::MemberRole::secondary: return "SECONDARY";
		case rg::MemberRole::read_replica: return "READ_REPLICA";
		case rg::MemberRole::undefined: break;
	}
	return "UNDEFINED";
}

const char* strategy_name(rg::Strategy strategy) {
	return strategy == rg::Strategy::first_available ? "first-available" : "round-robin";
}

// Documented equivalence of Router strategies on ProxySQL weighted load balancing.
void apply_strategy_weights(GuidelinePool& pool, rg::Strategy strategy) {
	pool.strategy = strategy_name(strategy);
	int weight = 10000000;
	for (auto& member : pool.members) {
		if (strategy == rg::Strategy::round_robin) {
			member.weight = 1;
		} else {
			member.weight = std::max(weight, 1);
			weight /= 100;
		}
	}
}

struct Candidate {
	const DesiredInstance* instance;
	rg::MemberRole role;
	std::vector<std::string> classes;
};

// Members of `group`: class order first, then topology order, without duplicates.
std::vector<const Candidate*> group_members(const rg::DestinationGroup& group,
	const std::vector<Candidate>& candidates) {
	std::vector<const Candidate*> members;
	std::set<const Candidate*> seen;
	for (const auto& klass : group.classes) {
		for (const auto& candidate : candidates) {
			if (std::find(candidate.classes.begin(), candidate.classes.end(), klass) ==
				candidate.classes.end()) continue;
			if (seen.insert(&candidate).second) members.push_back(&candidate);
		}
	}
	return members;
}

void fill_pool(GuidelinePool& pool, const rg::DestinationGroup& group,
	const std::vector<const Candidate*>& members) {
	pool.members.clear();
	for (const Candidate* member : members) {
		pool.members.push_back({member->instance->server_uuid, member->instance->classic.host,
			member->instance->classic.port, 1});
	}
	pool.priority = group.priority;
	pool.classes = group.classes;
	apply_strategy_weights(pool, group.strategy);
}

uint64_t cookie_for(uint32_t generation, size_t route_index) {
	return (static_cast<uint64_t>(generation) << 32) | static_cast<uint64_t>(route_index + 1);
}

} // namespace

std::string mysql_router_guideline_hostgroup_role(const std::string& route_name, const char* pool) {
	return std::string("rg:") + route_name + ":" + pool;
}

std::vector<GuidelineRoutePlan> mysql_router_guideline_route_plans(
	const rg::Guideline& guideline, const DesiredTopology& desired,
	const EffectiveTopology& effective, const rg::RouterInfo& router,
	std::vector<GuidelineDestinationRow>& destinations, std::vector<rg::Error>& errors) {
	std::vector<Candidate> candidates;
	for (const std::string& uuid : effective.guideline_candidates) {
		const DesiredInstance* instance = find_instance(desired, uuid);
		if (instance == nullptr) continue;
		rg::ServerInfo server;
		server.label = instance->label;
		server.address = instance->classic.host;
		server.port = instance->classic.port;
		server.uuid = instance->server_uuid;
		server.cluster_name = desired.topology_name;
		server.cluster_set_name = "";
		server.cluster_role = rg::ClusterRole::undefined;
		server.is_cluster_invalidated = false;
		server.tags = instance_tags(*instance);
		auto version = effective.versions.find(uuid);
		if (version != effective.versions.end()) server.version = version_number(version->second);
		if (instance->kind == InstanceKind::read_replica) server.member_role = rg::MemberRole::read_replica;
		else if (effective.writer && *effective.writer == uuid) server.member_role = rg::MemberRole::primary;
		else server.member_role = rg::MemberRole::secondary;

		Candidate candidate {instance, server.member_role, guideline.classify(server, router, errors)};
		GuidelineDestinationRow row;
		row.server_uuid = uuid;
		row.endpoint = instance->classic.host + ":" + std::to_string(instance->classic.port);
		row.member_role = member_role_name(server.member_role);
		for (size_t i = 0; i < candidate.classes.size(); ++i) {
			if (i) row.classes += ",";
			row.classes += candidate.classes[i];
		}
		destinations.push_back(std::move(row));
		candidates.push_back(std::move(candidate));
	}

	std::vector<GuidelineRoutePlan> plans;
	const auto& routes = guideline.routes();
	for (size_t index = 0; index < routes.size(); ++index) {
		const rg::Route& route = routes[index];
		if (!route.enabled) continue;
		GuidelineRoutePlan plan;
		plan.route_index = index;
		plan.name = route.name;
		plan.match = route.match;
		plan.enabled = route.enabled;
		plan.connection_sharing_allowed = route.connection_sharing_allowed;
		bool all_done = false, writer_done = false, reader_done = false;
		for (const rg::DestinationGroup& group : route.groups) {
			const auto members = group_members(group, candidates);
			if (members.empty()) continue;
			if (!all_done) {
				fill_pool(plan.all, group, members);
				all_done = true;
			}
			std::vector<const Candidate*> primaries, others;
			for (const Candidate* member : members) {
				(member->role == rg::MemberRole::primary ? primaries : others).push_back(member);
			}
			if (!writer_done && !primaries.empty()) {
				fill_pool(plan.writer, group, primaries);
				writer_done = true;
			}
			if (!reader_done && !others.empty()) {
				fill_pool(plan.reader, group, others);
				reader_done = true;
			}
		}
		std::ostringstream notes;
		notes << "fallback to the next priority group is evaluated at every topology refresh";
		if (!reader_done && writer_done) {
			plan.reader = plan.writer;
			notes << "; rw_split reads use the PRIMARY because the route has no read-only destination";
		}
		if (plan.all.strategy == "first-available" || plan.writer.strategy == "first-available" ||
			plan.reader.strategy == "first-available") {
			notes << "; first-available is emulated with decreasing weights";
		}
		if (plan.connection_sharing_allowed) {
			notes << "; connectionSharingAllowed is not applied (ProxySQL multiplexing rules apply)";
		}
		if (!all_done) notes << "; no destination is currently available";
		plan.notes = notes.str();
		plans.push_back(std::move(plan));
	}
	return plans;
}

GuidelineCompileOutcome GuidelineCompiler::compile(const DesiredTopology& desired,
	const EffectiveTopology& effective, const ListenerProfile& listeners) {
	GuidelineCompileOutcome outcome;
	if (!desired.guideline) {
		last_document_.clear();
		last_valid_.reset();
		last_valid_source_ = {};
		last_errors_.clear();
		last_good_compiled_.reset();
		outcome.state = "none";
		return outcome;
	}
	const RoutingGuidelineSource& source = *desired.guideline;
	std::shared_ptr<const rg::Guideline> parsed;
	std::vector<rg::Error> parse_errors;
	std::string error_kind;
	if (source.document.empty()) {
		error_kind = "guideline_validation";
		parse_errors.push_back({"", "routing guideline '" + source.guideline_id +
			"' referenced by the router options does not exist"});
	} else if (source.document == last_document_ && !last_errors_.empty()) {
		// Same rejected document as the previous refresh: keep reporting it.
		parse_errors = last_errors_;
		error_kind = last_error_kind_;
	} else if (last_valid_ && source.document == last_document_) {
		parsed = last_valid_;
	} else {
		parsed = rg::Guideline::parse(source.document, parse_errors);
		last_document_ = source.document;
		if (!parsed || !parse_errors.empty()) {
			parsed.reset();
			error_kind = "guideline_parse";
			last_errors_ = parse_errors;
			last_error_kind_ = error_kind;
		} else {
			last_errors_.clear();
			if (parsed->uses_router_route_name_in_destinations()) {
				parsed.reset();
				error_kind = "guideline_validation";
				parse_errors.push_back({"destinations", "$.router.routeName is not supported in destinations "
					"by ProxySQL: destinations are evaluated once for all listeners"});
				last_errors_ = parse_errors;
				last_error_kind_ = error_kind;
			}
		}
	}

	bool stale = false;
	RoutingGuidelineSource effective_source = source;
	if (!parsed) {
		std::ostringstream message;
		for (size_t i = 0; i < parse_errors.size(); ++i) {
			if (i) message << "; ";
			if (!parse_errors[i].path.empty()) message << parse_errors[i].path << ": ";
			message << parse_errors[i].message;
		}
		outcome.error_kind = error_kind;
		outcome.error_message = "routing guideline '" + (source.name.empty() ? source.guideline_id : source.name) +
			"' rejected: " + message.str();
		if (!last_valid_) {
			last_good_compiled_.reset();
			outcome.state = "invalid";
			return outcome;
		}
		parsed = last_valid_;
		effective_source = last_valid_source_;
		stale = true;
	} else {
		last_valid_ = parsed;
		last_valid_source_ = source;
	}

	auto compiled = std::make_shared<CompiledGuideline>();
	compiled->source = effective_source;
	compiled->guideline = parsed;
	compiled->stale = stale;
	compiled->router.port_rw = listeners.rw_port;
	compiled->router.port_ro = listeners.ro_port;
	compiled->router.port_rw_split = listeners.rw_split_port;
	compiled->router.bind_address = listeners.bind_address;
	compiled->router.hostname = desired.router.hostname;
	compiled->router.name = desired.router.name;
	compiled->router.local_cluster = desired.router.local_cluster;
	compiled->router.tags = desired.router.tags;
	std::vector<rg::Error> evaluation_errors;
	compiled->routes = mysql_router_guideline_route_plans(*parsed, desired, effective,
		compiled->router, compiled->destinations, evaluation_errors);
	if (!evaluation_errors.empty() && outcome.error_kind.empty()) {
		std::ostringstream message;
		for (size_t i = 0; i < evaluation_errors.size(); ++i) {
			if (i) message << "; ";
			if (!evaluation_errors[i].path.empty()) message << evaluation_errors[i].path << ": ";
			message << evaluation_errors[i].message;
		}
		outcome.error_kind = "guideline_evaluation";
		outcome.error_message = "routing guideline '" + effective_source.name +
			"' destination evaluation failed: " + message.str();
	}
	if (!evaluation_errors.empty()) {
		// Partially classified destinations must not be published: keep the last
		// pools computed without errors, or apply nothing.
		if (!last_good_compiled_) {
			outcome.state = "invalid";
			return outcome;
		}
		auto kept = std::make_shared<CompiledGuideline>(*last_good_compiled_);
		kept->stale = true;
		kept->fingerprint += "|evaluation-stale";
		outcome.compiled = kept;
		outcome.state = "stale";
		return outcome;
	}

	std::ostringstream fingerprint;
	// Hash the document actually routing (the last valid one when stale), so edits
	// of a rejected document do not trigger republication.
	fingerprint << compiled->source.guideline_id << '|' << std::hash<std::string>{}(effective_source.document)
		<< '|' << stale;
	for (const auto& plan : compiled->routes) {
		fingerprint << '|' << plan.name;
		for (const GuidelinePool* pool : {&plan.all, &plan.writer, &plan.reader}) {
			fingerprint << '[';
			for (const auto& member : pool->members) fingerprint << member.server_uuid << '=' << member.weight << ',';
			fingerprint << ']';
		}
	}
	compiled->fingerprint = fingerprint.str();
	last_good_compiled_ = compiled;
	outcome.compiled = compiled;
	outcome.state = stale ? "stale" : "active";
	return outcome;
}

void mysql_router_set_guideline_snapshot(std::shared_ptr<GuidelineRoutingSnapshot> snapshot) {
	if (snapshot) {
		uint32_t generation = g_snapshot_generation.fetch_add(1, std::memory_order_relaxed) + 1;
		if (generation == 0) generation = g_snapshot_generation.fetch_add(1, std::memory_order_relaxed) + 1;
		snapshot->generation = generation;
	}
	std::atomic_store(&g_snapshot, std::move(snapshot));
}

std::shared_ptr<const GuidelineRoutingSnapshot> mysql_router_guideline_snapshot() {
	return std::atomic_load(&g_snapshot);
}

GuidelineRouteDecision mysql_router_decide_route(const GuidelineRoutingSnapshot* snapshot,
	const GuidelineSessionRequest& request, double random_value) {
	GuidelineRouteDecision decision;
	decision.session_cookie = request.session_cookie;
	if (snapshot == nullptr || !snapshot->compiled || !snapshot->compiled->guideline) {
		decision.session_cookie = 0;
		return decision;
	}
	// Operator query rules that chose another hostgroup take precedence.
	if (request.destination_hostgroup != snapshot->route_writer_hostgroup &&
		request.destination_hostgroup != snapshot->route_reader_hostgroup) {
		return decision;
	}
	const char* route_name = nullptr;
	bool split = false;
	if (request.proxy_port == snapshot->rw_port) route_name = kMysqlRouterRouteNameRw;
	else if (request.proxy_port == snapshot->ro_port) route_name = kMysqlRouterRouteNameRo;
	else if (request.proxy_port == snapshot->rw_split_port) {
		route_name = kMysqlRouterRouteNameRwSplit;
		split = true;
	} else {
		return decision; // not a Router listener
	}

	const rg::Guideline& guideline = *snapshot->compiled->guideline;
	size_t route_index = 0;
	const uint64_t cookie = request.session_cookie;
	const uint32_t cookie_generation = static_cast<uint32_t>(cookie >> 32);
	const uint32_t cookie_route = static_cast<uint32_t>(cookie & 0xffffffffu);
	if (cookie_generation == snapshot->generation && cookie_route != 0 &&
		cookie_route <= guideline.routes().size()) {
		route_index = cookie_route - 1;
	} else {
		rg::SessionInfo session;
		session.target_ip = snapshot->bind_address;
		session.target_port = request.proxy_port;
		session.source_ip = request.client_ip;
		session.user = request.user;
		session.schema = request.schema;
		session.random_value = random_value;
		session.connect_attrs = request.connect_attrs;
		rg::RouterInfo router = snapshot->compiled->router;
		router.route_name = route_name;
		std::vector<rg::Error> errors;
		const std::optional<size_t> matched = guideline.match_route(session, router, errors);
		if (!errors.empty()) {
			decision.action = GuidelineRouteDecision::Action::deny;
			decision.session_cookie = 0;
			decision.message = "MySQL Router plugin: Routing Guideline route classification error: " +
				errors.front().message;
			return decision;
		}
		if (!matched) {
			decision.action = GuidelineRouteDecision::Action::deny;
			decision.session_cookie = 0;
			decision.message = "MySQL Router plugin: no Routing Guideline route matches this session";
			return decision;
		}
		route_index = *matched;
		decision.session_cookie = cookie_for(snapshot->generation, route_index);
	}

	if (route_index >= snapshot->hostgroups.size() || !snapshot->hostgroups[route_index] ||
		route_index >= snapshot->plan_index.size() || !snapshot->plan_index[route_index]) {
		decision.action = GuidelineRouteDecision::Action::deny;
		decision.message = "MySQL Router plugin: Routing Guideline route is not available";
		return decision;
	}
	const GuidelineRouteHostgroups& hostgroups = *snapshot->hostgroups[route_index];
	const GuidelineRoutePlan& plan = snapshot->compiled->routes[*snapshot->plan_index[route_index]];
	const GuidelinePool* pool = &plan.all;
	int hostgroup = hostgroups.all;
	if (split) {
		const bool writer = request.destination_hostgroup == snapshot->route_writer_hostgroup;
		pool = writer ? &plan.writer : &plan.reader;
		hostgroup = writer ? hostgroups.writer : hostgroups.reader;
	}
	if (pool->members.empty()) {
		decision.action = GuidelineRouteDecision::Action::deny;
		decision.message = "MySQL Router plugin: Routing Guideline route '" + plan.name +
			"' has no available " + (split ? (pool == &plan.writer ? "PRIMARY " : "read-only ") : "") +
			"destinations";
		return decision;
	}
	decision.action = GuidelineRouteDecision::Action::set_hostgroup;
	decision.hostgroup = hostgroup;
	return decision;
}

ProxySQL_PluginRouteHookResult mysql_router_route_hook(const ProxySQL_PluginRouteHookPayload& payload) {
	ProxySQL_PluginRouteHookResult result {ProxySQL_PluginRouteHookAction::unchanged, -1,
		payload.session_cookie, std::string()};
	const std::shared_ptr<const GuidelineRoutingSnapshot> snapshot = mysql_router_guideline_snapshot();
	if (!snapshot) {
		result.session_cookie = 0;
		return result;
	}
	if (payload.destination_hostgroup != snapshot->route_writer_hostgroup &&
		payload.destination_hostgroup != snapshot->route_reader_hostgroup) {
		return result;
	}
	GuidelineSessionRequest request;
	request.user = payload.user ? payload.user : "";
	request.schema = payload.schema ? payload.schema : "";
	request.client_ip = payload.client_ip ? payload.client_ip : "";
	request.proxy_port = payload.proxy_port > 0 && payload.proxy_port <= 65535
		? static_cast<uint16_t>(payload.proxy_port) : 0;
	request.destination_hostgroup = payload.destination_hostgroup;
	request.session_cookie = payload.session_cookie;
	const bool reuse = static_cast<uint32_t>(payload.session_cookie >> 32) == snapshot->generation &&
		(payload.session_cookie & 0xffffffffu) != 0;
	if (!reuse) {
		for (size_t i = 0; i < payload.connect_attrs_count; ++i) {
			const auto& attr = payload.connect_attrs[i];
			if (attr.key) request.connect_attrs[attr.key] = attr.value ? attr.value : "";
		}
	}
	// NOSONAR cpp:S2245: $.session.randomValue only distributes sessions across
	// routes (MySQL Router uses a non-cryptographic generator too); no security use.
	static thread_local std::mt19937_64 generator {std::random_device{}()}; // NOSONAR cpp:S2245
	const double random_value = std::uniform_real_distribution<double>(0.0, 1.0)(generator);
	GuidelineRouteDecision decision = mysql_router_decide_route(snapshot.get(), request, random_value);
	result.session_cookie = decision.session_cookie;
	switch (decision.action) {
	case GuidelineRouteDecision::Action::set_hostgroup:
		result.action = ProxySQL_PluginRouteHookAction::set_hostgroup;
		result.hostgroup = decision.hostgroup;
		break;
	case GuidelineRouteDecision::Action::deny:
		result.action = ProxySQL_PluginRouteHookAction::deny;
		result.message = std::move(decision.message);
		break;
	case GuidelineRouteDecision::Action::unchanged:
		break;
	}
	return result;
}

void mysql_router_set_pending_guideline(std::shared_ptr<const CompiledGuideline> compiled) {
	std::atomic_store(&g_pending, std::move(compiled));
}

std::shared_ptr<const CompiledGuideline> mysql_router_pending_guideline() {
	return std::atomic_load(&g_pending);
}

std::set<std::string> mysql_router_guideline_roles(const CompiledGuideline& compiled) {
	std::set<std::string> roles;
	for (const auto& plan : compiled.routes) {
		for (const char* pool : {"all", "writer", "reader"}) {
			roles.insert(mysql_router_guideline_hostgroup_role(plan.name, pool));
		}
	}
	return roles;
}

std::shared_ptr<GuidelineRoutingSnapshot> mysql_router_append_guideline_config(
	CompiledMysqlConfig& config, std::shared_ptr<const CompiledGuideline> compiled,
	const ManagedHostgroups& route_hostgroups, const ManagedHostgroups& baseline_hostgroups,
	const DesiredTopology& topology, const ListenerProfile& listeners, uint64_t generation) {
	if (!compiled || !compiled->guideline) return nullptr;
	auto snapshot = std::make_shared<GuidelineRoutingSnapshot>();
	snapshot->compiled = compiled;
	snapshot->bind_address = listeners.bind_address;
	snapshot->rw_port = listeners.rw_port;
	snapshot->ro_port = listeners.ro_port;
	snapshot->rw_split_port = listeners.rw_split_port;
	snapshot->route_writer_hostgroup = baseline_hostgroups.at("route_writer");
	snapshot->route_reader_hostgroup = baseline_hostgroups.at("route_reader");
	const size_t route_count = compiled->guideline->routes().size();
	snapshot->hostgroups.assign(route_count, std::nullopt);
	snapshot->plan_index.assign(route_count, std::nullopt);
	for (size_t plan_index = 0; plan_index < compiled->routes.size(); ++plan_index) {
		const GuidelineRoutePlan& plan = compiled->routes[plan_index];
		GuidelineRouteHostgroups hostgroups;
		const std::pair<const char*, const GuidelinePool*> pools[] {
			{"all", &plan.all}, {"writer", &plan.writer}, {"reader", &plan.reader}};
		for (const auto& [pool_name, pool] : pools) {
			const std::string role = mysql_router_guideline_hostgroup_role(plan.name, pool_name);
			const int hostgroup = route_hostgroups.at(role);
			const std::string comment = "mysql_router:topology=" + topology.topology_uuid +
				";guideline=" + compiled->source.name + ";route=" + plan.name + ";pool=" + pool_name +
				";generation=" + std::to_string(generation);
			config.owned_hostgroups.push_back(hostgroup);
			config.hostgroup_attributes.push_back({hostgroup, comment});
			for (const auto& member : pool->members) {
				CompiledServer server;
				server.hostgroup_id = hostgroup;
				server.hostname = member.host;
				server.port = member.port;
				server.weight = member.weight;
				server.comment = comment;
				config.servers.push_back(std::move(server));
			}
			if (std::string_view(pool_name) == "all") hostgroups.all = hostgroup;
			else if (std::string_view(pool_name) == "writer") hostgroups.writer = hostgroup;
			else hostgroups.reader = hostgroup;
		}
		snapshot->hostgroups[plan.route_index] = hostgroups;
		snapshot->plan_index[plan.route_index] = plan_index;
	}
	return snapshot;
}
