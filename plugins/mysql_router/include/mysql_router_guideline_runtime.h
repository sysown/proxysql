#ifndef PROXYSQL_MYSQL_ROUTER_GUIDELINE_RUNTIME_H
#define PROXYSQL_MYSQL_ROUTER_GUIDELINE_RUNTIME_H

// Routing Guidelines runtime for the mysql_router plugin (#6145).
//
// Destinations are classified against the live topology at reconcile time and
// every enabled route gets three plugin-owned hostgroups ("all", "writer",
// "reader"). Routes are selected per client session by the ABI-10 route hook,
// which remaps the plugin baseline destinations (route_writer/route_reader) to
// the selected route's hostgroups. See
// docs/superpowers/specs/2026-09-17-mysql-router-routing-guidelines-design.md.

#include "mysql_router_bootstrap.h"
#include "mysql_router_routing_guidelines.h"
#include "mysql_router_types.h"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

struct ProxySQL_PluginRouteHookPayload;
struct ProxySQL_PluginRouteHookResult;

// Router's bootstrap section names, used for $.router.routeName in routes.
inline constexpr const char* kMysqlRouterRouteNameRw = "bootstrap_rw";
inline constexpr const char* kMysqlRouterRouteNameRo = "bootstrap_ro";
inline constexpr const char* kMysqlRouterRouteNameRwSplit = "bootstrap_rw_split";

struct GuidelinePoolMember {
	std::string server_uuid;
	std::string host;
	uint16_t port {0};
	int weight {1};
};

struct GuidelinePool {
	std::vector<GuidelinePoolMember> members;
	std::string strategy;          // "round-robin" / "first-available", empty when unselected
	std::optional<uint64_t> priority;
	std::vector<std::string> classes;
};

struct GuidelineRoutePlan {
	size_t route_index {0};
	std::string name;
	std::string match;
	bool enabled {true};
	std::optional<bool> connection_sharing_allowed;
	GuidelinePool all;
	GuidelinePool writer;
	GuidelinePool reader;
	std::string notes;
};

struct GuidelineDestinationRow {
	std::string server_uuid;
	std::string endpoint;
	std::string member_role;
	std::string classes;       // comma separated, destination order
};

// Result of evaluating a parsed guideline against a topology.
struct CompiledGuideline {
	RoutingGuidelineSource source;
	std::shared_ptr<const mysql_router::rg::Guideline> guideline;
	mysql_router::rg::RouterInfo router;   // route_name left empty
	std::vector<GuidelineRoutePlan> routes; // enabled routes only
	std::vector<GuidelineDestinationRow> destinations;
	bool stale {false};                    // last valid guideline kept after an invalid update
	std::string fingerprint;
};

struct GuidelineCompileOutcome {
	std::shared_ptr<const CompiledGuideline> compiled;
	// "none", "active", "stale", "invalid"
	std::string state {"none"};
	std::string error_kind;                // guideline_parse / guideline_validation / guideline_evaluation
	std::string error_message;
};

// Keeps the last valid parsed guideline and memoizes parsing by document text.
class GuidelineCompiler {
public:
	GuidelineCompileOutcome compile(const DesiredTopology& desired,
		const EffectiveTopology& effective, const ListenerProfile& listeners);

private:
	std::string last_document_;
	RoutingGuidelineSource last_valid_source_;
	std::shared_ptr<const mysql_router::rg::Guideline> last_valid_;
	std::vector<mysql_router::rg::Error> last_errors_;
};

// Pure pool computation, exposed for unit tests.
std::vector<GuidelineRoutePlan> mysql_router_guideline_route_plans(
	const mysql_router::rg::Guideline& guideline, const DesiredTopology& desired,
	const EffectiveTopology& effective, const mysql_router::rg::RouterInfo& router,
	std::vector<GuidelineDestinationRow>& destinations,
	std::vector<mysql_router::rg::Error>& errors);

// Hostgroup assignment of one route plan.
struct GuidelineRouteHostgroups {
	int all {0};
	int writer {0};
	int reader {0};
};

// Immutable view used by the data-plane hook.
struct GuidelineRoutingSnapshot {
	uint32_t generation {0};
	std::shared_ptr<const CompiledGuideline> compiled;
	std::string bind_address;
	uint16_t rw_port {0};
	uint16_t ro_port {0};
	uint16_t rw_split_port {0};
	int route_writer_hostgroup {0};
	int route_reader_hostgroup {0};
	// indexed by Guideline::routes() index; nullopt for disabled routes
	std::vector<std::optional<GuidelineRouteHostgroups>> hostgroups;
	std::vector<std::optional<size_t>> plan_index;
};

// Publishes (or clears, with nullptr) the snapshot read by the route hook.
void mysql_router_set_guideline_snapshot(std::shared_ptr<GuidelineRoutingSnapshot> snapshot);
std::shared_ptr<const GuidelineRoutingSnapshot> mysql_router_guideline_snapshot();

// Session attributes decoupled from the ABI payload, for unit tests.
struct GuidelineSessionRequest {
	std::string user;
	std::string schema;
	std::string client_ip;
	uint16_t proxy_port {0};
	std::map<std::string, std::string> connect_attrs;
	int destination_hostgroup {-1};
	uint64_t session_cookie {0};
};

struct GuidelineRouteDecision {
	enum class Action { unchanged, set_hostgroup, deny } action {Action::unchanged};
	int hostgroup {-1};
	uint64_t session_cookie {0};
	std::string message;
};

GuidelineRouteDecision mysql_router_decide_route(const GuidelineRoutingSnapshot* snapshot,
	const GuidelineSessionRequest& request, double random_value);

// ABI-10 hook entry point registered by the plugin.
ProxySQL_PluginRouteHookResult mysql_router_route_hook(const ProxySQL_PluginRouteHookPayload& payload);

// Hostgroup role names used in mysql_router_hostgroups for a route.
std::string mysql_router_guideline_hostgroup_role(const std::string& route_name, const char* pool);

// Guideline to include in the next publication (set by the reconciler before it
// publishes; nullptr publishes no route hostgroups and disables the hook).
void mysql_router_set_pending_guideline(std::shared_ptr<const CompiledGuideline> compiled);
std::shared_ptr<const CompiledGuideline> mysql_router_pending_guideline();

class CompiledMysqlConfig;
struct ManagedHostgroups;

// Roles ("rg:<route>:all|writer|reader") needed by the compiled guideline.
std::set<std::string> mysql_router_guideline_roles(const CompiledGuideline& compiled);

// Appends route hostgroups and servers to `config` and returns the snapshot to
// activate once the configuration has been applied.
std::shared_ptr<GuidelineRoutingSnapshot> mysql_router_append_guideline_config(
	CompiledMysqlConfig& config, std::shared_ptr<const CompiledGuideline> compiled,
	const ManagedHostgroups& route_hostgroups, const ManagedHostgroups& baseline_hostgroups,
	const DesiredTopology& topology, const ListenerProfile& listeners, uint64_t generation);

#endif
