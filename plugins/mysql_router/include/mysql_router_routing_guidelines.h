#ifndef PROXYSQL_MYSQL_ROUTER_ROUTING_GUIDELINES_H
#define PROXYSQL_MYSQL_ROUTER_ROUTING_GUIDELINES_H

// MySQL Router Routing Guidelines engine (issue #6145).
//
// Pure C++17: depends only on the standard library (and nlohmann json in the
// implementation). No ProxySQL headers, so it can be unit tested in isolation.
//
// The document format and the expression language follow MySQL Router's
// routing_guidelines library (document versions "1.0" and "1.1"). See
// docs/superpowers/specs/2026-09-17-mysql-router-routing-guidelines-design.md
// sections 3 and 6.1.
//
// Thread safety: a parsed Guideline (and a compiled Expression) is immutable;
// all const member functions may be called concurrently from any number of
// threads.

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mysql_router::rg {

enum class MemberRole { undefined, primary, secondary, read_replica };
enum class ClusterRole { undefined, primary, replica };
enum class Strategy { round_robin, first_available };

// `path` is a JSON path such as "routes[1].destinations[0].classes[1]" for
// document errors, "destinations.<name>" / "route.<name>" for evaluation
// errors (MySQL Router's format), and may be empty for document-wide errors.
struct Error {
	std::string path;
	std::string message;
};

struct RouterInfo {
	uint16_t port_ro {0}, port_rw {0}, port_rw_split {0};
	std::string local_cluster, hostname, bind_address, route_name, name;
	std::map<std::string, std::string> tags; /* raw JSON text values */
};

struct ServerInfo {
	std::string label, address, uuid, cluster_name, cluster_set_name;
	uint16_t port {0};
	uint32_t version {0};
	MemberRole member_role {MemberRole::undefined};
	ClusterRole cluster_role {ClusterRole::undefined};
	bool is_cluster_invalidated {false};
	std::map<std::string, std::string> tags; /* raw JSON text values */
};

struct SessionInfo {
	std::string target_ip, source_ip, user, schema;
	uint16_t target_port {0};
	double random_value {0};
	std::map<std::string, std::string> connect_attrs;
};

struct DestinationGroup {
	std::vector<std::string> classes;
	Strategy strategy {Strategy::round_robin};
	uint64_t priority {0};
};

struct Route {
	std::string name, match;
	bool enabled {true};
	std::optional<bool> connection_sharing_allowed;
	std::vector<DestinationGroup> groups; /* stable sorted by priority */
};

struct Destination {
	std::string name, match;
};

// Resolves `host` for RESOLVE_V4 (ipv6 == false) / RESOLVE_V6 (ipv6 == true).
// Returns the textual address or std::nullopt when resolution fails.
using Resolver = std::function<std::optional<std::string>(const std::string& host, bool ipv6)>;

// Default resolver: getaddrinfo(), first address of the requested family.
std::optional<std::string> resolve_host(const std::string& host, bool ipv6);

// "path: message" (or just "message" with an empty path), MySQL Router style.
std::string format_error(const Error& error);

// ---------------------------------------------------------------------------
// Expression language (exposed mainly for diagnostics and unit tests).
// ---------------------------------------------------------------------------

enum class ValueType { null, number, string, boolean, role };

struct Value {
	ValueType type {ValueType::null};
	double number {0};    // number, boolean (0/1)
	std::string string;   // string, role
	// MySQL Router boolean coercion: number != 0, non-empty string,
	// role != UNDEFINED, NULL is false.
	bool truthy() const;
};

// Where a match expression is used. `destination` forbids $.session.*,
// `route` forbids $.server.*; both require the expression to evaluate to a
// boolean. `any` applies neither restriction (diagnostics/tests).
enum class ExpressionScope { destination, route, any };

namespace detail {
struct ExpressionAccess;
}

class Expression {
public:
	struct Impl;

	// Compiles `code` for the given document version ("1.0", "1.1", ...).
	// Returns std::nullopt and appends Router-style messages to `errors` on
	// failure. RESOLVE_V4/RESOLVE_V6 hosts are resolved here with `resolver`
	// (resolve_host() when empty); unresolved hosts fail at evaluation time.
	static std::optional<Expression> compile(std::string_view code, ExpressionScope scope,
		std::string_view version, std::vector<std::string>& errors,
		const Resolver& resolver = Resolver());

	// Evaluates the expression. Any of the info pointers may be null (the
	// corresponding variables evaluate to NULL). Throws std::runtime_error
	// with a Router-style message on evaluation errors.
	Value evaluate(const ServerInfo* server, const SessionInfo* session,
		const RouterInfo* router) const;
	// evaluate(...).truthy() without materializing the result value.
	bool matches(const ServerInfo* server, const SessionInfo* session,
		const RouterInfo* router) const;

	const std::string& text() const;
	// True if the (constant folded) expression references the variable,
	// e.g. "router.routeName" or "session.connectAttrs.program_name".
	bool references(std::string_view variable) const;
	// True if the whole expression was folded to a constant at compile time.
	bool is_constant() const;

private:
	friend struct detail::ExpressionAccess;
	explicit Expression(std::shared_ptr<const Impl> impl) : impl_(std::move(impl)) {}
	std::shared_ptr<const Impl> impl_;
};

// ---------------------------------------------------------------------------
// Routing Guidelines document.
// ---------------------------------------------------------------------------

class Guideline {  // immutable after parse
public:
	// Parses and validates a document. Returns nullptr when any error was
	// found; all errors are appended to `errors`.
	static std::shared_ptr<const Guideline> parse(std::string_view json, std::vector<Error>& errors);
	static std::shared_ptr<const Guideline> parse(std::string_view json, std::vector<Error>& errors,
		const Resolver& resolver);

	const std::string& name() const;
	const std::string& version() const;
	const std::vector<Destination>& destinations() const;
	const std::vector<Route>& routes() const;
	bool uses_router_route_name_in_destinations() const;
	// class names (destination order) matching the server; errors appended
	std::vector<std::string> classify(const ServerInfo&, const RouterInfo&, std::vector<Error>&) const;
	// index of first enabled matching route, nullopt if none; any error => nullopt + errors
	std::optional<size_t> match_route(const SessionInfo&, const RouterInfo&, std::vector<Error>&) const;

	struct Private;
	explicit Guideline(std::unique_ptr<Private> p);
	~Guideline();
	Guideline(const Guideline&) = delete;
	Guideline& operator=(const Guideline&) = delete;

private:
	std::unique_ptr<Private> p_;
};

constexpr const char* kSupportedVersion = "1.1";

}  // namespace mysql_router::rg

#endif  // PROXYSQL_MYSQL_ROUTER_ROUTING_GUIDELINES_H
