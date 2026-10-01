// MySQL Router Routing Guidelines: expression language (lexer, parser, type
// checker, constant folding and evaluator).
//
// The language and its observable behaviour (precedence, typing rules, error
// messages, NULL handling, short-circuit evaluation, LIKE translation, ...)
// follow MySQL Router's routing_guidelines library (bison grammar parser.yy,
// rules_parser.cc and rpn.cc). This is an independent implementation: a
// hand-written lexer and a precedence-climbing parser build a typed AST that
// is folded at compile time and evaluated recursively without mutable shared
// state, so a compiled expression can be evaluated concurrently.

#include "mysql_router_routing_guidelines.h"
#include "mysql_router_routing_guidelines_detail.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <climits>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <regex>
#include <stdexcept>
#include <utility>

namespace mysql_router::rg {

namespace detail {
struct ExpressionAccess {
	static Expression make(std::shared_ptr<const Expression::Impl> impl) {
		return Expression(std::move(impl));
	}
};
} // namespace detail

namespace {

// ---------------------------------------------------------------------------
// String helpers (ASCII case-insensitive, like Router).
// ---------------------------------------------------------------------------

inline int lower_char(char c) {
	return std::tolower(static_cast<unsigned char>(c));
}

bool caseeq(std::string_view a, std::string_view b) {
	if (a.size() != b.size()) return false;
	for (size_t i = 0; i < a.size(); i++) {
		if (lower_char(a[i]) != lower_char(b[i])) return false;
	}
	return true;
}

int casecmp(std::string_view a, std::string_view b) {
	const size_t n = std::min(a.size(), b.size());
	for (size_t i = 0; i < n; i++) {
		const int l = lower_char(a[i]);
		const int r = lower_char(b[i]);
		if (l != r) return l - r;
	}
	if (a.size() == b.size()) return 0;
	return a.size() < b.size() ? -1 : 1;
}

bool istarts_with(std::string_view s, std::string_view prefix) {
	return s.size() >= prefix.size() && caseeq(s.substr(0, prefix.size()), prefix);
}

bool iends_with(std::string_view s, std::string_view suffix) {
	return s.size() >= suffix.size() && caseeq(s.substr(s.size() - suffix.size()), suffix);
}

bool icontains(std::string_view s, std::string_view needle) {
	for (size_t i = 0; i + needle.size() <= s.size(); i++) {
		if (caseeq(s.substr(i, needle.size()), needle)) return true;
	}
	return false;
}

std::string to_upper(std::string_view s) {
	std::string r(s);
	for (auto& c : r) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	return r;
}

std::string to_lower(std::string_view s) {
	std::string r(s);
	for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return r;
}

bool starts_with(std::string_view s, std::string_view prefix) {
	return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

// MySQL style unescaping: \n \t \r \b \0 \Z are translated, any other
// escaped character stands for itself.
std::string unescape(std::string_view s) {
	std::string res;
	res.reserve(s.size());
	for (size_t i = 0; i < s.size(); i++) {
		if (s[i] == '\\' && i + 1 < s.size()) {
			switch (s[++i]) {
			case 'n': res.push_back('\n'); break;
			case 't': res.push_back('\t'); break;
			case 'r': res.push_back('\r'); break;
			case 'b': res.push_back('\b'); break;
			case '0': res.push_back('\0'); break;
			case 'Z': res.push_back('\032'); break;
			default: res.push_back(s[i]);
			}
		} else {
			res.push_back(s[i]);
		}
	}
	return res;
}

// LIKE pattern to ECMAScript regular expression (full match).
std::string like_to_regexp(std::string_view pattern) {
	std::string rgx;
	for (size_t i = 0; i < pattern.size(); i++) {
		const char c = pattern[i];
		switch (c) {
		case '.': case '*': case '+': case '?': case '{': case '}': case '(':
		case ')': case '[': case ']': case '^': case '$': case '|':
			rgx.push_back('\\');
			rgx.push_back(c);
			break;
		case '%':
			rgx.append(".*");
			break;
		case '_':
			rgx.push_back('.');
			break;
		case '\\':
			if (i + 1 < pattern.size() && pattern[i + 1] == '\\') {
				rgx.append("\\\\");
				i++;
			} else if (i + 1 < pattern.size() && (pattern[i + 1] == '%' || pattern[i + 1] == '_')) {
				rgx.push_back(pattern[++i]);
			} else {
				rgx.append("\\\\");
			}
			break;
		default:
			rgx.push_back(c);
		}
	}
	return rgx;
}

int numeric_family(const std::string& address) {
	addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	addrinfo* info = nullptr;
	if (getaddrinfo(address.c_str(), nullptr, &hints, &info) != 0) return AF_UNSPEC;
	const int family = info->ai_family;
	freeaddrinfo(info);
	return family;
}

bool is_ipv4(std::string_view address) {
	return numeric_family(std::string(address)) == AF_INET;
}

bool is_ipv6(std::string_view host) {
	if (host.empty() || host[0] == '[') return false;
	// zone ids are handled differently by getaddrinfo() implementations
	return numeric_family(std::string(host.substr(0, host.find('%')))) == AF_INET6;
}

std::string network(std::string_view address, int bits) {
	if (bits < 1 || bits > 32) {
		throw std::runtime_error("Valid mask length for IPv4 address is between 1 and 32");
	}
	const std::string addr(address);
	in_addr sa;
	if (inet_pton(AF_INET, addr.c_str(), &sa) <= 0) {
		throw std::runtime_error("Network function called on invalid IPv4 address: '" + addr + "'");
	}
	const uint32_t mask = htonl(static_cast<uint32_t>((0xFFFFFFFFULL << (32 - bits)) & 0xFFFFFFFFULL));
	sa.s_addr &= mask;
	char out[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &sa, out, sizeof(out)) == nullptr) {
		throw std::runtime_error("Unable to convert address to string");
	}
	return out;
}

bool valid_hostname(std::string_view host) {
	if (host.empty()) return false;
	size_t start = 0;
	while (true) {
		size_t dot = host.find('.', start);
		std::string_view label = host.substr(start, dot == std::string_view::npos ? host.npos : dot - start);
		if (label.empty()) return false;
		if (!std::isalnum(static_cast<unsigned char>(label.front()))) return false;
		if (!std::isalnum(static_cast<unsigned char>(label.back()))) return false;
		for (char c : label) {
			if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-') return false;
		}
		if (dot == std::string_view::npos) return true;
		start = dot + 1;
	}
}

int clamp_to_int(double d) {
	if (std::isnan(d)) return 0;
	if (d >= static_cast<double>(INT_MAX)) return INT_MAX;
	if (d <= -static_cast<double>(INT_MAX)) return -INT_MAX;
	return static_cast<int>(d);
}

std::string format_number(double d) {
	// same as the default formatting of std::ostream << double
	char buf[64];
	std::snprintf(buf, sizeof(buf), "%g", d);
	return buf;
}

const char* type_name(ValueType t) {
	switch (t) {
	case ValueType::number: return "NUMBER";
	case ValueType::string: return "STRING";
	case ValueType::boolean: return "BOOLEAN";
	case ValueType::role: return "ROLE";
	case ValueType::null: return "NULL";
	}
	return "UNKNOWN";
}

std::string located(std::string msg, const std::string& code, size_t b, size_t e) {
	if (!msg.empty() && msg.back() == '.') msg.back() = ',';
	if (e < b + 2) {
		msg += " (character " + std::to_string(b + 1) + ")";
	} else {
		msg += " in '" + (b < code.size() ? code.substr(b, e - b) : std::string()) + "'";
	}
	return msg;
}

// ---------------------------------------------------------------------------
// Language tables.
// ---------------------------------------------------------------------------

constexpr const char* kUndefinedRole = "UNDEFINED";
const std::array<const char*, 4> kMemberRoles {"UNDEFINED", "PRIMARY", "SECONDARY", "READ_REPLICA"};
const std::array<const char*, 3> kClusterRoles {"UNDEFINED", "PRIMARY", "REPLICA"};

bool is_member_role(std::string_view s) {
	for (const char* r : kMemberRoles) if (caseeq(s, r)) return true;
	return false;
}

bool is_cluster_role(std::string_view s) {
	for (const char* r : kClusterRoles) if (caseeq(s, r)) return true;
	return false;
}

const char* member_role_name(MemberRole r) {
	switch (r) {
	case MemberRole::primary: return "PRIMARY";
	case MemberRole::secondary: return "SECONDARY";
	case MemberRole::read_replica: return "READ_REPLICA";
	case MemberRole::undefined: break;
	}
	return kUndefinedRole;
}

const char* cluster_role_name(ClusterRole r) {
	switch (r) {
	case ClusterRole::primary: return "PRIMARY";
	case ClusterRole::replica: return "REPLICA";
	case ClusterRole::undefined: break;
	}
	return kUndefinedRole;
}

enum class VarScope : uint8_t { router, server, session };

enum class VarId : uint8_t {
	router_local_cluster, router_hostname, router_bind_address, router_port_ro, router_port_rw,
	router_port_rw_split, router_route_name, router_name,
	server_label, server_address, server_port, server_uuid, server_version, server_cluster_name,
	server_cluster_set_name, server_is_cluster_invalidated, server_member_role, server_cluster_role,
	session_target_ip, session_target_port, session_source_ip, session_random_value, session_user,
	session_schema
};

struct VarDef {
	const char* name;
	VarId id;
	VarScope scope;
	ValueType type;
};

const VarDef kVariables[] = {
	{"router.localCluster", VarId::router_local_cluster, VarScope::router, ValueType::string},
	{"router.hostname", VarId::router_hostname, VarScope::router, ValueType::string},
	{"router.bindAddress", VarId::router_bind_address, VarScope::router, ValueType::string},
	{"router.port.ro", VarId::router_port_ro, VarScope::router, ValueType::number},
	{"router.port.rw", VarId::router_port_rw, VarScope::router, ValueType::number},
	{"router.port.rw_split", VarId::router_port_rw_split, VarScope::router, ValueType::number},
	{"router.routeName", VarId::router_route_name, VarScope::router, ValueType::string},
	{"router.name", VarId::router_name, VarScope::router, ValueType::string},
	{"server.label", VarId::server_label, VarScope::server, ValueType::string},
	{"server.address", VarId::server_address, VarScope::server, ValueType::string},
	{"server.port", VarId::server_port, VarScope::server, ValueType::number},
	{"server.uuid", VarId::server_uuid, VarScope::server, ValueType::string},
	{"server.version", VarId::server_version, VarScope::server, ValueType::number},
	{"server.clusterName", VarId::server_cluster_name, VarScope::server, ValueType::string},
	{"server.clusterSetName", VarId::server_cluster_set_name, VarScope::server, ValueType::string},
	{"server.isClusterInvalidated", VarId::server_is_cluster_invalidated, VarScope::server, ValueType::boolean},
	{"server.memberRole", VarId::server_member_role, VarScope::server, ValueType::role},
	{"server.clusterRole", VarId::server_cluster_role, VarScope::server, ValueType::role},
	{"session.targetIP", VarId::session_target_ip, VarScope::session, ValueType::string},
	{"session.targetPort", VarId::session_target_port, VarScope::session, ValueType::number},
	{"session.sourceIP", VarId::session_source_ip, VarScope::session, ValueType::string},
	{"session.randomValue", VarId::session_random_value, VarScope::session, ValueType::number},
	{"session.user", VarId::session_user, VarScope::session, ValueType::string},
	{"session.schema", VarId::session_schema, VarScope::session, ValueType::string},
};

enum class TagScope : uint8_t { router_tags, server_tags, connect_attrs, sql_query_tags, sql_query_hints };

enum class Fn : uint8_t {
	sqrt, number, is_ipv4, is_ipv6, regexp_like, substring_index, startswith, endswith, contains,
	resolve_v4, resolve_v6, concat, network
};

struct FnDef {
	const char* name;
	Fn fn;
	std::vector<ValueType> args;
	ValueType ret;
};

const std::vector<FnDef>& functions() {
	static const std::vector<FnDef> defs {
		{"SQRT", Fn::sqrt, {ValueType::number}, ValueType::number},
		{"NUMBER", Fn::number, {ValueType::string}, ValueType::number},
		{"IS_IPV4", Fn::is_ipv4, {ValueType::string}, ValueType::boolean},
		{"IS_IPV6", Fn::is_ipv6, {ValueType::string}, ValueType::boolean},
		{"REGEXP_LIKE", Fn::regexp_like, {ValueType::string, ValueType::string}, ValueType::boolean},
		{"SUBSTRING_INDEX", Fn::substring_index, {ValueType::string, ValueType::string, ValueType::number}, ValueType::string},
		{"STARTSWITH", Fn::startswith, {ValueType::string, ValueType::string}, ValueType::boolean},
		{"ENDSWITH", Fn::endswith, {ValueType::string, ValueType::string}, ValueType::boolean},
		{"CONTAINS", Fn::contains, {ValueType::string, ValueType::string}, ValueType::boolean},
		{"RESOLVE_V4", Fn::resolve_v4, {ValueType::string}, ValueType::string},
		{"RESOLVE_V6", Fn::resolve_v6, {ValueType::string}, ValueType::string},
		{"CONCAT", Fn::concat, {}, ValueType::string},
		{"NETWORK", Fn::network, {ValueType::string, ValueType::number}, ValueType::string},
	};
	return defs;
}

const FnDef& fn_def(Fn fn) {
	return functions()[static_cast<size_t>(fn)];
}

// ---------------------------------------------------------------------------
// Runtime values.
// ---------------------------------------------------------------------------

// Evaluation value: strings are views into the compiled expression or the
// evaluated info structures when possible, owned only when computed.
struct RVal {
	ValueType t {ValueType::null};
	bool owns {false};
	double n {0};
	std::string_view sv;
	std::string own;

	std::string_view s() const { return owns ? std::string_view(own) : sv; }

	static RVal null() { return RVal(); }
	static RVal num(double v) {
		RVal r;
		r.t = ValueType::number;
		r.n = v;
		return r;
	}
	static RVal boolean(bool b) {
		RVal r;
		r.t = ValueType::boolean;
		r.n = b ? 1.0 : 0.0;
		return r;
	}
	static RVal view(ValueType t, std::string_view v) {
		RVal r;
		r.t = t;
		r.sv = v;
		return r;
	}
	static RVal owned(std::string v) {
		RVal r;
		r.t = ValueType::string;
		r.owns = true;
		r.own = std::move(v);
		return r;
	}
};

bool truthy(ValueType t, double n, std::string_view s) {
	switch (t) {
	case ValueType::number:
	case ValueType::boolean:
		return std::fabs(n) > std::numeric_limits<double>::epsilon();
	case ValueType::role:
		return !caseeq(s, kUndefinedRole);
	case ValueType::string:
		return !s.empty();
	case ValueType::null:
		break;
	}
	return false;
}

bool truthy(const RVal& v) {
	return truthy(v.t, v.n, v.s());
}

[[noreturn]] void incompatible(const RVal& l, const RVal& r) {
	throw std::runtime_error(std::string("Incompatible operands for comparison: '") +
		type_name(l.t) + "' vs '" + type_name(r.t) + "'");
}

bool val_eq(const RVal& l, const RVal& r) {
	if (l.t != r.t) {
		if (l.t == ValueType::null || r.t == ValueType::null) return false;
		if (l.t == ValueType::boolean || r.t == ValueType::boolean) return truthy(l) == truthy(r);
		incompatible(l, r);
	}
	switch (l.t) {
	case ValueType::number:
	case ValueType::boolean:
		return l.n == r.n;
	case ValueType::null:
		return true;
	case ValueType::role:
	case ValueType::string:
		return caseeq(l.s(), r.s());
	}
	return false;
}

bool val_lt(const RVal& l, const RVal& r) {
	if (l.t != r.t) {
		if (l.t == ValueType::null || r.t == ValueType::null) return false;
		incompatible(l, r);
	}
	if (l.t == ValueType::number) return l.n < r.n;
	if (l.t == ValueType::string) return casecmp(l.s(), r.s()) < 0;
	if (l.t == ValueType::null) return false;
	throw std::runtime_error("Only strings and numbers can be compared");
}

bool val_le(const RVal& l, const RVal& r) {
	if (l.t != r.t) {
		if (l.t == ValueType::null || r.t == ValueType::null) return false;
		incompatible(l, r);
	}
	if (l.t == ValueType::number) return l.n <= r.n;
	if (l.t == ValueType::string) return casecmp(l.s(), r.s()) <= 0;
	if (l.t == ValueType::null) return false;
	throw std::runtime_error("Only strings and numbers can be compared");
}

std::string substring_index(std::string_view str, std::string_view delim, double count) {
	const int index = clamp_to_int(count);
	if (index == 0 || delim.empty()) return std::string();
	if (index < 0) {
		size_t pos = str.rfind(delim);
		for (int i = 1; pos != std::string_view::npos && i < -index; i++) {
			pos = pos == 0 ? std::string_view::npos : str.rfind(delim, pos - 1);
		}
		if (pos != std::string_view::npos) return std::string(str.substr(pos + delim.size()));
		return std::string(str);
	}
	size_t pos = str.find(delim);
	for (int i = 1; pos != std::string_view::npos && i < index; i++) {
		pos = str.find(delim, pos + 1);
	}
	if (pos != std::string_view::npos) return std::string(str.substr(0, pos));
	return std::string(str);
}

// Scalar functions (all arguments are non-NULL and of the declared types).
RVal call_function(Fn fn, const RVal* args) {
	switch (fn) {
	case Fn::sqrt:
		return RVal::num(std::sqrt(args[0].n));
	case Fn::number: {
		const std::string s(args[0].s());
		char* end = nullptr;
		const double v = std::strtod(s.c_str(), &end);
		if (*end != '\0') {
			throw std::runtime_error("NUMBER function, unable to convert '" + s + "' to number");
		}
		return RVal::num(v);
	}
	case Fn::is_ipv4:
		return RVal::boolean(is_ipv4(args[0].s()));
	case Fn::is_ipv6:
		return RVal::boolean(is_ipv6(args[0].s()));
	case Fn::regexp_like: {
		const std::regex re(std::string(args[1].s()), std::regex_constants::icase | std::regex::ECMAScript);
		const std::string_view subject = args[0].s();
		return RVal::boolean(std::regex_match(subject.begin(), subject.end(), re));
	}
	case Fn::substring_index:
		return RVal::owned(substring_index(args[0].s(), args[1].s(), args[2].n));
	case Fn::startswith:
		return RVal::boolean(istarts_with(args[0].s(), args[1].s()));
	case Fn::endswith:
		return RVal::boolean(iends_with(args[0].s(), args[1].s()));
	case Fn::contains:
		return RVal::boolean(icontains(args[0].s(), args[1].s()));
	case Fn::resolve_v4:
	case Fn::resolve_v6:
	case Fn::concat:
	case Fn::network:
		break;
	}
	throw std::runtime_error("unsupported function");
}

// Thrown for fully formatted evaluation errors (not to be re-located).
class EvalError : public std::runtime_error {
public:
	using std::runtime_error::runtime_error;
};

class ParseError : public std::runtime_error {
public:
	using std::runtime_error::runtime_error;
};

enum class Op : uint8_t {
	constant, var, tag, neg, add, sub, mul, div, mod, lt, gt, le, ge, eq, ne, in, not_, and_, or_,
	func, regex, resolve, concat, network
};

struct Node {
	Op op {Op::constant};
	ValueType type {ValueType::null};  // static type
	bool has_loc {false};              // errors raised by this node carry a location
	VarId var {VarId::router_name};
	TagScope tag {TagScope::router_tags};
	Fn fn {Fn::sqrt};
	size_t b {0}, e {0};    // node location
	size_t xb {0}, xe {0};  // location as an operand (parentheses included)
	double num {0};         // constant number/boolean, NETWORK netmask
	std::string str;        // constant string/role, tag key, resolved address
	std::string name;       // referenced variable name, resolved host name
	bool resolved {false};
	uint32_t regex {0};
	uint32_t depth {1};     // height of the subtree (bounds evaluation recursion)
	std::vector<uint32_t> kids;
};

// Evaluation recurses once per tree level on the (possibly small) stack of a
// worker thread, so expression nesting is bounded. AND/OR chains are n-ary
// and do not count towards this limit.
constexpr uint32_t kMaxExpressionDepth = 200;

struct EvalCtx {
	const ServerInfo* server;
	const SessionInfo* session;
	const RouterInfo* router;
	bool dry_run;
};

} // namespace

struct Expression::Impl {
	std::string text;      // original expression
	std::string loc_text;  // text used for error locations (Router quirk: tag quotes rewritten)
	std::vector<Node> nodes;
	std::vector<std::regex> regexes;
	uint32_t root {0};

	RVal eval(uint32_t idx, const EvalCtx& ctx) const;
	RVal eval_node(const Node& n, const EvalCtx& ctx) const;
	RVal eval_in(const Node& n, const EvalCtx& ctx) const;
	RVal eval_func(const Node& n, const EvalCtx& ctx) const;
	RVal eval_concat(const Node& n, const EvalCtx& ctx) const;
	bool references(uint32_t idx, std::string_view name) const;
};

namespace {

RVal eval_var(VarId id, const EvalCtx& c) {
	switch (id) {
	case VarId::router_local_cluster: return c.router ? RVal::view(ValueType::string, c.router->local_cluster) : RVal::null();
	case VarId::router_hostname: return c.router ? RVal::view(ValueType::string, c.router->hostname) : RVal::null();
	case VarId::router_bind_address: return c.router ? RVal::view(ValueType::string, c.router->bind_address) : RVal::null();
	case VarId::router_port_ro: return c.router ? RVal::num(c.router->port_ro) : RVal::null();
	case VarId::router_port_rw: return c.router ? RVal::num(c.router->port_rw) : RVal::null();
	case VarId::router_port_rw_split: return c.router ? RVal::num(c.router->port_rw_split) : RVal::null();
	case VarId::router_route_name: return c.router ? RVal::view(ValueType::string, c.router->route_name) : RVal::null();
	case VarId::router_name: return c.router ? RVal::view(ValueType::string, c.router->name) : RVal::null();
	case VarId::server_label: return c.server ? RVal::view(ValueType::string, c.server->label) : RVal::null();
	case VarId::server_address: return c.server ? RVal::view(ValueType::string, c.server->address) : RVal::null();
	case VarId::server_port: return c.server ? RVal::num(c.server->port) : RVal::null();
	case VarId::server_uuid: return c.server ? RVal::view(ValueType::string, c.server->uuid) : RVal::null();
	case VarId::server_version: return c.server ? RVal::num(c.server->version) : RVal::null();
	case VarId::server_cluster_name: return c.server ? RVal::view(ValueType::string, c.server->cluster_name) : RVal::null();
	case VarId::server_cluster_set_name: return c.server ? RVal::view(ValueType::string, c.server->cluster_set_name) : RVal::null();
	case VarId::server_is_cluster_invalidated: return c.server ? RVal::boolean(c.server->is_cluster_invalidated) : RVal::null();
	case VarId::server_member_role: return c.server ? RVal::view(ValueType::role, member_role_name(c.server->member_role)) : RVal::null();
	case VarId::server_cluster_role: return c.server ? RVal::view(ValueType::role, cluster_role_name(c.server->cluster_role)) : RVal::null();
	case VarId::session_target_ip: return c.session ? RVal::view(ValueType::string, c.session->target_ip) : RVal::null();
	case VarId::session_target_port: return c.session ? RVal::num(c.session->target_port) : RVal::null();
	case VarId::session_source_ip: return c.session ? RVal::view(ValueType::string, c.session->source_ip) : RVal::null();
	case VarId::session_random_value: return c.session ? RVal::num(c.session->random_value) : RVal::null();
	case VarId::session_user: return c.session ? RVal::view(ValueType::string, c.session->user) : RVal::null();
	case VarId::session_schema: return c.session ? RVal::view(ValueType::string, c.session->schema) : RVal::null();
	}
	return RVal::null();
}

RVal eval_tag(const Node& n, const EvalCtx& c) {
	const std::map<std::string, std::string>* values = nullptr;
	switch (n.tag) {
	case TagScope::router_tags: values = c.router ? &c.router->tags : nullptr; break;
	case TagScope::server_tags: values = c.server ? &c.server->tags : nullptr; break;
	case TagScope::connect_attrs: values = c.session ? &c.session->connect_attrs : nullptr; break;
	case TagScope::sql_query_tags:
	case TagScope::sql_query_hints:
		break;  // $.sql.* is never populated when routing new connections
	}
	if (values == nullptr) return RVal::null();
	const auto it = values->find(n.str);
	if (it == values->end()) return RVal::null();
	return RVal::view(ValueType::string, it->second);
}

const char* math_name(Op op) {
	switch (op) {
	case Op::add: return "addition";
	case Op::sub: return "subtraction";
	case Op::mul: return "multiplication";
	case Op::div: return "division";
	default: return "modulo";
	}
}

} // namespace

RVal Expression::Impl::eval(uint32_t idx, const EvalCtx& ctx) const {
	const Node& n = nodes[idx];
	switch (n.op) {
	case Op::constant:
		if (n.type == ValueType::string || n.type == ValueType::role) return RVal::view(n.type, n.str);
		if (n.type == ValueType::null) return RVal::null();
		{
			RVal r;
			r.t = n.type;
			r.n = n.num;
			return r;
		}
	case Op::var:
		return eval_var(n.var, ctx);
	case Op::tag:
		return eval_tag(n, ctx);
	default:
		break;
	}
	try {
		return eval_node(n, ctx);
	} catch (const EvalError&) {
		throw;
	} catch (const std::exception& e) {
		if (n.has_loc) throw EvalError(located(e.what(), loc_text, n.b, n.e));
		throw EvalError(e.what());
	}
}

RVal Expression::Impl::eval_node(const Node& n, const EvalCtx& ctx) const {
	switch (n.op) {
	case Op::neg: {
		RVal v = eval(n.kids[0], ctx);
		if (v.t == ValueType::null) return v;
		if (v.t != ValueType::number) throw std::runtime_error("only numbers can be negated");
		v.n = -v.n;
		return v;
	}
	case Op::add:
	case Op::sub:
	case Op::mul:
	case Op::div:
	case Op::mod: {
		RVal l = eval(n.kids[0], ctx);
		RVal r = eval(n.kids[1], ctx);
		if (l.t == ValueType::null) return l;
		if (l.t != ValueType::number) {
			throw std::runtime_error(std::string("left operand of ") + math_name(n.op) + " needs to be a number");
		}
		if (r.t == ValueType::null) return r;
		if (r.t != ValueType::number) {
			throw std::runtime_error(std::string("right operand of ") + math_name(n.op) + " needs to be a number");
		}
		switch (n.op) {
		case Op::add: l.n += r.n; break;
		case Op::sub: l.n -= r.n; break;
		case Op::mul: l.n *= r.n; break;
		case Op::div: l.n /= r.n; break;
		default: l.n = std::fmod(l.n, r.n); break;
		}
		return l;
	}
	case Op::lt:
	case Op::gt:
	case Op::le:
	case Op::ge:
	case Op::eq:
	case Op::ne: {
		const RVal l = eval(n.kids[0], ctx);
		const RVal r = eval(n.kids[1], ctx);
		switch (n.op) {
		case Op::lt: return RVal::boolean(val_lt(l, r));
		case Op::gt: return RVal::boolean(val_lt(r, l));
		case Op::le: return RVal::boolean(val_le(l, r));
		case Op::ge: return RVal::boolean(val_le(r, l));
		case Op::eq: return RVal::boolean(val_eq(l, r));
		default: return RVal::boolean(!val_eq(l, r));
		}
	}
	case Op::in:
		return eval_in(n, ctx);
	case Op::not_:
		return RVal::boolean(!truthy(eval(n.kids[0], ctx)));
	case Op::and_: {
		// Router's short-circuit keeps the raw value of a falsy first operand
		RVal first = eval(n.kids[0], ctx);
		if (!truthy(first)) return first;
		for (size_t i = 1; i < n.kids.size(); i++) {
			if (!truthy(eval(n.kids[i], ctx))) return RVal::boolean(false);
		}
		return RVal::boolean(true);
	}
	case Op::or_: {
		RVal first = eval(n.kids[0], ctx);
		if (truthy(first)) return first;
		for (size_t i = 1; i < n.kids.size(); i++) {
			if (truthy(eval(n.kids[i], ctx))) return RVal::boolean(true);
		}
		return RVal::boolean(false);
	}
	case Op::func:
		return eval_func(n, ctx);
	case Op::regex: {
		const RVal v = eval(n.kids[0], ctx);
		if (v.t == ValueType::null) return v;
		if (v.t != ValueType::string) throw std::runtime_error("Type error, expected string");
		const std::string_view s = v.s();
		return RVal::boolean(std::regex_match(s.begin(), s.end(), regexes[n.regex]));
	}
	case Op::resolve:
		if (ctx.dry_run) return RVal::view(ValueType::string, n.name);
		if (n.resolved) return RVal::view(ValueType::string, n.str);
		throw std::runtime_error("No cache entry to resolve host: " + n.name);
	case Op::concat:
		return eval_concat(n, ctx);
	case Op::network: {
		const int mask = clamp_to_int(n.num);
		if (ctx.dry_run) {
			if (mask < 1 || mask > 32) {
				throw std::runtime_error("NETWORK function invalid netmask value: " + std::to_string(mask));
			}
			return RVal::owned(std::to_string(n.num));
		}
		const RVal ip = eval(n.kids[0], ctx);
		if (ip.t != ValueType::string) throw std::runtime_error("Type error, expected string");
		return RVal::owned(network(ip.s(), mask));
	}
	case Op::constant:
	case Op::var:
	case Op::tag:
		break;
	}
	throw std::runtime_error("invalid expression node");
}

// kept out of line so the recursive evaluation frame stays small
[[gnu::noinline]] RVal Expression::Impl::eval_in(const Node& n, const EvalCtx& ctx) const {
	const RVal needle = eval(n.kids[0], ctx);
	const size_t count = n.kids.size() - 1;
	// Router evaluates every element first, then compares from the last one.
	std::array<RVal, 8> small;
	std::vector<RVal> large;
	RVal* elems = small.data();
	if (count > small.size()) {
		large.resize(count);
		elems = large.data();
	}
	for (size_t i = 0; i < count; i++) elems[i] = eval(n.kids[i + 1], ctx);
	bool found = false;
	for (size_t i = count; !found && i > 0; i--) {
		if (val_eq(needle, elems[i - 1])) found = true;
	}
	return RVal::boolean(found);
}

// kept out of line so the recursive evaluation frame stays small
[[gnu::noinline]] RVal Expression::Impl::eval_func(const Node& n, const EvalCtx& ctx) const {
	std::array<RVal, 3> args;
	bool nulls = false;
	const FnDef& def = fn_def(n.fn);
	for (size_t i = 0; i < n.kids.size(); i++) {
		args[i] = eval(n.kids[i], ctx);
		if (args[i].t == ValueType::null) {
			nulls = true;
		} else if (args[i].t != def.args[i]) {
			throw std::runtime_error(std::string("Function ") + def.name + " argument type mismatch");
		}
	}
	if (nulls) return RVal::null();
	return call_function(n.fn, args.data());
}

// kept out of line so the recursive evaluation frame stays small
[[gnu::noinline]] RVal Expression::Impl::eval_concat(const Node& n, const EvalCtx& ctx) const {
	std::vector<RVal> vals;
	vals.reserve(n.kids.size());
	for (const uint32_t k : n.kids) vals.push_back(eval(k, ctx));
	std::string out;
	for (const RVal& v : vals) {
		switch (v.t) {
		case ValueType::null:
			return RVal::null();
		case ValueType::string:
		case ValueType::role:
			out.append(v.s());
			break;
		case ValueType::number:
			out += format_number(v.n);
			break;
		case ValueType::boolean:
			out += truthy(v) ? "1" : "0";
			break;
		}
	}
	return RVal::owned(std::move(out));
}

bool Expression::Impl::references(uint32_t idx, std::string_view name) const {
	const Node& n = nodes[idx];
	if ((n.op == Op::var || n.op == Op::tag) && n.name == name) return true;
	for (const uint32_t k : n.kids) {
		if (references(k, name)) return true;
	}
	return false;
}

namespace {

// ---------------------------------------------------------------------------
// Lexer.
// ---------------------------------------------------------------------------

enum class Kind : uint8_t {
	end, dash, plus, star, slash, percent, lparen, rparen, gt, lt, ge, le, eq, ne, kw_in, kw_like,
	kw_not, kw_and, kw_or, comma, kw_true, kw_false, kw_null, identifier, varref, string, role,
	number, function
};

const char* kind_name(Kind k) {
	switch (k) {
	case Kind::end: return "end of expression";
	case Kind::dash: return "-";
	case Kind::plus: return "+";
	case Kind::star: return "*";
	case Kind::slash: return "/";
	case Kind::percent: return "%";
	case Kind::lparen: return "(";
	case Kind::rparen: return ")";
	case Kind::gt: return ">";
	case Kind::lt: return "<";
	case Kind::ge: return ">=";
	case Kind::le: return "<=";
	case Kind::eq: return "=";
	case Kind::ne: return "<>";
	case Kind::kw_in: return "T_IN";
	case Kind::kw_like: return "T_LIKE";
	case Kind::kw_not: return "T_NOT";
	case Kind::kw_and: return "T_AND";
	case Kind::kw_or: return "T_OR";
	case Kind::comma: return "\",\"";
	case Kind::kw_true: return "T_TRUE";
	case Kind::kw_false: return "T_FALSE";
	case Kind::kw_null: return "T_NULL";
	case Kind::identifier: return "identifier";
	case Kind::varref: return "variable reference";
	case Kind::string: return "string";
	case Kind::role: return "role";
	case Kind::number: return "number";
	case Kind::function: return "function name";
	}
	return "token";
}

struct Token {
	Kind kind {Kind::end};
	size_t b {0}, e {0};
	std::string text;
	double num {0};
	Fn fn {Fn::sqrt};
};

class Lexer {
public:
	Lexer(std::string& buf, bool tags_as_json) : buf_(buf), tags_as_json_(tags_as_json) {}

	void set_tag_mode() { tag_mode_ = true; }
	bool tags_as_json() const { return tags_as_json_; }

	Token next() {
		while (pos_ < buf_.size()) {
			const size_t start = pos_;
			const char c = buf_[pos_++];
			last_b_ = start;
			last_e_ = start + 1;
			switch (c) {
			case '\0': return tok(Kind::end, start, start + 1);
			case '-': return tok(Kind::dash, start, pos_);
			case '+': return tok(Kind::plus, start, pos_);
			case '*': return tok(Kind::star, start, pos_);
			case '/': return tok(Kind::slash, start, pos_);
			case '%': return tok(Kind::percent, start, pos_);
			case '(': return tok(Kind::lparen, start, pos_);
			case ')': return tok(Kind::rparen, start, pos_);
			case '=': return tok(Kind::eq, start, pos_);
			case ',': return tok(Kind::comma, start, pos_);
			case '>':
				if (at(pos_) == '=') {
					pos_++;
					return tok(Kind::ge, start, pos_);
				}
				return tok(Kind::gt, start, pos_);
			case '<':
				if (at(pos_) == '=') {
					pos_++;
					return tok(Kind::le, start, pos_);
				}
				if (at(pos_) == '>') {
					pos_++;
					return tok(Kind::ne, start, pos_);
				}
				return tok(Kind::lt, start, pos_);
			case '$': {
				if (at(pos_) != '.') fail("$ not starting variable reference", start, start + 1);
				bool complex = false;
				const size_t len = span_id(pos_ + 1, complex, start);
				Token t = tok(Kind::varref, start, pos_ + 1 + len);
				t.text = buf_.substr(pos_ + 1, len);
				pos_ += 1 + len;
				return t;
			}
			case '\'':
			case '"': {
				const size_t close = span_quote(start);
				Token t;
				if (toggled()) {
					buf_[start] = '"';
					buf_[close - 1] = '"';
					t = tok(Kind::string, start, close);
					t.text = unescape(std::string_view(buf_).substr(start, close - start));
				} else {
					t = tok(Kind::string, start, close);
					t.text = unescape(std::string_view(buf_).substr(start + 1, close - start - 2));
				}
				pos_ = close;
				return t;
			}
			case '{':
			case '[':
				if (toggled()) {
					const char needle = c == '{' ? '}' : ']';
					size_t close = buf_.find(needle, start + 1);
					if (close == std::string::npos) fail(std::string("unclosed ") + c, start, start + 1);
					close++;
					Token t = tok(Kind::string, start, close);
					t.text = unescape(std::string_view(buf_).substr(start, close - start));
					pos_ = close;
					return t;
				}
				fail(std::string("unexpected character: '") + c + "'", start, start);
			default:
				break;
			}
			const unsigned char uc = static_cast<unsigned char>(c);
			if (std::isspace(uc)) continue;
			if (std::isdigit(uc)) {
				char* end = nullptr;
				const double v = std::strtod(buf_.c_str() + start, &end);
				pos_ = static_cast<size_t>(end - buf_.c_str());
				if (toggled()) {
					Token t = tok(Kind::string, start, pos_);
					t.text = buf_.substr(start, pos_ - start);
					return t;
				}
				Token t = tok(Kind::number, start, pos_);
				t.num = v;
				return t;
			}
			if (std::isalpha(uc)) {
				bool complex = false;
				const size_t len = span_id(start, complex, start);
				pos_ = start + len;
				const std::string word = buf_.substr(start, len);
				if (!complex) {
					const std::string up = to_upper(word);
					Kind kw = Kind::end;
					if (up == "TRUE") kw = Kind::kw_true;
					else if (up == "FALSE") kw = Kind::kw_false;
					else if (up == "NULL") kw = Kind::kw_null;
					else if (up == "IN") kw = Kind::kw_in;
					else if (up == "NOT") kw = Kind::kw_not;
					else if (up == "AND") kw = Kind::kw_and;
					else if (up == "OR") kw = Kind::kw_or;
					else if (up == "LIKE") kw = Kind::kw_like;
					if (kw != Kind::end) {
						// Router quirk (1.1): a keyword right after a tag reference is a string
						Token t = tok(toggled() ? Kind::string : kw, start, pos_);
						t.text = word;
						return t;
					}
					for (const FnDef& f : functions()) {
						if (up == f.name) {
							Token t = tok(Kind::function, start, pos_);
							t.text = word;
							t.fn = f.fn;
							return t;
						}
					}
					if (is_member_role(up) || is_cluster_role(up)) {
						Token t = tok(Kind::role, start, pos_);
						t.text = word;
						return t;
					}
				}
				Token t = tok(Kind::identifier, start, pos_);
				t.text = word;
				return t;
			}
			fail(std::string("unexpected character: '") + c + "'", start, start);
		}
		return tok(Kind::end, last_b_, last_e_);
	}

private:
	char at(size_t i) const { return i < buf_.size() ? buf_[i] : '\0'; }

	Token tok(Kind k, size_t b, size_t e) const {
		Token t;
		t.kind = k;
		t.b = b;
		t.e = e;
		return t;
	}

	bool toggled() {
		if (tag_mode_) {
			tag_mode_ = false;
			return true;
		}
		return false;
	}

	[[noreturn]] void fail(const std::string& what, size_t b, size_t e) const {
		throw ParseError(located("syntax error, " + what, buf_, b, e));
	}

	size_t span_id(size_t start, bool& complex, size_t err_pos) const {
		if (!std::isalpha(static_cast<unsigned char>(at(start)))) {
			fail("Id not starting with a letter", err_pos, err_pos + 1);
		}
		complex = false;
		size_t i = start + 1;
		while (i < buf_.size()) {
			while (std::isalnum(static_cast<unsigned char>(at(i))) || at(i) == '_') ++i;
			if (at(i) != '.' || (!std::isalpha(static_cast<unsigned char>(at(i + 1))) && at(i + 1) != '_')) break;
			complex = true;
			i += 2;
		}
		return i - start;
	}

	size_t span_quote(size_t offset) const {
		const char quote = buf_[offset];
		for (size_t i = offset + 1; i < buf_.size(); i++) {
			if (buf_[i] == quote && buf_[i - 1] != '\\') return i + 1;
		}
		fail(std::string("unclosed ") + quote, offset, offset + 1);
	}

	std::string& buf_;
	bool tags_as_json_;
	bool tag_mode_ {false};
	size_t pos_ {0};
	size_t last_b_ {0}, last_e_ {0};
};

// ---------------------------------------------------------------------------
// Parser.
// ---------------------------------------------------------------------------

constexpr int kPrecOr = 1;
constexpr int kPrecAnd = 2;
constexpr int kPrecNot = 3;
constexpr int kPrecCmp = 4;
constexpr int kPrecAdd = 5;
constexpr int kPrecMul = 6;

int infix_precedence(Kind k) {
	switch (k) {
	case Kind::kw_or: return kPrecOr;
	case Kind::kw_and: return kPrecAnd;
	case Kind::kw_not: return kPrecNot;
	case Kind::gt: case Kind::lt: case Kind::ge: case Kind::le: case Kind::eq: case Kind::ne:
	case Kind::kw_in: case Kind::kw_like:
		return kPrecCmp;
	case Kind::plus: case Kind::dash: return kPrecAdd;
	case Kind::star: case Kind::slash: case Kind::percent: return kPrecMul;
	default: return 0;
	}
}

bool is_nonassoc(Kind k) {
	return infix_precedence(k) == kPrecCmp;
}

bool can_start_expression(Kind k) {
	switch (k) {
	case Kind::number: case Kind::kw_true: case Kind::kw_false: case Kind::kw_null:
	case Kind::string: case Kind::identifier: case Kind::varref: case Kind::role:
	case Kind::lparen: case Kind::dash: case Kind::kw_not: case Kind::function:
		return true;
	default:
		return false;
	}
}

class Parser {
public:
	Parser(Expression::Impl& impl, std::string& buf, bool tags_as_json, const Resolver& resolver)
		: impl_(impl), nodes_(impl.nodes), buf_(buf), lex_(buf, tags_as_json), resolver_(resolver) {}

	uint32_t parse_unit() {
		const Token& first = peek();
		if (first.kind == Kind::end) return make_const(ValueType::null, 0, std::string(), 0, 0);
		if (!can_start_expression(first.kind)) unexpected(first, "end of expression or error");
		const uint32_t root = parse_expr(0);
		const Token& last = peek();
		if (last.kind != Kind::end) unexpected(last, "end of expression or error");
		return root;
	}

private:
	const Token& peek() {
		if (!have_) {
			tok_ = lex_.next();
			have_ = true;
		}
		return tok_;
	}

	Token take() {
		peek();
		have_ = false;
		return std::move(tok_);
	}

	[[noreturn]] void fail(const std::string& msg, size_t b, size_t e) const {
		throw ParseError(located(msg, buf_, b, e));
	}

	[[noreturn]] void too_deep(size_t b, size_t e) const {
		fail("syntax error, expression nesting exceeds " + std::to_string(kMaxExpressionDepth) + " levels", b, e);
	}

	[[noreturn]] void unexpected(const Token& t, const char* expecting = nullptr) const {
		std::string msg = std::string("syntax error, unexpected ") + kind_name(t.kind);
		if (expecting != nullptr) msg += std::string(", expecting ") + expecting;
		fail(msg, t.b, t.e);
	}

	void type_error(const std::string& what, ValueType expected, ValueType got, size_t b, size_t e) const {
		if (expected == got) return;
		fail("type error, " + what + ", expected " + type_name(expected) + " but got " + type_name(got), b, e);
	}

	Node& node(uint32_t i) { return nodes_[i]; }

	uint32_t add(Node n) {
		if (n.xb == 0 && n.xe == 0) {
			n.xb = n.b;
			n.xe = n.e;
		}
		n.depth = 1;
		for (const uint32_t k : n.kids) n.depth = std::max(n.depth, nodes_[k].depth + 1);
		if (n.depth > kMaxExpressionDepth) too_deep(n.b, n.e);
		nodes_.push_back(std::move(n));
		return static_cast<uint32_t>(nodes_.size() - 1);
	}

	uint32_t make_const(ValueType t, double num, std::string str, size_t b, size_t e) {
		Node n;
		n.op = Op::constant;
		n.type = t;
		n.num = num;
		n.str = std::move(str);
		n.b = n.xb = b;
		n.e = n.xe = e;
		return add(std::move(n));
	}

	uint32_t make_const(const RVal& v, size_t b, size_t e) {
		return make_const(v.t, v.n, std::string(v.s()), b, e);
	}

	bool is_const(uint32_t i) const { return nodes_[i].op == Op::constant; }

	RVal const_value(uint32_t i) const {
		const Node& n = nodes_[i];
		if (n.type == ValueType::string || n.type == ValueType::role) return RVal::view(n.type, n.str);
		if (n.type == ValueType::null) return RVal::null();
		RVal r;
		r.t = n.type;
		r.n = n.num;
		return r;
	}

	uint32_t make_op(Op op, ValueType type, std::vector<uint32_t> kids, size_t b, size_t e, bool has_loc = true) {
		Node n;
		n.op = op;
		n.type = type;
		n.kids = std::move(kids);
		n.b = n.xb = b;
		n.e = n.xe = e;
		n.has_loc = has_loc;
		return add(std::move(n));
	}

	// expr := prefix { infix-operator ... }
	struct NestingGuard {
		NestingGuard(Parser& p, size_t b, size_t e) : parser(p) {
			if (++parser.nesting_ > kMaxExpressionDepth) parser.too_deep(b, e);
		}
		~NestingGuard() { --parser.nesting_; }
		NestingGuard(const NestingGuard&) = delete;
		NestingGuard& operator=(const NestingGuard&) = delete;
		Parser& parser;
	};

	uint32_t parse_expr(int min_prec) {
		const Token& start = peek();
		const NestingGuard guard(*this, start.b, start.e);
		uint32_t lhs = parse_prefix();
		while (true) {
			const Kind k = peek().kind;
			const int prec = infix_precedence(k);
			if (prec == 0 || prec < min_prec) return lhs;
			Token op = take();
			switch (op.kind) {
			case Kind::kw_or:
			case Kind::kw_and: {
				const uint32_t rhs = parse_expr(prec + 1);
				lhs = make_logic(op.kind == Kind::kw_and ? Op::and_ : Op::or_, lhs, rhs);
				break;
			}
			case Kind::kw_not: {
				const Token& after = peek();
				if (after.kind == Kind::kw_in) {
					take();
					lhs = parse_in(lhs, &op);
				} else if (after.kind == Kind::kw_like) {
					take();
					const uint32_t rhs = parse_expr(kPrecCmp + 1);
					lhs = make_like(lhs, rhs, node(lhs).xb, node(rhs).xe);
					lhs = make_op(Op::not_, ValueType::boolean, {lhs}, op.b, op.e);
					check_nonassoc();
				} else {
					unexpected(after, "T_IN or T_LIKE");
				}
				break;
			}
			case Kind::kw_in:
				lhs = parse_in(lhs, nullptr);
				break;
			case Kind::kw_like: {
				const uint32_t rhs = parse_expr(kPrecCmp + 1);
				lhs = make_like(lhs, rhs, node(lhs).xb, node(rhs).xe);
				check_nonassoc();
				break;
			}
			case Kind::gt:
			case Kind::lt:
			case Kind::ge:
			case Kind::le: {
				const uint32_t rhs = parse_expr(kPrecCmp + 1);
				lhs = make_compare(op.kind, lhs, rhs);
				check_nonassoc();
				break;
			}
			case Kind::eq:
			case Kind::ne: {
				const uint32_t rhs = parse_expr(kPrecCmp + 1);
				lhs = make_equal(op.kind == Kind::eq, lhs, rhs);
				check_nonassoc();
				break;
			}
			case Kind::plus:
			case Kind::dash:
			case Kind::star:
			case Kind::slash:
			case Kind::percent: {
				const uint32_t rhs = parse_expr(prec + 1);
				lhs = make_math(op.kind, lhs, rhs);
				break;
			}
			default:
				unexpected(op);
			}
		}
	}

	void check_nonassoc() {
		const Token& t = peek();
		if (is_nonassoc(t.kind)) unexpected(t);
	}

	uint32_t parse_prefix() {
		const Token& t = peek();
		if (t.kind == Kind::dash) {
			const Token op = take();
			const uint32_t operand = parse_expr(kPrecAdd + 1);
			return make_neg(operand, op.b, node(operand).xe);
		}
		if (t.kind == Kind::kw_not) {
			const Token op = take();
			const uint32_t operand = parse_expr(kPrecNot + 1);
			const uint32_t result = make_not(operand, op.b, node(operand).xe);
			const Token& after = peek();
			if (after.kind == Kind::kw_not) unexpected(after);
			return result;
		}
		return parse_primary();
	}

	uint32_t parse_primary() {
		Token t = take();
		switch (t.kind) {
		case Kind::number:
			return make_const(ValueType::number, t.num, std::string(), t.b, t.e);
		case Kind::kw_true:
			return make_const(ValueType::boolean, 1, std::string(), t.b, t.e);
		case Kind::kw_false:
			return make_const(ValueType::boolean, 0, std::string(), t.b, t.e);
		case Kind::kw_null:
			return make_const(ValueType::null, 0, std::string(), t.b, t.e);
		case Kind::string:
			return make_const(ValueType::string, 0, std::move(t.text), t.b, t.e);
		case Kind::identifier:
			return make_const(ValueType::string, 0, unescape(t.text), t.b, t.e);
		case Kind::role:
			return make_const(ValueType::role, 0, std::move(t.text), t.b, t.e);
		case Kind::varref:
			return make_reference(t);
		case Kind::lparen: {
			const uint32_t inner = parse_expr(0);
			const Token& close = peek();
			if (close.kind != Kind::rparen) unexpected(close);
			const Token r = take();
			node(inner).xb = t.b;
			node(inner).xe = r.e;
			return inner;
		}
		case Kind::function: {
			const Token& open = peek();
			if (open.kind != Kind::lparen) unexpected(open, "(");
			take();
			if (peek().kind == Kind::rparen) {
				const Token r = take();
				return make_function(t.fn, nullptr, t.b, r.e);
			}
			std::vector<uint32_t> args;
			const size_t end = parse_list(args);
			return make_function(t.fn, &args, t.b, end);
		}
		default:
			unexpected(t);
		}
	}

	// explist ")" ; returns the end location of ")"
	size_t parse_list(std::vector<uint32_t>& items) {
		while (true) {
			items.push_back(parse_expr(0));
			const Token& sep = peek();
			if (sep.kind == Kind::comma) {
				take();
				continue;
			}
			if (sep.kind == Kind::rparen) return take().e;
			unexpected(sep, ") or \",\"");
		}
	}

	uint32_t parse_in(uint32_t needle, const Token* not_tok) {
		const Token& open = peek();
		if (open.kind != Kind::lparen) unexpected(open, "(");
		take();
		std::vector<uint32_t> items;
		const size_t end = parse_list(items);
		const size_t b = node(needle).xb;
		const ValueType nt = node(needle).type;
		for (size_t i = 0; i < items.size(); i++) {
			const ValueType et = node(items[i]).type;
			if (nt != ValueType::null && et != ValueType::null) {
				type_error("in operator, type of element at offset " + std::to_string(i) +
					" does not match the type of searched element", nt, et, b, end);
			}
		}
		std::vector<uint32_t> kids;
		kids.reserve(items.size() + 1);
		kids.push_back(needle);
		kids.insert(kids.end(), items.begin(), items.end());
		uint32_t result = make_op(Op::in, ValueType::boolean, std::move(kids), b, end);
		if (not_tok != nullptr) {
			result = make_op(Op::not_, ValueType::boolean, {result}, not_tok->b, not_tok->e);
			node(result).xb = b;
			node(result).xe = end;
		}
		return result;
	}

	uint32_t make_reference(const Token& t) {
		const std::string& name = t.text;
		for (const VarDef& v : kVariables) {
			if (name == v.name) {
				Node n;
				n.op = Op::var;
				n.type = v.type;
				n.var = v.id;
				n.name = name;
				n.b = t.b;
				n.e = t.e;
				return add(std::move(n));
			}
		}
		struct Prefix {
			const char* text;
			TagScope scope;
		};
		static const Prefix prefixes[] = {
			{"router.tags.", TagScope::router_tags},
			{"server.tags.", TagScope::server_tags},
			{"session.connectAttrs.", TagScope::connect_attrs},
			{"sql.queryTags.", TagScope::sql_query_tags},
			{"sql.queryHints.", TagScope::sql_query_hints},
		};
		for (const Prefix& p : prefixes) {
			if (starts_with(name, p.text)) {
				Node n;
				n.op = Op::tag;
				n.type = ValueType::string;
				n.tag = p.scope;
				n.str = name.substr(std::strlen(p.text));
				n.name = name;
				n.b = t.b;
				n.e = t.e;
				if (lex_.tags_as_json() && (starts_with(name, "router.tags") || starts_with(name, "server.tags"))) {
					lex_.set_tag_mode();
				}
				return add(std::move(n));
			}
		}
		fail("undefined variable: " + name, t.b, t.e);
	}

	uint32_t make_neg(uint32_t operand, size_t b, size_t e) {
		if (is_const(operand) && node(operand).type == ValueType::number) {
			node(operand).num = -node(operand).num;
			node(operand).b = node(operand).xb = b;
			node(operand).e = node(operand).xe = e;
			return operand;
		}
		type_error("- operator", ValueType::number, node(operand).type, b, e);
		return make_op(Op::neg, ValueType::number, {operand}, b, e);
	}

	uint32_t make_math(Kind k, uint32_t l, uint32_t r) {
		const size_t b = node(l).xb;
		const size_t e = node(r).xe;
		const char* sym = kind_name(k);
		if (is_const(l) && is_const(r) && node(l).type == ValueType::number && node(r).type == ValueType::number) {
			const double a = node(l).num;
			const double c = node(r).num;
			double v = 0;
			switch (k) {
			case Kind::plus: v = a + c; break;
			case Kind::dash: v = a - c; break;
			case Kind::star: v = a * c; break;
			case Kind::slash: v = a / c; break;
			default: v = std::fmod(a, c); break;
			}
			return make_const(ValueType::number, v, std::string(), b, e);
		}
		type_error(std::string(sym) + " operator, left operand", ValueType::number, node(l).type, b, e);
		type_error(std::string(sym) + " operator, right operand", ValueType::number, node(r).type, b, e);
		Op op = Op::mod;
		switch (k) {
		case Kind::plus: op = Op::add; break;
		case Kind::dash: op = Op::sub; break;
		case Kind::star: op = Op::mul; break;
		case Kind::slash: op = Op::div; break;
		default: break;
		}
		return make_op(op, ValueType::number, {l, r}, b, e);
	}

	uint32_t make_compare(Kind k, uint32_t l, uint32_t r) {
		const size_t b = node(l).xb;
		const size_t e = node(r).xe;
		const std::string sym = kind_name(k);
		const ValueType lt = node(l).type;
		if (lt != ValueType::number && lt != ValueType::string) {
			fail(std::string("type error, ") + type_name(lt) + " type arguments cannot be compared with " + sym + " operator", b, e);
		}
		type_error(sym + " operator, the type of left operand does not match right", lt, node(r).type, b, e);
		Op op = k == Kind::gt ? Op::gt : k == Kind::lt ? Op::lt : k == Kind::ge ? Op::ge : Op::le;
		if (is_const(l) && is_const(r)) {
			const RVal a = const_value(l);
			const RVal c = const_value(r);
			try {
				bool v = false;
				switch (op) {
				case Op::lt: v = val_lt(a, c); break;
				case Op::gt: v = val_lt(c, a); break;
				case Op::le: v = val_le(a, c); break;
				default: v = val_le(c, a); break;
				}
				return make_const(ValueType::boolean, v ? 1 : 0, std::string(), b, e);
			} catch (const std::exception&) {
			}
		}
		return make_op(op, ValueType::boolean, {l, r}, b, e);
	}

	enum class RoleKind { both, member, cluster };

	RoleKind role_kind(uint32_t i) {
		const Node& n = node(i);
		if (n.op == Op::var) {
			return n.var == VarId::server_member_role ? RoleKind::member : RoleKind::cluster;
		}
		if (is_member_role(n.str)) return is_cluster_role(n.str) ? RoleKind::both : RoleKind::member;
		return RoleKind::cluster;
	}

	uint32_t make_equal(bool equal, uint32_t l, uint32_t r) {
		const size_t b = node(l).xb;
		const size_t e = node(r).xe;
		const ValueType lt = node(l).type;
		const ValueType rt = node(r).type;
		if (lt != ValueType::null && rt != ValueType::null) {
			type_error(std::string(equal ? "=" : "<>") + " operator, the type of left operand does not match right", lt, rt, b, e);
		}
		if (lt == ValueType::role && rt == ValueType::role) {
			const RoleKind left = role_kind(l);
			if (left != RoleKind::both) {
				const RoleKind right = role_kind(r);
				if (right != RoleKind::both && right != left) {
					fail(left == RoleKind::member
						? "type error, incompatible operands for comparison: 'MEMBER ROLE' vs 'CLUSTER ROLE'"
						: "type error, incompatible operands for comparison: 'CLUSTER ROLE' vs 'MEMBER ROLE'", b, e);
				}
			}
		}
		if (is_const(l) && is_const(r) && lt == rt) {
			const bool v = val_eq(const_value(l), const_value(r));
			return make_const(ValueType::boolean, (v == equal) ? 1 : 0, std::string(), b, e);
		}
		return make_op(equal ? Op::eq : Op::ne, ValueType::boolean, {l, r}, b, e);
	}

	uint32_t make_logic(Op op, uint32_t l, uint32_t r) {
		const size_t b = node(l).xb;
		const size_t e = node(r).xe;
		if (is_const(l) && is_const(r) && node(l).type == ValueType::boolean && node(r).type == ValueType::boolean) {
			const bool a = truthy(const_value(l));
			const bool c = truthy(const_value(r));
			const bool v = op == Op::and_ ? (a && c) : (a || c);
			return make_const(ValueType::boolean, v ? 1 : 0, std::string(), b, e);
		}
		if (node(l).op == op) {
			// flatten ((a OR b) OR c) into OR(a, b, c): same result, bounded recursion
			node(l).kids.push_back(r);
			node(l).depth = std::max(node(l).depth, node(r).depth + 1);
			node(l).e = node(l).xe = e;
			return l;
		}
		return make_op(op, ValueType::boolean, {l, r}, b, e);
	}

	uint32_t make_not(uint32_t operand, size_t b, size_t e) {
		if (is_const(operand) && node(operand).type == ValueType::boolean) {
			const bool v = !truthy(const_value(operand));
			return make_const(ValueType::boolean, v ? 1 : 0, std::string(), b, e);
		}
		return make_op(Op::not_, ValueType::boolean, {operand}, b, e);
	}

	// LIKE is translated to STARTSWITH / ENDSWITH / CONTAINS or an anchored
	// regular expression.
	uint32_t make_like(uint32_t subject, uint32_t pattern, size_t b, size_t e) {
		type_error("LIKE operator, left operand", ValueType::string, node(subject).type, b, e);
		type_error("LIKE operator, right operand", ValueType::string, node(pattern).type, b, e);
		if (!is_const(pattern)) fail("LIKE operator only accepts string literals as its right operand", b, e);
		std::string pat = node(pattern).str;
		if (pat.empty() || pat == "%") return make_const(ValueType::boolean, 1, std::string(), b, e);

		// remove the escapes of '%' and '_' in pat[start, start + size)
		const auto strip = [&pat](size_t start, size_t size) {
			std::string np;
			if (size == 0) return np;
			const size_t last = start + size - 1;
			for (size_t i = start; i < last; i++) {
				if (pat[i] != '\\' || (pat[i + 1] != '%' && pat[i + 1] != '_')) np.push_back(pat[i]);
			}
			np.push_back(pat[last]);
			return np;
		};

		bool optimized = pat.front() != '_' && pat.back() != '_';
		for (size_t i = 1; optimized && i + 1 < pat.size(); i++) {
			if ((pat[i] == '%' || pat[i] == '_') && !(pat[i - 1] == '\\' && (i < 2 || pat[i - 2] != '\\'))) {
				optimized = false;
			}
		}
		Fn fn = Fn::regexp_like;
		std::string arg;
		if (optimized) {
			const size_t n = pat.size();
			const bool back_percent = pat.back() == '%' && n >= 2 &&
				(pat[n - 2] != '\\' || (n > 2 && pat[n - 3] == '\\'));
			if (pat.front() == '%') {
				if (back_percent) {
					fn = Fn::contains;
					arg = strip(1, n - 2);
				} else {
					fn = Fn::endswith;
					arg = strip(1, n - 1);
				}
			} else if (back_percent) {
				fn = Fn::startswith;
				arg = strip(0, n - 1);
			}
		}
		if (fn == Fn::regexp_like) arg = like_to_regexp(pat);
		const uint32_t pattern_node = make_const(ValueType::string, 0, std::move(arg), node(pattern).b, node(pattern).e);
		std::vector<uint32_t> args {subject, pattern_node};
		return make_function(fn, &args, b, e);
	}

	uint32_t make_function(Fn fn, std::vector<uint32_t>* args, size_t b, size_t e) {
		const FnDef& def = fn_def(fn);
		const std::string name = def.name;
		if (fn == Fn::concat) {
			if (args == nullptr || args->empty()) fail("CONCAT function, no arguments provided", b, e);
			return make_op(Op::concat, ValueType::string, *args, b, e, false);
		}
		const size_t expected = def.args.size();
		if (args == nullptr) {
			if (expected > 0) {
				fail("syntax error, function " + name + " expected " + std::to_string(expected) +
					(expected > 1 ? " arguments but got none" : " argument but got none"), b, e);
			}
		} else {
			if (expected != args->size()) {
				fail("syntax error, function " + name + " expected " + std::to_string(expected) +
					(expected > 1 ? " arguments but got " : " argument but got ") + std::to_string(args->size()), b, e);
			}
			for (size_t i = 0; i < expected; i++) {
				const ValueType got = node((*args)[i]).type;
				if (got == def.args[i]) continue;
				std::string what = name + " function";
				if (expected > 1) {
					what += ", " + std::to_string(i + 1) + (i == 0 ? "st" : i == 1 ? "nd" : i == 2 ? "rd" : "th") + " argument";
				}
				type_error(what, def.args[i], got, b, e);
			}
		}
		const std::vector<uint32_t> empty;
		const std::vector<uint32_t>& a = args != nullptr ? *args : empty;

		if (fn == Fn::resolve_v4 || fn == Fn::resolve_v6) {
			if (!is_const(a[0]) || node(a[0]).type != ValueType::string) {
				fail(name + " function only accepts string literals as its parameter", b, e);
			}
			const std::string& host = node(a[0]).str;
			if (!valid_hostname(host)) fail(name + " function, invalid hostname: '" + host + "'", b, e);
			Node n;
			n.op = Op::resolve;
			n.type = ValueType::string;
			n.fn = fn;
			n.name = to_lower(host);
			n.b = b;
			n.e = e;
			std::optional<std::string> addr = resolver_ ? resolver_(n.name, fn == Fn::resolve_v6)
				: resolve_host(n.name, fn == Fn::resolve_v6);
			if (addr) {
				n.resolved = true;
				n.str = std::move(*addr);
			}
			return add(std::move(n));
		}
		if (fn == Fn::network) {
			if (!is_const(a[1])) fail("NETWORK function only accepts number literals as its 2nd argument", b, e);
			Node n;
			n.op = Op::network;
			n.type = ValueType::string;
			n.fn = fn;
			n.num = node(a[1]).num;
			n.kids = {a[0]};
			n.b = b;
			n.e = e;
			return add(std::move(n));
		}

		bool reducible = true;
		for (const uint32_t k : a) reducible = reducible && is_const(k);
		if (reducible) {
			std::array<RVal, 3> vals;
			for (size_t i = 0; i < a.size(); i++) vals[i] = const_value(a[i]);
			try {
				const RVal v = call_function(fn, vals.data());
				return make_const(v, b, e);
			} catch (const std::exception& ex) {
				fail(std::string("Function execution failed with error: ") + ex.what(), b, e);
			}
		}
		if (fn == Fn::regexp_like && is_const(a[1])) {
			Node n;
			n.op = Op::regex;
			n.type = ValueType::boolean;
			n.fn = fn;
			n.kids = {a[0]};
			n.b = b;
			n.e = e;
			try {
				impl_.regexes.emplace_back(node(a[1]).str, std::regex_constants::icase | std::regex::ECMAScript);
			} catch (const std::exception& ex) {
				fail(std::string("REGEXP_LIKE function invalid regular expression: ") + ex.what(), b, e);
			}
			n.regex = static_cast<uint32_t>(impl_.regexes.size() - 1);
			return add(std::move(n));
		}
		Node n;
		n.op = Op::func;
		n.type = def.ret;
		n.fn = fn;
		n.kids = a;
		n.b = b;
		n.e = e;
		n.has_loc = true;
		return add(std::move(n));
	}

	Expression::Impl& impl_;
	std::vector<Node>& nodes_;
	std::string& buf_;
	Lexer lex_;
	const Resolver& resolver_;
	Token tok_;
	bool have_ {false};
	uint32_t nesting_ {0};
};

void check_context(const Expression::Impl& impl, uint32_t idx, ExpressionScope scope, std::vector<std::string>& errors) {
	const Node& n = impl.nodes[idx];
	for (const uint32_t k : n.kids) check_context(impl, k, scope, errors);
	if (n.op != Op::var) return;
	if (scope == ExpressionScope::destination && starts_with(n.name, "session")) {
		errors.push_back(n.name + " may not be used in 'destinations' context");
	} else if (scope == ExpressionScope::route && starts_with(n.name, "server")) {
		errors.push_back(n.name + " may not be used in 'routes' context");
	}
}

} // namespace

namespace detail {

bool parse_version(std::string_view text, unsigned& major, unsigned& minor) {
	const size_t dot = text.find('.');
	if (dot == std::string_view::npos || text.find('.', dot + 1) != std::string_view::npos) return false;
	const auto parse_part = [](std::string_view part, unsigned& out) {
		if (part.empty() || part.size() > 9) return false;
		unsigned v = 0;
		for (char c : part) {
			if (!std::isdigit(static_cast<unsigned char>(c))) return false;
			v = v * 10 + static_cast<unsigned>(c - '0');
		}
		out = v;
		return true;
	};
	return parse_part(text.substr(0, dot), major) && parse_part(text.substr(dot + 1), minor);
}

CompileStatus compile_expression(std::string_view code, ExpressionScope scope,
	std::string_view version, std::vector<std::string>& errors, const Resolver& resolver,
	std::optional<Expression>& out) {
	auto impl = std::make_shared<Expression::Impl>();
	impl->text = std::string(code);
	impl->loc_text = impl->text;
	unsigned major = 1, minor = 0;
	if (!parse_version(version, major, minor)) {
		major = 1;
		minor = 0;
	}
	const bool tags_as_json = major > 1 || (major == 1 && minor > 0);
	try {
		Parser parser(*impl, impl->loc_text, tags_as_json, resolver);
		impl->root = parser.parse_unit();
	} catch (const std::exception& e) {
		errors.push_back(e.what());
		return CompileStatus::parse_error;
	}
	const size_t before = errors.size();
	if (scope != ExpressionScope::any) {
		check_context(*impl, impl->root, scope, errors);
		static const ServerInfo server;
		static const SessionInfo session;
		static const RouterInfo router;
		const EvalCtx dry {&server, &session, &router, true};
		try {
			if (impl->eval(impl->root, dry).t != ValueType::boolean) {
				errors.push_back("match does not evaluate to boolean");
				return CompileStatus::validation_error;
			}
		} catch (const std::exception& e) {
			errors.push_back(e.what());
			return CompileStatus::validation_error;
		}
	}
	out = ExpressionAccess::make(std::move(impl));
	return errors.size() == before ? CompileStatus::ok : CompileStatus::context_error;
}

} // namespace detail

std::optional<std::string> resolve_host(const std::string& host, bool ipv6) {
	addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family = ipv6 ? AF_INET6 : AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	addrinfo* info = nullptr;
	if (getaddrinfo(host.c_str(), nullptr, &hints, &info) != 0 || info == nullptr) return std::nullopt;
	std::optional<std::string> result;
	for (addrinfo* ai = info; ai != nullptr && !result; ai = ai->ai_next) {
		char buf[INET6_ADDRSTRLEN];
		if (ai->ai_family == AF_INET && !ipv6) {
			const auto* sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
			if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)) != nullptr) result = buf;
		} else if (ai->ai_family == AF_INET6 && ipv6) {
			const auto* sa = reinterpret_cast<sockaddr_in6*>(ai->ai_addr);
			if (inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(buf)) != nullptr) result = buf;
		}
	}
	freeaddrinfo(info);
	return result;
}

bool Value::truthy() const {
	return rg::truthy(type, number, string);
}

std::optional<Expression> Expression::compile(std::string_view code, ExpressionScope scope,
	std::string_view version, std::vector<std::string>& errors, const Resolver& resolver) {
	std::optional<Expression> out;
	if (detail::compile_expression(code, scope, version, errors, resolver, out) != detail::CompileStatus::ok) {
		return std::nullopt;
	}
	return out;
}

Value Expression::evaluate(const ServerInfo* server, const SessionInfo* session, const RouterInfo* router) const {
	const EvalCtx ctx {server, session, router, false};
	RVal v = impl_->eval(impl_->root, ctx);
	Value out;
	out.type = v.t;
	out.number = v.n;
	if (v.t == ValueType::string || v.t == ValueType::role) out.string = std::string(v.s());
	return out;
}

bool Expression::matches(const ServerInfo* server, const SessionInfo* session, const RouterInfo* router) const {
	const EvalCtx ctx {server, session, router, false};
	return truthy(impl_->eval(impl_->root, ctx));
}

const std::string& Expression::text() const {
	return impl_->text;
}

bool Expression::references(std::string_view variable) const {
	return impl_->references(impl_->root, variable);
}

bool Expression::is_constant() const {
	return impl_->nodes[impl_->root].op == Op::constant;
}

} // namespace mysql_router::rg
