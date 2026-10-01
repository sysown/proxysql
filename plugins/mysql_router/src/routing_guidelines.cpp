// MySQL Router Routing Guidelines: document parsing/validation, destination
// classification and route matching.
//
// Validation rules and error messages follow MySQL Router's
// routing_guidelines.cc (Routing_guidelines_document_parser): every problem is
// collected and reported with the JSON path of the offending field.

#include "mysql_router_routing_guidelines.h"
#include "mysql_router_routing_guidelines_detail.h"

#include <json.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace mysql_router::rg {

struct Guideline::Private {
	std::string name;
	std::string version {"1.0"};
	std::vector<Destination> destinations;
	std::vector<Expression> destination_matches;
	std::vector<Route> routes;
	std::vector<Expression> route_matches;
	bool route_name_in_destinations {false};
};

namespace {

using ojson = nlohmann::ordered_json;

constexpr unsigned kSupportedMajor = 1;
constexpr unsigned kSupportedMinor = 1;

class DocumentParser {
public:
	DocumentParser(std::vector<Error>& errors, const Resolver& resolver)
		: errors_(errors), resolver_(resolver) {}

	std::shared_ptr<const Guideline> run(std::string_view json) {
		const size_t errors_before = errors_.size();
		if (json.find_first_not_of(" \t\r\n") == std::string_view::npos) {
			add_error("incorrect JSON: The document is empty");
			return nullptr;
		}
		ojson doc;
		try {
			doc = ojson::parse(json.begin(), json.end());
		} catch (const std::exception& e) {
			std::string what = e.what();
			const size_t pos = what.find("] ");
			if (what.rfind("[json.exception.", 0) == 0 && pos != std::string::npos) what = what.substr(pos + 2);
			add_error("incorrect JSON: " + what);
			return nullptr;
		}
		if (!doc.is_object()) {
			add_error("routing guidelines needs to be specified as a JSON document");
			return nullptr;
		}

		p_ = std::make_unique<Guideline::Private>();
		const auto version_it = doc.find("version");
		if (version_it != doc.end()) {
			Scope s(*this, "version");
			if (!version_it->is_string()) {
				add_error("field is expected to be a string");
			} else {
				const std::string text = version_it->get<std::string>();
				unsigned major = 0, minor = 0;
				if (!detail::parse_version(text, major, minor)) {
					add_error("Invalid routing guidelines version format. Expected <major>.<minor> got " + text);
				} else {
					p_->version = text;
					// Router: available <= supported && supported.major - available.major <= 1
					const bool not_newer = major < kSupportedMajor || (major == kSupportedMajor && minor <= kSupportedMinor);
					if (!not_newer || kSupportedMajor - major > 1) {
						add_error("routing guidelines version not supported, supported version is " +
							std::string(kSupportedVersion) + " but got " + text);
					}
				}
			}
		}

		for (auto it = doc.begin(); it != doc.end(); ++it) {
			Scope s(*this, it.key());
			if (it.key() == "version") {
				continue;
			} else if (it.key() == "destinations") {
				parse_destinations(it.value());
			} else if (it.key() == "routes") {
				parse_routes(it.value());
			} else if (it.key() == "name") {
				if (is_string_value(it.value())) p_->name = it.value().get<std::string>();
			} else {
				add_error("Unexpected field, only 'version', 'name', 'destinations', and 'routes' are allowed");
			}
		}
		if (p_->destinations.empty()) add_error("no destination classes defined by the document");
		if (p_->routes.empty()) add_error("no routes defined by the document");

		for (const ClassRef& ref : class_refs_) {
			if (declared_classes_.count(ref.name) == 0) {
				errors_.push_back({ref.path, "undefined destination class '" + ref.name +
					"' found in route '" + route_names_[ref.route] + "'"});
			}
		}

		if (errors_.size() != errors_before) return nullptr;

		for (auto& route : p_->routes) {
			std::stable_sort(route.groups.begin(), route.groups.end(),
				[](const DestinationGroup& a, const DestinationGroup& b) { return a.priority < b.priority; });
		}
		for (const Expression& m : p_->destination_matches) {
			if (m.references("router.routeName")) p_->route_name_in_destinations = true;
		}
		return std::make_shared<const Guideline>(std::move(p_));
	}

private:
	struct Scope {
		Scope(DocumentParser& parser, const std::string& name) : parser_(parser) {
			parser_.scope_.push_back(parser_.scope_.empty() ? name : "." + name);
		}
		Scope(DocumentParser& parser, size_t index) : parser_(parser) {
			parser_.scope_.push_back("[" + std::to_string(index) + "]");
		}
		~Scope() { parser_.scope_.pop_back(); }
		Scope(const Scope&) = delete;
		Scope& operator=(const Scope&) = delete;
		DocumentParser& parser_;
	};

	struct ClassRef {
		std::string path;
		std::string name;
		size_t route;
	};

	std::string path() const {
		std::string p;
		for (const auto& s : scope_) p += s;
		return p;
	}

	void add_error(const std::string& msg) {
		errors_.push_back({path(), msg});
	}

	bool is_string_value(const ojson& v) {
		if (!v.is_string()) {
			add_error("field is expected to be a string");
			return false;
		}
		if (v.get_ref<const std::string&>().empty()) {
			add_error("field is expected to be a non empty string");
			return false;
		}
		return true;
	}

	bool is_object_value(const ojson& v) {
		if (!v.is_object()) add_error("field is expected to be an object");
		return v.is_object();
	}

	bool is_bool_value(const ojson& v) {
		if (!v.is_boolean()) add_error("field is expected to be boolean");
		return v.is_boolean();
	}

	bool is_array_value(const ojson& v) {
		if (!v.is_array()) {
			add_error("field is expected to be an array");
			return false;
		}
		if (v.empty()) {
			add_error("field is expected to be a non empty array");
			return false;
		}
		return true;
	}

	detail::CompileStatus compile(const std::string& code, ExpressionScope scope, std::optional<Expression>& out) {
		std::vector<std::string> messages;
		const auto status = detail::compile_expression(code, scope, p_->version, messages, cached_resolver_, out);
		for (const auto& m : messages) add_error(m);
		return status;
	}

	void parse_destinations(const ojson& elem) {
		if (!is_array_value(elem)) return;
		for (size_t index = 0; index < elem.size(); index++) {
			Scope si(*this, index);
			const ojson& rule = elem[index];
			if (!is_object_value(rule)) continue;

			std::optional<std::string> name;
			std::optional<std::string> match_text;
			std::optional<Expression> match;
			bool match_defined = false;
			for (auto it = rule.begin(); it != rule.end(); ++it) {
				Scope sm(*this, it.key());
				if (it.key() == "name") {
					if (is_string_value(it.value())) name = it.value().get<std::string>();
				} else if (it.key() == "match") {
					if (!is_string_value(it.value())) continue;
					match_text = it.value().get<std::string>();
					const auto status = compile(*match_text, ExpressionScope::destination, match);
					// Router: a match that fails to parse is "not defined", one that
					// fails validation is defined but unusable.
					match_defined = status != detail::CompileStatus::parse_error;
				} else {
					add_error("unexpected field name, only 'name' and 'match' are allowed");
				}
			}
			if (!name) add_error("'name' field not defined");
			if (!match_defined) add_error("'match' field not defined");
			if (name) declared_classes_.insert(*name);
			if (!name || !match) continue;
			const bool duplicate = std::any_of(p_->destinations.begin(), p_->destinations.end(),
				[&name](const Destination& d) { return d.name == *name; });
			if (duplicate) {
				add_error("'" + *name + "' class was already defined");
			} else {
				p_->destinations.push_back({*name, *match_text});
				p_->destination_matches.push_back(std::move(*match));
			}
		}
	}

	void parse_routes(const ojson& elem) {
		if (!is_array_value(elem)) return;
		for (size_t index = 0; index < elem.size(); index++) {
			Scope si(*this, index);
			parse_route(elem[index]);
		}
	}

	void parse_route(const ojson& elem) {
		if (!is_object_value(elem)) return;

		Route route;
		std::optional<Expression> match;
		bool match_defined = false, destinations_defined = false, name_defined = false;
		const size_t route_index = route_names_.size();
		route_names_.emplace_back();

		for (auto it = elem.begin(); it != elem.end(); ++it) {
			Scope sm(*this, it.key());
			const ojson& value = it.value();
			if (it.key() == "destinations") {
				destinations_defined = true;
				route.groups = parse_route_destinations(value, route_index);
			} else if (it.key() == "match") {
				match_defined = true;
				if (is_string_value(value)) {
					route.match = value.get<std::string>();
					std::optional<Expression> compiled;
					compile(route.match, ExpressionScope::route, compiled);
					if (compiled) match = std::move(compiled);
				}
			} else if (it.key() == "name") {
				name_defined = true;
				if (is_string_value(value)) route.name = value.get<std::string>();
			} else if (it.key() == "enabled") {
				if (is_bool_value(value)) route.enabled = value.get<bool>();
			} else if (it.key() == "connectionSharingAllowed") {
				if (is_bool_value(value)) route.connection_sharing_allowed = value.get<bool>();
			} else {
				add_error("unexpected field, only 'name', 'connectionSharingAllowed', 'enabled', 'match' and 'destinations' are allowed");
			}
		}
		route_names_[route_index] = route.name;
		if (!name_defined) add_error("'name' field not defined");
		if (!match_defined) add_error("'match' field not defined");
		if (!destinations_defined) add_error("'destinations' field not defined");
		if (!match || route.groups.empty()) return;

		const bool duplicate = std::any_of(p_->routes.begin(), p_->routes.end(),
			[&route](const Route& r) { return r.name == route.name; });
		if (duplicate) {
			add_error("'" + route.name + "' route was already defined");
			return;
		}
		p_->routes.push_back(std::move(route));
		p_->route_matches.push_back(std::move(*match));
	}

	std::vector<DestinationGroup> parse_route_destinations(const ojson& elem, size_t route_index) {
		std::vector<DestinationGroup> groups;
		if (!is_array_value(elem)) return groups;
		for (size_t index = 0; index < elem.size(); index++) {
			Scope si(*this, index);
			const ojson& obj = elem[index];
			if (!is_object_value(obj)) continue;

			DestinationGroup group;
			bool classes_defined = false, strategy_defined = false, priority_defined = false;
			bool strategy_valid = false;
			for (auto it = obj.begin(); it != obj.end(); ++it) {
				Scope sm(*this, it.key());
				const ojson& value = it.value();
				if (it.key() == "strategy") {
					strategy_defined = true;
					if (!is_string_value(value)) continue;
					const std::string strategy = value.get<std::string>();
					if (strategy == "round-robin") {
						group.strategy = Strategy::round_robin;
						strategy_valid = true;
					} else if (strategy == "first-available") {
						group.strategy = Strategy::first_available;
						strategy_valid = true;
					} else {
						add_error("unexpected value '" + strategy + "', supported strategies: round-robin, first-available");
					}
				} else if (it.key() == "classes") {
					classes_defined = true;
					if (!is_array_value(value)) continue;
					for (size_t ci = 0; ci < value.size(); ci++) {
						Scope sc(*this, ci);
						if (is_string_value(value[ci])) {
							group.classes.push_back(value[ci].get<std::string>());
							class_refs_.push_back({path(), group.classes.back(), route_index});
						}
					}
				} else if (it.key() == "priority") {
					priority_defined = true;
					if (value.is_number_unsigned()) {
						group.priority = value.get<uint64_t>();
					} else {
						add_error("field is expected to be a positive integer");
					}
				} else {
					add_error("unexpected field name, only 'classes', 'strategy' and 'priority' are allowed");
				}
			}
			if (!classes_defined) add_error("'classes' field not defined");
			if (!strategy_defined) add_error("'strategy' field not defined");
			if (!priority_defined) add_error("'priority' field not defined");
			if (!group.classes.empty() && strategy_valid) groups.push_back(std::move(group));
		}
		return groups;
	}

	std::vector<Error>& errors_;
	const Resolver& resolver_;
	std::map<std::pair<std::string, bool>, std::optional<std::string>> resolve_cache_;
	Resolver cached_resolver_ {[this](const std::string& host, bool ipv6) {
		const auto key = std::make_pair(host, ipv6);
		const auto it = resolve_cache_.find(key);
		if (it != resolve_cache_.end()) return it->second;
		std::optional<std::string> addr = resolver_ ? resolver_(host, ipv6) : resolve_host(host, ipv6);
		resolve_cache_.emplace(key, addr);
		return addr;
	}};
	std::unique_ptr<Guideline::Private> p_;
	std::vector<std::string> scope_;
	std::set<std::string> declared_classes_;
	std::vector<ClassRef> class_refs_;
	std::vector<std::string> route_names_;
};

} // namespace

std::string format_error(const Error& error) {
	return error.path.empty() ? error.message : error.path + ": " + error.message;
}

Guideline::Guideline(std::unique_ptr<Private> p) : p_(std::move(p)) {}

Guideline::~Guideline() = default;

std::shared_ptr<const Guideline> Guideline::parse(std::string_view json, std::vector<Error>& errors) {
	return parse(json, errors, Resolver());
}

std::shared_ptr<const Guideline> Guideline::parse(std::string_view json, std::vector<Error>& errors,
	const Resolver& resolver) {
	DocumentParser parser(errors, resolver);
	return parser.run(json);
}

const std::string& Guideline::name() const {
	return p_->name;
}

const std::string& Guideline::version() const {
	return p_->version;
}

const std::vector<Destination>& Guideline::destinations() const {
	return p_->destinations;
}

const std::vector<Route>& Guideline::routes() const {
	return p_->routes;
}

bool Guideline::uses_router_route_name_in_destinations() const {
	return p_->route_name_in_destinations;
}

std::vector<std::string> Guideline::classify(const ServerInfo& server, const RouterInfo& router,
	std::vector<Error>& errors) const {
	std::vector<std::string> classes;
	for (size_t i = 0; i < p_->destinations.size(); i++) {
		try {
			if (p_->destination_matches[i].matches(&server, nullptr, &router)) {
				classes.push_back(p_->destinations[i].name);
			}
		} catch (const std::exception& e) {
			errors.push_back({"destinations." + p_->destinations[i].name, e.what()});
		}
	}
	return classes;
}

std::optional<size_t> Guideline::match_route(const SessionInfo& session, const RouterInfo& router,
	std::vector<Error>& errors) const {
	bool failed = false;
	for (size_t i = 0; i < p_->routes.size(); i++) {
		if (!p_->routes[i].enabled) continue;
		try {
			if (p_->route_matches[i].matches(nullptr, &session, &router)) {
				if (failed) return std::nullopt;
				return i;
			}
		} catch (const std::exception& e) {
			// Router keeps evaluating the remaining routes but fails the
			// connection when any route could not be evaluated.
			errors.push_back({"route." + p_->routes[i].name, e.what()});
			failed = true;
		}
	}
	return std::nullopt;
}

} // namespace mysql_router::rg
