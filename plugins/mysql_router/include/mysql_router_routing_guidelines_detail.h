#ifndef PROXYSQL_MYSQL_ROUTER_ROUTING_GUIDELINES_DETAIL_H
#define PROXYSQL_MYSQL_ROUTER_ROUTING_GUIDELINES_DETAIL_H

// Internal interface shared by the Routing Guidelines engine sources.

#include "mysql_router_routing_guidelines.h"

namespace mysql_router::rg::detail {

enum class CompileStatus {
	ok,                // compiled and valid
	parse_error,       // syntax/type error: the match is "not defined" (Router)
	validation_error,  // parsed but unusable (not boolean, dry-run failure)
	context_error      // compiled, but uses variables not allowed in its context
};

// Compiles `code`; `out` is set for ok and context_error. Messages are appended
// to `errors` without JSON paths.
CompileStatus compile_expression(std::string_view code, ExpressionScope scope,
	std::string_view version, std::vector<std::string>& errors, const Resolver& resolver,
	std::optional<Expression>& out);

// Parses "<major>.<minor>" (digits only).
bool parse_version(std::string_view text, unsigned& major, unsigned& minor);

} // namespace mysql_router::rg::detail

#endif // PROXYSQL_MYSQL_ROUTER_ROUTING_GUIDELINES_DETAIL_H
