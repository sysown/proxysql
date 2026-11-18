#include "Embedded_Admin_Statistics.h"
#include "sql_parser/parser.h"
#include "sql_parser/ast_walk.h"
#include <set>
#include <unordered_set>

namespace embedded {
namespace {
std::string lower(std::string s) {
 for (char& c : s) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
 return s;
}
Status fail(ErrorKind kind, const char* message) { return Error{kind, 0, message, "42000"}; }
// Exact standard relation names handled by GenericRefreshStatistics. Never pass
// user-controlled SQL or arbitrary identifiers to that substring-based routine.
const std::unordered_set<std::string> refresh_tables = {
 "stats_memory_metrics",
 "stats_mysql_client_host_cache",
 "stats_mysql_commands_counters",
 "stats_mysql_connection_pool",
 "stats_mysql_errors",
 "stats_mysql_free_connections",
 "stats_mysql_global",
 "stats_mysql_gtid_executed",
 "stats_mysql_hostgroup_connection_pool",
 "stats_mysql_passthrough_auth_cache",
 "stats_mysql_passthrough_auth_metrics",
 "stats_mysql_prepared_statements_info",
 "stats_mysql_processlist",
 "stats_mysql_query_digest",
 "stats_mysql_query_rules",
 "stats_mysql_users",
 "stats_pgsql_client_host_cache",
 "stats_pgsql_commands_counters",
 "stats_pgsql_connection_pool",
 "stats_pgsql_errors",
 "stats_pgsql_free_connections",
 "stats_pgsql_global",
 "stats_pgsql_hostgroup_connection_pool",
 "stats_pgsql_prepared_statements_info",
 "stats_pgsql_processlist",
 "stats_pgsql_query_digest",
 "stats_pgsql_query_rules",
 "stats_pgsql_stat_activity",
 "stats_pgsql_users",
 "stats_proxysql_global",
 "stats_proxysql_message_metrics",
 "stats_proxysql_servers_checksums",
 "stats_proxysql_servers_metrics",
 "stats_proxysql_servers_status",
 "stats_tls_certificates",
 "stats_tsdb",
};
const std::unordered_set<std::string> reset_tables = {
 "stats_mysql_client_host_cache_reset",
 "stats_mysql_connection_pool_reset",
 "stats_mysql_errors_reset",
 "stats_mysql_hostgroup_connection_pool_reset",
 "stats_mysql_query_digest_reset",
 "stats_pgsql_client_host_cache_reset",
 "stats_pgsql_connection_pool_reset",
 "stats_pgsql_errors_reset",
 "stats_pgsql_hostgroup_connection_pool_reset",
 "stats_pgsql_query_digest_reset",
 "stats_proxysql_message_metrics_reset",
};
}
bool admin_sqlite_statistics_reset_table(const std::string& name) {
 return reset_tables.count(lower(name)) != 0;
}
bool admin_sqlite_statistics_dynamic_table(const std::string& name) {
 return refresh_tables.count(lower(name)) != 0;
}
template <sql_parser::Dialect dialect>
Status refresh_query(const std::string& sql, std::string& out, std::vector<std::string>* relations) {
 out.clear();
 if (relations) relations->clear();
 try {
  if (sql.size() > 1048576) return fail(ErrorKind::resource, "Admin SQL exceeds size limit");
  using namespace sql_parser;
  Parser<dialect> parser;
  auto parsed = parser.parse(sql.data(), sql.size());
  if (parsed.status != ParseResult::OK || !parsed.full_input || parsed.has_remaining() ||
      !parsed.ast || parsed.ast->next_sibling)
   return fail(ErrorKind::syntax, "Admin SQL requires one complete statement");
  switch (parsed.stmt_type) {
   case StmtType::SELECT: case StmtType::INSERT: case StmtType::REPLACE:
   case StmtType::UPDATE: case StmtType::DELETE_STMT: break;
   default: return fail(ErrorKind::unsupported, "Admin statement is unsupported");
  }
  std::set<std::string> tables;
  const char* reason = nullptr;
  auto walked = walk_ast(parsed.ast, [&](const AstNode& node, const AstVisitContext&) {
   if (node.type == NodeType::NODE_CTE || node.type == NodeType::NODE_CTE_DEFINITION) {
    reason = "Admin prepared CTE scope is unsupported";
    return AstVisitAction::Stop;
   }
   if (node.type != NodeType::NODE_TABLE_REF || !node.first_child) return AstVisitAction::Continue;
   const AstNode* name = node.first_child;
   if (name->type == NodeType::NODE_QUALIFIED_NAME) {
    const AstNode* schema = name->first_child;
    name = schema ? schema->next_sibling : nullptr;
    if (!schema || !schema->value_ptr || lower(std::string(schema->value_ptr, schema->value_len)) != "main" ||
        !name || name->next_sibling) {
     reason = "Admin prepared cross-schema references are unsupported";
     return AstVisitAction::Stop;
    }
   }
   if (name->type == NodeType::NODE_IDENTIFIER && name->value_ptr) {
    std::string relation = lower(std::string(name->value_ptr, name->value_len));
    if (reset_tables.count(relation)) {
     reason = "Admin prepared statistics reset projections are unsupported";
     return AstVisitAction::Stop;
    }
    if (refresh_tables.count(relation)) tables.insert(std::move(relation));
   }
   return AstVisitAction::Continue;
  });
  if (reason) return fail(ErrorKind::unsupported, reason);
  if (walked.status != AstWalkStatus::Completed) return fail(ErrorKind::unsupported, "Admin AST traversal failed");
  std::string request;
  for (const auto& table : tables) {
   if (request.empty()) request = "SELECT * FROM "; else request += ", ";
   request += table;
  }
  if (relations) relations->assign(tables.begin(), tables.end());
  out.swap(request);
  return {};
 } catch (const std::bad_alloc&) { return fail(ErrorKind::resource, "Cannot allocate Admin statistics request"); }
}
Status admin_sqlite_statistics_refresh_query(const std::string& sql, std::string& out,
                                             std::vector<std::string>* relations, SQLSourceDialect dialect) {
    return dialect == SQLSourceDialect::postgresql
        ? refresh_query<sql_parser::Dialect::PostgreSQL>(sql, out, relations)
        : refresh_query<sql_parser::Dialect::MySQL>(sql, out, relations);
}
}
