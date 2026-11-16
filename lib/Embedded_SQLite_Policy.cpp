#include "Embedded_SQLite_Policy.h"
#include "sqlite3db.h"
#include "sql_parser/parser.h"
#include "sql_parser/ast_walk.h"
#include <algorithm>
#include <cctype>
#include <unordered_set>
#include <utility>

namespace embedded {
bool sqlite_prepared_function_allowed(const std::string& input) {
 static const std::unordered_set<std::string> names = {
  "count","sum","avg","min","max","abs","round","length","lower","upper",
  "coalesce","ifnull","nullif","substr","substring","hex","typeof","sqlite_version",
  "last_insert_rowid","changes","total_changes","date","time","datetime","julianday",
  "strftime","printf","random","randomblob","zeroblob","json","json_array",
  "json_object","json_quote","json_extract","json_array_length","json_type",
  "json_valid","json_error_position","json_pretty","jsonb","jsonb_array",
  "jsonb_object","jsonb_extract"
 };
 std::string name = input;
 std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
 return names.count(name) != 0;
}
namespace {
using namespace sql_parser;
Status error(ErrorKind kind, const char* message, int code = 0) {
 return Error{kind, code, message, kind == ErrorKind::internal ? "HY000" : "42000"};
}
bool safe_function(const AstNode& n) {
 return n.value_ptr && sqlite_prepared_function_allowed(std::string(n.value_ptr, n.value_len));
}
bool root_matches(StmtType s, NodeType n) {
 switch (s) {
 case StmtType::SELECT: return n == NodeType::NODE_SELECT_STMT || n == NodeType::NODE_COMPOUND_QUERY || n == NodeType::NODE_CTE;
 case StmtType::INSERT: case StmtType::REPLACE: return n == NodeType::NODE_INSERT_STMT;
 case StmtType::UPDATE: return n == NodeType::NODE_UPDATE_STMT;
 case StmtType::DELETE_STMT: return n == NodeType::NODE_DELETE_STMT;
 default: return false;
 }
}
template <Dialect dialect>
Status classify(const std::string& sql, bool& is_select) {
 if (sql.size() > 1048576) return error(ErrorKind::resource, "SQL exceeds policy size limit");
 Parser<dialect> parser;
 auto parsed = parser.parse(sql.data(), sql.size());
 if (parsed.status != ParseResult::OK || !parsed.full_input || parsed.has_remaining() || !parsed.ast || parsed.ast->next_sibling)
  return error(ErrorKind::syntax, "SQL must be one fully parsed statement");
 if (!root_matches(parsed.stmt_type, parsed.ast->type)) return error(ErrorKind::policy, "Statement is not admitted");
 if (parsed.has_user_variables) return error(ErrorKind::policy, "User variables are not admitted");
 is_select = parsed.stmt_type == StmtType::SELECT;
 bool denied = false;
 auto result = walk_ast(parsed.ast, [&](const AstNode& n, const AstVisitContext& ctx) {
  using N = NodeType;
  switch (n.type) {
  case N::NODE_FUNCTION_CALL: if (!safe_function(n)) denied = true; break;
  case N::NODE_SELECT_STMT: case N::NODE_COMPOUND_QUERY: case N::NODE_CTE: break;
  case N::NODE_INSERT_STMT: case N::NODE_UPDATE_STMT: case N::NODE_DELETE_STMT:
   if (is_select || ctx.parent) denied = true;
   break;
  case N::NODE_TABLE_REF: case N::NODE_SCHEMA_REF: case N::NODE_IDENTIFIER: case N::NODE_QUALIFIED_NAME:
  case N::NODE_SELECT_OPTIONS: case N::NODE_SELECT_ITEM_LIST: case N::NODE_SELECT_ITEM:
  case N::NODE_FROM_CLAUSE: case N::NODE_JOIN_CLAUSE: case N::NODE_WHERE_CLAUSE:
  case N::NODE_GROUP_BY_CLAUSE: case N::NODE_HAVING_CLAUSE: case N::NODE_ORDER_BY_CLAUSE:
  case N::NODE_ORDER_BY_ITEM: case N::NODE_LIMIT_CLAUSE: case N::NODE_ALIAS:
  case N::NODE_EXPRESSION: case N::NODE_BINARY_OP: case N::NODE_UNARY_OP:
  case N::NODE_LITERAL_INT: case N::NODE_LITERAL_FLOAT: case N::NODE_LITERAL_STRING:
  case N::NODE_LITERAL_NULL: case N::NODE_PLACEHOLDER: case N::NODE_SUBQUERY:
  case N::NODE_COLUMN_REF: case N::NODE_ASTERISK: case N::NODE_IS_NULL: case N::NODE_IS_NOT_NULL:
  case N::NODE_BETWEEN: case N::NODE_IN_LIST: case N::NODE_CASE_WHEN: case N::NODE_TUPLE:
  case N::NODE_INSERT_COLUMNS: case N::NODE_VALUES_CLAUSE: case N::NODE_VALUES_ROW:
  case N::NODE_INSERT_SET_CLAUSE: case N::NODE_ON_DUPLICATE_KEY: case N::NODE_ON_CONFLICT:
  case N::NODE_CONFLICT_TARGET: case N::NODE_CONFLICT_ACTION: case N::NODE_RETURNING_CLAUSE:
  case N::NODE_UPDATE_SET_CLAUSE: case N::NODE_DELETE_USING_CLAUSE: case N::NODE_SET_OPERATION:
  case N::NODE_WINDOW_FUNCTION: case N::NODE_WINDOW_SPEC: case N::NODE_WINDOW_PARTITION:
  case N::NODE_WINDOW_ORDER: case N::NODE_CTE_DEFINITION: case N::NODE_STMT_OPTIONS:
  case N::NODE_UPDATE_SET_ITEM: case N::NODE_LITERAL_HEX: case N::NODE_LITERAL_BIT:
  case N::NODE_WINDOW_CLAUSE: case N::NODE_WINDOW_DEFINITION: case N::NODE_WINDOW_REFERENCE:
  case N::NODE_WINDOW_FRAME: case N::NODE_WINDOW_BOUND: case N::NODE_WINDOW_EXCLUSION:
  case N::NODE_CTE_COLUMNS: case N::NODE_MYSQL_JSON_EXTRACT: case N::NODE_MYSQL_SUBSTRING:
   break;
  default: denied = true; break;
  }
  return denied ? AstVisitAction::Stop : AstVisitAction::Continue;
 });
 if (denied || result.status != AstWalkStatus::Completed) return error(ErrorKind::policy, "SQL contains a disallowed construct or function");
 return {};
}
}
SQLitePolicy::SQLitePolicy(sqlite3* db, std::function<bool()> ac, std::function<bool()> ro, SQLSourceDialect dialect)
 : dialect_(dialect), connection_(db), autocommit_(std::move(ac)), read_only_(std::move(ro)) {}
Status SQLitePolicy::admit(const std::string& sql, bool fetch) {
 if (!connection_ || !autocommit_ || !read_only_) return error(ErrorKind::internal, "SQLite policy is not configured");
 if (!cached_ || cached_sql_ != sql) {
  bool select = false;
  auto status = dialect_ == SQLSourceDialect::postgresql
      ? classify<Dialect::PostgreSQL>(sql, select) : classify<Dialect::MySQL>(sql, select);
  cached_ = sql.size() <= 1048576;
  cached_sql_ = cached_ ? sql : std::string{};
  cached_status_ = status;
  cached_select_ = select;
 }
 if (cached_status_) return cached_status_;
 const bool read_only = read_only_();
 if ((fetch || read_only) && !cached_select_) return error(ErrorKind::policy, "Only SELECT is admitted in this state");
 return {};
}
Status SQLitePolicy::authorize_prepare(const std::string& sql) { return admit(sql, false); }
Status SQLitePolicy::authorize_fetch(const std::string& sql) { return admit(sql, true); }
Status SQLitePolicy::authorize_execute(const std::string& sql, const std::vector<Value>&) {
 if (auto status = admit(sql, false)) return status;
 if (!autocommit_()) {
  if (!proxy_sqlite3_get_autocommit || !proxy_sqlite3_exec) return error(ErrorKind::internal, "SQLite functions are not configured");
  if (proxy_sqlite3_get_autocommit(connection_)) {
   int rc = proxy_sqlite3_exec(connection_, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
   if (rc != SQLITE_OK) return error(ErrorKind::transaction, "BEGIN IMMEDIATE failed", rc);
  }
 }
 return {};
}
}
