#pragma once
#include "Embedded_SQLite_Policy.h"
#include <vector>
namespace embedded {
// Provider owns the connection's authorizer slot (SQLite has no getter). No
// unrelated authorizer may be installed. Hold the Admin SQL global mutex across
// the entire guard lifetime, including prepare, execute, fetch and finalize.
// The connection, callbacks and policy must outlive every guard. Authorizer
// removal failure terminates the process to avoid a dangling native callback.
// Perform startup gating before guard acquisition. The trusted before_execute callback
// may refresh statistics but must never execute user SQL.
// before_execute receives a canonical, non-destructive statistics refresh
// request derived from relation ASTs, or an empty string. It never receives
// original SQL. It runs after admission and before native authorization arms.
class AdminSQLitePolicy final : public EndpointPolicy {
public:
 AdminSQLitePolicy(sqlite3*, std::function<bool()> read_only,
                   std::function<bool()> lock_held, std::vector<std::string> editable_tables,
                   std::function<Status(const std::string&)> before_execute = {},
                   SQLSourceDialect dialect = SQLSourceDialect::mysql);
 Status guard(std::unique_ptr<OperationGuard>& out);
 Status authorize_prepare(const std::string&) override;
 Status authorize_execute(const std::string&, const std::vector<Value>&) override;
 Status authorize_fetch(const std::string&) override;
private:
 SQLSourceDialect dialect_;
 sqlite3* db_;
 std::function<bool()> read_only_, lock_held_;
 std::vector<std::string> editable_;
 SQLitePolicy source_;
 std::function<Status(const std::string&)> before_execute_;
 Status arm(const std::vector<std::string>& relations = {});
};
}
