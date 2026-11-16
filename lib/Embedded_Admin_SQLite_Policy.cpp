#include "Embedded_Admin_SQLite_Policy.h"
#include "Embedded_Admin_Statistics.h"
#include "sqlite3db.h"
#include <algorithm>
#include <cctype>
#include <exception>
#include <mutex>
#include <unordered_map>
#include <utility>
namespace embedded {
namespace {
std::mutex registry_mutex;
struct NativeGuard;
std::unordered_map<sqlite3*, NativeGuard*> active;
Status fail(const char* msg, int rc = 0) { return Error{ErrorKind::policy, rc, msg, "42000"}; }
std::string lower(const char* s) {
 std::string result = s ? s : "";
 std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
 return result;
}
struct NativeGuard final : OperationGuard {
 sqlite3* db;
 AdminSQLitePolicy* owner;
 std::function<bool()> read_only;
 std::vector<std::string> editable;
 std::vector<std::string> refreshed_relations;
 bool installed = false;
 NativeGuard(sqlite3* d, AdminSQLitePolicy* o, std::function<bool()> r, std::vector<std::string> e)
  : db(d), owner(o), read_only(std::move(r)), editable(std::move(e)) {}
 ~NativeGuard() override {
  if (installed && proxy_sqlite3_set_authorizer(db, nullptr, nullptr) != SQLITE_OK) std::terminate();
  std::lock_guard<std::mutex> lock(registry_mutex);
  active.erase(db);
 }
 static int authorize(void* context, int action, const char* a, const char* b, const char* dbname, const char*) noexcept {
  try {
   auto& self = *static_cast<NativeGuard*>(context);
   switch (action) {
   case SQLITE_SELECT: case SQLITE_RECURSIVE: return SQLITE_OK;
   case SQLITE_READ: {
    if (!dbname || lower(dbname) != "main" || !a || admin_sqlite_statistics_reset_table(a)) return SQLITE_DENY;
    const std::string table = lower(a);
    if (admin_sqlite_statistics_dynamic_table(table) &&
        std::find(self.refreshed_relations.begin(), self.refreshed_relations.end(), table) == self.refreshed_relations.end())
     return SQLITE_DENY; // A hidden view dependency has no established refresh.
    return SQLITE_OK;
   }
   case SQLITE_FUNCTION: return b && sqlite_prepared_function_allowed(b) ? SQLITE_OK : SQLITE_DENY;
   case SQLITE_INSERT: case SQLITE_UPDATE: case SQLITE_DELETE:
    if (!dbname || lower(dbname) != "main" || !a || self.read_only()) return SQLITE_DENY;
    return std::find(self.editable.begin(), self.editable.end(), lower(a)) != self.editable.end() ? SQLITE_OK : SQLITE_DENY;
   default: return SQLITE_DENY;
   }
  } catch (...) { return SQLITE_DENY; }
 }
};
}
AdminSQLitePolicy::AdminSQLitePolicy(sqlite3* db, std::function<bool()> ro, std::function<bool()> held, std::vector<std::string> tables, std::function<Status(const std::string&)> before_execute)
 : db_(db), read_only_(std::move(ro)), lock_held_(std::move(held)), editable_(std::move(tables)), source_(db, [] { return true; }, read_only_), before_execute_(std::move(before_execute)) {
 for (auto& table : editable_) table = lower(table.c_str());
}
Status AdminSQLitePolicy::guard(std::unique_ptr<OperationGuard>& out) {
 out.reset();
 try {
  if (!db_ || !read_only_ || !lock_held_ || !lock_held_() || !proxy_sqlite3_set_authorizer ||
      !proxy_sqlite3_prepare_v2 || !proxy_sqlite3_step || !proxy_sqlite3_finalize ||
      !proxy_sqlite3_column_text || !proxy_sqlite3_column_int) return fail("Admin SQLite policy is not configured or lock is not held");
  {
   std::lock_guard<std::mutex> lock(registry_mutex);
   if (!active.emplace(db_, nullptr).second) return fail("Admin SQLite authorizer guard already active");
  }
  std::unique_ptr<NativeGuard> guard;
  try { guard.reset(new NativeGuard(db_, this, read_only_, editable_)); }
  catch (...) { std::lock_guard<std::mutex> lock(registry_mutex); active.erase(db_); throw; }
  sqlite3_stmt* stmt = nullptr;
  int rc = proxy_sqlite3_prepare_v2(db_, "PRAGMA function_list", -1, &stmt, nullptr);
  if (rc != SQLITE_OK) { if (stmt) proxy_sqlite3_finalize(stmt); return fail("Cannot inspect SQLite functions", rc); }
  struct Finalize { sqlite3_stmt* stmt; ~Finalize() { if (stmt) proxy_sqlite3_finalize(stmt); } } finalize{stmt};
  bool shadow = false, invalid = false;
  while ((rc = proxy_sqlite3_step(stmt)) == SQLITE_ROW) {
   const auto* name = proxy_sqlite3_column_text(stmt, 0);
   if (!name) { invalid = true; break; }
   if (!proxy_sqlite3_column_int(stmt, 1) && sqlite_prepared_function_allowed(reinterpret_cast<const char*>(name))) { shadow = true; break; }
  }
  int final_rc = proxy_sqlite3_finalize(stmt);
  finalize.stmt = nullptr;
  if (invalid) return fail("Cannot inspect SQLite function name");
  if (shadow) return fail("Allowed SQLite function is overridden");
  if (rc != SQLITE_DONE || final_rc != SQLITE_OK) return fail("Cannot inspect SQLite functions", rc != SQLITE_DONE ? rc : final_rc);
  { std::lock_guard<std::mutex> lock(registry_mutex); active[db_] = guard.get(); }
  out = std::move(guard);
  return {};
 } catch (...) { return fail("Admin SQLite policy callback or allocation failed"); }
}
Status AdminSQLitePolicy::arm(const std::vector<std::string>& relations) {
 try {
  if (!lock_held_ || !lock_held_()) return fail("Admin SQLite lock is not held");
  std::lock_guard<std::mutex> lock(registry_mutex);
  auto it = active.find(db_);
  if (it == active.end() || !it->second || it->second->owner != this) return fail("Admin SQLite guard is not active");
  auto* guard = it->second;
  if (guard->installed) return {};
  guard->refreshed_relations = relations;
  if (std::find(relations.begin(), relations.end(), "stats_pgsql_stat_activity") != relations.end())
   guard->refreshed_relations.push_back("stats_pgsql_processlist"); // Standard view definition.
  int rc = proxy_sqlite3_set_authorizer(db_, NativeGuard::authorize, guard);
  if (rc != SQLITE_OK) return fail("Cannot install SQLite authorizer", rc);
  guard->installed = true;
  return {};
 } catch (...) { return fail("Admin SQLite guard callback failed"); }
}
Status AdminSQLitePolicy::authorize_prepare(const std::string& sql) {
 try {
  if (auto status = source_.authorize_prepare(sql)) return status;
  std::string refresh;
  std::vector<std::string> relations;
  if (auto status = admin_sqlite_statistics_refresh_query(sql, refresh, &relations)) return status;
  return arm(relations);
 }
 catch (...) { return fail("Admin SQLite policy callback failed"); }
}
Status AdminSQLitePolicy::authorize_execute(const std::string& sql, const std::vector<Value>& v) {
 try {
  if (auto status = source_.authorize_execute(sql, v)) return status;
  std::string refresh;
  std::vector<std::string> relations;
  if (auto status = admin_sqlite_statistics_refresh_query(sql, refresh, &relations)) return status;
  if (!lock_held_ || !lock_held_()) return fail("Admin SQLite lock is not held");
  {
   std::lock_guard<std::mutex> lock(registry_mutex);
   auto it = active.find(db_);
   if (it == active.end() || !it->second || it->second->owner != this) return fail("Admin SQLite guard is not active");
   if (it->second->installed && before_execute_) return Error{ErrorKind::internal, 0, "Trusted refresh requires an unarmed guard", "HY000"};
  }
  if (before_execute_) if (auto status = before_execute_(refresh)) return status;
  return arm(relations);
 } catch (...) { return fail("Admin SQLite policy callback failed"); }
}
Status AdminSQLitePolicy::authorize_fetch(const std::string& sql) {
 try { if (auto status = source_.authorize_fetch(sql)) return status; return arm(); }
 catch (...) { return fail("Admin SQLite policy callback failed"); }
}
}
