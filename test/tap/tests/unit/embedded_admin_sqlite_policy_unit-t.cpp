#include "Embedded_Admin_SQLite_Policy.h"
#include "sqlite3db.h"
#include "tap.h"
#include <memory>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>
#include <exception>
using namespace embedded;
static int calls = 0;
static int fail_removal(sqlite3*, int (*)(void*, int, const char*, const char*, const char*, const char*), void*) { return SQLITE_ERROR; }
static void udf(sqlite3_context* ctx, int, sqlite3_value**) { ++calls; sqlite3_result_int(ctx, 42); }
static int run(sqlite3* db, const char* sql) { return sqlite3_exec(db, sql, nullptr, nullptr, nullptr); }
int main() {
 plan(NO_PLAN);
 sqlite3* db = nullptr; ok(sqlite3_open(":memory:", &db) == SQLITE_OK, "open database");
 run(db, "CREATE TABLE t(x); CREATE TABLE forbidden(x); INSERT INTO t VALUES(1); ATTACH ':memory:' AS other; CREATE TABLE other.t(x); CREATE VIEW v AS SELECT unsafe(x) FROM t; CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO forbidden VALUES(unsafe(new.x)); END");
 sqlite3_create_function(db, "unsafe", 1, SQLITE_UTF8, nullptr, udf, nullptr, nullptr);
 bool ro = false, held = true;
 AdminSQLitePolicy policy(db, [&] { return ro; }, [&] { return held; }, {"t"});
 std::unique_ptr<OperationGuard> guard, nested;
 held = false; ok(bool(policy.guard(guard)) && !guard, "missing lock rejected"); held = true;
 AdminSQLitePolicy bad(db, {}, [] { return true; }, {"t"});
 ok(bool(bad.guard(guard)) && !guard, "missing callback rejected");
 ok(!policy.guard(guard) && guard, "guard installs authorizer");
 ok(bool(policy.guard(nested)) && !nested, "nested guard rejected");
 ok(!policy.authorize_prepare("SELECT abs(x) FROM t") && run(db, "SELECT abs(x) FROM t") == SQLITE_OK, "safe select admitted");
 ok(!policy.authorize_execute("UPDATE t SET x=2", {}) && run(db, "UPDATE t SET x=2") == SQLITE_OK, "editable update admitted");
 ok(run(db, "DELETE FROM t") == SQLITE_OK, "editable delete admitted");
 ok(run(db, "INSERT INTO forbidden VALUES(1)") == SQLITE_AUTH, "noneditable table denied");
 ok(run(db, "INSERT INTO t VALUES(1)") == SQLITE_AUTH && calls == 0, "trigger denied without side effects");
 ok(run(db, "SELECT * FROM v") == SQLITE_ERROR && calls == 0, "unsafe view denied without side effects");
 ok(run(db, "SELECT unsafe(1)") == SQLITE_ERROR && calls == 0, "unknown extension function denied");
 ok(run(db, "SELECT * FROM other.t") == SQLITE_AUTH, "attached schema read denied");
 ok(run(db, "PRAGMA user_version=1") == SQLITE_AUTH, "pragma denied");
 ok(run(db, "ATTACH ':memory:' AS x") == SQLITE_AUTH, "attach denied");
 ok(run(db, "CREATE TABLE z(x)") == SQLITE_AUTH, "DDL denied");
 ok(run(db, "BEGIN") == SQLITE_AUTH && sqlite3_get_autocommit(db), "transaction denied");
 ro = true;
 ok(bool(policy.authorize_execute("UPDATE t SET x=3", {})) && run(db, "UPDATE t SET x=3") == SQLITE_AUTH, "read-only flip denies writes");
 ro = false; ok(run(db, "UPDATE t SET x=4") == SQLITE_OK, "write restored after read-only flip");
 ok(!policy.authorize_execute("SELECT 1", {}) && sqlite3_get_autocommit(db), "policy never begins transaction");
 guard.reset();
 ok(run(db, "DROP TRIGGER tr") == SQLITE_OK, "remove trigger for direct insert test");
 ok(!policy.guard(guard) && !policy.authorize_execute("INSERT INTO t VALUES(8)", {}) && run(db, "INSERT INTO t VALUES(8)") == SQLITE_OK, "editable insert admitted");
 guard.reset();
 ok(run(db, "PRAGMA user_version=1") == SQLITE_OK && run(db, "SELECT unsafe(1)") == SQLITE_OK && calls == 1, "guard restores native behavior");
 sqlite3_create_function(db, "abs", 1, SQLITE_UTF8, nullptr, udf, nullptr, nullptr);
 sqlite3_stmt* stmt = nullptr; int duplicates = 0;
 sqlite3_prepare_v2(db, "SELECT builtin FROM pragma_function_list WHERE name='abs'", -1, &stmt, nullptr);
 while (sqlite3_step(stmt) == SQLITE_ROW) ++duplicates;
 sqlite3_finalize(stmt);
 ok(duplicates >= 2, "function list exposes builtin and override registrations");
 ok(bool(policy.guard(guard)) && !guard && calls == 1, "builtin override rejected without executing it");
 run(db, "CREATE TABLE main.pragma_function_list(name,builtin)");
 ok(bool(policy.guard(guard)) && !guard && calls == 1, "main function-list shadow cannot hide override");
 run(db, "CREATE TEMP TABLE pragma_function_list(name,builtin)");
 ok(bool(policy.guard(guard)) && !guard && calls == 1, "temp function-list shadow cannot hide override");
 sqlite3_create_function(db, "abs", 1, SQLITE_UTF8, nullptr, nullptr, nullptr, nullptr);
 ok(!policy.guard(guard) && guard, "guard works after override removed");
 guard.reset(); ok(sqlite3_get_autocommit(db), "guard cleanup leaves transaction state unchanged");
 ok(bool(policy.authorize_prepare("SELECT 1")), "policy requires a guard");
 int refresh = 0; bool reject = false;
 AdminSQLitePolicy refresh_policy(db, [&] { return ro; }, [&] { return held; }, {"t"}, [&](const std::string&) -> Status {
  ++refresh;
  if (reject) return Error{ErrorKind::internal, 0, "refresh failed", "HY000"};
  if (run(db, "INSERT INTO forbidden VALUES(3)") != SQLITE_OK) return Error{ErrorKind::internal, 0, "refresh blocked", "HY000"};
  return {};
 });
 ok(!refresh_policy.guard(guard) && bool(refresh_policy.authorize_execute("PRAGMA user_version", {})) && refresh == 0, "unsupported SQL does not refresh");
 ro = true; ok(bool(refresh_policy.authorize_execute("UPDATE t SET x=1", {})) && refresh == 0, "read-only denial does not refresh"); ro = false;
 reject = true; ok(bool(refresh_policy.authorize_execute("UPDATE t SET x=1", {})) && refresh == 1, "refresh failure prevents authorization");
 reject = false; ok(!refresh_policy.authorize_execute("UPDATE t SET x=1", {}) && refresh == 2, "trusted refresh runs before authorizer");
 ok(run(db, "INSERT INTO forbidden VALUES(4)") == SQLITE_AUTH, "user operations protected after refresh");
 auto misuse = refresh_policy.authorize_execute("UPDATE t SET x=2", {});
 ok(misuse && misuse->kind == ErrorKind::internal && refresh == 2, "armed lease rejects another refresh");
 guard.reset(); ok(run(db, "INSERT INTO forbidden VALUES(5)") == SQLITE_OK, "cleanup restores native behavior after callback");
 run(db, "CREATE TABLE stats_mysql_query_digest_reset(x)");
 run(db, "CREATE VIEW hidden_reset AS SELECT x FROM stats_mysql_query_digest_reset");
 ok(!policy.guard(guard) && bool(policy.authorize_prepare("SELECT * FROM stats_mysql_query_digest_reset")),
    "direct destructive reset projection is refused before native prepare");
 guard.reset();
 ok(!policy.guard(guard) && !policy.authorize_prepare("SELECT * FROM hidden_reset") &&
    run(db, "SELECT * FROM hidden_reset") == SQLITE_AUTH,
    "a view cannot hide a reset projection from native authorization");
 guard.reset();
 std::string request;
 AdminSQLitePolicy canonical(db, [&] { return ro; }, [&] { return held; }, {"t"},
    [&](const std::string& sql) -> Status { request = sql; return {}; });
 ok(!canonical.guard(guard) && !canonical.authorize_execute("SELECT 'stats_mysql_query_digest_reset', ?", {}) && request.empty(),
    "literal reset names never reach the trusted refresh callback");
 guard.reset();
 ok(!canonical.guard(guard) && !canonical.authorize_execute("SELECT * FROM STATS_MYSQL_GLOBAL", {}) && request == "SELECT * FROM stats_mysql_global",
    "statistics callback receives canonical relation names rather than raw SQL");
 guard.reset();
 run(db, "CREATE TABLE stats_mysql_global(x); CREATE VIEW hidden_stats AS SELECT x FROM stats_mysql_global");
 ok(!policy.guard(guard) && !policy.authorize_prepare("SELECT * FROM hidden_stats") &&
    run(db, "SELECT * FROM hidden_stats") == SQLITE_AUTH,
    "hidden dynamic statistics dependencies are refused instead of returning stale rows");
 guard.reset();
 std::string pg_request;
 AdminSQLitePolicy pg(db, [] { return true; }, [&] { return held; }, {},
    [&](const std::string& sql) -> Status { pg_request = sql; return {}; },
    embedded::SQLSourceDialect::postgresql);
 ok(!pg.guard(guard) && !pg.authorize_execute("SELECT * FROM \"stats_pgsql_global\" WHERE $1 = 1", {}) &&
    pg_request == "SELECT * FROM stats_pgsql_global", "PostgreSQL dialect reaches source policy and statistics refresh");
 guard.reset();
 ok(!pg.guard(guard) && bool(pg.authorize_prepare("SELECT unsafe_udf($1)")), "PostgreSQL admin rejects unsafe function");
 guard.reset();
 ok(!pg.guard(guard) && bool(pg.authorize_prepare("INSERT INTO t VALUES (1)")), "PostgreSQL admin rejects writes");
 guard.reset();
 pid_t child = fork();
 if (child == 0) {
  std::set_terminate([] { _Exit(77); });
  std::unique_ptr<OperationGuard> child_guard;
  if (policy.guard(child_guard) || policy.authorize_prepare("SELECT 1")) _Exit(78);
  proxy_sqlite3_set_authorizer = fail_removal;
  child_guard.reset();
  _Exit(79);
 }
 int child_status = 0; if (child > 0) waitpid(child, &child_status, 0);
 ok(child > 0 && WIFEXITED(child_status) && WEXITSTATUS(child_status) == 77, "failed authorizer removal terminates before callback context is freed");
 sqlite3_close(db); return exit_status();
}
