#include "Embedded_SQLite_Policy.h"
#include "sqlite3db.h"
#include "tap.h"
#include <string>
using embedded::SQLitePolicy;
static int native_calls = 0;
static int count_autocommit(sqlite3*) { ++native_calls; return 1; }
static int count_exec(sqlite3*, const char*, int (*)(void*, int, char**, char**), void*, char**) {
 ++native_calls;
 return SQLITE_OK;
}
int main() {
 plan(39);
 sqlite3* db = nullptr;
 ok(sqlite3_open(":memory:", &db) == SQLITE_OK, "open database");
 sqlite3_exec(db, "CREATE TABLE t(x)", nullptr, nullptr, nullptr);
 bool ac = true, ro = false;
 SQLitePolicy policy(db, [&] { return ac; }, [&] { return ro; });
 ok(!policy.authorize_prepare("SELECT count(*) FROM t"), "select admitted");
 sqlite3_stmt* stmt = nullptr;
 ok(sqlite3_prepare_v2(db, "SELECT count(*) FROM t", -1, &stmt, nullptr) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW, "admitted select prepares and executes natively");
 sqlite3_finalize(stmt);
 ok(!policy.authorize_prepare("INSERT INTO t VALUES (?)"), "insert admitted");
 ok(!policy.authorize_prepare("UPDATE t SET x = 2"), "update admitted");
 ok(!policy.authorize_prepare("DELETE FROM t WHERE x = 1"), "delete admitted");
 ok(!policy.authorize_prepare("SELECT (SELECT abs(1))"), "nested safe select admitted");
 for (const char* sql : {"SELECT load_extension('x')", "SELECT (SELECT load_extension('x'))",
                         "SELECT main.load_extension('x')", "SELECT `load_extension`('x')",
                         "SELECT \"load_extension\"('x')", "SELECT [load_extension]('x')"})
  ok(bool(policy.authorize_prepare(sql)), "unsafe function spelling rejected: %s", sql);
 for (const char* sql : {"SELECT 1; SELECT 2", "SELECT 1 garbage garbage", "PRAGMA user_version=3", "ATTACH DATABASE ':memory:' AS evil", "SELECT load_extension('x')", "SELECT eval('DELETE FROM t')", "SELECT @foo", "SELECT 1 FOR UPDATE", "WITH c AS (DELETE FROM t RETURNING x) SELECT * FROM c", "SELECT unknown_function(1)", "SELECT 1 INTO OUTFILE 'x'"})
  ok(bool(policy.authorize_prepare(sql)), "disallowed SQL rejected: %s", sql);
 ok(!policy.authorize_prepare("INSERT INTO t VALUES (1)"), "write admitted before role change");
 ro = true;
 ok(bool(policy.authorize_execute("INSERT INTO t VALUES (1)", {})), "cached write rejected after role change");
 ok(bool(policy.authorize_prepare("INSERT INTO t VALUES (1)")), "cached write prepare rejected after role change");
 ro = false;
 ok(!policy.authorize_execute("INSERT INTO t VALUES (1)", {}), "cached write admitted after role restored");
 ro = false; ac = false;
 ok(!policy.authorize_prepare("SELECT 1") && sqlite3_get_autocommit(db), "prepare does not begin");
 ok(!policy.authorize_fetch("SELECT 1") && sqlite3_get_autocommit(db), "fetch does not begin");
 ok(!policy.authorize_execute("SELECT 1", {}) && !sqlite3_get_autocommit(db), "execute begins deferred transaction");
 ok(!policy.authorize_execute("SELECT 1", {}) && !sqlite3_get_autocommit(db), "subsequent execute retains transaction");
 sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
 ac = true;
 ok(!policy.authorize_execute("SELECT 1", {}) && sqlite3_get_autocommit(db), "autocommit execute does not begin");
 ok(bool(policy.authorize_fetch("INSERT INTO t VALUES (1)")), "fetch rejects write");
 auto saved_get_autocommit = proxy_sqlite3_get_autocommit;
 auto saved_exec = proxy_sqlite3_exec;
 proxy_sqlite3_get_autocommit = count_autocommit;
 proxy_sqlite3_exec = count_exec;
 SQLitePolicy bad(nullptr, [] { return true; });
 ok(bool(bad.authorize_execute("SELECT 1", {})) && sqlite3_get_autocommit(db), "null connection rejected without transaction");
 SQLitePolicy no_autocommit(db, {});
 auto missing_ac = no_autocommit.authorize_execute("SELECT 1", {});
 ok(missing_ac && missing_ac->kind == embedded::ErrorKind::internal && sqlite3_get_autocommit(db), "empty autocommit callback rejected without transaction");
 SQLitePolicy no_read_only(db, [] { return false; }, {});
 auto missing_ro = no_read_only.authorize_execute("SELECT 1", {});
 ok(missing_ro && missing_ro->kind == embedded::ErrorKind::internal && sqlite3_get_autocommit(db), "empty read-only callback rejected without transaction");
 ok(bool(no_read_only.authorize_prepare("SELECT 1")) && bool(no_autocommit.authorize_fetch("SELECT 1")) && native_calls == 0, "missing configuration performs no native calls");
 proxy_sqlite3_get_autocommit = saved_get_autocommit;
 proxy_sqlite3_exec = saved_exec;
 ac = false;
 auto original_exec = proxy_sqlite3_exec;
 proxy_sqlite3_exec = [](sqlite3*, const char*, int (*)(void*, int, char**, char**), void*, char**) { return SQLITE_BUSY; };
 auto failure = policy.authorize_execute("SELECT 1", {});
 ok(failure && failure->kind == embedded::ErrorKind::transaction && failure->native_code == SQLITE_BUSY && sqlite3_get_autocommit(db), "failed BEGIN propagates without opening transaction");
 proxy_sqlite3_exec = original_exec;
 sqlite3_close(db);
 return exit_status();
}
