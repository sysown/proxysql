#include "prepared_owned_fixture.h"
#include <mysql.h>
#include "tap.h"
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <stdexcept>
#include <vector>

static const char* required(const char* name) {
 const char* value = std::getenv(name);
 if (!value || !*value) BAIL_OUT("%s is required", name);
 return value;
}
static bool query(MYSQL* c, const std::string& sql) {
 if (mysql_query(c, sql.c_str())) { diag("query failed: %s: %s", sql.c_str(), mysql_error(c)); return false; }
 MYSQL_RES* r = mysql_store_result(c); if (r) mysql_free_result(r);
 return true;
}
static MYSQL_STMT* prepare(MYSQL* c, const std::string& sql) {
 MYSQL_STMT* s = mysql_stmt_init(c);
 if (!s) return nullptr;
 if (mysql_stmt_prepare(s, sql.data(), sql.size())) { diag("prepare failed: %s: %s", sql.c_str(), mysql_stmt_error(s)); mysql_stmt_close(s); return nullptr; }
 return s;
}
static void check_statement_limit(MYSQL* c) {
 std::vector<MYSQL_STMT*> handles;
 for (int i=0; i<128; ++i) {
  MYSQL_STMT* s=prepare(c, "SELECT 1");
  if (!s) break;
  handles.push_back(s);
 }
 ok(handles.size()==128, "Admin accepts the per-session limit of 128 prepared handles");
 MYSQL_STMT* overflow=mysql_stmt_init(c);
 const bool refused=overflow && mysql_stmt_prepare(overflow, "SELECT 1", 8)!=0;
 ok(refused, "Admin rejects a prepare above the statement limit");
 if (overflow) mysql_stmt_close(overflow);
 if (!handles.empty()) {
  mysql_stmt_close(handles.back());
  handles.pop_back();
 }
 MYSQL_STMT* recovered=prepare(c,"SELECT 1");
 ok(recovered!=nullptr, "closing a statement frees capacity");
 if (recovered) mysql_stmt_close(recovered);
 for (auto* s : handles) mysql_stmt_close(s);
}
static void check_schema_change(MYSQL* c) {
 const std::string name="admin_prepared_shape_"+std::to_string(getpid());
 if (!query(c,"CREATE TABLE "+name+" (id INTEGER)"))
  BAIL_OUT("cannot create the owned Admin schema fixture");
 MYSQL_STMT* old=prepare(c,"SELECT * FROM "+name);
 ok(old!=nullptr,"prepare against an owned Admin table");
 const bool changed=query(c,"ALTER TABLE "+name+" ADD COLUMN note TEXT");
 ok(changed && old && mysql_stmt_execute(old)!=0 && mysql_stmt_errno(old)==1615,
    "schema change requests reprepare before returning rows");
 if (old) mysql_stmt_close(old);
 MYSQL_STMT* fresh=prepare(c,"SELECT * FROM "+name);
 MYSQL_RES* fields=fresh ? mysql_stmt_result_metadata(fresh) : nullptr;
 ok(fields && mysql_num_fields(fields)==2,"reprepare reports the new Admin schema");
 if (fields) mysql_free_result(fields);
 if (fresh) mysql_stmt_close(fresh);
 ok(query(c,"DROP TABLE "+name),"drop the owned Admin schema fixture");
}
struct Cleanup {
 MYSQL* admin;
 std::string where;
 ~Cleanup() {
  query(admin, "PROXYSQL READWRITE");
  query(admin, "DELETE FROM mysql_servers WHERE " + where);
  query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
 }
};
int main() {
    prepared_owned_fixture::Fixture fixture("native", false);
 plan(NO_PLAN);
 const char* host = required("TAP_HOST");
 int port = std::atoi(required("TAP_ADMINPORT"));
 const char* au = required("TAP_ADMINUSERNAME"), *ap = required("TAP_ADMINPASSWORD");
 const char* su = required("TAP_STATSUSERNAME"), *sp = required("TAP_STATSPASSWORD");
 MYSQL* a = mysql_init(nullptr); MYSQL* st = mysql_init(nullptr);
 if (!a || !st || !mysql_real_connect(a, host, au, ap, nullptr, port, nullptr, 0) ||
     !mysql_real_connect(st, host, su, sp, nullptr, port, nullptr, 0)) BAIL_OUT("Admin/STATS connection failed");
 // The fixture requires read-only initially disabled. Check the live Admin
 // setting before creating the cleanup guard or changing runtime state.
 if (mysql_query(a, "SHOW GLOBAL VARIABLES LIKE 'read_only'")) BAIL_OUT("cannot inspect admin read-only: %s", mysql_error(a));
 MYSQL_RES* ro_result = mysql_store_result(a);
 MYSQL_ROW ro_row = ro_result ? mysql_fetch_row(ro_result) : nullptr;
 bool initially_off = ro_row && ro_row[1] && (!strcasecmp(ro_row[1], "OFF") || !strcmp(ro_row[1], "0") || !strcasecmp(ro_row[1], "false"));
 if (ro_result) mysql_free_result(ro_result);
 if (!initially_off) BAIL_OUT("fixture requires admin read-only initially false");
 const int hg = 1900000000 + (getpid() % 1000000);
 const std::string where = "hostgroup_id=" + std::to_string(hg) + " AND hostname='127.0.0.1' AND port=1";
 try {
 Cleanup cleanup{a, where};
 MYSQL_STMT* s = prepare(a, "SELECT ?, ?, ?");
 ok(s != nullptr, "prepare parameterized SELECT");
 if (!s) throw std::runtime_error("SELECT prepare failed");
 MYSQL_RES* meta = mysql_stmt_result_metadata(s);
 ok(meta && mysql_num_fields(meta) == 3 && mysql_stmt_param_count(s) == 3, "metadata and parameter count");
 if (meta) mysql_free_result(meta);
 long long number = 42; char blob[] = {'a', '\0', 'b'}; unsigned long len = sizeof(blob); my_bool null_value = 1;
 MYSQL_BIND in[3]{}; in[0].buffer_type=MYSQL_TYPE_LONGLONG; in[0].buffer=&number;
 in[1].buffer_type=MYSQL_TYPE_NULL; in[1].is_null=&null_value;
 in[2].buffer_type=MYSQL_TYPE_BLOB; in[2].buffer=blob; in[2].buffer_length=len; in[2].length=&len;
 ok(!mysql_stmt_bind_param(s,in) && !mysql_stmt_execute(s), "execute integer, NULL and binary parameters");
 long long out_number=0; char out_blob[8]{}; unsigned long out_len=0; my_bool out_null=0;
 MYSQL_BIND out[3]{}; out[0].buffer_type=MYSQL_TYPE_LONGLONG; out[0].buffer=&out_number;
 out[1].buffer_type=MYSQL_TYPE_STRING; out[1].is_null=&out_null;
 out[2].buffer_type=MYSQL_TYPE_BLOB; out[2].buffer=out_blob; out[2].buffer_length=sizeof(out_blob); out[2].length=&out_len;
 ok(!mysql_stmt_bind_result(s,out) && !mysql_stmt_fetch(s) && out_number==42 && out_null && out_len==3 && !memcmp(blob,out_blob,3), "dynamic result preserves values");
 ok(!mysql_stmt_reset(s) && !mysql_stmt_execute(s), "reset and reexecute");
 mysql_stmt_free_result(s);
 const char chunks[] = {'x', '\0', 'y'};
 ok(!mysql_stmt_send_long_data(s, 2, chunks, 1) &&
    !mysql_stmt_send_long_data(s, 2, chunks+1, 2) &&
    !mysql_stmt_execute(s) && !mysql_stmt_bind_result(s,out) &&
    !mysql_stmt_fetch(s) && out_len==3 && !memcmp(chunks,out_blob,3),
    "prepared reads accept bounded native long data with a NUL byte");
 mysql_stmt_free_result(s);
 ok(query(a, "PROXYSQL READONLY"), "enable legacy Admin read-only mode");
 ok(!mysql_stmt_execute(s), "existing prepared SELECT remains readable in read-only mode");
 mysql_stmt_free_result(s);
 ok(query(a, "PROXYSQL READWRITE"), "restore legacy Admin read-write mode");
 mysql_stmt_close(s);
 const char* refused[] = {"LOAD MYSQL SERVERS TO RUNTIME", "SAVE MYSQL SERVERS TO DISK", "PRAGMA query_only", "ATTACH DATABASE ':memory:' AS other", "BEGIN", "SELECT load_extension('x')", "SELECT * FROM stats.stats_mysql_connection_pool", "SELECT * FROM stats_mysql_query_digest_reset"};
 for (const char* sql : refused) { MYSQL_STMT* bad = prepare(a,sql); ok(!bad, "refuse prepare: %s", sql); if (bad) mysql_stmt_close(bad); }
 MYSQL_STMT* insert = prepare(a, "INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES(?,?,?)");
 ok(!insert, "read-only prepared policy refuses server inserts even in legacy read-write mode");
 if (insert) mysql_stmt_close(insert);
 std::string stats_sql = "SELECT hostgroup FROM STATS_MYSQL_CONNECTION_POOL WHERE hostgroup=" + std::to_string(hg);
 MYSQL_STMT* stats = prepare(st,stats_sql);
 ok(stats != nullptr, "prepare STATS pool query");
 if (!stats) throw std::runtime_error("STATS prepare failed");
 ok(!mysql_stmt_execute(stats) && !mysql_stmt_store_result(stats) && mysql_stmt_num_rows(stats)==0, "pool initially empty");
 ok(query(a, "INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES (" +
             std::to_string(hg) + ",'127.0.0.1',1)"), "legacy Admin insert still works");
 ok(query(a,"LOAD MYSQL SERVERS TO RUNTIME"), "load test server");
 ok(!mysql_stmt_execute(stats) && !mysql_stmt_store_result(stats) && mysql_stmt_num_rows(stats)==1, "STATS refreshes on each execute");
 MYSQL_STMT* denied=prepare(st,"DELETE FROM mysql_servers WHERE hostgroup_id=1");
 ok(!denied, "STATS write refused"); if (denied) mysql_stmt_close(denied);
 mysql_stmt_close(stats);
 check_schema_change(a);
 check_statement_limit(a);
 } catch (const std::exception& e) {
  diag("test aborted after fixture setup: %s", e.what());
  ok(false, "fixture completed");
 }
 mysql_close(st); mysql_close(a);
 return exit_status();
}
