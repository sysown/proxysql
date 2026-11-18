#include "prepared_owned_fixture.h"
#include <mysql.h>
#include "tap.h"
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <stdexcept>

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
    prepared_owned_fixture::Fixture fixture;
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
 mysql_stmt_close(s);
 const char* refused[] = {"LOAD MYSQL SERVERS TO RUNTIME", "SAVE MYSQL SERVERS TO DISK", "PRAGMA query_only", "ATTACH DATABASE ':memory:' AS other", "BEGIN", "SELECT load_extension('x')", "SELECT * FROM stats.stats_mysql_connection_pool"};
 for (const char* sql : refused) { MYSQL_STMT* bad = prepare(a,sql); ok(!bad, "refuse prepare: %s", sql); if (bad) mysql_stmt_close(bad); }
 s = prepare(a, "INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES(?,?,?)");
 ok(s != nullptr, "prepare permitted server insert");
 if (!s) throw std::runtime_error("insert prepare failed");
 int p=1; char addr[]="127.0.0.1"; unsigned long alen=sizeof(addr)-1; MYSQL_BIND args[3]{};
 args[0].buffer_type=MYSQL_TYPE_LONG; args[0].buffer=const_cast<int*>(&hg);
 args[1].buffer_type=MYSQL_TYPE_STRING; args[1].buffer=addr; args[1].buffer_length=alen; args[1].length=&alen;
 args[2].buffer_type=MYSQL_TYPE_LONG; args[2].buffer=&p;
 ok(!mysql_stmt_bind_param(s,args), "bind server insert");
 ok(query(a,"PROXYSQL READONLY"), "enable read-only");
 ok(mysql_stmt_execute(s) != 0, "previously prepared insert observes read-only");
 ok(query(a,"PROXYSQL READWRITE"), "restore read-only");
 std::string stats_sql = "SELECT hostgroup FROM STATS_MYSQL_CONNECTION_POOL WHERE hostgroup=" + std::to_string(hg);
 MYSQL_STMT* stats = prepare(st,stats_sql);
 ok(stats != nullptr, "prepare STATS pool query");
 if (!stats) throw std::runtime_error("STATS prepare failed");
 ok(!mysql_stmt_execute(stats) && !mysql_stmt_store_result(stats) && mysql_stmt_num_rows(stats)==0, "pool initially empty");
 ok(!mysql_stmt_execute(s), "execute permitted server insert");
 ok(query(a,"LOAD MYSQL SERVERS TO RUNTIME"), "load test server");
 ok(!mysql_stmt_execute(stats) && !mysql_stmt_store_result(stats) && mysql_stmt_num_rows(stats)==1, "STATS refreshes on each execute");
 MYSQL_STMT* denied=prepare(st,"DELETE FROM mysql_servers WHERE hostgroup_id=1");
 ok(!denied, "STATS write refused"); if (denied) mysql_stmt_close(denied);
 mysql_stmt_close(stats); mysql_stmt_close(s);
 } catch (const std::exception& e) {
  diag("test aborted after fixture setup: %s", e.what());
  ok(false, "fixture completed");
 }
 mysql_close(st); mysql_close(a);
 return exit_status();
}
