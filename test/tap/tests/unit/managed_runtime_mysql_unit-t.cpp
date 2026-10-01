#include "MySQL_Monitor.hpp"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "ProxySQL_ConfigurationAccess.h"
#include "ProxySQL_ManagedRuntime.h"
#include "ProxySQL_Statistics.hpp"
#include "Web_Interface.hpp"
#include "cpp.h"
#include "json.hpp"
#include "proxysql.h"
#include "proxysql_admin.h"
#include "sqlite3db.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include <arpa/inet.h>
#include <fstream>
#include <memory>
#include <openssl/ssl.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

using nlohmann::json;
extern ProxySQL_Admin *GloAdmin;
extern ProxySQL_Statistics *GloProxyStats;
extern MySQL_Monitor *GloMyMon;
extern Web_Interface *GloWebInterface;
extern int ProxySQL_create_or_load_TLS(bool, std::string &);
namespace {
class ObservedWebInterface : public Web_Interface {
public:
  unsigned starts = 0;
  unsigned stops = 0;
  void start(int) override { ++starts; }
  void stop() override { ++stops; }
};
const std::pair<const char *, const char *> definitions[] = {
    {"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS},
    {"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS},
    {"mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES},
    {"mysql_query_rules_fast_routing", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_FAST_ROUTING},
    {"mysql_hostgroup_attributes", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES},
    {"mysql_replication_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS},
    {"mysql_group_replication_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS},
    {"mysql_galera_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS},
    {"mysql_aws_aurora_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS},
    {"mysql_servers_ssl_params", ADMIN_SQLITE_TABLE_MYSQL_SERVERS_SSL_PARAMS}};
std::string scalar(SQLite3DB &db, const std::string &sql) {
  sqlite3_stmt *statement = nullptr;
  if (sqlite3_prepare_v2(db.get_db(), sql.c_str(), -1, &statement, nullptr) != SQLITE_OK)
    return "<error>";
  std::string result = "<null>";
  if (sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_text(statement, 0))
    result = reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
  sqlite3_finalize(statement);
  return result;
}
int reserve_port() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (fd < 0 || bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a))) {
    if (fd >= 0)
      close(fd);
    return 0;
  }
  socklen_t n = sizeof(a);
  getsockname(fd, reinterpret_cast<sockaddr *>(&a), &n);
  close(fd);
  return ntohs(a.sin_port);
}
bool connects(const char *address, int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  inet_pton(AF_INET, address, &a.sin_addr);
  bool connected = fd >= 0 && connect(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0;
  if (fd >= 0)
    close(fd);
  return connected;
}
std::string file_contents(const std::string &path) {
  std::ifstream in(path);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
decltype(proxy_sqlite3_prepare_v2) original_prepare = nullptr;
bool inspected_staged_schema = false;
int observed_prepare(sqlite3 *db, const char *sql, int length, sqlite3_stmt **statement,
                     const char **tail) {
  if (sql && std::string(sql).compare(0, 18, "PRAGMA table_info(") == 0)
    inspected_staged_schema = true;
  return original_prepare(db, sql, length, statement, tail);
}
json configuration() {
  json d = {{"identity",
             {{"deployment_id", "unit-deployment"},
              {"resource_id", "unit-proxy"},
              {"resource_name", "unit"},
              {"engine", "MYSQL"}}},
            {"scope",
             {{"hostgroups", {10, 11, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29}},
              {"users", {{{"username", "managed"}, {"frontend", 1}, {"backend", 1}}}},
              {"query_rules", {100}},
              {"listeners", json::array()}}},
            {"tables", json::object()},
            {"variables", json::object()},
            {"tls", json::object()},
            {"listeners", json::array()}};
  for (const auto &table : definitions)
    d["tables"][table.first] = json::array();
  d["tables"]["mysql_servers"] = {{{"hostgroup_id", 10},
                                   {"hostname", "managed.test"},
                                   {"port", 3306},
                                   {"max_connections", 40}}};
  d["tables"]["mysql_users"] = {{{"username", "managed"},
                                 {"password", nullptr},
                                 {"default_hostgroup", 10},
                                 {"frontend", 1},
                                 {"backend", 1},
                                 {"default_schema", nullptr}}};
  d["tables"]["mysql_query_rules"] = {{{"rule_id", 100},
                                       {"active", 1},
                                       {"destination_hostgroup", 10},
                                       {"match_pattern", "^SELECT"},
                                       {"replace_pattern", "SELECT"},
                                       {"cache_timeout", 50},
                                       {"cache_empty_result", 0},
                                       {"sticky_conn", 1},
                                       {"gtid_from_hostgroup", 10},
                                       {"next_query_flagIN", 42},
                                       {"OK_msg", nullptr},
                                       {"attributes", "{\"tag\":\"complete\"}"},
                                       {"apply", 1}}};
  d["tables"]["mysql_query_rules_fast_routing"] = {{{"username", "managed"},
                                                    {"schemaname", "db"},
                                                    {"destination_hostgroup", 10},
                                                    {"comment", "managed"}}};
  d["tables"]["mysql_hostgroup_attributes"] = {{{"hostgroup_id", 10},
                                                {"init_connect", "SET @managed=1"},
                                                {"servers_defaults", "{\"max_connections\":40}"}}};
  d["tables"]["mysql_replication_hostgroups"] = {
      {{"writer_hostgroup", 10}, {"reader_hostgroup", 11}}};
  d["tables"]["mysql_group_replication_hostgroups"] = {{{"writer_hostgroup", 20},
                                                        {"backup_writer_hostgroup", 21},
                                                        {"reader_hostgroup", 22},
                                                        {"offline_hostgroup", 23},
                                                        {"comment", nullptr}}};
  d["tables"]["mysql_galera_hostgroups"] = {{{"writer_hostgroup", 24},
                                             {"backup_writer_hostgroup", 25},
                                             {"reader_hostgroup", 26},
                                             {"offline_hostgroup", 27},
                                             {"comment", nullptr}}};
  d["tables"]["mysql_aws_aurora_hostgroups"] = {{{"writer_hostgroup", 28},
                                                 {"reader_hostgroup", 29},
                                                 {"domain_name", ".unit.test"},
                                                 {"comment", nullptr}}};
  d["tables"]["mysql_servers_ssl_params"] = {{{"hostname", "managed.test"},
                                              {"port", 3306},
                                              {"username", "managed"},
                                              {"ssl_key", ""},
                                              {"tls_version", "TLSv1.2"}}};
  return d;
}
bool prepare(const json &d, ManagedPreparedRuntime **out, std::string &error) {
  return proxysql_prepare_managed_runtime_locked({"unit-deployment", d.dump()}, out, error);
}
void rejected(const json &d, const char *reason) {
  ManagedPreparedRuntime *prepared = nullptr;
  std::string error;
  bool result = prepare(d, &prepared, error);
  ok(!result && prepared == nullptr && !error.empty(), "%s", reason);
  proxysql_destroy_managed_prepared_runtime(prepared);
}
} // namespace
int main() {
  plan(NO_PLAN);
  test_init_minimal();
  test_init_auth();
  test_init_query_processor();
  test_init_hostgroups();
  GloVars.statsdb_disk = const_cast<char *>(":memory:");
  GloProxyStats = new ProxySQL_Statistics();
  GloProxyStats->init();
  GloAdmin = new ProxySQL_Admin(); // Existing process-scoped partial Admin fixture.
  GloAdmin->admindb = new SQLite3DB();
  GloAdmin->admindb->open(const_cast<char *>(":memory:"),
                          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
  GloAdmin->configdb = new SQLite3DB();
  GloAdmin->configdb->open(const_cast<char *>(":memory:"),
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
  auto &db = *GloAdmin->admindb;
  for (const auto &table : definitions)
    ok(db.execute(table.second), "fixture creates exact current %s schema", table.first);
  db.execute(ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
  db.execute("CREATE TABLE runtime_global_variables(variable_name VARCHAR PRIMARY "
             "KEY,variable_value VARCHAR)");
  db.execute(ADMIN_SQLITE_TABLE_MYSQL_AWS_RDS_BGD_HOSTGROUPS);
  db.execute("INSERT INTO mysql_servers(hostgroup_id,hostname) VALUES (99,'unrelated.test')");
  db.execute("INSERT INTO mysql_users(username,default_hostgroup) VALUES ('unrelated',99)");
  db.execute(
      "INSERT INTO mysql_query_rules(rule_id,active,destination_hostgroup) VALUES (999,1,99)");
  db.execute("INSERT INTO mysql_servers_ssl_params(hostname,port,username) VALUES "
             "('unrelated.test',3306,'unrelated')");
  db.execute("INSERT INTO global_variables VALUES ('mysql-poll_timeout','2000')");
  GloMTH->set_variable("caching_sha2_password_auto_generate_rsa_keys", "false");
  GloMTH->set_variable("caching_sha2_password_private_key_path", "");
  GloMTH->set_variable("caching_sha2_password_public_key_path", "");
  GloVars.datadir = getcwd(nullptr, 0);
  GloVars.global.ssl_ctx = SSL_CTX_new(TLS_server_method());
  std::string tls_error;
  ok(ProxySQL_create_or_load_TLS(true, tls_error) == 0,
     "existing TLS bootstrap supplies owned fixture material");
  GloMyMon = new MySQL_Monitor();
  MyHGM->gtid_ev_loop = ev_loop_new(EVBACKEND_POLL | EVFLAG_NOENV);
  ev_async_init(MyHGM->gtid_ev_async, +[](EV_P_ ev_async *, int) {});
  ev_async_start(MyHGM->gtid_ev_loop, MyHGM->gtid_ev_async);
  proxysql_lock_configuration();
  json d = configuration();
  ManagedPreparedRuntime *prepared = nullptr;
  std::string error;
  original_prepare = proxy_sqlite3_prepare_v2;
  proxy_sqlite3_prepare_v2 = &observed_prepare;
  ok(prepare(d, &prepared, error) && prepared != nullptr,
     "prepare accepts all MySQL sections, schema defaults and nullable fields: %s", error.c_str());
  proxy_sqlite3_prepare_v2 = original_prepare;
  ok(inspected_staged_schema, "managed SQL preparation uses configured SQLite provider dispatch");
  ok(scalar(db, "SELECT count(*) FROM mysql_servers WHERE hostgroup_id=10") == "0",
     "prepare never modifies Admin memory");
  ok(sqlite3_get_autocommit(GloAdmin->configdb->get_db()) == 1,
     "prepare does not start a store transaction");
  proxysql_destroy_managed_prepared_runtime(prepared);
  for (const auto &table : definitions) {
    auto bad = d;
    bad["tables"].erase(table.first);
    rejected(bad, (std::string("complete configuration requires ") + table.first).c_str());
    bad = d;
    bad["tables"][table.first][0]["unknown_column"] = 1;
    rejected(bad, (std::string("unknown column rejected for ") + table.first).c_str());
  }
  auto bad = d;
  bad["tables"]["mysql_servers"][0]["max_connections"] = -1;
  rejected(bad, "real server CHECK constraints reject negative limits");
  bad = d;
  bad["tables"]["mysql_users"][0]["username"] = nullptr;
  rejected(bad, "real NOT NULL user key rejected");
  bad = d;
  bad["tables"]["mysql_query_rules"][0]["rule_id"] = nullptr;
  rejected(bad, "managed rule IDs never allocate implicitly");
  bad = d;
  bad["tables"]["mysql_query_rules"][0]["sticky_conn"] = 3;
  rejected(bad, "complete query-rule fields retain their real constraints");
  bad = d;
  bad["tables"]["mysql_servers"][0]["hostgroup_id"] = 99;
  rejected(bad, "server cannot escape declared hostgroups");
  bad = d;
  bad["tables"]["mysql_users"][0]["frontend"] = 0;
  rejected(bad, "user role keys cannot escape scope");
  bad = d;
  bad["tables"]["mysql_servers_ssl_params"][0]["hostname"] = "unrelated.test";
  rejected(bad, "TLS rows cannot escape managed server endpoints");
  bad = d;
  bad["scope"]["listeners"] = {"invalid address"};
  rejected(bad, "listener address syntax is validated before persistence");
  bad = d;
  bad["scope"]["listeners"] = {"127.0.0.1"};
  bad["listeners"] = {{{"protocol", "POSTGRESQL"}, {"address", "127.0.0.1"}, {"port", 3306}}};
  rejected(bad, "listener protocol must match the configured engine");
  auto ipv6 = d;
  ipv6["scope"]["listeners"] = {"::1"};
  ipv6["listeners"] = {{{"protocol", "MYSQL"}, {"address", "::1"}, {"port", 3306}}};
  ManagedPreparedRuntime *ipv6_prepared = nullptr;
  std::string ipv6_error;
  ok(prepare(ipv6, &ipv6_prepared, ipv6_error),
     "raw IPv6 addresses project to existing bracketed listener syntax without binding in prepare");
  proxysql_destroy_managed_prepared_runtime(ipv6_prepared);
  bad = d;
  bad["variables"]["admin-refresh_interval"] = 1;
  rejected(bad, "invalid Admin range is rejected during pure preparation");
  for (const auto *name : {"web_enabled", "restapi_enabled"}) {
    for (bool enabled : {false, true}) {
      bad = d;
      bad["variables"][std::string("admin-") + name] = enabled;
      rejected(bad, "management endpoint enablement is startup-only, in either direction");
    }
  }
  for (const auto *name : {"web_port", "restapi_port"}) {
    bad = d;
    bad["variables"][std::string("admin-") + name] = reserve_port();
    rejected(bad, "management endpoint port is startup-only");
  }
  ok(scalar(db, "SELECT count(*) FROM global_variables WHERE variable_name IN "
                "('admin-web_enabled','admin-web_port','admin-restapi_enabled',"
                "'admin-restapi_port')") == "0" &&
         scalar(*GloAdmin->configdb, "SELECT count(*) FROM sqlite_master WHERE type='table'") == "0",
     "rejected management endpoint settings leave Admin intent and service store untouched");
  bad = d;
  bad["variables"]["mysql-threads"] = 7;
  rejected(bad, "startup-only worker count is rejected explicitly");
  bad = d;
  bad["variables"]["mysql-unknown_setting"] = 1;
  rejected(bad, "unknown variables are rejected during preparation");
  bad = d;
  bad["variables"]["mysql-poll_timeout"] = 1;
  rejected(bad, "invalid existing runtime variable range rejected before persistence");
  ok(GloMTH->get_variable_int("poll_timeout") == 2000,
     "variable validation does not mutate live settings");
  bool variable_catalog = true;
  char **variable_names = GloMTH->get_variables_list();
  for (size_t i = 0; variable_names[i]; ++i) {
    const std::string name(variable_names[i]);
    char *current = GloMTH->get_variable(variable_names[i]);
    if (name != "interfaces" && name != "threads" && name != "stacksize" && current &&
        !GloMTH->validate_variable(name.c_str(), current)) {
      diag("current valid variable is missing pure validation: %s", name.c_str());
      variable_catalog = false;
    }
    free(current);
    free(variable_names[i]);
  }
  free(variable_names);
  ok(variable_catalog, "pure validation covers existing MySQL variable catalog values");
  bad = d;
  bad["tables"]["mysql_servers_ssl_params"][0]["ssl_key"] = "arbitrary/path";
  rejected(bad, "resolved backend private key must be PEM material");
  bad = d;
  bad["tls"]["key_pem"] = "invalid PEM";
  rejected(bad, "invalid TLS material rejected during preparation");
  d["variables"]["mysql-poll_timeout"] = 1500;
  d["variables"]["admin-refresh_interval"] = 1800;
  db.execute("INSERT INTO global_variables VALUES ('admin-stats_mysql_connections','17')");
  char *prior_admin_connections =
      GloAdmin->get_variable(const_cast<char *>("stats_mysql_connections"));
  const std::string prior_connections(prior_admin_connections);
  free(prior_admin_connections);
  prepared = nullptr;
  const bool ready = prepare(d, &prepared, error);
  ok(ready, "complete MySQL runtime input prepares: %s", error.c_str());
  ObservedWebInterface web;
  GloWebInterface = &web;
  const auto *prior_web_plugin = GloVars.web_interface_plugin;
  GloVars.web_interface_plugin = const_cast<char *>("observed-web-plugin");
  GloAdmin->set_managed_variable_locked("web_port", std::to_string(reserve_port()));
  GloAdmin->set_managed_variable_locked("web_enabled", "true");
  GloAdmin->all_modules_started = true;
  ManagedRuntimeResult result;
  if (ready)
    result = proxysql_activate_managed_runtime_locked(*prepared, 1);
  ok(result.applied, "direct existing operations activate full configuration: %s",
     result.message.c_str());
  ok(web.starts == 0 && web.stops == 0,
     "operational Admin updates never enter management HTTP server lifecycle");
  GloAdmin->all_modules_started = false;
  GloAdmin->set_managed_variable_locked("web_enabled", "false");
  GloVars.web_interface_plugin = const_cast<char *>(prior_web_plugin);
  GloWebInterface = nullptr;
  for (const auto &table : definitions)
    ok(scalar(db, std::string("SELECT count(*) FROM ") + table.first) != "0",
       "activation populates %s", table.first);
  ok(scalar(db, "SELECT sticky_conn||':'||cache_timeout||':'||next_query_flagIN FROM "
                "mysql_query_rules WHERE rule_id=100") == "1:50:42",
     "full query-rule fields survive activation");
  ok(scalar(db, "SELECT default_schema IS NULL AND password IS NULL FROM mysql_users WHERE "
                "username='managed'") == "1",
     "nullable user fields survive memory application");
  ok(scalar(db, "SELECT count(*) FROM mysql_servers WHERE hostgroup_id=99") == "1" &&
         scalar(db, "SELECT count(*) FROM mysql_users WHERE username='unrelated'") == "1" &&
         scalar(db, "SELECT count(*) FROM mysql_query_rules WHERE rule_id=999") == "1",
     "scoped replacement preserves unrelated rows");
  ok(GloMTH->get_variable_int("poll_timeout") == 1500,
     "runtime variable reaches existing thread handler");
  char *interval = GloAdmin->get_variable(const_cast<char *>("refresh_interval"));
  char *connections = GloAdmin->get_variable(const_cast<char *>("stats_mysql_connections"));
  ok(interval && std::string(interval) == "1800" && connections &&
         std::string(connections) == prior_connections &&
         scalar(db, "SELECT variable_value FROM global_variables WHERE "
                    "variable_name='admin-stats_mysql_connections'") == "17",
     "Admin direct setting preserves unrelated memory and runtime values");
  free(interval);
  free(connections);
  ok(sqlite3_get_autocommit(GloAdmin->configdb->get_db()) == 1 &&
         scalar(*GloAdmin->configdb, "SELECT count(*) FROM sqlite_master WHERE type='table'") ==
             "0",
     "runtime activation never writes or transacts on the service store");
  proxysql_destroy_managed_prepared_runtime(prepared);

  // Existing transient health survives when canonical status is unchanged.
  MyHGM->wrlock();
  auto *managed = MyHGM->find_server_in_hg(10, "managed.test", 3306);
  auto *unrelated = MyHGM->find_server_in_hg(99, "unrelated.test", 3306);
  if (managed) {
    managed->set_status(MYSQL_SERVER_STATUS_SHUNNED);
    managed->shunned_automatic = true;
    managed->time_last_detected_error = 123;
  }
  if (unrelated) {
    unrelated->set_status(MYSQL_SERVER_STATUS_SHUNNED);
    unrelated->shunned_automatic = true;
    unrelated->time_last_detected_error = 456;
  }
  MyHGM->wrunlock();
  prepared = nullptr;
  bool health_ready = prepare(d, &prepared, error);
  if (health_ready)
    result = proxysql_activate_managed_runtime_locked(*prepared, 2);
  ok(health_ready && result.applied && managed && unrelated &&
         managed->get_status() == MYSQL_SERVER_STATUS_SHUNNED &&
         unrelated->get_status() == MYSQL_SERVER_STATUS_SHUNNED && managed->shunned_automatic &&
         unrelated->shunned_automatic && managed->time_last_detected_error == 123 &&
         unrelated->time_last_detected_error == 456,
     "managed and unrelated transient health and recovery metadata survive unchanged canonical "
     "status");
  ok(scalar(db, "SELECT status FROM mysql_servers WHERE hostgroup_id=10") == "ONLINE",
     "monitor health never replaces Admin configuration intent");
  auto runtime = std::unique_ptr<SQLite3_result>(MyHGM->dump_table_mysql("mysql_servers"));
  bool runtime_shun = false;
  if (runtime)
    for (const auto *row : runtime->rows)
      if (std::string(row->fields[0]) == "10" && std::string(row->fields[4]) == "SHUNNED")
        runtime_shun = true;
  ok(runtime_shun, "normal HGM runtime view includes preserved SHUN");
  auto *runtime_checksum_rows = MyHGM->get_current_mysql_table("cluster_mysql_servers");
  bool checksum_intent = false;
  if (runtime_checksum_rows)
    for (const auto *row : runtime_checksum_rows->rows)
      if (std::string(row->fields[0]) == "10" && std::string(row->fields[4]) == "ONLINE")
        checksum_intent = true;
  ok(checksum_intent, "native Cluster checksum projection continues to normalize transient health");
  proxysql_destroy_managed_prepared_runtime(prepared);
  auto changed = d;
  changed["tables"]["mysql_servers"][0]["status"] = "OFFLINE_SOFT";
  prepared = nullptr;
  bool status_ready = prepare(changed, &prepared, error);
  if (status_ready)
    result = proxysql_activate_managed_runtime_locked(*prepared, 3);
  ok(status_ready && result.applied && managed->get_status() == MYSQL_SERVER_STATUS_OFFLINE_SOFT &&
         unrelated->get_status() == MYSQL_SERVER_STATUS_SHUNNED,
     "explicit managed status change applies while unrelated health remains");
  proxysql_destroy_managed_prepared_runtime(prepared);
  db.execute("UPDATE mysql_servers SET status='ONLINE'");
  GloAdmin->mysql_servers_wrlock();
  bool ordinary = GloAdmin->load_mysql_servers_to_runtime();
  GloAdmin->mysql_servers_wrunlock();
  ok(ordinary && managed->get_status() == MYSQL_SERVER_STATUS_ONLINE &&
         unrelated->get_status() == MYSQL_SERVER_STATUS_ONLINE,
     "ordinary LOAD keeps its existing status replacement behavior");
  // Live listeners replace only addresses included in the supplied deletion scope.
  const int old_port = reserve_port(), new_port = reserve_port(), other_port = reserve_port();
  const std::string old_interface = "127.0.0.1:" + std::to_string(old_port),
                    other_interface = "127.0.0.2:" + std::to_string(other_port);
  bool listener_fixture =
      old_port && new_port && other_port &&
      GloMTH->set_variable("interfaces", (old_interface + ";" + other_interface).c_str()) &&
      GloMTH->listener_add(old_interface.c_str()) >= 0 &&
      GloMTH->listener_add(other_interface.c_str()) >= 0;
  auto listeners = d;
  listeners["scope"]["listeners"] = {"127.0.0.1"};
  listeners["listeners"] = {{{"protocol", "MYSQL"}, {"address", "127.0.0.1"}, {"port", new_port}}};
  prepared = nullptr;
  bool listener_ready = prepare(listeners, &prepared, error);
  if (listener_ready)
    result = proxysql_activate_managed_runtime_locked(*prepared, 4);
  ok(listener_fixture && listener_ready && result.applied && !connects("127.0.0.1", old_port) &&
         connects("127.0.0.1", new_port) && connects("127.0.0.2", other_port),
     "existing live listener API replaces scoped endpoint and preserves unrelated address");
  ok(scalar(db,
            "SELECT variable_value FROM global_variables WHERE variable_name='mysql-interfaces'")
             .find(other_interface) != std::string::npos,
     "merged listener intent is recorded in Admin memory");
  proxysql_destroy_managed_prepared_runtime(prepared);
  // Material is supplied as PEM and reaches the real TLS reload and backend APIs.
  auto tls = d;
  tls["tls"] = {
      {"trust_pem", file_contents(std::string(GloVars.datadir) + "/proxysql-ca.pem")},
      {"certificate_pem", file_contents(std::string(GloVars.datadir) + "/proxysql-cert.pem")},
      {"key_pem", file_contents(std::string(GloVars.datadir) + "/proxysql-key.pem")},
      {"frontend", {{"require_tls", true}, {"verify_peer", true}}},
      {"backend", {{"require_tls", true}, {"verify_peer", true}}}};
  tls["tables"]["mysql_servers_ssl_params"][0]["ssl_key"] = tls["tls"]["key_pem"];
  tls["tables"]["mysql_servers_ssl_params"][0]["ssl_cert"] =
      std::string(GloVars.datadir) + "/proxysql-cert.pem";
  const auto previous_tls_count = GloVars.global.tls_load_count;
  prepared = nullptr;
  bool tls_ready = prepare(tls, &prepared, error);
  if (tls_ready)
    result = proxysql_activate_managed_runtime_locked(*prepared, 5);
  const std::string backend_key =
      scalar(db, "SELECT ssl_key FROM mysql_servers_ssl_params WHERE hostname='managed.test'");
  struct stat key_stat {};
  ok(tls_ready && result.applied && GloVars.global.tls_load_count == previous_tls_count + 1,
     "PEM material reaches existing global frontend TLS reload");
  ok(stat(backend_key.c_str(), &key_stat) == 0 && (key_stat.st_mode & 0777) == 0600 &&
         file_contents(backend_key) == tls["tls"]["key_pem"],
     "resolved backend key becomes a deterministic private file for existing TLS table API");
  ok(scalar(db, "SELECT use_ssl FROM mysql_servers WHERE hostgroup_id=10") == "1" &&
         scalar(db, "SELECT use_ssl FROM mysql_users WHERE username='managed'") == "1" &&
         scalar(db, "SELECT use_ssl FROM mysql_servers WHERE hostgroup_id=99") == "0",
     "require_tls projects through scoped existing server and user settings");
  proxysql_destroy_managed_prepared_runtime(prepared);
  // Empty desired arrays remove all entries in the explicit deletion scope.
  auto empty = d;
  for (const auto &table : definitions)
    empty["tables"][table.first] = json::array();
  empty["scope"]["listeners"] = {"127.0.0.1"};
  prepared = nullptr;
  bool empty_ready = prepare(empty, &prepared, error);
  if (empty_ready)
    result = proxysql_activate_managed_runtime_locked(*prepared, 6);
  ok(empty_ready && result.applied &&
         scalar(db, "SELECT count(*) FROM mysql_servers WHERE hostgroup_id=10") == "0" &&
         scalar(db, "SELECT count(*) FROM mysql_users WHERE username='managed'") == "0" &&
         scalar(db, "SELECT count(*) FROM mysql_query_rules WHERE rule_id=100") == "0" &&
         scalar(db,
                "SELECT count(*) FROM mysql_servers_ssl_params WHERE hostname='managed.test'") ==
             "0" &&
         !connects("127.0.0.1", new_port) && connects("127.0.0.2", other_port),
     "supplied deletion scope removes old managed rows and listeners while preserving unrelated "
     "entries");
  proxysql_destroy_managed_prepared_runtime(prepared);
  // Removing an existing companion table exercises a real loader/database failure.
  prepared = nullptr;
  const bool failure_ready = prepare(d, &prepared, error);
  db.execute("DROP TABLE mysql_aws_rds_bgd_hostgroups");
  if (failure_ready)
    result = proxysql_activate_managed_runtime_locked(*prepared, 2);
  ok(failure_ready && !result.applied && !result.message.empty(),
     "existing loader errors propagate without reporting success");
  proxysql_destroy_managed_prepared_runtime(prepared);
  proxysql_unlock_configuration();
  return exit_status();
}
