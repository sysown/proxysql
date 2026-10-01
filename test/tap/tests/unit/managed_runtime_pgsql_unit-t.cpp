#include "PgSQL_Authentication.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "ProxySQL_ConfigurationAccess.h"
#include "ProxySQL_ManagedRuntime.h"
#include "ProxySQL_ServerDiscovery.h"
#include "ProxySQL_Statistics.hpp"
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
using nlohmann::json;
extern ProxySQL_Admin *GloAdmin;
extern ProxySQL_Statistics *GloProxyStats;
extern PgSQL_Threads_Handler *GloPTH;
extern PgSQL_Authentication *GloPgAuth;
extern int ProxySQL_create_or_load_TLS(bool, std::string &);
const std::pair<const char *, const char *> pgsql_definitions[] = {
    {"pgsql_servers", ADMIN_SQLITE_TABLE_PGSQL_SERVERS},
    {"pgsql_users", ADMIN_SQLITE_TABLE_PGSQL_USERS},
    {"pgsql_query_rules", ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES},
    {"pgsql_query_rules_fast_routing", ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES_FAST_ROUTING},
    {"pgsql_hostgroup_attributes", ADMIN_SQLITE_TABLE_PGSQL_HOSTGROUP_ATTRIBUTES},
    {"pgsql_replication_hostgroups", ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS},
    {"pgsql_servers_ssl_params", ADMIN_SQLITE_TABLE_PGSQL_SERVERS_SSL_PARAMS}};
json configuration() {
  json d = {{"identity",
             {{"deployment_id", "pgsql-unit"},
              {"resource_id", "pgsql-proxy"},
              {"resource_name", "unit"},
              {"engine", "POSTGRESQL"}}},
            {"scope",
             {{"hostgroups", {10, 11}},
              {"users", {{{"username", "managed"}, {"frontend", 1}, {"backend", 1}}}},
              {"query_rules", {100}},
              {"listeners", json::array()}}},
            {"tables", json::object()},
            {"variables", json::object()},
            {"tls", json::object()},
            {"listeners", json::array()}};
  for (const auto &t : pgsql_definitions)
    d["tables"][t.first] = json::array();
  d["tables"]["pgsql_servers"] = {
      {{"hostgroup_id", 10}, {"hostname", "managed.test"}, {"max_connections", 40}}};
  d["tables"]["pgsql_users"] = {{{"username", "managed"},
                                 {"password", nullptr},
                                 {"default_hostgroup", 10},
                                 {"attributes", "{\"application\":\"unit\"}"}}};
  d["tables"]["pgsql_query_rules"] = {{{"rule_id", 100},
                                       {"active", 1},
                                       {"database", "unitdb"},
                                       {"match_pattern", "^SELECT"},
                                       {"replace_pattern", "SELECT"},
                                       {"destination_hostgroup", 10},
                                       {"sticky_conn", 1},
                                       {"cache_timeout", 50},
                                       {"next_query_flagIN", 42},
                                       {"OK_msg", nullptr},
                                       {"apply", 1}}};
  d["tables"]["pgsql_query_rules_fast_routing"] = {{{"username", "managed"},
                                                    {"database", "unitdb"},
                                                    {"destination_hostgroup", 10},
                                                    {"comment", "unit"}}};
  d["tables"]["pgsql_hostgroup_attributes"] = {
      {{"hostgroup_id", 10},
       {"init_connect", "SET application_name='managed-pgsql'"},
       {"hostgroup_settings", "{\"tag\":1}"}}};
  d["tables"]["pgsql_replication_hostgroups"] = {
      {{"writer_hostgroup", 10}, {"reader_hostgroup", 11}}};
  d["tables"]["pgsql_servers_ssl_params"] = {
      {{"hostname", "managed.test"}, {"username", "managed"}}};
  return d;
}
std::string scalar(SQLite3DB &db, const std::string &sql) {
  sqlite3_stmt *raw = nullptr;
  if ((*proxy_sqlite3_prepare_v2)(db.get_db(), sql.c_str(), -1, &raw, nullptr) != SQLITE_OK)
    return "<error>";
  std::string value = "<null>";
  if ((*proxy_sqlite3_step)(raw) == SQLITE_ROW && (*proxy_sqlite3_column_text)(raw, 0))
    value = reinterpret_cast<const char *>((*proxy_sqlite3_column_text)(raw, 0));
  (*proxy_sqlite3_finalize)(raw);
  return value;
}
bool prepare(const json &d, ManagedPreparedRuntime **p, std::string &error) {
  return proxysql_prepare_managed_runtime_locked({"pgsql-unit", d.dump()}, p, error);
}
void rejected(const json &d, const char *reason) {
  ManagedPreparedRuntime *p = nullptr;
  std::string error;
  bool accepted = prepare(d, &p, error);
  ok(!accepted && !p && !error.empty(), "%s", reason);
  proxysql_destroy_managed_prepared_runtime(p);
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
  bool result = fd >= 0 && connect(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0;
  if (fd >= 0)
    close(fd);
  return result;
}
std::string contents(const std::string &path) {
  std::ifstream in(path);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
ManagedRuntimeResult activate_document(const json &d, uint64_t revision) {
  ManagedPreparedRuntime *p = nullptr;
  std::string error;
  if (!prepare(d, &p, error))
    return {false, "PreparationFailed", error};
  auto result = proxysql_activate_managed_runtime_locked(*p, revision);
  proxysql_destroy_managed_prepared_runtime(p);
  return result;
}
int main() {
  plan(NO_PLAN);
  test_init_minimal();
  test_init_auth();
  test_init_query_processor();
  test_init_hostgroups();
  GloVars.statsdb_disk = const_cast<char *>(":memory:");
  GloProxyStats = new ProxySQL_Statistics();
  GloProxyStats->init();
  GloAdmin = new ProxySQL_Admin();
  GloAdmin->admindb = new SQLite3DB();
  GloAdmin->admindb->open(const_cast<char *>(":memory:"),
                          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
  for (const auto &t : pgsql_definitions)
    ok(GloAdmin->admindb->execute(t.second), "current PostgreSQL fixture schema %s", t.first);
  GloAdmin->admindb->execute(ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
  GloAdmin->configdb = new SQLite3DB();
  GloAdmin->configdb->open(const_cast<char *>(":memory:"),
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
  auto &db = *GloAdmin->admindb;
  db.execute("CREATE TABLE runtime_global_variables(variable_name VARCHAR PRIMARY "
             "KEY,variable_value VARCHAR)");
  db.execute("INSERT INTO pgsql_servers(hostgroup_id,hostname) VALUES(99,'unrelated.test')");
  db.execute("INSERT INTO pgsql_users(username,default_hostgroup) VALUES('unrelated',99)");
  db.execute(
      "INSERT INTO pgsql_query_rules(rule_id,active,destination_hostgroup) VALUES(999,1,99)");
  db.execute("INSERT INTO pgsql_servers_ssl_params(hostname,username) "
             "VALUES('unrelated.test','unrelated')");
  GloVars.datadir = getcwd(nullptr, 0);
  GloVars.global.ssl_ctx = SSL_CTX_new(TLS_server_method());
  GloMTH->set_variable("caching_sha2_password_auto_generate_rsa_keys", "false");
  GloMTH->set_variable("caching_sha2_password_private_key_path", "");
  GloMTH->set_variable("caching_sha2_password_public_key_path", "");
  std::string tls_error;
  ok(ProxySQL_create_or_load_TLS(true, tls_error) == 0, "owned existing frontend TLS fixture");
  proxysql_lock_configuration();
  ManagedPreparedRuntime *p = nullptr;
  std::string error;
  auto d = configuration();
  bool accepted = proxysql_prepare_managed_runtime_locked({"pgsql-unit", d.dump()}, &p, error);
  ok(accepted && p,
     "complete PostgreSQL projection prepares with existing engine-specific "
     "schemas: %s",
     error.c_str());
  proxysql_destroy_managed_prepared_runtime(p);
  if (!accepted) {
    proxysql_unlock_configuration();
    return exit_status();
  }
  ok(scalar(db, "SELECT count(*) FROM pgsql_servers") == "1",
     "pure PostgreSQL preparation leaves Admin intent untouched");
  auto bad = d;
  bad["tables"]["pgsql_users"][0]["default_schema"] = "mysql-only";
  rejected(bad, "PostgreSQL uses its own user schema");
  bad = d;
  bad["tables"]["pgsql_query_rules"][0]["gtid_from_hostgroup"] = 10;
  rejected(bad, "MySQL-only rule fields are rejected");
  bad = d;
  bad["tables"]["pgsql_query_rules"][0].erase("rule_id");
  rejected(bad, "explicit PostgreSQL rule identity required");
  bad = d;
  bad["tables"]["pgsql_servers"][0]["max_connections"] = -1;
  rejected(bad, "existing PostgreSQL table CHECK validated");
  bad = d;
  bad["tables"]["pgsql_servers"][0]["hostgroup_id"] = 99;
  rejected(bad, "server outside supplied scope rejected");
  bad = d;
  bad["tables"]["pgsql_users"].push_back(bad["tables"]["pgsql_users"][0]);
  rejected(bad, "duplicate native user roles rejected");
  bad = d;
  bad["tables"]["pgsql_servers_ssl_params"][0]["ssl_key"] = "arbitrary/path";
  rejected(bad, "resolved PostgreSQL backend key must be PEM");
  bad = d;
  bad["tls"]["key_pem"] = "invalid PEM";
  rejected(bad, "invalid PostgreSQL TLS material rejected before activation");
  bad = d;
  bad["tables"]["pgsql_replication_hostgroups"][0]["check_type"] = "super_read_only";
  rejected(bad, "PostgreSQL native topology does not assume MySQL check_type parity");
  for (const auto *name : {"pgsql-threads", "pgsql-stacksize", "pgsql-interfaces",
                           "mysql-poll_timeout", "admin-web_enabled", "admin-web_port"}) {
    bad = d;
    bad["variables"][name] = 1;
    rejected(bad, "unsupported engine/startup/control-plane setting rejected");
  }
  bad = d;
  bad["variables"]["pgsql-poll_timeout"] = 1;
  rejected(bad, "invalid native PostgreSQL range rejected");
  bad = d;
  bad["variables"]["pgsql-server_encoding"] = "nonexistent-encoding";
  rejected(bad, "native PostgreSQL encoding parser validates input without setter");
  bad = d;
  bad["variables"]["pgsql-default_datestyle"] = "invalid style";
  rejected(bad, "native tracked PostgreSQL variable validator rejects malformed value");
  ok(GloPTH->get_variable_int(const_cast<char *>("poll_timeout")) == 2000,
     "pure PostgreSQL variable validation has no setter side effects");
  bool catalog = true;
  char **names = GloPTH->get_variables_list();
  for (size_t i = 0; names[i]; ++i) {
    std::string name(names[i]);
    char *value = GloPTH->get_variable(names[i]);
    if (value && name != "interfaces" && name != "threads" && name != "stacksize" &&
        !GloPTH->validate_variable(name.c_str(), value)) {
      diag("missing pure PostgreSQL variable validation: %s", name.c_str());
      catalog = false;
    }
    free(value);
    free(names[i]);
  }
  free(names);
  ok(catalog, "pure validation covers current native PostgreSQL variable catalog");
  d["variables"]["pgsql-poll_timeout"] = 1500;
  d["variables"]["pgsql-authentication_method"] = 2;
  d["variables"]["pgsql-default_datestyle"] = "ISO, MDY";
  d["variables"]["admin-refresh_interval"] = 1800;
  auto result = activate_document(d, 1);
  ok(result.applied, "existing PostgreSQL operations activate all sections: %s",
     result.message.c_str());
  if (!result.applied) {
    proxysql_unlock_configuration();
    return exit_status();
  }
  for (const auto &t : pgsql_definitions)
    ok(scalar(db, std::string("SELECT count(*) FROM ") + t.first) != "0", "activation populates %s",
       t.first);
  ok(scalar(db, "SELECT port FROM pgsql_servers WHERE hostgroup_id=10") == "5432",
     "native PostgreSQL server port default retained");
  ok(scalar(db, "SELECT password IS NULL FROM pgsql_users WHERE username='managed'") == "1",
     "nullable PostgreSQL credentials retained");
  ok(scalar(db, "SELECT database||':'||sticky_conn||':'||cache_timeout||':'||next_query_flagIN "
                "FROM pgsql_query_rules WHERE rule_id=100") == "unitdb:1:50:42",
     "full PostgreSQL routing fields retained");
  ok(scalar(db, "SELECT count(*) FROM pgsql_servers WHERE hostgroup_id=99") == "1" &&
         scalar(db, "SELECT count(*) FROM pgsql_users WHERE username='unrelated'") == "1" &&
         scalar(db, "SELECT count(*) FROM pgsql_query_rules WHERE rule_id=999") == "1",
     "unrelated native PostgreSQL configuration preserved");
  ok(GloPTH->get_variable_int(const_cast<char *>("poll_timeout")) == 1500 &&
         GloPTH->get_variable_int(const_cast<char *>("authentication_method")) == 2,
     "native PostgreSQL variable/authentication settings applied");
  auto users = GloPgAuth->get_current_pgsql_users();
  ok(users && users->rows_count >= 2,
     "native PostgreSQL Auth contains managed and unrelated users");
  ok(GloVars.checksums_values.pgsql_users.checksum[0] != '\0',
     "managed PostgreSQL Auth refresh retains a computed native runtime checksum");
  auto attrs =
      std::unique_ptr<SQLite3_result>(PgHGM->dump_table_pgsql("pgsql_hostgroup_attributes"));
  bool init = false;
  if (attrs)
    for (auto *row : attrs->rows)
      if (std::string(row->fields[0]) == "10" &&
          std::string(row->fields[4]) == "SET application_name='managed-pgsql'")
        init = true;
  ok(init, "existing PostgreSQL HGM receives hostgroup init_connect");
  ok((*proxy_sqlite3_get_autocommit)(GloAdmin->configdb->get_db()) == 1 &&
         scalar(*GloAdmin->configdb, "SELECT count(*) FROM sqlite_master WHERE type='table'") ==
             "0",
     "runtime adapter does not write or transact on service store");
  bool drift = true;
  std::vector<std::string> drift_modules;
  std::string drift_error;
  auto observe_drift = [&] {
    return proxysql_detect_managed_admin_memory_drift_locked({"pgsql-unit", d.dump()}, drift,
                                                             drift_modules, drift_error);
  };
  ok(observe_drift() && !drift && drift_modules.empty(),
     "PostgreSQL scoped Admin memory initially matches managed intent");
  db.execute("UPDATE pgsql_servers SET max_connections=41 WHERE hostgroup_id=10");
  db.execute(
      "UPDATE global_variables SET variable_value='1700' WHERE variable_name='pgsql-poll_timeout'");
  GloPTH->wrlock();
  GloPTH->set_variable(const_cast<char *>("poll_timeout"), "1700");
  GloPTH->commit();
  GloPTH->wrunlock();
  GloAdmin->pgsql_servers_wrlock();
  GloAdmin->load_pgsql_servers_to_runtime();
  GloAdmin->pgsql_servers_wrunlock();
  ok(observe_drift() && drift &&
         std::find(drift_modules.begin(), drift_modules.end(), "pgsql_servers") !=
             drift_modules.end() &&
         std::find(drift_modules.begin(), drift_modules.end(), "pgsql_variables") !=
             drift_modules.end(),
     "legacy PostgreSQL table/variable override and LOAD is visible in scoped Admin memory");
  result = activate_document(d, 1);
  ok(result.applied && observe_drift() && !drift,
     "PostgreSQL API reapply clears observed Admin memory drift");
  PgHGM->wrlock();
  auto *managed = PgHGM->find_server_in_hg(10, "managed.test", 5432);
  auto *unrelated = PgHGM->find_server_in_hg(99, "unrelated.test", 5432);
  if (managed) {
    managed->status = MYSQL_SERVER_STATUS_SHUNNED;
    managed->shunned_automatic = true;
    managed->time_last_detected_error = 123;
  }
  if (unrelated) {
    unrelated->status = MYSQL_SERVER_STATUS_SHUNNED;
    unrelated->shunned_automatic = true;
    unrelated->time_last_detected_error = 456;
  }
  PgHGM->wrunlock();
  result = activate_document(d, 2);
  ok(result.applied && managed && unrelated && managed->status == MYSQL_SERVER_STATUS_SHUNNED &&
         unrelated->status == MYSQL_SERVER_STATUS_SHUNNED && managed->shunned_automatic &&
         unrelated->shunned_automatic && managed->time_last_detected_error == 123 &&
         unrelated->time_last_detected_error == 456,
     "unchanged canonical PostgreSQL status retains managed/unrelated transient health metadata");
  auto live = proxysql_current_server_runtime_rows(ProxySQL_ServerProtocol::pgsql);
  bool shun = false;
  if (live)
    for (const auto &row : *live)
      if (row.hostgroup_id == 10 && row.hostname == "managed.test" && row.status == "SHUNNED")
        shun = true;
  ok(shun, "current PostgreSQL runtime snapshot preserves actual SHUN under caller Admin mutex");
  ok(observe_drift() && !drift,
     "PostgreSQL Admin memory drift excludes transient runtime health");
  proxysql_unlock_configuration();
  auto unlocked = proxysql_current_server_runtime_rows(ProxySQL_ServerProtocol::pgsql);
  proxysql_lock_configuration();
  ok(live && unlocked && unlocked->size() == live->size(),
     "copied PostgreSQL runtime snapshot is usable without caller Admin mutex");
  ok(scalar(db, "SELECT status FROM pgsql_servers WHERE hostgroup_id=10") == "ONLINE",
     "monitor health does not overwrite PostgreSQL Admin intent");
  auto changed = d;
  changed["tables"]["pgsql_servers"][0]["status"] = "OFFLINE_SOFT";
  result = activate_document(changed, 3);
  ok(result.applied && managed->status == MYSQL_SERVER_STATUS_OFFLINE_SOFT &&
         unrelated->status == MYSQL_SERVER_STATUS_SHUNNED,
     "explicit managed PostgreSQL status applies while unrelated health remains");
  ok(shun && live->at(0).status != "OFFLINE_SOFT", "earlier runtime snapshot owns copied values");
  db.execute("UPDATE pgsql_servers SET status='ONLINE'");
  GloAdmin->pgsql_servers_wrlock();
  GloAdmin->load_pgsql_servers_to_runtime();
  GloAdmin->pgsql_servers_wrunlock();
  ok(managed->status == MYSQL_SERVER_STATUS_ONLINE &&
         unrelated->status == MYSQL_SERVER_STATUS_ONLINE,
     "ordinary PostgreSQL LOAD keeps native status reset behavior");
  int old_port = reserve_port(), new_port = reserve_port(), other_port = reserve_port();
  auto old_iface = "127.0.0.1:" + std::to_string(old_port),
       other_iface = "127.0.0.2:" + std::to_string(other_port);
  bool fixture = old_port && new_port && other_port &&
                 GloPTH->set_variable(const_cast<char *>("interfaces"),
                                      (old_iface + ";" + other_iface).c_str()) &&
                 GloPTH->listener_add(old_iface.c_str()) >= 0 &&
                 GloPTH->listener_add(other_iface.c_str()) >= 0;
  auto listeners = d;
  listeners["scope"]["listeners"] = {"127.0.0.1"};
  listeners["listeners"] = {
      {{"protocol", "POSTGRESQL"}, {"address", "127.0.0.1"}, {"port", new_port}}};
  result = activate_document(listeners, 4);
  ok(fixture && result.applied && !connects("127.0.0.1", old_port) &&
         connects("127.0.0.1", new_port) && connects("127.0.0.2", other_port),
     "native live PostgreSQL listener replacement preserves unrelated address");
  auto tls = d;
  tls["tls"] = {{"trust_pem", contents(std::string(GloVars.datadir) + "/proxysql-ca.pem")},
                {"certificate_pem", contents(std::string(GloVars.datadir) + "/proxysql-cert.pem")},
                {"key_pem", contents(std::string(GloVars.datadir) + "/proxysql-key.pem")},
                {"frontend", {{"require_tls", true}, {"verify_peer", true}}},
                {"backend", {{"require_tls", true}}}};
  tls["tables"]["pgsql_servers_ssl_params"][0]["ssl_key"] = tls["tls"]["key_pem"];
  result = activate_document(tls, 5);
  ok(result.applied, "validated PostgreSQL PEM material activates existing TLS APIs: %s",
     result.message.c_str());
  ok(scalar(db, "SELECT use_ssl FROM pgsql_servers WHERE hostgroup_id=10") == "1" &&
         scalar(db, "SELECT use_ssl FROM pgsql_users WHERE username='managed'") == "1",
     "require_tls maps native PostgreSQL per-user/server use_ssl");
  auto key =
      scalar(db, "SELECT ssl_key FROM pgsql_servers_ssl_params WHERE hostname='managed.test'");
  struct stat st {};
  ok(key.find("/proxysql-managed-pgsql-") != std::string::npos && stat(key.c_str(), &st) == 0 &&
         (st.st_mode & 0777) == 0600 && contents(key) == tls["tls"]["key_pem"],
     "resolved PostgreSQL endpoint private key materializes into deterministic private existing "
     "path");
  char *backend = GloPTH->get_variable(const_cast<char *>("ssl_p2s_key"));
  ok(backend && std::string(backend) ==
                    std::string(GloVars.datadir) + "/proxysql-managed-pgsql-backend-key.pem",
     "PostgreSQL backend default TLS material uses engine-specific path");
  free(backend);
  bool tls_drift=true;
  ok(proxysql_detect_managed_admin_memory_drift_locked(
         {"pgsql-unit",tls.dump()},tls_drift,drift_modules,drift_error) && !tls_drift,
     "Admin memory observation normalizes applied PostgreSQL require_tls and PEM material paths");
  auto listener_drift=listeners;
  listener_drift["tls"]=tls["tls"];
  listener_drift["tables"]=tls["tables"];
  // The listener remains from its earlier successful apply; unrelated addresses are excluded.
  ok(proxysql_detect_managed_admin_memory_drift_locked(
         {"pgsql-unit",listener_drift.dump()},tls_drift,drift_modules,drift_error) && !tls_drift,
     "Admin memory observation compares only owned PostgreSQL listener addresses");
  const int busy_port=reserve_port();
  const int busy_fd=socket(AF_INET,SOCK_STREAM,0);
  sockaddr_in busy_address{};busy_address.sin_family=AF_INET;
  busy_address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);busy_address.sin_port=htons(busy_port);
  const bool busy_bound=busy_fd>=0 && bind(busy_fd,reinterpret_cast<sockaddr*>(&busy_address),sizeof(busy_address))==0;
  auto busy=listeners;busy["listeners"][0]["port"]=busy_port;
  result=activate_document(busy,6);
  ok(busy_bound && !result.applied && result.error_code=="ListenersApplyFailed" &&
         connects("127.0.0.1",new_port) && connects("127.0.0.2",other_port),
     "real PostgreSQL bind failure is reported without claiming successful activation");
  if(busy_fd>=0)close(busy_fd);
  auto empty = d;
  for (const auto &t : pgsql_definitions)
    empty["tables"][t.first] = json::array();
  empty["scope"]["listeners"] = {"127.0.0.1"};
  result = activate_document(empty, 6);
  ok(result.applied, "empty desired PostgreSQL arrays activate supplied removal scope");
  ok(scalar(db, "SELECT count(*) FROM pgsql_servers WHERE hostgroup_id=10") == "0" &&
         scalar(db, "SELECT count(*) FROM pgsql_servers WHERE hostgroup_id=99") == "1" &&
         scalar(db, "SELECT count(*) FROM pgsql_users WHERE username='managed'") == "0" &&
         scalar(db, "SELECT count(*) FROM pgsql_query_rules WHERE rule_id=100") == "0",
     "supplied scope removes owned PostgreSQL rows while preserving unrelated rows");
  ok(!connects("127.0.0.1", new_port) && connects("127.0.0.2", other_port),
     "empty desired PostgreSQL listeners remove owned addresses only");
  proxysql_unlock_configuration();
  return exit_status();
}
