#ifdef PROXYSQL40
#include "ProxySQL_ManagedRuntime.h"
#include "MySQL_Query_Processor.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "cpp.h"
#include "json.hpp"
#include "proxysql.h"
#include "proxysql_admin.h"
#include "sqlite3db.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <functional>
#include <map>
#include <memory>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using nlohmann::json;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Authentication *GloMyAuth;
extern MySQL_Query_Processor *GloMyQPro;
extern pthread_mutex_t users_mutex;
extern int admin___web_verbosity;
extern int ProxySQL_create_or_load_TLS(bool, std::string &);
namespace {
struct Unlock {
  std::function<void()> action;
  ~Unlock() { action(); }
};
using Statement = std::unique_ptr<sqlite3_stmt, decltype(proxy_sqlite3_finalize)>;
struct Column {
  std::string name, type;
  bool not_null, primary, has_default;
};
struct Table {
  std::string name, definition, removal;
  std::vector<Column> columns;
  json rows;
};
const std::pair<const char *, const char *> mysql_definitions[] = {
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
std::string quote(const std::string &value) {
  std::string result = "'";
  for (char c : value) {
    result += c;
    if (c == '\'')
      result += '\'';
  }
  return result + "'";
}
Statement statement(SQLite3DB &db, const std::string &sql, std::string &error) {
  sqlite3_stmt *raw = nullptr;
  if ((*proxy_sqlite3_prepare_v2)(db.get_db(), sql.c_str(), -1, &raw, nullptr) != SQLITE_OK)
    error = (*proxy_sqlite3_errmsg)(db.get_db());
  return Statement(raw, proxy_sqlite3_finalize);
}
bool execute(SQLite3DB &db, const std::string &sql, std::string &error) {
  auto stmt = statement(db, sql, error);
  if (!stmt)
    return false;
  if ((*proxy_sqlite3_step)(stmt.get()) != SQLITE_DONE) {
    error = (*proxy_sqlite3_errmsg)(db.get_db());
    return false;
  }
  return true;
}
json rows(SQLite3DB &db, const std::string &sql, std::string &error) {
  auto stmt = statement(db, sql, error);
  json result = json::array();
  if (!stmt)
    return result;
  int rc = SQLITE_OK;
  while ((rc = (*proxy_sqlite3_step)(stmt.get())) == SQLITE_ROW) {
    json row = json::object();
    for (int i = 0; i < (*proxy_sqlite3_column_count)(stmt.get()); ++i) {
      const char *name = (*proxy_sqlite3_column_name)(stmt.get(), i);
      switch ((*proxy_sqlite3_column_type)(stmt.get(), i)) {
      case SQLITE_NULL:
        row[name] = nullptr;
        break;
      case SQLITE_INTEGER:
        row[name] = (*proxy_sqlite3_column_int64)(stmt.get(), i);
        break;
      default:
        row[name] =
            std::string(reinterpret_cast<const char *>((*proxy_sqlite3_column_text)(stmt.get(), i)),
                        (*proxy_sqlite3_column_bytes)(stmt.get(), i));
        break;
      }
    }
    result.push_back(std::move(row));
  }
  if (rc != SQLITE_DONE)
    error = (*proxy_sqlite3_errmsg)(db.get_db());
  return result;
}
bool insert(SQLite3DB &db, const Table &table, const json &row, std::string &error) {
  std::string sql = "INSERT INTO " + table.name + " (", values;
  size_t i = 0;
  for (const auto &kv : row.items()) {
    if (i++) {
      sql += ",";
      values += ",";
    }
    sql += kv.key();
    values += "?";
  }
  sql += ") VALUES (" + values + ")";
  auto stmt = statement(db, sql, error);
  if (!stmt)
    return false;
  i = 0;
  for (const auto &kv : row.items()) {
    const auto &value = kv.value();
    int rc;
    if (value.is_null())
      rc = (*proxy_sqlite3_bind_null)(stmt.get(), ++i);
    else if (value.is_boolean())
      rc = (*proxy_sqlite3_bind_int)(stmt.get(), ++i, value.get<bool>());
    else if (value.is_number_integer())
      rc = (*proxy_sqlite3_bind_int64)(stmt.get(), ++i, value.get<int64_t>());
    else {
      const auto &text = value.get_ref<const std::string &>();
      rc = (*proxy_sqlite3_bind_text)(stmt.get(), ++i, text.data(), text.size(), SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
      error = "cannot bind mapped table value";
      return false;
    }
  }
  if ((*proxy_sqlite3_step)(stmt.get()) != SQLITE_DONE) {
    error = table.name + ": " + (*proxy_sqlite3_errmsg)(db.get_db());
    return false;
  }
  return true;
}
bool listener_address(const std::string &address, std::string &normalized) {
  if (address.empty() || address.find('\0') != std::string::npos)
    return false;
  std::string host = address;
  if (host.front() == '[' && host.back() == ']')
    host = host.substr(1, host.size() - 2);
  if (host.find(':') != std::string::npos) {
    in6_addr ipv6{};
    if (inet_pton(AF_INET6, host.c_str(), &ipv6) != 1)
      return false;
    normalized = "[" + host + "]";
    return true;
  }
  if (!std::all_of(host.begin(), host.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '.' || c == '-' || c == '_';
      }))
    return false;
  normalized = host;
  return true;
}
bool contains(const json &array, const json &value) {
  return std::find(array.begin(), array.end(), value) != array.end();
}
std::string number_set(const json &array) {
  std::string result;
  for (const auto &value : array) {
    if (!result.empty())
      result += ",";
    result += std::to_string(value.get<int64_t>());
  }
  return result.empty() ? "NULL" : result;
}
std::string user_set(const json &scope) {
  std::string result;
  for (const auto &user : scope["users"]) {
    if (!result.empty())
      result += ",";
    result += quote(user["username"].get<std::string>());
  }
  return result.empty() ? "NULL" : result;
}
bool check_scope(const json &d, const Table &table, const json &row, std::string &error) {
  const auto &scope = d["scope"];
  static const std::set<std::string> group_columns = {
      "hostgroup_id",      "default_hostgroup", "destination_hostgroup",
      "writer_hostgroup",  "reader_hostgroup",  "backup_writer_hostgroup",
      "offline_hostgroup", "mirror_hostgroup",  "gtid_from_hostgroup"};
  for (const auto &kv : row.items())
    if (group_columns.count(kv.key()) && !kv.value().is_null() && kv.value().is_number_integer() &&
        kv.value().get<int64_t>() >= 0 && !contains(scope["hostgroups"], kv.value())) {
      error = table.name + "." + kv.key() + " is outside managed hostgroup scope";
      return false;
    }
  if (table.name == "mysql_users") {
    const json key = {
        {"username", row["username"]}, {"frontend", row["frontend"]}, {"backend", row["backend"]}};
    if (!contains(scope["users"], key)) {
      error = "user roles are outside managed scope";
      return false;
    }
  }
  if (table.name == "mysql_query_rules" && !contains(scope["query_rules"], row["rule_id"])) {
    error = "rule ID is outside managed scope";
    return false;
  }
  if (table.name == "mysql_query_rules_fast_routing") {
    bool found = false;
    for (const auto &user : scope["users"])
      if (user["username"] == row["username"])
        found = true;
    if (!found) {
      error = "fast routing user is outside managed scope";
      return false;
    }
  }
  if (table.name == "mysql_servers_ssl_params") {
    bool found = false;
    for (const auto &server : d["tables"]["mysql_servers"])
      if (server["hostname"] == row["hostname"] && server.value("port", 3306) == row["port"])
        found = true;
    if (!found) {
      error = "backend TLS endpoint is outside managed server scope";
      return false;
    }
  }
  return true;
}
bool valid_admin_variable(const std::string &name, const std::string &value) {
  // A managed request runs inside the serving endpoint. Its lifecycle belongs to process
  // startup/shutdown, and the existing plugin start operation cannot rebind a live port.
  if (name == "web_enabled" || name == "web_port" || name == "restapi_enabled" ||
      name == "restapi_port")
    return false;
  if (name.compare(0, 8, "cluster_") == 0 || name.compare(0, 9, "checksum_") == 0 ||
      name == "version" || name == "hash_passwords" || name.find("ifaces") != std::string::npos)
    return false;
  char *existing = GloAdmin->get_variable(const_cast<char *>(name.c_str()));
  if (!existing)
    return false;
  free(existing);
  auto number = [&](long long low, long long high) {
    char *end = nullptr;
    errno = 0;
    auto v = strtoll(value.c_str(), &end, 10);
    return !value.empty() && !*end && errno != ERANGE && v >= low && v <= high;
  };
  if (name == "admin_credentials" || name == "stats_credentials")
    return !value.empty();
  if (name == "stats_mysql_connection_pool" || name == "stats_mysql_connections" ||
      name == "stats_mysql_query_cache")
    return number(0, 300);
  if (name == "stats_mysql_query_digest_to_disk" ||
      name == "stats_mysql_eventslog_sync_buffer_to_disk" ||
      name == "stats_pgsql_eventslog_sync_buffer_to_disk")
    return number(0, 24 * 3600);
  if (name == "stats_system_cpu" || name == "stats_system_memory")
    return number(0, 600);
  if (name == "refresh_interval")
    return number(101, 99999);
  if (name == "web_verbosity")
    return number(0, 10);
  if (name == "prometheus_memory_metrics_interval")
    return number(1, 7 * 24 * 3600 - 1);
  if (name == "coredump_generation_interval_ms")
    return number(0, INT_MAX - 1);
  if (name == "coredump_generation_threshold")
    return number(1, 500);
  if (name == "debug_output")
    return number(1, 3);
  if (name == "ssl_keylog_file")
    return true;
  static const std::set<std::string> booleans = {
      "vacuum_stats", "read_only", "debug"};
  return booleans.count(name) &&
         (value == "true" || value == "false" || value == "0" || value == "1");
}
std::string variable_value(const json &value) {
  if (value.is_string())
    return value.get<std::string>();
  if (value.is_boolean())
    return value.get<bool>() ? "true" : "false";
  return value.dump();
}
bool validate_pem(const json &tls, std::string &error) {
  EVP_PKEY *key = nullptr;
  X509 *certificate = nullptr;
  for (const auto &name : {"trust_pem", "certificate_pem", "key_pem"})
    if (tls.contains(name)) {
      if (!tls[name].is_string() || tls[name].get_ref<const std::string &>().empty()) {
        error = "TLS material must be PEM content";
        break;
      }
      const auto &value = tls[name].get_ref<const std::string &>();
      BIO *bio = BIO_new_mem_buf(value.data(), value.size());
      if (std::string(name) == "key_pem")
        key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
      else {
        X509 *parsed = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (std::string(name) == "certificate_pem")
          certificate = parsed;
        else
          X509_free(parsed);
        if (!parsed)
          error = "invalid TLS certificate or trust material";
      }
      BIO_free(bio);
      if (std::string(name) == "key_pem" && !key)
        error = "invalid TLS private key material";
      if (!error.empty())
        break;
    }
  if (error.empty() && key && certificate && X509_check_private_key(certificate, key) != 1)
    error = "TLS certificate and private key do not match";
  EVP_PKEY_free(key);
  X509_free(certificate);
  return error.empty();
}
std::string endpoint_key_path(const std::string &deployment, const json &row) {
  const std::string identity = deployment + "\n" + row["hostname"].get<std::string>() + "\n" +
                               row["port"].dump() + "\n" + row["username"].get<std::string>();
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char *>(identity.data()), identity.size(), digest);
  static const char hex[] = "0123456789abcdef";
  std::string suffix;
  for (auto byte : digest) {
    suffix += hex[byte >> 4];
    suffix += hex[byte & 15];
  }
  return std::string(GloVars.datadir) + "/proxysql-managed-mysql-" + suffix + "-key.pem";
}
bool write_material(const std::string &path, const std::string &material, std::string &error) {
  const std::string temporary = path + ".managed.XXXXXX";
  std::vector<char> name(temporary.begin(), temporary.end());
  name.push_back(0);
  int fd = mkstemp(name.data());
  if (fd < 0) {
    error = "cannot create TLS material file";
    return false;
  }
  bool success = fchmod(fd, S_IRUSR | S_IWUSR) == 0;
  size_t offset = 0;
  while (success && offset < material.size()) {
    ssize_t n = write(fd, material.data() + offset, material.size() - offset);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      success = false;
      break;
    }
    offset += n;
  }
  if (close(fd) != 0)
    success = false;
  if (success && rename(name.data(), path.c_str()) == 0)
    return true;
  unlink(name.data());
  error = "cannot publish TLS material file";
  return false;
}
} // namespace
struct ManagedPreparedRuntime {
  json document;
  std::vector<Table> tables;
  std::map<std::string, std::string> variables;
  std::string interfaces;
  bool listeners_changed{false};
};

bool proxysql_prepare_managed_runtime_locked(const ManagedRuntimePlan &plan,
                                             ManagedPreparedRuntime **out, std::string &error) {
  error.clear();
  if (!out) {
    error = "prepared output is required";
    return false;
  }
  *out = nullptr;
  if (!GloAdmin || !GloAdmin->admindb || !GloMTH) {
    error = "MySQL configuration runtime is unavailable";
    return false;
  }
  try {
    auto p = std::make_unique<ManagedPreparedRuntime>();
    p->document = json::parse(plan.configuration_json);
    auto &d = p->document;
    if (!d.is_object() || d.size() != 6) {
      error = "mapped configuration requires exactly identity/scope/tables/variables/tls/listeners";
      return false;
    }
    for (const auto &key : {"identity", "scope", "tables", "variables", "tls"})
      if (!d.contains(key) || !d[key].is_object()) {
        error = std::string("invalid mapped ") + key;
        return false;
      }
    if (!d.contains("listeners") || !d["listeners"].is_array() ||
        d["identity"].value("engine", "") != "MYSQL" || plan.deployment_id.empty() ||
        d["identity"].value("deployment_id", "") != plan.deployment_id) {
      error = "mapped identity or listener section is invalid";
      return false;
    }
    const auto &scope = d["scope"];
    for (const auto &key : {"hostgroups", "users", "query_rules", "listeners"})
      if (!scope.contains(key) || !scope[key].is_array()) {
        error = "complete managed scope is required";
        return false;
      }
    for (const auto &key : {"hostgroups", "query_rules"})
      for (const auto &v : scope[key])
        if (!v.is_number_integer() || v.get<int64_t>() < 0 || v.get<uint64_t>() > UINT32_MAX) {
          error = "scope IDs must be nonnegative 32-bit integers";
          return false;
        }
    for (const auto &user : scope["users"])
      if (!user.is_object() || !user.contains("username") || !user["username"].is_string() ||
          user["username"].get_ref<const std::string &>().empty() || !user.contains("frontend") ||
          !user.contains("backend") || !user["frontend"].is_number_integer() ||
          !user["backend"].is_number_integer() || user["frontend"].get<int>() < 0 ||
          user["frontend"].get<int>() > 1 || user["backend"].get<int>() < 0 ||
          user["backend"].get<int>() > 1) {
        error = "scope requires exact user role keys";
        return false;
      }
    if (d["tables"].size() != std::size(mysql_definitions)) {
      error = "complete MySQL table set is required";
      return false;
    }
    SQLite3DB candidate;
    candidate.open(const_cast<char *>(":memory:"),
                   SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
    for (const auto &definition : mysql_definitions) {
      Table table;
      table.name = definition.first;
      table.definition = definition.second;
      if (!d["tables"].contains(table.name) || !d["tables"][table.name].is_array()) {
        error = "missing mapped table " + table.name;
        return false;
      }
      if (!execute(candidate, table.definition, error))
        return false;
      for (const auto &c : rows(candidate, "PRAGMA table_info(" + table.name + ")", error))
        table.columns.push_back(
            {c["name"], c["type"], c["notnull"] != 0, c["pk"] != 0, !c["dflt_value"].is_null()});
      for (const auto &row : d["tables"][table.name]) {
        if (!row.is_object() || row.empty()) {
          error = "table row must contain explicit keys";
          return false;
        }
        for (const auto &value : row.items()) {
          const auto column = std::find_if(table.columns.begin(), table.columns.end(),
                                           [&](const Column &c) { return c.name == value.key(); });
          if (column == table.columns.end()) {
            error = "unknown column in " + table.name;
            return false;
          }
          const auto &v = value.value();
          bool integer = column->type.find("INT") != std::string::npos;
          if ((v.is_null() && (column->not_null || column->primary)) ||
              (!v.is_null() &&
               (integer ? !(v.is_number_integer() || v.is_boolean()) : !v.is_string()))) {
            error = "invalid type or nullability in " + table.name + "." + value.key();
            return false;
          }
          if (v.is_string() && v.get_ref<const std::string &>().find('\0') != std::string::npos) {
            error = "mapped text cannot contain NUL bytes";
            return false;
          }
        }
        for (const auto &c : table.columns)
          if (c.primary && !c.has_default && !row.contains(c.name)) {
            error = "explicit primary key required in " + table.name;
            return false;
          }
        if (!insert(candidate, table, row, error))
          return false;
      }
      table.rows = rows(candidate, "SELECT * FROM " + table.name, error);
      if (table.name == "mysql_servers_ssl_params")
        for (const auto &row : table.rows)
          if (!row["ssl_key"].get_ref<const std::string &>().empty())
            if (!validate_pem({{"key_pem", row["ssl_key"]}}, error))
              return false;
      for (const auto &row : table.rows)
        if (!check_scope(d, table, row, error))
          return false;
      p->tables.push_back(std::move(table));
    }
    if (!error.empty())
      return false;
    SQLite3DB combined;
    combined.open(const_cast<char *>(":memory:"),
                  SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
    for (auto &table : p->tables) {
      if (!execute(combined, table.definition, error))
        return false;
      auto existing = rows(*GloAdmin->admindb, "SELECT * FROM " + table.name, error);
      if (!error.empty())
        return false;
      for (const auto &row : existing)
        if (!insert(combined, table, row, error))
          return false;
      if (table.name == "mysql_servers" || table.name == "mysql_hostgroup_attributes")
        table.removal = "hostgroup_id IN (" + number_set(scope["hostgroups"]) + ")";
      else if (table.name == "mysql_query_rules")
        table.removal = "rule_id IN (" + number_set(scope["query_rules"]) + ")";
      else if (table.name == "mysql_users") {
        for (const auto &user : scope["users"]) {
          if (!table.removal.empty())
            table.removal += " OR ";
          table.removal += "(username=" + quote(user["username"]) +
                           " AND frontend=" + std::to_string(user["frontend"].get<int>()) +
                           " AND backend=" + std::to_string(user["backend"].get<int>()) + ")";
        }
      } else if (table.name == "mysql_query_rules_fast_routing")
        table.removal = "username IN (" + user_set(scope) + ")";
      else if (table.name == "mysql_servers_ssl_params") {
        const auto previous =
            rows(*GloAdmin->admindb,
                 "SELECT hostname,port FROM mysql_servers WHERE hostgroup_id IN (" +
                     number_set(scope["hostgroups"]) + ")",
                 error);
        const auto unrelated =
            rows(*GloAdmin->admindb,
                 "SELECT hostname,port FROM mysql_servers WHERE hostgroup_id NOT IN (" +
                     number_set(scope["hostgroups"]) + ")",
                 error);
        for (const auto &row : table.rows)
          for (const auto &other : unrelated)
            if (row["hostname"] == other["hostname"] && row["port"] == other["port"]) {
              error = "backend TLS endpoint is shared with an unrelated hostgroup";
              return false;
            }
        json endpoints = previous;
        for (const auto &server : d["tables"]["mysql_servers"])
          endpoints.push_back(
              {{"hostname", server["hostname"]}, {"port", server.value("port", 3306)}});
        for (const auto &endpoint : endpoints) {
          for (const auto &other : unrelated)
            if (endpoint["hostname"] == other["hostname"] && endpoint["port"] == other["port"])
              for (const auto &old : existing)
                if (old["hostname"] == endpoint["hostname"] && old["port"] == endpoint["port"]) {
                  error = "backend TLS replacement overlaps an unrelated hostgroup endpoint";
                  return false;
                }
          if (!table.removal.empty())
            table.removal += " OR ";
          table.removal += "(hostname=" + quote(endpoint["hostname"]) +
                           " AND port=" + std::to_string(endpoint["port"].get<int>()) + ")";
        }
      } else {
        table.removal = "writer_hostgroup IN (" + number_set(scope["hostgroups"]) + ")";
        for (const auto &row : existing)
          if (contains(scope["hostgroups"], row["writer_hostgroup"]) &&
              !check_scope(d, table, row, error)) {
            error = "topology replacement overlaps unrelated hostgroups";
            return false;
          }
      }
      if (table.removal.empty())
        table.removal = "0";
      if (!execute(combined, "DELETE FROM " + table.name + " WHERE " + table.removal, error))
        return false;
      for (const auto &row : table.rows)
        if (!insert(combined, table, row, error))
          return false;
    }
    for (const auto &kv : d["variables"].items()) {
      if (!(kv.value().is_string() || kv.value().is_boolean() || kv.value().is_number_integer())) {
        error = "variable requires resolved scalar value";
        return false;
      }
      std::string value = variable_value(kv.value());
      if (value.find('\0') != std::string::npos) {
        error = "variable cannot contain NUL";
        return false;
      }
      const bool mysql = kv.key().compare(0, 6, "mysql-") == 0,
                 admin = kv.key().compare(0, 6, "admin-") == 0;
      const std::string name = kv.key().substr(6);
      if ((!mysql && !admin) || name == "threads" || name == "stacksize" || name == "interfaces" ||
          !(mysql ? GloMTH->validate_variable(name.c_str(), value.c_str())
                  : valid_admin_variable(name, value))) {
        error = "unsupported or invalid runtime variable " + kv.key();
        return false;
      }
      p->variables[kv.key()] = value;
    }
    for (const auto &kv : d["tls"].items()) {
      if (kv.key() == "frontend" || kv.key() == "backend") {
        if (!kv.value().is_object()) {
          error = "TLS policy must be an object";
          return false;
        }
        for (const auto &policy : kv.value().items())
          if ((policy.key() != "require_tls" && policy.key() != "verify_peer") ||
              !policy.value().is_boolean()) {
            error = "unsupported TLS policy shape";
            return false;
          }
      } else if (kv.key() != "trust_pem" && kv.key() != "certificate_pem" &&
                 kv.key() != "key_pem") {
        error = "TLS secrets must be resolved to material";
        return false;
      }
    }
    if (!validate_pem(d["tls"], error))
      return false;
    // A material update uses the global frontend context already shared by both engines.
    if (d["tls"].contains("key_pem") != d["tls"].contains("certificate_pem")) {
      error = "TLS certificate/key material must be supplied together";
      return false;
    }
    if (!d["listeners"].empty() || !scope["listeners"].empty()) {
      char *current = GloMTH->get_variable("interfaces");
      if (!current) {
        error = "current MySQL interfaces are unavailable";
        return false;
      }
      std::string existing(current);
      free(current);
      std::set<std::string> endpoints, scoped_addresses;
      for (const auto &address : scope["listeners"]) {
        std::string normalized;
        if (!address.is_string() || !listener_address(address.get<std::string>(), normalized)) {
          error = "listener scope must contain valid addresses";
          return false;
        }
        scoped_addresses.insert(normalized);
      }
      size_t begin = 0;
      while (begin < existing.size()) {
        size_t end = existing.find(';', begin);
        auto endpoint = existing.substr(begin, end == std::string::npos ? end : end - begin);
        bool scoped = false;
        for (const auto &prefix : scoped_addresses)
          if (endpoint == prefix || endpoint.compare(0, prefix.size() + 1, prefix + ":") == 0)
            scoped = true;
        if (!scoped)
          endpoints.insert(endpoint);
        if (end == std::string::npos)
          break;
        begin = end + 1;
      }
      for (const auto &listener : d["listeners"]) {
        if (!listener.is_object() || listener.value("protocol", "") != "MYSQL" ||
            !listener.contains("address") || !listener["address"].is_string() ||
            !listener.contains("port") || !listener["port"].is_number_integer() ||
            listener["port"].get<int64_t>() <= 0 || listener["port"].get<int64_t>() > 65535 ||
            !contains(scope["listeners"], listener["address"])) {
          error = "invalid scoped MySQL listener";
          return false;
        }
        std::string address;
        if (!listener_address(listener["address"].get<std::string>(), address)) {
          error = "invalid listener address";
          return false;
        }
        endpoints.insert(address + ":" + std::to_string(listener["port"].get<int>()));
      }
      for (const auto &endpoint : endpoints) {
        if (!p->interfaces.empty())
          p->interfaces += ';';
        p->interfaces += endpoint;
      }
      p->listeners_changed = p->interfaces != existing;
    }
    *out = p.release();
    return true;
  } catch (const std::exception &) {
    error = "invalid mapped configuration document";
    return false;
  }
}

ManagedRuntimeResult proxysql_activate_managed_runtime_locked(ManagedPreparedRuntime &p, uint64_t) {
  std::string error;
  if (!GloAdmin || !GloAdmin->admindb || !MyHGM || !GloMyAuth || !GloMyQPro || !GloMTH)
    return {false, "RuntimeUnavailable", "required MySQL modules are unavailable"};
  try {
    const auto &tls = p.document["tls"];
    if ((tls.contains("trust_pem") || tls.contains("certificate_pem") || tls.contains("key_pem")) &&
        !GloVars.datadir)
      return {false, "TlsApplyFailed", "TLS datadir is unavailable"};
    for (const auto &name : {"trust_pem", "certificate_pem", "key_pem"})
      if (tls.contains(name)) {
        const std::string stem = std::string(name) == "trust_pem"         ? "ca"
                                 : std::string(name) == "certificate_pem" ? "cert"
                                                                          : "key";
        const std::string path = std::string(GloVars.datadir) + "/proxysql-" + stem + ".pem";
        if (!write_material(path, tls[name], error))
          return {false, "TlsApplyFailed", error};
        const std::string backend =
            std::string(GloVars.datadir) + "/proxysql-managed-backend-" + stem + ".pem";
        if (!write_material(backend, tls[name], error))
          return {false, "TlsApplyFailed", error};
        p.variables["mysql-ssl_p2s_" + stem] = backend;
      }
    if (tls.contains("trust_pem") || tls.contains("certificate_pem") || tls.contains("key_pem"))
      if (ProxySQL_create_or_load_TLS(false, error) != 0)
        return {false, "TlsApplyFailed", error};
    auto &db = *GloAdmin->admindb;
    const auto previous_servers =
        rows(db, "SELECT hostgroup_id,hostname,port,status FROM mysql_servers", error);
    if (!error.empty())
      return {false, "MemoryApplyFailed", error};
    for (const auto &table : p.tables) {
      if (!execute(db, "DELETE FROM " + table.name + " WHERE " + table.removal, error))
        return {false, "MemoryApplyFailed", error};
      for (auto row : table.rows) {
        if (tls.contains("frontend") && tls["frontend"].contains("require_tls") &&
            table.name == "mysql_users" && row["frontend"] == 1)
          row["use_ssl"] = int(tls["frontend"]["require_tls"].get<bool>());
        if (tls.contains("backend") && tls["backend"].contains("require_tls") &&
            table.name == "mysql_servers")
          row["use_ssl"] = int(tls["backend"]["require_tls"].get<bool>());
        if (table.name == "mysql_servers_ssl_params" &&
            !row["ssl_key"].get_ref<const std::string &>().empty()) {
          if (!GloVars.datadir)
            return {false, "TlsApplyFailed", "TLS datadir is unavailable"};
          const auto path = endpoint_key_path(p.document["identity"]["deployment_id"], row);
          if (!write_material(path, row["ssl_key"], error))
            return {false, "TlsApplyFailed", error};
          row["ssl_key"] = path;
        }
        if (!insert(db, table, row, error))
          return {false, "MemoryApplyFailed", error};
      }
    }
    MySQL_ServerHealthPreservationKeys preserve_health;
    const auto desired_servers =
        rows(db, "SELECT hostgroup_id,hostname,port,status FROM mysql_servers", error);
    if (!error.empty())
      return {false, "MemoryApplyFailed", error};
    for (const auto &desired : desired_servers)
      for (const auto &prior : previous_servers)
        if (desired == prior)
          preserve_health.emplace(desired["hostgroup_id"].get<unsigned int>(),
                                  desired["hostname"].get<std::string>(),
                                  desired["port"].get<unsigned int>());
    bool servers = false;
    {
      GloAdmin->mysql_servers_wrlock();
      Unlock unlock{[] { GloAdmin->mysql_servers_wrunlock(); }};
      servers = GloAdmin->load_mysql_servers_to_runtime({}, {}, {}, true, true, &preserve_health);
    }
    if (!servers)
      return {false, "ServersApplyFailed",
              GloAdmin->servers_load_veto[0].empty()
                  ? "existing MySQL server loader rejected configuration"
                  : GloAdmin->servers_load_veto[0]};
    auto users = std::unique_ptr<SQLite3_result>();
    char *sqlite_error = nullptr;
    int columns = 0, affected = 0;
    SQLite3_result *raw = nullptr;
    db.execute_statement(
        "SELECT "
        "username,password,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_"
        "persistent,fast_forward,backend,frontend,max_connections,attributes,comment FROM "
        "mysql_users WHERE active=1 ORDER BY username,backend DESC",
        &sqlite_error, &columns, &affected, &raw);
    users.reset(raw);
    if (sqlite_error) {
      error = sqlite_error;
      free(sqlite_error);
      return {false, "UsersApplyFailed", error};
    }
    if (!users)
      return {false, "UsersApplyFailed", "user input is unavailable"};
    bool authenticated = false;
    {
      pthread_mutex_lock(&users_mutex);
      Unlock unlock{[] { pthread_mutex_unlock(&users_mutex); }};
      authenticated = GloAdmin->init_users_under_lock(std::move(users), error);
    }
    if (!authenticated)
      return {false, "UsersApplyFailed", error};
    char *rules_error = GloAdmin->load_mysql_query_rules_to_runtime();
    if (rules_error) {
      error = rules_error;
      free(rules_error);
      return {false, "RulesApplyFailed", error};
    }
    bool mysql_variables = false, admin_variables = false;
    for (const auto &kv : p.variables) {
      const bool mysql = kv.first.compare(0, 6, "mysql-") == 0;
      const std::string name = kv.first.substr(6);
      bool accepted;
      if (mysql) {
        GloMTH->wrlock();
        Unlock unlock{[] { GloMTH->wrunlock(); }};
        accepted = GloMTH->set_variable(name.c_str(), kv.second.c_str());
        mysql_variables = true;
      } else {
        accepted = GloAdmin->set_managed_variable_locked(name, kv.second);
        admin_variables = true;
      }
      if (!accepted)
        return {false, "VariablesApplyFailed", "existing variable setter rejected " + kv.first};
      Table globals;
      globals.name = "global_variables";
      if (!execute(db, "DELETE FROM global_variables WHERE variable_name=" + quote(kv.first),
                   error) ||
          !insert(db, globals, {{"variable_name", kv.first}, {"variable_value", kv.second}}, error))
        return {false, "VariablesApplyFailed", error};
    }
    if (mysql_variables) {
      GloMTH->wrlock();
      Unlock unlock{[] { GloMTH->wrunlock(); }};
      const auto result = GloMTH->commit();
      if (!result.rejected_variables.empty())
        return {false, "VariablesApplyFailed",
                "existing variable commit rejected " + result.rejected_variables.front()};
    }
    if (admin_variables && !GloAdmin->commit_managed_admin_variables_locked(error))
      return {false, "VariablesApplyFailed", error};
    if (p.listeners_changed) {
      {
        GloMTH->wrlock();
        Unlock unlock{[] { GloMTH->wrunlock(); }};
        if (!GloMTH->apply_interfaces_under_lock(p.interfaces.c_str(), error))
          return {false, "ListenersApplyFailed", error};
      }
      Table globals;
      globals.name = "global_variables";
      if (!execute(db, "DELETE FROM global_variables WHERE variable_name='mysql-interfaces'",
                   error) ||
          !insert(db, globals,
                  {{"variable_name", "mysql-interfaces"}, {"variable_value", p.interfaces}}, error))
        return {false, "ListenersApplyFailed", error};
    }
    return {true, "", ""};
  } catch (const std::exception &) {
    return {false, "RuntimeApplyFailed", "existing MySQL runtime operation failed"};
  }
}
void proxysql_destroy_managed_prepared_runtime(ManagedPreparedRuntime *prepared) noexcept {
  delete prepared;
}
bool ProxySQL_Admin::set_managed_variable_locked(const std::string &name,
                                                 const std::string &value) {
  wrlock();
  Unlock unlock{[this] { wrunlock(); }};
  return set_variable(const_cast<char *>(name.c_str()), const_cast<char *>(value.c_str()), false);
}
bool ProxySQL_Admin::commit_managed_admin_variables_locked(std::string &error) {
  {
    wrlock();
    Unlock unlock{[this] { wrunlock(); }};
    // Refresh the existing runtime checksum from live values without loading unrelated memory
    // intent.
    if (!execute(*admindb,
                 "DELETE FROM runtime_global_variables WHERE variable_name LIKE 'admin-%'", error))
      return false;
    char **names = get_variables_list();
    Unlock free_names{[names] {
      for (size_t i = 0; names[i]; ++i)
        free(names[i]);
      free(names);
    }};
    Table globals;
    globals.name = "runtime_global_variables";
    for (size_t i = 0; names[i]; ++i) {
      std::unique_ptr<char, decltype(&free)> value(get_variable(names[i]), free);
      if (!insert(*admindb, globals,
                  {{"variable_name", std::string("admin-") + names[i]},
                   {"variable_value", value ? value.get() : ""}},
                  error))
        return false;
    }
    pthread_mutex_lock(&GloVars.checksum_mutex);
    Unlock checksum_unlock{[] { pthread_mutex_unlock(&GloVars.checksum_mutex); }};
    flush_GENERIC_variables__checksum__database_to_runtime("admin", "", 0);
  }
  // Preparation excludes endpoint lifecycle settings. Refresh operational values without
  // entering synchronous HTTP shutdown/start from the current managed request callback.
  admin___web_verbosity = variables.web_verbosity;
  return true;
}
#endif
