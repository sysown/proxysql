#include "Embedded_Admin_SQLite_Policy.h"

#include "PgSQL_Data_Stream.h"
#include "proxysql.h"
#include "proxysql_admin.h"
#include "sqlite3db.h"

#include <set>
#include <strings.h>
#include <unordered_set>

namespace embedded {
namespace {
// Exact standard relation names handled by GenericRefreshStatistics. Never pass
// user-controlled SQL or arbitrary identifiers to that substring-based routine.
const std::unordered_set<std::string> refresh_tables = {
 "stats_memory_metrics",
 "stats_mysql_client_host_cache",
 "stats_mysql_commands_counters",
 "stats_mysql_connection_pool",
 "stats_mysql_errors",
 "stats_mysql_free_connections",
 "stats_mysql_global",
 "stats_mysql_gtid_executed",
 "stats_mysql_hostgroup_connection_pool",
 "stats_mysql_passthrough_auth_cache",
 "stats_mysql_passthrough_auth_metrics",
 "stats_mysql_prepared_statements_info",
 "stats_mysql_processlist",
 "stats_mysql_query_digest",
 "stats_mysql_query_rules",
 "stats_mysql_users",
 "stats_pgsql_client_host_cache",
 "stats_pgsql_commands_counters",
 "stats_pgsql_connection_pool",
 "stats_pgsql_errors",
 "stats_pgsql_free_connections",
 "stats_pgsql_global",
 "stats_pgsql_hostgroup_connection_pool",
 "stats_pgsql_prepared_statements_info",
 "stats_pgsql_processlist",
 "stats_pgsql_query_digest",
 "stats_pgsql_query_rules",
 "stats_pgsql_stat_activity",
 "stats_pgsql_users",
 "stats_proxysql_global",
 "stats_proxysql_message_metrics",
 "stats_proxysql_servers_checksums",
 "stats_proxysql_servers_metrics",
 "stats_proxysql_servers_status",
 "stats_tls_certificates",
 "stats_tsdb",
 "runtime_checksums_values",
 "runtime_clickhouse_users",
 "runtime_coredump_filters",
 "runtime_mysql_aws_aurora_hostgroups",
 "runtime_mysql_aws_rds_bgd_hostgroups",
 "runtime_mysql_firewall_whitelist_rules",
 "runtime_mysql_firewall_whitelist_sqli_fingerprints",
 "runtime_mysql_firewall_whitelist_users",
 "runtime_mysql_galera_hostgroups",
 "runtime_mysql_group_replication_hostgroups",
 "runtime_mysql_hostgroup_attributes",
 "runtime_mysql_ldap_mapping",
 "runtime_mysql_query_rules",
 "runtime_mysql_query_rules_fast_routing",
 "runtime_mysql_replication_hostgroups",
 "runtime_mysql_servers",
 "runtime_mysql_servers_ssl_params",
 "runtime_mysql_users",
 "runtime_pgsql_firewall_whitelist_rules",
 "runtime_pgsql_firewall_whitelist_sqli_fingerprints",
 "runtime_pgsql_firewall_whitelist_users",
 "runtime_pgsql_hostgroup_attributes",
 "runtime_pgsql_ldap_mapping",
 "runtime_pgsql_query_rules",
 "runtime_pgsql_query_rules_fast_routing",
 "runtime_pgsql_replication_hostgroups",
 "runtime_pgsql_servers",
 "runtime_pgsql_users",
 "runtime_proxysql_servers",
 "runtime_restapi_routes",
 "runtime_scheduler",

 "stats_mysql_client_host_cache_reset",
 "stats_mysql_connection_pool_reset",
 "stats_mysql_errors_reset",
 "stats_mysql_hostgroup_connection_pool_reset",
 "stats_mysql_query_digest_reset",
 "stats_pgsql_client_host_cache_reset",
 "stats_pgsql_connection_pool_reset",
 "stats_pgsql_errors_reset",
 "stats_pgsql_hostgroup_connection_pool_reset",
 "stats_pgsql_query_digest_reset",
 "stats_proxysql_message_metrics_reset",
};

Status sqlite_error(sqlite3* db, int rc) {
    return Error{ErrorKind::engine, rc, proxy_sqlite3_errmsg(db), "HY000"};
}
}

struct AdminSQLitePolicy::Guard final : OperationGuard {
    AdminSQLitePolicy& policy;
    bool read_only;
    bool query_only_set = false;
    bool installed = false;
    bool inspecting = false;
    bool needs_vacuum = false;
    bool savepoint = false;
    bool managing_savepoint = false;
    std::set<std::string> relations;

    explicit Guard(AdminSQLitePolicy& p)
        : policy(p), read_only(!p.is_admin_ || p.admin_.get_read_only()) {}

    ~Guard() override {
        if (installed && proxy_sqlite3_set_authorizer(policy.db_, nullptr, nullptr) != SQLITE_OK)
            std::terminate();
        if (savepoint && !proxy_sqlite3_get_autocommit(policy.db_) &&
            proxy_sqlite3_exec(policy.db_, "ROLLBACK TO proxysql_prepared; RELEASE proxysql_prepared",
                               nullptr, nullptr, nullptr) != SQLITE_OK)
            std::terminate();
        if (query_only_set && proxy_sqlite3_exec(policy.db_, "PRAGMA query_only = OFF",
                                                 nullptr, nullptr, nullptr) != SQLITE_OK)
            std::terminate();
        if (needs_vacuum)
            policy.admin_.vacuum_stats(policy.is_admin_);
        policy.active_ = nullptr;
    }

    Status run_savepoint(const char* sql) {
        managing_savepoint = true;
        const int rc = proxy_sqlite3_exec(policy.db_, sql, nullptr, nullptr, nullptr);
        managing_savepoint = false;
        return rc == SQLITE_OK ? Status{} : sqlite_error(policy.db_, rc);
    }

    Status finish() override {
        if (!savepoint)
            return {};
        if (auto error = run_savepoint("RELEASE proxysql_prepared"))
            return error;
        savepoint = false;
        return {};
    }

    static int authorize(void* context, int action, const char* name, const char* value,
                         const char* schema, const char* source) noexcept {
        auto& g = *static_cast<Guard*>(context);
        // STATS ordinary SQL forbids PRAGMA and ATTACH. Do not let read-only
        // Admin disable the SQLite restriction for the current operation.
        if (!g.policy.is_admin_ && (action == SQLITE_PRAGMA || action == SQLITE_ATTACH))
            return SQLITE_DENY;
        if (action == SQLITE_PRAGMA && g.read_only && name && value &&
            strcasecmp(name, "query_only") == 0)
            return SQLITE_DENY;
        // A prepared operation cannot leave an open transaction on the
        // shared Admin connection after its operation guard releases the lock.
        if (action == SQLITE_TRANSACTION || action == SQLITE_SAVEPOINT)
            return g.managing_savepoint ? SQLITE_OK : SQLITE_DENY;
        if (!g.inspecting)
            return SQLITE_OK;
        // Some SQLite PRAGMAs take effect at prepare time. Inspection only
        // discovers relation accesses and must not run a PRAGMA again.
        if (action == SQLITE_PRAGMA)
            return SQLITE_IGNORE;
        // These native actions to report PostgreSQL command completion do not
        // participate in authorization.
        if (!source && g.policy.command_ == Command::unknown && name &&
            strcasecmp(name, "sqlite_master") != 0 && strcasecmp(name, "sqlite_temp_master") != 0) {
            switch (action) {
                case SQLITE_INSERT: g.policy.command_ = Command::insert; break;
                case SQLITE_UPDATE: g.policy.command_ = Command::update; break;
                case SQLITE_DELETE: g.policy.command_ = Command::delete_; break;
            }
        }
        if (action == SQLITE_READ && name && schema && strcasecmp(schema, "main") == 0) {
            try {
                std::string relation(name);
                for (char& ch : relation)
                    if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
                if (refresh_tables.count(relation))
                    g.relations.insert(std::move(relation));
            } catch (...) {
                return SQLITE_DENY;
            }
        }
        return SQLITE_OK;
    }
};

AdminSQLitePolicy::AdminSQLitePolicy(ProxySQL_Admin& admin, sqlite3* db, bool is_admin)
    : admin_(admin), db_(db), is_admin_(is_admin) {}

Status AdminSQLitePolicy::guard(std::unique_ptr<OperationGuard>& out) {
    if (active_ || !proxy_sqlite3_set_authorizer)
        return Error{ErrorKind::internal, 0, "Admin SQLite operation guard unavailable", "HY000"};
    auto g = std::make_unique<Guard>(*this);
    if (g->read_only) {
        const int rc = proxy_sqlite3_exec(db_, "PRAGMA query_only = ON", nullptr, nullptr, nullptr);
        if (rc != SQLITE_OK)
            return sqlite_error(db_, rc);
        g->query_only_set = true;
    }
    const int rc = proxy_sqlite3_set_authorizer(db_, Guard::authorize, g.get());
    if (rc != SQLITE_OK)
        return sqlite_error(db_, rc);
    g->installed = true;
    active_ = g.get();
    out = std::move(g);
    return {};
}

Status AdminSQLitePolicy::authorize_execute(const std::string& sql, const std::vector<Value>&) {
    auto& g = *active_;
    command_ = Command::unknown;
    // Resolve the current schema, including view dependencies, before refresh.
    // Bindings do not change which tables SQLite resolves during preparation.
    sqlite3_stmt* probe = nullptr;
    g.inspecting = true;
    const int prepared = proxy_sqlite3_prepare_v2(db_, sql.c_str(), static_cast<int>(sql.size()),
                                                 &probe, nullptr);
    g.inspecting = false;
    const bool write_result = probe && !proxy_sqlite3_stmt_readonly(probe) &&
                              proxy_sqlite3_column_count(probe) > 0;
    proxy_sqlite3_finalize(probe);
    if (prepared != SQLITE_OK)
        return sqlite_error(db_, prepared);
    if (!g.relations.empty()) {
        std::string refresh;
        for (const auto& relation : g.relations) {
            refresh += "SELECT * FROM ";
            refresh += relation;
            refresh += ';';
        }

        // Refresh is trusted maintenance work and writes to the statistics
        // tables before the user statement runs under its ordinary permissions.
        int rc = proxy_sqlite3_set_authorizer(db_, nullptr, nullptr);
        if (rc != SQLITE_OK)
            return sqlite_error(db_, rc);
        g.installed = false;
        if (g.query_only_set) {
            rc = proxy_sqlite3_exec(db_, "PRAGMA query_only = OFF", nullptr, nullptr, nullptr);
            if (rc != SQLITE_OK)
                return sqlite_error(db_, rc);
        }
        g.needs_vacuum = admin_.GenericRefreshStatistics(refresh.c_str(), refresh.size(), is_admin_);
        if (g.query_only_set) {
            rc = proxy_sqlite3_exec(db_, "PRAGMA query_only = ON", nullptr, nullptr, nullptr);
            if (rc != SQLITE_OK)
                return sqlite_error(db_, rc);
        }
        rc = proxy_sqlite3_set_authorizer(db_, Guard::authorize, &g);
        if (rc != SQLITE_OK)
            return sqlite_error(db_, rc);
        g.installed = true;
    }
    if (write_result) {
        if (auto error = g.run_savepoint("SAVEPOINT proxysql_prepared"))
            return error;
        g.savepoint = true;
    }
    return {};
}

}
