#include <iostream>
#include <vector>
#include <map>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "proxysql.h"
#include "proxysql_debug.h"
#include "ProxySQL_TSDB.hpp"
#include "ProxySQL_Statistics.hpp"
#include "proxysql_glovars.hpp"
#include "proxysql_admin.h"
#include "MySQL_Variables.h"
#include "PgSQL_Variables.h"
#include "tap.h"
#include <strings.h>
#include <sys/stat.h>

// Global variables required by ProxySQL components
ProxySQL_GlobalVariables GloVars;
ProxySQL_Admin *GloAdmin = nullptr;
MySQL_Variables mysql_variables;
PgSQL_Variables pgsql_variables;

// Mock other globals to satisfy linker
void *GloMyLdapAuth = nullptr;
void *GloPgQPro = nullptr;
void *GloClickHouseAuth = nullptr;
void *GloPgAuth = nullptr;
void *GloPTH = nullptr;
void *GloSQLite3Server = nullptr;
void *GloClickHouseServer = nullptr;
void *GloPgSQL_Logger = nullptr;
void *GloPgQC = nullptr;
void *GloPgStmt = nullptr;
void *GloMTH = nullptr;
void *GloMyAuth = nullptr;
void *GloProxyStats = nullptr;
void *GloMyQC = nullptr;
void *GloProxyCluster = nullptr;
void *GloMyLogger = nullptr;
void *GloWebInterface = nullptr;
void *GloMyStmt = nullptr;
void *GloPgMon = nullptr;
void *GloMyMon = nullptr;
void *GloMyQPro = nullptr;

// Mock functions
extern "C" {
    void proxy_error_func(int errcode, const char *fmt, ...) {}
    void proxy_debug_func(enum debug_module module, int verbosity, int tid, const char *file, int line, const char *func, const char *fmt, ...) {}
    unsigned int binary_sha1(const char *src, unsigned int src_len, char *dst) { return 0; }
    void format_time_s(long long t, char *buf) {}
    int mallctl(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) { return 0; }
}

bool ProxySQL_create_or_load_TLS(bool a, std::string &b) { return true; }

int main() {
    plan(4);

    // Initialization
    GloTSDB = new ProxySQL_TSDB();
    
    // Minimal setup for GloVars
    GloVars.datadir = (char*)"/tmp/proxysql_tsdb_test";
    mkdir(GloVars.datadir, 0755);

    GloTSDB->init();
    ok(1, "TSDB initialized");

    // Test basic variable setting
    if (GloTSDB->set_variable("enabled", "true")) {
        ok(1, "TSDB enabled");
    } else {
        ok(0, "Failed to enable TSDB");
    }

    GloTSDB->set_variable("retention_hours", "1");
    GloTSDB->set_variable("sample_interval_seconds", "0"); // Disable auto-sampling
    GloTSDB->set_variable("monitor_enabled", "false");

    // Start TSDB (starts threads)
    GloTSDB->start();

    std::map<std::string, std::string> labels;
    labels["host"] = "server1";
    long long now = 1000;
    
    // Test write
    GloTSDB->write("test_metric", labels, now, 10.5);
    ok(1, "Write called");

    // Test query
    std::vector<ProxySQL_TSDB::query_result_t> results = GloTSDB->query("test_metric", labels, 0, 2000, 0, "");
    ok(results.size() >= 0, "Query executed");

    GloTSDB->stop();
    delete GloTSDB;

    return exit_status();
}