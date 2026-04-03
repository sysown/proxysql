/**
 * @file pgbouncer_converter_unit-t.cpp
 * @brief Unit tests for PgBouncer-to-ProxySQL config converter.
 */

#include "tap.h"
#include "PgBouncer_Config.h"
#include "PgBouncer_ConfigConverter.h"

#include <string>
#include <algorithm>

#define CHECK(cond, msg) ok((cond), "%s", (msg))
#define CHECK_INT(actual, expected, msg) \
    ok((actual) == (expected), "%s: got %d, expected %d", (msg), (actual), (expected))

// Helper: check if any SQL entry contains a substring
static bool has_sql_containing(const PgBouncer::ConversionResult& r, const std::string& substr) {
    for (const auto& e : r.entries) {
        if (e.sql.find(substr) != std::string::npos) return true;
    }
    return false;
}

// ============================================================
// Test: Minimal config conversion
// ============================================================
void test_minimal_conversion() {
    PgBouncer::Config config;
    config.global.listen_port = 6432;
    config.global.auth_type = "trust";

    PgBouncer::Database db;
    db.name = "mydb";
    db.host = "localhost";
    db.port = 5432;
    config.databases.push_back(db);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(result.success, "minimal conversion succeeds");
    CHECK_INT(result.server_count, 1, "one server");
    CHECK(has_sql_containing(result, "INSERT INTO pgsql_servers"), "has server INSERT");
    CHECK(has_sql_containing(result, "'localhost'"), "server has localhost");
    CHECK(has_sql_containing(result, "LOAD PGSQL SERVERS TO RUNTIME"), "has LOAD SERVERS");
    CHECK(has_sql_containing(result, "SAVE PGSQL SERVERS TO DISK"), "has SAVE SERVERS");
}

// ============================================================
// Test: Multi-host database creates multiple server rows
// ============================================================
void test_multi_host_conversion() {
    PgBouncer::Config config;

    PgBouncer::Database db;
    db.name = "multi";
    db.host = "db1,db2,db3";
    db.port = 5432;
    db.dbname = "shared";
    config.databases.push_back(db);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(result.success, "multi-host conversion succeeds");
    CHECK_INT(result.server_count, 3, "three servers from comma-separated host");
    CHECK(has_sql_containing(result, "'db1'"), "has db1");
    CHECK(has_sql_containing(result, "'db2'"), "has db2");
    CHECK(has_sql_containing(result, "'db3'"), "has db3");
}

// ============================================================
// Test: Wildcard database becomes default_hostgroup
// ============================================================
void test_wildcard_database() {
    PgBouncer::Config config;

    PgBouncer::Database db1;
    db1.name = "mydb";
    db1.host = "db1.example.com";
    config.databases.push_back(db1);

    PgBouncer::Database wildcard;
    wildcard.name = "*";
    wildcard.host = "default.example.com";
    config.databases.push_back(wildcard);

    PgBouncer::AuthFileEntry auth;
    auth.username = "testuser";
    auth.password = "secret";
    auth.type = PgBouncer::AuthType::PLAIN;
    config.auth_entries.push_back(auth);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(result.success, "wildcard conversion succeeds");
    // The wildcard hostgroup should be used as default_hostgroup for users
    // Wildcard is the second database, so hostgroup_id = 1
    CHECK(has_sql_containing(result, "default_hostgroup"), "users have default_hostgroup");
}

// ============================================================
// Test: User pool mode mapping
// ============================================================
void test_user_pool_mode_mapping() {
    PgBouncer::Config config;
    config.global.pool_mode = "transaction";

    PgBouncer::AuthFileEntry auth1;
    auth1.username = "session_user";
    auth1.password = "pass1";
    auth1.type = PgBouncer::AuthType::PLAIN;
    config.auth_entries.push_back(auth1);

    PgBouncer::AuthFileEntry auth2;
    auth2.username = "txn_user";
    auth2.password = "pass2";
    auth2.type = PgBouncer::AuthType::PLAIN;
    config.auth_entries.push_back(auth2);

    PgBouncer::User u1;
    u1.name = "session_user";
    u1.pool_mode = "session";
    config.users.push_back(u1);

    PgBouncer::User u2;
    u2.name = "txn_user";
    u2.pool_mode = "transaction";
    config.users.push_back(u2);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(result.success, "pool mode conversion succeeds");
    CHECK_INT(result.user_count, 2, "two users");
    // session → fast_forward=1
    CHECK(has_sql_containing(result, "fast_forward"), "session user has fast_forward");
    // transaction → transaction_persistent=1
    CHECK(has_sql_containing(result, "transaction_persistent"), "txn user has transaction_persistent");
}

// ============================================================
// Test: Global settings conversion
// ============================================================
void test_global_settings() {
    PgBouncer::Config config;
    config.global.listen_addr = "0.0.0.0";
    config.global.listen_port = 6432;
    config.global.max_client_conn = 500;
    config.global.server_connect_timeout = 30;
    config.global.query_timeout = 60;
    config.global.idle_transaction_timeout = 120;
    config.global.tcp_keepalive = true;

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(result.success, "global settings conversion succeeds");
    CHECK(has_sql_containing(result, "pgsql-interfaces"), "has interfaces variable");
    CHECK(has_sql_containing(result, "0.0.0.0:6432"), "correct interface value");
    // server_connect_timeout 30s → 30000ms
    CHECK(has_sql_containing(result, "connect_timeout_server"), "has connect_timeout_server");
}

// ============================================================
// Test: Strict mode fails on unmappable params
// ============================================================
void test_strict_mode() {
    PgBouncer::Config config;
    config.global.auth_query = "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1";
    config.global.auth_user = "pgbouncer_auth";

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, true);

    CHECK(!result.success, "strict mode fails on auth_query");
    CHECK(!result.errors.empty(), "has errors for unmappable params");

    bool found_auth_query = false;
    for (const auto& e : result.errors) {
        if (e.message.find("auth_query") != std::string::npos) found_auth_query = true;
    }
    CHECK(found_auth_query, "error mentions auth_query");
}

// ============================================================
// Test: Relaxed mode warns on unmappable params
// ============================================================
void test_relaxed_mode() {
    PgBouncer::Config config;
    config.global.auth_query = "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1";
    config.global.auth_user = "pgbouncer_auth";

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(result.success, "relaxed mode succeeds despite auth_query");
    CHECK(!result.warnings.empty(), "has warnings for unmappable params");
}

// ============================================================
// Test: Query rules created for non-wildcard databases
// ============================================================
void test_query_rules() {
    PgBouncer::Config config;

    PgBouncer::Database db1;
    db1.name = "mydb";
    db1.host = "db1.example.com";
    config.databases.push_back(db1);

    PgBouncer::Database db2;
    db2.name = "analytics";
    db2.host = "db2.example.com";
    config.databases.push_back(db2);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(result.success, "query rules conversion succeeds");
    CHECK_INT(result.rule_count, 2, "two query rules");
    CHECK(has_sql_containing(result, "pgsql_query_rules"), "has query rules INSERT");
    CHECK(has_sql_containing(result, "'mydb'"), "rule for mydb");
    CHECK(has_sql_containing(result, "'analytics'"), "rule for analytics");
}

// ============================================================
// Test: Dry-run output format
// ============================================================
void test_dry_run_format() {
    PgBouncer::Config config;
    config.global.listen_port = 6432;

    PgBouncer::Database db;
    db.name = "mydb";
    db.host = "localhost";
    config.databases.push_back(db);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    std::string output = PgBouncer::ConfigConverter::format_dry_run(
        result, "/etc/pgbouncer/pgbouncer.ini", false);

    CHECK(!output.empty(), "dry-run output is not empty");
    CHECK(output.find("PgBouncer") != std::string::npos, "output mentions PgBouncer");
    CHECK(output.find("ProxySQL") != std::string::npos, "output mentions ProxySQL");
    CHECK(output.find("INSERT INTO") != std::string::npos, "output has INSERT statements");
    CHECK(output.find("Summary") != std::string::npos, "output has summary section");
}

// ============================================================
// Test: TLS settings conversion
// ============================================================
void test_tls_conversion() {
    PgBouncer::Config config;
    config.global.server_tls_sslmode = "require";
    config.global.server_tls_ca_file = "/etc/ssl/ca.pem";
    config.global.server_tls_cert_file = "/etc/ssl/cert.pem";
    config.global.server_tls_key_file = "/etc/ssl/key.pem";

    PgBouncer::Database db;
    db.name = "mydb";
    db.host = "localhost";
    config.databases.push_back(db);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(result.success, "TLS conversion succeeds");
    CHECK(has_sql_containing(result, "ssl_p2s_ca"), "has ssl_p2s_ca");
    CHECK(has_sql_containing(result, "/etc/ssl/ca.pem"), "correct CA path");
}

int main() {
    plan(39);

    test_minimal_conversion();     // 6
    test_multi_host_conversion();  // 5
    test_wildcard_database();      // 3
    test_user_pool_mode_mapping(); // 4
    test_global_settings();        // 4
    test_strict_mode();            // 3
    test_relaxed_mode();           // 2
    test_query_rules();            // 5
    test_dry_run_format();         // 5
    test_tls_conversion();         // 3

    // Note: plan count = sum above. Adjust if needed.
    return exit_status();
}
