/**
 * @file pgbouncer_config_parser_unit-t.cpp
 * @brief Unit tests for PgBouncer configuration file parser.
 *
 * Tests the parser library in isolation — no ProxySQL dependencies.
 * Covers: INI parsing, auth file parsing, HBA parsing, %include, edge cases.
 */

#include "tap.h"
#include "PgBouncer_Config.h"

// Test helpers
#define CHECK(cond, msg) ok((cond), "%s", (msg))
#define CHECK_STR(actual, expected, msg) \
    ok((actual) == (expected), "%s: got '%s', expected '%s'", (msg), (actual).c_str(), (expected))
#define CHECK_INT(actual, expected, msg) \
    ok((actual) == (expected), "%s: got %d, expected %d", (msg), (actual), (expected))

// ============================================================
// Test: Minimal config parsing
// ============================================================
void test_minimal_config() {
    PgBouncer::Config config;
    bool ok_result = PgBouncer::parse_config_file(
        "fixtures/pgbouncer_compat/minimal.ini", config);

    CHECK(ok_result, "minimal config parses successfully");
    CHECK(config.errors.empty(), "minimal config has no errors");
    CHECK_INT(config.global.listen_port, 6432, "listen_port");
    CHECK_STR(config.global.auth_type, "trust", "auth_type");
    CHECK_INT((int)config.databases.size(), 1, "one database entry");
    CHECK_STR(config.databases[0].name, "mydb", "database name");
    CHECK_STR(config.databases[0].host, "localhost", "database host");
    CHECK_INT(config.databases[0].port, 5432, "database port (default)");
}

// ============================================================
// Test: Full config parsing
// ============================================================
void test_full_config() {
    PgBouncer::Config config;
    bool ok_result = PgBouncer::parse_config_file(
        "fixtures/pgbouncer_compat/full.ini", config);

    CHECK(ok_result, "full config parses successfully");

    // Global settings
    CHECK_STR(config.global.listen_addr, "0.0.0.0", "listen_addr");
    CHECK_INT(config.global.listen_port, 6432, "listen_port");
    CHECK_STR(config.global.unix_socket_dir, "/var/run/postgresql", "unix_socket_dir");
    CHECK_STR(config.global.auth_type, "md5", "auth_type");
    CHECK_STR(config.global.pool_mode, "transaction", "pool_mode");
    CHECK_INT(config.global.default_pool_size, 25, "default_pool_size");
    CHECK_INT(config.global.min_pool_size, 5, "min_pool_size");
    CHECK_INT(config.global.reserve_pool_size, 5, "reserve_pool_size");
    CHECK_INT(config.global.max_client_conn, 1000, "max_client_conn");
    CHECK_INT(config.global.max_db_connections, 100, "max_db_connections");
    CHECK_INT(config.global.max_user_connections, 50, "max_user_connections");
    CHECK_INT(config.global.server_lifetime, 3600, "server_lifetime");
    CHECK_INT(config.global.server_idle_timeout, 600, "server_idle_timeout");
    CHECK_INT(config.global.server_connect_timeout, 15, "server_connect_timeout");
    CHECK_INT(config.global.query_timeout, 30, "query_timeout");
    CHECK_INT(config.global.idle_transaction_timeout, 10, "idle_transaction_timeout");
    CHECK_INT(config.global.client_idle_timeout, 300, "client_idle_timeout");
    CHECK_STR(config.global.server_tls_sslmode, "require", "server_tls_sslmode");
    CHECK_STR(config.global.server_tls_ca_file, "/etc/ssl/certs/ca.pem", "server_tls_ca_file");
    CHECK(config.global.log_connections, "log_connections");
    CHECK(config.global.log_disconnections, "log_disconnections");
    CHECK_INT(config.global.verbose, 2, "verbose");
    CHECK_INT(config.global.stats_period, 30, "stats_period");
    CHECK_STR(config.global.admin_users, "admin", "admin_users");
    CHECK(config.global.tcp_keepalive, "tcp_keepalive");
    CHECK_INT(config.global.tcp_keepidle, 60, "tcp_keepidle");
    CHECK_INT(config.global.max_prepared_statements, 100, "max_prepared_statements");

    // Databases
    CHECK_INT((int)config.databases.size(), 5, "five database entries");

    // prod database
    bool found_prod = false;
    for (const auto& db : config.databases) {
        if (db.name == "prod") {
            found_prod = true;
            CHECK_STR(db.host, "db1.example.com", "prod host");
            CHECK_INT(db.port, 5432, "prod port");
            CHECK_STR(db.dbname, "production", "prod dbname");
            CHECK_INT(db.pool_size, 20, "prod pool_size");
            CHECK_STR(db.pool_mode, "session", "prod pool_mode");
        }
    }
    CHECK(found_prod, "prod database found");

    // multi-host database
    bool found_multi = false;
    for (const auto& db : config.databases) {
        if (db.name == "multi") {
            found_multi = true;
            CHECK_STR(db.host, "db1,db2,db3", "multi host (comma-separated)");
            CHECK_STR(db.dbname, "shared", "multi dbname");
            CHECK_STR(db.load_balance_hosts, "round-robin", "multi load_balance_hosts");
        }
    }
    CHECK(found_multi, "multi database found");

    // wildcard database
    bool found_wildcard = false;
    for (const auto& db : config.databases) {
        if (db.name == "*") {
            found_wildcard = true;
            CHECK_STR(db.host, "default.example.com", "wildcard host");
        }
    }
    CHECK(found_wildcard, "wildcard database found");

    // connect_query with single-quoted value
    bool found_withquery = false;
    for (const auto& db : config.databases) {
        if (db.name == "withquery") {
            found_withquery = true;
            CHECK_STR(db.connect_query, "SET statement_timeout = 5000", "connect_query value");
        }
    }
    CHECK(found_withquery, "withquery database found");

    // Users
    CHECK_INT((int)config.users.size(), 3, "three user entries");

    bool found_appuser = false;
    for (const auto& u : config.users) {
        if (u.name == "appuser") {
            found_appuser = true;
            CHECK_STR(u.pool_mode, "transaction", "appuser pool_mode");
            CHECK_INT(u.pool_size, 10, "appuser pool_size");
            CHECK_INT(u.max_user_connections, 50, "appuser max_user_connections");
        }
    }
    CHECK(found_appuser, "appuser found");

    bool found_readonly = false;
    for (const auto& u : config.users) {
        if (u.name == "readonly") {
            found_readonly = true;
            CHECK_INT(u.query_timeout, 60, "readonly query_timeout");
            CHECK_INT(u.idle_transaction_timeout, 30, "readonly idle_transaction_timeout");
        }
    }
    CHECK(found_readonly, "readonly user found");

    // Peers
    CHECK_INT((int)config.peers.size(), 2, "two peer entries");

    bool found_peer2 = false;
    for (const auto& p : config.peers) {
        if (p.peer_id == 2) {
            found_peer2 = true;
            CHECK_STR(p.host, "pgbouncer2.example.com", "peer 2 host");
            CHECK_INT(p.port, 6433, "peer 2 port");
            CHECK_INT(p.pool_size, 3, "peer 2 pool_size");
        }
    }
    CHECK(found_peer2, "peer 2 found");

    // Auth file entries (resolved from auth_file)
    CHECK_INT((int)config.auth_entries.size(), 4, "four auth entries");

    bool found_auth_plain = false;
    bool found_auth_md5 = false;
    bool found_auth_scram = false;
    for (const auto& a : config.auth_entries) {
        if (a.username == "appuser") {
            found_auth_plain = true;
            CHECK(a.type == PgBouncer::AuthType::PLAIN, "appuser is PLAIN auth");
            CHECK_STR(a.password, "secretpassword", "appuser password");
        }
        if (a.username == "admin") {
            found_auth_md5 = true;
            CHECK(a.type == PgBouncer::AuthType::MD5, "admin is MD5 auth");
        }
        if (a.username == "scramuser") {
            found_auth_scram = true;
            CHECK(a.type == PgBouncer::AuthType::SCRAM, "scramuser is SCRAM auth");
        }
    }
    CHECK(found_auth_plain, "plain auth entry found");
    CHECK(found_auth_md5, "md5 auth entry found");
    CHECK(found_auth_scram, "scram auth entry found");
}

// ============================================================
// Test: Auth file parsing standalone
// ============================================================
void test_auth_file() {
    std::vector<PgBouncer::AuthFileEntry> entries;
    std::vector<PgBouncer::ParseMessage> errors;
    bool ok_result = PgBouncer::parse_auth_file(
        "fixtures/pgbouncer_compat/userlist.txt", entries, errors);

    CHECK(ok_result, "auth file parses successfully");
    CHECK_INT((int)entries.size(), 4, "four entries in auth file");

    // Plain password
    CHECK_STR(entries[0].username, "appuser", "entry 0 username");
    CHECK_STR(entries[0].password, "secretpassword", "entry 0 password");
    CHECK(entries[0].type == PgBouncer::AuthType::PLAIN, "entry 0 is PLAIN");

    // MD5 password
    CHECK_STR(entries[1].username, "admin", "entry 1 username");
    CHECK(entries[1].type == PgBouncer::AuthType::MD5, "entry 1 is MD5");

    // SCRAM password
    CHECK_STR(entries[2].username, "scramuser", "entry 2 username");
    CHECK(entries[2].type == PgBouncer::AuthType::SCRAM, "entry 2 is SCRAM");

    // Quoted username with escaped quotes
    CHECK_STR(entries[3].username, "quoted\"user", "entry 3 username with escaped quote");
    CHECK_STR(entries[3].password, "pass\"word", "entry 3 password with escaped quote");
}

// ============================================================
// Test: HBA file parsing
// ============================================================
void test_hba_file() {
    std::vector<PgBouncer::HBARule> rules;
    std::vector<PgBouncer::ParseMessage> errors;
    bool ok_result = PgBouncer::parse_hba_file(
        "fixtures/pgbouncer_compat/pg_hba.conf", rules, errors);

    CHECK(ok_result, "hba file parses successfully");
    CHECK(errors.empty(), "hba file has no errors");
    CHECK_INT((int)rules.size(), 5, "five HBA rules");

    // local rule
    CHECK_STR(rules[0].conn_type, "local", "rule 0 type");
    CHECK_STR(rules[0].database, "all", "rule 0 database");
    CHECK_STR(rules[0].user, "all", "rule 0 user");
    CHECK_STR(rules[0].method, "peer", "rule 0 method");

    // host with IPv4
    CHECK_STR(rules[1].conn_type, "host", "rule 1 type");
    CHECK_STR(rules[1].address, "127.0.0.1/32", "rule 1 address");
    CHECK_STR(rules[1].method, "md5", "rule 1 method");

    // host with IPv6
    CHECK_STR(rules[2].conn_type, "host", "rule 2 type");
    CHECK_STR(rules[2].address, "::1/128", "rule 2 address");
    CHECK_STR(rules[2].method, "scram-sha-256", "rule 2 method");

    // hostssl with options
    CHECK_STR(rules[3].conn_type, "hostssl", "rule 3 type");
    CHECK_STR(rules[3].database, "mydb", "rule 3 database");
    CHECK_STR(rules[3].user, "admin", "rule 3 user");
    CHECK_STR(rules[3].address, "10.0.0.0/8", "rule 3 address");
    CHECK_STR(rules[3].method, "cert", "rule 3 method");
    CHECK(rules[3].options.count("map") > 0, "rule 3 has map option");
    CHECK_STR(rules[3].options.at("map"), "mymap", "rule 3 map=mymap");

    // hostnossl reject
    CHECK_STR(rules[4].conn_type, "hostnossl", "rule 4 type");
    CHECK_STR(rules[4].method, "reject", "rule 4 method");
}

// ============================================================
// Test: Malformed config (strict parsing)
// ============================================================
void test_malformed_config() {
    PgBouncer::Config config;
    bool ok_result = PgBouncer::parse_config_file(
        "fixtures/pgbouncer_compat/malformed.ini", config);

    CHECK(!ok_result, "malformed config fails to parse");
    CHECK(!config.errors.empty(), "malformed config has errors");

    // Should have errors for unknown_param and bogus_section
    bool found_unknown_param = false;
    bool found_unknown_section = false;
    for (const auto& err : config.errors) {
        if (err.message.find("unknown_param") != std::string::npos ||
            err.message.find("Unknown") != std::string::npos) {
            found_unknown_param = true;
        }
        if (err.message.find("bogus_section") != std::string::npos ||
            err.message.find("unknown section") != std::string::npos ||
            err.message.find("Unknown section") != std::string::npos) {
            found_unknown_section = true;
        }
    }
    CHECK(found_unknown_param || found_unknown_section,
          "errors mention unknown parameter or section");
}

// ============================================================
// Test: %include directive
// ============================================================
void test_include_directive() {
    PgBouncer::Config config;
    bool ok_result = PgBouncer::parse_config_file(
        "fixtures/pgbouncer_compat/include_main.ini", config);

    CHECK(ok_result, "include config parses successfully");
    CHECK_INT(config.global.listen_port, 6432, "listen_port from main");
    CHECK_STR(config.global.auth_type, "md5", "auth_type from main");
    CHECK_INT((int)config.databases.size(), 1, "one database from included file");
    if (!config.databases.empty()) {
        CHECK_STR(config.databases[0].name, "included_db", "included database name");
        CHECK_STR(config.databases[0].host, "included.example.com", "included database host");
        CHECK_INT(config.databases[0].port, 5433, "included database port");
    } else {
        ok(0, "included database name - SKIPPED (no databases)");
        ok(0, "included database host - SKIPPED (no databases)");
        ok(0, "included database port - SKIPPED (no databases)");
    }
}

// ============================================================
// Test: Nonexistent file
// ============================================================
void test_nonexistent_file() {
    PgBouncer::Config config;
    bool ok_result = PgBouncer::parse_config_file(
        "fixtures/pgbouncer_compat/does_not_exist.ini", config);

    CHECK(!ok_result, "nonexistent file returns false");
    CHECK(!config.errors.empty(), "nonexistent file produces errors");
}

// ============================================================
// Test: Default values
// ============================================================
void test_defaults() {
    PgBouncer::Config config;
    bool ok_result = PgBouncer::parse_config_file(
        "fixtures/pgbouncer_compat/minimal.ini", config);

    CHECK(ok_result, "minimal config parses for defaults test");

    // Verify defaults that were NOT explicitly set in minimal.ini
    CHECK_STR(config.global.pool_mode, "session", "default pool_mode is session");
    CHECK_INT(config.global.default_pool_size, 20, "default pool_size is 20");
    CHECK_INT(config.global.max_client_conn, 100, "default max_client_conn is 100");
    CHECK_INT(config.global.server_lifetime, 3600, "default server_lifetime is 3600");
    CHECK_INT(config.global.server_idle_timeout, 600, "default server_idle_timeout is 600");
    CHECK_STR(config.global.server_reset_query, "DISCARD ALL", "default server_reset_query");
    CHECK(!config.global.syslog, "default syslog is false");
    CHECK(config.global.tcp_keepalive, "default tcp_keepalive is true");
    CHECK_INT(config.global.max_prepared_statements, 200, "default max_prepared_statements is 200");
}

// ============================================================
// Main
// ============================================================
int main() {
    plan(127);

    test_minimal_config();        // 7 tests
    test_full_config();           // 42 tests
    test_auth_file();             // 11 tests
    test_hba_file();              // 19 tests
    test_malformed_config();      // 3 tests
    test_include_directive();     // 7 tests
    test_nonexistent_file();      // 2 tests
    test_defaults();              // 9 tests (adjusted: removed 1 duplicate)

    return exit_status();
}
