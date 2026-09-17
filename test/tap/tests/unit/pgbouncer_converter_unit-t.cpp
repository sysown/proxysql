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
    auth.password = "secret"; // NOSONAR(cpp:S2068): synthetic fixture value; the converter is exercised entirely in memory.
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
    auth1.password = "pass1"; // NOSONAR(cpp:S2068): synthetic fixture value.
    auth1.type = PgBouncer::AuthType::PLAIN;
    config.auth_entries.push_back(auth1);

    PgBouncer::AuthFileEntry auth2;
    auth2.username = "txn_user";
    auth2.password = "pass2"; // NOSONAR(cpp:S2068): synthetic fixture value.
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


// Helper: does any warning or error mention this substring?
static bool has_issue_containing(const PgBouncer::ConversionResult& r,
                                 const std::string& substr) {
    for (const auto& w : r.warnings)
        if (w.message.find(substr) != std::string::npos) return true;
    for (const auto& e : r.errors)
        if (e.message.find(substr) != std::string::npos) return true;
    return false;
}

// ============================================================
// Test: generated SQL uses the real pgsql_* column names
//
// Regression: routing rules were emitted as
//   INSERT INTO pgsql_query_rules (..., schemaname, ...)
// but pgsql_query_rules has no `schemaname` column (that is the MySQL table);
// the PgSQL one calls it `database`. Every generated rule failed on execute.
// ============================================================
void test_query_rule_column_names() {
    PgBouncer::Config config;
    PgBouncer::Database db;
    db.name = "mydb";
    db.host = "10.0.0.1";
    config.databases.push_back(db);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(!has_sql_containing(result, "schemaname"),
          "query rules do not reference the nonexistent `schemaname` column");
    CHECK(has_sql_containing(result, "(rule_id, active, database, destination_hostgroup, apply)"),
          "query rules use the `database` column");
}

// ============================================================
// Test: firewall whitelist INSERT satisfies the table's NOT NULL columns
//
// pgsql_firewall_whitelist_rules declares `digest` and `comment` NOT NULL with
// no default, and names the database column `database`.
// ============================================================
void test_firewall_rule_columns() {
    PgBouncer::Config config;
    PgBouncer::Database db;
    db.name = "mydb";
    db.host = "10.0.0.1";
    config.databases.push_back(db);

    PgBouncer::HBARule rule;
    rule.conn_type = "host";
    rule.database = "all";
    rule.user = "all";
    rule.address = "10.0.0.0/8";
    rule.method = "md5";
    config.hba_rules.push_back(rule);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(has_sql_containing(result,
            "(active, client_address, username, database, flagIN, digest, comment)"),
          "firewall INSERT lists database, digest and comment");
    CHECK(!has_sql_containing(result, "pgsql_firewall_whitelist_rules (active, client_address, username, schemaname"),
          "firewall INSERT does not use `schemaname`");
}

// ============================================================
// Test: HBA reject rules are reported, not silently swallowed
//
// The ProxySQL whitelist is allow-only, so a `reject` cannot be reproduced.
// It used to be emitted as an SQL comment and still flipped the whitelist on.
// ============================================================
void test_hba_reject_is_reported() {
    PgBouncer::Config config;
    PgBouncer::Database db;
    db.name = "mydb";
    db.host = "10.0.0.1";
    config.databases.push_back(db);

    PgBouncer::HBARule rule;
    rule.conn_type = "host";
    rule.database = "all";
    rule.user = "baduser";
    rule.address = "192.168.0.0/16";
    rule.method = "reject";
    config.hba_rules.push_back(rule);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult relaxed = converter.convert(config, false);
    CHECK(has_issue_containing(relaxed, "reject"),
          "reject rule raises an issue in relaxed mode");

    PgBouncer::ConfigConverter strict_conv;
    PgBouncer::ConversionResult strict = strict_conv.convert(config, true);
    CHECK(!strict.success, "reject rule fails the import in strict mode");
}

// ============================================================
// Tests: hashed userlist.txt credentials (#6134)
//
// pgsql_users.password holds cleartext, an md5 hash or a SCRAM-SHA-256
// verifier, so every userlist.txt form is imported as-is. What is reported
// are the combinations that cannot authenticate.
// ============================================================

// md5("alicesecret" + "alice"), stored with uppercase hex.
static const char* ALICE_MD5_UPPER = "md5902BCC6DCAF8611722A6846FE97204EC"; // NOSONAR(cpp:S2068): synthetic md5 hash of a fixture password.
static const char* ALICE_MD5_LOWER = "md5902bcc6dcaf8611722a6846fe97204ec"; // NOSONAR(cpp:S2068): synthetic md5 hash of a fixture password.
// A well-formed verifier for "bobsecret" (4096 iterations, 16-byte salt).
static const char* BOB_SCRAM =
    "SCRAM-SHA-256$4096:MDEyMzQ1Njc4OWFiY2RlZg==$"
    "cdWal4MCQ0HGW7A3x3U+vsJWZ7JtgZGTWehOdEhE4MQ=:"
    "jb79Cqvy9CgOXvdQAp3Ct/A/6kJfqdxvNcBrTeduXUY="; // NOSONAR(cpp:S2068): synthetic verifier of a fixture password.

static bool has_note_containing(const PgBouncer::ConversionResult& r,
                                const std::string& substr) {
    for (const auto& n : r.notes)
        if (n.message.find(substr) != std::string::npos) return true;
    return false;
}

static PgBouncer::Config config_with_credentials(const char* auth_type,
                                                 const char* alice_pw,
                                                 const char* bob_pw) {
    PgBouncer::Config config;
    config.global.auth_type = auth_type;
    PgBouncer::Database db;
    db.name = "mydb";
    db.host = "10.0.0.1";
    config.databases.push_back(db);

    PgBouncer::AuthFileEntry md5e;
    md5e.username = "alice";
    md5e.password = alice_pw;
    md5e.type = PgBouncer::AuthType::MD5;
    config.auth_entries.push_back(md5e);

    PgBouncer::AuthFileEntry scram;
    scram.username = "bob";
    scram.password = bob_pw;
    scram.type = PgBouncer::AuthType::SCRAM;
    config.auth_entries.push_back(scram);

    PgBouncer::AuthFileEntry plain;
    plain.username = "carol";
    plain.password = "secret"; // NOSONAR(cpp:S2068): synthetic fixture value.
    plain.type = PgBouncer::AuthType::PLAIN;
    config.auth_entries.push_back(plain);

    return config;
}

void test_hashed_passwords_are_imported() {
    PgBouncer::Config config = config_with_credentials("md5", ALICE_MD5_LOWER, BOB_SCRAM);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult r = converter.convert(config, true);

    CHECK(r.success, "hashed passwords import in strict mode under auth_type=md5");
    CHECK(!has_issue_containing(r, "alice"), "md5 hash for alice is not reported as an issue");
    CHECK(!has_issue_containing(r, "bob"), "SCRAM verifier for bob is not reported as an issue");
    CHECK(has_sql_containing(r, std::string("'alice', '") + ALICE_MD5_LOWER + "'"),
          "md5 hash for alice is imported verbatim");
    CHECK(has_sql_containing(r, std::string("'bob', '") + BOB_SCRAM + "'"),
          "SCRAM verifier for bob is imported verbatim");
    CHECK(has_sql_containing(r, "'carol', 'secret'"), "cleartext password for carol is imported");
    CHECK_INT(r.user_count, 3, "all three users are imported");

    CHECK(has_note_containing(r, "'alice'") && has_note_containing(r, "md5 method"),
          "backend md5 constraint is noted for alice");
    CHECK(has_note_containing(r, "'bob'") && has_note_containing(r, "byte-identical"),
          "backend SCRAM verifier constraint is noted for bob");
    CHECK(!has_note_containing(r, "carol"), "no note for the cleartext user");

    std::string output = PgBouncer::ConfigConverter::format_dry_run(r, "pgbouncer.ini", true);
    CHECK(output.find("-- NOTE: ") != std::string::npos, "dry-run output lists the notes");
}

void test_md5_hash_is_lowercased() {
    PgBouncer::Config config = config_with_credentials("md5", ALICE_MD5_UPPER, BOB_SCRAM);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult r = converter.convert(config, true);

    CHECK(has_sql_containing(r, std::string("'alice', '") + ALICE_MD5_LOWER + "'"),
          "uppercase md5 hex is imported lowercased, the only form ProxySQL recognises");
    CHECK(!has_sql_containing(r, ALICE_MD5_UPPER + 3), "uppercase md5 hex is not imported");
}

void test_md5_under_scram_method_is_reported() {
    PgBouncer::Config config = config_with_credentials("scram-sha-256", ALICE_MD5_LOWER, BOB_SCRAM);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult r = converter.convert(config, false);
    CHECK(has_issue_containing(r, "'alice'") && has_issue_containing(r, "pgsql-authentication_method=3"),
          "md5 hash under auth_type=scram-sha-256 is reported");
    CHECK(!has_issue_containing(r, "'bob'"), "SCRAM verifier under auth_type=scram-sha-256 is not reported");

    PgBouncer::ConfigConverter strict_conv;
    PgBouncer::ConversionResult strict = strict_conv.convert(config, true);
    CHECK(!strict.success, "md5 hash under auth_type=scram-sha-256 fails the import in strict mode");

    // Cleartext frontend authentication accepts an md5-stored user.
    PgBouncer::ConfigConverter plain_conv;
    PgBouncer::ConversionResult plain = plain_conv.convert(
        config_with_credentials("plain", ALICE_MD5_LOWER, BOB_SCRAM), true);
    CHECK(plain.success, "md5 hash under auth_type=plain imports in strict mode");
}

void test_md5_without_mapped_method_is_noted() {
    PgBouncer::Config config = config_with_credentials("trust", ALICE_MD5_LOWER, BOB_SCRAM);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult r = converter.convert(config, false);
    CHECK(has_note_containing(r, "pgsql-authentication_method 1 or 2"),
          "md5 hash with no mapped authentication method is noted");
}

void test_malformed_scram_verifier_is_reported() {
    const char* malformed[] = {
        // keys that do not decode to 32 bytes
        "SCRAM-SHA-256$4096:c2FsdA==$c3Ry:c3Ry",
        // non-numeric iteration count
        "SCRAM-SHA-256$many:MDEyMzQ1Njc4OWFiY2RlZg==$cdWal4MCQ0HGW7A3x3U+vsJWZ7JtgZGTWehOdEhE4MQ=:jb79Cqvy9CgOXvdQAp3Ct/A/6kJfqdxvNcBrTeduXUY=",
        // missing keys
        "SCRAM-SHA-256$4096:MDEyMzQ1Njc4OWFiY2RlZg==",
        // invalid base64 in the salt
        "SCRAM-SHA-256$4096:not*base64$cdWal4MCQ0HGW7A3x3U+vsJWZ7JtgZGTWehOdEhE4MQ=:jb79Cqvy9CgOXvdQAp3Ct/A/6kJfqdxvNcBrTeduXUY=",
    }; // NOSONAR(cpp:S2068): deliberately malformed synthetic verifiers.

    for (const char* v : malformed) {
        PgBouncer::Config config = config_with_credentials("md5", ALICE_MD5_LOWER, v);

        PgBouncer::ConfigConverter converter;
        PgBouncer::ConversionResult r = converter.convert(config, false);
        std::string msg = std::string("malformed verifier is reported: ") + v;
        CHECK(has_issue_containing(r, "'bob'") && has_issue_containing(r, "malformed"), msg.c_str());

        PgBouncer::ConfigConverter strict_conv;
        PgBouncer::ConversionResult strict = strict_conv.convert(config, true);
        std::string smsg = std::string("malformed verifier fails the import in strict mode: ") + v;
        CHECK(!strict.success, smsg.c_str());
    }
}

// ============================================================
// Test: a dbname alias is reported rather than silently dropped
//
// PgBouncer's `dbname=` connects to a differently-named backend database.
// ProxySQL routes to a hostgroup but does not rewrite the startup packet.
// ============================================================
void test_dbname_alias_is_reported() {
    PgBouncer::Config config;
    PgBouncer::Database db;
    db.name = "alias";
    db.dbname = "real_backend_db";
    db.host = "10.0.0.1";
    config.databases.push_back(db);

    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, false);

    CHECK(has_issue_containing(result, "real_backend_db"),
          "dbname alias is reported");

    PgBouncer::ConfigConverter strict_conv;
    PgBouncer::ConversionResult strict = strict_conv.convert(config, true);
    CHECK(!strict.success, "dbname alias fails the import in strict mode");
}


// ============================================================
// Test: auth_type is mapped, not silently dropped
//
// Regression: auth_type was parsed into the Config and then ignored by the
// converter entirely -- neither mapped nor reported. The frontend
// authentication method of the pooler being replaced simply vanished, which
// under the converter's strict-by-default contract should never happen.
// ============================================================
static PgBouncer::Config config_with_auth_type(const char* auth_type) {
    PgBouncer::Config config;
    PgBouncer::Database db;
    db.name = "mydb";
    db.host = "10.0.0.1";
    config.databases.push_back(db);
    config.global.auth_type = auth_type;
    return config;
}

void test_auth_type_mapping() {
    // Match the whole emitted statement, so a wrong level fails the assertion
    // rather than passing on an incidental substring.
    struct { const char* auth_type; const char* expect_sql; } mapped[] = {
        { "plain",         "SET pgsql-authentication_method=1;" },
        { "password",      "SET pgsql-authentication_method=1;" },
        { "md5",           "SET pgsql-authentication_method=2;" },
        { "scram-sha-256", "SET pgsql-authentication_method=3;" },
    };
    for (const auto& m : mapped) {
        PgBouncer::Config config = config_with_auth_type(m.auth_type);
        PgBouncer::ConfigConverter conv;
        PgBouncer::ConversionResult r = conv.convert(config, false);
        std::string msg = std::string("auth_type=") + m.auth_type + " emits " + m.expect_sql;
        CHECK(has_sql_containing(r, m.expect_sql), msg.c_str());
    }

    // A mapped auth_type must not also be reported as a problem.
    {
        PgBouncer::ConfigConverter conv;
        PgBouncer::ConversionResult r = conv.convert(config_with_auth_type("md5"), true);
        CHECK(r.success, "a mappable auth_type does not fail strict mode");
    }

    // Case-insensitive, matching the rest of the INI handling.
    {
        PgBouncer::ConfigConverter conv;
        PgBouncer::ConversionResult r = conv.convert(config_with_auth_type("MD5"), false);
        CHECK(has_sql_containing(r, "pgsql-authentication_method"),
              "auth_type matching is case-insensitive");
    }

    // The methods ProxySQL cannot express are reported, not dropped.
    for (const char* unmappable : { "trust", "hba", "any", "cert", "pam" }) {
        PgBouncer::ConfigConverter conv;
        PgBouncer::ConversionResult r = conv.convert(config_with_auth_type(unmappable), false);
        std::string msg = std::string("auth_type=") + unmappable + " is reported as unmappable";
        CHECK(has_issue_containing(r, unmappable), msg.c_str());

        PgBouncer::ConfigConverter sconv;
        PgBouncer::ConversionResult sr = sconv.convert(config_with_auth_type(unmappable), true);
        std::string smsg = std::string("auth_type=") + unmappable + " fails the import in strict mode";
        CHECK(!sr.success, smsg.c_str());
    }
}

int main() {
    plan(89);

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
    test_query_rule_column_names();
    test_firewall_rule_columns();
    test_hba_reject_is_reported();
    test_hashed_passwords_are_imported();
    test_md5_hash_is_lowercased();
    test_md5_under_scram_method_is_reported();
    test_md5_without_mapped_method_is_noted();
    test_malformed_scram_verifier_is_reported();
    test_dbname_alias_is_reported();
    test_auth_type_mapping();

    return exit_status();
}
