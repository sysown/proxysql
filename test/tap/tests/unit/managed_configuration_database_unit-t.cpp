#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_admin.h"
#include "ProxySQL_Statistics.hpp"
#include "ProxySQL_ConfigurationAccess.h"
#include "ProxySQL_PluginSecrets.h"
#include "sqlite3db.h"

#include <atomic>
#include <chrono>
#include <future>
#include <string>
#include <thread>
#include <unistd.h>

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;

static int scalar(SQLite3DB& db, const char* sql) {
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db.get_db(), sql, -1, &statement, nullptr) != SQLITE_OK) return -1;
    const int result = sqlite3_step(statement) == SQLITE_ROW ? sqlite3_column_int(statement, 0) : -1;
    sqlite3_finalize(statement);
    return result;
}

static std::string journal_mode(SQLite3DB& db) {
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db.get_db(), "PRAGMA journal_mode", -1, &statement, nullptr) != SQLITE_OK) return "error";
    const std::string result = sqlite3_step(statement) == SQLITE_ROW ?
        reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)) : "error";
    sqlite3_finalize(statement);
    return result;
}

static int deny_secret_insert(void*, int action, const char* table, const char*, const char*, const char*) {
    return action == SQLITE_INSERT && table && std::string(table) == "proxysql_plugin_secrets" ? SQLITE_DENY : SQLITE_OK;
}

int main() {
    plan(25);
    test_init_minimal();
    char directory[] = "/tmp/proxysql-managed-database.XXXXXX";
    if (!mkdtemp(directory)) return 1;
    const std::string path = std::string(directory) + "/proxysql.db";
    char* old_path = GloVars.admindb;
    char* old_stats_path = GloVars.statsdb_disk;
    GloVars.admindb = strdup(path.c_str());
    GloVars.statsdb_disk = const_cast<char*>(":memory:");
    // Real process-scoped Admin, matching the existing publisher unit fixture.
    // Its normal destructor requires the full daemon lifecycle.
    GloProxyStats = new ProxySQL_Statistics();
    GloAdmin = new ProxySQL_Admin();
    GloAdmin->admindb = new SQLite3DB();
    GloAdmin->admindb->open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
    GloAdmin->configdb = new SQLite3DB();
    GloAdmin->configdb->open(const_cast<char*>(path.c_str()), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
    GloAdmin->admindb->execute(("ATTACH DATABASE '" + path + "' AS disk").c_str());

    proxysql_lock_configuration();
    SQLite3DB* db = proxysql_configdb_locked();
    ok(db == GloAdmin->configdb, "borrow returns the current configdb handle under the Admin SQL mutex");
    const int synchronous = scalar(*db, "PRAGMA synchronous");
    const int foreign_keys = scalar(*db, "PRAGMA foreign_keys");
    const std::string journal = journal_mode(*db);
    ProxySQL_PluginSecrets store(db, directory);
    const uint8_t secret[] = {'t', 'e', 's', 't'};
    db->execute("CREATE TABLE managed_test_reference (name TEXT PRIMARY KEY)");
    db->execute(proxysql_plugin_secrets_table_definition());
    ok(store.put_locked("aws", "a", secret, sizeof(secret), SecretTransactionMode::existing_transaction) == ProxySQL_PluginSecretResult::storage_error,
       "existing-transaction secret write requires an active caller transaction");
    db->execute("BEGIN IMMEDIATE");
    ok(store.put_locked("aws", "a", secret, sizeof(secret), SecretTransactionMode::existing_transaction) == ProxySQL_PluginSecretResult::ok,
       "locked secret write composes with the caller transaction without recursive mutex or BEGIN");
    db->execute("INSERT INTO managed_test_reference VALUES ('a')");
    ok(sqlite3_get_autocommit(db->get_db()) == 0, "locked secret write leaves the caller transaction open");
    std::vector<uint8_t> value;
    ok(store.get_locked("aws", "a", value) == ProxySQL_PluginSecretResult::ok && value == std::vector<uint8_t>(secret, secret + sizeof(secret)),
       "locked secret read sees the caller's uncommitted value");
    db->execute("ROLLBACK");
    ok(store.get_locked("aws", "a", value) == ProxySQL_PluginSecretResult::not_found &&
       scalar(*db, "SELECT count(*) FROM managed_test_reference") == 0,
       "secret and reference roll back together");
    ok(store.put("aws", "a", secret, sizeof(secret)) == ProxySQL_PluginSecretResult::ok &&
       sqlite3_get_autocommit(db->get_db()) != 0, "existing secret callers retain owned-transaction behavior");
    db->execute("BEGIN IMMEDIATE");
    ok(store.erase_locked("aws", "a", SecretTransactionMode::existing_transaction) == ProxySQL_PluginSecretResult::ok,
       "locked secret erase uses the caller transaction");
    db->execute("ROLLBACK");
    ok(store.get("aws", "a", value) == ProxySQL_PluginSecretResult::ok, "rolled-back erase retains encrypted secret");
    db->execute("BEGIN IMMEDIATE");
    ok(store.put_locked("aws", "b", secret, sizeof(secret), SecretTransactionMode::own_transaction) == ProxySQL_PluginSecretResult::storage_error &&
       sqlite3_get_autocommit(db->get_db()) == 0, "owned-transaction helper cannot end a caller transaction");
    db->execute("ROLLBACK");
    db->execute("BEGIN IMMEDIATE");
    db->execute("INSERT INTO managed_test_reference VALUES ('failure')");
    sqlite3_set_authorizer(db->get_db(), deny_secret_insert, nullptr);
    ok(store.put_locked("aws", "failed", secret, sizeof(secret), SecretTransactionMode::existing_transaction) == ProxySQL_PluginSecretResult::storage_error,
       "encrypted secret storage failure propagates to the caller transaction");
    sqlite3_set_authorizer(db->get_db(), nullptr, nullptr);
    ok(sqlite3_get_autocommit(db->get_db()) == 0 && scalar(*db, "SELECT count(*) FROM managed_test_reference") == 1,
       "failed existing-transaction helper neither commits nor rolls back caller work");
    db->execute("ROLLBACK");
    ok(scalar(*db, "SELECT count(*) FROM managed_test_reference") == 0 &&
       store.get_locked("aws", "failed", value) == ProxySQL_PluginSecretResult::not_found,
       "caller rollback removes references after encrypted write failure");
    ok(synchronous == scalar(*db, "PRAGMA synchronous") && foreign_keys == scalar(*db, "PRAGMA foreign_keys") &&
       journal == journal_mode(*db),
       "database settings are unchanged by configuration access and secret transactions");

    std::promise<void> started;
    auto second = std::async(std::launch::async, [&] {
        started.set_value();
        proxysql_lock_configuration();
        const bool valid = proxysql_configdb_locked() == GloAdmin->configdb;
        proxysql_unlock_configuration();
        return valid;
    });
    started.get_future().wait();
    ok(second.wait_for(std::chrono::milliseconds(40)) == std::future_status::timeout,
       "second mutation cannot overtake the owner between durable save and memory application");
    ok(sqlite3_get_autocommit(db->get_db()) != 0, "serialization spans the gap between disk transactions");
    proxysql_unlock_configuration();
    ok(second.get(), "second mutation proceeds after the whole first operation unlocks");

    proxysql_lock_configuration();
    std::promise<void> reopen_started;
    auto reopen = std::async(std::launch::async, [&] {
        reopen_started.set_value();
        GloAdmin->flush_configdb();
    });
    reopen_started.get_future().wait();
    ok(reopen.wait_for(std::chrono::milliseconds(40)) == std::future_status::timeout,
       "database reopen waits for the borrowed configuration handle");
    ok(proxysql_configdb_locked() == db && scalar(*db, "SELECT count(*) FROM proxysql_plugin_secrets") == 1,
       "borrowed handle remains usable while reopen is waiting");
    proxysql_unlock_configuration();
    reopen.get();
    proxysql_lock_configuration();
    db = proxysql_configdb_locked();
    ok(db && scalar(*db, "SELECT count(*) FROM proxysql_plugin_secrets") == 1, "reopened current handle retains durable secrets");
    ProxySQL_PluginSecrets reopened(db, directory);
    ok(reopened.get_locked("aws", "a", value) == ProxySQL_PluginSecretResult::ok, "secret decrypts after configuration database reopen");
    GloAdmin->flush_configdb_locked();
    db = proxysql_configdb_locked();
    ok(db && scalar(*db, "SELECT count(*) FROM proxysql_plugin_secrets") == 1,
       "Admin's already-locked reopen path never recursively locks the SQL mutex");
    ProxySQL_PluginSecrets final_store(db, directory);
    db->execute("BEGIN IMMEDIATE");
    ok(final_store.erase_locked("aws", "a", SecretTransactionMode::existing_transaction) == ProxySQL_PluginSecretResult::ok,
       "existing transaction mode remains usable after reopen");
    db->execute("COMMIT");
    ok(final_store.get_locked("aws", "a", value) == ProxySQL_PluginSecretResult::not_found, "committed caller erase persists");
    ok(sqlite3_get_autocommit(db->get_db()) != 0, "all configuration operations leave no accidental transaction");
    proxysql_unlock_configuration();

    delete GloAdmin->admindb;
    delete GloAdmin->configdb;
    GloAdmin->admindb = GloAdmin->configdb = nullptr;
    free(GloVars.admindb);
    GloVars.admindb = old_path;
    GloVars.statsdb_disk = old_stats_path;
    unlink(path.c_str());
    unlink((std::string(directory) + "/proxysql-plugin-secrets.key").c_str());
    rmdir(directory);
    return exit_status();
}
