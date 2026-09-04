#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "proxysql_utils.h"

namespace {

constexpr int WRITER_HG = 10;
constexpr int READER_HG = 11;

#define ADMIN_QUERY(admin, query) \
    do { \
        if (mysql_query((admin), (query))) { \
            fprintf(stderr, "File %s, line %d, Error: %s\n", \
                    __FILE__, __LINE__, mysql_error((admin))); \
            goto cleanup; \
        } \
    } while (0)

int count_runtime_servers(MYSQL* admin,
                          const char* hostname,
                          int port,
                          int hostgroup_id) {
    char query[512];
    std::snprintf(query, sizeof(query),
        "SELECT COUNT(*) FROM runtime_mysql_servers "
        "WHERE hostname='%s' AND port=%d AND hostgroup_id=%d",
        hostname, port, hostgroup_id);

    if (mysql_query(admin, query)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n",
                __FILE__, __LINE__, mysql_error(admin));
        return -1;
    }

    MYSQL_RES* result = mysql_store_result(admin);
    if (result == nullptr) {
        return -1;
    }

    int count = -1;
    MYSQL_ROW row = mysql_fetch_row(result);
    if (row != nullptr && row[0] != nullptr) {
        count = std::atoi(row[0]);
    }
    mysql_free_result(result);
    return count;
}

int set_read_only_value(const char* host,
                        uint16_t port,
                        const char* user,
                        const char* pass,
                        int read_only_val) {
    MYSQL* db = mysql_init(nullptr);
    if (db == nullptr) {
        return EXIT_FAILURE;
    }

    if (mysql_real_connect(db, host, user, pass, nullptr,
                           port, nullptr, 0) == nullptr) {
        fprintf(stderr, "File %s, line %d, Error: %s\n",
                __FILE__, __LINE__, mysql_error(db));
        mysql_close(db);
        return EXIT_FAILURE;
    }

    char query[64];
    std::snprintf(query, sizeof(query),
                  "SET @@global.read_only=%d", read_only_val);
    int rc = mysql_query(db, query);
    mysql_close(db);
    return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

int run_test(MYSQL* admin, const CommandLine& cl) {
    diag("Testing: server statically declared in both writer_hg=%d "
         "and reader_hg=%d with mysql-monitor_writer_is_also_reader=0",
         WRITER_HG, READER_HG);

    int ret = EXIT_FAILURE;
    int writer_count = -1;
    int reader_count = -1;

    // Capture the monitor variables we'll modify, so cleanup can
    // restore them and not contaminate later tests sharing this
    // ProxySQL instance.
    std::vector<std::pair<std::string, std::string>> saved_vars = {
        {"mysql-monitor_writer_is_also_reader", ""},
        {"mysql-monitor_read_only_interval",    ""},
        {"mysql-monitor_read_only_timeout",     ""},
        {"mysql-monitor_enabled",               ""},
    };
    for (auto& v : saved_vars) {
        show_admin_global_variable(admin, v.first, v.second);
    }

    // Make sure the backend reports as a writer.
    if (set_read_only_value(cl.mysql_host, cl.mysql_port,
                            cl.mysql_username, cl.mysql_password, 0)
            != EXIT_SUCCESS) {
        diag("Failed to set read_only=0 on backend");
        return EXIT_FAILURE;
    }

    // Clean slate.
    ADMIN_QUERY(admin, "DELETE FROM mysql_servers");
    ADMIN_QUERY(admin, "DELETE FROM mysql_replication_hostgroups");
    ADMIN_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

    // Configure the monitor for fast read_only polling and
    // writer_is_also_reader=0.
    ADMIN_QUERY(admin, "SET mysql-monitor_writer_is_also_reader=0");
    ADMIN_QUERY(admin, "SET mysql-monitor_read_only_interval=200");
    ADMIN_QUERY(admin, "SET mysql-monitor_read_only_timeout=100");
    ADMIN_QUERY(admin, "SET mysql-monitor_enabled='true'");
    ADMIN_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    // Replication pair.
    {
        char q[256];
        std::snprintf(q, sizeof(q),
            "INSERT INTO mysql_replication_hostgroups "
            "(writer_hostgroup, reader_hostgroup, check_type) "
            "VALUES (%d, %d, 'read_only')",
            WRITER_HG, READER_HG);
        ADMIN_QUERY(admin, q);
    }

    // Static config: same backend in BOTH hostgroups.
    // This is the state that triggers the bug.
    {
        char q[512];
        std::snprintf(q, sizeof(q),
            "INSERT INTO mysql_servers "
            "(hostgroup_id, hostname, port, status, weight, max_connections) "
            "VALUES "
            "  (%d, '%s', %d, 'ONLINE', 1000, 1000), "
            "  (%d, '%s', %d, 'ONLINE', 1000, 1000)",
            WRITER_HG, cl.mysql_host, cl.mysql_port,
            READER_HG, cl.mysql_host, cl.mysql_port);
        ADMIN_QUERY(admin, q);
    }

    ADMIN_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

    // Poll up to ~3 s (15 monitor intervals at 200 ms each) for the
    // monitor to reconcile. Exit early on the expected state.
    for (int i = 0; i < 15; ++i) {
        usleep(200 * 1000);
        writer_count = count_runtime_servers(admin, cl.mysql_host,
                                             cl.mysql_port, WRITER_HG);
        reader_count = count_runtime_servers(admin, cl.mysql_host,
                                             cl.mysql_port, READER_HG);
        if (writer_count == 1 && reader_count == 0) {
            break;
        }
    }

    diag("After LOAD + monitor reconciliation: "
         "writer_hg(%d) count=%d, reader_hg(%d) count=%d",
         WRITER_HG, writer_count, READER_HG, reader_count);

    ok(writer_count == 1,
       "Server is present in writer_hg=%d (got count=%d, want 1)",
       WRITER_HG, writer_count);
    ok(reader_count == 0,
       "Server is NOT present in reader_hg=%d (got count=%d, want 0)",
       READER_HG, reader_count);

    ret = EXIT_SUCCESS;

cleanup:
    mysql_query(admin, "DELETE FROM mysql_servers");
    mysql_query(admin, "DELETE FROM mysql_replication_hostgroups");
    mysql_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

    // Restore monitor variables to their original values.
    for (const auto& v : saved_vars) {
        if (v.second.empty()) {
            continue;
        }
        set_admin_global_variable(admin, v.first, v.second);
    }
    mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    return ret;
}

}  // namespace

int main(int, char**) {
    CommandLine cl;

    if (cl.getEnv() != 0) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }

    plan(2);

    MYSQL* admin = mysql_init(nullptr);
    if (admin == nullptr) {
        fprintf(stderr, "File %s, line %d, Error: mysql_init() failed\n",
                __FILE__, __LINE__);
        return EXIT_FAILURE;
    }

    if (mysql_real_connect(admin, cl.host, cl.admin_username,
                           cl.admin_password, nullptr,
                           cl.admin_port, nullptr, 0) == nullptr) {
        fprintf(stderr, "File %s, line %d, Error: %s\n",
                __FILE__, __LINE__, mysql_error(admin));
        return EXIT_FAILURE;
    }

    run_test(admin, cl);

    mysql_close(admin);
    return exit_status();
}
