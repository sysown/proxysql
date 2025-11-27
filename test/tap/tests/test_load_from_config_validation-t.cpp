/**
 * @file test_load_from_config_validation-t.cpp
 * @brief Test validation for LOAD FROM CONFIG commands
 *
 * This test validates loading configuration from config file for,
 * - mysql_users
 * - pgsql_users
 * - mysql_servers
 * - pgsql_servers
 * - proxysql_servers
 */

#include <cstddef>
#include <cstring>
#include <string>
#include <fstream>
#include <unistd.h>
#include "mysql.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using std::string;
using std::fstream;

void create_config_with_duplicates(const string& config_file_path) {
    string config_content = R"(
        datadir="/tmp"
        errorlog="/tmp/proxysql.log"

        mysql_users:
        (
            {
                username="user1"
                password="test"
                backend=1
                default_hostgroup=0
            },
            {
                username="user1"
                password="test"
                backend=1
                default_hostgroup=0
            }
        )

        mysql_servers:
        (
            {
                address="127.0.0.1"
                port=3306
                hostgroup=0
                weight=900
            },
            {
                address="127.0.0.1"
                port=3306
                hostgroup=0
                weight=800
            }
        )

        pgsql_users:
        (
            {
                username="user1"
                password="test"
                backend=1
                default_hostgroup=1
            },
            {
                username="user1"
                password="test"
                backend=1
                default_hostgroup=1
            }
        )

        pgsql_servers:
        (
            {
                address="127.0.0.1"
                port=5432
                hostgroup=0
                weight=900
            },
            {
                address="127.0.0.1"
                port=5432
                hostgroup=0
                weight=800
            }
        )

        proxysql_servers:
        (
            {
                address="127.0.0.1"
                port=6033
            },
            {
                address="127.0.0.1"
                port=6033
            }
        )
    )";

    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    config_file << config_content;
    config_file.close();
}

void create_config_without_mandatory_fields(const string& config_file_path) {
    string config_content = R"(
        datadir="/tmp"
        errorlog="/tmp/proxysql.log"

        mysql_users:
        (
            {
                password="test"
                backend=1
                default_hostgroup=0
            }
        )

        mysql_servers:
        (
            {
                address="127.0.0.1"
                port=3306
            }
        )

        pgsql_users:
        (
            {
                password="test"
                backend=1
                default_hostgroup=1
            }
        )

        pgsql_servers:
        (
            {
                port=5432
                hostgroup=0
                weight=900
            }
        )

        proxysql_servers:
        (
            {
                address="127.0.0.1"
            }
        )
    )";

    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    config_file << config_content;
    config_file.close();
}

void create_valid_config(const string& config_file_path) {
    string config_content = R"(
        datadir="/tmp"
        errorlog="/tmp/proxysql.log"

        mysql_users:
        (
            {
                username="user1"
                password="test"
                backend=1
                default_hostgroup=0
            },
            {
                username="user2"
                password="test"
                backend=1
                default_hostgroup=0
            }
        )

        mysql_servers:
        (
            {
                address="127.0.0.1"
                port=3306
                hostgroup=0
                weight=900
            },
            {
                address="192.168.42.1"
                port=3306
                hostgroup=0
                weight=800
            }
        )

        pgsql_users:
        (
            {
                username="user1"
                password="test"
                backend=1
                default_hostgroup=1
            },
            {
                username="user2"
                password="test"
                backend=1
                default_hostgroup=1
            }
        )

        pgsql_servers:
        (
            {
                address="127.0.0.1"
                port=5432
                hostgroup=0
                weight=900
            },
            {
                address="192.168.42.1"
                port=5432
                hostgroup=0
                weight=800
            }
        )

        proxysql_servers:
        (
            {
                address="192.168.42.1"
                port=6033
            },
            {
                address="192.168.42.2"
                port=6033
            }
        )
    )";

    fstream config_file;
    config_file.open(config_file_path, std::ios::out);
    config_file << config_content;
    config_file.close();
}

int main(int argc, char** argv) {
    CommandLine cl;

    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }

    std::vector<std::tuple<std::string, std::string>> tc_for_duplicates_check = {
        {"LOAD MYSQL USERS FROM CONFIG", "duplicate entries found in mysql_users"},
        {"LOAD PGSQL USERS FROM CONFIG", "duplicate entries found in pgsql_users"},
        {"LOAD MYSQL SERVERS FROM CONFIG", "duplicate entries found in mysql_servers"},
        {"LOAD PGSQL SERVERS FROM CONFIG", "duplicate entries found in pgsql_servers"},
        {"LOAD PROXYSQL SERVERS FROM CONFIG", "duplicate entries found in proxysql_servers"}
    };

    std::vector<std::tuple<std::string, std::string>> tc_for_mandatory_fields = {
        {"LOAD MYSQL USERS FROM CONFIG", "mandatory field username missing from a mysql_users entry"},
        {"LOAD PGSQL USERS FROM CONFIG", "mandatory field username missing from a pgsql_users entry"},
        {"LOAD MYSQL SERVERS FROM CONFIG", "mandatory field hostgroup_id missing from a mysql_servers entry"},
        {"LOAD PGSQL SERVERS FROM CONFIG", "mandatory field hostname missing from a pgsql_servers entry"},
        {"LOAD PROXYSQL SERVERS FROM CONFIG", "mandatory field port missing from a proxysql_servers entry"}
    };

    std::vector<std::tuple<std::string, std::string, int>> tc_valid = {
        {"LOAD MYSQL USERS FROM CONFIG", "SELECT * FROM mysql_users", 2},
        {"LOAD PGSQL USERS FROM CONFIG", "SELECT * FROM pgsql_users", 2},
        {"LOAD MYSQL SERVERS FROM CONFIG", "SELECT * FROM mysql_servers", 2},
        {"LOAD PGSQL SERVERS FROM CONFIG", "SELECT * FROM pgsql_servers", 2},
        {"LOAD PROXYSQL SERVERS FROM CONFIG", "SELECT * FROM proxysql_servers", 2}
    };

    int n = tc_valid.size()
            + tc_for_duplicates_check.size()
            + tc_for_mandatory_fields.size();

    plan(n);

    MYSQL* admin = mysql_init(NULL);
    if (!admin) {
        fprintf(stderr, "Failed to initialize MySQL client\n");
        return exit_status();
    }

    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(admin));
        return exit_status();
    }

    string config_file = "/tmp/proxysql_test_config.cfg";
    create_config_with_duplicates(config_file);

    string set_config_cmd = "PROXYSQL SET CONFIG FILE '" + config_file + "'";
    MYSQL_QUERY_T(admin, set_config_cmd.c_str());

    diag("Running test cases for duplicate entry check");
    for (auto it = tc_for_duplicates_check.begin(); it != tc_for_duplicates_check.end(); it++) {
        auto [query, exp_error] = *it;
        const char* query_c = query.c_str();
        const char* exp_error_c = exp_error.c_str();

        int query_result = mysql_query(admin, query_c);
        if (query_result == 0) {
            ok(false, "%s succeeded with invalid configuration", query_c);
            continue;
        }

        const char* error_msg = mysql_error(admin);

        bool match = (strstr(error_msg, exp_error_c) != nullptr);
        if (match) {
            ok(true, "%s failed as expected with reason: %s", query_c, error_msg);
        } else {
            ok(false, "%s failed for unexpected reason: %s", query_c, error_msg);
        }
    }

    create_config_without_mandatory_fields(config_file);
    diag("Running test cases for mandatory field check");
    for (auto it = tc_for_mandatory_fields.begin(); it != tc_for_mandatory_fields.end(); it++) {
        auto [query, exp_error] = *it;
        const char* query_c = query.c_str();
        const char* exp_error_c = exp_error.c_str();

        int query_result = mysql_query(admin, query_c);
        if (query_result == 0) {
            ok(false, "%s succeeded with invalid configuration", query_c);
            continue;
        }

        const char* error_msg = mysql_error(admin);

        bool match = (strstr(error_msg, exp_error_c) != nullptr);
        if (match) {
            ok(true, "%s failed as expected with reason: %s", query_c, error_msg);
        } else {
            ok(false, "%s failed for unexpected reason: %s", query_c, error_msg);
        }
    }

    diag("Running test cases with valid configuration");

    MYSQL_QUERY_T(admin, "DELETE FROM mysql_users");
    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_users");
    MYSQL_QUERY_T(admin, "DELETE FROM mysql_servers");
    MYSQL_QUERY_T(admin, "DELETE FROM pgsql_servers");
    MYSQL_QUERY_T(admin, "DELETE FROM proxysql_servers");

    create_valid_config(config_file);
    for (auto it = tc_valid.begin(); it != tc_valid.end(); it++) {
        auto [load_query, select_query, exp_row_count] = *it;
        const char* load_query_c = load_query.c_str();
        const char* select_query_c = select_query.c_str();


        int query_result = mysql_query(admin, load_query_c);
        if (query_result != 0) {
            const char* error_msg = mysql_error(admin);
            ok(false, "%s failed with error: %s", load_query_c, error_msg);
            continue;
        }

        MYSQL_QUERY_T(admin, select_query_c);
        MYSQL_RES* result = mysql_store_result(admin);
        int row_count = mysql_num_rows(result);
        mysql_free_result(result);

        bool match = (row_count == exp_row_count);
        ok(match, "%s %s; row_count = %d", load_query_c, (match) ? "successful" : "failed", row_count);
    }

    unlink(config_file.c_str());
    mysql_close(admin);

    return exit_status();
}
