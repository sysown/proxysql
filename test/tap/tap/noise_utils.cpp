#include <chrono>
#include <iostream>
#include <random>
#include <algorithm>
#include "noise_utils.h"
#include "utils.h"
#include "tap.h"
#include "mysql.h"
#include "libpq-fe.h"

static std::vector<std::thread> internal_noise_threads;
static std::atomic<bool> stop_internal_noise{false};

// Helper for PostgreSQL noise
static void pg_noise_query(PGconn* conn, const char* query) {
    PGresult* res = PQexec(conn, query);
    if (res) PQclear(res);
}

void spawn_internal_noise(const CommandLine& cl, internal_noise_func_t func) {
    if (!cl.use_noise) {
        return;
    }
    
    stop_internal_noise = false;
    internal_noise_threads.emplace_back(func, std::ref(cl), std::ref(stop_internal_noise));
    diag("Spawned internal noise thread");
}

void stop_internal_noise_threads() {
    stop_internal_noise = true;
    for (auto& t : internal_noise_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    internal_noise_threads.clear();
}

// --- Standard Internal Noise Functions Implementation ---

void internal_noise_admin_pinger(const CommandLine& cl, std::atomic<bool>& stop) {
    MYSQL* admin_my = mysql_init(NULL);
    PGconn* admin_pg = NULL;

    if (admin_my) {
        mysql_real_connect(admin_my, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0);
    }

    std::string conninfo = "host=" + std::string(cl.host) + " port=" + std::to_string(cl.pgsql_admin_port) + 
                           " user=" + std::string(cl.admin_username) + " password=" + std::string(cl.admin_password) +
                           " dbname=stats connect_timeout=2";
    admin_pg = PQconnectdb(conninfo.c_str());

    while (!stop) {
        if (admin_my && mysql_ping(admin_my) == 0) {
            if (mysql_query(admin_my, "SELECT 1") == 0) {
                MYSQL_RES* res = mysql_store_result(admin_my);
                if (res) mysql_free_result(res);
            }
        }
        if (admin_pg && PQstatus(admin_pg) == CONNECTION_OK) {
            pg_noise_query(admin_pg, "SELECT 1");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if (admin_my) mysql_close(admin_my);
    if (admin_pg) PQfinish(admin_pg);
}

void internal_noise_stats_poller(const CommandLine& cl, std::atomic<bool>& stop) {
    MYSQL* admin_my = mysql_init(NULL);
    PGconn* admin_pg = NULL;

    if (admin_my) {
        mysql_real_connect(admin_my, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0);
    }

    std::string conninfo = "host=" + std::string(cl.host) + " port=" + std::to_string(cl.pgsql_admin_port) + 
                           " user=" + std::string(cl.admin_username) + " password=" + std::string(cl.admin_password) +
                           " dbname=stats connect_timeout=2";
    admin_pg = PQconnectdb(conninfo.c_str());

    while (!stop) {
        const char* my_queries[] = {
            "SELECT * FROM stats_mysql_query_digest",
            "SELECT * FROM stats_mysql_connection_pool",
            "SELECT * FROM stats_mysql_processlist"
        };
        const char* pg_queries[] = {
            "SELECT * FROM stats_pgsql_query_digest",
            "SELECT * FROM stats_pgsql_connection_pool",
            "SELECT * FROM stats_pgsql_processlist"
        };

        for (size_t i = 0; i < 3; ++i) {
            if (stop) break;
            if (admin_my && mysql_ping(admin_my) == 0) {
                if (mysql_query(admin_my, my_queries[i]) == 0) {
                    MYSQL_RES* res = mysql_store_result(admin_my);
                    if (res) mysql_free_result(res);
                }
            }
            if (admin_pg && PQstatus(admin_pg) == CONNECTION_OK) {
                pg_noise_query(admin_pg, pg_queries[i]);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    if (admin_my) mysql_close(admin_my);
    if (admin_pg) PQfinish(admin_pg);
}

void internal_noise_prometheus_poller(const CommandLine& cl, std::atomic<bool>& stop) {
    MYSQL* admin_my = mysql_init(NULL);
    PGconn* admin_pg = NULL;

    if (admin_my) {
        mysql_real_connect(admin_my, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0);
    }

    std::string conninfo = "host=" + std::string(cl.host) + " port=" + std::to_string(cl.pgsql_admin_port) + 
                           " user=" + std::string(cl.admin_username) + " password=" + std::string(cl.admin_password) +
                           " dbname=stats connect_timeout=2";
    admin_pg = PQconnectdb(conninfo.c_str());

    while (!stop) {
        if (admin_my && mysql_ping(admin_my) == 0) {
            if (mysql_query(admin_my, "SELECT * FROM stats_prometheus_metrics") == 0) {
                MYSQL_RES* res = mysql_store_result(admin_my);
                if (res) mysql_free_result(res);
            }
        }
        
        if (admin_pg && PQstatus(admin_pg) == CONNECTION_OK) {
            pg_noise_query(admin_pg, "SELECT * FROM stats_prometheus_metrics");
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    if (admin_my) mysql_close(admin_my);
    if (admin_pg) PQfinish(admin_pg);
}

void internal_noise_random_stats_poller(const CommandLine& cl, std::atomic<bool>& stop) {
    MYSQL* admin_my = mysql_init(NULL);
    PGconn* admin_pg = NULL;

    if (admin_my) {
        mysql_real_connect(admin_my, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0);
    }

    std::string conninfo = "host=" + std::string(cl.host) + " port=" + std::to_string(cl.pgsql_admin_port) + 
                           " user=" + std::string(cl.admin_username) + " password=" + std::string(cl.admin_password) +
                           " dbname=stats connect_timeout=2";
    admin_pg = PQconnectdb(conninfo.c_str());

    std::vector<std::string> my_tables = {
        "stats_mysql_query_digest", "stats_mysql_connection_pool", "stats_mysql_processlist",
        "stats_mysql_global", "stats_mysql_user_stats", "stats_mysql_query_rules", "stats_mysql_commands_counters"
    };
    std::vector<std::string> pg_tables = {
        "stats_pgsql_query_digest", "stats_pgsql_connection_pool", "stats_pgsql_processlist",
        "stats_pgsql_global", "stats_pgsql_commands_counters"
    };

    std::random_device rd;
    std::mt19937 g(rd());

    while (!stop) {
        std::shuffle(my_tables.begin(), my_tables.end(), g);
        std::shuffle(pg_tables.begin(), pg_tables.end(), g);

        for (size_t i = 0; i < 3; ++i) {
            if (stop) break;
            if (admin_my && mysql_ping(admin_my) == 0) {
                std::string q = "SELECT * FROM " + my_tables[i % my_tables.size()] + " LIMIT 10";
                if (mysql_query(admin_my, q.c_str()) == 0) {
                    MYSQL_RES* res = mysql_store_result(admin_my);
                    if (res) mysql_free_result(res);
                }
            }
            if (admin_pg && PQstatus(admin_pg) == CONNECTION_OK) {
                std::string q = "SELECT * FROM " + pg_tables[i % pg_tables.size()] + " LIMIT 10";
                pg_noise_query(admin_pg, q.c_str());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if (admin_my) mysql_close(admin_my);
    if (admin_pg) PQfinish(admin_pg);
}

void internal_noise_mysql_traffic(const CommandLine& cl, std::atomic<bool>& stop) {
    MYSQL* conn = mysql_init(NULL);
    if (!conn) return;

    if (!mysql_real_connect(conn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        mysql_close(conn);
        return;
    }

    const char* queries[] = {
        "SELECT 1", "SELECT @@version", "SELECT NOW()", "SHOW TABLES", "SELECT 'noise'"
    };
    std::random_device rd;
    std::mt19937 g(rd());

    while (!stop) {
        if (mysql_ping(conn) != 0) {
            // Reconnect if needed
            mysql_close(conn);
            conn = mysql_init(NULL);
            if (!conn || !mysql_real_connect(conn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
        }

        const char* q = queries[g() % 5];
        if (mysql_query(conn, q) == 0) {
            MYSQL_RES* res = mysql_store_result(conn);
            if (res) mysql_free_result(res);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    mysql_close(conn);
}

void internal_noise_pgsql_traffic(const CommandLine& cl, std::atomic<bool>& stop) {
    std::string conninfo = "host=" + std::string(cl.host) + " port=" + std::to_string(cl.pgsql_port) + 
                           " user=" + std::string(cl.pgsql_username) + " password=" + std::string(cl.pgsql_password) +
                           " dbname=test connect_timeout=2";
    PGconn* conn = PQconnectdb(conninfo.c_str());

    const char* queries[] = {
        "SELECT 1", "SELECT version()", "SELECT current_timestamp", "SELECT 'noise'"
    };
    std::random_device rd;
    std::mt19937 g(rd());

    while (!stop) {
        if (PQstatus(conn) != CONNECTION_OK) {
            PQfinish(conn);
            conn = PQconnectdb(conninfo.c_str());
            if (PQstatus(conn) != CONNECTION_OK) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
        }

        const char* q = queries[g() % 4];
        pg_noise_query(conn, q);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    PQfinish(conn);
}
