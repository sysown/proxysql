#include <chrono>
#include <iostream>
#include <random>
#include <algorithm>
#include <map>
#include "noise_utils.h"
#include "utils.h"
#include "tap.h"
#include "mysql.h"
#include "libpq-fe.h"

static std::vector<std::thread> internal_noise_threads;
static std::atomic<bool> stop_internal_noise{false};
std::atomic<bool> noise_failure_detected{false};
std::mutex noise_report_mutex;

/**
 * @brief Thread-safe logging to stderr for noise routines.
 */
void noise_log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(noise_report_mutex);
    fprintf(stderr, "%s", msg.c_str());
}

// Helper for PostgreSQL noise
static void pg_noise_query(PGconn* conn, const char* query) {
    PGresult* res = PQexec(conn, query);
    if (res) PQclear(res);
}

// Helper to get int option from map
static int get_opt_int(const NoiseOptions& opt, const std::string& key, int default_val) {
    if (opt.find(key) != opt.end()) {
        try {
            return std::stoi(opt.at(key));
        } catch (...) {}
    }
    return default_val;
}

void spawn_internal_noise(const CommandLine& cl, internal_noise_func_t func, const NoiseOptions& opt) {
    if (!cl.use_noise) {
        return;
    }
    
    stop_internal_noise = false;
    internal_noise_threads.emplace_back(func, std::ref(cl), opt, std::ref(stop_internal_noise));
    diag("Spawned internal noise thread");
}

void stop_internal_noise_threads() {
    stop_internal_noise = true;
    
    // Grace period for threads to report before joining
    for (int i = 0; i < 50; ++i) { // max 5 seconds grace period
        bool all_finished = true;
        // We can't easily check if threads have finished without joining, 
        // but we can at least wait a bit.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    for (auto& t : internal_noise_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    internal_noise_threads.clear();
}

int get_internal_noise_threads_count() {
    return (int)internal_noise_threads.size();
}

// --- Standard Internal Noise Functions Implementation ---

void internal_noise_admin_pinger(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop) {
    int interval_ms = get_opt_int(opt, "interval_ms", 500);
    int max_retries = get_opt_int(opt, "max_retries", 5);
    int retries = 0;
    uint64_t total_pings = 0;
    uint64_t success_pings = 0;

    MYSQL* admin_my = mysql_init(NULL);
    PGconn* admin_pg = NULL;

    while (!stop) {
        bool my_ok = true;
        bool pg_ok = true;

        total_pings++;

        if (admin_my && mysql_ping(admin_my) != 0) {
            if (!mysql_real_connect(admin_my, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
                my_ok = false;
            }
        }

        if (!admin_pg || PQstatus(admin_pg) != CONNECTION_OK) {
            if (admin_pg) PQfinish(admin_pg);
            std::string conninfo = "host=" + std::string(cl.host) + " port=" + std::to_string(cl.pgsql_admin_port) + 
                                   " user=" + std::string(cl.admin_username) + " password=" + std::string(cl.admin_password) +
                                   " dbname=stats connect_timeout=2";
            admin_pg = PQconnectdb(conninfo.c_str());
            if (PQstatus(admin_pg) != CONNECTION_OK) {
                pg_ok = false;
            }
        }

        if (!my_ok && !pg_ok) {
            retries++;
            noise_log("[NOISE] Admin Pinger: Failed to connect to both MySQL and PgSQL admin (retry " + std::to_string(retries) + "/" + std::to_string(max_retries) + ")\n");
            if (retries >= max_retries) {
                noise_failure_detected = true;
                break;
            }
        } else {
            retries = 0;
            success_pings++;
            if (my_ok && mysql_query(admin_my, "SELECT 1") == 0) {
                MYSQL_RES* res = mysql_store_result(admin_my);
                if (res) mysql_free_result(res);
            }
            if (pg_ok) {
                pg_noise_query(admin_pg, "SELECT 1");
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    if (admin_my) mysql_close(admin_my);
    if (admin_pg) PQfinish(admin_pg);

    noise_log("[NOISE] Admin Pinger report: total=" + std::to_string(total_pings) + ", success=" + std::to_string(success_pings) + "\n");
}

void internal_noise_stats_poller(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop) {
    int interval_ms = get_opt_int(opt, "interval_ms", 200);
    int max_retries = get_opt_int(opt, "max_retries", 5);
    int retries = 0;
    uint64_t total_queries = 0;

    MYSQL* admin_my = mysql_init(NULL);
    PGconn* admin_pg = NULL;

    while (!stop) {
        bool my_ok = true;
        bool pg_ok = true;

        if (admin_my && mysql_ping(admin_my) != 0) {
            if (!mysql_real_connect(admin_my, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
                my_ok = false;
            }
        }

        if (!admin_pg || PQstatus(admin_pg) != CONNECTION_OK) {
            if (admin_pg) PQfinish(admin_pg);
            std::string conninfo = "host=" + std::string(cl.host) + " port=" + std::to_string(cl.pgsql_admin_port) + 
                                   " user=" + std::string(cl.admin_username) + " password=" + std::string(cl.admin_password) +
                                   " dbname=stats connect_timeout=2";
            admin_pg = PQconnectdb(conninfo.c_str());
            if (PQstatus(admin_pg) != CONNECTION_OK) {
                pg_ok = false;
            }
        }

        if (!my_ok && !pg_ok) {
            retries++;
            noise_log("[NOISE] Stats Poller: Connection failure (retry " + std::to_string(retries) + "/" + std::to_string(max_retries) + ")\n");
            if (retries >= max_retries) {
                noise_failure_detected = true;
                break;
            }
        } else {
            retries = 0;
            const char* my_queries[] = {"SELECT * FROM stats_mysql_query_digest", "SELECT * FROM stats_mysql_connection_pool", "SELECT * FROM stats_mysql_processlist"};
            const char* pg_queries[] = {"SELECT * FROM stats_pgsql_query_digest", "SELECT * FROM stats_pgsql_connection_pool", "SELECT * FROM stats_pgsql_processlist"};

            for (size_t i = 0; i < 3; ++i) {
                if (stop) break;
                total_queries++;
                if (my_ok && mysql_query(admin_my, my_queries[i]) == 0) {
                    MYSQL_RES* res = mysql_store_result(admin_my);
                    if (res) mysql_free_result(res);
                }
                if (pg_ok) pg_noise_query(admin_pg, pg_queries[i]);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    if (admin_my) mysql_close(admin_my);
    if (admin_pg) PQfinish(admin_pg);
    noise_log("[NOISE] Stats Poller report: total_queries=" + std::to_string(total_queries) + "\n");
}

void internal_noise_prometheus_poller(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop) {
    int interval_ms = get_opt_int(opt, "interval_ms", 1000);
    int max_retries = get_opt_int(opt, "max_retries", 5);
    int retries = 0;
    uint64_t total_scrapes = 0;

    MYSQL* admin_my = mysql_init(NULL);

    while (!stop) {
        bool my_ok = true;

        if (admin_my && mysql_ping(admin_my) != 0) {
            if (!mysql_real_connect(admin_my, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
                my_ok = false;
            }
        }

        if (!my_ok) {
            retries++;
            noise_log("[NOISE] Prometheus Poller: Connection failure (retry " + std::to_string(retries) + "/" + std::to_string(max_retries) + ")\n");
            if (retries >= max_retries) {
                noise_failure_detected = true;
                break;
            }
        } else {
            retries = 0;
            total_scrapes++;
            if (mysql_query(admin_my, "SHOW PROMETHEUS METRICS") == 0) {
                MYSQL_RES* res = mysql_store_result(admin_my);
                if (res) mysql_free_result(res);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    if (admin_my) mysql_close(admin_my);
    noise_log("[NOISE] Prometheus Poller report: total_scrapes=" + std::to_string(total_scrapes) + "\n");
}

void internal_noise_rest_prometheus_poller(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop) {
    int interval_ms = get_opt_int(opt, "interval_ms", 1000);
    int max_retries = get_opt_int(opt, "max_retries", 5);
    int retries = 0;
    uint64_t total_scrapes = 0;

    // Use default REST API port 6070 and admin:admin if not specified
    std::string endpoint = "http://admin:admin@localhost:6070/metrics";
    if (opt.find("endpoint") != opt.end()) {
        endpoint = opt.at("endpoint");
    }

    while (!stop) {
        uint64_t curl_res_code = 0;
        std::string curl_res_data;
        CURLcode res = perform_simple_get(endpoint, curl_res_code, curl_res_data);

        if (res != CURLE_OK || curl_res_code != 200) {
            retries++;
            noise_log("[NOISE] REST Prometheus Poller: Failure (retry " + std::to_string(retries) + "/" + std::to_string(max_retries) + ") curl_rc=" + std::to_string(res) + " http_code=" + std::to_string(curl_res_code) + "\n");
            if (retries >= max_retries) {
                noise_failure_detected = true;
                break;
            }
        } else {
            retries = 0;
            total_scrapes++;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    noise_log("[NOISE] REST Prometheus Poller report: total_scrapes=" + std::to_string(total_scrapes) + "\n");
}

void internal_noise_random_stats_poller(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop) {
    int interval_ms = get_opt_int(opt, "interval_ms", 500);
    int max_retries = get_opt_int(opt, "max_retries", 5);
    int retries = 0;
    uint64_t total_queries = 0;

    MYSQL* admin_my = mysql_init(NULL);
    PGconn* admin_pg = NULL;

    std::vector<std::string> my_tables = {"stats_mysql_query_digest", "stats_mysql_connection_pool", "stats_mysql_processlist", "stats_mysql_global", "stats_mysql_user_stats", "stats_mysql_query_rules", "stats_mysql_commands_counters"};
    std::vector<std::string> pg_tables = {"stats_pgsql_query_digest", "stats_pgsql_connection_pool", "stats_pgsql_processlist", "stats_pgsql_global", "stats_pgsql_commands_counters"};
    std::random_device rd;
    std::mt19937 g(rd());

    while (!stop) {
        bool my_ok = true;
        bool pg_ok = true;

        if (admin_my && mysql_ping(admin_my) != 0) {
            if (!mysql_real_connect(admin_my, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
                my_ok = false;
            }
        }

        if (!admin_pg || PQstatus(admin_pg) != CONNECTION_OK) {
            if (admin_pg) PQfinish(admin_pg);
            std::string conninfo = "host=" + std::string(cl.host) + " port=" + std::to_string(cl.pgsql_admin_port) + 
                                   " user=" + std::string(cl.admin_username) + " password=" + std::string(cl.admin_password) +
                                   " dbname=stats connect_timeout=2";
            admin_pg = PQconnectdb(conninfo.c_str());
            if (PQstatus(admin_pg) != CONNECTION_OK) {
                pg_ok = false;
            }
        }

        if (!my_ok && !pg_ok) {
            retries++;
            noise_log("[NOISE] Random Stats: Connection failure (retry " + std::to_string(retries) + "/" + std::to_string(max_retries) + ")\n");
            if (retries >= max_retries) {
                noise_failure_detected = true;
                break;
            }
        } else {
            retries = 0;
            std::shuffle(my_tables.begin(), my_tables.end(), g);
            std::shuffle(pg_tables.begin(), pg_tables.end(), g);
            for (size_t i = 0; i < 3; ++i) {
                if (stop) break;
                total_queries++;
                if (my_ok && mysql_query(admin_my, ("SELECT * FROM " + my_tables[i % my_tables.size()] + " LIMIT 10").c_str()) == 0) {
                    MYSQL_RES* res = mysql_store_result(admin_my);
                    if (res) mysql_free_result(res);
                }
                if (pg_ok) pg_noise_query(admin_pg, ("SELECT * FROM " + pg_tables[i % pg_tables.size()] + " LIMIT 10").c_str());
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    if (admin_my) mysql_close(admin_my);
    if (admin_pg) PQfinish(admin_pg);
    noise_log("[NOISE] Random Stats report: total_queries=" + std::to_string(total_queries) + "\n");
}

void internal_noise_mysql_traffic(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop) {
    int interval_ms = get_opt_int(opt, "interval_ms", 100);
    int max_retries = get_opt_int(opt, "max_retries", 5);
    int retries = 0;
    uint64_t total_queries = 0;

    MYSQL* conn = mysql_init(NULL);
    const char* queries[] = {"SELECT 1", "SELECT @@version", "SELECT NOW()", "SHOW TABLES", "SELECT 'noise'"};
    std::random_device rd;
    std::mt19937 g(rd());

    while (!stop) {
        if (mysql_ping(conn) != 0) {
            mysql_close(conn);
            conn = mysql_init(NULL);
            if (!conn || !mysql_real_connect(conn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
                retries++;
                noise_log("[NOISE] MySQL Traffic: Connection failure (retry " + std::to_string(retries) + "/" + std::to_string(max_retries) + ")\n");
                if (retries >= max_retries) {
                    noise_failure_detected = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
        }

        retries = 0;
        total_queries++;
        if (mysql_query(conn, queries[g() % 5]) == 0) {
            MYSQL_RES* res = mysql_store_result(conn);
            if (res) mysql_free_result(res);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }
    if (conn) mysql_close(conn);
    noise_log("[NOISE] MySQL Traffic report: total_queries=" + std::to_string(total_queries) + "\n");
}

void internal_noise_pgsql_traffic(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop) {
    int interval_ms = get_opt_int(opt, "interval_ms", 100);
    int max_retries = get_opt_int(opt, "max_retries", 5);
    int retries = 0;
    uint64_t total_queries = 0;

    PGconn* conn = NULL;
    const char* queries[] = {"SELECT 1", "SELECT version()", "SELECT current_timestamp", "SELECT 'noise'"};
    std::random_device rd;
    std::mt19937 g(rd());

    while (!stop) {
        if (!conn || PQstatus(conn) != CONNECTION_OK) {
            if (conn) PQfinish(conn);
            std::string conninfo = "host=" + std::string(cl.host) + " port=" + std::to_string(cl.pgsql_port) + 
                                   " user=" + std::string(cl.pgsql_username) + " password=" + std::string(cl.pgsql_password) +
                                   " dbname=test connect_timeout=2";
            conn = PQconnectdb(conninfo.c_str());
            if (PQstatus(conn) != CONNECTION_OK) {
                retries++;
                noise_log("[NOISE] PgSQL Traffic: Connection failure (retry " + std::to_string(retries) + "/" + std::to_string(max_retries) + ")\n");
                if (retries >= max_retries) {
                    noise_failure_detected = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
        }

        retries = 0;
        total_queries++;
        pg_noise_query(conn, queries[g() % 4]);
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }
    if (conn) PQfinish(conn);
    noise_log("[NOISE] PgSQL Traffic report: total_queries=" + std::to_string(total_queries) + "\n");
}
