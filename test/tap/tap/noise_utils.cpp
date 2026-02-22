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
std::mutex noise_report_mutex;
std::vector<std::string> noise_failures;
std::mutex noise_failure_mutex;

/**
 * @brief Records a fatal failure for a specific noise routine.
 */
void register_noise_failure(const std::string& routine_name) {
    std::lock_guard<std::mutex> lock(noise_failure_mutex);
    noise_failures.push_back(routine_name);
}

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

// Helper to get string option from map
static std::string get_opt_str(const NoiseOptions& opt, const std::string& key, const std::string& default_val) {
    if (opt.find(key) != opt.end()) {
        return opt.at(key);
    }
    return default_val;
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
    int interval_ms = get_opt_int(opt, "interval_ms", 200);
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
                register_noise_failure("Admin Pinger");
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
                register_noise_failure("Stats Poller");
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
                register_noise_failure("Prometheus Poller");
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

    // Optional: explicitly enable REST API via Admin
    bool enable_rest_api = false;
    if (opt.find("enable_rest_api") != opt.end()) {
        std::string val = opt.at("enable_rest_api");
        if (val == "true" || val == "1" || val == "yes") {
            enable_rest_api = true;
        }
    }

    if (enable_rest_api) {
        MYSQL* admin = mysql_init(NULL);
        if (mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
            mysql_query(admin, "SET admin-restapi_enabled='true'");
            mysql_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
            mysql_close(admin);
        } else {
            noise_log("[NOISE] REST Prometheus Poller: Failed to connect to Admin to enable REST API\n");
            if (admin) mysql_close(admin);
        }
    }

    // Port defaults to 6070
    int port = get_opt_int(opt, "port", 6070);
    std::string endpoint = "http://admin:admin@localhost:" + std::to_string(port) + "/metrics";
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
                register_noise_failure("REST Prometheus Poller");
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

    std::vector<std::string> stats_tables;
    bool tables_fetched = false;

    std::random_device rd;
    std::mt19937 g(rd());
    std::uniform_int_distribution<int> limit_dist(10, 1000);

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
                register_noise_failure("Random Stats Poller");
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
            continue;
        }

        retries = 0;

        // Fetch tables once
        if (!tables_fetched && my_ok) {
            if (mysql_query(admin_my, "SHOW TABLES FROM stats") == 0) {
                MYSQL_RES* res = mysql_store_result(admin_my);
                if (res) {
                    MYSQL_ROW row;
                    while ((row = mysql_fetch_row(res))) {
                        std::string table = row[0];
                        // Ignore tables ending in _reset
                        if (table.size() < 6 || table.compare(table.size() - 6, 6, "_reset") != 0) {
                            stats_tables.push_back(table);
                        }
                    }
                    mysql_free_result(res);
                    tables_fetched = true;
                }
            }
        }

        if (tables_fetched && !stats_tables.empty()) {
            std::shuffle(stats_tables.begin(), stats_tables.end(), g);
            for (size_t i = 0; i < 3; ++i) {
                if (stop) break;
                total_queries++;
                std::string table = stats_tables[i % stats_tables.size()];
                int limit = limit_dist(g);
                std::string query = "SELECT * FROM stats." + table + " LIMIT " + std::to_string(limit);
                
                if (my_ok) {
                    if (mysql_query(admin_my, query.c_str()) == 0) {
                        MYSQL_RES* res = mysql_store_result(admin_my);
                        if (res) mysql_free_result(res);
                    }
                }
                if (pg_ok) {
                    pg_noise_query(admin_pg, query.c_str());
                }
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
                    register_noise_failure("MySQL Traffic");
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
                                   " dbname=postgres connect_timeout=2";
            conn = PQconnectdb(conninfo.c_str());
            if (PQstatus(conn) != CONNECTION_OK) {
                retries++;
                noise_log("[NOISE] PgSQL Traffic: Connection failure (retry " + std::to_string(retries) + "/" + std::to_string(max_retries) + ")\n");
                if (retries >= max_retries) {
                    register_noise_failure("PgSQL Traffic");
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

void internal_noise_pgsql_traffic_v2(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop) {
    std::string tablename = get_opt_str(opt, "tablename", "pgsql_noise_test");
    int num_connections = get_opt_int(opt, "num_connections", 20);
    int reconnect_interval = get_opt_int(opt, "reconnect_interval", 200);
    int max_retries = get_opt_int(opt, "max_retries", 5);

    // Use postgres user for setup and load to ensure permissions
    std::string conninfo = "host=" + std::string(cl.host) + " port=" + std::to_string(cl.pgsql_port) + 
                           " user=postgres password=postgres" +
                           " dbname=postgres connect_timeout=5";

    // --- Phase A: Ensure table exists ---
    PGconn* setup_conn = PQconnectdb(conninfo.c_str());
    if (PQstatus(setup_conn) != CONNECTION_OK) {
        noise_log("[NOISE] PgSQL Traffic v2: Setup connection failure: " + std::string(PQerrorMessage(setup_conn)) + "\n");
        PQfinish(setup_conn);
        register_noise_failure("PgSQL Traffic v2 (Setup)");
        return;
    }

    std::string check_table = "SELECT 1 FROM information_schema.tables WHERE table_name = '" + tablename + "'";
    PGresult* res = PQexec(setup_conn, check_table.c_str());
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 0) {
        PQclear(res);
        noise_log("[NOISE] PgSQL Traffic v2: Creating table " + tablename + " in postgres database\n");
        std::string create_sql = "CREATE TABLE " + tablename + " (id SERIAL PRIMARY KEY, val TEXT, counter INT)";
        res = PQexec(setup_conn, create_sql.c_str());
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            noise_log("[NOISE] PgSQL Traffic v2: Table creation failed: " + std::string(PQresultErrorMessage(res)) + "\n");
        } else {
            noise_log("[NOISE] PgSQL Traffic v2: Table " + tablename + " created successfully\n");
        }
        PQclear(res);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    } else {
        noise_log("[NOISE] PgSQL Traffic v2: Table " + tablename + " already exists or verification failed\n");
        PQclear(res);
    }

    // --- Phase B: Ensure 10,000 rows ---
    while (!stop) {
        std::string count_sql = "SELECT COUNT(*) FROM " + tablename;
        res = PQexec(setup_conn, count_sql.c_str());
        if (PQresultStatus(res) == PGRES_TUPLES_OK) {
            long current_rows = std::stol(PQgetvalue(res, 0, 0));
            PQclear(res);
            if (current_rows < 10000) {
                noise_log("[NOISE] PgSQL Traffic v2: " + std::to_string(current_rows) + " rows found, adding 5000...\n");
                std::string insert_sql = "INSERT INTO " + tablename + " (val, counter) SELECT 'noise_data', generate_series(1, 5000)";
                res = PQexec(setup_conn, insert_sql.c_str());
                if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                    noise_log("[NOISE] PgSQL Traffic v2: Row insertion failed: " + std::string(PQresultErrorMessage(res)) + "\n");
                }
                PQclear(res);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            } else {
                break;
            }
        } else {
            noise_log("[NOISE] PgSQL Traffic v2: Row count failed: " + std::string(PQresultErrorMessage(res)) + "\n");
            PQclear(res);
            break;
        }
    }
    PQfinish(setup_conn);

    if (stop) return;

    // --- Phase C, D, E: Multi-threaded load ---
    std::atomic<uint64_t> total_queries{0};
    std::atomic<uint64_t> total_connections_opened{0};
    std::atomic<uint64_t> total_connections_closed{0};
    std::vector<std::thread> workers;

    for (int i = 0; i < num_connections; ++i) {
        workers.emplace_back([&, conninfo, tablename, reconnect_interval]() {
            PGconn* conn = nullptr;
            uint64_t worker_queries = 0;
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> op_dist(0, 3);
            std::uniform_int_distribution<> id_dist(1, 10000);
            std::uniform_int_distribution<> delay_dist(50, 200);
            std::uniform_int_distribution<> start_dist(0, 500);

            // Staggered start
            std::this_thread::sleep_for(std::chrono::milliseconds(start_dist(gen)));

            auto connect = [&]() {
                if (conn) {
                    PQfinish(conn);
                    total_connections_closed++;
                }
                conn = PQconnectdb(conninfo.c_str());
                if (PQstatus(conn) == CONNECTION_OK) {
                    total_connections_opened++;
                    return true;
                }
                return false;
            };

            if (!connect()) {
                noise_log("[NOISE] PgSQL Traffic v2: Worker failed initial connection\n");
                return;
            }

            while (!stop) {
                int op = op_dist(gen);
                std::string sql;
                int target_id = id_dist(gen);

                switch (op) {
                    case 0: // SELECT
                        sql = "SELECT * FROM " + tablename + " WHERE id = " + std::to_string(target_id);
                        break;
                    case 1: // INSERT
                        sql = "INSERT INTO " + tablename + " (val, counter) VALUES ('extra_noise', " + std::to_string(target_id) + ")";
                        break;
                    case 2: // UPDATE
                        sql = "UPDATE " + tablename + " SET counter = counter + 1 WHERE id = " + std::to_string(target_id);
                        break;
                    case 3: // DELETE
                        sql = "DELETE FROM " + tablename + " WHERE id = " + std::to_string(target_id);
                        break;
                }

                PGresult* r = PQexec(conn, sql.c_str());
                if (r) PQclear(r);
                
                worker_queries++;
                uint64_t current_total = ++total_queries;

                if (current_total % 1000 == 0) {
                    noise_log("[NOISE] PgSQL Traffic v2 progress: " + std::to_string(current_total) + " queries executed...\n");
                }

                if (worker_queries % reconnect_interval == 0) {
                    if (!connect()) break;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(delay_dist(gen)));
            }
            if (conn) {
                PQfinish(conn);
                total_connections_closed++;
            }
        });
    }

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    noise_log("[NOISE] PgSQL Traffic v2 report: total_queries=" + std::to_string(total_queries) + 
              ", total_connections_opened=" + std::to_string(total_connections_opened) + 
              ", total_connections_closed=" + std::to_string(total_connections_closed) + "\n");
}
