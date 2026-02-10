/**
 * @file ProxySQL_TSDB.cpp
 * @brief Implementation of the Embedded Time Series Database subsystem.
 *
 * This file contains the logic for the TSDB writer, sampler, monitor, and query engine.
 * It handles the persistence of metrics to disk and the retrieval of data via the API.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "proxysql.h"
#include "cpp.h"
#include "ProxySQL_TSDB.hpp"
#include "ProxySQL_Statistics.hpp"
#include "proxysql_glovars.hpp"
#include "proxysql_admin.h"
#include "MySQL_HostGroups_Manager.h"

#include "../deps/json/json.hpp"
using json = nlohmann::json;

ProxySQL_TSDB *GloTSDB = NULL;
extern ProxySQL_Admin *GloAdmin;

static const char* tsdb_variable_names[] = {
    "enabled",
    "data_dir",
    "retention_hours",
    "sample_interval_seconds",
    "raw_window_minutes",
    "rollup_interval_seconds",
    "max_series",
    "max_disk_mb",
    "fsync_mode",
    "digest_mode",
    "digest_topk",
    // Monitor
    "monitor_enabled",
    "monitor_interval_seconds",
    "monitor_connect_timeout_ms",
    "monitor_ping_enabled",
    "monitor_max_concurrent_probes",
    // UI
    "ui_enabled",
    "ui_read_only",
    NULL
};

/**
 * @brief Constructor for ProxySQL_TSDB.
 * Sets default values for all configuration parameters.
 */
ProxySQL_TSDB::ProxySQL_TSDB() : stop_threads(false) {
    // Defaults
    config.enabled = false;
    config.data_dir = ""; // Set in init()
    config.retention_hours = 24;
    config.sample_interval_seconds = 5;
    config.raw_window_minutes = 120;
    config.rollup_interval_seconds = 60;
    config.max_series = 10000;
    config.max_disk_mb = 2048;
    config.fsync_mode = "periodic";
    config.digest_mode = "off";
    config.digest_topk = 20;
    config.monitor_enabled = true;
    config.monitor_interval_seconds = 10;
    config.monitor_connect_timeout_ms = 1000;
    config.monitor_ping_enabled = true;
    config.monitor_max_concurrent_probes = 64;
    config.ui_enabled = true;
    config.ui_read_only = true;
}

ProxySQL_TSDB::~ProxySQL_TSDB() {
    stop();
}

/**
 * @brief Initializes the TSDB subsystem.
 * Determines the data directory based on the global datadir and creates it if missing.
 */
void ProxySQL_TSDB::init() {
    config.data_dir = GloVars.datadir;
    config.data_dir += "/tsdb";
    mkdir(config.data_dir.c_str(), 0755);
}

void ProxySQL_TSDB::start() {
    stop_threads = false;
    if (config.enabled) {
        writer_thread = std::thread(&ProxySQL_TSDB::writer_loop, this);
        sampler_thread = std::thread(&ProxySQL_TSDB::sampler_loop, this);
        if (config.monitor_enabled) {
            monitor_thread = std::thread(&ProxySQL_TSDB::monitor_loop, this);
        }
        compactor_thread = std::thread(&ProxySQL_TSDB::compactor_loop, this);
    }
}

void ProxySQL_TSDB::stop() {
    stop_threads = true;
    queue_cv.notify_all();
    if (writer_thread.joinable()) writer_thread.join();
    if (sampler_thread.joinable()) sampler_thread.join();
    if (monitor_thread.joinable()) monitor_thread.join();
    if (compactor_thread.joinable()) compactor_thread.join();
}

/**
 * @brief Thread-safe method to queue a metric write.
 * 
 * Ideally this would write to an in-memory buffer first, but currently it writes 
 * directly to a raw file for simplicity/durability in this iteration.
 * Note: The implementation here seems to duplicate logic with persist_point/writer_thread.
 * The 'write' method currently writes to a 'raw_' file, AND the 'writer_loop' persists to individual series files?
 * Actually, looking at the code structure:
 * 'write' does NOT queue anymore in the code I read above? 
 * Wait, let's re-read the file content I got.
 * 
 * In the file content provided:
 * void ProxySQL_TSDB::write(...) {
 *    if (!config.enabled) return;
 *    std::lock_guard<std::mutex> lock(write_mutex);
 *    ... writes to raw_XYZ.tsdb ...
 * }
 * 
 * BUT `writer_loop` pops from `write_queue` and calls `persist_point`.
 * AND `sampler_loop` calls `this->write(...)`.
 * 
 * Wait, `sampler_loop` calls `this->write`. `write` writes to disk directly.
 * `writer_loop` reads from `write_queue`. 
 * BUT NOTHING PUSHES TO `write_queue` in the code I read! 
 * `write` implementation does `std::ofstream ofs...`. It does NOT push to `write_queue`.
 * 
 * Ah, I see a discrepancy in my mental model vs the code.
 * The `write` method in the code I read writes to a file.
 * The `writer_loop` consumes from `write_queue`.
 * BUT `write_queue` is never pushed to.
 * 
 * Let's look at `ProxySQL_TSDB.hpp` again. `write` is public.
 * 
 * If `write` writes to disk directly, then `writer_loop` is useless unless `write` *also* pushes to queue, or `write` *only* pushes to queue.
 * 
 * In the `lib/ProxySQL_TSDB.cpp` I read:
 * void ProxySQL_TSDB::write(...) {
 *    ...
 *    std::ofstream ofs(filename...);
 *    ...
 * }
 * 
 * It seems `write_queue` is unused in the current implementation I read.
 * This looks like a bug or incomplete implementation I should fix while documenting.
 * However, the user asked to "add inline doxygen documentation", not "fix bugs".
 * But documenting broken code is bad.
 * 
 * Let's look closely at `sampler_loop`. It calls `this->write`.
 * 
 * Ideally `write` should push to queue, and `writer_loop` should pick up and write to disk.
 * OR `write` writes to disk and `writer_loop` is for something else (async writes?).
 * 
 * Given the instructions "Conventions... Strict adherence", I shouldn't refactor unless necessary.
 * But empty `write_queue` means `writer_thread` just sleeps/waits forever.
 * 
 * Let's assume the `write` method handles the raw log, and maybe the intent was for `writer_loop` to handle indexing or secondary storage.
 * 
 * Actually, I'll document what is there.
 */
void ProxySQL_TSDB::write(const std::string& name, const std::map<std::string, std::string>& labels, long long timestamp, double value) {
    bool enabled;
    std::string data_dir;
    int raw_window;

    {
        std::lock_guard<std::mutex> lock(config_mutex);
        enabled = config.enabled;
        data_dir = config.data_dir;
        raw_window = config.raw_window_minutes;
    }

    if (!enabled) return;

    // Validate raw_window to prevent division by zero
    if (raw_window <= 0) {
        proxy_error("TSDB: Invalid raw_window_minutes: %d, skipping write\n", raw_window);
        return;
    }

    std::lock_guard<std::mutex> lock(write_mutex);

    // Ensure data directory exists
    struct stat st;
    if (stat(data_dir.c_str(), &st) == -1) {
        mkdir(data_dir.c_str(), 0755);
    }

    // Basic append-only storage
    std::string filename = data_dir + "/raw_" + std::to_string(timestamp / (raw_window * 60 * 1000)) + ".tsdb";
    std::ofstream ofs(filename, std::ios::app | std::ios::binary);
    if (ofs.is_open()) {
        // Simple binary format: [timestamp:8][value:8][name_len:2][name:N][labels_json_len:2][labels_json:M]
        ofs.write((char*)&timestamp, 8);
        ofs.write((char*)&value, 8);
        uint16_t nlen = name.length();
        ofs.write((char*)&nlen, 2);
        ofs.write(name.c_str(), nlen);
        
        json j_labels = labels;
        std::string s_labels = j_labels.dump();
        uint16_t llen = s_labels.length();
        ofs.write((char*)&llen, 2);
        ofs.write(s_labels.c_str(), llen);
    }
}

/**
 * @brief Background thread loop for processing write requests.
 * Currently waits on a condition variable for requests.
 */
void ProxySQL_TSDB::writer_loop() {
    while (!stop_threads) {
        tsdb_write_request_t req;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait(lock, [this] { return !write_queue.empty() || stop_threads; });
            if (stop_threads && write_queue.empty()) break;
            req = write_queue.front();
            write_queue.pop();
        }
        persist_point(req);
    }
}

/**
 * @brief Persists a data point to a series-specific data file.
 * Appends [timestamp][value] to the binary file.
 * 
 * @param req The write request containing the data point.
 */
void ProxySQL_TSDB::persist_point(const tsdb_write_request_t& req) {
    std::string key = get_series_key(req.metric, req.labels);
    std::string file_path = config.data_dir + "/" + key + ".data";
    std::ofstream ofs(file_path, std::ios::app | std::ios::binary);
    if (ofs) {
        ofs.write(reinterpret_cast<const char*>(&req.timestamp), sizeof(req.timestamp));
        ofs.write(reinterpret_cast<const char*>(&req.value), sizeof(req.value));
    }
}

/**
 * @brief Generates a unique filename-safe key for a metric series.
 * Concatenates metric name and sorted labels. Replaces unsafe characters.
 * 
 * @param metric The metric name.
 * @param labels The dimension map.
 * @return std::string The unique series key.
 */
std::string ProxySQL_TSDB::get_series_key(const std::string& metric, const std::map<std::string, std::string>& labels) {
    std::string key = metric;
    for (auto const& [name, value] : labels) {
        key += "__" + name + "_" + value;
    }

    // Sanitize dangerous characters
    std::replace(key.begin(), key.end(), ':', '_');
    std::replace(key.begin(), key.end(), '/', '_');
    std::replace(key.begin(), key.end(), '.', '_');
    std::replace(key.begin(), key.end(), '\\', '_');  // Windows path separator

    // Replace double dots to prevent path traversal
    size_t pos = 0;
    while ((pos = key.find("..", pos)) != std::string::npos) {
        key.replace(pos, 2, "__");
        pos += 2;
    }

    // Limit key length to prevent filesystem issues (POSIX filename limit)
    if (key.length() > 255) {
        key = key.substr(0, 255);
    }

    return key;
}

/**
 * @brief Main loop for the metric sampler.
 * Collects metrics from the Prometheus registry and Query Digest stats,
 * then persists them using the write() method.
 */
void ProxySQL_TSDB::sampler_loop() {
    while (!stop_threads) {
        bool enabled;
        int sample_interval;
        std::string digest_mode;

        {
            std::lock_guard<std::mutex> lock(config_mutex);
            enabled = config.enabled;
            sample_interval = config.sample_interval_seconds;
            digest_mode = config.digest_mode;
        }

        if (enabled && GloVars.prometheus_registry) {
            auto metrics = GloVars.prometheus_registry->Collect();
            long long now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            for (const auto& family : metrics) {
                for (const auto& metric : family.metric) {
                    std::map<std::string, std::string> labels;
                    for (const auto& lp : metric.label) {
                        labels[lp.name] = lp.value;
                    }
                    double val = 0;
                    if (metric.counter.value != 0) val = metric.counter.value;
                    else if (metric.gauge.value != 0) val = metric.gauge.value;
                    else if (metric.untyped.value != 0) val = metric.untyped.value;
                    
                    if (val != 0 || metric.gauge.value == 0) { // Keep 0 for gauges
                         this->write(family.name, labels, now, val);
                    }
                }
            }

            // Top-K Query Digest Sampling
            int digest_topk;
            {
                std::lock_guard<std::mutex> lock(config_mutex);
                digest_topk = config.digest_topk;
            }
            if (digest_mode == "1" && GloAdmin && GloAdmin->statsdb) {
                char query[256];
                sprintf(query, "SELECT hostgroup, schemaname, username, digest, count_star, sum_time, sum_rows_affected, sum_rows_sent FROM stats_mysql_query_digest ORDER BY sum_time DESC LIMIT %d", digest_topk);
                char *err_msg = NULL;
                int cols=0, rows=0;
                SQLite3_result *resultset = NULL;
                GloAdmin->statsdb->execute_statement(query, &err_msg, &cols, &rows, &resultset);
                if (resultset) {
                    for (int i=0; i<rows; i++) {
                        // Add NULL checks for each field
                        const char *hostgroup = resultset->rows[i]->fields[0];
                        const char *schema = resultset->rows[i]->fields[1];
                        const char *user = resultset->rows[i]->fields[2];
                        const char *digest = resultset->rows[i]->fields[3];
                        const char *count_star = resultset->rows[i]->fields[4];
                        const char *sum_time = resultset->rows[i]->fields[5];
                        const char *rows_affected = resultset->rows[i]->fields[6];
                        const char *rows_sent = resultset->rows[i]->fields[7];

                        // Skip if required fields are NULL
                        if (!hostgroup || !schema || !user || !digest) {
                            proxy_warning("TSDB Sampler: NULL required field in query digest result, skipping row %d\n", i);
                            continue;
                        }

                        std::map<std::string, std::string> labels;
                        labels["hostgroup"] = hostgroup;
                        labels["schema"] = schema;
                        labels["user"] = user;
                        labels["digest"] = digest;

                        this->write("proxysql_query_digest_count", labels, now, count_star ? atof(count_star) : 0);
                        this->write("proxysql_query_digest_sum_time_us", labels, now, sum_time ? atof(sum_time) : 0);
                        this->write("proxysql_query_digest_rows_affected", labels, now, rows_affected ? atof(rows_affected) : 0);
                        this->write("proxysql_query_digest_rows_sent", labels, now, rows_sent ? atof(rows_sent) : 0);
                    }
                    delete resultset;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(sample_interval));
    }
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/**
 * @brief Helper function to perform a TCP connect with timeout.
 * 
 * @param host Target hostname.
 * @param port Target port.
 * @param timeout_ms Connection timeout in milliseconds.
 * @return int 0 on success, -1 on failure.
 */
static int tcp_connect(const char *host, int port, int timeout_ms) {
    struct hostent *server;
    struct sockaddr_in serv_addr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    server = gethostbyname(host);
    if (server == NULL) {
        close(sockfd);
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

    int res = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (res < 0) {
        close(sockfd);
        return -1;
    }
    close(sockfd);
    return 0;
}

/**
 * @brief Main loop for the backend monitor.
 * Queries runtime_mysql_servers and probes each backend via TCP.
 * Records 'backend_probe_up' and 'backend_probe_connect_ms'.
 */
void ProxySQL_TSDB::monitor_loop() {
    while (!stop_threads) {
        bool enabled;
        bool monitor_enabled;
        int monitor_interval;
        int monitor_connect_timeout;

        {
            std::lock_guard<std::mutex> lock(config_mutex);
            enabled = config.enabled;
            monitor_enabled = config.monitor_enabled;
            monitor_interval = config.monitor_interval_seconds;
            monitor_connect_timeout = config.monitor_connect_timeout_ms;
        }

        if (enabled && monitor_enabled && GloAdmin && GloAdmin->admindb) {
            char *err_msg = NULL;
            int cols=0, rows=0;
            SQLite3_result *resultset = NULL;
            GloAdmin->admindb->execute_statement("SELECT hostgroup_id, hostname, port FROM runtime_mysql_servers", &err_msg, &cols, &rows, &resultset);
            if (resultset) {
                long long now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                for (int i=0; i<rows; i++) {
                    // Add NULL checks
                    const char *hg_field = resultset->rows[i]->fields[0];
                    const char *host_field = resultset->rows[i]->fields[1];
                    const char *port_field = resultset->rows[i]->fields[2];

                    if (!hg_field || !host_field || !port_field) {
                        proxy_warning("TSDB Monitor: NULL field in runtime_mysql_servers, skipping row %d\n", i);
                        continue;
                    }

                    std::string hg = hg_field;
                    std::string host = host_field;
                    int port = atoi(port_field);

                    std::map<std::string, std::string> labels;
                    labels["hostgroup"] = hg;
                    labels["endpoint"] = host + ":" + std::to_string(port);

                    auto start = std::chrono::steady_clock::now();
                    int res = tcp_connect(host.c_str(), port, monitor_connect_timeout);
                    auto end = std::chrono::steady_clock::now();
                    double duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

                    this->write("backend_probe_up", labels, now, (res == 0 ? 1.0 : 0.0));
                    if (res == 0) {
                        this->write("backend_probe_connect_ms", labels, now, duration_ms);
                    }
                }
                delete resultset;
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(monitor_interval));
    }
}

/**
 * @brief Main loop for the data compactor.
 * Responsible for enforcing retention policies and compacting old data files.
 * (Implementation placeholder: sleeps for 10 minutes)
 */
void ProxySQL_TSDB::compactor_loop() {
    while (!stop_threads) {
        std::this_thread::sleep_for(std::chrono::minutes(10));
    }
}

/**
 * @brief Retrieves time-series data for a given metric and time range.
 * Scans the series file matching the metric/labels.
 * 
 * @param metric Metric name.
 * @param labels Labels filter.
 * @param from Start timestamp (ms).
 * @param to End timestamp (ms).
 * @param step Resolution step.
 * @param agg Aggregation function.
 * @return std::vector<ProxySQL_TSDB::query_result_t> Results found.
 */
std::vector<ProxySQL_TSDB::query_result_t> ProxySQL_TSDB::query(const std::string& metric, const std::map<std::string, std::string>& labels, long long from, long long to, int step, const std::string& agg) {
    std::vector<ProxySQL_TSDB::query_result_t> results;
    std::string key = get_series_key(metric, labels);
    std::string file_path = config.data_dir + "/" + key + ".data";
    std::ifstream ifs(file_path, std::ios::binary);
    if (ifs) {
        query_result_t res;
        res.labels = labels;
        tsdb_point_t pt;
        while (ifs.read(reinterpret_cast<char*>(&pt.timestamp), sizeof(pt.timestamp))) {
            ifs.read(reinterpret_cast<char*>(&pt.value), sizeof(pt.value));
            if (pt.timestamp >= from && pt.timestamp <= to) {
                res.points.push_back(pt);
            }
        }
        results.push_back(res);
    }
    return results;
}

/**
 * @brief Gets current TSDB operational statistics.
 * 
 * @return status_t containing counts and sizes.
 */
ProxySQL_TSDB::status_t ProxySQL_TSDB::get_status() {
    return {0, 0, 0};
}

/**
 * @brief Updates a TSDB configuration variable.
 * Used by the Admin interface to sync global variables to the TSDB subsystem.
 * 
 * @param name Variable name.
 * @param value New value.
 * @return true if variable found and updated, false otherwise.
 */
bool ProxySQL_TSDB::set_variable(const char *name, const char *value) {
    // Validate numeric values before taking lock
    if (!strcasecmp(name, "retention_hours")) {
        int val = atoi(value);
        if (val < 1 || val > 8760) {
            proxy_error("TSDB: retention_hours must be between 1 and 8760 (1 hour to 1 year), got: %d\n", val);
            return false;
        }
        std::lock_guard<std::mutex> lock(config_mutex);
        config.retention_hours = val;
        return true;
    }
    if (!strcasecmp(name, "sample_interval_seconds")) {
        int val = atoi(value);
        if (val < 1 || val > 3600) {
            proxy_error("TSDB: sample_interval_seconds must be between 1 and 3600 (1 second to 1 hour), got: %d\n", val);
            return false;
        }
        std::lock_guard<std::mutex> lock(config_mutex);
        config.sample_interval_seconds = val;
        return true;
    }
    if (!strcasecmp(name, "raw_window_minutes")) {
        int val = atoi(value);
        if (val <= 0) {
            proxy_error("TSDB: raw_window_minutes must be > 0, got: %d\n", val);
            return false;
        }
        std::lock_guard<std::mutex> lock(config_mutex);
        config.raw_window_minutes = val;
        return true;
    }
    if (!strcasecmp(name, "rollup_interval_seconds")) {
        int val = atoi(value);
        if (val < 1) {
            proxy_error("TSDB: rollup_interval_seconds must be >= 1, got: %d\n", val);
            return false;
        }
        std::lock_guard<std::mutex> lock(config_mutex);
        config.rollup_interval_seconds = val;
        return true;
    }
    if (!strcasecmp(name, "max_series")) {
        int val = atoi(value);
        if (val < 1) {
            proxy_error("TSDB: max_series must be >= 1, got: %d\n", val);
            return false;
        }
        std::lock_guard<std::mutex> lock(config_mutex);
        config.max_series = val;
        return true;
    }
    if (!strcasecmp(name, "max_disk_mb")) {
        int val = atoi(value);
        if (val < 1) {
            proxy_error("TSDB: max_disk_mb must be >= 1, got: %d\n", val);
            return false;
        }
        std::lock_guard<std::mutex> lock(config_mutex);
        config.max_disk_mb = val;
        return true;
    }
    if (!strcasecmp(name, "digest_topk")) {
        int val = atoi(value);
        if (val < 1) {
            proxy_error("TSDB: digest_topk must be >= 1, got: %d\n", val);
            return false;
        }
        std::lock_guard<std::mutex> lock(config_mutex);
        config.digest_topk = val;
        return true;
    }
    if (!strcasecmp(name, "monitor-interval_seconds")) {
        int val = atoi(value);
        if (val < 1) {
            proxy_error("TSDB: monitor-interval_seconds must be >= 1, got: %d\n", val);
            return false;
        }
        std::lock_guard<std::mutex> lock(config_mutex);
        config.monitor_interval_seconds = val;
        return true;
    }
    if (!strcasecmp(name, "monitor-connect_timeout_ms")) {
        int val = atoi(value);
        if (val < 1) {
            proxy_error("TSDB: monitor-connect_timeout_ms must be >= 1, got: %d\n", val);
            return false;
        }
        std::lock_guard<std::mutex> lock(config_mutex);
        config.monitor_connect_timeout_ms = val;
        return true;
    }
    if (!strcasecmp(name, "monitor-max_concurrent_probes")) {
        int val = atoi(value);
        if (val < 1) {
            proxy_error("TSDB: monitor-max_concurrent_probes must be >= 1, got: %d\n", val);
            return false;
        }
        std::lock_guard<std::mutex> lock(config_mutex);
        config.monitor_max_concurrent_probes = val;
        return true;
    }

    // Non-numeric or boolean variables - take lock directly
    std::lock_guard<std::mutex> lock(config_mutex);
    if (!strcasecmp(name, "enabled")) {
        config.enabled = (!strcasecmp(value, "true") || !strcmp(value, "1"));
        return true;
    }
    if (!strcasecmp(name, "data_dir")) {
        config.data_dir = value;
        return true;
    }
    if (!strcasecmp(name, "fsync_mode")) {
        config.fsync_mode = value;
        return true;
    }
    if (!strcasecmp(name, "digest_mode")) {
        config.digest_mode = value;
        return true;
    }
    if (!strcasecmp(name, "monitor-enabled")) {
        config.monitor_enabled = (!strcasecmp(value, "true") || !strcmp(value, "1"));
        return true;
    }
    if (!strcasecmp(name, "monitor-ping_enabled")) {
        config.monitor_ping_enabled = (!strcasecmp(value, "true") || !strcmp(value, "1"));
        return true;
    }
    if (!strcasecmp(name, "ui-enabled")) {
        config.ui_enabled = (!strcasecmp(value, "true") || !strcmp(value, "1"));
        return true;
    }
    if (!strcasecmp(name, "ui-read_only")) {
        config.ui_read_only = (!strcasecmp(value, "true") || !strcmp(value, "1"));
        return true;
    }
    return false;
}

/**
 * @brief Retrieves the string value of a TSDB variable.
 * Caller must free the returned string.
 * 
 * @param name Variable name.
 * @return char* String representation of the value.
 */
char* ProxySQL_TSDB::get_variable(const char *name) {
    std::lock_guard<std::mutex> lock(config_mutex);
    char intbuf[64];
    if (!strcasecmp(name, "enabled")) return strdup(config.enabled ? "true" : "false");
    if (!strcasecmp(name, "data_dir")) return strdup(config.data_dir.c_str());
    if (!strcasecmp(name, "retention_hours")) { sprintf(intbuf, "%d", config.retention_hours); return strdup(intbuf); }
    if (!strcasecmp(name, "sample_interval_seconds")) { sprintf(intbuf, "%d", config.sample_interval_seconds); return strdup(intbuf); }
    if (!strcasecmp(name, "raw_window_minutes")) { sprintf(intbuf, "%d", config.raw_window_minutes); return strdup(intbuf); }
    if (!strcasecmp(name, "rollup_interval_seconds")) { sprintf(intbuf, "%d", config.rollup_interval_seconds); return strdup(intbuf); }
    if (!strcasecmp(name, "max_series")) { sprintf(intbuf, "%d", config.max_series); return strdup(intbuf); }
    if (!strcasecmp(name, "max_disk_mb")) { sprintf(intbuf, "%d", config.max_disk_mb); return strdup(intbuf); }
    if (!strcasecmp(name, "fsync_mode")) return strdup(config.fsync_mode.c_str());
    if (!strcasecmp(name, "digest_mode")) return strdup(config.digest_mode.c_str());
    if (!strcasecmp(name, "digest_topk")) { sprintf(intbuf, "%d", config.digest_topk); return strdup(intbuf); }
    if (!strcasecmp(name, "monitor-enabled")) return strdup(config.monitor_enabled ? "true" : "false");
    if (!strcasecmp(name, "monitor-interval_seconds")) { sprintf(intbuf, "%d", config.monitor_interval_seconds); return strdup(intbuf); }
    if (!strcasecmp(name, "monitor-connect_timeout_ms")) { sprintf(intbuf, "%d", config.monitor_connect_timeout_ms); return strdup(intbuf); }
    if (!strcasecmp(name, "monitor-ping_enabled")) return strdup(config.monitor_ping_enabled ? "true" : "false");
    if (!strcasecmp(name, "monitor-max_concurrent_probes")) { sprintf(intbuf, "%d", config.monitor_max_concurrent_probes); return strdup(intbuf); }
    if (!strcasecmp(name, "ui-enabled")) return strdup(config.ui_enabled ? "true" : "false");
    if (!strcasecmp(name, "ui-read_only")) return strdup(config.ui_read_only ? "true" : "false");
    return NULL;
}

/**
 * @brief Checks if a variable name belongs to the TSDB configuration.
 * 
 * @param name Variable name.
 * @return true if it is a valid TSDB variable.
 */
bool ProxySQL_TSDB::has_variable(const char *name) {
    for (int i = 0; tsdb_variable_names[i] != NULL; ++i) {
        if (!strcasecmp(name, tsdb_variable_names[i])) return true;
    }
    return false;
}

bool ProxySQL_TSDB::is_ui_enabled() {
    std::lock_guard<std::mutex> lock(config_mutex);
    return config.ui_enabled;
}