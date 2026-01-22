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

void ProxySQL_TSDB::write(const std::string& name, const std::map<std::string, std::string>& labels, long long timestamp, double value) {
    if (!config.enabled) return;
    std::lock_guard<std::mutex> lock(write_mutex);
    
    // Ensure data directory exists
    struct stat st;
    if (stat(config.data_dir.c_str(), &st) == -1) {
        mkdir(config.data_dir.c_str(), 0755);
    }

    // Basic append-only storage
    std::string filename = config.data_dir + "/raw_" + std::to_string(timestamp / (config.raw_window_minutes * 60 * 1000)) + ".tsdb";
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

void ProxySQL_TSDB::persist_point(const tsdb_write_request_t& req) {
    std::string key = get_series_key(req.metric, req.labels);
    std::string file_path = config.data_dir + "/" + key + ".data";
    std::ofstream ofs(file_path, std::ios::app | std::ios::binary);
    if (ofs) {
        ofs.write(reinterpret_cast<const char*>(&req.timestamp), sizeof(req.timestamp));
        ofs.write(reinterpret_cast<const char*>(&req.value), sizeof(req.value));
    }
}

std::string ProxySQL_TSDB::get_series_key(const std::string& metric, const std::map<std::string, std::string>& labels) {
    std::string key = metric;
    for (auto const& [name, value] : labels) {
        key += "__" + name + "_" + value;
    }
    std::replace(key.begin(), key.end(), ':', '_');
    std::replace(key.begin(), key.end(), '/', '_');
    std::replace(key.begin(), key.end(), '.', '_');
    return key;
}

void ProxySQL_TSDB::sampler_loop() {
    while (!stop_threads) {
        if (config.enabled && GloVars.prometheus_registry) {
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
            if (config.digest_mode == "1" && GloAdmin && GloAdmin->statsdb) {
                char query[256];
                sprintf(query, "SELECT hostgroup, schemaname, username, digest, count_star, sum_time, sum_rows_affected, sum_rows_sent FROM stats_mysql_query_digest ORDER BY sum_time DESC LIMIT %d", config.digest_topk);
                char *err_msg = NULL;
                int cols=0, rows=0;
                SQLite3_result *resultset = NULL;
                GloAdmin->statsdb->execute_statement(query, &err_msg, &cols, &rows, &resultset);
                if (resultset) {
                    for (int i=0; i<rows; i++) {
                        std::map<std::string, std::string> labels;
                        labels["hostgroup"] = resultset->rows[i]->fields[0];
                        labels["schema"] = resultset->rows[i]->fields[1];
                        labels["user"] = resultset->rows[i]->fields[2];
                        labels["digest"] = resultset->rows[i]->fields[3];
                        
                        this->write("proxysql_query_digest_count", labels, now, atof(resultset->rows[i]->fields[4]));
                        this->write("proxysql_query_digest_sum_time_us", labels, now, atof(resultset->rows[i]->fields[5]));
                        this->write("proxysql_query_digest_rows_affected", labels, now, atof(resultset->rows[i]->fields[6]));
                        this->write("proxysql_query_digest_rows_sent", labels, now, atof(resultset->rows[i]->fields[7]));
                    }
                    delete resultset;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(config.sample_interval_seconds));
    }
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

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

void ProxySQL_TSDB::monitor_loop() {
    while (!stop_threads) {
        if (config.enabled && config.monitor_enabled && GloAdmin && GloAdmin->admindb) {
            char *err_msg = NULL;
            int cols=0, rows=0;
            SQLite3_result *resultset = NULL;
            GloAdmin->admindb->execute_statement("SELECT hostgroup_id, hostname, port FROM runtime_mysql_servers", &err_msg, &cols, &rows, &resultset);
            if (resultset) {
                long long now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                for (int i=0; i<rows; i++) {
                    std::string hg = resultset->rows[i]->fields[0];
                    std::string host = resultset->rows[i]->fields[1];
                    int port = atoi(resultset->rows[i]->fields[2]);
                    
                    std::map<std::string, std::string> labels;
                    labels["hostgroup"] = hg;
                    labels["endpoint"] = host + ":" + std::to_string(port);
                    
                    auto start = std::chrono::steady_clock::now();
                    int res = tcp_connect(host.c_str(), port, config.monitor_connect_timeout_ms);
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
        std::this_thread::sleep_for(std::chrono::seconds(config.monitor_interval_seconds));
    }
}

void ProxySQL_TSDB::compactor_loop() {
    while (!stop_threads) {
        std::this_thread::sleep_for(std::chrono::minutes(10));
    }
}

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

ProxySQL_TSDB::status_t ProxySQL_TSDB::get_status() {
    return {0, 0, 0};
}

bool ProxySQL_TSDB::set_variable(const char *name, const char *value) {
    if (!strcasecmp(name, "enabled")) {
        config.enabled = (!strcasecmp(value, "true") || !strcmp(value, "1"));
        return true;
    }
    if (!strcasecmp(name, "data_dir")) {
        config.data_dir = value;
        return true;
    }
    if (!strcasecmp(name, "retention_hours")) {
        config.retention_hours = atoi(value);
        return true;
    }
    if (!strcasecmp(name, "sample_interval_seconds")) {
        config.sample_interval_seconds = atoi(value);
        return true;
    }
    if (!strcasecmp(name, "raw_window_minutes")) {
        config.raw_window_minutes = atoi(value);
        return true;
    }
    if (!strcasecmp(name, "rollup_interval_seconds")) {
        config.rollup_interval_seconds = atoi(value);
        return true;
    }
    if (!strcasecmp(name, "max_series")) {
        config.max_series = atoi(value);
        return true;
    }
    if (!strcasecmp(name, "max_disk_mb")) {
        config.max_disk_mb = atoi(value);
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
    if (!strcasecmp(name, "digest_topk")) {
        config.digest_topk = atoi(value);
        return true;
    }
    if (!strcasecmp(name, "monitor-enabled")) {
        config.monitor_enabled = (!strcasecmp(value, "true") || !strcmp(value, "1"));
        return true;
    }
    if (!strcasecmp(name, "monitor-interval_seconds")) {
        config.monitor_interval_seconds = atoi(value);
        return true;
    }
    if (!strcasecmp(name, "monitor-connect_timeout_ms")) {
        config.monitor_connect_timeout_ms = atoi(value);
        return true;
    }
    if (!strcasecmp(name, "monitor-ping_enabled")) {
        config.monitor_ping_enabled = (!strcasecmp(value, "true") || !strcmp(value, "1"));
        return true;
    }
    if (!strcasecmp(name, "monitor-max_concurrent_probes")) {
        config.monitor_max_concurrent_probes = atoi(value);
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

char* ProxySQL_TSDB::get_variable(const char *name) {
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

bool ProxySQL_TSDB::has_variable(const char *name) {
    for (int i = 0; tsdb_variable_names[i] != NULL; ++i) {
        if (!strcasecmp(name, tsdb_variable_names[i])) return true;
    }
    return false;
}