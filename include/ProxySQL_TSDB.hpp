#ifndef CLASS_PROXYSQL_TSDB_H
#define CLASS_PROXYSQL_TSDB_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <queue>
#include <condition_variable>

struct tsdb_point_t {
    long long timestamp;
    double value;
};

struct tsdb_write_request_t {
    std::string metric;
    std::map<std::string, std::string> labels;
    long long timestamp;
    double value;
};

struct TSDB_Config {
    bool enabled;
    std::string data_dir;
    int retention_hours;
    int sample_interval_seconds;
    int raw_window_minutes;
    int rollup_interval_seconds;
    int max_series;
    int max_disk_mb;
    std::string fsync_mode;
    std::string digest_mode;
    int digest_topk;
    
    // Monitor configs
    bool monitor_enabled;
    int monitor_interval_seconds;
    int monitor_connect_timeout_ms;
    bool monitor_ping_enabled;
    int monitor_max_concurrent_probes;
    
    // UI configs
    bool ui_enabled;
    bool ui_read_only;
};

class ProxySQL_TSDB {
private:
    TSDB_Config config;
    std::mutex write_mutex;
    std::atomic<bool> stop_threads;
    
    std::thread writer_thread;
    std::thread sampler_thread;
    std::thread monitor_thread;
    std::thread compactor_thread;

    std::queue<tsdb_write_request_t> write_queue;
    std::mutex queue_mutex;
    std::condition_variable queue_cv;

    void writer_loop();
    void sampler_loop();
    void monitor_loop();
    void compactor_loop();

    // Storage internal methods
    std::string get_series_key(const std::string& metric, const std::map<std::string, std::string>& labels);
    void persist_point(const tsdb_write_request_t& req);

public:
    ProxySQL_TSDB();
    ~ProxySQL_TSDB();
    void init();
    void start();
    void stop();

    void write(const std::string& metric, const std::map<std::string, std::string>& labels, long long timestamp, double value);
    
    struct query_result_t {
        std::map<std::string, std::string> labels;
        std::vector<tsdb_point_t> points;
    };
    std::vector<query_result_t> query(const std::string& metric, const std::map<std::string, std::string>& labels, long long from, long long to, int step, const std::string& agg);
    
    struct status_t {
        size_t series_count;
        size_t disk_usage_bytes;
        long long last_compaction_ts;
    };
    status_t get_status();

    // Configuration management
    bool set_variable(const char *name, const char *value);
    char* get_variable(const char *name);
    bool has_variable(const char *name);
};

extern ProxySQL_TSDB *GloTSDB;

#endif