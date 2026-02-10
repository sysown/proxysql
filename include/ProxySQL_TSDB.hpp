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

/**
 * @brief Represents a single data point in the Time Series Database.
 */
struct tsdb_point_t {
    long long timestamp;    /**< Timestamp in milliseconds since epoch */
    double value;           /**< The value of the metric */
};

/**
 * @brief Represents a write request to be processed by the writer thread.
 */
struct tsdb_write_request_t {
    std::string metric;                         /**< Name of the metric */
    std::map<std::string, std::string> labels;  /**< Key-value pairs for dimensions */
    long long timestamp;                        /**< Timestamp in milliseconds */
    double value;                               /**< Value to record */
};

/**
 * @brief Configuration structure for the embedded TSDB subsystem.
 * Holds all tunable parameters for retention, sampling, and monitoring.
 */
struct TSDB_Config {
    bool enabled;                       /**< Master switch for the TSDB subsystem */
    std::string data_dir;               /**< Directory where TSDB data files are stored */
    int retention_hours;                /**< How long to keep data in hours */
    int sample_interval_seconds;        /**< Frequency of internal metric sampling */
    int raw_window_minutes;             /**< Duration of the raw data write buffer window */
    int rollup_interval_seconds;        /**< Interval for aggregating raw data */
    int max_series;                     /**< Maximum number of unique series allowed */
    int max_disk_mb;                    /**< Maximum disk usage in Megabytes */
    std::string fsync_mode;             /**< File sync strategy: 'periodic' or 'always' */
    std::string digest_mode;            /**< Query digest collection mode */
    int digest_topk;                    /**< Number of top queries to track */
    
    // Monitor configs
    bool monitor_enabled;               /**< Enable active backend monitoring */
    int monitor_interval_seconds;       /**< Frequency of backend health probes */
    int monitor_connect_timeout_ms;     /**< Timeout for TCP connect probes */
    bool monitor_ping_enabled;          /**< Enable MySQL Ping probes */
    int monitor_max_concurrent_probes;  /**< Concurrency limit for probes */
    
    // UI configs
    bool ui_enabled;                    /**< Enable the embedded web dashboard */
    bool ui_read_only;                  /**< Restrict UI to read-only mode */
};

/**
 * @class ProxySQL_TSDB
 * @brief Main class for the embedded Time Series Database in ProxySQL.
 * 
 * This class manages the lifecycle of the TSDB subsystem, including:
 * - Data ingestion (writes)
 * - Background sampling of internal metrics
 * - Active monitoring of backend targets
 * - Data compaction and retention enforcement
 * - Querying and retrieval of time-series data
 */
class ProxySQL_TSDB {
private:
    TSDB_Config config;
    std::mutex config_mutex;  // Protects config access from multiple threads
    std::mutex write_mutex;
    std::atomic<bool> stop_threads;
    
    std::thread writer_thread;
    std::thread sampler_thread;
    std::thread monitor_thread;
    std::thread compactor_thread;

    std::queue<tsdb_write_request_t> write_queue;
    std::mutex queue_mutex;
    std::condition_variable queue_cv;

    /**
     * @brief Main loop for the writer thread.
     * Consumes write requests from the queue and persists them to disk.
     */
    void writer_loop();

    /**
     * @brief Main loop for the sampler thread.
     * Periodically collects internal ProxySQL metrics (Prometheus & Query Digest)
     * and queues them for storage.
     */
    void sampler_loop();

    /**
     * @brief Main loop for the monitor thread.
     * Performs active health checks (TCP connect, Ping) against backend servers.
     */
    void monitor_loop();

    /**
     * @brief Main loop for the compactor thread.
     * Handles data retention enforcement and file compaction.
     */
    void compactor_loop();

    // Storage internal methods
    /**
     * @brief Generates a unique series key from metric name and labels.
     * @param metric Name of the metric.
     * @param labels Map of label key-value pairs.
     * @return A unique string identifier for the series.
     */
    std::string get_series_key(const std::string& metric, const std::map<std::string, std::string>& labels);

    /**
     * @brief Persists a single data point to the append-only log.
     * @param req The write request containing data to persist.
     */
    void persist_point(const tsdb_write_request_t& req);

public:
    /**
     * @brief Constructor. Initializes default configuration.
     */
    ProxySQL_TSDB();

    /**
     * @brief Destructor. Stops threads and cleans up resources.
     */
    ~ProxySQL_TSDB();

    /**
     * @brief Initializes the TSDB subsystem (e.g., creates directories).
     */
    void init();

    /**
     * @brief Starts all background threads (Writer, Sampler, Monitor, Compactor).
     */
    void start();

    /**
     * @brief Stops all background threads gracefully.
     */
    void stop();

    /**
     * @brief Enqueues a metric for writing to the TSDB.
     * @param metric Name of the metric.
     * @param labels Dimensions associated with the metric.
     * @param timestamp Timestamp in milliseconds.
     * @param value The numerical value.
     */
    void write(const std::string& metric, const std::map<std::string, std::string>& labels, long long timestamp, double value);
    
    /**
     * @brief Structure representing the result of a TSDB query.
     */
    struct query_result_t {
        std::map<std::string, std::string> labels;  /**< Labels identifying the series */
        std::vector<tsdb_point_t> points;           /**< Vector of time-value pairs */
    };

    /**
     * @brief Queries the TSDB for data points.
     * @param metric Metric name to query.
     * @param labels Filters for labels (exact match).
     * @param from Start timestamp (ms).
     * @param to End timestamp (ms).
     * @param step Resolution step (not currently implemented fully).
     * @param agg Aggregation function (e.g., "sum", "avg").
     * @return A vector of query results matching the criteria.
     */
    std::vector<query_result_t> query(const std::string& metric, const std::map<std::string, std::string>& labels, long long from, long long to, int step, const std::string& agg);
    
    /**
     * @brief Structure for reporting TSDB internal status.
     */
    struct status_t {
        size_t series_count;        /**< Number of active series */
        size_t disk_usage_bytes;    /**< Total disk usage in bytes */
        long long last_compaction_ts; /**< Timestamp of last compaction run */
    };

    /**
     * @brief Retrieves the current status of the TSDB.
     * @return status_t struct containing metrics.
     */
    status_t get_status();

    // Configuration management
    /**
     * @brief Sets a configuration variable for TSDB.
     * @param name Variable name (e.g., "retention_hours").
     * @param value New value as string.
     * @return true if successful, false otherwise.
     */
    bool set_variable(const char *name, const char *value);

    /**
     * @brief Gets the current value of a configuration variable.
     * @param name Variable name.
     * @return String pointer to value (must be freed by caller), or NULL if not found.
     */
    char* get_variable(const char *name);

    /**
     * @brief Checks if a variable exists in the TSDB configuration.
     * @param name Variable name.
     * @return true if the variable exists.
     */
    bool has_variable(const char *name);

    /**
     * @brief Checks if the TSDB UI is enabled.
     * @return true if the UI is enabled.
     */
    bool is_ui_enabled();
};

/**
 * @brief Global pointer to the singleton instance of ProxySQL_TSDB.
 */
extern ProxySQL_TSDB *GloTSDB;

#endif