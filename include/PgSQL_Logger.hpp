#ifndef __CLASS_PGSQL_LOGGER_H
#define __CLASS_PGSQL_LOGGER_H
#include "proxysql.h"
#include "cpp.h"
#include <atomic>
#include <array>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class LogBuffer;
class LogBufferThreadContext;

#define PROXYSQL_LOGGER_PTHREAD_MUTEX

/**
 * @brief Counter metric indices for PostgreSQL advanced query logging.
 */
struct p_pl_counter {
	enum metric : uint8_t {
		memory_copy_count = 0,
		disk_copy_count,
		get_all_events_calls_count,
		get_all_events_events_count,
		total_memory_copy_time_us,
		total_disk_copy_time_us,
		total_get_all_events_time_us,
		total_events_copied_to_memory,
		total_events_copied_to_disk,
		circular_buffer_events_added_count,
		circular_buffer_events_dropped_count,
		SIZE_
	};
};

struct p_pl_gauge {
	enum metric : uint8_t {
		circular_buffer_events_size,
		SIZE_
	};
};

/**
 * @brief Metric map tuple indexes used by Prometheus helper initializers.
 */
struct pl_metrics_map_idx {
	enum index {
		counters = 0,
		gauges
	};
};

/**
 * @brief PostgreSQL event types captured by advanced logging.
 */
enum class PGSQL_LOG_EVENT_TYPE {
	SIMPLE_QUERY,
	AUTH_OK,
	AUTH_ERR,
	AUTH_CLOSE,
	AUTH_QUIT,
	INITDB,
	ADMIN_AUTH_OK,
	ADMIN_AUTH_ERR,
	ADMIN_AUTH_CLOSE,
	ADMIN_AUTH_QUIT,
	SQLITE_AUTH_OK,
	SQLITE_AUTH_ERR,
	SQLITE_AUTH_CLOSE,
	SQLITE_AUTH_QUIT,
	STMT_EXECUTE,
	STMT_DESCRIBE,
	STMT_PREPARE
};

/**
 * @brief Query or connection event payload written to PostgreSQL logs/sinks.
 */
class PgSQL_Event {
	private:
	uint32_t thread_id;
	char *username;
	char *schemaname;
	size_t username_len;
	size_t schemaname_len;
	size_t client_stmt_name_len;
	uint64_t start_time;
	uint64_t end_time;
	uint64_t query_digest;
	char *query_ptr;
	size_t query_len;
	char *server;
	char *client;
	size_t server_len;
	size_t client_len;
	//uint64_t total_length;
	unsigned char buf[10];
	PGSQL_LOG_EVENT_TYPE et;
	uint64_t hid;
	char *extra_info;
	char *client_stmt_name;
	bool have_affected_rows;
	bool have_rows_sent;

	uint64_t affected_rows;
	uint64_t rows_sent;
	char* sqlstate;
	char* errmsg;
	bool free_on_delete;
	bool free_error_on_delete;
	
	public:
		/**
		 * @brief Builds an event object using session/query context.
		 */
		PgSQL_Event(PGSQL_LOG_EVENT_TYPE _et, uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest, char *_client, size_t _client_len);
		/**
		 * @brief Deep-copy constructor used by circular buffer insertion.
		 */
		PgSQL_Event(const PgSQL_Event& other);
		/**
		 * @brief Copy assignment is disabled to prevent shallow pointer ownership bugs.
		 */
		PgSQL_Event& operator=(const PgSQL_Event&) = delete;
		/**
		 * @brief Frees event-owned allocations for deep-copied instances.
		 */
		~PgSQL_Event();
		/**
		 * @brief Serializes this event into the configured events/audit file format.
		 * @return Number of bytes written for binary format, 0 for JSON format.
		 */
		uint64_t write(LogBuffer *f, PgSQL_Session *sess);
		/**
		 * @brief Writes binary format payload for query events.
		 */
		uint64_t write_query_format_1(LogBuffer *f);
		/**
		 * @brief Writes JSON format payload for query events.
		 */
		uint64_t write_query_format_2_json(LogBuffer *f);
		/**
		 * @brief Writes JSON payload for authentication/audit events.
		 */
		void write_auth(LogBuffer *f, PgSQL_Session *sess);
		/**
		 * @brief Sets client prepared statement name associated with this event.
		 */
		void set_client_stmt_name(char* client_stmt_name);
	/**
	 * @brief Sets event query text and effective query length.
	 */
	void set_query(const char *ptr, int len);
	/**
	 * @brief Sets backend endpoint and hostgroup information.
	 */
	void set_server(int _hid, const char *ptr, int len);
	/**
	 * @brief Sets event extra info text payload.
	 */
	void set_extra_info(char *);
	/**
	 * @brief Sets affected rows flag/value for this event.
	 */
	void set_affected_rows(uint64_t ar);
	/**
	 * @brief Sets rows-sent flag/value for this event.
	 */
	void set_rows_sent(uint64_t rs);
	/**
	 * @brief Sets SQLSTATE and textual error information associated with this event.
	 * @param _sqlstate SQLSTATE code.
	 * @param _errmsg Error message string.
	 */
	void set_error(const char* _sqlstate, const char* _errmsg);
	friend class PgSQL_Logger;
};

/**
 * @brief Thread-safe circular buffer for advanced PostgreSQL query events logging.
 */
class PgSQL_Logger_CircularBuffer {
private:
	std::deque<PgSQL_Event*> event_buffer;
	std::mutex mutex;
	std::atomic<unsigned long long> eventsAddedCount;
	std::atomic<unsigned long long> eventsDroppedCount;

public:
	std::atomic<size_t> buffer_size;
	/**
	 * @brief Creates a bounded circular buffer with the supplied capacity.
	 */
	explicit PgSQL_Logger_CircularBuffer(size_t size);
	/**
	 * @brief Destroys the circular buffer and frees retained events.
	 */
	~PgSQL_Logger_CircularBuffer();
	/**
	 * @brief Inserts one event, evicting older entries when full.
	 */
	void insert(PgSQL_Event* event);
	/**
	 * @brief Drains all buffered events into @p events and clears the buffer.
	 */
	void get_all_events(std::vector<PgSQL_Event*>& events);
	/**
	 * @brief Returns current number of retained events.
	 */
	size_t size();
	/**
	 * @brief Returns configured buffer capacity.
	 */
	size_t getBufferSize() const;
	/**
	 * @brief Updates buffer capacity and drops oldest events if oversized.
	 */
	void setBufferSize(size_t newSize);
	/**
	 * @brief Returns total number of inserted events.
	 */
	unsigned long long getEventsAddedCount() const { return eventsAddedCount; }
	/**
	 * @brief Returns total number of dropped/evicted events.
	 */
	unsigned long long getEventsDroppedCount() const { return eventsDroppedCount; }
};

class PgSQL_Logger {
	private:
	struct {
		bool enabled;
		char *base_filename;
		char *datadir;
		unsigned int log_file_id;
		unsigned int current_log_size;
		unsigned int max_log_file_size;
		std::fstream *logfile;
		std::atomic<bool> logfile_open{false};
	} events;
	struct {
		bool enabled;
		char *base_filename;
		char *datadir;
		unsigned int log_file_id;
		unsigned int current_log_size;
		unsigned int max_log_file_size;
		std::fstream *logfile;
		std::atomic<bool> logfile_open{false};
	} audit;
		/**
		 * @brief Accumulated runtime metrics for PostgreSQL advanced events logging.
		 */
	struct EventLogMetrics {
		std::atomic<unsigned long long> memoryCopyCount;
		std::atomic<unsigned long long> diskCopyCount;
		std::atomic<unsigned long long> getAllEventsCallsCount;
		std::atomic<unsigned long long> getAllEventsEventsCount;
		std::atomic<unsigned long long> totalMemoryCopyTimeMicros;
		std::atomic<unsigned long long> totalDiskCopyTimeMicros;
		std::atomic<unsigned long long> totalGetAllEventsTimeMicros;
		std::atomic<unsigned long long> totalEventsCopiedToMemory;
		std::atomic<unsigned long long> totalEventsCopiedToDisk;
	} metrics;

		struct {
			std::atomic<unsigned long long> total_queries_logged { 0 };
			prometheus::Counter* p_queries_logged_total { nullptr };
			std::array<prometheus::Counter*, p_pl_counter::SIZE_> p_counter_array {};
			std::array<prometheus::Gauge*, p_pl_gauge::SIZE_> p_gauge_array {};
		} prom_metrics;
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_t wmutex;
#else
	rwlock_t rwlock;
#endif
	std::unordered_map<pthread_t, std::unique_ptr<LogBufferThreadContext>> log_thread_contexts;
 	std::mutex log_thread_contexts_lock;

 	LogBufferThreadContext* get_log_thread_context();
 	bool is_events_logfile_open() const;
 	void set_events_logfile_open(bool open);
 	bool is_audit_logfile_open() const;
 	void set_audit_logfile_open(bool open);
	void events_close_log_unlocked();
	void events_open_log_unlocked();
	void audit_close_log_unlocked();
	void audit_open_log_unlocked();
	unsigned int events_find_next_id();
	unsigned int audit_find_next_id();
	public:
	/**
	 * @brief Constructs PostgreSQL logger state, circular buffer, and metrics.
	 */
	PgSQL_Logger();
	/**
	 * @brief Destroys logger-owned resources and buffered events.
	 */
	~PgSQL_Logger();
	void print_version();
	void flush_log();
	void events_flush_log_unlocked();
	void audit_flush_log_unlocked();
	void events_set_datadir(char *);
	void events_set_base_filename();
	void audit_set_datadir(char *);
	void audit_set_base_filename();
	void log_request(PgSQL_Session *, PgSQL_Data_Stream *);
	void log_audit_entry(PGSQL_LOG_EVENT_TYPE, PgSQL_Session *, PgSQL_Data_Stream *, char *e = NULL);
	void flush(bool force = false);
	void p_update_metrics();
	void wrlock();
	void wrunlock();
	PgSQL_Logger_CircularBuffer* PgLogCB;

	/**
	 * @brief Inserts PostgreSQL events into a SQLite table using bulk prepared statements.
	 */
	void insertPgSQLEventsIntoDb(SQLite3DB* db, const std::string& tableName, size_t numEvents, std::vector<PgSQL_Event*>::const_iterator begin);

	/**
	 * @brief Drains buffered PostgreSQL events and writes them to memory and/or disk stats tables.
	 * @return Number of drained events.
	 */
	int processEvents(SQLite3DB* statsdb, SQLite3DB* statsdb_disk);

	/**
	 * @brief Returns all PostgreSQL logger metrics for stats table export.
	 */
	std::unordered_map<std::string, unsigned long long> getAllMetrics() const;

};

#endif /* __CLASS_PGSQL_LOGGER_H */
