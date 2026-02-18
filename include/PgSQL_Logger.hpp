#ifndef __CLASS_PGSQL_LOGGER_H
#define __CLASS_PGSQL_LOGGER_H
#include "proxysql.h"
#include "cpp.h"
#include <atomic>
#include <array>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#define PROXYSQL_LOGGER_PTHREAD_MUTEX

struct p_pl_counter {
	enum metric {
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
		__size
	};
};

struct p_pl_gauge {
	enum metric {
		circular_buffer_events_size,
		__size
	};
};

struct pl_metrics_map_idx {
	enum index {
		counters = 0,
		gauges
	};
};

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
	
	public:
	PgSQL_Event(PGSQL_LOG_EVENT_TYPE _et, uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest, char *_client, size_t _client_len);
	PgSQL_Event(const PgSQL_Event& other);
	~PgSQL_Event();
	uint64_t write(std::fstream *f, PgSQL_Session *sess);
	uint64_t write_query_format_1(std::fstream *f);
	uint64_t write_query_format_2_json(std::fstream *f);
	void write_auth(std::fstream *f, PgSQL_Session *sess);
	void set_client_stmt_name(char* client_stmt_name);
	void set_query(const char *ptr, int len);
	void set_server(int _hid, const char *ptr, int len);
	void set_extra_info(char *);
	void set_affected_rows(uint64_t ar);
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
	explicit PgSQL_Logger_CircularBuffer(size_t size);
	~PgSQL_Logger_CircularBuffer();
	void insert(PgSQL_Event* event);
	void get_all_events(std::vector<PgSQL_Event*>& events);
	size_t size();
	size_t getBufferSize() const;
	void setBufferSize(size_t newSize);
	unsigned long long getEventsAddedCount() const { return eventsAddedCount; }
	unsigned long long getEventsDroppedCount() const { return eventsDroppedCount; }
};

class PgSQL_Logger {
	private:
	struct {
		bool enabled;
		char *base_filename;
		char *datadir;
		unsigned int log_file_id;
		unsigned int max_log_file_size;
		std::fstream *logfile;
	} events;
	struct {
		bool enabled;
		char *base_filename;
		char *datadir;
		unsigned int log_file_id;
		unsigned int max_log_file_size;
		std::fstream *logfile;
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
		std::array<prometheus::Counter*, p_pl_counter::__size> p_counter_array {};
		std::array<prometheus::Gauge*, p_pl_gauge::__size> p_gauge_array {};
	} prom_metrics;

#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_t wmutex;
#else
	rwlock_t rwlock;
#endif
	void events_close_log_unlocked();
	void events_open_log_unlocked();
	void audit_close_log_unlocked();
	void audit_open_log_unlocked();
	unsigned int events_find_next_id();
	unsigned int audit_find_next_id();
	public:
	PgSQL_Logger();
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
	void flush();
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

	/**
	 * @brief Prometheus serial exposer update hook for PostgreSQL logger metrics.
	 */
	void p_update_metrics();
};

#endif /* __CLASS_PGSQL_LOGGER_H */
