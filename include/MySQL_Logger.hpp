#ifndef __CLASS_MYSQL_LOGGER_H
#define __CLASS_MYSQL_LOGGER_H
#include "proxysql.h"
#include "cpp.h"
#include <atomic>

#define PROXYSQL_LOGGER_PTHREAD_MUTEX

class MySQL_Logger;

class MySQL_Event {
	private:
	uint32_t thread_id;
	char *username;
	char *schemaname;
	size_t username_len;
	size_t schemaname_len;
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
	enum log_event_type et;
	uint64_t hid;
	char *extra_info;
	bool have_affected_rows;
	bool have_rows_sent;
	bool have_gtid;
	bool free_on_delete; // this bool defines if pointers should be freed when the destructor is called
	uint64_t affected_rows;
	uint64_t last_insert_id;
	uint64_t rows_sent;
	uint32_t client_stmt_id;
	const char * gtid;
	public:
	MySQL_Event(log_event_type _et, uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest, char *_client, size_t _client_len);
	MySQL_Event(const MySQL_Event &other);
	~MySQL_Event();
	uint64_t write(std::fstream *f, MySQL_Session *sess);
	uint64_t write_query_format_1(std::fstream *f);
	uint64_t write_query_format_2_json(std::fstream *f);
	void write_auth(std::fstream *f, MySQL_Session *sess);
	void set_client_stmt_id(uint32_t client_stmt_id);
	void set_query(const char *ptr, int len);
	void set_server(int _hid, const char *ptr, int len);
	void set_extra_info(char *);
	void set_affected_rows(uint64_t ar, uint64_t lid);
	void set_rows_sent(uint64_t rs);
	void set_gtid(MySQL_Session *sess);
	friend MySQL_Logger;
};

/**
 * @class MySQL_Logger_CircularBuffer
 * @brief A thread-safe circular buffer for storing MySQL events.
 *
 * This class implements a circular buffer that stores pointers to MySQL_Event objects.
 * It provides thread-safe methods for inserting events and retrieving all stored events.
 * The buffer automatically manages memory for the stored events.  Once an event is inserted, the buffer assumes ownership.
 */
class MySQL_Logger_CircularBuffer {
private:
	std::deque<MySQL_Event*> event_buffer;  ///< The internal deque storing event pointers.
	std::mutex mutex;                        ///< Mutex for thread safety.

public:
	std::atomic<size_t> buffer_size;        ///< Atomic variable to store the buffer size. (Public for direct access)
	/**
	 * @brief Constructor for the MySQL_Logger_CircularBuffer class.
	 * @param size The initial size of the circular buffer.
	 */
	MySQL_Logger_CircularBuffer(size_t size);

	/**
	 * @brief Destructor for the MySQL_Logger_CircularBuffer class.
	 *
	 * This destructor deallocates the memory used by the buffer and the MySQL_Event objects it contains.
	 */
	~MySQL_Logger_CircularBuffer();

	/**
	 * @brief Inserts a new MySQL_Event into the circular buffer.
	 * @param event A pointer to the MySQL_Event object to insert.  The buffer takes ownership.
	 *
	 * If the buffer is full, the oldest event is removed before inserting the new event.
	 */
	void insert(MySQL_Event* event);

	/**
	 * @brief Retrieves all events from the circular buffer and populates a provided vector.
	 * @param events A reference to a vector that will be populated with the events from the buffer.  The caller takes ownership of the events and is responsible for deleting them.
	 *
	 * This method clears the buffer after retrieving the events.  The function reserves space in the vector to avoid unnecessary reallocations.
	 */
	void get_all_events(std::vector<MySQL_Event*>& events);


	/**
	 * @brief Gets the current size of the buffer.
	 * @return The current size of the circular buffer.
	 */
	size_t getBufferSize() const;

	/**
	 * @brief Sets the size of the buffer.
	 * @param newSize The new size of the circular buffer.
	 */
	void setBufferSize(size_t newSize);
};



class MySQL_Logger {
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
	int eventslog_table_memory_size;
	MySQL_Logger();
	~MySQL_Logger();
	void print_version();
	void flush_log();
	void events_flush_log_unlocked();
	void audit_flush_log_unlocked();
	void events_set_datadir(char *);
	void events_set_base_filename();
	void audit_set_datadir(char *);
	void audit_set_base_filename();
	void log_request(MySQL_Session *, MySQL_Data_Stream *);
	void log_audit_entry(log_event_type, MySQL_Session *, MySQL_Data_Stream *, char *e = NULL);
	void flush();
	void wrlock();
	void wrunlock();
	MySQL_Logger_CircularBuffer * MyLogCB;
	/**
	 * @brief Inserts a batch of MySQL events into a specified SQLite table.
	 * @param db A pointer to the SQLite3DB object representing the database connection.
	 * @param tableName The name of the SQLite table to insert into.
	 * @param numEvents The number of events to insert.
	 * @param begin An iterator pointing to the beginning of the range of MySQL_Event* in the vector to insert.
	 * @return 0 if the insertion was successful, a negative error code otherwise.
	 *
	 * This function inserts a batch of MySQL events into the specified SQLite table using bulk insert techniques for efficiency.
	 * It handles the conversion of MySQL_Event data to a format suitable for SQLite insertion.  Error handling includes logging of errors.
	 * The function uses a prepared statement for bulk insertion.
	 * The function assumes that the provided events have been allocated with `new` and will not be deleted by this function.
	 */
	void insertMysqlEventsIntoDb(SQLite3DB * db, const std::string& tableName, size_t numEvents, std::vector<MySQL_Event*>::const_iterator begin);
	/**
	 * @brief Processes and inserts MySQL events into in-memory and/or on-disk SQLite databases.
	 * @param statsdb A pointer to the SQLite3DB object for the in-memory database (can be nullptr).
	 * @param statsdb_disk A pointer to the SQLite3DB object for the on-disk database (can be nullptr).
	 * @return The number of events processed. Returns a negative value if an error occurs.
	 *
	 * This function retrieves events from the circular buffer, handles in-memory table size limits, and inserts them into the specified SQLite databases.
	 * If either statsdb or statsdb_disk is nullptr, events are only written to the other database.
     * It handles in-memory table size limits by deleting existing entries if necessary.
	 * The function ensures that the in-memory table size does not exceed a predefined limit (`eventslog_table_memory_size`).
	 * The function assumes ownership of the MySQL_Event pointers and deletes them after processing.
	 */
	int processEvents(SQLite3DB * statsdb , SQLite3DB * statsdb_disk);
};


#endif /* __CLASS_MYSQL_LOGGER_H */
