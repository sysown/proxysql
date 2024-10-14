#ifndef __CLASS_MYSQL_LOGGER_H
#define __CLASS_MYSQL_LOGGER_H
#include "proxysql.h"
#include "cpp.h"
#include <atomic>

#define PROXYSQL_LOGGER_PTHREAD_MUTEX

class MySQL_Logger;


/**
 * @class MySQL_Event
 * @brief Represents a single event logged by the MySQL logger.
 *
 * This class encapsulates information about a MySQL event, including the query, timestamps, user information, and other relevant details.
 *  It provides methods for writing the event data to a file in different formats (binary and JSON).  The class manages memory dynamically allocated for its members.
 */
class MySQL_Event {
private:
	uint32_t thread_id;        ///< The ID of the thread that executed the query.
	char* username;            ///< The username associated with the query.  Memory managed by the class.
	char* schemaname;          ///< The schema name associated with the query. Memory managed by the class.
	size_t username_len;       ///< Length of the username string.
	size_t schemaname_len;     ///< Length of the schema name string.
	uint64_t start_time;       ///< Start time of the query in microseconds.
	uint64_t end_time;         ///< End time of the query in microseconds.
	uint64_t query_digest;     ///< Digest of the query.
	char* query_ptr;           ///< Pointer to the query string. Memory managed by the class.
	size_t query_len;          ///< Length of the query string.
	char* server;              ///< Server address. Memory managed by the class.
	char* client;              ///< Client address. Memory managed by the class.
	size_t server_len;         ///< Length of the server address.
	size_t client_len;         ///< Length of the client address.
	unsigned char buf[10];     ///< Buffer for encoding lengths.
	enum log_event_type et;    ///< Type of the event.
	uint64_t hid;              ///< Hostgroup ID.
	char* extra_info;          ///< Additional information about the event. Memory managed by the class.
	bool have_affected_rows;   ///< Flag indicating if affected rows are available.
	bool have_rows_sent;       ///< Flag indicating if rows sent are available.
	bool have_gtid;            ///< Flag indicating if GTID is available.
	bool free_on_delete;       ///< Flag indicating whether to free memory in the destructor.
	uint64_t affected_rows;    ///< Number of rows affected by the query.
	uint64_t last_insert_id;   ///< Last insert ID.
	uint64_t rows_sent;        ///< Number of rows sent.
	uint32_t client_stmt_id;   ///< Client statement ID.
	const char* gtid;          ///< GTID.

public:
	/**
	 * @brief Constructor for the MySQL_Event class.
	 * @param _et The type of the event.
	 * @param _thread_id The ID of the thread that executed the query.
	 * @param _username The username associated with the query.
	 * @param _schemaname The schema name associated with the query.
	 * @param _start_time The start time of the query in microseconds.
	 * @param _end_time The end time of the query in microseconds.
	 * @param _query_digest The digest of the query.
	 * @param _client The client address.
	 * @param _client_len The length of the client address.
	 *
	 * This constructor initializes the MySQL_Event object with the provided parameters.  It does not allocate memory for string members.
	 */
	MySQL_Event(log_event_type _et, uint32_t _thread_id, char* _username, char* _schemaname, uint64_t _start_time, uint64_t _end_time, uint64_t _query_digest, char* _client, size_t _client_len);

	/**
	 * @brief Copy constructor for the MySQL_Event class.
	 * @param other The MySQL_Event object to copy.
	 *
	 * This copy constructor creates a deep copy of the provided MySQL_Event object.
	 */
	MySQL_Event(const MySQL_Event& other);

	/**
	 * @brief Destructor for the MySQL_Event class.
	 *
	 * This destructor deallocates the memory used by the object's string members if `free_on_delete` is true.
	 */
	~MySQL_Event();

	/**
	 * @brief Writes the event data to a file stream.
	 * @param f A pointer to the file stream.
	 * @param sess A pointer to the MySQL_Session object.
	 * @return The total number of bytes written.
	 *
	 * This function writes the event data to the specified file stream based on the event type and the configured log format.
	 */
	uint64_t write(std::fstream* f, MySQL_Session* sess);

	/**
	 * @brief Writes the event data in binary format (format 1) to a file stream.
	 * @param f A pointer to the file stream to write to. Must not be NULL.
	 * @return The total number of bytes written to the stream.
	 *
	 * This function serializes the event data into a binary format according to the MySQL event log format 1 specification.
	 * It encodes lengths using MySQL's length encoding scheme.
	 * The function writes the event type, thread ID, username, schema name, client address, hostgroup ID (if available), server address (if available), timestamps, client statement ID (if applicable), affected rows, last insert ID, rows sent, query digest, and query string to the file stream.
	 * The function writes all fields as defined by the MySQL event log format.
	 * It handles variable-length fields using MySQL's length encoding, which means that the length of each field is written before the field data itself.
	 * The function carefully handles potential errors during file writing operations.
	 */
	uint64_t write_query_format_1(std::fstream* f);


	/**
	 * @brief Writes the event data in JSON format (format 2) to a file stream.
	 * @param f A pointer to the file stream to write to. Must not be NULL.
	 * @return The total number of bytes written to the stream (always 0 in the current implementation).
	 *
	 * This function serializes the event data into a JSON format.
	 * It converts various data fields into a JSON object and writes this object to the file stream.
	 * The function uses the nlohmann::json library for JSON serialization.
	 * This function currently always returns 0.
	 * The function constructs a JSON object containing relevant event information such as the hostgroup ID, thread ID, event type, username, schema name, client and server addresses, affected rows, last insert ID, rows sent, query string, timestamps, query digest, and client statement ID (if applicable).
	 * After constructing the JSON object, it serializes it into a string using the `dump()` method of the nlohmann::json library and writes the resulting string to the output file stream.
	 */
	uint64_t write_query_format_2_json(std::fstream* f);

	/**
	 * @brief Writes authentication-related event data to a file stream.
	 * @param f A pointer to the file stream.
	 * @param sess A pointer to the MySQL_Session object.
	 */
	void write_auth(std::fstream* f, MySQL_Session* sess);

	/**
	 * @brief Sets the client statement ID for the event.
	 * @param client_stmt_id The client statement ID.
	 */
	void set_client_stmt_id(uint32_t client_stmt_id);

	/**
	 * @brief Sets the query string for the event.
	 * @param ptr A pointer to the query string.
	 * @param len The length of the query string.
	 *
	 * This method sets the query string for the event. The provided pointer and length are stored; ownership is not transferred.
	 */
	void set_query(const char* ptr, int len);

	/**
	 * @brief Sets the server address and hostgroup ID for the event.
	 * @param _hid The hostgroup ID.
	 * @param ptr A pointer to the server address string.
	 * @param len The length of the server address string.
	 *
	 * This method sets the server address and hostgroup ID for the event. The provided pointer and length are stored; ownership is not transferred.
	 */
	void set_server(int _hid, const char* ptr, int len);

	/**
	 * @brief Sets additional information for the event.
	 * @param _err A pointer to the extra information string.
	 *
	 * This method sets additional information for the event. A copy of the string is made; the original string is not modified.
	 */
	void set_extra_info(char* _err);

	/**
	 * @brief Sets the affected rows and last insert ID for the event.
	 * @param ar The number of affected rows.
	 * @param lid The last insert ID.
	 */
	void set_affected_rows(uint64_t ar, uint64_t lid);

	/**
	 * @brief Sets the number of rows sent for the event.
	 * @param rs The number of rows sent.
	 */
	void set_rows_sent(uint64_t rs);

	/**
	 * @brief Sets the GTID for the event from a MySQL session.
	 * @param sess A pointer to the MySQL_Session object.
	 *
	 * This method extracts the GTID from the provided MySQL session and sets it for the event.
	 */
	void set_gtid(MySQL_Session* sess);

	/**
	 * @brief Declares MySQL_Logger as a friend class, granting it access to private members of MySQL_Event.
	 */
	friend class MySQL_Logger;
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


/**
 * @class MySQL_Logger
 * @brief A class for logging MySQL events and audit entries.
 *
 * This class manages the logging of MySQL events (queries, connections, etc.) and audit entries to files.  It uses circular buffers for efficient event handling.
 * It provides methods for configuring log files, opening and closing log files, flushing log buffers, and logging various events.
 * The class uses mutexes or rwlocks for thread safety, depending on the compilation settings.
 */
class MySQL_Logger {
private:
	/**
	 * @brief Structure to hold configuration and state for event logging.
	 */
	struct {
		bool enabled;              ///< Flag indicating whether event logging is enabled.
		char* base_filename;       ///< Base filename for event log files. Memory managed by the class.
		char* datadir;             ///< Directory for event log files. Memory managed by the class.
		unsigned int log_file_id;  ///< ID of the current event log file.
		unsigned int max_log_file_size; ///< Maximum size of an event log file in bytes.
		std::fstream* logfile;     ///< File stream for event logging.
	} events;

	/**
	 * @brief Structure to hold configuration and state for audit logging.
	 */
	struct {
		bool enabled;              ///< Flag indicating whether audit logging is enabled.
		char* base_filename;       ///< Base filename for audit log files. Memory managed by the class.
		char* datadir;             ///< Directory for audit log files. Memory managed by the class.
		unsigned int log_file_id;  ///< ID of the current audit log file.
		unsigned int max_log_file_size; ///< Maximum size of an audit log file in bytes.
		std::fstream* logfile;     ///< File stream for audit logging.
	} audit;

	// Mutex or rwlock for thread safety
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_t wmutex;      ///< Pthread mutex for thread safety.
#else
	rwlock_t rwlock;             ///< rwlock for thread safety.
#endif

	/**
	 * @brief Closes the event log file.  This function should only be called while holding the write lock.
	 */
	void events_close_log_unlocked();

	/**
	 * @brief Opens the event log file. This function should only be called while holding the write lock.
	 */
	void events_open_log_unlocked();

	/**
	 * @brief Closes the audit log file.  This function should only be called while holding the write lock.
	 */
	void audit_close_log_unlocked();

	/**
	 * @brief Opens the audit log file. This function should only be called while holding the write lock.
	 */
	void audit_open_log_unlocked();

	/**
	 * @brief Finds the next available ID for an event log file.
	 * @return The next available ID.
	 */
	unsigned int events_find_next_id();

	/**
	 * @brief Finds the next available ID for an audit log file.
	 * @return The next available ID.
	 */
	unsigned int audit_find_next_id();

public:
	int eventslog_table_memory_size; ///< Maximum size of the in-memory event log table.

	/**
	 * @brief Constructor for the MySQL_Logger class.
	 *
	 * This constructor initializes the logger with default settings.
	 */
	MySQL_Logger();

	/**
	 * @brief Destructor for the MySQL_Logger class.
	 *
	 * This destructor deallocates resources used by the logger, including log files and mutexes.
	 */
	~MySQL_Logger();

	/**
	 * @brief Prints the version information of the logger.
	 */
	void print_version();

	/**
	 * @brief Flushes the event and audit log buffers to disk.
	 */
	void flush_log();

	/**
	 * @brief Flushes the event log buffer to disk. This function should only be called while holding the write lock.
	 */
	void events_flush_log_unlocked();

	/**
	 * @brief Flushes the audit log buffer to disk. This function should only be called while holding the write lock.
	 */
	void audit_flush_log_unlocked();

	/**
	 * @brief Sets the data directory for event log files.
	 * @param s The path to the data directory.
	 */
	void events_set_datadir(char* s);

	/**
	 * @brief Sets the base filename for event log files.
	 */
	void events_set_base_filename();

	/**
	 * @brief Sets the data directory for audit log files.
	 * @param s The path to the data directory.
	 */
	void audit_set_datadir(char* s);

	/**
	 * @brief Sets the base filename for audit log files.
	 */
	void audit_set_base_filename();

	/**
	 * @brief Logs a request event.
	 * @param sess A pointer to the MySQL_Session object.
	 * @param myds A pointer to the MySQL_Data_Stream object.
	 *
	 * This function logs information about a MySQL request, including the query, timestamps, user information, and other relevant details.
	 * It creates a MySQL_Event object, populates it with data from the session and data stream, and writes it to the event log file and/or the circular buffer.
	 * The function handles different types of requests (normal queries, prepared statements, etc.) and manages memory carefully.
	 * The function handles different query types (standard queries, prepared statements). It extracts relevant information from the session object, such as timestamps, user credentials, and query details.
	 * If the circular buffer is enabled, it creates a copy of the event and adds it to the buffer for later processing.
	 * The function also checks the size of the log file and flushes it if it exceeds the maximum configured size.
	 * The function uses mutexes to protect shared resources and avoid race conditions.
	 * The function assumes ownership of the dynamically allocated memory for the `MySQL_Event` object created within this function.
	 */
	void log_request(MySQL_Session* sess, MySQL_Data_Stream* myds);

	/**
	 * @brief Logs an audit entry.
	 * @param _et The type of the audit event.
	 * @param sess A pointer to the MySQL_Session object.
	 * @param myds A pointer to the MySQL_Data_Stream object.
	 * @param xi Additional information for the audit entry.
	 */
	void log_audit_entry(log_event_type _et, MySQL_Session* sess, MySQL_Data_Stream* myds, char* xi = NULL);

	/**
	 * @brief Flushes the log files.
	 */
	void flush();

	/**
	 * @brief Acquires a write lock.
	 */
	void wrlock();

	/**
	 * @brief Releases a write lock.
	 */
	void wrunlock();

	MySQL_Logger_CircularBuffer* MyLogCB; ///< Pointer to the circular buffer for managing events.

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
