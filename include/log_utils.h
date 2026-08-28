#ifndef PROXYSQL_LOG_UTILS_H
#define PROXYSQL_LOG_UTILS_H

#include <string>
#include <cstdint>
#include <random>
#include <mutex>
#include <memory>
#include <unordered_map>
#include <fstream>
#include <functional>
#include <pthread.h>

namespace prometheus {
class Counter;
}

/**
 * @brief Manages a string buffer and a flush timestamp for logging.
 * 
 * Used to accumulate log data in memory before writing to a file.
 */
class LogBuffer {
private:
	std::string buffer;
	uint64_t last_flush_time;

public:
	LogBuffer();

	/**
	 * @brief Stream insertion operator for appending strings to the buffer.
	 * @param value The string to append to the buffer.
	 * @return Reference to this LogBuffer for method chaining.
	 */
	LogBuffer& operator<<(const std::string& value);

	/**
	 * @brief Stream insertion operator for appending C-strings to the buffer.
	 * @param value The C-string to append to the buffer.
	 * @return Reference to this LogBuffer for method chaining.
	 */
	LogBuffer& operator<<(const char* value);

	/**
	 * @brief Stream insertion operator for appending characters to the buffer.
	 * @param value The character to append to the buffer.
	 * @return Reference to this LogBuffer for method chaining.
	 */
	LogBuffer& operator<<(char value);

	/**
	 * @brief Appends a string to the buffer.
	 * @param str The string to append to the buffer.
	 * @return Reference to this LogBuffer for method chaining.
	 */
	LogBuffer& append(const std::string& str);

	/**
	 * @brief Appends a C-string to the buffer.
	 * @param str The C-string to append to the buffer.
	 * @return Reference to this LogBuffer for method chaining.
	 */
	LogBuffer& append(const char* str);

	/**
	 * @brief Appends a character sequence to the buffer.
	 * @param str Pointer to the character sequence.
	 * @param len Length of the character sequence.
	 * @return Reference to this LogBuffer for method chaining.
	 */
	LogBuffer& append(const char* str, size_t len);

	/**
	 * @brief Writes a string to the buffer (alias for append).
	 * @param str The string to write to the buffer.
	 * @return Reference to this LogBuffer for method chaining.
	 */
	LogBuffer& write(const std::string& str);

	/**
	 * @brief Writes a character sequence to the buffer.
	 * @param str Pointer to the character sequence.
	 * @param len Length of the character sequence.
	 * @return Reference to this LogBuffer for method chaining.
	 */
	LogBuffer& write(const char* str, size_t len);

	/**
	 * @brief Resets the buffer for next use.
	 * 
	 * Clears the buffer content and updates the last flush time.
	 * 
	 * @param flush_time The timestamp at which the buffer was flushed.
	 */
	void reset(uint64_t flush_time);
	
	/**
	 * @brief Sets the last flush time explicitly.
	 * 
	 * @param flush_time The timestamp to set.
	 */
	void set_last_flush_time(uint64_t flush_time);

	/**
	 * @brief Returns the last flush time.
	 */
	uint64_t get_last_flush_time() const;

	/**
	 * @brief Returns true if the buffer is empty.
	 */
	bool empty() const;

	/**
	 * @brief Returns the size of the buffer.
	 */
	size_t size() const;

	/**
	 * @brief Returns a pointer to the buffer data.
	 */
	const char* data() const;

	/**
	 * @brief Flushes the buffer to an output file stream.
	 * 
	 * Writes the entire contents of the buffer to the provided file stream.
	 * The caller is responsible for resetting the buffer after flushing.
	 * 
	 * @param logfile The output file stream to write to.
	 */
	void flush_to_file(std::fstream* logfile);
};

/**
 * @brief Class to hold per-thread logging context for both event and audit logging.
 * 
 * This class encapsulates all per-thread state needed for logging operations:
 * - events: Buffer and timestamp state for event logging
 * - audit: Buffer and timestamp state for audit logging
 * - rng: Thread-local Mersenne Twister random number generator for log sampling
 * - dist: Uniform real distribution [0.0, 1.0) for sampling
 * 
 * Each thread gets its own instance to avoid race conditions and lock contention.
 */
class LogBufferThreadContext {
private:
	std::mt19937 rng;  ///< Mersenne Twister random number generator (per-thread)
	std::uniform_real_distribution<double> dist; ///< Uniform distribution [0.0, 1.0)

public:
	std::mutex buffer_lock; ///< Protects cross-thread flush operations on thread-local buffers.
	LogBuffer events;  ///< Event log buffer and timestamp
	LogBuffer audit;   ///< Audit log buffer and timestamp
	
	/**
	 * @brief Constructor that initializes the thread logging context with random seed.
	 * 
	 * Seeds the RNG using a combination of hardware entropy, high-resolution time,
	 * and thread ID for maximum uniqueness and unpredictability.
	 */
	LogBufferThreadContext();

	/**
	 * @brief Determines if an event should be logged based on the rate limit.
	 * 
	 * Calculates whether a random sample falls within the acceptance threshold
	 * determined by the rate limit.
	 * 
	 * @param rate_limit The sampling rate limit. 1 means log all, N means log approx 1/N.
	 * @return true if the event should be logged, false otherwise.
	 */
	bool should_log(int rate_limit);
};

/**
 * @brief Retrieves or creates the LogBufferThreadContext for the current thread.
 * 
 * This helper function checks if a context for the current thread exists in the provided map.
 * If found, it returns the existing context. Otherwise, it creates a new one, initializes
 * it with the current time, and adds it to the map.
 * 
 * @param log_thread_contexts The map of thread contexts.
 * @param log_thread_contexts_lock The mutex protecting access to the map.
 * @param current_time The current time to initialize last_flush_time (e.g. monotonic_time()).
 * @return LogBufferThreadContext* Pointer to the thread's logging context.
 */
LogBufferThreadContext* GetLogBufferThreadContext(std::unordered_map<pthread_t, std::unique_ptr<LogBufferThreadContext>>& log_thread_contexts, std::mutex& log_thread_contexts_lock, uint64_t current_time);

/**
 * @brief Helper function to flush buffer to file stream and rotate file if required.
 * 
 * @param buffer The LogBuffer to flush
 * @param logfile Pointer to the logfile stream
 * @param current_log_size Reference to current log size counter
 * @param max_log_file_size Maximum log file size before rotation
 * @param lock_fn Function to acquire write lock
 * @param unlock_fn Function to release write lock
 * @param rotate_fn Function to rotate the log file
 * @param reset_time Timestamp to use when resetting the buffer after flush
 * @return true if buffer was flushed, false otherwise
 */
bool flush_and_rotate(
	LogBuffer& buffer,
	std::fstream*& logfile,
	unsigned int& current_log_size,
	unsigned int max_log_file_size,
	std::function<void()> lock_fn,
	std::function<void()> unlock_fn,
	std::function<void()> rotate_fn,
	uint64_t reset_time = 0);

/**
 * @brief Returns the protocol-scoped query logger counter.
 * @param protocol Protocol label (e.g. "mysql" or "pgsql").
 * @return Counter pointer or nullptr if Prometheus registry isn't available.
 */
prometheus::Counter* get_logger_queries_logged_counter(const std::string& protocol);

#endif /* PROXYSQL_LOG_UTILS_H */
