#ifndef NOISE_UTILS_H
#define NOISE_UTILS_H

#include <atomic>
#include <functional>
#include <thread>
#include <vector>
#include <string>
#include <map>
#include "command_line.h"

#include <mutex>

/**
 * @brief Configuration for internal noise routines.
 */
typedef std::map<std::string, std::string> NoiseOptions;

/**
 * @brief Global mutex for synchronized reporting to stderr.
 */
extern std::mutex noise_report_mutex;

/**
 * @brief Thread-safe logging to stderr for noise routines.
 */
void noise_log(const std::string& msg);

/**
 * @brief Type for internal noise functions.
 * @param cl CommandLine configuration.
 * @param opt Noise routines configuration.
 * @param stop Atomic boolean to signal the thread to exit.
 */
typedef std::function<void(const CommandLine&, const NoiseOptions&, std::atomic<bool>&)> internal_noise_func_t;

/**
 * @brief Spawns an internal noise function in a separate thread.
 * @param cl The CommandLine object containing configuration.
 * @param func The function to execute in the background.
 * @param opt Configuration for the noise routine.
 */
void spawn_internal_noise(const CommandLine& cl, internal_noise_func_t func, const NoiseOptions& opt = NoiseOptions());

/**
 * @brief Global flag indicating if any noise routine encountered a fatal error.
 */
extern std::atomic<bool> noise_failure_detected;

/**
 * @brief Stops all internal noise threads.
 */
void stop_internal_noise_threads();

/**
 * @brief Returns the number of active internal noise threads.
 */
int get_internal_noise_threads_count();

// --- Standard Internal Noise Functions ---

/**
 * @brief Periodically executes 'SELECT 1' against the ProxySQL Admin interface.
 */
void internal_noise_admin_pinger(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop);

/**
 * @brief Periodically polls stats tables.
 */
void internal_noise_stats_poller(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop);

/**
 * @brief Periodically fetches Prometheus metrics via MySQL and PostgreSQL protocols.
 */
void internal_noise_prometheus_poller(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop);

/**
 * @brief Periodically queries random stats tables via MySQL and PostgreSQL protocols.
 */
void internal_noise_random_stats_poller(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop);

/**
 * @brief Periodically executes simple queries against the main MySQL port.
 */
void internal_noise_mysql_traffic(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop);

/**
 * @brief Periodically fetches Prometheus metrics via the REST API.
 */
void internal_noise_rest_prometheus_poller(const CommandLine& cl, const NoiseOptions& opt, std::atomic<bool>& stop);

#endif // #ifndef NOISE_UTILS_H
