#ifndef NOISE_UTILS_H
#define NOISE_UTILS_H

#include <atomic>
#include <functional>
#include <thread>
#include <vector>
#include <string>
#include "command_line.h"

/**
 * @brief Type for internal noise functions.
 * @param cl CommandLine configuration.
 * @param stop Atomic boolean to signal the thread to exit.
 */
typedef std::function<void(const CommandLine&, std::atomic<bool>&)> internal_noise_func_t;

/**
 * @brief Spawns an internal noise function in a separate thread.
 * @param cl The CommandLine object containing configuration.
 * @param func The function to execute in the background.
 */
void spawn_internal_noise(const CommandLine& cl, internal_noise_func_t func);

/**
 * @brief Stops all internal noise threads.
 */
void stop_internal_noise_threads();

// --- Standard Internal Noise Functions ---

/**
 * @brief Periodically executes 'SELECT 1' against the ProxySQL Admin interface.
 */
void internal_noise_admin_pinger(const CommandLine& cl, std::atomic<bool>& stop);

/**
 * @brief Periodically polls stats_mysql_query_digest.
 */
void internal_noise_stats_poller(const CommandLine& cl, std::atomic<bool>& stop);

/**
 * @brief Periodically fetches Prometheus metrics via MySQL and PostgreSQL protocols.
 */
void internal_noise_prometheus_poller(const CommandLine& cl, std::atomic<bool>& stop);

/**
 * @brief Periodically queries random stats tables via MySQL and PostgreSQL protocols.
 */
void internal_noise_random_stats_poller(const CommandLine& cl, std::atomic<bool>& stop);

/**
 * @brief Periodically executes simple queries against the main MySQL port.
 */
void internal_noise_mysql_traffic(const CommandLine& cl, std::atomic<bool>& stop);

/**
 * @brief Periodically executes simple queries against the main PostgreSQL port.
 */
void internal_noise_pgsql_traffic(const CommandLine& cl, std::atomic<bool>& stop);

#endif // #ifndef NOISE_UTILS_H
