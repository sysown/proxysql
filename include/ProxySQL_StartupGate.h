#ifndef __CLASS_PROXYSQL_STARTUP_GATE_H
#define __CLASS_PROXYSQL_STARTUP_GATE_H

/**
 * @file ProxySQL_StartupGate.h
 * @brief Orders startup so that plugin lifecycle callbacks never run
 *   concurrently with Admin commands or ProxySQL Cluster synchronization.
 *
 * Plugin init/start/runtime_ready run with the plugin manager held
 * exclusively, and may call back into Admin and the Hostgroup Manager.
 * Admin sessions and Cluster peer threads take the same locks in the opposite
 * order, so they must not run until the plugin lifecycle has finished.
 *
 * States:
 * - open: nothing waits. This is the initial state, so builds and code paths
 *   that never configure the gate are unaffected.
 * - prestart_open: --no-start mode before PROXYSQL START. Admin commands run
 *   (configuring a stopped ProxySQL is the purpose of --no-start); Cluster
 *   threads wait.
 * - closed: startup in progress. Admin commands and Cluster threads wait.
 *
 * Transitions: reset(nostart) -> prestart_open or closed;
 * close_for_start() moves prestart_open -> closed; open() -> open.
 */

#include <functional>

enum class ProxySQL_StartupGateState {
	open,
	prestart_open,
	closed,
};

/** @brief Sets the state for a new startup: prestart_open with --no-start, closed otherwise. */
void proxysql_startup_gate_reset(bool nostart);

/** @brief PROXYSQL START: moves prestart_open to closed. Other states are left unchanged. */
void proxysql_startup_gate_close_for_start();

/** @brief Opens the gate and wakes every waiter. */
void proxysql_startup_gate_open();

ProxySQL_StartupGateState proxysql_startup_gate_state();

/**
 * @brief Blocks an Admin command while the gate is closed.
 * @param stop Polled periodically; returning true abandons the wait (shutdown).
 * @return true when the gate allows Admin commands, false when @p stop ended the wait.
 */
bool proxysql_startup_gate_wait_for_admin(const std::function<bool()>& stop);

/**
 * @brief Blocks a runtime worker (Cluster peer thread) until the gate is open.
 * @param stop Polled periodically; returning true abandons the wait (shutdown).
 * @return true when the gate is open, false when @p stop ended the wait.
 */
bool proxysql_startup_gate_wait_for_runtime(const std::function<bool()>& stop);

#endif /* __CLASS_PROXYSQL_STARTUP_GATE_H */
