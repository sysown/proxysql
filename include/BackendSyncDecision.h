/**
 * @file BackendSyncDecision.h
 * @brief Pure decision functions for backend variable synchronization.
 *
 * Extracted from MySQL_Session's verify chain (handler_again___verify_*).
 * Determines what sync actions are needed before a query can execute
 * on a backend connection.
 *
 * @see Phase 3.6 (GitHub issue #5494)
 */

#ifndef BACKEND_SYNC_DECISION_H
#define BACKEND_SYNC_DECISION_H

/**
 * @brief Actions that may be needed to synchronize backend state.
 */
enum BackendSyncAction {
	SYNC_NONE = 0,             ///< No synchronization needed.
	SYNC_SCHEMA = 1,           ///< Schema (USE db) needs to be sent.
	SYNC_USER = 2,             ///< Username mismatch, CHANGE USER required.
	SYNC_AUTOCOMMIT = 4,       ///< Autocommit state needs to be synced.
};

/**
 * @brief Determine what sync actions are needed for the backend.
 *
 * Checks client vs backend state and returns a bitmask of required
 * actions. Mirrors the MySQL_Session verify chain logic.
 *
 * @param client_user       Client connection username.
 * @param backend_user      Backend connection username.
 * @param client_schema     Client connection schema.
 * @param backend_schema    Backend connection schema.
 * @param client_autocommit Client autocommit setting.
 * @param backend_autocommit Backend autocommit setting.
 * @return Bitmask of BackendSyncAction values.
 */
int determine_backend_sync_actions(
	const char *client_user,
	const char *backend_user,
	const char *client_schema,
	const char *backend_schema,
	bool client_autocommit,
	bool backend_autocommit
);

#endif // BACKEND_SYNC_DECISION_H
