/**
 * @file BackendSyncDecision.cpp
 * @brief Implementation of backend variable sync decisions.
 *
 * @see BackendSyncDecision.h
 * @see Phase 3.6 (GitHub issue #5494)
 */

#include "BackendSyncDecision.h"
#include <cstring>

int determine_backend_sync_actions(
	const char *client_user,
	const char *backend_user,
	const char *client_schema,
	const char *backend_schema,
	bool client_autocommit,
	bool backend_autocommit)
{
	int actions = SYNC_NONE;

	// Username mismatch → CHANGE USER required
	// Asymmetric NULLs (one set, other not) count as mismatch
	if (client_user == nullptr && backend_user != nullptr) {
		actions |= SYNC_USER;
	} else if (client_user != nullptr && backend_user == nullptr) {
		actions |= SYNC_USER;
	} else if (client_user && backend_user) {
		if (strcmp(client_user, backend_user) != 0) {
			actions |= SYNC_USER;
		}
	}

	// Schema mismatch → USE <db> required
	// Only check if usernames match (user change handles schema too)
	if (!(actions & SYNC_USER)) {
		if (client_schema == nullptr && backend_schema != nullptr) {
			actions |= SYNC_SCHEMA;
		} else if (client_schema != nullptr && backend_schema == nullptr) {
			actions |= SYNC_SCHEMA;
		} else if (client_schema && backend_schema) {
			if (strcmp(client_schema, backend_schema) != 0) {
				actions |= SYNC_SCHEMA;
			}
		}
	}

	// Autocommit mismatch → SET autocommit required
	if (client_autocommit != backend_autocommit) {
		actions |= SYNC_AUTOCOMMIT;
	}

	return actions;
}
