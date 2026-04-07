/**
 * @file PgSQLMonitorDecision.cpp
 * @brief Implementation of PgSQL monitor health decisions.
 *
 * @see PgSQLMonitorDecision.h
 * @see Phase 3.9 (GitHub issue #5497)
 */

#include "PgSQLMonitorDecision.h"

bool pgsql_should_shun_on_ping_failure(
	unsigned int missed_heartbeats,
	unsigned int max_failures_threshold)
{
	if (max_failures_threshold == 0) {
		return false;  // shunning disabled
	}
	return (missed_heartbeats >= max_failures_threshold);
}

bool pgsql_should_offline_for_readonly(
	bool is_read_only,
	bool is_writer_hg)
{
	// A read-only server in a writer hostgroup should go OFFLINE_SOFT
	return (is_read_only && is_writer_hg);
}
