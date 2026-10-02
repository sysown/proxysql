#ifndef PGSQL_NATIVE_TIER_H
#define PGSQL_NATIVE_TIER_H

#include <cstring>

#include "libpq-fe.h"
#include "tap.h"

// Probe the target server, not the test binary. Stable does not register this
// setting. A failed probe is an infrastructure failure, never a reason to skip.
inline bool pgsql_native_supported(PGconn* admin) {
	PGresult* result = PQexec(admin,
		"SELECT count(*) FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	if (PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) != 1) {
		PQclear(result);
		BAIL_OUT("cannot probe native backend protocol availability");
		return false;
	}
	const bool supported = PQgetvalue(result, 0, 0)[0] == '1';
	PQclear(result);
	return supported;
}

// Capability and active mode are distinct: native-capable tiers may still be
// configured to use libpq. Existing pooled connections retain their old mode.
inline bool pgsql_native_active(PGconn* admin) {
	PGresult* result = PQexec(admin,
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	if (PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) > 1) {
		PQclear(result);
		BAIL_OUT("cannot probe active native backend protocol mode");
		return false;
	}
	const bool active = PQntuples(result) == 1 && strcmp(PQgetvalue(result, 0, 0), "true") == 0;
	PQclear(result);
	return active;
}

#endif
