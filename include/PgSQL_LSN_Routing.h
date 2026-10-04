#ifndef PGSQL_LSN_ROUTING_H
#define PGSQL_LSN_ROUTING_H
#include "PgSQL_LSN_Manager.h"

// Routing configuration belongs to the hostgroup manager. It does not own LSN
// progress, probe connections, completion batches, or server generations.
struct PgSQL_LSN_Policy {
	uint32_t writer_hostgroup = 0, reader_hostgroup = 0;
	bool enabled = false;
	std::vector<pgsql_lsn::Endpoint> writers, readers;
	uint64_t version = 0, activation_epoch = 0;
};
#endif
