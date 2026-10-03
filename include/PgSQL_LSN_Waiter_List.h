#ifndef PGSQL_LSN_WAITER_LIST_H
#define PGSQL_LSN_WAITER_LIST_H
#include "PgSQL_LSN_Manager.h"
#include "PgSQL_Waiter_List.h"

// Independent worker-owned lists and nodes reuse the established intrusive
// container; LSN waits never enter the ordinary connection-checkout queue.
using PgSQL_LSN_Waiter_List = PgSQL_Waiter_Lists;
using PgSQL_LSN_Waiter_Node = PgSQL_Waiter_Node;
enum class LsnAdmission { Proceed, Wait, UseWriter, Error };

struct PgSQL_LSN_Request {
	bool initialized = false, fallback = false, waiting_for_pool = false;
	bool cancelled = false;
	uint32_t requested_hostgroup = 0, route_hostgroup = 0;
	pgsql_lsn::Micros entered_at = 0, deadline = 0, query_deadline = 0;
	std::optional<pgsql_lsn::GroupId> group;
	pgsql_lsn::GroupSnapshot snapshot;
	pgsql_lsn::Dependency dependency;
	pgsql_lsn::DependencyView view;
	pgsql_lsn::Reason error = pgsql_lsn::Reason::None;
};
#endif
