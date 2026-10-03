#ifndef PGSQL_LSN_MONITOR_H
#define PGSQL_LSN_MONITOR_H
#include "PgSQL_LSN_Manager.h"
#include <functional>

// Owned and driven by the existing monitor scheduler, never a frontend worker.
class PgSQL_LSN_Monitor {
public:
	using Conninfo = std::function<std::optional<std::string>(const pgsql_lsn::Endpoint&)>;
	PgSQL_LSN_Monitor(PgSQL_LSN_Manager&, Conninfo);
	~PgSQL_LSN_Monitor();
	bool tick(pgsql_lsn::Micros now, pgsql_lsn::Micros interval,
		pgsql_lsn::Micros connect_timeout, pgsql_lsn::Micros query_timeout);
	void wait(pgsql_lsn::Micros max_wait);
	void reset();
private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};
#endif
