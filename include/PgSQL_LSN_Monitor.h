#ifndef PGSQL_LSN_MONITOR_H
#define PGSQL_LSN_MONITOR_H
#include "PgSQL_LSN_Manager.h"
#ifdef PROXYSQL31
#include <functional>
// Driven exclusively by PgSQL_Monitor. Neither callbacks nor entries own sessions.
class PgSQL_LSN_Monitor {
  public:
	using Conninfo = std::function<std::optional<std::string>(const pgsql_lsn::Endpoint &)>;
	using Clock = std::function<pgsql_lsn::Micros()>;
	using Housekeeping = std::function<void(pgsql_lsn::Micros)>;
	PgSQL_LSN_Monitor(PgSQL_LSN_Manager &, Conninfo, Clock = {}, Housekeeping = {});
	~PgSQL_LSN_Monitor();
	bool tick(pgsql_lsn::Micros, const std::vector<pgsql_lsn::Endpoint> &,
			  pgsql_lsn::Micros interval, pgsql_lsn::Micros connect_timeout,
			  pgsql_lsn::Micros query_timeout);
	void wait(pgsql_lsn::Micros max_wait);
	void reset();

  private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};
#endif
#endif
