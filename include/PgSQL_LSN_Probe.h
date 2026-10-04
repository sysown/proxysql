#ifndef PGSQL_LSN_PROBE_H
#define PGSQL_LSN_PROBE_H
#include "PgSQL_LSN_Manager.h"
#ifdef PROXYSQL31
namespace pgsql_lsn {
// Read once on each monitor connection. Unknown server formats retain raw LSNs.
struct WalLayout {
	uint32_t alignment = 0, block_size = 0, segment_size = 0, server_version = 0;
};
using ProbeRows = std::vector<std::vector<std::optional<std::string>>>;
class ProbeCadence {
  public:
	bool due(Micros now, Micros interval) const;
	void started(Micros now);
	void finished();

  private:
	std::optional<Micros> last_start_;
	bool active_ = false;
};
} // namespace pgsql_lsn
// Adapter consumes each entire command through final PQgetResult(NULL) first.
// Time passed to next_command is captured immediately before sending the
// command.
class PgSQL_LSN_Probe {
  public:
	explicit PgSQL_LSN_Probe(pgsql_lsn::Endpoint,
							 std::optional<pgsql_lsn::History> preceding_identity = {},
							 std::optional<pgsql_lsn::WalLayout> preceding_layout = {});
	std::optional<std::string> next_command(pgsql_lsn::Micros);
	bool consume_result(const pgsql_lsn::ProbeRows &, std::string &error);
	std::optional<pgsql_lsn::Observation> finish() const;
	void fail(const std::string &);
	std::optional<pgsql_lsn::WalLayout> layout() const {
		return layout_;
	}

  private:
	enum class Stage { InitialIdentity, Layout, Sample, FinalIdentity, Complete, Failed };
	Stage stage_ = Stage::InitialIdentity;
	bool awaiting_ = false;
	std::optional<pgsql_lsn::History> identity_;
	std::optional<pgsql_lsn::WalLayout> layout_;
	pgsql_lsn::Observation result_;
};
#endif
#endif
