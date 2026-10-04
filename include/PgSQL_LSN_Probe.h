#ifndef PGSQL_LSN_PROBE_H
#define PGSQL_LSN_PROBE_H
#include "PgSQL_LSN_Manager.h"

namespace pgsql_lsn {
using ProbeRows = std::vector<std::vector<std::optional<std::string>>>;

// This clock-independent policy is used by the real monitor scheduler.
class ProbeCadence {
public:
	bool due(Micros now, Micros interval, bool demand) const;
	void started(Micros now);
	void finished();
private:
	std::optional<Micros> last_start_;
	bool active_ = false;
};
}

// The adapter must consume a whole command response (through the final NULL
// PQgetResult), then feed exactly one tuples result here. This class does no IO.
class PgSQL_LSN_Probe {
public:
	PgSQL_LSN_Probe(pgsql_lsn::Generation generation,
		pgsql_lsn::Endpoint endpoint,
		std::optional<pgsql_lsn::ServerToken> expected, uint64_t connection_generation,
		pgsql_lsn::Micros started_at, std::optional<pgsql_lsn::History> preceding_identity = {});
	std::optional<std::string> next_command();
	bool consume_result(const pgsql_lsn::ProbeRows&, std::string& error);
	std::optional<pgsql_lsn::Progress> finish() const;
	void fail(const std::string& error, pgsql_lsn::Reason reason);
	pgsql_lsn::Reason failure_reason() const { return failure_reason_; }
	const std::string& error() const { return result_.error; }
private:
	enum class Stage { InitialIdentity, Sample, FinalIdentity, Complete, Failed };
	Stage stage_ = Stage::InitialIdentity;
	bool awaiting_ = false;
	std::optional<pgsql_lsn::ServerToken> expected_;
	std::optional<pgsql_lsn::History> identity_;
	pgsql_lsn::Progress result_;
	pgsql_lsn::Reason failure_reason_ = pgsql_lsn::Reason::None;
};
#endif
