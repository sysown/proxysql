#ifndef PGSQL_LSN_MANAGER_H
#define PGSQL_LSN_MANAGER_H
#ifdef PROXYSQL31
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
namespace pgsql_lsn {
using Lsn = uint64_t;
using Micros = uint64_t;
struct Endpoint {
	std::string address;
	uint16_t port = 0;
	bool operator==(const Endpoint &rhs) const {
		return address == rhs.address && port == rhs.port;
	}
	bool operator<(const Endpoint &rhs) const {
		return std::tie(address, port) < std::tie(rhs.address, rhs.port);
	}
};
struct History {
	uint64_t system_id = 0;
	uint32_t timeline = 0;
	bool operator==(const History &rhs) const {
		return system_id == rhs.system_id && timeline == rhs.timeline;
	}
};
struct LastExecution {
	Endpoint endpoint;
	Micros completed_at = 0;
};
struct Sample {
	Micros started_at = 0;
	Lsn lsn = 0;
};
struct RequiredLsn {
	History history;
	Lsn lsn = 0;
};
enum class LookupState { Ready, Pending, Unavailable, HistoryChanged };
struct LookupResult {
	LookupState state = LookupState::Unavailable;
	std::optional<RequiredLsn> required;
};
struct Observation {
	Endpoint endpoint;
	History history;
	int64_t postmaster_start_us = 0;
	Sample sample;
	bool valid = false;
};
std::optional<Lsn> parse_lsn(std::string_view);
std::string format_lsn(Lsn);
} // namespace pgsql_lsn
class PgSQL_LSN_Manager {
  public:
	PgSQL_LSN_Manager();
	~PgSQL_LSN_Manager();
	PgSQL_LSN_Manager(const PgSQL_LSN_Manager &) = delete;
	PgSQL_LSN_Manager &operator=(const PgSQL_LSN_Manager &) = delete;
	void reconcile_endpoints(const std::vector<pgsql_lsn::Endpoint> &);
	void publish(const pgsql_lsn::Observation &);
	void withdraw(const pgsql_lsn::Endpoint &);
	pgsql_lsn::LookupResult lookup_after(const pgsql_lsn::Endpoint &, pgsql_lsn::Micros) const;
	std::optional<pgsql_lsn::Observation> latest(const pgsql_lsn::Endpoint &) const;
	void retain_predecessor(const pgsql_lsn::Endpoint &, pgsql_lsn::Lsn);
	void prune_before(pgsql_lsn::Micros);
	std::vector<pgsql_lsn::Observation> latest_all() const;

  private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};
#endif
#endif
