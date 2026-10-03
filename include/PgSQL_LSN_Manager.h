#ifndef PGSQL_LSN_MANAGER_H
#define PGSQL_LSN_MANAGER_H

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

class PgSQL_LSN_Manager;

namespace pgsql_lsn {
using Lsn = uint64_t;
using GroupId = uint32_t;
using Generation = uint64_t;
using Micros = uint64_t;

struct Endpoint {
	std::string address;
	uint16_t port = 0;
	bool operator==(const Endpoint& rhs) const { return address == rhs.address && port == rhs.port; }
	bool operator<(const Endpoint& rhs) const { return std::tie(address, port) < std::tie(rhs.address, rhs.port); }
};
struct History {
	uint64_t system_id = 0;
	uint32_t timeline = 0;
	bool operator==(const History& rhs) const { return system_id == rhs.system_id && timeline == rhs.timeline; }
};
struct Incarnation {
	History history;
	int64_t postmaster_start_us = 0;
	bool operator==(const Incarnation& rhs) const {
		return history == rhs.history && postmaster_start_us == rhs.postmaster_start_us;
	}
};
enum class Role { Writer, Replica };
struct ServerToken {
	GroupId group = 0;
	Generation generation = 0;
	Endpoint endpoint;
	Incarnation incarnation;
	Role role = Role::Replica;
	bool operator==(const ServerToken& rhs) const {
		return group == rhs.group && generation == rhs.generation && endpoint == rhs.endpoint
			&& incarnation == rhs.incarnation && role == rhs.role;
	}
};
enum class Reason { None, HistoryChanged, TrackingNotInitialized, NoSafeBackend };
const char* reason_code(Reason reason);
enum class DependencyState { Clean, Pending, Ready, Invalid };
struct DependencyView {
	DependencyState state = DependencyState::Clean;
	std::optional<ServerToken> source;
	std::optional<Lsn> required_lsn;
	uint64_t revision = 0;
	Reason reason = Reason::None;
	uint64_t batch_id = 0;
};
struct GroupConfig {
	GroupId writer_hostgroup = 0;
	uint32_t reader_hostgroup = 0;
	bool enabled = false;
	std::vector<Endpoint> writers, readers;
};
struct Progress {
	ServerToken server;
	uint64_t connection_generation = 0;
	std::optional<Lsn> insert_lsn, replay_lsn;
	bool valid = false;
	Micros sampled_at_us = 0, duration_us = 0;
	std::string error;
};

struct GroupState;
struct Batch;

// Handles carry frontend demand across pool changes. They never own a session.
class Dependency {
	friend class ::PgSQL_LSN_Manager;
	std::shared_ptr<GroupState> group_;
	std::shared_ptr<Batch> batch_;
	std::optional<ServerToken> source_;
	std::optional<Lsn> floor_;
	Reason error_ = Reason::None;
};
class SampleTicket {
	friend class ::PgSQL_LSN_Manager;
	ServerToken source_;
	uint64_t batch_ = 0, attempt_ = 0;
};
struct GroupSnapshot {
	GroupConfig config;
	Generation generation = 0;
	uint64_t revision = 0, activation_epoch = 0;
	std::optional<ServerToken> writer;
	std::vector<Progress> servers;
	bool has_pending = false;
	std::optional<Lsn> required_lsn;
	size_t live_batches = 0, unresolved_batches = 0;
	uint64_t completions = 0, batches = 0;
};

std::optional<Lsn> parse_lsn(std::string_view text);
std::string format_lsn(Lsn value);
bool replica_satisfies(const DependencyView&, const Progress&, const ServerToken& backend);
bool validate_lsn_groups(const std::vector<GroupConfig>&, std::string& error);
} // namespace pgsql_lsn

class PgSQL_LSN_Manager {
public:
	PgSQL_LSN_Manager();
	~PgSQL_LSN_Manager();
	PgSQL_LSN_Manager(const PgSQL_LSN_Manager&) = delete;
	PgSQL_LSN_Manager& operator=(const PgSQL_LSN_Manager&) = delete;
	void reconcile_groups(const std::vector<pgsql_lsn::GroupConfig>&);
	pgsql_lsn::Dependency observe_completion(const pgsql_lsn::ServerToken&,
		const pgsql_lsn::Dependency& previous);
	pgsql_lsn::DependencyView resolve(const pgsql_lsn::Dependency&) const;
	std::optional<pgsql_lsn::SampleTicket> seal_writer_batch(pgsql_lsn::GroupId);
	bool complete_writer_sample(const pgsql_lsn::SampleTicket&, const pgsql_lsn::Progress&);
	void fail_writer_sample(const pgsql_lsn::SampleTicket&, const std::string& error);
	void publish_progress(const pgsql_lsn::Progress&);
	void invalidate_endpoint(const pgsql_lsn::Endpoint&, pgsql_lsn::Reason,
		uint64_t retired_connection_generation = 0);
	pgsql_lsn::GroupSnapshot snapshot(pgsql_lsn::GroupId) const;
	std::vector<pgsql_lsn::GroupSnapshot> snapshots() const;
	std::optional<pgsql_lsn::GroupId> group_for_hostgroup(uint32_t hostgroup) const;
	uint64_t configuration_epoch() const;
private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};
#endif
