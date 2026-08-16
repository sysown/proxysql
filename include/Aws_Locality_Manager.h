#ifndef __CLASS_AWS_LOCALITY_MANAGER_H
#define __CLASS_AWS_LOCALITY_MANAGER_H

#include "Aws_Locality_Types.h"
#include "json_fwd.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

AwsLocalityPolicy parse_aws_locality_policy(
	const nlohmann::json& policy_json,
	uint32_t hostgroup_id,
	AwsLocalityPolicyError& error);

AwsEndpointCandidate recognize_rds_endpoint(
	uint32_t hostgroup_id,
	std::string_view hostname,
	uint16_t port);

AwsLocalityClass classify_aws_locality(
	const AwsLocalLocation& local,
	const AwsBackendLocation& backend);

uint64_t aws_locality_effective_weight(
	int64_t configured_weight,
	double multiplier);

uint64_t aws_locality_saturating_add(uint64_t lhs, uint64_t rhs);
size_t aws_locality_weighted_index(
	const uint64_t* weights,
	size_t count,
	uint64_t random_value);

using AwsMetadataProviderDestroyFn = void (*)(AwsMetadataProvider*);

class AwsMetadataProviderLease {
public:
	AwsMetadataProviderLease() = default;
	~AwsMetadataProviderLease();
	AwsMetadataProviderLease(AwsMetadataProviderLease&& other) noexcept;
	AwsMetadataProviderLease& operator=(AwsMetadataProviderLease&& other) noexcept;

	AwsMetadataProvider* get() const { return provider_; }
	AwsMetadataProvider* operator->() const { return provider_; }
	explicit operator bool() const { return provider_ != nullptr; }

	AwsMetadataProviderLease(const AwsMetadataProviderLease&) = delete;
	AwsMetadataProviderLease& operator=(const AwsMetadataProviderLease&) = delete;

private:
	explicit AwsMetadataProviderLease(AwsMetadataProvider* provider)
		: provider_(provider) {}
	void release();
	AwsMetadataProvider* provider_ { nullptr };

	friend AwsMetadataProviderLease acquire_global_aws_metadata_provider();
};

bool install_global_aws_metadata_provider(
	AwsMetadataProvider* provider,
	AwsMetadataProviderDestroyFn destroy,
	void* module_handle);
AwsMetadataProviderLease acquire_global_aws_metadata_provider();
void shutdown_global_aws_metadata_provider();

struct AwsLocalitySnapshotEntry {
	uint32_t hostgroup_id { 0 };
	std::string hostname;
	uint16_t port { 0 };
	AwsEndpointType endpoint_type { AwsEndpointType::unknown };
	int64_t configured_weight { 0 };
	AwsLocalLocation local;
	AwsBackendLocation backend;
	AwsLocalityClass locality { AwsLocalityClass::unknown };
	double multiplier { 1.0 };
	AwsLocalityMetadataStatus status { AwsLocalityMetadataStatus::disabled };
	int64_t last_success_timestamp { 0 };
	int64_t last_attempt_timestamp { 0 };
	std::string failure_category;
};

struct AwsLocalitySnapshot {
	uint64_t generation { 0 };
	bool enabled { false };
	std::unordered_multimap<uint64_t, AwsLocalitySnapshotEntry> entries;
	std::unordered_set<uint32_t> hostgroups;

	const AwsLocalitySnapshotEntry* find(
		uint32_t hostgroup_id,
		std::string_view hostname,
		uint16_t port) const;
	uint64_t effective_weight(
		uint32_t hostgroup_id,
		std::string_view hostname,
		uint16_t port,
		int64_t configured_weight) const;
	bool has_hostgroup(uint32_t hostgroup_id) const {
		return hostgroups.find(hostgroup_id) != hostgroups.end();
	}
};

struct AwsLocalityManagerConfig {
	using SteadyClock = std::function<std::chrono::steady_clock::time_point()>;
	using WallClock = std::function<std::chrono::system_clock::time_point()>;

	AwsLocalityManagerConfig();
	SteadyClock steady_clock;
	WallClock wall_clock;
	std::chrono::milliseconds request_timeout { std::chrono::seconds(5) };
	std::chrono::milliseconds disable_wait_timeout { std::chrono::milliseconds(250) };
	std::function<void()> before_completion;
};

class MySQLAwsLocalityManager {
public:
	explicit MySQLAwsLocalityManager(AwsLocalityManagerConfig config = {});
	~MySQLAwsLocalityManager();
	MySQLAwsLocalityManager(const MySQLAwsLocalityManager&) = delete;
	MySQLAwsLocalityManager& operator=(const MySQLAwsLocalityManager&) = delete;

	void configure(std::vector<AwsLocalityHostgroupConfig> hostgroups);
	void set_enabled(bool enabled);
	void request_refresh();
	std::shared_ptr<const AwsLocalitySnapshot> snapshot() const;
	std::vector<AwsLocalitySnapshotEntry> diagnostic_rows() const;
	void shutdown();

private:
	class Impl;
	std::unique_ptr<Impl> impl_;
};

#endif // __CLASS_AWS_LOCALITY_MANAGER_H
