#ifndef PROXYSQL_AWS_LOCALITY_PROVIDER_H
#define PROXYSQL_AWS_LOCALITY_PROVIDER_H

#include "Aws_Locality_Types.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Aws { namespace RDS { class RDSClient; } }

using AwsLocalityCancelPredicate = std::function<bool()>;
using AwsLocalityEnvironmentGetter = std::function<std::string(const char*)>;

struct AwsMetadataProviderConfig {
	using SteadyClock = std::function<std::chrono::steady_clock::time_point()>;

	size_t worker_count { 2 };
	size_t max_pending { 256 };
	SteadyClock steady_clock {
		[] { return std::chrono::steady_clock::now(); }
	};
};

class AwsLocalityDiscoveryBackend {
public:
	virtual AwsMetadataResult discover(
		const AwsMetadataRequest& request,
		const AwsLocalityCancelPredicate& cancelled) = 0;
	virtual ~AwsLocalityDiscoveryBackend() = default;
};

class AwsSdkMetadataProvider final : public AwsMetadataProvider {
public:
	explicit AwsSdkMetadataProvider(
		std::shared_ptr<AwsLocalityDiscoveryBackend> backend,
		AwsMetadataProviderConfig config = {});
	~AwsSdkMetadataProvider() override;

	AwsMetadataRequestHandle request(
		const AwsMetadataRequest& request,
		std::weak_ptr<AwsMetadataCompletionSink> sink) override;
	void cancel(AwsMetadataRequestHandle handle) override;
	void shutdown() override;

	AwsSdkMetadataProvider(const AwsSdkMetadataProvider&) = delete;
	AwsSdkMetadataProvider& operator=(const AwsSdkMetadataProvider&) = delete;

private:
	class Impl;
	std::unique_ptr<Impl> impl_;
};

struct AwsImdsResponse {
	bool transport_ok { false };
	long status_code { 0 };
	std::string body;
};

class AwsImdsTransport {
public:
	virtual AwsImdsResponse put_token(
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) = 0;
	virtual AwsImdsResponse get_identity_document(
		const std::string& token,
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) = 0;
	virtual ~AwsImdsTransport() = default;
};

AwsLocalLocation aws_locality_environment_location(
	const AwsLocalityEnvironmentGetter& getenv_value);

class AwsLocalityLocalDiscovery {
public:
	AwsLocalityLocalDiscovery(
		std::shared_ptr<AwsImdsTransport> transport,
		AwsLocalityEnvironmentGetter getenv_value);

	AwsMetadataResult discover(
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) const;

private:
	std::shared_ptr<AwsImdsTransport> transport_;
	AwsLocalityEnvironmentGetter getenv_value_;
};

struct AwsRdsInstanceRecord {
	std::string endpoint;
	int port { 0 };
	std::string availability_zone;
	std::string arn;
};

struct AwsRdsClusterRecord {
	std::string identifier;
	std::string endpoint;
	std::string reader_endpoint;
	int port { 0 };
	std::vector<std::string> custom_endpoints;
	std::string arn;
};

struct AwsRdsClusterEndpointRecord {
	std::string endpoint;
	std::string endpoint_type;
	std::string cluster_identifier;
};

struct AwsRdsInstancesPage {
	AwsMetadataStatus status { AwsMetadataStatus::provider_unavailable };
	std::vector<AwsRdsInstanceRecord> instances;
	std::string next_marker;
};

struct AwsRdsClustersPage {
	AwsMetadataStatus status { AwsMetadataStatus::provider_unavailable };
	std::vector<AwsRdsClusterRecord> clusters;
	std::string next_marker;
};

struct AwsRdsClusterEndpointsPage {
	AwsMetadataStatus status { AwsMetadataStatus::provider_unavailable };
	std::vector<AwsRdsClusterEndpointRecord> endpoints;
	std::string next_marker;
};

class AwsRdsDiscoveryApi {
public:
	virtual AwsRdsInstancesPage describe_instances(
		const std::string& region,
		const std::string& marker,
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) = 0;
	virtual AwsRdsClustersPage describe_clusters(
		const std::string& region,
		const std::string& marker,
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) = 0;
	virtual AwsRdsClusterEndpointsPage describe_cluster_endpoints(
		const std::string& region,
		const std::string& marker,
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) = 0;
	virtual ~AwsRdsDiscoveryApi() = default;
};

class AwsLocalityRdsDiscovery {
public:
	explicit AwsLocalityRdsDiscovery(std::shared_ptr<AwsRdsDiscoveryApi> api);

	AwsMetadataResult discover(
		const AwsMetadataRequest& request,
		const AwsLocalityCancelPredicate& cancelled) const;

private:
	std::shared_ptr<AwsRdsDiscoveryApi> api_;
};

class AwsCurlImdsTransport final : public AwsImdsTransport {
public:
	AwsImdsResponse put_token(
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) override;
	AwsImdsResponse get_identity_document(
		const std::string& token,
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) override;
};

class AwsSdkRdsDiscoveryApi final : public AwsRdsDiscoveryApi {
public:
	AwsRdsInstancesPage describe_instances(
		const std::string& region,
		const std::string& marker,
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) override;
	AwsRdsClustersPage describe_clusters(
		const std::string& region,
		const std::string& marker,
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) override;
	AwsRdsClusterEndpointsPage describe_cluster_endpoints(
		const std::string& region,
		const std::string& marker,
		std::chrono::steady_clock::time_point deadline,
		const AwsLocalityCancelPredicate& cancelled) override;

private:
	std::shared_ptr<Aws::RDS::RDSClient> client_for_region(const std::string& region);
	std::mutex clients_mutex_;
	std::unordered_map<std::string, std::shared_ptr<Aws::RDS::RDSClient>> clients_;
};

class AwsLocalityCompositeDiscovery final : public AwsLocalityDiscoveryBackend {
public:
	AwsLocalityCompositeDiscovery(
		std::shared_ptr<AwsImdsTransport> imds,
		AwsLocalityEnvironmentGetter getenv_value,
		std::shared_ptr<AwsRdsDiscoveryApi> rds);

	AwsMetadataResult discover(
		const AwsMetadataRequest& request,
		const AwsLocalityCancelPredicate& cancelled) override;

private:
	AwsLocalityLocalDiscovery local_;
	AwsLocalityRdsDiscovery rds_;
};

#endif // PROXYSQL_AWS_LOCALITY_PROVIDER_H
