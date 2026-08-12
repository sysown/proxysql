#include "Aws_Iam_Sdk.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <utility>

#ifdef PROXYSQLAWSIAM
#include <aws/core/Aws.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/rds/RDSClient.h>

#include <string>
#include <unordered_map>
#endif

namespace {
std::mutex global_source_mutex;
std::condition_variable global_source_cv;
AwsIamTokenSource *leased_global_source = nullptr;
size_t global_source_leases = 0;
bool global_source_accepting = false;

#ifndef PROXYSQLAWSIAM
class AwsIamNotCompiledTokenSource final : public AwsIamTokenSource {
public:
	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink> sink) override {
		AwsIamRequestHandle handle { next_handle_.fetch_add(1, std::memory_order_relaxed) };
		token_requests_.fetch_add(1, std::memory_order_relaxed);
		if (auto live_sink = sink.lock()) {
			AwsIamCompletion completion;
			completion.opaque_id = opaque_id;
			completion.result.status = AwsIamStatus::SUPPORT_NOT_COMPILED;
			live_sink->post(std::move(completion));
		}
		return handle;
	}

	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point) override {
		token_requests_.fetch_add(1, std::memory_order_relaxed);
		AwsIamTokenResult result;
		result.status = AwsIamStatus::SUPPORT_NOT_COMPILED;
		return result;
	}

	void cancel(AwsIamRequestHandle) override {}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}

	void record_backend_connection(bool success) override {
		(success ? backend_successes_ : backend_failures_).fetch_add(1, std::memory_order_relaxed);
	}

	AwsIamStatsSnapshot snapshot() const override {
		AwsIamStatsSnapshot result;
		result.token_requests = token_requests_.load(std::memory_order_relaxed);
		result.backend_connection_successes = backend_successes_.load(std::memory_order_relaxed);
		result.backend_connection_failures = backend_failures_.load(std::memory_order_relaxed);
		return result;
	}

private:
	std::atomic<uint64_t> next_handle_ { 1 };
	std::atomic<uint64_t> token_requests_ { 0 };
	std::atomic<uint64_t> backend_successes_ { 0 };
	std::atomic<uint64_t> backend_failures_ { 0 };
};
#else
class AwsIamSdkRuntime final {
public:
	AwsIamSdkRuntime() { Aws::InitAPI(options_); }
	~AwsIamSdkRuntime() { Aws::ShutdownAPI(options_); }

	AwsIamSdkRuntime(const AwsIamSdkRuntime&) = delete;
	AwsIamSdkRuntime& operator=(const AwsIamSdkRuntime&) = delete;

private:
	Aws::SDKOptions options_;
};

class AwsIamSensitiveStringCleanup final {
public:
	explicit AwsIamSensitiveStringCleanup(Aws::String& value) : value_(value) {}
	~AwsIamSensitiveStringCleanup() noexcept {
		if (!value_.empty()) {
			OPENSSL_cleanse(&value_[0], value_.size());
		}
	}

	AwsIamSensitiveStringCleanup(const AwsIamSensitiveStringCleanup&) = delete;
	AwsIamSensitiveStringCleanup& operator=(const AwsIamSensitiveStringCleanup&) = delete;

private:
	Aws::String& value_;
};

class AwsIamRdsSigner final : public AwsIamTokenSigner {
public:
	AwsIamSignResult sign(const AwsIamTokenKey& key) override {
		Aws::RDS::RDSClient& rds_client = client_for_region(key.region);
		Aws::String token = rds_client.GenerateConnectAuthToken(
			key.endpoint.c_str(), key.region.c_str(), key.port,
			key.database_user.c_str());
		AwsIamSensitiveStringCleanup token_cleanup(token);

		AwsIamSignResult result;
		if (token.empty()) {
			result.status = AwsIamStatus::CREDENTIAL_PROVIDER_ERROR;
			return result;
		}
		result.status = AwsIamStatus::OK;
		result.token = SecureString(std::string_view(token.data(), token.size()));
		return result;
	}

private:
	Aws::RDS::RDSClient& client_for_region(const std::string& region) {
		std::lock_guard<std::mutex> lock(clients_mutex_);
		auto found = regional_clients_.find(region);
		if (found == regional_clients_.end()) {
			Aws::Client::ClientConfiguration client_config;
			client_config.region = region.c_str();
			found = regional_clients_.emplace(
				region, std::make_unique<Aws::RDS::RDSClient>(client_config)).first;
		}
		return *found->second;
	}

	std::mutex clients_mutex_;
	std::unordered_map<std::string, std::unique_ptr<Aws::RDS::RDSClient>> regional_clients_;
};

class AwsIamSdkTokenSource final : public AwsIamTokenSource {
public:
	explicit AwsIamSdkTokenSource(const AwsIamRuntimeConfig& config)
		: signer_(std::make_shared<AwsIamRdsSigner>()) {
		AwsIamTokenManagerConfig manager_config(config.max_total_waiters);
		manager_config.max_total_waiters = config.max_total_waiters;
		manager_config.max_waiters_per_key = config.max_waiters_per_key;
		manager_ = std::make_unique<AwsIamTokenManager>(signer_, std::move(manager_config));
	}

	AwsIamRequestHandle request(const AwsIamTokenKey& key, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink> sink) override {
		return manager_->request(key, opaque_id, std::move(sink));
	}

	AwsIamTokenResult request_blocking(const AwsIamTokenKey& key,
		std::chrono::steady_clock::time_point deadline) override {
		return manager_->request_blocking(key, deadline);
	}

	void cancel(AwsIamRequestHandle handle) override { manager_->cancel(handle); }
	void invalidate(const AwsIamTokenKey& key, uint64_t generation) override {
		manager_->invalidate(key, generation);
	}
	void record_backend_connection(bool success) override {
		manager_->record_backend_connection(success);
	}
	AwsIamStatsSnapshot snapshot() const override { return manager_->snapshot(); }

private:
	// Destruction is reverse declaration order: workers, regional clients,
	// then ShutdownAPI. SDK signing remains non-interruptible; shutdown joins
	// any in-progress manager signing call before destroying these members.
	AwsIamSdkRuntime runtime_;
	std::shared_ptr<AwsIamRdsSigner> signer_;
	std::unique_ptr<AwsIamTokenManager> manager_;
};
#endif
} // namespace

void AwsIamTokenSourceLease::release() {
	if (source_ == nullptr) return;
	{
		std::lock_guard<std::mutex> lock(global_source_mutex);
		if (global_source_leases != 0) --global_source_leases;
	}
	source_ = nullptr;
	global_source_cv.notify_all();
}

AwsIamTokenSourceLease::~AwsIamTokenSourceLease() { release(); }

AwsIamTokenSourceLease::AwsIamTokenSourceLease(
	AwsIamTokenSourceLease&& other) noexcept : source_(other.source_) {
	other.source_ = nullptr;
}

AwsIamTokenSourceLease& AwsIamTokenSourceLease::operator=(
	AwsIamTokenSourceLease&& other) noexcept {
	if (this != &other) {
		release();
		source_ = other.source_;
		other.source_ = nullptr;
	}
	return *this;
}

void publish_global_aws_iam_token_source(AwsIamTokenSource *source) {
	std::lock_guard<std::mutex> lock(global_source_mutex);
	leased_global_source = source;
	global_source_accepting = source != nullptr;
	GloAwsIamTokenSource = source;
}

AwsIamTokenSourceLease acquire_global_aws_iam_token_source() {
	std::lock_guard<std::mutex> lock(global_source_mutex);
	if (!global_source_accepting || leased_global_source == nullptr) return {};
	++global_source_leases;
	return AwsIamTokenSourceLease(leased_global_source);
}

void shutdown_global_aws_iam_token_source() {
	std::unique_lock<std::mutex> lock(global_source_mutex);
	global_source_accepting = false;
	GloAwsIamTokenSource = nullptr;
	global_source_cv.wait(lock, [] { return global_source_leases == 0; });
	leased_global_source = nullptr;
}

std::unique_ptr<AwsIamTokenSource> create_aws_iam_token_source(
	const AwsIamRuntimeConfig& config) {
#ifdef PROXYSQLAWSIAM
	return std::make_unique<AwsIamSdkTokenSource>(config);
#else
	(void)config;
	return std::make_unique<AwsIamNotCompiledTokenSource>();
#endif
}
