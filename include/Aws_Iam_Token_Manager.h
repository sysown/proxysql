#ifndef AWS_IAM_TOKEN_MANAGER_H
#define AWS_IAM_TOKEN_MANAGER_H

#include "Aws_Iam_Types.h"

#include <openssl/crypto.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace prometheus { class Registry; }

class SecureString {
public:
	using CleanseFn = void (*)(void*, size_t);
	SecureString();
	explicit SecureString(std::string_view, CleanseFn = OPENSSL_cleanse);
	SecureString(SecureString&&) noexcept;
	SecureString& operator=(SecureString&&) noexcept;
	SecureString(const SecureString&) = delete;
	SecureString& operator=(const SecureString&) = delete;
	~SecureString();
	SecureString clone() const;
	const char* c_str() const;
	size_t size() const;
	bool empty() const;
	void clear();

private:
	std::unique_ptr<unsigned char[]> bytes_;
	size_t size_ { 0 };
	CleanseFn cleanse_ { OPENSSL_cleanse };
};

enum class AwsIamStatus : uint8_t {
	OK, SUPPORT_NOT_COMPILED, INVALID_CONFIG, PROVIDER_ERROR,
	CREDENTIAL_PROVIDER_ERROR, QUEUE_FULL, WAITER_LIMIT, TIMEOUT,
	CANCELED, SHUTDOWN,
};

struct AwsIamRedactedFailure {
	std::string category;
	std::string aws_error_code;
	std::string request_id;
};

struct AwsIamTokenResult {
	AwsIamStatus status { AwsIamStatus::PROVIDER_ERROR };
	SecureString token;
	std::chrono::steady_clock::time_point expires_at {};
	uint64_t generation { 0 };
	AwsIamRedactedFailure failure;
};

struct AwsIamSignResult {
	AwsIamStatus status { AwsIamStatus::PROVIDER_ERROR };
	SecureString token;
	AwsIamRedactedFailure failure;
};

class AwsIamTokenSigner {
public:
	virtual AwsIamSignResult sign(const AwsIamTokenKey&) = 0;
	virtual ~AwsIamTokenSigner() = default;
};

struct AwsIamCompletion {
	uint64_t opaque_id { 0 };
	AwsIamTokenResult result;
};

class AwsIamCompletionSink {
public:
	virtual void post(AwsIamCompletion&&) = 0;
	virtual ~AwsIamCompletionSink() = default;
};

struct AwsIamRequestHandle { uint64_t value { 0 }; };

struct AwsIamStatsSnapshot {
	uint64_t token_requests { 0 };
	uint64_t token_cache_hits { 0 };
	uint64_t token_refresh_successes { 0 };
	uint64_t token_refresh_failures { 0 };
	uint64_t credential_provider_failures { 0 };
	uint64_t queue_rejections { 0 };
	uint64_t backend_connection_successes { 0 };
	uint64_t backend_connection_failures { 0 };
	uint64_t token_cache_entries { 0 };
	uint64_t in_flight_generations { 0 };
	uint64_t queued_generations { 0 };
	uint64_t waiting_sessions { 0 };
};

struct AwsIamNamedStat {
	const char *name;
	uint64_t value;
};

using AwsIamNamedStats = std::array<AwsIamNamedStat, 12>;

AwsIamNamedStats aws_iam_stats_mysql_global_rows(const AwsIamStatsSnapshot&);
void initialize_aws_iam_prometheus_metrics(prometheus::Registry&);
void update_aws_iam_prometheus_metrics(const AwsIamStatsSnapshot&);

class AwsIamTokenSource {
public:
	virtual bool support_compiled() const { return true; }
	virtual AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink>) = 0;
	virtual AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point deadline) = 0;
	virtual void cancel(AwsIamRequestHandle) = 0;
	virtual void invalidate(const AwsIamTokenKey&, uint64_t generation) = 0;
	virtual void record_backend_connection(bool success) = 0;
	virtual void record_waiting_session(bool waiting) = 0;
	virtual AwsIamStatsSnapshot snapshot() const = 0;
	virtual ~AwsIamTokenSource() = default;
};

struct AwsIamTokenManagerConfig {
	using Clock = std::function<std::chrono::steady_clock::time_point()>;
	using Jitter = std::function<std::chrono::milliseconds(std::chrono::milliseconds)>;
	explicit AwsIamTokenManagerConfig(size_t mysql_max_connections);

	size_t max_pending_keys { 1024 };
	size_t max_cache_entries { 1024 };
	size_t max_total_waiters;
	size_t max_waiters_per_key;
	size_t mysql_max_connections;
	std::chrono::steady_clock::duration minimum_remaining_lifetime { std::chrono::minutes(2) };
	std::chrono::steady_clock::duration generated_lifetime { std::chrono::minutes(15) };
	std::chrono::milliseconds initial_backoff { 100 };
	std::chrono::milliseconds maximum_backoff { 5000 };
	Clock clock;
	Jitter jitter;
	std::function<void()> before_dispatch;
	std::function<void()> before_finish_publish;
};

class AwsIamTokenManager final : public AwsIamTokenSource {
public:
	AwsIamTokenManager(std::shared_ptr<AwsIamTokenSigner>, AwsIamTokenManagerConfig);
	~AwsIamTokenManager() override;
	AwsIamTokenManager(const AwsIamTokenManager&) = delete;
	AwsIamTokenManager& operator=(const AwsIamTokenManager&) = delete;
	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink>) override;
	AwsIamTokenResult request_blocking(const AwsIamTokenKey&,
		std::chrono::steady_clock::time_point deadline) override;
	void cancel(AwsIamRequestHandle) override;
	void invalidate(const AwsIamTokenKey&, uint64_t generation) override;
	void record_backend_connection(bool success) override;
	void record_waiting_session(bool waiting) override;
	AwsIamStatsSnapshot snapshot() const override;

private:
	class Impl;
	std::unique_ptr<Impl> impl_;
};

#endif
