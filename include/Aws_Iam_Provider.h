#ifndef AWS_IAM_PROVIDER_H
#define AWS_IAM_PROVIDER_H

#include "Aws_Iam_Types.h"

#include <openssl/crypto.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace prometheus { class Registry; }

inline void aws_iam_default_cleanse(void* bytes, size_t bytes_size) {
	OPENSSL_cleanse(bytes, bytes_size);
}

class SecureString {
public:
	// A custom cleanser must remain callable for the SecureString's full
	// lifetime. Provider DSOs must use the process-lifetime default cleanser
	// for values that can outlive the provider module.
	using CleanseFn = void (*)(void*, size_t);

	SecureString() = default;
explicit SecureString(std::string_view value, CleanseFn cleanse = aws_iam_default_cleanse)
		: size_(value.size()), cleanse_(cleanse ? cleanse : aws_iam_default_cleanse) {
	if (size_ != 0) {
		bytes_ = std::make_unique<unsigned char[]>(size_ + 1);
		std::memcpy(bytes_.get(), value.data(), size_);
		bytes_[size_] = 0;
	}
}
	SecureString(SecureString&& other) noexcept
		: bytes_(std::move(other.bytes_)), size_(other.size_), cleanse_(other.cleanse_) {
		other.size_ = 0;
		other.cleanse_ = aws_iam_default_cleanse;
	}
	SecureString& operator=(SecureString&& other) noexcept {
		if (this != &other) {
			clear();
			bytes_ = std::move(other.bytes_);
			size_ = other.size_;
			cleanse_ = other.cleanse_;
			other.size_ = 0;
			other.cleanse_ = aws_iam_default_cleanse;
		}
		return *this;
	}
	SecureString(const SecureString&) = delete;
	SecureString& operator=(const SecureString&) = delete;
	~SecureString() { clear(); }

	SecureString clone() const {
		return empty() ? SecureString() :
			SecureString(std::string_view(c_str(), size_), cleanse_);
	}
	const char* c_str() const {
		return bytes_ ? reinterpret_cast<const char*>(bytes_.get()) : "";
	}
	size_t size() const { return size_; }
	bool empty() const { return size_ == 0; }
	void clear() {
		if (bytes_) {
			cleanse_(bytes_.get(), size_);
			bytes_[size_] = 0;
			bytes_.reset();
		}
		size_ = 0;
	}

private:
	std::unique_ptr<unsigned char[]> bytes_;
	size_t size_ { 0 };
	CleanseFn cleanse_ { aws_iam_default_cleanse };
};

using AwsIamModuleHandle = void *;

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

struct AwsIamRuntimeConfig {
	size_t max_total_waiters;
	size_t max_waiters_per_key;
};

using AwsIamTokenSourceDestroyFn = void (*)(AwsIamTokenSource *);

class AwsIamTokenSourceLease {
public:
	AwsIamTokenSourceLease() = default;
	~AwsIamTokenSourceLease();
	AwsIamTokenSourceLease(AwsIamTokenSourceLease&& other) noexcept;
	AwsIamTokenSourceLease& operator=(AwsIamTokenSourceLease&& other) noexcept;

	AwsIamTokenSource *get() const { return source_; }
	AwsIamTokenSource *operator->() const { return source_; }
	explicit operator bool() const { return source_ != nullptr; }

	AwsIamTokenSourceLease(const AwsIamTokenSourceLease&) = delete;
	AwsIamTokenSourceLease& operator=(const AwsIamTokenSourceLease&) = delete;

private:
	explicit AwsIamTokenSourceLease(AwsIamTokenSource *source) : source_(source) {}
	void release();
	AwsIamTokenSource *source_ { nullptr };

	friend AwsIamTokenSourceLease acquire_global_aws_iam_token_source();
};

std::unique_ptr<AwsIamTokenSource> create_aws_iam_token_source(
	const AwsIamRuntimeConfig& config);

void publish_global_aws_iam_token_source(AwsIamTokenSource *source);
AwsIamTokenSourceLease acquire_global_aws_iam_token_source();
void shutdown_global_aws_iam_token_source();

// Transfers ownership of a provider created by a dynamically loaded plugin.
// `module_handle` is an extra dlopen() reference retained by core until every
// source lease has drained and `destroy` has run.
// `destroy` runs while core still owns the retirement claim. It must not call
// uninstall_global_aws_iam_token_source() or
// shutdown_global_aws_iam_token_source(), because either call would wait for
// that same claim and deadlock.
bool install_global_aws_iam_token_source(
	AwsIamTokenSource *source, AwsIamTokenSourceDestroyFn destroy, AwsIamModuleHandle module_handle);
bool uninstall_global_aws_iam_token_source(AwsIamTokenSource *expected_source);

extern AwsIamTokenSource* GloAwsIamTokenSource;

#endif
