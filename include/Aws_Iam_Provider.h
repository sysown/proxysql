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
			bytes_ = std::make_unique<char[]>(size_ + 1);
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
		return bytes_ ? bytes_.get() : "";
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
	std::unique_ptr<char[]> bytes_;
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
/**
 * @brief stats_mysql_global rows for one provider (#6649).
 * @param provider The token slot.
 * @param stats The slot's counters.
 * @return AwsIam_* or AzureEntra_* rows.
 */
AwsIamNamedStats backend_token_stats_mysql_global_rows(BackendTokenProvider, const AwsIamStatsSnapshot&);
void initialize_aws_iam_prometheus_metrics(prometheus::Registry&);
void update_aws_iam_prometheus_metrics(const AwsIamStatsSnapshot&);
/**
 * @brief Register one provider's Prometheus series once (#6649).
 * @param provider The token slot: proxysql_mysql_aws_iam_* or proxysql_mysql_azure_entra_*.
 * @param registry The registry to add the series to.
 */
void initialize_backend_token_prometheus_metrics(BackendTokenProvider, prometheus::Registry&);
/**
 * @brief Set one provider's Prometheus series from a stats snapshot (#6649).
 * @param provider The token slot.
 * @param stats The slot's counters.
 */
void update_backend_token_prometheus_metrics(BackendTokenProvider, const AwsIamStatsSnapshot&);

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

struct BackendTokenSlot;

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
	AwsIamTokenSourceLease(AwsIamTokenSource *source, BackendTokenSlot *slot)
		: source_(source), slot_(slot) {}
	void release();
	AwsIamTokenSource *source_ { nullptr };
	BackendTokenSlot *slot_ { nullptr };

	friend AwsIamTokenSourceLease acquire_backend_token_source(BackendTokenProvider);
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

// The same operations for one provider's slot; the *_aws_iam_* functions above
// act on the AWS_IAM slot. GloAwsIamTokenSource and the AWS Prometheus metrics
// follow the AWS_IAM slot only.
/**
 * @brief Publish a source in a slot without ownership. Refused while the slot
 *   retires, or when the slot holds a different plugin-owned source.
 * @param provider The token slot.
 * @param source The source, or nullptr to clear the slot.
 */
void publish_global_backend_token_source(BackendTokenProvider, AwsIamTokenSource *source);
/**
 * @brief Install a plugin-owned source in an empty slot.
 * @param provider The token slot.
 * @param source The source; the slot owns it from now on.
 * @param destroy Destroys the source when the slot retires it, after the last lease ends.
 * @param module_handle The plugin's dlopen handle, kept with the source.
 * @return false if an argument is null, or the slot has a source or is retiring.
 */
bool install_global_backend_token_source(BackendTokenProvider, AwsIamTokenSource *source,
	AwsIamTokenSourceDestroyFn destroy, AwsIamModuleHandle module_handle);
/**
 * @brief Retire the slot's source if it is expected_source; waits until every
 *   lease ends, then destroys it.
 * @param provider The token slot.
 * @param expected_source The source the caller installed.
 * @return false unless expected_source is the plugin-installed source of the slot.
 */
bool uninstall_global_backend_token_source(BackendTokenProvider, AwsIamTokenSource *expected_source);
/**
 * @brief Lease the slot's source; the source is not destroyed while the lease lives.
 * @param provider The token slot.
 * @return An empty lease if the slot is empty or retired.
 */
AwsIamTokenSourceLease acquire_backend_token_source(BackendTokenProvider);
/** @brief Retire every slot; process shutdown calls it once. */
void shutdown_global_backend_token_sources();

extern AwsIamTokenSource* GloAwsIamTokenSource;

#endif
