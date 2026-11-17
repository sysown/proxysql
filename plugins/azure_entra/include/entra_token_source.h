#ifndef AZURE_ENTRA_TOKEN_SOURCE_H
#define AZURE_ENTRA_TOKEN_SOURCE_H

#include "Aws_Iam_Provider.h"
#include "entra_config.h"
#include "entra_exchange.h"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

/**
 * @brief Token source for 'azure_entra' backends (#6649).
 * @details One Entra access token serves every key: it is bound to the
 *   identity, not to a server or a database user. One background thread does
 *   every HTTP exchange, so request() never blocks a session thread, and
 *   requests on a cold cache share one fetch. Rules:
 *   - a token is usable until 30 s before it expires;
 *   - it is refreshed 10 min before expiry (half its lifetime if shorter than
 *     20 min), and a failed refresh keeps the old token;
 *   - after a failed fetch, requests get the same failure for 2 s;
 *   - invalidate() is honoured at most once per 60 s, so one rejected user
 *     cannot empty the shared cache on every attempt.
 */
class AzureEntraTokenSource final : public AwsIamTokenSource {
public:
	using Clock = std::chrono::steady_clock;

	AzureEntraTokenSource(EntraConfig cfg, HttpPostFn post, AwsIamRuntimeConfig limits,
		std::function<bool(std::string&)> read_assertion,
		std::function<Clock::time_point()> now = &Clock::now);
	~AzureEntraTokenSource() override;

	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink>) override;
	AwsIamTokenResult request_blocking(const AwsIamTokenKey&, Clock::time_point deadline) override;
	void cancel(AwsIamRequestHandle) override;
	void invalidate(const AwsIamTokenKey&, uint64_t generation) override;
	void record_backend_connection(bool success) override;
	void record_waiting_session(bool waiting) override;
	AwsIamStatsSnapshot snapshot() const override;

	/** @brief Re-check the refresh time now (the worker otherwise re-checks every second). */
	void wake();

private:
	struct Waiter {
		uint64_t handle;
		uint64_t opaque_id;
		std::weak_ptr<AwsIamCompletionSink> sink;
	};

	bool usable_locked(Clock::time_point now) const;
	bool refresh_due_locked(Clock::time_point now) const;
	AwsIamTokenResult cached_result_locked() const;
	AwsIamTokenResult failure_result_locked() const;
	void run();

	const EntraConfig cfg_;
	const HttpPostFn post_;
	const AwsIamRuntimeConfig limits_;
	const std::function<bool(std::string&)> read_assertion_;
	const std::function<Clock::time_point()> now_;

	mutable std::mutex mutex_;
	std::condition_variable cv_;
	SecureString token_;
	Clock::time_point expires_at_ {};
	Clock::time_point refresh_at_ {};
	uint64_t generation_ { 0 };
	Clock::time_point backoff_until_ {};
	unsigned failed_refreshes_ { 0 };
	AwsIamRedactedFailure last_failure_;
	Clock::time_point last_invalidate_ {};
	bool invalidated_once_ { false };
	bool fetch_requested_ { false };
	bool fetching_ { false };
	uint64_t fetches_done_ { 0 };
	bool stopping_ { false };
	uint64_t next_handle_ { 1 };
	std::deque<Waiter> waiters_;
	AwsIamStatsSnapshot stats_;
	std::thread worker_;
};

/**
 * @brief Read the federated token file on every call (the kubelet rotates it).
 * @param path The file in AZURE_FEDERATED_TOKEN_FILE.
 * @return A reader that fails on a missing, empty or over-16-KiB file.
 */
std::function<bool(std::string&)> file_assertion_reader(std::string path);

#endif // AZURE_ENTRA_TOKEN_SOURCE_H
