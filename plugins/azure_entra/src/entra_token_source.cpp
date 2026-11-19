#include "entra_token_source.h"

#include <algorithm>
#include <fstream>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace {

constexpr std::chrono::seconds kUsableMargin { 30 };
constexpr std::chrono::seconds kFailureBackoff { 2 };
constexpr std::chrono::seconds kMaxRefreshBackoff { 60 };
constexpr size_t kMaxAssertionBytes { 16 * 1024 };
constexpr std::chrono::seconds kInvalidateInterval { 60 };

std::chrono::seconds refresh_lead(std::chrono::seconds lifetime) {
	return lifetime >= std::chrono::minutes(20) ? std::chrono::minutes(10) : lifetime / 2;
}

AwsIamTokenResult status_only(AwsIamStatus status) {
	AwsIamTokenResult r;
	r.status = status;
	return r;
}

} // namespace

AzureEntraTokenSource::AzureEntraTokenSource(EntraConfig cfg, HttpPostFn post,
	AwsIamRuntimeConfig limits, std::function<bool(std::string&)> read_assertion,
	std::function<Clock::time_point()> now)
	: cfg_(std::move(cfg)), post_(std::move(post)), limits_(limits),
	  read_assertion_(std::move(read_assertion)), now_(std::move(now)) {
	worker_ = std::thread([this] { run(); });
}

AzureEntraTokenSource::~AzureEntraTokenSource() {
	{
		std::lock_guard<std::mutex> lock(mutex_);
		stopping_ = true;
	}
	cv_.notify_all();
	if (worker_.joinable()) worker_.join();
}

bool AzureEntraTokenSource::usable_locked(Clock::time_point now) const {
	return !token_.empty() && now + kUsableMargin < expires_at_;
}

bool AzureEntraTokenSource::refresh_due_locked(Clock::time_point now) const {
	return !token_.empty() && now >= refresh_at_ && now >= backoff_until_;
}

AwsIamTokenResult AzureEntraTokenSource::cached_result_locked() const {
	AwsIamTokenResult r;
	r.status = AwsIamStatus::OK;
	r.token = token_.clone();
	r.expires_at = expires_at_;
	r.generation = generation_;
	return r;
}

AwsIamTokenResult AzureEntraTokenSource::failure_result_locked() const {
	AwsIamTokenResult r;
	r.status = last_failure_.category == "credential_provider_error"
		? AwsIamStatus::CREDENTIAL_PROVIDER_ERROR : AwsIamStatus::PROVIDER_ERROR;
	r.failure = last_failure_;
	return r;
}

AwsIamRequestHandle AzureEntraTokenSource::request(const AwsIamTokenKey&, uint64_t opaque_id,
	std::weak_ptr<AwsIamCompletionSink> sink) {
	AwsIamRequestHandle handle {};
	AwsIamCompletion immediate;
	immediate.opaque_id = opaque_id;
	bool answer_now = true;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		++stats_.token_requests;
		const Clock::time_point now = now_();
		if (stopping_) {
			immediate.result = status_only(AwsIamStatus::SHUTDOWN);
		} else if (usable_locked(now)) {
			++stats_.token_cache_hits;
			immediate.result = cached_result_locked();
		} else if (now < backoff_until_) {
			immediate.result = failure_result_locked();
		} else if (waiters_.size() >= limits_.max_total_waiters) {
			++stats_.queue_rejections;
			immediate.result = status_only(AwsIamStatus::WAITER_LIMIT);
		} else {
			handle.value = next_handle_++;
			waiters_.push_back({ handle.value, opaque_id, std::move(sink) });
			fetch_requested_ = true;
			answer_now = false;
		}
	}
	if (answer_now) {
		if (auto target = sink.lock()) target->post(std::move(immediate));
	} else {
		cv_.notify_all();
	}
	return handle;
}

AwsIamTokenResult AzureEntraTokenSource::request_blocking(const AwsIamTokenKey&,
	Clock::time_point deadline) {
	std::unique_lock<std::mutex> lock(mutex_);
	++stats_.token_requests;
	if (stopping_) return status_only(AwsIamStatus::SHUTDOWN);
	if (usable_locked(now_())) {
		++stats_.token_cache_hits;
		return cached_result_locked();
	}
	if (now_() < backoff_until_) return failure_result_locked();
	const uint64_t fetches_before = fetches_done_;
	fetch_requested_ = true;
	cv_.notify_all();
	const bool finished = cv_.wait_until(lock, deadline,
		[&] { return stopping_ || fetches_done_ != fetches_before; });
	if (stopping_) return status_only(AwsIamStatus::SHUTDOWN);
	if (!finished) return status_only(AwsIamStatus::TIMEOUT);
	return usable_locked(now_()) ? cached_result_locked() : failure_result_locked();
}

void AzureEntraTokenSource::cancel(AwsIamRequestHandle handle) {
	std::lock_guard<std::mutex> lock(mutex_);
	for (auto it = waiters_.begin(); it != waiters_.end(); ++it) {
		if (it->handle == handle.value) {
			waiters_.erase(it);
			return;
		}
	}
}

void AzureEntraTokenSource::invalidate(const AwsIamTokenKey&, uint64_t generation) {
	{
		std::lock_guard<std::mutex> lock(mutex_);
		const Clock::time_point now = now_();
		if (token_.empty() || generation != generation_) return;
		if (invalidated_once_ && now - last_invalidate_ < kInvalidateInterval) return;
		// One token serves every user, and a 1045 is usually one user's mapping:
		// refresh, but keep serving the current token (#6649).
		fetch_requested_ = true;
		invalidated_once_ = true;
		last_invalidate_ = now;
	}
	cv_.notify_all();
}

void AzureEntraTokenSource::record_backend_connection(bool success) {
	std::lock_guard<std::mutex> lock(mutex_);
	++(success ? stats_.backend_connection_successes : stats_.backend_connection_failures);
}

void AzureEntraTokenSource::record_waiting_session(bool waiting) {
	std::lock_guard<std::mutex> lock(mutex_);
	if (waiting) ++stats_.waiting_sessions;
	else if (stats_.waiting_sessions != 0) --stats_.waiting_sessions;
}

AwsIamStatsSnapshot AzureEntraTokenSource::snapshot() const {
	std::lock_guard<std::mutex> lock(mutex_);
	AwsIamStatsSnapshot s = stats_;
	s.token_cache_entries = token_.empty() ? 0 : 1;
	s.in_flight_generations = fetching_ ? 1 : 0;
	s.queued_generations = fetch_requested_ ? 1 : 0;
	return s;
}

void AzureEntraTokenSource::wake() {
	cv_.notify_all();
}

void AzureEntraTokenSource::apply_response_locked(EntraTokenResponse& response, Clock::time_point now) {
	if (response.ok) {
		token_ = std::move(response.access_token);
		++generation_;
		expires_at_ = now + response.expires_in;
		refresh_at_ = expires_at_ - refresh_lead(response.expires_in);
		backoff_until_ = {};
		failed_refreshes_ = 0;
		++stats_.token_refresh_successes;
		return;
	}
	// A failed refresh keeps a still-valid token (usable_locked decides).
	last_failure_ = response.failure;
	// While a usable token is held, double the wait (2 s up to 60 s) so an
	// Entra outage or throttling does not get a request every 2 s.
	backoff_until_ = now + (usable_locked(now)
		? std::min(kFailureBackoff * (1u << std::min(failed_refreshes_, 5u)), kMaxRefreshBackoff)
		: kFailureBackoff);
	++failed_refreshes_;
	++stats_.token_refresh_failures;
	if (last_failure_.category == "credential_provider_error") ++stats_.credential_provider_failures;
}

template <typename MakeResult>
AzureEntraTokenSource::Completions AzureEntraTokenSource::take_waiters_locked(MakeResult make_result) {
	Completions out;
	for (Waiter& w : waiters_) {
		AwsIamCompletion c;
		c.opaque_id = w.opaque_id;
		c.result = make_result();
		out.emplace_back(std::move(w.sink), std::move(c));
	}
	waiters_.clear();
	return out;
}

void AzureEntraTokenSource::post_completions(Completions& out) {
	for (auto& o : out) {
		if (auto target = o.first.lock()) target->post(std::move(o.second));
	}
}

void AzureEntraTokenSource::run() {
	Completions out;
	{
		std::unique_lock<std::mutex> lock(mutex_);
		while (!stopping_) {
			// Re-check every second: the refresh time is a deadline on the injected clock.
			cv_.wait_for(lock, 1s, [this] { return stopping_ || fetch_requested_ || refresh_due_locked(now_()); });
			if (stopping_) break;
			if (!fetch_requested_ && !refresh_due_locked(now_())) continue;

			fetching_ = true;
			fetch_requested_ = false;
			lock.unlock();
			EntraTokenResponse response = exchange_workload_identity(cfg_, read_assertion_, post_);
			lock.lock();
			fetching_ = false;
			++fetches_done_;
			if (stopping_) break;

			apply_response_locked(response, now_());
			// Every waiter queued until now gets this fetch's outcome.
			out = take_waiters_locked([this, &response] {
				return response.ok ? cached_result_locked() : failure_result_locked();
			});
			fetch_requested_ = false;
			cv_.notify_all();
			lock.unlock();
			post_completions(out);
			lock.lock();
		}
		out = take_waiters_locked([] { return status_only(AwsIamStatus::SHUTDOWN); });
		cv_.notify_all();
	}
	post_completions(out);
}

std::function<bool(std::string&)> file_assertion_reader(std::string path) {
	return [path = std::move(path)](std::string& out) {
		std::ifstream in(path, std::ios::binary);
		if (!in) return false;
		out.assign(kMaxAssertionBytes + 1, '\0');
		in.read(&out[0], static_cast<std::streamsize>(out.size()));
		out.resize(static_cast<size_t>(in.gcount()));
		if (out.size() > kMaxAssertionBytes) {
			out.clear();
			return false;
		}
		while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) out.pop_back();
		return !out.empty();
	};
}
