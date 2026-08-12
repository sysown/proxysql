#include "tap.h"

#include "Aws_Iam_Token_Manager.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace {

class FakeClock {
public:
	std::chrono::steady_clock::time_point now() const {
		return std::chrono::steady_clock::time_point(std::chrono::nanoseconds(nanos_.load()));
	}
	void advance(std::chrono::nanoseconds amount) { nanos_.fetch_add(amount.count()); }
private:
	std::atomic<int64_t> nanos_ { 0 };
};

struct ScriptedSign {
	AwsIamStatus status { AwsIamStatus::OK };
	std::string token { "token" };
	AwsIamRedactedFailure failure;
	SecureString::CleanseFn cleanse { OPENSSL_cleanse };
};

class FakeSigner final : public AwsIamTokenSigner {
public:
	AwsIamSignResult sign(const AwsIamTokenKey& key) override {
		std::unique_lock<std::mutex> lock(mu_);
		++calls_;
		keys_.push_back(key);
		entered_.notify_all();
		blocked_.wait(lock, [&] { return !block_; });
		ScriptedSign scripted;
		if (!script_.empty()) {
			scripted = std::move(script_.front());
			script_.pop_front();
		} else {
			scripted.token = key.endpoint + ":" + std::to_string(key.port) + ":" +
				key.region + ":" + key.database_user;
		}
		AwsIamSignResult result;
		result.status = scripted.status;
		result.failure = std::move(scripted.failure);
		if (!scripted.token.empty()) {
			result.token = SecureString(scripted.token, scripted.cleanse);
		}
		return result;
	}

	void push(ScriptedSign scripted) {
		std::lock_guard<std::mutex> lock(mu_);
		script_.push_back(std::move(scripted));
	}
	void set_blocked(bool value) {
		std::lock_guard<std::mutex> lock(mu_);
		block_ = value;
		if (!value) blocked_.notify_all();
	}
	bool wait_for_calls(size_t count, std::chrono::milliseconds timeout = 2s) {
		std::unique_lock<std::mutex> lock(mu_);
		return entered_.wait_for(lock, timeout, [&] { return calls_ >= count; });
	}
	size_t calls() const {
		std::lock_guard<std::mutex> lock(mu_);
		return calls_;
	}
private:
	mutable std::mutex mu_;
	std::condition_variable entered_;
	std::condition_variable blocked_;
	bool block_ { false };
	size_t calls_ { 0 };
	std::vector<AwsIamTokenKey> keys_;
	std::deque<ScriptedSign> script_;
};

class CollectingSink final : public AwsIamCompletionSink {
public:
	void post(AwsIamCompletion&& completion) override {
		std::lock_guard<std::mutex> lock(mu_);
		completions_.push_back(std::move(completion));
		cv_.notify_all();
	}
	bool wait_for(size_t count, std::chrono::milliseconds timeout = 2s) {
		std::unique_lock<std::mutex> lock(mu_);
		return cv_.wait_for(lock, timeout, [&] { return completions_.size() >= count; });
	}
	size_t size() const {
		std::lock_guard<std::mutex> lock(mu_);
		return completions_.size();
	}
	AwsIamCompletion take(size_t pos = 0) {
		std::lock_guard<std::mutex> lock(mu_);
		AwsIamCompletion value = std::move(completions_.at(pos));
		completions_.erase(completions_.begin() + pos);
		return value;
	}
private:
	mutable std::mutex mu_;
	std::condition_variable cv_;
	std::vector<AwsIamCompletion> completions_;
};

AwsIamTokenKey key(std::string endpoint = "db.us-east-1.rds.amazonaws.com",
	uint16_t port = 3306, std::string region = "us-east-1", std::string user = "app") {
	return { std::move(endpoint), port, std::move(region), std::move(user) };
}

AwsIamTokenManagerConfig config(FakeClock& clock, size_t mysql_max = 4096) {
	AwsIamTokenManagerConfig value(mysql_max);
	value.clock = [&clock] { return clock.now(); };
	value.jitter = [](std::chrono::milliseconds) { return 0ms; };
	return value;
}

AwsIamTokenResult blocking(AwsIamTokenSource& source, const AwsIamTokenKey& token_key) {
	return source.request_blocking(token_key, std::chrono::steady_clock::now() + 2s);
}

std::mutex cleanse_mu;
std::vector<std::string> cleansed_values;
bool all_cleanse_writes_zero = true;

void observing_cleanse(void* data, size_t size) {
	std::lock_guard<std::mutex> lock(cleanse_mu);
	cleansed_values.emplace_back(static_cast<const char*>(data), size);
	std::memset(data, 0, size);
	for (size_t i = 0; i < size; ++i) {
		if (static_cast<unsigned char*>(data)[i] != 0) all_cleanse_writes_zero = false;
	}
}

void reset_cleanse_observer() {
	std::lock_guard<std::mutex> lock(cleanse_mu);
	cleansed_values.clear();
	all_cleanse_writes_zero = true;
}

size_t cleanse_count_for(const std::string& value) {
	std::lock_guard<std::mutex> lock(cleanse_mu);
	return std::count(cleansed_values.begin(), cleansed_values.end(), value);
}

void test_secure_string_ownership_and_cleanse() {
	reset_cleanse_observer();
	{
		SecureString cleared("clear-secret", observing_cleanse);
		cleared.clear();
		SecureString target("old-secret", observing_cleanse);
		SecureString source("new-secret", observing_cleanse);
		target = std::move(source);
		SecureString original("clone-secret", observing_cleanse);
		SecureString copy = original.clone();
		ok(copy.c_str() != original.c_str() && std::strcmp(copy.c_str(), original.c_str()) == 0,
			"clone creates a distinct move-only secure buffer");
	}
	ok(cleanse_count_for("clear-secret") == 1 && cleanse_count_for("old-secret") == 1 &&
		cleanse_count_for("new-secret") == 1 && cleanse_count_for("clone-secret") == 2,
		"clear, move assignment, clone destruction, and destruction cleanse every owned value");
	ok(all_cleanse_writes_zero, "the configured cleanser overwrites every observed token byte with zero");
}

void test_cache_partition_expiry_and_invalidation() {
	FakeClock clock;
	auto signer = std::make_shared<FakeSigner>();
	AwsIamTokenManager manager(signer, config(clock));
	const AwsIamTokenKey base = key();
	AwsIamTokenResult first = blocking(manager, base);
	const auto generated_at = clock.now();
	ok(first.status == AwsIamStatus::OK && first.expires_at == generated_at + 15min,
		"successful tokens expire 15 minutes from the monotonic generation point");

	clock.advance(12min + 59s);
	AwsIamTokenResult hit = blocking(manager, base);
	ok(hit.status == AwsIamStatus::OK && signer->calls() == 1,
		"a cached token with more than two minutes remaining is a hit");
	clock.advance(1s);
	AwsIamTokenResult refreshed = blocking(manager, base);
	ok(refreshed.status == AwsIamStatus::OK && signer->calls() == 2 &&
		refreshed.generation > first.generation,
		"a token with exactly two minutes remaining is refreshed");

	manager.invalidate(base, first.generation);
	AwsIamTokenResult retained = blocking(manager, base);
	ok(retained.generation == refreshed.generation && signer->calls() == 2,
		"conditional invalidation cannot remove a newer generation");
	manager.invalidate(base, refreshed.generation);
	blocking(manager, base);
	ok(signer->calls() == 3, "conditional invalidation removes the matching generation");

	blocking(manager, key("other.us-east-1.rds.amazonaws.com", 3306, "us-east-1", "app"));
	blocking(manager, key(base.endpoint, 3307, "us-east-1", "app"));
	blocking(manager, key(base.endpoint, 3306, "us-west-2", "app"));
	blocking(manager, key(base.endpoint, 3306, "us-east-1", "other"));
	ok(signer->calls() == 7, "endpoint, port, region, and database user each partition the cache key");
}

void test_coalescing_and_distinct_buffers() {
	FakeClock clock;
	auto signer = std::make_shared<FakeSigner>();
	signer->set_blocked(true);
	AwsIamTokenManager manager(signer, config(clock));
	std::vector<std::shared_ptr<CollectingSink>> sinks;
	std::vector<std::thread> callers;
	for (size_t i = 0; i < 100; ++i) sinks.push_back(std::make_shared<CollectingSink>());
	for (size_t i = 0; i < sinks.size(); ++i) {
		callers.emplace_back([&, i] { manager.request(key(), i + 1, sinks[i]); });
	}
	for (auto& caller : callers) caller.join();
	ok(signer->wait_for_calls(1) && signer->calls() == 1,
		"100 concurrent requests for one key coalesce into one signer call");
	signer->set_blocked(false);
	std::unordered_set<const char*> buffers;
	std::vector<AwsIamCompletion> owned_completions;
	bool delivered = true;
	for (auto& sink : sinks) {
		delivered = sink->wait_for(1) && delivered;
		if (sink->size()) {
			owned_completions.push_back(sink->take());
			buffers.insert(owned_completions.back().result.token.c_str());
		}
	}
	ok(delivered && buffers.size() == 100,
		"each coalesced waiter receives a distinct owned token buffer");

	auto delayed_signer = std::make_shared<FakeSigner>();
	delayed_signer->set_blocked(true);
	AwsIamTokenManager delayed_manager(delayed_signer, config(clock));
	auto delayed_sink = std::make_shared<CollectingSink>();
	delayed_manager.request(key("delayed.us-east-1.rds.amazonaws.com"), 200, delayed_sink);
	delayed_signer->wait_for_calls(1);
	clock.advance(5min);
	delayed_signer->set_blocked(false);
	delayed_sink->wait_for(1);
	ok(delayed_sink->take().result.expires_at == clock.now() + 15min,
		"queue and signer latency do not consume the generated token lifetime");
}

void test_pending_and_waiter_bounds() {
	FakeClock clock;
	auto signer = std::make_shared<FakeSigner>();
	signer->set_blocked(true);
	auto cfg = config(clock, 2048);
	cfg.max_pending_keys = 1024;
	AwsIamTokenManager manager(signer, cfg);
	std::vector<std::shared_ptr<CollectingSink>> sinks;
	for (size_t i = 0; i < 1025; ++i) {
		auto sink = std::make_shared<CollectingSink>();
		sinks.push_back(sink);
		manager.request(key("db" + std::to_string(i) + ".us-east-1.rds.amazonaws.com"), i, sink);
	}
	ok(sinks.back()->wait_for(1) && sinks.back()->take().result.status == AwsIamStatus::QUEUE_FULL &&
		manager.snapshot().in_flight_generations + manager.snapshot().queued_generations == 1024,
		"the 1,025th distinct pending miss is rejected without exceeding the 1,024-key bound");
	signer->set_blocked(false);

	FakeClock waiter_clock;
	auto waiter_signer = std::make_shared<FakeSigner>();
	waiter_signer->set_blocked(true);
	auto waiter_cfg = config(waiter_clock, 3);
	waiter_cfg.worker_count = 1;
	waiter_cfg.max_waiters_per_key = 2;
	waiter_cfg.max_total_waiters = 3;
	AwsIamTokenManager waiter_manager(waiter_signer, waiter_cfg);
	auto a = std::make_shared<CollectingSink>();
	auto b = std::make_shared<CollectingSink>();
	auto per_key_rejected = std::make_shared<CollectingSink>();
	waiter_manager.request(key(), 1, a);
	waiter_manager.request(key(), 2, b);
	waiter_manager.request(key(), 3, per_key_rejected);
	auto c = std::make_shared<CollectingSink>();
	auto total_rejected = std::make_shared<CollectingSink>();
	waiter_manager.request(key("second.us-east-1.rds.amazonaws.com"), 4, c);
	waiter_manager.request(key("third.us-east-1.rds.amazonaws.com"), 5, total_rejected);
	ok(per_key_rejected->wait_for(1) && total_rejected->wait_for(1) &&
		per_key_rejected->take().result.status == AwsIamStatus::WAITER_LIMIT &&
		total_rejected->take().result.status == AwsIamStatus::WAITER_LIMIT &&
		waiter_manager.snapshot().waiting_sessions == 3,
		"per-key and total waiter caps reject without growing the waiter set");
	waiter_signer->set_blocked(false);
}

void test_cancellation_timeout_late_completion_and_shutdown() {
	FakeClock clock;
	auto signer = std::make_shared<FakeSigner>();
	signer->set_blocked(true);
	auto cfg = config(clock);
	cfg.worker_count = 1;
	AwsIamTokenManager manager(signer, cfg);
	auto active = std::make_shared<CollectingSink>();
	manager.request(key("active.us-east-1.rds.amazonaws.com"), 1, active);
	ok(signer->wait_for_calls(1), "the first generation enters the signer");
	auto before = std::make_shared<CollectingSink>();
	AwsIamRequestHandle before_handle = manager.request(key("queued.us-east-1.rds.amazonaws.com"), 2, before);
	manager.cancel(before_handle);
	ok(manager.snapshot().queued_generations == 0,
		"cancel-before-sign immediately releases distinct-key queue capacity");
	auto during = std::make_shared<CollectingSink>();
	AwsIamRequestHandle during_handle = manager.request(key("active.us-east-1.rds.amazonaws.com"), 3, during);
	manager.cancel(during_handle);
	auto expired = std::make_shared<CollectingSink>();
	manager.request(key("active.us-east-1.rds.amazonaws.com"), 4, expired);
	expired.reset();
	signer->set_blocked(false);
	ok(active->wait_for(1) && !before->wait_for(1, 50ms) && !during->wait_for(1, 50ms) &&
		signer->calls() == 1 && manager.snapshot().waiting_sessions == 0,
		"cancel-before-sign, cancel-during-sign, and an expired late sink leave no completion or waiter");

	reset_cleanse_observer();
	auto late_signer = std::make_shared<FakeSigner>();
	ScriptedSign late_response;
	late_response.token = "late-secret";
	late_response.cleanse = observing_cleanse;
	late_signer->push(std::move(late_response));
	late_signer->set_blocked(true);
	AwsIamTokenManager late_manager(late_signer, config(clock));
	auto late_sink = std::make_shared<CollectingSink>();
	late_manager.request(key(), 8, late_sink);
	late_signer->wait_for_calls(1);
	late_sink.reset();
	late_signer->set_blocked(false);
	for (size_t spin = 0; spin < 100 && late_manager.snapshot().in_flight_generations; ++spin)
		std::this_thread::sleep_for(1ms);
	ok(cleanse_count_for("late-secret") >= 1 && late_manager.snapshot().token_cache_entries == 0,
		"a late successful result for an expired sink is cleansed instead of retained");

	auto timeout_signer = std::make_shared<FakeSigner>();
	timeout_signer->set_blocked(true);
	AwsIamTokenManager timeout_manager(timeout_signer, config(clock));
	AwsIamTokenResult timed_out = timeout_manager.request_blocking(key(), std::chrono::steady_clock::now() + 30ms);
	ok(timed_out.status == AwsIamStatus::TIMEOUT && timeout_manager.snapshot().waiting_sessions == 0,
		"a blocking request cancels its waiter when its deadline expires");
	timeout_signer->set_blocked(false);

	auto shutdown_signer = std::make_shared<FakeSigner>();
	shutdown_signer->set_blocked(true);
	auto shutdown_sink = std::make_shared<CollectingSink>();
	auto shutdown_manager = std::make_unique<AwsIamTokenManager>(shutdown_signer, config(clock));
	shutdown_manager->request(key(), 9, shutdown_sink);
	shutdown_signer->wait_for_calls(1);
	std::thread release([shutdown_signer] {
		std::this_thread::sleep_for(20ms);
		shutdown_signer->set_blocked(false);
	});
	shutdown_manager.reset();
	release.join();
	ok(shutdown_sink->wait_for(1) && shutdown_sink->take().result.status == AwsIamStatus::SHUTDOWN,
		"shutdown resolves outstanding requests without delivering a late signer result");
}

void test_lru_cleanse_and_failure_recovery() {
	reset_cleanse_observer();
	FakeClock clock;
	auto signer = std::make_shared<FakeSigner>();
	for (const char* value : { "token-a", "token-b", "token-c", "token-b2" }) {
		ScriptedSign response;
		response.token = value;
		response.cleanse = observing_cleanse;
		signer->push(std::move(response));
	}
	auto cfg = config(clock);
	cfg.max_cache_entries = 2;
	AwsIamTokenManager manager(signer, cfg);
	auto a_key = key("a.us-east-1.rds.amazonaws.com");
	auto b_key = key("b.us-east-1.rds.amazonaws.com");
	auto c_key = key("c.us-east-1.rds.amazonaws.com");
	blocking(manager, a_key).token.clear();
	blocking(manager, b_key).token.clear();
	blocking(manager, a_key).token.clear();
	const size_t b_before = cleanse_count_for("token-b");
	blocking(manager, c_key).token.clear();
	const size_t b_after = cleanse_count_for("token-b");
	blocking(manager, b_key).token.clear();
	ok(b_after > b_before && signer->calls() == 4 && manager.snapshot().token_cache_entries == 2,
		"LRU eviction cleanses the evicted cache value and keeps the cache bounded");

	FakeClock replacement_clock;
	auto replacement_signer = std::make_shared<FakeSigner>();
	for (const char* value : { "replace-old", "replace-new" }) {
		ScriptedSign response;
		response.token = value;
		response.cleanse = observing_cleanse;
		replacement_signer->push(std::move(response));
	}
	AwsIamTokenManager replacement_manager(replacement_signer, config(replacement_clock));
	blocking(replacement_manager, key()).token.clear();
	const size_t old_before = cleanse_count_for("replace-old");
	replacement_clock.advance(13min);
	blocking(replacement_manager, key()).token.clear();
	ok(cleanse_count_for("replace-old") > old_before,
		"refresh replacement cleanses the superseded cached token");

	FakeClock failure_clock;
	auto failure_signer = std::make_shared<FakeSigner>();
	for (size_t attempt = 0; attempt < 7; ++attempt) {
		ScriptedSign failure;
		failure.status = AwsIamStatus::CREDENTIAL_PROVIDER_ERROR;
		failure.token = "FAKE_AWS_SECRET";
		failure.failure = { "credential_provider", "ExpiredToken", "request-123" };
		failure_signer->push(std::move(failure));
	}
	ScriptedSign recovery;
	recovery.token = "recovered";
	failure_signer->push(std::move(recovery));
	std::atomic<size_t> jitter_calls { 0 };
	auto failure_cfg = config(failure_clock);
	failure_cfg.maximum_backoff = 30s;
	failure_cfg.jitter = [&jitter_calls](std::chrono::milliseconds maximum) {
		++jitter_calls;
		return std::min(maximum, 25ms);
	};
	AwsIamTokenManager failure_manager(failure_signer, failure_cfg);
	AwsIamTokenResult failed = blocking(failure_manager, key());
	AwsIamTokenResult backed_off = blocking(failure_manager, key());
	ok(failed.status == AwsIamStatus::CREDENTIAL_PROVIDER_ERROR &&
		backed_off.status == AwsIamStatus::CREDENTIAL_PROVIDER_ERROR && failure_signer->calls() == 1 &&
		jitter_calls == 1, "provider failures enter deterministic bounded backoff without another signer call");
	ok(failed.failure.category.find("FAKE_AWS_SECRET") == std::string::npos &&
		failed.failure.aws_error_code.find("FAKE_AWS_SECRET") == std::string::npos &&
		failed.failure.request_id.find("FAKE_AWS_SECRET") == std::string::npos && failed.token.empty(),
		"provider failures retain only redacted fields and never retain fake secret material");
	const std::chrono::milliseconds delays[] = { 125ms, 225ms, 425ms, 825ms, 1625ms, 3225ms, 5000ms };
	AwsIamTokenResult recovered;
	bool every_delay_honored = true;
	for (size_t attempt = 0; attempt < 7; ++attempt) {
		failure_clock.advance(delays[attempt] - 1ms);
		AwsIamTokenResult still_backed_off = blocking(failure_manager, key());
		every_delay_honored = every_delay_honored &&
			still_backed_off.status == AwsIamStatus::CREDENTIAL_PROVIDER_ERROR &&
			failure_signer->calls() == attempt + 1;
		failure_clock.advance(1ms);
		AwsIamTokenResult next = blocking(failure_manager, key());
		if (attempt == 6) recovered = std::move(next);
		else every_delay_honored = every_delay_honored &&
			next.status == AwsIamStatus::CREDENTIAL_PROVIDER_ERROR &&
			failure_signer->calls() == attempt + 2;
	}
	AwsIamTokenResult cached = blocking(failure_manager, key());
	ok(recovered.status == AwsIamStatus::OK && cached.status == AwsIamStatus::OK &&
		failure_signer->calls() == 8 && failure_manager.snapshot().credential_provider_failures == 7 &&
		jitter_calls == 7 && every_delay_honored,
		"exponential jittered backoff caps at five seconds, later recovers, and clears on success");

	failure_manager.record_backend_connection(true);
	failure_manager.record_backend_connection(false);
	AwsIamStatsSnapshot stats = failure_manager.snapshot();
	ok(stats.backend_connection_successes == 1 && stats.backend_connection_failures == 1,
		"backend connection outcomes are included in the thread-safe stats snapshot");
}

} // namespace

int main() {
	plan(0);
	test_secure_string_ownership_and_cleanse();
	test_cache_partition_expiry_and_invalidation();
	test_coalescing_and_distinct_buffers();
	test_pending_and_waiter_bounds();
	test_cancellation_timeout_late_completion_and_shutdown();
	test_lru_cleanse_and_failure_recovery();
	return exit_status();
}
