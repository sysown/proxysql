#include "tap.h"

#include "Aws_Iam_Token_Manager.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <stdexcept>
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

class CallbackSink final : public AwsIamCompletionSink {
public:
	explicit CallbackSink(std::function<void()> callback) : callback_(std::move(callback)) {}
	void post(AwsIamCompletion&& completion) override {
		callback_();
		std::lock_guard<std::mutex> lock(mu_);
		completions_.push_back(std::move(completion));
		cv_.notify_all();
	}
	bool wait_for(size_t count, std::chrono::milliseconds timeout = 2s) {
		std::unique_lock<std::mutex> lock(mu_);
		return cv_.wait_for(lock, timeout, [&] { return completions_.size() >= count; });
	}
	AwsIamCompletion take() {
		std::lock_guard<std::mutex> lock(mu_);
		AwsIamCompletion result = std::move(completions_.front());
		completions_.erase(completions_.begin());
		return result;
	}
private:
	std::function<void()> callback_;
	std::mutex mu_;
	std::condition_variable cv_;
	std::vector<AwsIamCompletion> completions_;
};

class ThrowingSink final : public AwsIamCompletionSink {
public:
	void post(AwsIamCompletion&&) override {
		{
			std::lock_guard<std::mutex> lock(mu_);
			called_ = true;
		}
		cv_.notify_all();
		throw std::runtime_error("intentional completion callback failure");
	}
	bool wait_for_call(std::chrono::milliseconds timeout = 2s) {
		std::unique_lock<std::mutex> lock(mu_);
		return cv_.wait_for(lock, timeout, [&] { return called_; });
	}
private:
	std::mutex mu_;
	std::condition_variable cv_;
	bool called_ { false };
};

class DispatchPause {
public:
	void hook() {
		std::unique_lock<std::mutex> lock(mu_);
		if (!armed_) return;
		entered_ = true;
		entered_cv_.notify_all();
		release_cv_.wait(lock, [&] { return released_; });
		armed_ = false;
	}
	bool wait_until_entered(std::chrono::milliseconds timeout = 2s) {
		std::unique_lock<std::mutex> lock(mu_);
		return entered_cv_.wait_for(lock, timeout, [&] { return entered_; });
	}
	void release() {
		std::lock_guard<std::mutex> lock(mu_);
		released_ = true;
		release_cv_.notify_all();
	}
private:
	std::mutex mu_;
	std::condition_variable entered_cv_;
	std::condition_variable release_cv_;
	bool armed_ { true };
	bool entered_ { false };
	bool released_ { false };
};

class FinishPublishPause {
public:
	void arm() {
		std::lock_guard<std::mutex> lock(mu_);
		armed_ = true;
	}
	void hook() {
		std::unique_lock<std::mutex> lock(mu_);
		if (!armed_) return;
		const size_t position = ++arrivals_;
		arrived_cv_.notify_all();
		if (position == 1) {
			arrived_cv_.wait(lock, [&] { return arrivals_ == 2; });
			return;
		}
		release_cv_.wait(lock, [&] { return released_; });
	}
	bool wait_for_two(std::chrono::milliseconds timeout = 2s) {
		std::unique_lock<std::mutex> lock(mu_);
		return arrived_cv_.wait_for(lock, timeout, [&] { return arrivals_ == 2; });
	}
	void release_second() {
		std::lock_guard<std::mutex> lock(mu_);
		released_ = true;
		release_cv_.notify_all();
	}
private:
	std::mutex mu_;
	std::condition_variable arrived_cv_;
	std::condition_variable release_cv_;
	bool armed_ { false };
	bool released_ { false };
	size_t arrivals_ { 0 };
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

	FakeClock delivery_clock;
	auto delivery_signer = std::make_shared<FakeSigner>();
	DispatchPause delivery_pause;
	std::atomic<bool> pause_delivery { false };
	auto delivery_config = config(delivery_clock);
	delivery_config.before_dispatch = [&] {
		if (pause_delivery.load()) delivery_pause.hook();
	};
	AwsIamTokenManager delivery_manager(delivery_signer, delivery_config);
	blocking(delivery_manager, key()).token.clear();
	pause_delivery = true;
	auto boundary_sink = std::make_shared<CollectingSink>();
	std::thread boundary_request([&] { delivery_manager.request(key(), 90, boundary_sink); });
	delivery_pause.wait_until_entered();
	delivery_clock.advance(13min);
	delivery_pause.release();
	boundary_request.join();
	boundary_sink->wait_for(1);
	AwsIamTokenResult boundary_result = std::move(boundary_sink->take().result);
	ok(boundary_result.status != AwsIamStatus::OK && boundary_result.token.empty(),
		"a cache hit that reaches exactly two minutes remaining before dispatch is not delivered");

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

	FakeClock freshness_clock;
	auto invalid_lifetime_signer = std::make_shared<FakeSigner>();
	auto invalid_lifetime_config = config(freshness_clock);
	invalid_lifetime_config.generated_lifetime = 2min;
	AwsIamTokenManager invalid_lifetime_manager(invalid_lifetime_signer, invalid_lifetime_config);
	AwsIamTokenResult invalid_lifetime = blocking(invalid_lifetime_manager, key());
	ok(invalid_lifetime.status == AwsIamStatus::INVALID_CONFIG && invalid_lifetime.token.empty() &&
		invalid_lifetime_signer->calls() == 0,
		"a generated lifetime at the minimum-remaining boundary is rejected before signing");

	auto stale_signer = std::make_shared<FakeSigner>();
	stale_signer->set_blocked(true);
	DispatchPause stale_pause;
	auto stale_config = config(freshness_clock);
	stale_config.before_dispatch = [&] { stale_pause.hook(); };
	AwsIamTokenManager stale_manager(stale_signer, stale_config);
	auto stale_a = std::make_shared<CollectingSink>();
	auto stale_b = std::make_shared<CollectingSink>();
	stale_manager.request(key("stale.us-east-1.rds.amazonaws.com"), 301, stale_a);
	stale_manager.request(key("stale.us-east-1.rds.amazonaws.com"), 302, stale_b);
	stale_signer->wait_for_calls(1);
	stale_signer->set_blocked(false);
	stale_pause.wait_until_entered();
	freshness_clock.advance(13min);
	stale_pause.release();
	stale_a->wait_for(1);
	stale_b->wait_for(1);
	AwsIamCompletion stale_a_result = stale_a->take();
	AwsIamCompletion stale_b_result = stale_b->take();
	ok(stale_a_result.result.status != AwsIamStatus::OK && stale_a_result.result.token.empty() &&
		stale_b_result.result.status != AwsIamStatus::OK && stale_b_result.result.token.empty(),
		"coalesced results at exactly the minimum-remaining boundary never deliver a token");
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
		waiter_manager.snapshot().waiting_sessions == 0,
		"manager waiter caps reject without reporting non-session helpers as sessions");
	waiter_signer->set_blocked(false);

	FakeClock worker_clock;
	auto worker_signer = std::make_shared<FakeSigner>();
	worker_signer->set_blocked(true);
	AwsIamTokenManager worker_manager(worker_signer, config(worker_clock));
	auto worker_a = std::make_shared<CollectingSink>();
	auto worker_b = std::make_shared<CollectingSink>();
	auto worker_c = std::make_shared<CollectingSink>();
	worker_manager.request(key("worker-a.us-east-1.rds.amazonaws.com"), 10, worker_a);
	worker_manager.request(key("worker-b.us-east-1.rds.amazonaws.com"), 11, worker_b);
	worker_manager.request(key("worker-c.us-east-1.rds.amazonaws.com"), 12, worker_c);
	const bool two_entered = worker_signer->wait_for_calls(2);
	std::this_thread::sleep_for(20ms);
	ok(two_entered && worker_signer->calls() == 2 && worker_manager.snapshot().queued_generations == 1,
		"the manager owns exactly two long-lived signing workers");
	worker_signer->set_blocked(false);
}

void test_cancellation_timeout_late_completion_and_shutdown() {
	FakeClock clock;
	auto signer = std::make_shared<FakeSigner>();
	signer->set_blocked(true);
	AwsIamTokenManager manager(signer, config(clock));
	auto active = std::make_shared<CollectingSink>();
	manager.request(key("active.us-east-1.rds.amazonaws.com"), 1, active);
	auto second_active = std::make_shared<CollectingSink>();
	manager.request(key("second-active.us-east-1.rds.amazonaws.com"), 10, second_active);
	ok(signer->wait_for_calls(2), "both signing workers enter the signer");
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
	ok(active->wait_for(1) && second_active->wait_for(1) && !before->wait_for(1, 50ms) &&
		!during->wait_for(1, 50ms) &&
		signer->calls() == 2 && manager.snapshot().waiting_sessions == 0,
		"cancel-before-sign, cancel-during-sign, and an expired late sink leave no completion or waiter");

	FakeClock dispatch_clock;
	auto dispatch_signer = std::make_shared<FakeSigner>();
	DispatchPause dispatch_pause;
	auto dispatch_config = config(dispatch_clock);
	dispatch_config.before_dispatch = [&] { dispatch_pause.hook(); };
	AwsIamTokenManager dispatch_manager(dispatch_signer, dispatch_config);
	auto dispatch_sink = std::make_shared<CollectingSink>();
	AwsIamRequestHandle dispatch_handle = dispatch_manager.request(key(), 20, dispatch_sink);
	dispatch_pause.wait_until_entered();
	dispatch_manager.cancel(dispatch_handle);
	dispatch_pause.release();
	ok(!dispatch_sink->wait_for(1, 50ms),
		"cancel at the dispatch boundary returns before and suppresses every later completion");

	auto cross_thread_signer = std::make_shared<FakeSigner>();
	cross_thread_signer->set_blocked(true);
	AwsIamTokenManager cross_thread_manager(cross_thread_signer, config(dispatch_clock));
	auto cross_thread_b = std::make_shared<CollectingSink>();
	AwsIamRequestHandle cross_thread_b_handle;
	auto cross_thread_a = std::make_shared<CallbackSink>([&] {
		std::thread canceler([&] { cross_thread_manager.cancel(cross_thread_b_handle); });
		canceler.join();
	});
	cross_thread_manager.request(key("cross-thread.us-east-1.rds.amazonaws.com"), 22, cross_thread_a);
	cross_thread_b_handle = cross_thread_manager.request(
		key("cross-thread.us-east-1.rds.amazonaws.com"), 23, cross_thread_b);
	cross_thread_signer->wait_for_calls(1);
	cross_thread_signer->set_blocked(false);
	ok(cross_thread_a->wait_for(1) && !cross_thread_b->wait_for(1, 50ms) &&
		cross_thread_a->take().result.status == AwsIamStatus::OK,
		"a completion callback can join another thread that cancels a later waiter without deadlock");

	auto shutdown_boundary_signer = std::make_shared<FakeSigner>();
	DispatchPause shutdown_boundary_pause;
	auto shutdown_boundary_config = config(dispatch_clock);
	shutdown_boundary_config.before_dispatch = [&] { shutdown_boundary_pause.hook(); };
	auto shutdown_boundary_manager = std::make_unique<AwsIamTokenManager>(
		shutdown_boundary_signer, shutdown_boundary_config);
	auto shutdown_boundary_sink = std::make_shared<CollectingSink>();
	shutdown_boundary_manager->request(key("shutdown-boundary.us-east-1.rds.amazonaws.com"),
		21, shutdown_boundary_sink);
	shutdown_boundary_pause.wait_until_entered();
	std::thread boundary_shutdown([&] { shutdown_boundary_manager.reset(); });
	const bool shutdown_won_boundary = shutdown_boundary_sink->wait_for(1);
	shutdown_boundary_pause.release();
	boundary_shutdown.join();
	AwsIamCompletion shutdown_boundary_result = shutdown_boundary_sink->take();
	ok(shutdown_won_boundary && shutdown_boundary_result.result.status == AwsIamStatus::SHUTDOWN &&
		shutdown_boundary_sink->size() == 0,
		"shutdown at the dispatch boundary suppresses the successful completion and posts shutdown once");

	auto reentrant_signer = std::make_shared<FakeSigner>();
	reentrant_signer->set_blocked(true);
	auto reentrant_manager = std::make_unique<AwsIamTokenManager>(reentrant_signer, config(dispatch_clock));
	auto shutdown_b = std::make_shared<CollectingSink>();
	AwsIamRequestHandle shutdown_b_handle;
	AwsIamTokenManager* reentrant_source = reentrant_manager.get();
	auto shutdown_a = std::make_shared<CallbackSink>([&] {
		reentrant_source->cancel(shutdown_b_handle);
	});
	reentrant_manager->request(key("reentrant-shutdown.us-east-1.rds.amazonaws.com"), 24, shutdown_a);
	shutdown_b_handle = reentrant_manager->request(
		key("reentrant-shutdown.us-east-1.rds.amazonaws.com"), 25, shutdown_b);
	reentrant_signer->wait_for_calls(1);
	std::thread reentrant_shutdown([&] { reentrant_manager.reset(); });
	const bool shutdown_a_called = shutdown_a->wait_for(1);
	reentrant_signer->set_blocked(false);
	reentrant_shutdown.join();
	ok(shutdown_a_called && shutdown_a->take().result.status == AwsIamStatus::SHUTDOWN &&
		!shutdown_b->wait_for(1, 50ms),
		"shutdown revalidates each handle so callback A can cancel snapshotted callback B");

	FakeClock finish_clock;
	auto finish_signer = std::make_shared<FakeSigner>();
	FinishPublishPause finish_pause;
	auto finish_config = config(finish_clock);
	finish_config.before_finish_publish = [&] { finish_pause.hook(); };
	auto finish_manager = std::make_unique<AwsIamTokenManager>(finish_signer, finish_config);
	const AwsIamTokenKey finish_key_a = key("finish-a.us-east-1.rds.amazonaws.com");
	const AwsIamTokenKey finish_key_b = key("finish-b.us-east-1.rds.amazonaws.com");
	blocking(*finish_manager, finish_key_a);
	blocking(*finish_manager, finish_key_b);
	finish_pause.arm();
	auto finish_sink_a = std::make_shared<CollectingSink>();
	auto finish_sink_b = std::make_shared<CollectingSink>();
	AwsIamTokenManager* finish_source = finish_manager.get();
	std::thread finish_request_a([&] { finish_source->request(finish_key_a, 26, finish_sink_a); });
	std::thread finish_request_b([&] { finish_source->request(finish_key_b, 27, finish_sink_b); });
	const bool both_finishes_paused = finish_pause.wait_for_two();
	std::mutex destroyed_mu;
	std::condition_variable destroyed_cv;
	bool destroyed = false;
	std::thread finish_shutdown([&] {
		finish_manager.reset();
		{
			std::lock_guard<std::mutex> lock(destroyed_mu);
			destroyed = true;
		}
		destroyed_cv.notify_all();
	});
	bool returned_while_final_finish_paused;
	{
		std::unique_lock<std::mutex> lock(destroyed_mu);
		returned_while_final_finish_paused = destroyed_cv.wait_for(lock, 100ms, [&] { return destroyed; });
	}
	ok(both_finishes_paused && !returned_while_final_finish_paused,
		"shutdown cannot destroy dispatch state before the final callback completes its finish path");
	if (returned_while_final_finish_paused) {
		std::fflush(stdout);
		std::_Exit(1);
	}
	finish_pause.release_second();
	finish_request_a.join();
	finish_request_b.join();
	finish_shutdown.join();

	auto throwing_signer = std::make_shared<FakeSigner>();
	throwing_signer->set_blocked(true);
	auto throwing_manager = std::make_unique<AwsIamTokenManager>(throwing_signer, config(clock));
	auto throwing_sink = std::make_shared<ThrowingSink>();
	throwing_manager->request(key("throwing-shutdown.us-east-1.rds.amazonaws.com"), 28, throwing_sink);
	throwing_signer->wait_for_calls(1);
	std::thread throwing_shutdown([&] { throwing_manager.reset(); });
	const bool throwing_callback_called = throwing_sink->wait_for_call();
	throwing_signer->set_blocked(false);
	throwing_shutdown.join();
	ok(throwing_callback_called,
		"a throwing completion callback cannot escape or terminate token-manager shutdown");

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

	auto expired_deadline_signer = std::make_shared<FakeSigner>();
	AwsIamTokenManager expired_deadline_manager(expired_deadline_signer, config(clock));
	AwsIamTokenResult already_expired = expired_deadline_manager.request_blocking(
		key(), std::chrono::steady_clock::now());
	ok(already_expired.status == AwsIamStatus::TIMEOUT && expired_deadline_signer->calls() == 0,
		"an already-expired blocking deadline takes precedence before a request is started");

	auto immediate_signer = std::make_shared<FakeSigner>();
	auto immediate_config = config(clock);
	DispatchPause immediate_pause;
	std::atomic<bool> pause_immediate { false };
	immediate_config.before_dispatch = [&] {
		if (pause_immediate.load()) immediate_pause.hook();
	};
	AwsIamTokenManager immediate_timeout_manager(immediate_signer, immediate_config);
	blocking(immediate_timeout_manager, key()).token.clear();
	pause_immediate = true;
	std::thread immediate_release([&] {
		immediate_pause.wait_until_entered();
		std::this_thread::sleep_for(30ms);
		immediate_pause.release();
	});
	AwsIamTokenResult immediate_timeout = immediate_timeout_manager.request_blocking(
		key(), std::chrono::steady_clock::now() + 10ms);
	immediate_release.join();
	ok(immediate_timeout.status == AwsIamStatus::TIMEOUT && immediate_timeout.token.empty(),
		"a blocking deadline crossed while obtaining an immediate cache completion wins over that completion");

	auto completion_signer = std::make_shared<FakeSigner>();
	DispatchPause completion_pause;
	auto completion_config = config(clock);
	completion_config.before_dispatch = [&] { completion_pause.hook(); };
	AwsIamTokenManager completion_timeout_manager(completion_signer, completion_config);
	std::thread completion_release([&] {
		completion_pause.wait_until_entered();
		std::this_thread::sleep_for(30ms);
		completion_pause.release();
	});
	AwsIamTokenResult completion_timeout = completion_timeout_manager.request_blocking(
		key(), std::chrono::steady_clock::now() + 10ms);
	completion_release.join();
	ok(completion_timeout.status == AwsIamStatus::TIMEOUT && completion_timeout.token.empty(),
		"a blocking deadline crossed while a generated completion is dispatching wins over that completion");

	auto backoff_signer = std::make_shared<FakeSigner>();
	ScriptedSign backoff_failure;
	backoff_failure.status = AwsIamStatus::PROVIDER_ERROR;
	backoff_failure.token.clear();
	backoff_signer->push(std::move(backoff_failure));
	DispatchPause backoff_pause;
	std::atomic<bool> pause_backoff { false };
	auto backoff_config = config(clock);
	backoff_config.before_dispatch = [&] {
		if (pause_backoff.load()) backoff_pause.hook();
	};
	AwsIamTokenManager backoff_timeout_manager(backoff_signer, backoff_config);
	blocking(backoff_timeout_manager, key());
	pause_backoff = true;
	std::thread backoff_release([&] {
		backoff_pause.wait_until_entered();
		std::this_thread::sleep_for(30ms);
		backoff_pause.release();
	});
	AwsIamTokenResult backoff_timeout = backoff_timeout_manager.request_blocking(
		key(), std::chrono::steady_clock::now() + 10ms);
	backoff_release.join();
	ok(backoff_timeout.status == AwsIamStatus::TIMEOUT,
		"a blocking deadline crossed while obtaining an immediate backoff result wins over that result");

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
