#include "Aws_Iam_Token_Manager.h"

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

SecureString::SecureString() = default;

SecureString::SecureString(std::string_view value, CleanseFn cleanse)
	: size_(value.size()), cleanse_(cleanse ? cleanse : OPENSSL_cleanse) {
	if (size_) {
		bytes_.reset(new unsigned char[size_ + 1]);
		std::memcpy(bytes_.get(), value.data(), size_);
		bytes_[size_] = 0;
	}
}

SecureString::SecureString(SecureString&& other) noexcept
	: bytes_(std::move(other.bytes_)), size_(other.size_), cleanse_(other.cleanse_) {
	other.size_ = 0;
	other.cleanse_ = OPENSSL_cleanse;
}

SecureString& SecureString::operator=(SecureString&& other) noexcept {
	if (this != &other) {
		clear();
		bytes_ = std::move(other.bytes_);
		size_ = other.size_;
		cleanse_ = other.cleanse_;
		other.size_ = 0;
		other.cleanse_ = OPENSSL_cleanse;
	}
	return *this;
}

SecureString::~SecureString() { clear(); }
SecureString SecureString::clone() const {
	return empty() ? SecureString() : SecureString(std::string_view(c_str(), size_), cleanse_);
}
const char* SecureString::c_str() const {
	return bytes_ ? reinterpret_cast<const char*>(bytes_.get()) : "";
}
size_t SecureString::size() const { return size_; }
bool SecureString::empty() const { return size_ == 0; }
void SecureString::clear() {
	if (bytes_) {
		cleanse_(bytes_.get(), size_);
		bytes_[size_] = 0;
		bytes_.reset();
	}
	size_ = 0;
}

AwsIamTokenManagerConfig::AwsIamTokenManagerConfig(size_t mysql_max)
	: max_total_waiters(mysql_max), max_waiters_per_key(mysql_max),
	  mysql_max_connections(mysql_max),
	  clock([] { return std::chrono::steady_clock::now(); }),
	  jitter([](std::chrono::milliseconds) { return std::chrono::milliseconds(0); }) {}

namespace {
struct KeyHash {
	size_t operator()(const AwsIamTokenKey& key) const noexcept {
		size_t value = std::hash<std::string>{}(key.endpoint);
		auto mix = [&value](size_t part) {
			value ^= part + 0x9e3779b97f4a7c15ULL + (value << 6) + (value >> 2);
		};
		mix(std::hash<uint16_t>{}(key.port));
		mix(std::hash<std::string>{}(key.region));
		mix(std::hash<std::string>{}(key.database_user));
		return value;
	}
};

class BlockingSink final : public AwsIamCompletionSink {
public:
	void post(AwsIamCompletion&& completion) override {
		std::lock_guard<std::mutex> lock(mu_);
		if (!accepting_) return;
		result_ = std::move(completion.result);
		complete_ = true;
		cv_.notify_one();
	}
	bool wait_until(std::chrono::steady_clock::time_point deadline, AwsIamTokenResult& result) {
		std::unique_lock<std::mutex> lock(mu_);
		if (!cv_.wait_until(lock, deadline, [&] { return complete_; })) {
			accepting_ = false;
			return false;
		}
		result = std::move(result_);
		accepting_ = false;
		return true;
	}
private:
	std::mutex mu_;
	std::condition_variable cv_;
	bool accepting_ { true };
	bool complete_ { false };
	AwsIamTokenResult result_;
};
} // namespace

class AwsIamTokenManager::Impl {
public:
	Impl(std::shared_ptr<AwsIamTokenSigner> signer_arg, AwsIamTokenManagerConfig config_arg)
		: signer(std::move(signer_arg)), config(std::move(config_arg)) {
		config.max_pending_keys = std::max<size_t>(1, config.max_pending_keys);
		config.max_total_waiters = std::min(config.max_total_waiters, config.mysql_max_connections);
		config.max_waiters_per_key = std::min(config.max_waiters_per_key, config.mysql_max_connections);
		config.max_waiters_per_key = std::min(config.max_waiters_per_key, config.max_total_waiters);
		config.maximum_backoff = std::min(config.maximum_backoff, std::chrono::milliseconds(5000));
		config.initial_backoff = std::min(config.initial_backoff, config.maximum_backoff);
		valid_config = config.generated_lifetime > config.minimum_remaining_lifetime;
		for (size_t i = 0; i < 2; ++i) {
			workers.emplace_back([this] { worker_loop(); });
		}
	}
	~Impl() { shutdown(); }

	struct Delivery {
		uint64_t opaque_id;
		std::weak_ptr<AwsIamCompletionSink> sink;
	};
	struct Waiter {
		uint64_t handle;
		std::shared_ptr<Delivery> delivery;
	};
	struct Generation {
		AwsIamTokenKey key;
		uint64_t generation;
		bool queued { true };
		std::vector<Waiter> waiters;
	};
	struct CacheEntry {
		SecureString token;
		std::chrono::steady_clock::time_point expires_at;
		uint64_t generation;
		uint64_t lru;
	};
	struct BackoffEntry {
		uint32_t attempts;
		std::chrono::steady_clock::time_point retry_at;
		AwsIamStatus status;
		AwsIamRedactedFailure failure;
		uint64_t lru;
	};
	struct PendingCompletion {
		uint64_t handle;
		std::shared_ptr<Delivery> delivery;
		AwsIamCompletion completion;
	};
	using CompletionPair = std::pair<std::shared_ptr<AwsIamCompletionSink>, AwsIamCompletion>;

	AwsIamRequestHandle request(const AwsIamTokenKey& key, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink> sink) {
		AwsIamRequestHandle handle;
		CompletionPair immediate;
		bool has_immediate = false;
		bool notify = false;
		{
			std::lock_guard<std::mutex> lock(mu);
			handle.value = next_handle++;
			++stats.token_requests;
			auto make_immediate = [&](AwsIamStatus status, const AwsIamRedactedFailure* failure = nullptr) {
				if (auto live = sink.lock()) {
					AwsIamCompletion completion;
					completion.opaque_id = opaque_id;
					completion.result.status = status;
					if (failure) completion.result.failure = *failure;
					immediate = { std::move(live), std::move(completion) };
					has_immediate = true;
				}
			};
			if (shutting_down) {
				make_immediate(AwsIamStatus::SHUTDOWN);
			} else if (!valid_config) {
				make_immediate(AwsIamStatus::INVALID_CONFIG);
			} else {
				const auto now = config.clock();
				auto cached = cache.find(key);
				if (cached != cache.end() && cached->second.expires_at - now > config.minimum_remaining_lifetime) {
					++stats.token_cache_hits;
					cached->second.lru = ++lru_clock;
					if (auto live = sink.lock()) {
						AwsIamCompletion completion;
						completion.opaque_id = opaque_id;
						completion.result.status = AwsIamStatus::OK;
						completion.result.token = cached->second.token.clone();
						completion.result.expires_at = cached->second.expires_at;
						completion.result.generation = cached->second.generation;
						immediate = { std::move(live), std::move(completion) };
						has_immediate = true;
					}
				} else {
					if (cached != cache.end()) cache.erase(cached);
					auto delayed = backoff.find(key);
					if (delayed != backoff.end() && now < delayed->second.retry_at) {
						delayed->second.lru = ++lru_clock;
						make_immediate(delayed->second.status, &delayed->second.failure);
					} else {
						auto generation = generations.find(key);
						const size_t per_key = generation == generations.end() ? 0 : generation->second.waiters.size();
						if (total_waiters >= config.max_total_waiters || per_key >= config.max_waiters_per_key) {
							make_immediate(AwsIamStatus::WAITER_LIMIT);
						} else if (generation == generations.end() && generations.size() >= config.max_pending_keys) {
							++stats.queue_rejections;
							make_immediate(AwsIamStatus::QUEUE_FULL);
						} else {
							if (generation == generations.end()) {
								Generation created { key, next_generation++, true, {} };
								generation = generations.emplace(key, std::move(created)).first;
								jobs.push_back(key);
								notify = true;
							}
							auto delivery = std::make_shared<Delivery>();
							delivery->opaque_id = opaque_id;
							delivery->sink = std::move(sink);
							generation->second.waiters.push_back({ handle.value, delivery });
							active_deliveries.emplace(handle.value, std::move(delivery));
							++total_waiters;
						}
					}
				}
			}
		}
		if (notify) cv.notify_one();
		if (has_immediate) dispatch_immediate(std::move(immediate));
		return handle;
	}

	void cancel(AwsIamRequestHandle handle) {
		if (!handle.value) return;
		std::lock_guard<std::recursive_mutex> dispatch_lock(dispatch_mu);
		std::lock_guard<std::mutex> lock(mu);
		auto active = active_deliveries.find(handle.value);
		if (active == active_deliveries.end()) return;
		for (auto item = generations.begin(); item != generations.end(); ++item) {
			auto& waiters = item->second.waiters;
			auto found = std::find_if(waiters.begin(), waiters.end(),
				[&](const Waiter& waiter) { return waiter.handle == handle.value; });
			if (found != waiters.end()) {
				waiters.erase(found);
				--total_waiters;
				if (waiters.empty() && item->second.queued) {
					jobs.erase(std::remove(jobs.begin(), jobs.end(), item->first), jobs.end());
					generations.erase(item);
				}
				break;
			}
		}
		active_deliveries.erase(handle.value);
	}

	void invalidate(const AwsIamTokenKey& key, uint64_t generation) {
		std::lock_guard<std::mutex> lock(mu);
		auto found = cache.find(key);
		if (found != cache.end() && found->second.generation == generation) cache.erase(found);
	}

	void record_backend_connection(bool success) {
		std::lock_guard<std::mutex> lock(mu);
		if (success) ++stats.backend_connection_successes;
		else ++stats.backend_connection_failures;
	}

	AwsIamStatsSnapshot snapshot() const {
		std::lock_guard<std::mutex> lock(mu);
		AwsIamStatsSnapshot result = stats;
		result.token_cache_entries = cache.size();
		result.waiting_sessions = total_waiters;
		for (const auto& item : generations) {
			if (item.second.queued) ++result.queued_generations;
			else ++result.in_flight_generations;
		}
		return result;
	}

	void shutdown() {
		std::vector<std::shared_ptr<Delivery>> deliveries;
		{
			std::lock_guard<std::recursive_mutex> dispatch_lock(dispatch_mu);
			{
				std::lock_guard<std::mutex> lock(mu);
				if (shutting_down) return;
				shutting_down = true;
				for (const auto& active : active_deliveries) deliveries.push_back(active.second);
				generations.clear();
				jobs.clear();
				total_waiters = 0;
				cache.clear();
				backoff.clear();
			}
			cv.notify_all();
			for (auto& delivery : deliveries) {
				if (auto sink = delivery->sink.lock()) {
					AwsIamCompletion completion;
					completion.opaque_id = delivery->opaque_id;
					completion.result.status = AwsIamStatus::SHUTDOWN;
					sink->post(std::move(completion));
				}
			}
		}
		for (auto& worker : workers) if (worker.joinable()) worker.join();
		std::lock_guard<std::mutex> lock(mu);
		active_deliveries.clear();
	}

	void worker_loop() {
		for (;;) {
			AwsIamTokenKey key;
			uint64_t generation_number;
			{
				std::unique_lock<std::mutex> lock(mu);
				cv.wait(lock, [&] { return shutting_down || !jobs.empty(); });
				if (shutting_down) return;
				key = std::move(jobs.front());
				jobs.pop_front();
				auto found = generations.find(key);
				if (found == generations.end()) continue;
				if (found->second.waiters.empty()) {
					generations.erase(found);
					continue;
				}
				found->second.queued = false;
				generation_number = found->second.generation;
			}
			AwsIamSignResult signed_result;
			if (signer) signed_result = signer->sign(key);
			else {
				signed_result.status = AwsIamStatus::INVALID_CONFIG;
				signed_result.failure.category = "missing_signer";
			}
			const auto generated_at = config.clock();
			std::vector<PendingCompletion> completions;
			{
				std::lock_guard<std::mutex> lock(mu);
				auto found = generations.find(key);
				if (shutting_down || found == generations.end() ||
					found->second.generation != generation_number) continue;
				auto& waiters = found->second.waiters;
				if (signed_result.status == AwsIamStatus::OK) {
					++stats.token_refresh_successes;
					backoff.erase(key);
					const auto expires_at = generated_at + config.generated_lifetime;
					bool has_live_waiter = false;
					for (auto& waiter : waiters) {
						if (auto sink = waiter.delivery->sink.lock()) {
							has_live_waiter = true;
							AwsIamCompletion completion;
							completion.opaque_id = waiter.delivery->opaque_id;
							completion.result.status = AwsIamStatus::OK;
							completion.result.token = signed_result.token.clone();
							completion.result.expires_at = expires_at;
							completion.result.generation = generation_number;
							completions.push_back({ waiter.handle, waiter.delivery, std::move(completion) });
						}
					}
					if (has_live_waiter && config.max_cache_entries) {
						if (cache.find(key) == cache.end() && cache.size() >= config.max_cache_entries) {
							auto victim = std::min_element(cache.begin(), cache.end(),
								[](const auto& left, const auto& right) { return left.second.lru < right.second.lru; });
							cache.erase(victim);
						}
						CacheEntry entry { signed_result.token.clone(), expires_at, generation_number, ++lru_clock };
						cache.insert_or_assign(key, std::move(entry));
					}
				} else {
					++stats.token_refresh_failures;
					if (signed_result.status == AwsIamStatus::CREDENTIAL_PROVIDER_ERROR)
						++stats.credential_provider_failures;
					uint32_t attempts = 1;
					auto old = backoff.find(key);
					if (old != backoff.end()) attempts = std::min<uint32_t>(old->second.attempts + 1, 63);
					auto delay = config.initial_backoff;
					for (uint32_t i = 1; i < attempts && delay < config.maximum_backoff; ++i)
						delay = std::min(config.maximum_backoff, delay * 2);
					auto jitter = config.jitter ? config.jitter(delay) : std::chrono::milliseconds(0);
					if (jitter < std::chrono::milliseconds(0)) jitter = std::chrono::milliseconds(0);
					delay = std::min(config.maximum_backoff, delay + jitter);
					if (old == backoff.end() && backoff.size() >= config.max_pending_keys) {
						auto victim = std::min_element(backoff.begin(), backoff.end(),
							[](const auto& left, const auto& right) { return left.second.lru < right.second.lru; });
						backoff.erase(victim);
					}
					backoff[key] = { attempts, config.clock() + delay, signed_result.status,
						signed_result.failure, ++lru_clock };
					for (auto& waiter : waiters) {
						if (auto sink = waiter.delivery->sink.lock()) {
							AwsIamCompletion completion;
							completion.opaque_id = waiter.delivery->opaque_id;
							completion.result.status = signed_result.status;
							completion.result.failure = signed_result.failure;
							completions.push_back({ waiter.handle, waiter.delivery, std::move(completion) });
						}
					}
				}
				total_waiters -= waiters.size();
				for (const auto& waiter : waiters) {
					if (std::none_of(completions.begin(), completions.end(),
						[&](const PendingCompletion& pending) { return pending.handle == waiter.handle; })) {
						active_deliveries.erase(waiter.handle);
					}
				}
				generations.erase(found);
			}
			for (auto& pending : completions) dispatch_pending(std::move(pending));
		}
	}

	void call_before_dispatch() {
		if (config.before_dispatch) config.before_dispatch();
	}

	void dispatch_immediate(CompletionPair&& immediate) {
		call_before_dispatch();
		std::lock_guard<std::recursive_mutex> dispatch_lock(dispatch_mu);
		{
			std::lock_guard<std::mutex> lock(mu);
			if (shutting_down) {
				immediate.second.result.token.clear();
				immediate.second.result.status = AwsIamStatus::SHUTDOWN;
			}
			if (immediate.second.result.status == AwsIamStatus::OK &&
				immediate.second.result.expires_at - config.clock() <= config.minimum_remaining_lifetime) {
				auto cached = cache.begin();
				while (cached != cache.end()) {
					if (cached->second.generation == immediate.second.result.generation) cached = cache.erase(cached);
					else ++cached;
				}
				immediate.second.result.token.clear();
				immediate.second.result.status = AwsIamStatus::PROVIDER_ERROR;
				immediate.second.result.failure.category = "token_not_fresh_at_delivery";
			}
		}
		immediate.first->post(std::move(immediate.second));
	}

	void dispatch_pending(PendingCompletion&& pending) {
		call_before_dispatch();
		std::lock_guard<std::recursive_mutex> dispatch_lock(dispatch_mu);
		std::shared_ptr<AwsIamCompletionSink> sink;
		{
			std::lock_guard<std::mutex> lock(mu);
			auto active = active_deliveries.find(pending.handle);
			if (shutting_down || active == active_deliveries.end() || active->second != pending.delivery) return;
			if (pending.completion.result.status == AwsIamStatus::OK &&
				pending.completion.result.expires_at - config.clock() <= config.minimum_remaining_lifetime) {
				for (auto cached = cache.begin(); cached != cache.end();) {
					if (cached->second.generation == pending.completion.result.generation) cached = cache.erase(cached);
					else ++cached;
				}
				pending.completion.result.token.clear();
				pending.completion.result.status = AwsIamStatus::PROVIDER_ERROR;
				pending.completion.result.failure.category = "token_not_fresh_at_delivery";
			}
			sink = pending.delivery->sink.lock();
			active_deliveries.erase(active);
		}
		if (sink) sink->post(std::move(pending.completion));
	}

	std::shared_ptr<AwsIamTokenSigner> signer;
	AwsIamTokenManagerConfig config;
	mutable std::mutex mu;
	std::recursive_mutex dispatch_mu;
	std::condition_variable cv;
	bool shutting_down { false };
	bool valid_config { true };
	uint64_t next_handle { 1 };
	uint64_t next_generation { 1 };
	uint64_t lru_clock { 0 };
	size_t total_waiters { 0 };
	AwsIamStatsSnapshot stats;
	std::unordered_map<AwsIamTokenKey, Generation, KeyHash> generations;
	std::unordered_map<AwsIamTokenKey, CacheEntry, KeyHash> cache;
	std::unordered_map<AwsIamTokenKey, BackoffEntry, KeyHash> backoff;
	std::unordered_map<uint64_t, std::shared_ptr<Delivery>> active_deliveries;
	std::deque<AwsIamTokenKey> jobs;
	std::vector<std::thread> workers;
};

AwsIamTokenManager::AwsIamTokenManager(std::shared_ptr<AwsIamTokenSigner> signer,
	AwsIamTokenManagerConfig config)
	: impl_(new Impl(std::move(signer), std::move(config))) {}
AwsIamTokenManager::~AwsIamTokenManager() = default;
AwsIamRequestHandle AwsIamTokenManager::request(const AwsIamTokenKey& key, uint64_t opaque_id,
	std::weak_ptr<AwsIamCompletionSink> sink) {
	return impl_->request(key, opaque_id, std::move(sink));
}
AwsIamTokenResult AwsIamTokenManager::request_blocking(const AwsIamTokenKey& key,
	std::chrono::steady_clock::time_point deadline) {
	if (std::chrono::steady_clock::now() >= deadline) {
		AwsIamTokenResult result;
		result.status = AwsIamStatus::TIMEOUT;
		return result;
	}
	auto sink = std::make_shared<BlockingSink>();
	AwsIamRequestHandle handle = request(key, 0, sink);
	AwsIamTokenResult result;
	if (std::chrono::steady_clock::now() < deadline && sink->wait_until(deadline, result) &&
		std::chrono::steady_clock::now() < deadline) return result;
	cancel(handle);
	result.token.clear();
	result.status = AwsIamStatus::TIMEOUT;
	return result;
}
void AwsIamTokenManager::cancel(AwsIamRequestHandle handle) { impl_->cancel(handle); }
void AwsIamTokenManager::invalidate(const AwsIamTokenKey& key, uint64_t generation) {
	impl_->invalidate(key, generation);
}
void AwsIamTokenManager::record_backend_connection(bool success) {
	impl_->record_backend_connection(success);
}
AwsIamStatsSnapshot AwsIamTokenManager::snapshot() const { return impl_->snapshot(); }
