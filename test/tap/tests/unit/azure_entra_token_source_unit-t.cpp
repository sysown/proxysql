/**
 * @file azure_entra_token_source_unit-t.cpp
 * @brief Azure Entra token source: cache, refresh, coalescing, backoff (issue #6649).
 */
#include "tap.h"

#include "curl_transport.h"
#include "entra_token_source.h"

#include <atomic>
#include <condition_variable>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <stdlib.h>
#include <unistd.h>

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

namespace {

class TestSink final : public AwsIamCompletionSink {
public:
	void post(AwsIamCompletion&& completion) override {
		std::lock_guard<std::mutex> lock(mutex);
		completions.push_back(std::move(completion));
		cv.notify_all();
	}
	bool wait_for(size_t count, std::chrono::milliseconds timeout = 2000ms) {
		std::unique_lock<std::mutex> lock(mutex);
		return cv.wait_for(lock, timeout, [&] { return completions.size() >= count; });
	}
	size_t size() {
		std::lock_guard<std::mutex> lock(mutex);
		return completions.size();
	}
	AwsIamStatus status(size_t i) {
		std::lock_guard<std::mutex> lock(mutex);
		return i < completions.size() ? completions[i].result.status : AwsIamStatus::PROVIDER_ERROR;
	}
	std::mutex mutex;
	std::condition_variable cv;
	std::vector<AwsIamCompletion> completions;
};

/** Fake Entra token endpoint: counts POSTs, can hold them until released. */
struct FakeEntra {
	std::mutex mutex;
	std::condition_variable cv;
	int posts { 0 };
	bool block { false };
	bool released { false };
	HttpResponse reply { 200, R"({"access_token":"tok","expires_in":3600})" };

	HttpPostFn fn() {
		return [this](const std::string&, const std::string&, std::chrono::milliseconds) {
			std::unique_lock<std::mutex> lock(mutex);
			++posts;
			cv.notify_all();
			cv.wait(lock, [this] { return !block || released; });
			return reply;
		};
	}
	bool wait_posts(int n, std::chrono::milliseconds timeout = 2000ms) {
		std::unique_lock<std::mutex> lock(mutex);
		return cv.wait_for(lock, timeout, [&] { return posts >= n; });
	}
	int count() {
		std::lock_guard<std::mutex> lock(mutex);
		return posts;
	}
	void release() {
		std::lock_guard<std::mutex> lock(mutex);
		released = true;
		cv.notify_all();
	}
	void set_reply(long status, const char *body) {
		std::lock_guard<std::mutex> lock(mutex);
		reply = { status, body };
	}
};

struct FakeClock {
	const Clock::time_point base { Clock::now() };
	std::atomic<long long> offset_ms { 0 };
	std::function<Clock::time_point()> fn() {
		return [this] { return base + std::chrono::milliseconds(offset_ms.load()); };
	}
	void advance(std::chrono::milliseconds d) { offset_ms += d.count(); }
};

EntraConfig config() {
	EntraConfig cfg;
	cfg.tenant_id = "11111111-2222-3333-4444-555555555555";
	cfg.client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
	cfg.federated_token_file = "/unused";
	cfg.authority_host = "https://login.microsoftonline.com/";
	cfg.scope = "https://ossrdbms-aad.database.windows.net/.default";
	return cfg;
}

std::function<bool(std::string&)> assertion() {
	return [](std::string& out) { out = "federated-token"; return true; };
}

const AwsIamTokenKey kKey { "app.mysql.database.azure.com", 3306, "", "entra_app" };

struct Rig {
	FakeEntra http;
	FakeClock clock;
	std::shared_ptr<TestSink> sink { std::make_shared<TestSink>() };
	std::unique_ptr<AzureEntraTokenSource> source;
	explicit Rig(size_t max_waiters = 100) {
		source = std::make_unique<AzureEntraTokenSource>(config(), http.fn(),
			AwsIamRuntimeConfig { max_waiters, max_waiters }, assertion(), clock.fn());
	}
	void request(uint64_t id) { source->request(kKey, id, sink); }
};

/** Poll a condition that a background thread makes true. */
template <typename F> bool eventually(F cond, std::chrono::milliseconds timeout = 2000ms) {
	const auto end = Clock::now() + timeout;
	while (Clock::now() < end) {
		if (cond()) return true;
		std::this_thread::sleep_for(5ms);
	}
	return cond();
}

void test_cold_cache_and_cache_hit() {
	Rig rig;
	rig.request(1);
	const bool got = rig.sink->wait_for(1);
	ok(got && rig.http.count() == 1 && rig.sink->status(0) == AwsIamStatus::OK &&
		rig.sink->completions[0].result.generation == 1 &&
		std::string(rig.sink->completions[0].result.token.c_str()) == "tok" &&
		rig.sink->completions[0].opaque_id == 1,
		"cold_cache_single_fetch");
	rig.request(2);
	ok(rig.sink->wait_for(2) && rig.http.count() == 1 && rig.sink->status(1) == AwsIamStatus::OK &&
		rig.source->snapshot().token_cache_hits == 1,
		"cache_hit_no_fetch");
}

void test_concurrent_requests_coalesce() {
	Rig rig;
	rig.http.block = true;
	for (uint64_t i = 1; i <= 50; ++i) rig.request(i);
	const bool started = rig.http.wait_posts(1);
	rig.http.release();
	ok(started && rig.sink->wait_for(50) && rig.http.count() == 1 &&
		rig.sink->status(49) == AwsIamStatus::OK,
		"concurrent_requests_coalesce: 50 requests, 1 POST, 50 completions");
}

void test_refresh_ahead() {
	Rig rig;
	rig.request(1);
	rig.sink->wait_for(1);
	rig.clock.advance(51min);
	rig.source->wake();
	const bool refreshed = eventually([&] { return rig.source->snapshot().token_refresh_successes == 2; });
	rig.request(2);
	ok(refreshed && rig.sink->wait_for(2) && rig.http.count() == 2 &&
		rig.sink->completions[1].result.generation == 2,
		"refresh_ahead: a background POST runs before the token gets short");
}

void test_invalidate_matching_generation_only() {
	Rig rig;
	rig.request(1);
	rig.sink->wait_for(1);
	rig.source->invalidate(kKey, 2);
	std::this_thread::sleep_for(100ms);
	const bool kept = rig.http.count() == 1;
	rig.source->invalidate(kKey, 1);
	ok(kept && eventually([&] { return rig.source->snapshot().token_refresh_successes == 2; }) &&
		rig.http.count() == 2,
		"invalidate_matching_generation_only: only the current generation starts a refresh");
}

void test_invalidate_keeps_shared_token() {
	Rig rig;
	rig.request(1);
	rig.sink->wait_for(1);
	{
		std::lock_guard<std::mutex> lock(rig.http.mutex);
		rig.http.block = true;
		rig.http.reply = { 503, R"({"error":"temporarily_unavailable"})" };
	}
	rig.source->invalidate(kKey, 1);
	const bool refetch_started = rig.http.wait_posts(2);
	rig.request(2);
	const bool served_during_fetch = rig.sink->wait_for(2, 200ms) && rig.sink->status(1) == AwsIamStatus::OK &&
		rig.sink->completions[1].result.generation == 1;
	rig.http.release();
	const bool fetch_failed = eventually([&] { return rig.source->snapshot().token_refresh_failures == 1; });
	rig.request(3);
	ok(refetch_started && served_during_fetch && fetch_failed && rig.sink->wait_for(3) &&
		rig.sink->status(2) == AwsIamStatus::OK && rig.sink->completions[2].result.generation == 1,
		"invalidate_keeps_shared_token: other users keep the token while and after a failed refresh");
}

void test_invalidate_rate_limited() {
	Rig rig;
	auto refreshes = [&] { return rig.source->snapshot().token_refresh_successes; };
	rig.request(1);
	rig.sink->wait_for(1);
	rig.source->invalidate(kKey, 1);
	const bool refetched = eventually([&] { return refreshes() == 2; });
	rig.clock.advance(10s);
	rig.source->invalidate(kKey, 2);
	std::this_thread::sleep_for(100ms);
	const bool kept = rig.http.count() == 2;
	rig.clock.advance(51s);
	rig.source->invalidate(kKey, 2);
	ok(refetched && kept && eventually([&] { return refreshes() == 3; }) && rig.http.count() == 3,
		"invalidate_rate_limited: at most one accepted invalidate per 60 s");
}

void test_failure_backoff() {
	Rig rig;
	rig.http.set_reply(503, R"({"error":"temporarily_unavailable","correlation_id":"c1"})");
	rig.request(1);
	const bool first = rig.sink->wait_for(1) && rig.sink->status(0) == AwsIamStatus::PROVIDER_ERROR &&
		rig.sink->completions[0].result.failure.aws_error_code == "temporarily_unavailable";
	for (uint64_t i = 2; i <= 20; ++i) rig.request(i);
	const bool backed_off = rig.sink->wait_for(20) && rig.http.count() == 1 &&
		rig.sink->status(19) == AwsIamStatus::PROVIDER_ERROR;
	rig.clock.advance(2100ms);
	rig.request(21);
	ok(first && backed_off && rig.sink->wait_for(21) && rig.http.count() == 2,
		"failure_backoff: 20 requests within 2 s cause 1 POST; a request after 2 s tries again");
}

void test_refresh_backoff_grows() {
	Rig rig;
	auto failures = [&] { return rig.source->snapshot().token_refresh_failures; };
	auto step = [&](std::chrono::milliseconds d) { rig.clock.advance(d); rig.source->wake(); };
	rig.request(1);
	rig.sink->wait_for(1);
	rig.http.set_reply(503, "{}");
	step(51min);
	const bool first = eventually([&] { return failures() == 1; });
	step(2100ms);
	const bool second = eventually([&] { return failures() == 2; });
	step(2100ms);
	std::this_thread::sleep_for(1200ms);
	const bool waited = rig.http.count() == 3;
	step(2100ms);
	ok(first && second && waited && eventually([&] { return failures() == 3; }),
		"refresh_backoff_grows: with a usable token, the wait after each failed refresh doubles");
}

void test_file_assertion_reader() {
	char path[] = "/tmp/entra_assertion_XXXXXX";
	const int fd = mkstemp(path);
	const std::string jwt = "hdr.payload.sig";
	const bool written = fd >= 0 && write(fd, (jwt + "\n").data(), jwt.size() + 1) == (ssize_t)(jwt.size() + 1);
	if (fd >= 0) close(fd);
	std::string out;
	const bool read_ok = file_assertion_reader(path)(out) && out == jwt;
	{
		std::ofstream big(path, std::ios::binary | std::ios::trunc);
		big << std::string(20000, 'a');
	}
	out.clear();
	const bool big_refused = !file_assertion_reader(path)(out) && out.empty();
	unlink(path);
	ok(written && read_ok && big_refused,
		"file_assertion_reader: trims the newline and refuses a file over 16 KiB");
}

void test_serve_until_expiry() {
	Rig rig;
	rig.request(1);
	rig.sink->wait_for(1);
	rig.http.set_reply(503, "{}");
	rig.clock.advance(59min);
	rig.source->wake();
	const bool refresh_failed = eventually([&] { return rig.source->snapshot().token_refresh_failures == 1; });
	rig.request(2);
	const bool served = rig.sink->wait_for(2) && rig.sink->status(1) == AwsIamStatus::OK &&
		rig.http.count() == 2;
	rig.clock.advance(40s); // 20 s left: no longer usable
	rig.request(3);
	ok(refresh_failed && served && rig.sink->wait_for(3) && rig.http.count() == 3 &&
		rig.sink->status(2) == AwsIamStatus::PROVIDER_ERROR,
		"serve_until_expiry: an old token is served while refresh fails, until 30 s before expiry");
}

void test_waiter_limit() {
	Rig rig(2);
	rig.http.block = true;
	rig.request(1);
	rig.request(2);
	rig.request(3);
	const bool limited = rig.sink->wait_for(1, 500ms) && rig.sink->status(0) == AwsIamStatus::WAITER_LIMIT &&
		rig.sink->completions[0].opaque_id == 3;
	rig.http.release();
	ok(limited && rig.sink->wait_for(3), "waiter_limit: the third waiter is refused");
}

void test_shutdown_answers_waiters() {
	auto rig = std::make_unique<Rig>();
	rig->http.block = true;
	rig->request(1);
	rig->http.wait_posts(1);
	std::shared_ptr<TestSink> sink = rig->sink;
	FakeEntra *http = &rig->http;
	auto destroyed = std::async(std::launch::async, [&rig] { rig->source.reset(); });
	std::this_thread::sleep_for(50ms);
	http->release();
	const bool done = destroyed.wait_for(2s) == std::future_status::ready;
	ok(done && sink->size() == 1 && sink->status(0) == AwsIamStatus::SHUTDOWN,
		"shutdown_answers_waiters");
}

void test_request_blocking() {
	Rig rig;
	AwsIamTokenResult r = rig.source->request_blocking(kKey, Clock::now() + 2s);
	ok(r.status == AwsIamStatus::OK && std::string(r.token.c_str()) == "tok" && rig.http.count() == 1,
		"request_blocking fetches on a cold cache and returns the token");
}

void test_curl_refuses_plain_http() {
	const HttpResponse r = make_curl_post()("http://127.0.0.1:9/token", "a=b", 1000ms);
	ok(r.status == 0, "the curl transport refuses a non-https URL");
}

} // namespace

int main() {
	plan(0);
	test_cold_cache_and_cache_hit();
	test_concurrent_requests_coalesce();
	test_refresh_ahead();
	test_invalidate_matching_generation_only();
	test_invalidate_keeps_shared_token();
	test_invalidate_rate_limited();
	test_failure_backoff();
	test_refresh_backoff_grows();
	test_serve_until_expiry();
	test_file_assertion_reader();
	test_waiter_limit();
	test_shutdown_answers_waiters();
	test_request_blocking();
	test_curl_refuses_plain_http();
	return exit_status();
}
