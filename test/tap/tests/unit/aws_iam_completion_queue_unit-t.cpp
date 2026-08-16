/**
 * @file aws_iam_completion_queue_unit-t.cpp
 * @brief Concurrency and lifetime tests for the per-worker IAM completion inbox.
 */

#include "tap.h"

#include "MySQL_Thread.h"

#include <openssl/crypto.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>
#include <unistd.h>

namespace {

std::atomic<unsigned int> cleanse_calls { 0 };

void tracked_cleanse(void *ptr, size_t size) {
	OPENSSL_cleanse(ptr, size);
	cleanse_calls.fetch_add(1, std::memory_order_relaxed);
}

AwsIamCompletion completion(uint64_t opaque_id, bool with_token = false) {
	AwsIamCompletion value;
	value.opaque_id = opaque_id;
	value.result.status = AwsIamStatus::OK;
	if (with_token) {
		value.result.token = SecureString("sensitive-queue-token", tracked_cleanse);
	}
	return value;
}

struct PipePair {
	int fds[2] { -1, -1 };
	PipePair() {
		if (pipe(fds) != 0) {
			BAIL_OUT("pipe() failed");
		}
		const int flags = fcntl(fds[1], F_GETFL, 0);
		if (flags < 0 || fcntl(fds[1], F_SETFL, flags | O_NONBLOCK) != 0) {
			BAIL_OUT("failed to make completion pipe nonblocking");
		}
	}
	~PipePair() {
		if (fds[0] >= 0) close(fds[0]);
		if (fds[1] >= 0) close(fds[1]);
	}
	unsigned int wake_count() {
		const int flags = fcntl(fds[0], F_GETFL, 0);
		fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
		unsigned int count = 0;
		unsigned char byte = 0;
		while (read(fds[0], &byte, 1) == 1) ++count;
		return count;
	}
};

bool run_multi_producer_once() {
	PipePair pipe_pair;
	auto inbox = std::make_shared<AwsIamWorkerInbox>(pipe_pair.fds[1], 512);
	constexpr unsigned int producers = 8;
	constexpr unsigned int per_producer = 32;
	std::vector<std::thread> threads;
	threads.reserve(producers);
	for (unsigned int producer = 0; producer < producers; ++producer) {
		threads.emplace_back([inbox, producer] {
			for (unsigned int item = 0; item < per_producer; ++item) {
				const uint64_t id = producer * per_producer + item + 1;
				inbox->post(completion(id));
			}
		});
	}
	for (auto& thread : threads) thread.join();

	auto values = inbox->drain();
	std::unordered_set<uint64_t> ids;
	for (const auto& value : values) ids.insert(value.opaque_id);
	return values.size() == producers * per_producer &&
		ids.size() == producers * per_producer && pipe_pair.wake_count() == 1;
}

void test_multi_producer_and_wake_coalescing() {
	bool passed = true;
	for (unsigned int iteration = 0; iteration < 100; ++iteration) {
		passed = passed && run_multi_producer_once();
	}
	ok(passed,
		"100 multi-producer runs deliver every completion with one empty-to-nonempty wake each");
}

void test_fifo_drain() {
	PipePair pipe_pair;
	AwsIamWorkerInbox inbox(pipe_pair.fds[1], 4);
	inbox.post(completion(11));
	inbox.post(completion(12));
	inbox.post(completion(13));
	auto values = inbox.drain();
	ok(values.size() == 3 && values[0].opaque_id == 11 &&
		values[1].opaque_id == 12 && values[2].opaque_id == 13,
		"drain preserves completion FIFO order");
	ok(pipe_pair.wake_count() == 1,
		"multiple posts before a drain write only one pipe wake");
}

void test_bounded_overflow_cleanses() {
	cleanse_calls.store(0, std::memory_order_relaxed);
	PipePair pipe_pair;
	AwsIamWorkerInbox inbox(pipe_pair.fds[1], 2);
	inbox.post(completion(1, true));
	inbox.post(completion(2, true));
	inbox.post(completion(3, true));
	ok(cleanse_calls.load(std::memory_order_relaxed) == 1,
		"a completion rejected by the queue bound is cleansed immediately");
	auto values = inbox.drain();
	ok(values.size() == 2 && values[0].opaque_id == 1 && values[1].opaque_id == 2,
		"bounded overflow does not displace accepted FIFO completions");
	values.clear();
	ok(cleanse_calls.load(std::memory_order_relaxed) == 3,
		"drained completion tokens remain independently owned and are cleansed on release");
}

void test_close_and_late_post() {
	cleanse_calls.store(0, std::memory_order_relaxed);
	PipePair pipe_pair;
	AwsIamWorkerInbox inbox(pipe_pair.fds[1], 2);
	inbox.close();
	inbox.close();
	inbox.post(completion(9, true));
	ok(cleanse_calls.load(std::memory_order_relaxed) == 1 && inbox.drain().empty(),
		"close is idempotent and a late post is cleansed instead of retained");
	ok(pipe_pair.wake_count() == 0,
		"a post after close never writes to the worker pipe");
}

void test_expired_weak_producers() {
	PipePair pipe_pair;
	auto inbox = std::make_shared<AwsIamWorkerInbox>(pipe_pair.fds[1], 64);
	std::weak_ptr<AwsIamCompletionSink> weak = inbox;
	std::atomic<bool> release { false };
	std::vector<std::thread> producers;
	for (unsigned int i = 0; i < 16; ++i) {
		producers.emplace_back([weak, &release, i] {
			while (!release.load(std::memory_order_acquire)) std::this_thread::yield();
			if (auto live = weak.lock()) live->post(completion(i + 1));
		});
	}
	inbox.reset();
	release.store(true, std::memory_order_release);
	for (auto& producer : producers) producer.join();
	ok(weak.expired(),
		"inbox destruction is safe while producer threads hold only expired weak pointers");
}

} // namespace

int main() {
	plan(9);
	test_multi_producer_and_wake_coalescing();
	test_fifo_drain();
	test_bounded_overflow_cleanses();
	test_close_and_late_post();
	test_expired_weak_producers();
	return exit_status();
}
