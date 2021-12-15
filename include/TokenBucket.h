/*
Original work Copyright (c) 2017 Erik Rigtorp <erik@rigtorp.se>
Modified work Copyright 2021 Javier Jaramago Fernández <javier@sysown.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#pragma once

#include <atomic>
#include <chrono>

class TokenBucket {
public:
	TokenBucket() {}

	TokenBucket(const uint64_t rate, const uint64_t burstSize) {
		timePerToken_ = 1000000 / rate;
		timePerBurst_ = burstSize * timePerToken_;
	}

	TokenBucket(const TokenBucket &other) {
		timePerToken_ = other.timePerToken_.load();
		timePerBurst_ = other.timePerBurst_.load();
		disabled_ = other.disabled_.load();
	}

	TokenBucket &operator=(const TokenBucket &other) {
		timePerToken_ = other.timePerToken_.load();
		timePerBurst_ = other.timePerBurst_.load();
		disabled_ = other.disabled_.load();
		return *this;
	}

	bool consume(const uint64_t tokens) {
		if (disabled_.load(std::memory_order_relaxed) == true) {
			return true;
		}

		const uint64_t now =
				std::chrono::duration_cast<std::chrono::microseconds>(
					std::chrono::steady_clock::now().time_since_epoch()
				).count();
		const uint64_t timeNeeded =
				tokens * timePerToken_.load(std::memory_order_relaxed);
		const uint64_t minTime =
				now - timePerBurst_.load(std::memory_order_relaxed);
		uint64_t oldTime = time_.load(std::memory_order_relaxed);
		uint64_t newTime = oldTime;

		if (minTime > oldTime) {
			newTime = minTime;
		}

		for (;;) {
			newTime += timeNeeded;
			if (newTime > now) {
				return false;
			}
			if (time_.compare_exchange_weak(oldTime, newTime,
											std::memory_order_relaxed,
											std::memory_order_relaxed)) {
				return true;
			}
			newTime = oldTime;
		}

		return false;
	}

	void disable() {
		disabled_ = true;
	}

	void enable() {
		disabled_ = false;
	}

	void update(const uint64_t rate, const uint64_t burstSize) {
		timePerToken_ = 1000000 / rate;
		timePerBurst_ = burstSize;
	}

	bool is_disabled() {
		return disabled_.load(std::memory_order_relaxed);
	}

private:
	std::atomic<bool> disabled_ = {false};
	std::atomic<uint64_t> time_ = {0};
	std::atomic<uint64_t> timePerToken_ = {0};
	std::atomic<uint64_t> timePerBurst_ = {0};
};
