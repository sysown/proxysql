#include <chrono>
#include <random>
#include "log_utils.h"


LogBuffer::LogBuffer() : last_flush_time(0) {}

LogBuffer& LogBuffer::operator<<(const std::string& value) {
    buffer.append(value);
	return *this;
}

LogBuffer& LogBuffer::operator<<(const char* value) {
	buffer.append(value);
	return *this;
}

LogBuffer& LogBuffer::operator<<(char value) {
	buffer.push_back(value);
	return *this;
}

LogBuffer& LogBuffer::append(const std::string& str) {
	buffer.append(str);
	return *this;
}

LogBuffer& LogBuffer::append(const char* str) {
	buffer.append(str);
	return *this;
}

LogBuffer& LogBuffer::append(const char* str, size_t len) {
	buffer.append(str, len);
	return *this;
}

LogBuffer& LogBuffer::write(const std::string& str) {
	buffer.append(str);
	return *this;
}

LogBuffer& LogBuffer::write(const char* str, size_t len) {
	buffer.append(str, len);
	return *this;
}

void LogBuffer::reset(uint64_t flush_time) {
	buffer.clear();
	last_flush_time = flush_time;
}

void LogBuffer::set_last_flush_time(uint64_t flush_time) {
	last_flush_time = flush_time;
}

uint64_t LogBuffer::get_last_flush_time() const {
	return last_flush_time;
}

bool LogBuffer::empty() const {
	return buffer.empty();
}

size_t LogBuffer::size() const {
	return buffer.size();
}

const char* LogBuffer::data() const {
	return buffer.data();
}

void LogBuffer::flush_to_file(std::fstream* logfile) {
	if (!logfile || buffer.empty()) {
		return;
	}
	logfile->write(buffer.data(), buffer.size());
}

bool flush_and_rotate(
	LogBuffer& buffer,
	std::fstream*& logfile,
	unsigned int& current_log_size,
	unsigned int max_log_file_size,
	std::function<void()> lock_fn,
	std::function<void()> unlock_fn,
	std::function<void()> rotate_fn,
	uint64_t reset_time)
{
	bool flushed = false;
	lock_fn();
	if (logfile) {
		buffer.flush_to_file(logfile);
		current_log_size += buffer.size();
		flushed = true;
		logfile->flush();
		if (current_log_size > max_log_file_size && rotate_fn) {
			rotate_fn();
			current_log_size = 0;
		}
	}
	unlock_fn();
	if (flushed) {
		buffer.reset(reset_time);
	}
	return flushed;
}

LogBufferThreadContext::LogBufferThreadContext() : dist(0.0, 1.0) {
	// Seed the Mersenne Twister with multiple entropy sources
	std::random_device rd;
	std::seed_seq seed{
		rd(),
		static_cast<unsigned>(std::chrono::high_resolution_clock::now().time_since_epoch().count()),
		static_cast<unsigned>(reinterpret_cast<uintptr_t>(pthread_self()))
	};
	rng.seed(seed);
}

bool LogBufferThreadContext::should_log(int rate_limit) {
	return dist(rng) * static_cast<double>(rate_limit) <= 1.0;
}

LogBufferThreadContext* GetLogBufferThreadContext(std::unordered_map<pthread_t, std::unique_ptr<LogBufferThreadContext>>& log_thread_contexts, std::mutex& log_thread_contexts_lock, uint64_t current_time) {
	pthread_t tid = pthread_self();
	std::lock_guard<std::mutex> lock(log_thread_contexts_lock);
	auto it = log_thread_contexts.find(tid);
	if (it != log_thread_contexts.end()) {
		return it->second.get();
	}

	// Context doesn't exist for this thread, create it with proper initialization
	auto new_context = std::make_unique<LogBufferThreadContext>();
	// init() is already called in the constructor, which initializes both events and audit buffers
	new_context->events.set_last_flush_time(current_time);
	new_context->audit.set_last_flush_time(current_time);

	LogBufferThreadContext* ptr = new_context.get();
	auto [insert_it, inserted] = log_thread_contexts.emplace(tid, std::move(new_context));
	return inserted ? ptr : insert_it->second.get();
}
