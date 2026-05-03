#ifndef SQL_ENGINE_THREAD_POOL_H
#define SQL_ENGINE_THREAD_POOL_H

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>

namespace sql_engine {

// Lightweight thread pool for parallel shard I/O.
//
// Workers are pre-spawned and sleep on a condition variable until work arrives.
// Dispatch overhead is ~1-2us (mutex lock + cv signal) vs ~200us for
// std::async thread creation. This matters at high QPS where per-query
// overhead directly impacts throughput.
//
// Usage:
//   ThreadPool pool(4);
//   auto f1 = pool.submit([&]{ shard1->open(); });
//   auto f2 = pool.submit([&]{ shard2->open(); });
//   f1.get(); f2.get();
class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads = 4) {
        workers_.reserve(num_threads);
        for (size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(mutex_);
                        cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    // Exception safety: submit() wraps callables in
                    // std::packaged_task, which catches any exception and
                    // stores it in the shared state to be rethrown by
                    // future::get(). `task()` therefore does not throw, so
                    // the worker loop cannot die on a user exception. If
                    // submit() is ever changed to queue raw callables, this
                    // must be wrapped in try { task(); } catch (...) { log; }.
                    task();
                }
            });
        }
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& w : workers_) {
            if (w.joinable()) w.join();
        }
    }

    // Non-copyable, non-movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    // Submit work and get a future to wait on completion.
    template<class F>
    std::future<void> submit(F&& f) {
        auto task = std::make_shared<std::packaged_task<void()>>(std::forward<F>(f));
        std::future<void> fut = task->get_future();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            tasks_.emplace([task]() { (*task)(); });
        }
        cv_.notify_one();
        return fut;
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_ = false;
};

} // namespace sql_engine

#endif // SQL_ENGINE_THREAD_POOL_H
