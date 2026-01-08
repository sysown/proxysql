/**
 * @file genai_demo.cpp
 * @brief Standalone demonstration of GenAI module architecture
 *
 * This program demonstrates:
 * - GenAI module with thread pool and epoll-based listener
 * - Multiple clients making concurrent requests
 * - Request queue with worker threads
 * - Simulated async processing (sleep instead of real LLM calls)
 *
 * Compile: g++ -std=c++17 -o genai_demo genai_demo.cpp -lpthread
 * Run: ./genai_demo
 */

#include <iostream>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <chrono>
#include <random>

// Define eventfd flags if not available
#ifndef EFD_CLOEXEC
#define EFD_CLOEXEC 0200000
#endif
#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK 04000
#endif

// ============================================================================
// Protocol Definitions
// ============================================================================

struct RequestHeader {
    uint64_t request_id;
    uint32_t operation;      // 0=embedding, 1=completion, 2=rag
    uint32_t input_size;
    uint32_t flags;
};

struct ResponseHeader {
    uint64_t request_id;
    uint32_t status_code;    // 0=success, >0=error
    uint32_t output_size;
    uint32_t processing_time_ms;
};

enum Operation {
    OP_EMBEDDING = 0,
    OP_COMPLETION = 1,
    OP_RAG = 2
};

// ============================================================================
// GenAI Module
// ============================================================================

class GenAIModule {
public:
    struct Request {
        int client_fd;
        uint64_t request_id;
        uint32_t operation;
        std::string input;
    };

    GenAIModule(int num_workers = 4) : num_workers_(num_workers), running_(false) {}

    void start() {
        running_ = true;

        // Create epoll instance
        epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
        if (epoll_fd_ < 0) {
            perror("epoll_create1");
            exit(1);
        }

        // Create eventfd for shutdown notification
        event_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (event_fd_ < 0) {
            perror("eventfd");
            exit(1);
        }

        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = event_fd_;
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, event_fd_, &ev) < 0) {
            perror("epoll_ctl eventfd");
            exit(1);
        }

        // Start worker threads
        for (int i = 0; i < num_workers_; i++) {
            worker_threads_.emplace_back([this, i]() { worker_loop(i); });
        }

        // Start listener thread
        listener_thread_ = std::thread([this]() { listener_loop(); });

        std::cout << "[GenAI] Module started with " << num_workers_ << " workers\n";
    }

    // Register a new client connection
    void register_client(int client_fd) {
        std::lock_guard<std::mutex> lock(clients_mutex_);

        // Set non-blocking
        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = client_fd;
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            perror("epoll_ctl client_fd");
            return;
        }

        client_fds_.insert(client_fd);
        std::cout << "[GenAI] Registered client fd " << client_fd << "\n";
    }

    void stop() {
        running_ = false;

        // Wake up listener
        uint64_t value = 1;
        write(event_fd_, &value, sizeof(value));

        // Wake up all workers
        queue_cv_.notify_all();

        // Wait for threads
        if (listener_thread_.joinable()) {
            listener_thread_.join();
        }

        for (auto& t : worker_threads_) {
            if (t.joinable()) {
                t.join();
            }
        }

        // Clean up
        for (int fd : client_fds_) {
            close(fd);
        }

        close(epoll_fd_);
        close(event_fd_);

        std::cout << "[GenAI] Module stopped\n";
    }

    size_t get_queue_size() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return request_queue_.size();
    }

private:
    void listener_loop() {
        const int MAX_EVENTS = 64;
        struct epoll_event events[MAX_EVENTS];

        std::cout << "[GenAI] Listener thread started\n";

        while (running_) {
            int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, 100);

            if (nfds < 0 && errno != EINTR) {
                perror("epoll_wait");
                break;
            }

            for (int i = 0; i < nfds; i++) {
                if (events[i].data.fd == event_fd_) {
                    // Shutdown signal
                    continue;
                }

                int client_fd = events[i].data.fd;

                // Read request header
                RequestHeader header;
                ssize_t n = read(client_fd, &header, sizeof(header));

                if (n <= 0) {
                    // Connection closed or error
                    std::cout << "[GenAI] Client fd " << client_fd << " disconnected\n";
                    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, client_fd, nullptr);
                    close(client_fd);
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    client_fds_.erase(client_fd);
                    continue;
                }

                // Read input data
                std::string input(header.input_size, '\0');
                size_t total_read = 0;
                while (total_read < header.input_size) {
                    ssize_t r = read(client_fd, &input[total_read], header.input_size - total_read);
                    if (r <= 0) break;
                    total_read += r;
                }

                // Create request and push to queue
                Request req;
                req.client_fd = client_fd;
                req.request_id = header.request_id;
                req.operation = header.operation;
                req.input = std::move(input);

                {
                    std::lock_guard<std::mutex> lock(queue_mutex_);
                    request_queue_.push(std::move(req));
                }

                queue_cv_.notify_one();

                std::cout << "[GenAI] Enqueued request " << header.request_id
                         << " from fd " << client_fd
                         << " (queue size: " << get_queue_size() << ")\n" << std::flush;
            }
        }

        std::cout << "[GenAI] Listener thread stopped\n";
    }

    void worker_loop(int worker_id) {
        std::cout << "[GenAI] Worker " << worker_id << " started\n";

        while (running_) {
            Request req;

            // Wait for work
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_cv_.wait(lock, [this] {
                    return !running_ || !request_queue_.empty();
                });

                if (!running_) break;

                if (request_queue_.empty()) continue;

                req = std::move(request_queue_.front());
                request_queue_.pop();
            }

            // Simulate processing time (random sleep)
            unsigned int seed = req.request_id;
            int sleep_ms = 100 + (rand_r(&seed) % 400);  // 100-500ms

            std::cout << "[GenAI] Worker " << worker_id
                     << " processing request " << req.request_id
                     << " (sleep " << sleep_ms << "ms)\n";

            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));

            // Prepare response
            std::string output = "Processed: " + req.input;

            ResponseHeader resp;
            resp.request_id = req.request_id;
            resp.status_code = 0;
            resp.output_size = output.size();
            resp.processing_time_ms = sleep_ms;

            // Send response back to client
            write(req.client_fd, &resp, sizeof(resp));
            write(req.client_fd, output.data(), output.size());

            std::cout << "[GenAI] Worker " << worker_id
                     << " completed request " << req.request_id << "\n";
        }

        std::cout << "[GenAI] Worker " << worker_id << " stopped\n";
    }

    int num_workers_;
    std::atomic<bool> running_;

    int epoll_fd_;
    int event_fd_;

    std::thread listener_thread_;
    std::vector<std::thread> worker_threads_;

    std::queue<Request> request_queue_;
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_cv_;

    std::unordered_set<int> client_fds_;
    mutable std::mutex clients_mutex_;
};

// ============================================================================
// Client
// ============================================================================

class Client {
public:
    Client(const std::string& name, int num_requests = 5)
        : name_(name), num_requests_(num_requests), next_id_(1) {}

    void connect_to_genai(GenAIModule& genai) {
        // Create socketpair
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
            perror("socketpair");
            exit(1);
        }

        read_fd_ = fds[0];
        genai_fd_ = fds[1];

        // Register with GenAI (pass the write end)
        genai.register_client(genai_fd_);

        // Set read_fd to non-blocking for later
        int flags = fcntl(read_fd_, F_GETFL, 0);
        fcntl(read_fd_, F_SETFL, flags | O_NONBLOCK);

        std::cout << "[" << name_ << "] Connected to GenAI (read_fd=" << read_fd_ << ")\n";
    }

    void run() {
        // Send all requests
        for (int i = 0; i < num_requests_; i++) {
            send_request(i);
        }

        // Wait for all responses (simulate async handling)
        std::cout << "[" << name_ << "] Waiting for " << num_requests_ << " responses...\n";

        while (completed_ < num_requests_) {
            process_responses();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        std::cout << "[" << name_ << "] All requests completed!\n";
    }

    void close() {
        if (read_fd_ >= 0) ::close(read_fd_);
        if (genai_fd_ >= 0) ::close(genai_fd_);
    }

private:
    void send_request(int index) {
        std::string input = name_ + " input #" + std::to_string(index);
        uint64_t request_id = next_id_++;

        RequestHeader req;
        req.request_id = request_id;
        req.operation = OP_EMBEDDING;
        req.input_size = input.size();
        req.flags = 0;

        // Send request
        write(genai_fd_, &req, sizeof(req));
        write(genai_fd_, input.data(), input.size());

        pending_requests_[request_id] = std::chrono::steady_clock::now();

        std::cout << "[" << name_ << "] Sent request " << request_id
                 << " (" << input << ")\n";
    }

    void process_responses() {
        ResponseHeader resp;
        ssize_t n = read(read_fd_, &resp, sizeof(resp));

        if (n <= 0) {
            return;  // No data available yet
        }

        // Read output
        std::string output(resp.output_size, '\0');
        size_t total_read = 0;
        while (total_read < resp.output_size) {
            ssize_t r = read(read_fd_, &output[total_read], resp.output_size - total_read);
            if (r <= 0) break;
            total_read += r;
        }

        auto it = pending_requests_.find(resp.request_id);
        if (it != pending_requests_.end()) {
            auto start_time = it->second;
            auto end_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time).count();

            std::cout << "[" << name_ << "] Received response for request " << resp.request_id
                     << " (took " << duration << "ms, processed in "
                     << resp.processing_time_ms << "ms): " << output << "\n";

            pending_requests_.erase(it);
            completed_++;
        }
    }

    std::string name_;
    int num_requests_;
    uint64_t next_id_;
    int completed_ = 0;

    int read_fd_ = -1;
    int genai_fd_ = -1;

    std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> pending_requests_;
};

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== GenAI Module Demonstration ===\n\n";

    // Create and start GenAI module with 4 worker threads
    GenAIModule genai(4);
    genai.start();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Create multiple clients
    std::cout << "\n=== Creating Clients ===\n";

    std::vector<std::thread> client_threads;

    // Client 1: MySQL Thread simulation
    client_threads.emplace_back([&genai]() {
        Client client("MySQL-Thread-1", 3);
        client.connect_to_genai(genai);
        client.run();
        client.close();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Client 2: MySQL Thread simulation
    client_threads.emplace_back([&genai]() {
        Client client("MySQL-Thread-2", 3);
        client.connect_to_genai(genai);
        client.run();
        client.close();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Client 3: PgSQL Thread simulation
    client_threads.emplace_back([&genai]() {
        Client client("PgSQL-Thread-1", 3);
        client.connect_to_genai(genai);
        client.run();
        client.close();
    });

    // Wait for all clients to complete
    for (auto& t : client_threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    std::cout << "\n=== All Clients Completed ===\n";

    // Stop GenAI module
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    genai.stop();

    std::cout << "\n=== Demonstration Complete ===\n";

    return 0;
}
