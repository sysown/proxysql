/**
 * @file genai_demo_event.cpp
 * @brief Event-driven demonstration of GenAI module architecture
 *
 * This program demonstrates an event-driven approach to testing the GenAI
 * module, which is more realistic and provides better isolation than the
 * thread-based approach.
 *
 * @par Key Differences from genai_demo.cpp
 *
 * - **Clients are objects, not threads**: Clients are managed by a main
 *   event loop instead of running in their own threads
 *
 * - **Randomized timing**: Clients are added and send requests at random
 *   intervals, simulating realistic traffic patterns
 *
 * - **Single epoll set**: Main loop monitors both client responses and
 *   uses timeouts for periodic tasks (adding clients, sending requests)
 *
 * - **Better observability**: Central event loop makes it easy to see
 *   queue depth, active clients, and overall system state
 *
 * @par Architecture
 *
 * ```
 * Main Event Loop
 *   ├─ Randomly add new clients (configurable probability)
 *   ├─ For each client: randomly send request if ready
 *   ├─ epoll_wait() for responses (with timeout)
 *   ├─ Process incoming responses
 *   ├─ Remove completed clients
 *   ├─ Print statistics periodically
 *   └─ Exit when duration elapsed or max clients completed
 * ```
 *
 * @par Client Lifecycle
 *
 * ```
 * NEW → CONNECTED → IDLE → WAITING_FOR_RESPONSE → IDLE → ... → DONE
 *                      ↑                                    │
 *                      └────────────────────────────────────┘
 *                       (after response, can send again)
 * ```
 *
 * @par Configuration
 *
 * The demo behavior can be configured via Config struct:
 * - genai_workers: Number of GenAI worker threads
 * - max_clients: Maximum number of concurrent clients
 * - run_duration_seconds: How long to run the demo
 * - client_add_probability: Chance to add a client per iteration
 * - request_send_probability: Chance an idle client sends a request
 * - min/max_requests_per_client: Range of requests per client
 *
 * @par Build and Run
 *
 * @code{.sh}
 * # Compile
 * g++ -std=c++17 -o genai_demo_event genai_demo_event.cpp -lpthread
 *
 * # Run
 * ./genai_demo_event
 *
 * @author ProxySQL Team
 * @date 2025-01-08
 * @version 2.0
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
#include <cmath>
#include <algorithm>

// Platform compatibility
#ifndef EFD_CLOEXEC
#define EFD_CLOEXEC 0200000
#endif
#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK 04000
#endif

// ============================================================================
// Protocol Definitions
// ============================================================================

/**
 * @struct RequestHeader
 * @brief Header structure for client requests to GenAI module
 *
 * See genai_demo.cpp for full documentation.
 */
struct RequestHeader {
    uint64_t request_id;
    uint32_t operation;
    uint32_t input_size;
    uint32_t flags;
};

/**
 * @struct ResponseHeader
 * @brief Header structure for GenAI module responses to clients
 *
 * See genai_demo.cpp for full documentation.
 */
struct ResponseHeader {
    uint64_t request_id;
    uint32_t status_code;
    uint32_t output_size;
    uint32_t processing_time_ms;
};

/**
 * @enum Operation
 * @brief Supported GenAI operations
 */
enum Operation {
    OP_EMBEDDING = 0,
    OP_COMPLETION = 1,
    OP_RAG = 2
};

// ============================================================================
// GenAI Module (reused from genai_demo.cpp)
// ============================================================================

/**
 * @class GenAIModule
 * @brief Thread-pool based GenAI processing module
 *
 * This is the same GenAI module from genai_demo.cpp, providing
 * the asynchronous request processing with thread pool.
 *
 * See genai_demo.cpp for detailed documentation.
 */
class GenAIModule {
public:
    struct Request {
        int client_fd;
        uint64_t request_id;
        uint32_t operation;
        std::string input;
    };

    GenAIModule(int num_workers = 4)
        : num_workers_(num_workers), running_(false) {}

    void start() {
        running_ = true;

        epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
        if (epoll_fd_ < 0) {
            perror("epoll_create1");
            exit(1);
        }

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

        for (int i = 0; i < num_workers_; i++) {
            worker_threads_.emplace_back([this, i]() { worker_loop(i); });
        }

        listener_thread_ = std::thread([this]() { listener_loop(); });

        std::cout << "[GenAI] Module started with " << num_workers_ << " workers\n";
    }

    void register_client(int client_fd) {
        std::lock_guard<std::mutex> lock(clients_mutex_);

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
    }

    void stop() {
        running_ = false;

        uint64_t value = 1;
        write(event_fd_, &value, sizeof(value));
        queue_cv_.notify_all();

        if (listener_thread_.joinable()) {
            listener_thread_.join();
        }

        for (auto& t : worker_threads_) {
            if (t.joinable()) {
                t.join();
            }
        }

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

        while (running_) {
            int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, 100);

            if (nfds < 0 && errno != EINTR) {
                perror("epoll_wait");
                break;
            }

            for (int i = 0; i < nfds; i++) {
                if (events[i].data.fd == event_fd_) {
                    continue;
                }

                int client_fd = events[i].data.fd;

                RequestHeader header;
                ssize_t n = read(client_fd, &header, sizeof(header));

                if (n <= 0) {
                    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, client_fd, nullptr);
                    close(client_fd);
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    client_fds_.erase(client_fd);
                    continue;
                }

                std::string input(header.input_size, '\0');
                size_t total_read = 0;
                while (total_read < header.input_size) {
                    ssize_t r = read(client_fd, &input[total_read], header.input_size - total_read);
                    if (r <= 0) break;
                    total_read += r;
                }

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
            }
        }
    }

    void worker_loop(int worker_id) {
        while (running_) {
            Request req;

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

            unsigned int seed = req.request_id;
            int sleep_ms = 100 + (rand_r(&seed) % 400);

            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));

            std::string output = "Processed: " + req.input;

            ResponseHeader resp;
            resp.request_id = req.request_id;
            resp.status_code = 0;
            resp.output_size = output.size();
            resp.processing_time_ms = sleep_ms;

            write(req.client_fd, &resp, sizeof(resp));
            write(req.client_fd, output.data(), output.size());
        }
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
// Configuration
// ============================================================================

/**
 * @struct Config
 * @brief Configuration for the event-driven GenAI demo
 *
 * @var genai_workers
 * Number of worker threads in the GenAI module pool
 *
 * @var max_clients
 * Maximum number of concurrent client connections to create
 *
 * @var run_duration_seconds
 * How long the demo should run before terminating
 *
 * @var client_add_probability
 * Probability (0.0 to 1.0) of adding a new client per main loop iteration
 *
 * @var request_send_probability
 * Probability (0.0 to 1.0) that an idle client sends a request per iteration
 *
 * @var min_requests_per_client
 * Minimum number of requests each client must send before completing
 *
 * @var max_requests_per_client
 * Maximum number of requests each client will send
 *
 * @var stats_print_interval_ms
 * How often to print statistics (in milliseconds)
 */
struct Config {
    int genai_workers = 4;
    int max_clients = 15;
    int run_duration_seconds = 20;
    double client_add_probability = 0.15;   // 15% chance per iteration
    double request_send_probability = 0.08;  // 8% chance per idle client (more spread out)
    int min_requests_per_client = 5;
    int max_requests_per_client = 15;
    int stats_print_interval_ms = 500;
};

// ============================================================================
// Client
// ============================================================================

/**
 * @class Client
 * @brief Event-driven client for GenAI module testing
 *
 * Unlike the thread-based Client in genai_demo.cpp, this client is
 * designed to be managed by a main event loop. It maintains internal
 * state and processes events incrementally.
 *
 * @par State Machine
 *
 * ```
 * NEW → CONNECTED → IDLE → WAITING_FOR_RESPONSE → IDLE → ... → DONE
 *                      ↑                                    │
 *                      └────────────────────────────────────┘
 *                       (after response, can send again)
 * ```
 *
 * @par Usage Pattern
 *
 * @code{.cpp}
 * // Create client
 * Client* client = new Client(id, config);
 *
 * // Connect to GenAI
 * client->connect(genai_module);
 *
 * // In main event loop:
 * if (client->can_send_request() && random() < threshold) {
 *     client->send_request();
 * }
 *
 * // After epoll event:
 * if (client->has_response()) {
 *     client->process_response();
 * }
 *
 * // Check if done
 * if (client->is_done()) {
 *     delete client;
 * }
 * @endcode
 */
class Client {
public:

    /**
     * @enum State
     * @brief Client state for state machine
     */
    enum State {
        NEW,                   ///< Client just created, not connected
        CONNECTED,            ///< Connected to GenAI, ready to send
        IDLE,                 ///< Ready to send next request
        WAITING_FOR_RESPONSE, ///< Request sent, waiting for response
        DONE                  ///< All requests completed
    };

    /**
     * @brief Construct a Client with specified ID and configuration
     *
     * @param id Unique identifier for this client
     * @param config Configuration determining client behavior
     */
    Client(int id, const Config& config)
        : id_(id),
          config_(config),
          state_(NEW),
          read_fd_(-1),
          genai_fd_(-1),
          next_request_id_(1),
          requests_sent_(0),
          total_requests_(0),
          responses_received_(0),
          last_send_time_(std::chrono::steady_clock::now()),
          last_response_time_(std::chrono::steady_clock::now()) {

        // Randomize total requests for this client
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(
            config_.min_requests_per_client,
            config_.max_requests_per_client
        );
        total_requests_ = dist(gen);
    }

    /**
     * @brief Connect this client to the GenAI module
     *
     * Creates a socketpair and registers with GenAI module.
     *
     * @param genai Reference to the GenAI module
     *
     * @post state_ is CONNECTED
     * @post read_fd_ and genai_fd_ are set
     */
    void connect(GenAIModule& genai) {
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
            perror("socketpair");
            return;
        }

        // Client uses fds[0] for both reading and writing
        // GenAI uses fds[1] for both reading and writing
        read_fd_ = fds[0];
        genai_fd_ = fds[1];  // Only used for registration

        int flags = fcntl(read_fd_, F_GETFL, 0);
        fcntl(read_fd_, F_SETFL, flags | O_NONBLOCK);

        genai.register_client(genai_fd_);  // GenAI gets the other end

        state_ = IDLE;  // Ready to send requests

        std::cout << "[" << id_ << "] Connected (will send "
                 << total_requests_ << " requests)\n";
    }

    /**
     * @brief Check if this client can send a request
     *
     * @return true if client is in IDLE state and can send
     */
    bool can_send_request() const {
        return state_ == IDLE;
    }

    /**
     * @brief Send a request to the GenAI module
     *
     * @pre state_ is IDLE
     * @post state_ is WAITING_FOR_RESPONSE
     */
    void send_request() {
        if (state_ != IDLE) return;

        std::string input = "Client" + std::to_string(id_) + " req#" +
                           std::to_string(requests_sent_ + 1);
        uint64_t request_id = next_request_id_++;

        RequestHeader req;
        req.request_id = request_id;
        req.operation = OP_EMBEDDING;
        req.input_size = input.size();
        req.flags = 0;

        write(read_fd_, &req, sizeof(req));
        write(read_fd_, input.data(), input.size());

        pending_requests_[request_id] = std::chrono::steady_clock::now();
        requests_sent_++;
        last_send_time_ = std::chrono::steady_clock::now();
        state_ = WAITING_FOR_RESPONSE;

        std::cout << "[" << id_ << "] Sent request " << request_id
                 << " (" << requests_sent_ << "/" << total_requests_ << ")\n";
    }

    /**
     * @brief Check if this client has a response ready to process
     *
     * Non-blocking read to check for response.
     *
     * @return true if response was received and processed
     */
    bool has_response() {
        if (state_ != WAITING_FOR_RESPONSE) {
            return false;
        }

        ResponseHeader resp;
        ssize_t n = read(read_fd_, &resp, sizeof(resp));

        if (n <= 0) {
            return false;
        }

        // Read output data
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

            std::cout << "[" << id_ << "] Received response " << resp.request_id
                     << " (rtt=" << duration << "ms, proc=" << resp.processing_time_ms << "ms)\n";

            pending_requests_.erase(it);
        }

        responses_received_++;
        last_response_time_ = std::chrono::steady_clock::now();

        // Check if we should send more requests or are done
        if (requests_sent_ >= total_requests_) {
            state_ = DONE;
        } else {
            state_ = IDLE;
        }

        return true;
    }

    /**
     * @brief Check if this client is done (all requests completed)
     *
     * @return true if state_ is DONE
     */
    bool is_done() const {
        return state_ == DONE;
    }

    /**
     * @brief Get the file descriptor for monitoring responses
     *
     * @return read_fd_ for epoll monitoring
     */
    int get_read_fd() const {
        return read_fd_;
    }

    /**
     * @brief Get client ID
     *
     * @return Client's unique identifier
     */
    int get_id() const {
        return id_;
    }

    /**
     * @brief Close connection and clean up
     */
    void close() {
        if (read_fd_ >= 0) ::close(read_fd_);
        if (genai_fd_ >= 0) ::close(genai_fd_);
        read_fd_ = -1;
        genai_fd_ = -1;
    }

    /**
     * @brief Get current state as string
     *
     * @return String representation of state_
     */
    const char* get_state_string() const {
        switch (state_) {
            case NEW: return "NEW";
            case CONNECTED: return "CONNECTED";
            case IDLE: return "IDLE";
            case WAITING_FOR_RESPONSE: return "WAITING";
            case DONE: return "DONE";
            default: return "UNKNOWN";
        }
    }

private:
    int id_;                     ///< Client identifier
    Config config_;              ///< Configuration
    State state_;                ///< Current state

    int read_fd_;                ///< FD for reading responses
    int genai_fd_;               ///< FD for writing requests

    uint64_t next_request_id_;   ///< Next request ID to use
    int requests_sent_;          ///< Number of requests sent
    int total_requests_;         ///< Total requests to send
    int responses_received_;     ///< Number of responses received

    std::chrono::steady_clock::time_point last_send_time_;
    std::chrono::steady_clock::time_point last_response_time_;

    std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> pending_requests_;
};

// ============================================================================
// Main
// ============================================================================

/**
 * @brief Main entry point for event-driven GenAI demonstration
 *
 * Creates a single event loop that:
 * - Randomly adds clients over time
 * - Randomly sends requests from idle clients
 * - Monitors all client FDs for responses via epoll
 * - Prints statistics periodically
 * - Runs for a configurable duration
 *
 * @par Event Loop Flow
 *
 * 1. Check if we should add a new client (random chance)
 * 2. For each client: randomly send request if idle
 * 3. epoll_wait() with timeout for:
 *    - Client responses
 *    - Periodic tasks (add client, send request, print stats)
 * 4. Process any responses received
 * 5. Remove completed clients
 * 6. Print stats periodically
 * 7. Exit when duration elapsed or max clients completed
 *
 * @return 0 on success
 */
int main() {
    std::cout << "=== GenAI Module Event-Driven Demonstration ===\n\n";

    Config config;

    std::cout << "Configuration:\n";
    std::cout << "  GenAI workers: " << config.genai_workers << "\n";
    std::cout << "  Max clients: " << config.max_clients << "\n";
    std::cout << "  Run duration: " << config.run_duration_seconds << "s\n";
    std::cout << "  Client add probability: " << config.client_add_probability << "\n";
    std::cout << "  Request send probability: " << config.request_send_probability << "\n";
    std::cout << "  Requests per client: " << config.min_requests_per_client
             << "-" << config.max_requests_per_client << "\n\n";

    // Create and start GenAI module
    GenAIModule genai(config.genai_workers);
    genai.start();

    // Create main epoll set for monitoring client responses
    int main_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (main_epoll_fd < 0) {
        perror("epoll_create1");
        return 1;
    }

    // Clients managed by main loop
    std::vector<Client*> clients;
    int next_client_id = 1;
    int total_clients_created = 0;
    int total_clients_completed = 0;

    // Statistics
    uint64_t total_requests_sent = 0;
    uint64_t total_responses_received = 0;
    auto last_stats_time = std::chrono::steady_clock::now();

    // Random number generation
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);

    auto start_time = std::chrono::steady_clock::now();

    std::cout << "=== Starting Event Loop ===\n\n";

    bool running = true;
    while (running) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - start_time).count();

        // Check termination conditions
        bool all_work_done = (total_clients_created >= config.max_clients) &&
                             (clients.empty()) &&
                             (total_clients_completed >= config.max_clients);

        if (all_work_done) {
            std::cout << "\n=== All work completed, shutting down early ===\n";
            running = false;
            break;
        }

        if (elapsed >= config.run_duration_seconds) {
            std::cout << "\n=== Time elapsed, shutting down ===\n";
            running = false;
            break;
        }

        // --------------------------------------------------------
        // 1. Randomly add new clients
        // --------------------------------------------------------
        if (clients.size() < static_cast<size_t>(config.max_clients) &&
            total_clients_created < config.max_clients &&
            dis(gen) < config.client_add_probability) {

            Client* client = new Client(next_client_id++, config);
            client->connect(genai);

            // Add to main epoll for monitoring responses
            struct epoll_event ev;
            ev.events = EPOLLIN;
            ev.data.ptr = client;
            if (epoll_ctl(main_epoll_fd, EPOLL_CTL_ADD, client->get_read_fd(), &ev) < 0) {
                perror("epoll_ctl client");
                delete client;
            } else {
                clients.push_back(client);
                total_clients_created++;
            }
        }

        // --------------------------------------------------------
        // 2. Randomly send requests from idle clients
        // --------------------------------------------------------
        for (auto* client : clients) {
            if (client->can_send_request() && dis(gen) < config.request_send_probability) {
                client->send_request();
                total_requests_sent++;
            }
        }

        // --------------------------------------------------------
        // 3. Wait for events (responses or timeout)
        // --------------------------------------------------------
        const int MAX_EVENTS = 64;
        struct epoll_event events[MAX_EVENTS];

        int timeout_ms = 100;  // 100ms timeout for periodic checks
        int nfds = epoll_wait(main_epoll_fd, events, MAX_EVENTS, timeout_ms);

        // --------------------------------------------------------
        // 4. Process responses
        // --------------------------------------------------------
        for (int i = 0; i < nfds; i++) {
            Client* client = static_cast<Client*>(events[i].data.ptr);

            if (client->has_response()) {
                total_responses_received++;

                if (client->is_done()) {
                    // Remove from epoll
                    epoll_ctl(main_epoll_fd, EPOLL_CTL_DEL, client->get_read_fd(), nullptr);

                    // Remove from clients vector
                    clients.erase(
                        std::remove(clients.begin(), clients.end(), client),
                        clients.end()
                    );

                    std::cout << "[" << client->get_id() << "] Completed all requests, removing\n";

                    client->close();
                    delete client;
                    total_clients_completed++;
                }
            }
        }

        // --------------------------------------------------------
        // 5. Print statistics periodically
        // --------------------------------------------------------
        auto time_since_last_stats = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_stats_time).count();

        if (time_since_last_stats >= config.stats_print_interval_ms) {
            std::cout << "\n[STATS] T+" << elapsed << "s "
                     << "| Active clients: " << clients.size()
                     << " | Queue depth: " << genai.get_queue_size()
                     << " | Requests sent: " << total_requests_sent
                     << " | Responses: " << total_responses_received
                     << " | Completed: " << total_clients_completed << "\n";

            // Show state distribution
            std::unordered_map<const char*, int> state_counts;
            for (auto* client : clients) {
                state_counts[client->get_state_string()]++;
            }
            std::cout << "        States: ";
            for (auto& [state, count] : state_counts) {
                std::cout << state << "=" << count << " ";
            }
            std::cout << "\n\n";

            last_stats_time = now;
        }
    }

    // ------------------------------------------------------------
    // Final statistics
    // ------------------------------------------------------------
    std::cout << "\n=== Final Statistics ===\n";
    std::cout << "Total clients created: " << total_clients_created << "\n";
    std::cout << "Total clients completed: " << total_clients_completed << "\n";
    std::cout << "Total requests sent: " << total_requests_sent << "\n";
    std::cout << "Total responses received: " << total_responses_received << "\n";

    // Clean up remaining clients
    for (auto* client : clients) {
        epoll_ctl(main_epoll_fd, EPOLL_CTL_DEL, client->get_read_fd(), nullptr);
        client->close();
        delete client;
    }
    clients.clear();

    close(main_epoll_fd);

    // Stop GenAI module
    std::cout << "\nStopping GenAI module...\n";
    genai.stop();

    std::cout << "\n=== Demonstration Complete ===\n";

    return 0;
}
