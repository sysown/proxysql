/**
 * @file genai_demo_event.cpp
 * @brief Event-driven GenAI module POC with real llama-server integration
 *
 * This POC demonstrates the GenAI module architecture with:
 * - Shared memory communication (passing pointers, not copying data)
 * - Real embedding generation via llama-server HTTP API
 * - Real reranking via llama-server HTTP API
 * - Support for single or multiple documents per request
 * - libcurl-based HTTP client for API calls
 *
 * @par Architecture
 *
 * Client and GenAI module share the same process memory space.
 * Documents and results are passed by pointer to avoid copying.
 *
 * @par Embedding Request Flow
 *
 * 1. Client allocates document(s) in its own memory
 * 2. Client sends request with document pointers to GenAI
 * 3. GenAI reads document pointers and accesses shared memory
 * 4. GenAI calls llama-server via HTTP to get embeddings
 * 5. GenAI allocates embedding result and passes pointer back to client
 * 6. Client reads embedding from shared memory and displays length
 *
 * @par Rerank Request Flow
 *
 * 1. Client allocates query and document(s) in its own memory
 * 2. Client sends request with query pointer and document pointers to GenAI
 * 3. GenAI reads pointers and accesses shared memory
 * 4. GenAI calls llama-server via HTTP to get rerank results
 * 5. GenAI allocates rerank result array and passes pointer back to client
 * 6. Client reads results (index, score) from shared memory
 *
 * @author ProxySQL Team
 * @date 2025-01-09
 * @version 3.1 - POC with embeddings and reranking
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
#include <memory>
#include <curl/curl.h>
#include <sstream>
#include <iomanip>

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
 * @enum Operation
 * @brief GenAI operation types
 */
enum Operation : uint32_t {
    OP_EMBEDDING = 0,  ///< Generate embeddings for documents
    OP_COMPLETION = 1, ///< Text completion (future)
    OP_RERANK = 2,     ///< Rerank documents by relevance to query
};

/**
 * @struct Document
 * @brief Document structure passed by pointer (shared memory)
 *
 * Client allocates this structure and passes its pointer to GenAI.
 * GenAI reads the document directly from shared memory.
 */
struct Document {
    const char* text;  ///< Pointer to document text (owned by client)
    size_t text_size;  ///< Length of text in bytes

    Document() : text(nullptr), text_size(0) {}

    Document(const char* t, size_t s) : text(t), text_size(s) {}
};

/**
 * @struct RequestHeader
 * @brief Header for GenAI requests
 *
 * For embedding requests: client sends document_count pointers to Document structures (as uint64_t).
 * For rerank requests: client sends query (as null-terminated string), then document_count pointers.
 */
struct RequestHeader {
    uint64_t request_id;      ///< Client's correlation ID
    uint32_t operation;       ///< Operation type (OP_EMBEDDING, OP_RERANK, etc.)
    uint32_t document_count;  ///< Number of documents (1 or more)
    uint32_t flags;           ///< Reserved for future use
    uint32_t top_n;           ///< For rerank: number of top results to return
};

/**
 * @struct EmbeddingResult
 * @brief Single embedding vector allocated by GenAI, read by client
 *
 * GenAI allocates this and passes the pointer to client.
 * Client reads the embedding and then frees it.
 */
struct EmbeddingResult {
    float* data;      ///< Pointer to embedding vector (owned by GenAI initially)
    size_t size;      ///< Number of floats in the embedding

    EmbeddingResult() : data(nullptr), size(0) {}

    ~EmbeddingResult() {
        if (data) {
            delete[] data;
            data = nullptr;
        }
    }

    // Move constructor and assignment
    EmbeddingResult(EmbeddingResult&& other) noexcept
        : data(other.data), size(other.size) {
        other.data = nullptr;
        other.size = 0;
    }

    EmbeddingResult& operator=(EmbeddingResult&& other) noexcept {
        if (this != &other) {
            if (data) delete[] data;
            data = other.data;
            size = other.size;
            other.data = nullptr;
            other.size = 0;
        }
        return *this;
    }

    // Disable copy
    EmbeddingResult(const EmbeddingResult&) = delete;
    EmbeddingResult& operator=(const EmbeddingResult&) = delete;
};

/**
 * @struct BatchEmbeddingResult
 * @brief Multiple embedding vectors allocated by GenAI, read by client
 *
 * For batch requests, GenAI allocates an array of embeddings.
 * The embeddings are stored contiguously: [emb1 floats, emb2 floats, ...]
 * Each embedding has the same size.
 */
struct BatchEmbeddingResult {
    float* data;           ///< Pointer to contiguous embedding array (owned by GenAI initially)
    size_t embedding_size; ///< Number of floats per embedding
    size_t count;          ///< Number of embeddings

    BatchEmbeddingResult() : data(nullptr), embedding_size(0), count(0) {}

    ~BatchEmbeddingResult() {
        if (data) {
            delete[] data;
            data = nullptr;
        }
    }

    // Move constructor and assignment
    BatchEmbeddingResult(BatchEmbeddingResult&& other) noexcept
        : data(other.data), embedding_size(other.embedding_size), count(other.count) {
        other.data = nullptr;
        other.embedding_size = 0;
        other.count = 0;
    }

    BatchEmbeddingResult& operator=(BatchEmbeddingResult&& other) noexcept {
        if (this != &other) {
            if (data) delete[] data;
            data = other.data;
            embedding_size = other.embedding_size;
            count = other.count;
            other.data = nullptr;
            other.embedding_size = 0;
            other.count = 0;
        }
        return *this;
    }

    // Disable copy
    BatchEmbeddingResult(const BatchEmbeddingResult&) = delete;
    BatchEmbeddingResult& operator=(const BatchEmbeddingResult&) = delete;

    size_t total_floats() const { return embedding_size * count; }
};

/**
 * @struct RerankResult
 * @brief Single rerank result with index and relevance score
 *
 * Represents one document's rerank result.
 * Allocated by GenAI, passed to client via shared memory.
 */
struct RerankResult {
    uint32_t index;  ///< Original document index
    float score;     ///< Relevance score (higher is better)
};

/**
 * @struct RerankResultArray
 * @brief Array of rerank results allocated by GenAI
 *
 * For rerank requests, GenAI allocates an array of RerankResult.
 * Client takes ownership and must free the array.
 */
struct RerankResultArray {
    RerankResult* data;  ///< Pointer to result array (owned by GenAI initially)
    size_t count;         ///< Number of results

    RerankResultArray() : data(nullptr), count(0) {}

    ~RerankResultArray() {
        if (data) {
            delete[] data;
            data = nullptr;
        }
    }

    // Move constructor and assignment
    RerankResultArray(RerankResultArray&& other) noexcept
        : data(other.data), count(other.count) {
        other.data = nullptr;
        other.count = 0;
    }

    RerankResultArray& operator=(RerankResultArray&& other) noexcept {
        if (this != &other) {
            if (data) delete[] data;
            data = other.data;
            count = other.count;
            other.data = nullptr;
            other.count = 0;
        }
        return *this;
    }

    // Disable copy
    RerankResultArray(const RerankResultArray&) = delete;
    RerankResultArray& operator=(const RerankResultArray&) = delete;
};

/**
 * @struct ResponseHeader
 * @brief Header for GenAI responses
 *
 * For embeddings: passes pointer to BatchEmbeddingResult as uint64_t.
 * For rerank: passes pointer to RerankResultArray as uint64_t.
 */
struct ResponseHeader {
    uint64_t request_id;        ///< Echo client's request ID
    uint32_t status_code;       ///< 0=success, >0=error
    uint32_t embedding_size;    ///< For embeddings: floats per embedding
    uint32_t processing_time_ms;///< Time taken to process
    uint64_t result_ptr;        ///< Pointer to result data (as uint64_t)
    uint32_t result_count;      ///< Number of results (embeddings or rerank results)
    uint32_t data_size;         ///< Additional data size (for future use)
};

// ============================================================================
// GenAI Module
// ============================================================================

/**
 * @class GenAIModule
 * @brief Thread-pool based GenAI processing module with real embedding support
 *
 * This module provides embedding generation via llama-server HTTP API.
 * It uses a thread pool with epoll-based listener for async processing.
 */
class GenAIModule {
public:
    /**
     * @struct Request
     * @brief Internal request representation
     */
    struct Request {
        int client_fd;
        uint64_t request_id;
        uint32_t operation;
        std::string query;                 ///< Query text (for rerank)
        uint32_t top_n;                    ///< Number of top results (for rerank)
        std::vector<Document> documents;   ///< Document pointers from shared memory
    };

    GenAIModule(int num_workers = 4)
        : num_workers_(num_workers), running_(false) {

        // Initialize libcurl
        curl_global_init(CURL_GLOBAL_ALL);
    }

    ~GenAIModule() {
        if (running_) {
            stop();
        }
        curl_global_cleanup();
    }

    /**
     * @brief Start the GenAI module (spawn threads)
     */
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
        std::cout << "[GenAI] Embedding endpoint: http://127.0.0.1:8013/embedding\n";
        std::cout << "[GenAI] Rerank endpoint: http://127.0.0.1:8012/rerank\n";
    }

    /**
     * @brief Register a client file descriptor with GenAI
     *
     * @param client_fd File descriptor to monitor (from socketpair)
     */
    void register_client(int client_fd) {
        std::lock_guard<std::mutex> lock(clients_mutex_);

        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = client_fd;
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            perror("epoll_ctl add client");
            return;
        }

        client_fds_.insert(client_fd);
    }

    /**
     * @brief Stop the GenAI module
     */
    void stop() {
        running_ = false;

        uint64_t value = 1;
        write(event_fd_, &value, sizeof(value));

        queue_cv_.notify_all();

        for (auto& t : worker_threads_) {
            if (t.joinable()) t.join();
        }

        if (listener_thread_.joinable()) {
            listener_thread_.join();
        }

        close(event_fd_);
        close(epoll_fd_);

        std::cout << "[GenAI] Module stopped\n";
    }

    /**
     * @brief Get current queue depth (for statistics)
     */
    size_t get_queue_size() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return request_queue_.size();
    }

private:
    /**
     * @brief Listener loop - reads requests from clients via epoll
     */
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

                // For rerank operations, read the query first
                std::string query;
                if (header.operation == OP_RERANK) {
                    // Read query as null-terminated string
                    char ch;
                    while (true) {
                        ssize_t r = read(client_fd, &ch, 1);
                        if (r <= 0) break;
                        if (ch == '\0') break;  // Null terminator
                        query += ch;
                    }
                }

                // Read document pointers (passed as uint64_t)
                std::vector<uint64_t> doc_ptrs(header.document_count);
                size_t total_read = 0;
                while (total_read < header.document_count * sizeof(uint64_t)) {
                    ssize_t r = read(client_fd,
                                   (char*)doc_ptrs.data() + total_read,
                                   header.document_count * sizeof(uint64_t) - total_read);
                    if (r <= 0) break;
                    total_read += r;
                }

                // Build request with document pointers (shared memory)
                Request req;
                req.client_fd = client_fd;
                req.request_id = header.request_id;
                req.operation = header.operation;
                req.query = query;
                req.top_n = header.top_n;
                req.documents.reserve(header.document_count);

                for (uint32_t i = 0; i < header.document_count; i++) {
                    Document* doc = reinterpret_cast<Document*>(doc_ptrs[i]);
                    if (doc && doc->text) {
                        req.documents.push_back(*doc);
                    }
                }

                {
                    std::lock_guard<std::mutex> lock(queue_mutex_);
                    request_queue_.push(std::move(req));
                }

                queue_cv_.notify_one();
            }
        }
    }

    /**
     * @brief Callback function for libcurl to handle HTTP response
     */
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t totalSize = size * nmemb;
        std::string* response = static_cast<std::string*>(userp);
        response->append(static_cast<char*>(contents), totalSize);
        return totalSize;
    }

    /**
     * @brief Call llama-server embedding API via libcurl
     *
     * @param text Document text to embed
     * @return EmbeddingResult containing the embedding vector
     */
    EmbeddingResult call_llama_embedding(const std::string& text) {
        EmbeddingResult result;
        CURL* curl = curl_easy_init();

        if (!curl) {
            std::cerr << "[Worker] Failed to initialize curl\n";
            return result;
        }

        // Build JSON request
        std::stringstream json;
        json << "{\"input\":\"";

        // Escape JSON special characters
        for (char c : text) {
            switch (c) {
                case '"':  json << "\\\""; break;
                case '\\': json << "\\\\"; break;
                case '\n': json << "\\n"; break;
                case '\r': json << "\\r"; break;
                case '\t': json << "\\t"; break;
                default:   json << c; break;
            }
        }

        json << "\"}";

        std::string json_str = json.str();

        // Configure curl
        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8013/embedding");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

        std::string response_data;
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

        // Add content-type header
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Perform request
        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "[Worker] curl_easy_perform() failed: "
                     << curl_easy_strerror(res) << "\n";
        } else {
            // Parse JSON response to extract embedding
            // Response format: [{"index":0,"embedding":[0.1,0.2,...]}]
            size_t embedding_pos = response_data.find("\"embedding\":");
            if (embedding_pos != std::string::npos) {
                // Find the array start
                size_t array_start = response_data.find("[", embedding_pos);
                if (array_start != std::string::npos) {
                    // Find matching bracket
                    size_t array_end = array_start;
                    int bracket_count = 0;
                    bool in_array = false;

                    for (size_t i = array_start; i < response_data.size(); i++) {
                        if (response_data[i] == '[') {
                            bracket_count++;
                            in_array = true;
                        } else if (response_data[i] == ']') {
                            bracket_count--;
                            if (bracket_count == 0 && in_array) {
                                array_end = i;
                                break;
                            }
                        }
                    }

                    // Parse the array of floats
                    std::string array_str = response_data.substr(array_start + 1, array_end - array_start - 1);
                    std::vector<float> embedding;
                    std::stringstream ss(array_str);
                    std::string token;

                    while (std::getline(ss, token, ',')) {
                        // Remove whitespace and "null" values
                        token.erase(0, token.find_first_not_of(" \t\n\r"));
                        token.erase(token.find_last_not_of(" \t\n\r") + 1);

                        if (token == "null" || token.empty()) {
                            continue;
                        }

                        try {
                            float val = std::stof(token);
                            embedding.push_back(val);
                        } catch (...) {
                            // Skip invalid values
                        }
                    }

                    if (!embedding.empty()) {
                        result.size = embedding.size();
                        result.data = new float[embedding.size()];
                        std::copy(embedding.begin(), embedding.end(), result.data);
                    }
                }
            }
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        return result;
    }

    /**
     * @brief Call llama-server batch embedding API via libcurl
     *
     * @param texts Vector of document texts to embed
     * @return BatchEmbeddingResult containing multiple embedding vectors
     */
    BatchEmbeddingResult call_llama_batch_embedding(const std::vector<std::string>& texts) {
        BatchEmbeddingResult result;
        CURL* curl = curl_easy_init();

        if (!curl) {
            std::cerr << "[Worker] Failed to initialize curl\n";
            return result;
        }

        // Build JSON request with array of inputs
        std::stringstream json;
        json << "{\"input\":[";

        for (size_t i = 0; i < texts.size(); i++) {
            if (i > 0) json << ",";
            json << "\"";

            // Escape JSON special characters
            for (char c : texts[i]) {
                switch (c) {
                    case '"':  json << "\\\""; break;
                    case '\\': json << "\\\\"; break;
                    case '\n': json << "\\n"; break;
                    case '\r': json << "\\r"; break;
                    case '\t': json << "\\t"; break;
                    default:   json << c; break;
                }
            }

            json << "\"";
        }

        json << "]}";

        std::string json_str = json.str();

        // Configure curl
        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8013/embedding");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

        std::string response_data;
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

        // Add content-type header
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Perform request
        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "[Worker] curl_easy_perform() failed: "
                     << curl_easy_strerror(res) << "\n";
        } else {
            // Parse JSON response to extract embeddings
            // Response format: [{"index":0,"embedding":[[float1,float2,...]]}, {"index":1,...}]
            std::vector<std::vector<float>> all_embeddings;

            // Find all result objects by looking for "embedding":
            size_t pos = 0;
            while ((pos = response_data.find("\"embedding\":", pos)) != std::string::npos) {
                // Find the array start (expecting nested [[...]])
                size_t array_start = response_data.find("[", pos);
                if (array_start == std::string::npos) break;

                // Skip the first [ to find the inner array
                size_t inner_start = array_start + 1;
                if (inner_start >= response_data.size() || response_data[inner_start] != '[') {
                    // Not a nested array, use first bracket
                    inner_start = array_start;
                }

                // Find matching bracket for the inner array
                size_t array_end = inner_start;
                int bracket_count = 0;
                bool in_array = false;

                for (size_t i = inner_start; i < response_data.size(); i++) {
                    if (response_data[i] == '[') {
                        bracket_count++;
                        in_array = true;
                    } else if (response_data[i] == ']') {
                        bracket_count--;
                        if (bracket_count == 0 && in_array) {
                            array_end = i;
                            break;
                        }
                    }
                }

                // Parse the array of floats
                std::string array_str = response_data.substr(inner_start + 1, array_end - inner_start - 1);
                std::vector<float> embedding;
                std::stringstream ss(array_str);
                std::string token;

                while (std::getline(ss, token, ',')) {
                    // Remove whitespace and "null" values
                    token.erase(0, token.find_first_not_of(" \t\n\r"));
                    token.erase(token.find_last_not_of(" \t\n\r") + 1);

                    if (token == "null" || token.empty()) {
                        continue;
                    }

                    try {
                        float val = std::stof(token);
                        embedding.push_back(val);
                    } catch (...) {
                        // Skip invalid values
                    }
                }

                if (!embedding.empty()) {
                    all_embeddings.push_back(std::move(embedding));
                }

                // Move past this result
                pos = array_end + 1;
            }

            // Convert to contiguous array
            if (!all_embeddings.empty()) {
                result.count = all_embeddings.size();
                result.embedding_size = all_embeddings[0].size();

                // Allocate contiguous array
                size_t total_floats = result.embedding_size * result.count;
                result.data = new float[total_floats];

                // Copy embeddings
                for (size_t i = 0; i < all_embeddings.size(); i++) {
                    size_t offset = i * result.embedding_size;
                    const auto& emb = all_embeddings[i];
                    std::copy(emb.begin(), emb.end(), result.data + offset);
                }
            }
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        return result;
    }

    /**
     * @brief Call llama-server rerank API via libcurl
     *
     * @param query Query string to rerank against
     * @param texts Vector of document texts to rerank
     * @param top_n Maximum number of results to return
     * @return RerankResultArray containing top N results with index and score
     */
    RerankResultArray call_llama_rerank(const std::string& query,
                                        const std::vector<std::string>& texts,
                                        uint32_t top_n) {
        RerankResultArray result;
        CURL* curl = curl_easy_init();

        if (!curl) {
            std::cerr << "[Worker] Failed to initialize curl\n";
            return result;
        }

        // Build JSON request
        std::stringstream json;
        json << "{\"query\":\"";

        // Escape query JSON special characters
        for (char c : query) {
            switch (c) {
                case '"':  json << "\\\""; break;
                case '\\': json << "\\\\"; break;
                case '\n': json << "\\n"; break;
                case '\r': json << "\\r"; break;
                case '\t': json << "\\t"; break;
                default:   json << c; break;
            }
        }

        json << "\",\"documents\":[";

        // Add documents
        for (size_t i = 0; i < texts.size(); i++) {
            if (i > 0) json << ",";
            json << "\"";

            // Escape document JSON special characters
            for (char c : texts[i]) {
                switch (c) {
                    case '"':  json << "\\\""; break;
                    case '\\': json << "\\\\"; break;
                    case '\n': json << "\\n"; break;
                    case '\r': json << "\\r"; break;
                    case '\t': json << "\\t"; break;
                    default:   json << c; break;
                }
            }

            json << "\"";
        }

        json << "]}";

        std::string json_str = json.str();

        // Configure curl
        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8012/rerank");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

        std::string response_data;
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

        // Add content-type header
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Perform request
        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "[Worker] curl_easy_perform() failed: "
                     << curl_easy_strerror(res) << "\n";
        } else {
            // Parse JSON response to extract rerank results
            // Response format: {"results": [{"index": 0, "relevance_score": 0.95}, ...]}
            size_t results_pos = response_data.find("\"results\":");
            if (results_pos != std::string::npos) {
                // Find the array start
                size_t array_start = response_data.find("[", results_pos);
                if (array_start != std::string::npos) {
                    // Find matching bracket
                    size_t array_end = array_start;
                    int bracket_count = 0;
                    bool in_array = false;

                    for (size_t i = array_start; i < response_data.size(); i++) {
                        if (response_data[i] == '[') {
                            bracket_count++;
                            in_array = true;
                        } else if (response_data[i] == ']') {
                            bracket_count--;
                            if (bracket_count == 0 && in_array) {
                                array_end = i;
                                break;
                            }
                        }
                    }

                    // Parse each result object
                    std::string array_str = response_data.substr(array_start + 1, array_end - array_start - 1);
                    std::vector<RerankResult> results;

                    // Simple parsing - look for "index" and "relevance_score" patterns
                    size_t pos = 0;
                    while (pos < array_str.size()) {
                        size_t index_pos = array_str.find("\"index\":", pos);
                        if (index_pos == std::string::npos) break;

                        // Skip to the number
                        size_t num_start = index_pos + 8;  // Skip "\"index\":"
                        while (num_start < array_str.size() &&
                               (array_str[num_start] == ' ' || array_str[num_start] == '\t')) {
                            num_start++;
                        }

                        // Find the end of the number
                        size_t num_end = num_start;
                        while (num_end < array_str.size() &&
                               (isdigit(array_str[num_end]) || array_str[num_end] == '-')) {
                            num_end++;
                        }

                        uint32_t index = 0;
                        if (num_start < num_end) {
                            try {
                                index = std::stoul(array_str.substr(num_start, num_end - num_start));
                            } catch (...) {}
                        }

                        // Find relevance_score
                        size_t score_pos = array_str.find("\"relevance_score\":", index_pos);
                        if (score_pos == std::string::npos) break;

                        // Skip to the number
                        size_t score_start = score_pos + 18;  // Skip "\"relevance_score\":"
                        while (score_start < array_str.size() &&
                               (array_str[score_start] == ' ' || array_str[score_start] == '\t')) {
                            score_start++;
                        }

                        // Find the end of the number (including decimal point and negative sign)
                        size_t score_end = score_start;
                        while (score_end < array_str.size() &&
                               (isdigit(array_str[score_end]) ||
                                array_str[score_end] == '.' ||
                                array_str[score_end] == '-' ||
                                array_str[score_end] == 'e' ||
                                array_str[score_end] == 'E')) {
                            score_end++;
                        }

                        float score = 0.0f;
                        if (score_start < score_end) {
                            try {
                                score = std::stof(array_str.substr(score_start, score_end - score_start));
                            } catch (...) {}
                        }

                        results.push_back({index, score});
                        pos = score_end + 1;
                    }

                    // Limit to top_n results
                    if (!results.empty() && top_n > 0) {
                        size_t count = std::min(static_cast<size_t>(top_n), results.size());
                        result.count = count;
                        result.data = new RerankResult[count];
                        std::copy(results.begin(), results.begin() + count, result.data);
                    }
                }
            }
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        return result;
    }

    /**
     * @brief Worker loop - processes requests from queue
     */
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

            auto start_time = std::chrono::steady_clock::now();

            // Process based on operation type
            if (req.operation == OP_EMBEDDING) {
                if (!req.documents.empty()) {
                    // Prepare texts for batch embedding
                    std::vector<std::string> texts;
                    texts.reserve(req.documents.size());
                    size_t total_bytes = 0;

                    for (const auto& doc : req.documents) {
                        texts.emplace_back(doc.text, doc.text_size);
                        total_bytes += doc.text_size;
                    }

                    std::cout << "[Worker " << worker_id << "] Processing batch embedding for "
                             << req.documents.size() << " document(s) (" << total_bytes << " bytes)\n";

                    // Use batch embedding for all documents
                    BatchEmbeddingResult batch_embedding = call_llama_batch_embedding(texts);

                    auto end_time = std::chrono::steady_clock::now();
                    int processing_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        end_time - start_time).count();

                    // Prepare response
                    ResponseHeader resp;
                    resp.request_id = req.request_id;
                    resp.status_code = (batch_embedding.data != nullptr) ? 0 : 1;
                    resp.embedding_size = batch_embedding.embedding_size;
                    resp.processing_time_ms = processing_time_ms;
                    resp.result_ptr = reinterpret_cast<uint64_t>(batch_embedding.data);
                    resp.result_count = batch_embedding.count;
                    resp.data_size = 0;

                    // Send response header
                    write(req.client_fd, &resp, sizeof(resp));

                    // The batch embedding data stays in shared memory (allocated by GenAI)
                    // Client will read it and then take ownership (client must free it)
                    batch_embedding.data = nullptr;  // Transfer ownership to client
                } else {
                    // No documents
                    auto end_time = std::chrono::steady_clock::now();
                    int processing_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        end_time - start_time).count();

                    ResponseHeader resp;
                    resp.request_id = req.request_id;
                    resp.status_code = 1;  // Error
                    resp.embedding_size = 0;
                    resp.processing_time_ms = processing_time_ms;
                    resp.result_ptr = 0;
                    resp.result_count = 0;
                    resp.data_size = 0;

                    write(req.client_fd, &resp, sizeof(resp));
                }
            } else if (req.operation == OP_RERANK) {
                if (!req.documents.empty() && !req.query.empty()) {
                    // Prepare texts for reranking
                    std::vector<std::string> texts;
                    texts.reserve(req.documents.size());
                    size_t total_bytes = 0;

                    for (const auto& doc : req.documents) {
                        texts.emplace_back(doc.text, doc.text_size);
                        total_bytes += doc.text_size;
                    }

                    std::cout << "[Worker " << worker_id << "] Processing rerank for "
                             << req.documents.size() << " document(s), query=\""
                             << req.query.substr(0, 50)
                             << (req.query.size() > 50 ? "..." : "")
                             << "\" (" << total_bytes << " bytes)\n";

                    // Call rerank API
                    RerankResultArray rerank_results = call_llama_rerank(req.query, texts, req.top_n);

                    auto end_time = std::chrono::steady_clock::now();
                    int processing_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        end_time - start_time).count();

                    // Prepare response
                    ResponseHeader resp;
                    resp.request_id = req.request_id;
                    resp.status_code = (rerank_results.data != nullptr) ? 0 : 1;
                    resp.embedding_size = 0;  // Not used for rerank
                    resp.processing_time_ms = processing_time_ms;
                    resp.result_ptr = reinterpret_cast<uint64_t>(rerank_results.data);
                    resp.result_count = rerank_results.count;
                    resp.data_size = 0;

                    // Send response header
                    write(req.client_fd, &resp, sizeof(resp));

                    // The rerank results stay in shared memory (allocated by GenAI)
                    // Client will read them and then take ownership (client must free it)
                    rerank_results.data = nullptr;  // Transfer ownership to client
                } else {
                    // No documents or query
                    auto end_time = std::chrono::steady_clock::now();
                    int processing_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        end_time - start_time).count();

                    ResponseHeader resp;
                    resp.request_id = req.request_id;
                    resp.status_code = 1;  // Error
                    resp.embedding_size = 0;
                    resp.processing_time_ms = processing_time_ms;
                    resp.result_ptr = 0;
                    resp.result_count = 0;
                    resp.data_size = 0;

                    write(req.client_fd, &resp, sizeof(resp));
                }
            } else {
                // Unknown operation
                auto end_time = std::chrono::steady_clock::now();
                int processing_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    end_time - start_time).count();

                ResponseHeader resp;
                resp.request_id = req.request_id;
                resp.status_code = 1;  // Error
                resp.embedding_size = 0;
                resp.processing_time_ms = processing_time_ms;
                resp.result_ptr = 0;
                resp.result_count = 0;
                resp.data_size = 0;

                write(req.client_fd, &resp, sizeof(resp));
            }
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
 * @brief Configuration for the GenAI event-driven demo
 */
struct Config {
    int genai_workers = 8;
    int max_clients = 20;
    int run_duration_seconds = 60;
    double client_add_probability = 0.15;
    double request_send_probability = 0.20;
    int min_documents_per_request = 1;
    int max_documents_per_request = 10;
    int stats_print_interval_ms = 2000;
};

// ============================================================================
// Sample Documents
// ============================================================================

/**
 * @brief Sample documents for testing embeddings
 */
const std::vector<std::string> SAMPLE_DOCUMENTS = {
    "The quick brown fox jumps over the lazy dog. This is a classic sentence that contains all letters of the alphabet.",
    "Machine learning is a subset of artificial intelligence that enables systems to learn from data.",
    "Embeddings convert text into numerical vectors that capture semantic meaning.",
    "Natural language processing has revolutionized how computers understand human language.",
    "Vector databases store embeddings for efficient similarity search and retrieval.",
    "Transformers have become the dominant architecture for modern natural language processing tasks.",
    "Large language models demonstrate remarkable capabilities in text generation and comprehension.",
    "Semantic search uses embeddings to find content based on meaning rather than keyword matching.",
    "Neural networks learn complex patterns through interconnected layers of artificial neurons.",
    "Convolutional neural networks excel at image recognition and computer vision tasks.",
    "Recurrent neural networks can process sequential data like text and time series.",
    "Attention mechanisms allow models to focus on relevant parts of the input.",
    "Transfer learning enables models trained on one task to be applied to related tasks.",
    "Gradient descent is the fundamental optimization algorithm for training neural networks.",
    "Backpropagation efficiently computes gradients by propagating errors backward through the network.",
    "Regularization techniques like dropout prevent overfitting in deep learning models.",
    "Batch normalization stabilizes training by normalizing layer inputs.",
    "Learning rate schedules adjust the step size during optimization for better convergence.",
    "Tokenization breaks text into smaller units for processing by language models.",
    "Word embeddings like Word2Vec capture semantic relationships between words.",
    "Contextual embeddings like BERT generate representations based on surrounding context.",
    "Sequence-to-sequence models are used for translation and text summarization.",
    "Beam search improves output quality in text generation by considering multiple candidates.",
    "Temperature controls randomness in probabilistic sampling for language model outputs.",
    "Fine-tuning adapts pre-trained models to specific tasks with limited data."
};

/**
 * @brief Sample queries for testing reranking
 */
const std::vector<std::string> SAMPLE_QUERIES = {
    "What is machine learning?",
    "How do neural networks work?",
    "Explain embeddings and vectors",
    "What is transformers architecture?",
    "How does attention mechanism work?",
    "What is backpropagation?",
    "Explain natural language processing"
};

/**
 * @class Client
 * @brief Client that sends embedding and rerank requests to GenAI module
 *
 * The client allocates documents and passes pointers to GenAI (shared memory).
 * Client waits for response before sending next request (ensures memory validity).
 */
class Client {
public:
    enum State {
        NEW,
        CONNECTED,
        IDLE,
        WAITING_FOR_RESPONSE,
        DONE
    };

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
          owned_embedding_(nullptr),
          owned_rerank_results_(nullptr) {

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(
            config_.min_documents_per_request,
            config_.max_documents_per_request
        );
        total_requests_ = dist(gen);
    }

    ~Client() {
        close();
        // Clean up any owned embedding
        if (owned_embedding_) {
            delete[] owned_embedding_;
        }
        // Clean up any owned rerank results
        if (owned_rerank_results_) {
            delete[] owned_rerank_results_;
        }
    }

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

        state_ = IDLE;

        std::cout << "[" << id_ << "] Connected (will send "
                 << total_requests_ << " requests)\n";
    }

    bool can_send_request() const {
        return state_ == IDLE;
    }

    void send_request() {
        if (state_ != IDLE) return;

        std::random_device rd;
        std::mt19937 gen(rd());

        // Randomly choose between embedding and rerank (30% chance of rerank)
        std::uniform_real_distribution<> op_dist(0.0, 1.0);
        bool use_rerank = op_dist(gen) < 0.3;

        // Allocate documents for this request (owned by client until response)
        current_documents_.clear();

        std::uniform_int_distribution<> doc_dist(0, SAMPLE_DOCUMENTS.size() - 1);
        std::uniform_int_distribution<> count_dist(
            config_.min_documents_per_request,
            config_.max_documents_per_request
        );

        int num_docs = count_dist(gen);
        for (int i = 0; i < num_docs; i++) {
            const std::string& sample_text = SAMPLE_DOCUMENTS[doc_dist(gen)];
            current_documents_.push_back(Document(sample_text.c_str(), sample_text.size()));
        }

        uint64_t request_id = next_request_id_++;

        if (use_rerank && !SAMPLE_QUERIES.empty()) {
            // Send rerank request
            std::uniform_int_distribution<> query_dist(0, SAMPLE_QUERIES.size() - 1);
            const std::string& query = SAMPLE_QUERIES[query_dist(gen)];
            uint32_t top_n = 3 + (gen() % 3);  // 3-5 results

            RequestHeader req;
            req.request_id = request_id;
            req.operation = OP_RERANK;
            req.document_count = current_documents_.size();
            req.flags = 0;
            req.top_n = top_n;

            // Send request header
            write(read_fd_, &req, sizeof(req));

            // Send query as null-terminated string
            write(read_fd_, query.c_str(), query.size() + 1);  // +1 for null terminator

            // Send document pointers (as uint64_t)
            std::vector<uint64_t> doc_ptrs;
            doc_ptrs.reserve(current_documents_.size());
            for (const auto& doc : current_documents_) {
                doc_ptrs.push_back(reinterpret_cast<uint64_t>(&doc));
            }
            write(read_fd_, doc_ptrs.data(), doc_ptrs.size() * sizeof(uint64_t));

            pending_requests_[request_id] = std::chrono::steady_clock::now();
            requests_sent_++;
            state_ = WAITING_FOR_RESPONSE;

            std::cout << "[" << id_ << "] Sent RERANK request " << request_id
                     << " with " << current_documents_.size() << " document(s), top_n=" << top_n
                     << " (" << requests_sent_ << "/" << total_requests_ << ")\n";
        } else {
            // Send embedding request
            RequestHeader req;
            req.request_id = request_id;
            req.operation = OP_EMBEDDING;
            req.document_count = current_documents_.size();
            req.flags = 0;
            req.top_n = 0;  // Not used for embedding

            // Send request header
            write(read_fd_, &req, sizeof(req));

            // Send document pointers (as uint64_t)
            std::vector<uint64_t> doc_ptrs;
            doc_ptrs.reserve(current_documents_.size());
            for (const auto& doc : current_documents_) {
                doc_ptrs.push_back(reinterpret_cast<uint64_t>(&doc));
            }
            write(read_fd_, doc_ptrs.data(), doc_ptrs.size() * sizeof(uint64_t));

            pending_requests_[request_id] = std::chrono::steady_clock::now();
            requests_sent_++;
            state_ = WAITING_FOR_RESPONSE;

            std::cout << "[" << id_ << "] Sent EMBEDDING request " << request_id
                     << " with " << current_documents_.size() << " document(s) ("
                     << requests_sent_ << "/" << total_requests_ << ")\n";
        }
    }

    void send_rerank_request(const std::string& query, const std::vector<Document>& documents, uint32_t top_n = 5) {
        if (state_ != IDLE) return;

        // Store documents for this request (owned by client until response)
        current_documents_ = documents;

        uint64_t request_id = next_request_id_++;

        RequestHeader req;
        req.request_id = request_id;
        req.operation = OP_RERANK;
        req.document_count = current_documents_.size();
        req.flags = 0;
        req.top_n = top_n;

        // Send request header
        write(read_fd_, &req, sizeof(req));

        // Send query as null-terminated string
        write(read_fd_, query.c_str(), query.size() + 1);  // +1 for null terminator

        // Send document pointers (as uint64_t)
        std::vector<uint64_t> doc_ptrs;
        doc_ptrs.reserve(current_documents_.size());
        for (const auto& doc : current_documents_) {
            doc_ptrs.push_back(reinterpret_cast<uint64_t>(&doc));
        }
        write(read_fd_, doc_ptrs.data(), doc_ptrs.size() * sizeof(uint64_t));

        pending_requests_[request_id] = std::chrono::steady_clock::now();
        requests_sent_++;
        state_ = WAITING_FOR_RESPONSE;

        std::cout << "[" << id_ << "] Sent rerank request " << request_id
                 << " with " << current_documents_.size() << " document(s), top_n=" << top_n
                 << " (" << requests_sent_ << "/" << total_requests_ << ")\n";
    }

    bool has_response() {
        if (state_ != WAITING_FOR_RESPONSE) {
            return false;
        }

        ResponseHeader resp;
        ssize_t n = read(read_fd_, &resp, sizeof(resp));

        if (n <= 0) {
            return false;
        }

        auto it = pending_requests_.find(resp.request_id);
        if (it != pending_requests_.end()) {
            auto start_time = it->second;
            auto end_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time).count();

            if (resp.status_code == 0) {
                if (resp.embedding_size > 0) {
                    // Batch embedding response
                    float* batch_embedding_ptr = reinterpret_cast<float*>(resp.result_ptr);

                    std::cout << "[" << id_ << "] Received embedding response " << resp.request_id
                             << " (rtt=" << duration << "ms, proc=" << resp.processing_time_ms
                             << "ms, embeddings=" << resp.result_count
                             << " x " << resp.embedding_size << " floats = "
                             << (resp.result_count * resp.embedding_size) << " total floats)\n";

                    // Take ownership of the batch embedding
                    if (owned_embedding_) {
                        delete[] owned_embedding_;
                    }
                    owned_embedding_ = batch_embedding_ptr;
                } else if (resp.result_count > 0) {
                    // Rerank response
                    RerankResult* rerank_ptr = reinterpret_cast<RerankResult*>(resp.result_ptr);

                    std::cout << "[" << id_ << "] Received rerank response " << resp.request_id
                             << " (rtt=" << duration << "ms, proc=" << resp.processing_time_ms
                             << "ms, results=" << resp.result_count << ")\n";

                    // Print top results
                    for (uint32_t i = 0; i < std::min(resp.result_count, 5u); i++) {
                        std::cout << "  [" << i << "] index=" << rerank_ptr[i].index
                                 << ", score=" << rerank_ptr[i].score << "\n";
                    }

                    // Take ownership of the rerank results
                    if (owned_rerank_results_) {
                        delete[] owned_rerank_results_;
                    }
                    owned_rerank_results_ = rerank_ptr;
                }
            } else {
                std::cout << "[" << id_ << "] Received response " << resp.request_id
                         << " (rtt=" << duration << "ms, status=ERROR)\n";
            }

            pending_requests_.erase(it);
        }

        responses_received_++;

        // Clean up current documents (safe now that response is received)
        current_documents_.clear();

        // Check if we should send more requests or are done
        if (requests_sent_ >= total_requests_) {
            state_ = DONE;
        } else {
            state_ = IDLE;
        }

        return true;
    }

    bool is_done() const {
        return state_ == DONE;
    }

    int get_read_fd() const {
        return read_fd_;
    }

    int get_id() const {
        return id_;
    }

    void close() {
        if (read_fd_ >= 0) ::close(read_fd_);
        if (genai_fd_ >= 0) ::close(genai_fd_);
        read_fd_ = -1;
        genai_fd_ = -1;
    }

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
    int id_;
    Config config_;
    State state_;

    int read_fd_;
    int genai_fd_;

    uint64_t next_request_id_;
    int requests_sent_;
    int total_requests_;
    int responses_received_;

    std::vector<Document> current_documents_;  ///< Documents for current request
    float* owned_embedding_;  ///< Embedding received from GenAI (owned by client)
    RerankResult* owned_rerank_results_;  ///< Rerank results from GenAI (owned by client)

    std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> pending_requests_;
};

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== GenAI Module Event-Driven POC ===\n";
    std::cout << "Real embedding generation and reranking via llama-server\n\n";

    Config config;
    std::cout << "Configuration:\n";
    std::cout << "  GenAI workers: " << config.genai_workers << "\n";
    std::cout << "  Max clients: " << config.max_clients << "\n";
    std::cout << "  Run duration: " << config.run_duration_seconds << "s\n";
    std::cout << "  Client add probability: " << config.client_add_probability << "\n";
    std::cout << "  Request send probability: " << config.request_send_probability << "\n";
    std::cout << "  Documents per request: " << config.min_documents_per_request
             << "-" << config.max_documents_per_request << "\n";
    std::cout << "  Sample documents: " << SAMPLE_DOCUMENTS.size() << "\n\n";

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

        int timeout_ms = 100;
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
