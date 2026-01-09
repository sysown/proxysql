#include "GenAI_Thread.h"
#include "proxysql_debug.h"
#include <cstring>
#include <sstream>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <chrono>
#include <random>
#include <thread>
#include <poll.h>
#include "json.hpp"

using json = nlohmann::json;

// Platform compatibility
#ifndef EFD_CLOEXEC
#define EFD_CLOEXEC 0200000
#endif
#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK 04000
#endif

// epoll compatibility - detect epoll availability at compile time
#ifdef epoll_create1
	#define EPOLL_CREATE epoll_create1(0)
#else
	#define EPOLL_CREATE epoll_create(1)
#endif

// Define the array of variable names for the GenAI module
// Note: These do NOT include the "genai_" prefix - it's added by the flush functions
static const char* genai_thread_variables_names[] = {
	"threads",
	"embedding_uri",
	"rerank_uri",
	"embedding_timeout_ms",
	"rerank_timeout_ms",
	NULL
};

// ============================================================================
// Move constructors and destructors for result structures
// ============================================================================

GenAI_EmbeddingResult::~GenAI_EmbeddingResult() {
	if (data) {
		delete[] data;
		data = nullptr;
	}
}

GenAI_EmbeddingResult::GenAI_EmbeddingResult(GenAI_EmbeddingResult&& other) noexcept
	: data(other.data), embedding_size(other.embedding_size), count(other.count) {
	other.data = nullptr;
	other.embedding_size = 0;
	other.count = 0;
}

GenAI_EmbeddingResult& GenAI_EmbeddingResult::operator=(GenAI_EmbeddingResult&& other) noexcept {
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

GenAI_RerankResultArray::~GenAI_RerankResultArray() {
	if (data) {
		delete[] data;
		data = nullptr;
	}
}

GenAI_RerankResultArray::GenAI_RerankResultArray(GenAI_RerankResultArray&& other) noexcept
	: data(other.data), count(other.count) {
	other.data = nullptr;
	other.count = 0;
}

GenAI_RerankResultArray& GenAI_RerankResultArray::operator=(GenAI_RerankResultArray&& other) noexcept {
	if (this != &other) {
		if (data) delete[] data;
		data = other.data;
		count = other.count;
		other.data = nullptr;
		other.count = 0;
	}
	return *this;
}

// ============================================================================
// GenAI_Threads_Handler implementation
// ============================================================================

GenAI_Threads_Handler::GenAI_Threads_Handler() {
	shutdown_ = 0;
	num_threads = 0;
	pthread_rwlock_init(&rwlock, NULL);
	epoll_fd_ = -1;
	event_fd_ = -1;

	curl_global_init(CURL_GLOBAL_ALL);

	// Initialize variables with default values
	variables.genai_threads = 4;
	variables.genai_embedding_uri = strdup("http://127.0.0.1:8013/embedding");
	variables.genai_rerank_uri = strdup("http://127.0.0.1:8012/rerank");
	variables.genai_embedding_timeout_ms = 30000;
	variables.genai_rerank_timeout_ms = 30000;

	status_variables.threads_initialized = 0;
	status_variables.active_requests = 0;
	status_variables.completed_requests = 0;
	status_variables.failed_requests = 0;
}

GenAI_Threads_Handler::~GenAI_Threads_Handler() {
	if (shutdown_ == 0) {
		shutdown();
	}

	if (variables.genai_embedding_uri)
		free(variables.genai_embedding_uri);
	if (variables.genai_rerank_uri)
		free(variables.genai_rerank_uri);

	pthread_rwlock_destroy(&rwlock);
}

void GenAI_Threads_Handler::init(unsigned int num, size_t stack) {
	proxy_info("Initializing GenAI Threads Handler\n");

	// Use variable value if num is 0
	if (num == 0) {
		num = variables.genai_threads;
	}

	num_threads = num;
	shutdown_ = 0;

#ifdef epoll_create1
	// Use epoll for async I/O
	epoll_fd_ = EPOLL_CREATE;
	if (epoll_fd_ < 0) {
		proxy_error("Failed to create epoll: %s\n", strerror(errno));
		return;
	}

	// Create eventfd for wakeup
	event_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (event_fd_ < 0) {
		proxy_error("Failed to create eventfd: %s\n", strerror(errno));
		close(epoll_fd_);
		epoll_fd_ = -1;
		return;
	}

	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = event_fd_;
	if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, event_fd_, &ev) < 0) {
		proxy_error("Failed to add eventfd to epoll: %s\n", strerror(errno));
		close(event_fd_);
		close(epoll_fd_);
		event_fd_ = -1;
		epoll_fd_ = -1;
		return;
	}
#else
	// Use pipe for wakeup on systems without epoll
	int pipefds[2];
	if (pipe(pipefds) < 0) {
		proxy_error("Failed to create pipe: %s\n", strerror(errno));
		return;
	}

	// Set both ends to non-blocking
	fcntl(pipefds[0], F_SETFL, O_NONBLOCK);
	fcntl(pipefds[1], F_SETFL, O_NONBLOCK);

	event_fd_ = pipefds[1];  // Use write end for wakeup
	epoll_fd_ = pipefds[0];  // Use read end for polling (repurposed)
#endif

	// Start listener thread
	listener_thread_ = std::thread(&GenAI_Threads_Handler::listener_loop, this);

	// Start worker threads
	for (unsigned int i = 0; i < num; i++) {
		pthread_t thread;
		if (pthread_create(&thread, NULL, [](void* arg) -> void* {
			auto* handler = static_cast<std::pair<GenAI_Threads_Handler*, int>*>(arg);
			handler->first->worker_loop(handler->second);
			delete handler;
			return NULL;
		}, new std::pair<GenAI_Threads_Handler*, int>(this, i)) == 0) {
			worker_threads_.push_back(thread);
		} else {
			proxy_error("Failed to create worker thread %d\n", i);
		}
	}

	status_variables.threads_initialized = worker_threads_.size();

	proxy_info("GenAI module started with %zu workers\n", worker_threads_.size());
	proxy_info("Embedding endpoint: %s\n", variables.genai_embedding_uri);
	proxy_info("Rerank endpoint: %s\n", variables.genai_rerank_uri);
	print_version();
}

void GenAI_Threads_Handler::shutdown() {
	if (shutdown_ == 1) {
		return; // Already shutting down
	}

	proxy_info("Shutting down GenAI module\n");
	shutdown_ = 1;

	// Wake up listener
	if (event_fd_ >= 0) {
		uint64_t value = 1;
		write(event_fd_, &value, sizeof(value));
	}

	// Notify all workers
	queue_cv_.notify_all();

	// Join worker threads
	for (auto& t : worker_threads_) {
		pthread_join(t, NULL);
	}
	worker_threads_.clear();

	// Join listener thread
	if (listener_thread_.joinable()) {
		listener_thread_.join();
	}

	// Clean up epoll
	if (event_fd_ >= 0) {
		close(event_fd_);
		event_fd_ = -1;
	}
	if (epoll_fd_ >= 0) {
		close(epoll_fd_);
		epoll_fd_ = -1;
	}

	status_variables.threads_initialized = 0;
}

void GenAI_Threads_Handler::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
}

void GenAI_Threads_Handler::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
}

char* GenAI_Threads_Handler::get_variable(char* name) {
	if (!name)
		return NULL;

	if (!strcmp(name, "threads")) {
		char buf[64];
		sprintf(buf, "%d", variables.genai_threads);
		return strdup(buf);
	}
	if (!strcmp(name, "embedding_uri")) {
		return strdup(variables.genai_embedding_uri ? variables.genai_embedding_uri : "");
	}
	if (!strcmp(name, "rerank_uri")) {
		return strdup(variables.genai_rerank_uri ? variables.genai_rerank_uri : "");
	}
	if (!strcmp(name, "embedding_timeout_ms")) {
		char buf[64];
		sprintf(buf, "%d", variables.genai_embedding_timeout_ms);
		return strdup(buf);
	}
	if (!strcmp(name, "rerank_timeout_ms")) {
		char buf[64];
		sprintf(buf, "%d", variables.genai_rerank_timeout_ms);
		return strdup(buf);
	}

	return NULL;
}

bool GenAI_Threads_Handler::set_variable(char* name, const char* value) {
	if (!name || !value)
		return false;

	if (!strcmp(name, "threads")) {
		int val = atoi(value);
		if (val < 1 || val > 256) {
			proxy_error("Invalid value for genai_threads: %d (must be 1-256)\n", val);
			return false;
		}
		variables.genai_threads = val;
		return true;
	}
	if (!strcmp(name, "embedding_uri")) {
		if (variables.genai_embedding_uri)
			free(variables.genai_embedding_uri);
		variables.genai_embedding_uri = strdup(value);
		return true;
	}
	if (!strcmp(name, "rerank_uri")) {
		if (variables.genai_rerank_uri)
			free(variables.genai_rerank_uri);
		variables.genai_rerank_uri = strdup(value);
		return true;
	}
	if (!strcmp(name, "embedding_timeout_ms")) {
		int val = atoi(value);
		if (val < 100 || val > 300000) {
			proxy_error("Invalid value for genai_embedding_timeout_ms: %d (must be 100-300000)\n", val);
			return false;
		}
		variables.genai_embedding_timeout_ms = val;
		return true;
	}
	if (!strcmp(name, "rerank_timeout_ms")) {
		int val = atoi(value);
		if (val < 100 || val > 300000) {
			proxy_error("Invalid value for genai_rerank_timeout_ms: %d (must be 100-300000)\n", val);
			return false;
		}
		variables.genai_rerank_timeout_ms = val;
		return true;
	}

	return false;
}

char** GenAI_Threads_Handler::get_variables_list() {
	// Count variables
	int count = 0;
	while (genai_thread_variables_names[count]) {
		count++;
	}

	// Allocate array
	char** list = (char**)malloc(sizeof(char*) * (count + 1));
	if (!list)
		return NULL;

	// Fill array
	for (int i = 0; i < count; i++) {
		list[i] = strdup(genai_thread_variables_names[i]);
	}
	list[count] = NULL;

	return list;
}

void GenAI_Threads_Handler::print_version() {
	fprintf(stderr, "GenAI Threads Handler rev. %s -- %s -- %s\n", GENAI_THREAD_VERSION, __FILE__, __TIMESTAMP__);
}

bool GenAI_Threads_Handler::register_client(int client_fd) {
	std::lock_guard<std::mutex> lock(clients_mutex_);

	int flags = fcntl(client_fd, F_GETFL, 0);
	fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

#ifdef epoll_create1
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = client_fd;
	if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
		proxy_error("Failed to add client fd %d to epoll: %s\n", client_fd, strerror(errno));
		return false;
	}
#endif

	client_fds_.insert(client_fd);
	proxy_debug(PROXY_DEBUG_GENAI, 3, "Registered GenAI client fd %d\n", client_fd);
	return true;
}

void GenAI_Threads_Handler::unregister_client(int client_fd) {
	std::lock_guard<std::mutex> lock(clients_mutex_);

#ifdef epoll_create1
	if (epoll_fd_ >= 0) {
		epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, client_fd, NULL);
	}
#endif

	client_fds_.erase(client_fd);
	close(client_fd);
	proxy_debug(PROXY_DEBUG_GENAI, 3, "Unregistered GenAI client fd %d\n", client_fd);
}

size_t GenAI_Threads_Handler::get_queue_size() {
	std::lock_guard<std::mutex> lock(queue_mutex_);
	return request_queue_.size();
}

// ============================================================================
// Public API methods
// ============================================================================

size_t GenAI_Threads_Handler::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t totalSize = size * nmemb;
	std::string* response = static_cast<std::string*>(userp);
	response->append(static_cast<char*>(contents), totalSize);
	return totalSize;
}

GenAI_EmbeddingResult GenAI_Threads_Handler::call_llama_embedding(const std::string& text) {
	// For single document, use batch API with 1 document
	std::vector<std::string> texts = {text};
	return call_llama_batch_embedding(texts);
}

GenAI_EmbeddingResult GenAI_Threads_Handler::call_llama_batch_embedding(const std::vector<std::string>& texts) {
	GenAI_EmbeddingResult result;
	CURL* curl = curl_easy_init();

	if (!curl) {
		proxy_error("Failed to initialize curl\n");
		status_variables.failed_requests++;
		return result;
	}

	// Build JSON request
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
	curl_easy_setopt(curl, CURLOPT_URL, variables.genai_embedding_uri);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, variables.genai_embedding_timeout_ms);

	std::string response_data;
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

	// Add content-type header
	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// Perform request
	auto start_time = std::chrono::steady_clock::now();
	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		proxy_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		status_variables.failed_requests++;
	} else {
		// Parse JSON response to extract embeddings
		std::vector<std::vector<float>> all_embeddings;

		size_t pos = 0;
		while ((pos = response_data.find("\"embedding\":", pos)) != std::string::npos) {
			size_t array_start = response_data.find("[", pos);
			if (array_start == std::string::npos) break;

			size_t inner_start = array_start + 1;
			if (inner_start >= response_data.size() || response_data[inner_start] != '[') {
				inner_start = array_start;
			}

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

			std::string array_str = response_data.substr(inner_start + 1, array_end - inner_start - 1);
			std::vector<float> embedding;
			std::stringstream ss(array_str);
			std::string token;

			while (std::getline(ss, token, ',')) {
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

			pos = array_end + 1;
		}

		// Convert to contiguous array
		if (!all_embeddings.empty()) {
			result.count = all_embeddings.size();
			result.embedding_size = all_embeddings[0].size();

			size_t total_floats = result.embedding_size * result.count;
			result.data = new float[total_floats];

			for (size_t i = 0; i < all_embeddings.size(); i++) {
				size_t offset = i * result.embedding_size;
				const auto& emb = all_embeddings[i];
				std::copy(emb.begin(), emb.end(), result.data + offset);
			}

			status_variables.completed_requests++;
		} else {
			status_variables.failed_requests++;
		}
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	return result;
}

GenAI_RerankResultArray GenAI_Threads_Handler::call_llama_rerank(const std::string& query,
																  const std::vector<std::string>& texts,
																  uint32_t top_n) {
	GenAI_RerankResultArray result;
	CURL* curl = curl_easy_init();

	if (!curl) {
		proxy_error("Failed to initialize curl\n");
		status_variables.failed_requests++;
		return result;
	}

	// Build JSON request
	std::stringstream json;
	json << "{\"query\":\"";

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

	for (size_t i = 0; i < texts.size(); i++) {
		if (i > 0) json << ",";
		json << "\"";

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
	curl_easy_setopt(curl, CURLOPT_URL, variables.genai_rerank_uri);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, variables.genai_rerank_timeout_ms);

	std::string response_data;
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		proxy_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		status_variables.failed_requests++;
	} else {
		size_t results_pos = response_data.find("\"results\":");
		if (results_pos != std::string::npos) {
			size_t array_start = response_data.find("[", results_pos);
			if (array_start != std::string::npos) {
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

				std::string array_str = response_data.substr(array_start + 1, array_end - array_start - 1);
				std::vector<GenAI_RerankResult> results;

				size_t pos = 0;
				while (pos < array_str.size()) {
					size_t index_pos = array_str.find("\"index\":", pos);
					if (index_pos == std::string::npos) break;

					size_t num_start = index_pos + 8;
					while (num_start < array_str.size() &&
						   (array_str[num_start] == ' ' || array_str[num_start] == '\t')) {
						num_start++;
					}

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

					size_t score_pos = array_str.find("\"relevance_score\":", index_pos);
					if (score_pos == std::string::npos) break;

					size_t score_start = score_pos + 18;
					while (score_start < array_str.size() &&
						   (array_str[score_start] == ' ' || array_str[score_start] == '\t')) {
						score_start++;
					}

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

				if (!results.empty() && top_n > 0) {
					size_t count = std::min(static_cast<size_t>(top_n), results.size());
					result.count = count;
					result.data = new GenAI_RerankResult[count];
					std::copy(results.begin(), results.begin() + count, result.data);
				} else {
					result.count = results.size();
					result.data = new GenAI_RerankResult[results.size()];
					std::copy(results.begin(), results.end(), result.data);
				}

				status_variables.completed_requests++;
			} else {
				status_variables.failed_requests++;
			}
		} else {
			status_variables.failed_requests++;
		}
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	return result;
}

// ============================================================================
// Public API methods
// ============================================================================

GenAI_EmbeddingResult GenAI_Threads_Handler::embed_documents(const std::vector<std::string>& documents) {
	if (documents.empty()) {
		proxy_error("embed_documents called with empty documents list\n");
		status_variables.failed_requests++;
		return GenAI_EmbeddingResult();
	}

	status_variables.active_requests++;

	GenAI_EmbeddingResult result;
	if (documents.size() == 1) {
		result = call_llama_embedding(documents[0]);
	} else {
		result = call_llama_batch_embedding(documents);
	}

	status_variables.active_requests--;
	return result;
}

GenAI_RerankResultArray GenAI_Threads_Handler::rerank_documents(const std::string& query,
																const std::vector<std::string>& documents,
																uint32_t top_n) {
	if (documents.empty()) {
		proxy_error("rerank_documents called with empty documents list\n");
		status_variables.failed_requests++;
		return GenAI_RerankResultArray();
	}

	if (query.empty()) {
		proxy_error("rerank_documents called with empty query\n");
		status_variables.failed_requests++;
		return GenAI_RerankResultArray();
	}

	status_variables.active_requests++;

	GenAI_RerankResultArray result = call_llama_rerank(query, documents, top_n);

	status_variables.active_requests--;
	return result;
}

// ============================================================================
// Worker and listener loops (for future socket pair integration)
// ============================================================================

void GenAI_Threads_Handler::listener_loop() {
	proxy_debug(PROXY_DEBUG_GENAI, 3, "GenAI listener thread started\n");

#ifdef epoll_create1
	const int MAX_EVENTS = 64;
	struct epoll_event events[MAX_EVENTS];

	while (!shutdown_) {
		int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, 100);

		if (nfds < 0 && errno != EINTR) {
			if (errno != EINTR) {
				proxy_error("epoll_wait failed: %s\n", strerror(errno));
			}
			continue;
		}

		for (int i = 0; i < nfds; i++) {
			if (events[i].data.fd == event_fd_) {
				continue;
			}

			// Handle client events here
			// This will be implemented when integrating with MySQL/PgSQL threads
		}
	}
#else
	// Use poll() for systems without epoll support
	while (!shutdown_) {
		// Build pollfd array
		std::vector<struct pollfd> pollfds;
		pollfds.reserve(client_fds_.size() + 1);

		// Add wakeup pipe read end
		struct pollfd wakeup_pfd;
		wakeup_pfd.fd = epoll_fd_;  // Reused as pipe read end
		wakeup_pfd.events = POLLIN;
		wakeup_pfd.revents = 0;
		pollfds.push_back(wakeup_pfd);

		// Add all client fds
		{
			std::lock_guard<std::mutex> lock(clients_mutex_);
			for (int fd : client_fds_) {
				struct pollfd pfd;
				pfd.fd = fd;
				pfd.events = POLLIN;
				pfd.revents = 0;
				pollfds.push_back(pfd);
			}
		}

		int nfds = poll(pollfds.data(), pollfds.size(), 100);

		if (nfds < 0 && errno != EINTR) {
			proxy_error("poll failed: %s\n", strerror(errno));
			continue;
		}

		// Check for wakeup event
		if (pollfds.size() > 0 && (pollfds[0].revents & POLLIN)) {
			uint64_t value;
			read(pollfds[0].fd, &value, sizeof(value));  // Clear the pipe
			continue;
		}

		// Handle client events
		for (size_t i = 1; i < pollfds.size(); i++) {
			if (pollfds[i].revents & POLLIN) {
				// Handle client events here
				// This will be implemented when integrating with MySQL/PgSQL threads
			}
		}
	}
#endif

	proxy_debug(PROXY_DEBUG_GENAI, 3, "GenAI listener thread stopped\n");
}

void GenAI_Threads_Handler::worker_loop(int worker_id) {
	proxy_debug(PROXY_DEBUG_GENAI, 3, "GenAI worker thread %d started\n", worker_id);

	while (!shutdown_) {
		std::unique_lock<std::mutex> lock(queue_mutex_);
		queue_cv_.wait(lock, [this] {
			return shutdown_ || !request_queue_.empty();
		});

		if (shutdown_) break;

		if (request_queue_.empty()) continue;

		GenAI_Request req = std::move(request_queue_.front());
		request_queue_.pop();
		lock.release();

		// Process request
		// This will be implemented when integrating with MySQL/PgSQL threads
		proxy_debug(PROXY_DEBUG_GENAI, 3, "Worker %d processing request %lu\n", worker_id, req.request_id);
	}

	proxy_debug(PROXY_DEBUG_GENAI, 3, "GenAI worker thread %d stopped\n", worker_id);
}

// Helper function to execute SQL query and return documents
// Returns pair of (success, vector of documents) or (success, error message)
static std::pair<bool, std::vector<std::string>> execute_sql_for_documents(const std::string& sql_query) {
	std::vector<std::string> documents;

	// TODO: Implement MySQL connection handling
	// For now, return error indicating this needs MySQL connectivity
	return {false, {}};
}

// Process JSON query autonomously
std::string GenAI_Threads_Handler::process_json_query(const std::string& json_query) {
	json result;

	try {
		// Parse JSON query
		json query_json = json::parse(json_query);

		if (!query_json.is_object()) {
			result["error"] = "Query must be a JSON object";
			return result.dump();
		}

		// Extract operation type
		if (!query_json.contains("type") || !query_json["type"].is_string()) {
			result["error"] = "Query must contain a 'type' field (embed or rerank)";
			return result.dump();
		}

		std::string op_type = query_json["type"].get<std::string>();

		// Handle embed operation
		if (op_type == "embed") {
			// Extract documents array
			if (!query_json.contains("documents") || !query_json["documents"].is_array()) {
				result["error"] = "Embed operation requires a 'documents' array";
				return result.dump();
			}

			std::vector<std::string> documents;
			for (const auto& doc : query_json["documents"]) {
				if (doc.is_string()) {
					documents.push_back(doc.get<std::string>());
				} else {
					documents.push_back(doc.dump());
				}
			}

			if (documents.empty()) {
				result["error"] = "Embed operation requires at least one document";
				return result.dump();
			}

			// Call embedding service
			GenAI_EmbeddingResult embeddings = embed_documents(documents);

			if (!embeddings.data || embeddings.count == 0) {
				result["error"] = "Failed to generate embeddings";
				return result.dump();
			}

			// Build result
			result["columns"] = json::array({"embedding"});
			json rows = json::array();

			for (size_t i = 0; i < embeddings.count; i++) {
				float* embedding = embeddings.data + (i * embeddings.embedding_size);
				std::ostringstream oss;
				for (size_t k = 0; k < embeddings.embedding_size; k++) {
					if (k > 0) oss << ",";
					oss << embedding[k];
				}
				rows.push_back(json::array({oss.str()}));
			}

			result["rows"] = rows;
			return result.dump();
		}

		// Handle rerank operation
		if (op_type == "rerank") {
			// Extract query
			if (!query_json.contains("query") || !query_json["query"].is_string()) {
				result["error"] = "Rerank operation requires a 'query' string";
				return result.dump();
			}
			std::string query_str = query_json["query"].get<std::string>();

			if (query_str.empty()) {
				result["error"] = "Rerank query cannot be empty";
				return result.dump();
			}

			// Check for document_from_sql or documents array
			std::vector<std::string> documents;
			bool use_sql_documents = query_json.contains("document_from_sql") && query_json["document_from_sql"].is_object();

			if (use_sql_documents) {
				// document_from_sql mode - execute SQL to get documents
				if (!query_json["document_from_sql"].contains("query") || !query_json["document_from_sql"]["query"].is_string()) {
					result["error"] = "document_from_sql requires a 'query' string";
					return result.dump();
				}

				std::string sql_query = query_json["document_from_sql"]["query"].get<std::string>();
				if (sql_query.empty()) {
					result["error"] = "document_from_sql query cannot be empty";
					return result.dump();
				}

				// Execute SQL query to get documents
				auto [success, docs] = execute_sql_for_documents(sql_query);
				if (!success) {
					result["error"] = "document_from_sql feature not yet implemented - MySQL connection handling required";
					return result.dump();
				}
				documents = docs;
			} else {
				// Direct documents array mode
				if (!query_json.contains("documents") || !query_json["documents"].is_array()) {
					result["error"] = "Rerank operation requires 'documents' array or 'document_from_sql' object";
					return result.dump();
				}

				for (const auto& doc : query_json["documents"]) {
					if (doc.is_string()) {
						documents.push_back(doc.get<std::string>());
					} else {
						documents.push_back(doc.dump());
					}
				}
			}

			if (documents.empty()) {
				result["error"] = "Rerank operation requires at least one document";
				return result.dump();
			}

			// Extract optional top_n (default 0 = return all)
			uint32_t opt_top_n = 0;
			if (query_json.contains("top_n") && query_json["top_n"].is_number()) {
				opt_top_n = query_json["top_n"].get<uint32_t>();
			}

			// Extract optional columns (default 3 = index, score, document)
			uint32_t opt_columns = 3;
			if (query_json.contains("columns") && query_json["columns"].is_number()) {
				opt_columns = query_json["columns"].get<uint32_t>();
				if (opt_columns != 2 && opt_columns != 3) {
					result["error"] = "Rerank 'columns' must be 2 or 3";
					return result.dump();
				}
			}

			// Call rerank service
			GenAI_RerankResultArray rerank_result = rerank_documents(query_str, documents, opt_top_n);

			if (!rerank_result.data || rerank_result.count == 0) {
				result["error"] = "Failed to rerank documents";
				return result.dump();
			}

			// Build result
			json rows = json::array();

			if (opt_columns == 2) {
				result["columns"] = json::array({"index", "score"});

				for (size_t i = 0; i < rerank_result.count; i++) {
					const GenAI_RerankResult& r = rerank_result.data[i];
					std::string index_str = std::to_string(r.index);
					std::string score_str = std::to_string(r.score);
					rows.push_back(json::array({index_str, score_str}));
				}
			} else {
				result["columns"] = json::array({"index", "score", "document"});

				for (size_t i = 0; i < rerank_result.count; i++) {
					const GenAI_RerankResult& r = rerank_result.data[i];
					if (r.index >= documents.size()) {
						continue;  // Skip invalid index
					}
					std::string index_str = std::to_string(r.index);
					std::string score_str = std::to_string(r.score);
					const std::string& doc = documents[r.index];
					rows.push_back(json::array({index_str, score_str, doc}));
				}
			}

			result["rows"] = rows;
			return result.dump();
		}

		// Unknown operation type
		result["error"] = "Unknown operation type: " + op_type + ". Use 'embed' or 'rerank'";
		return result.dump();

	} catch (const json::parse_error& e) {
		result["error"] = std::string("JSON parse error: ") + e.what();
		return result.dump();
	} catch (const std::exception& e) {
		result["error"] = std::string("Error: ") + e.what();
		return result.dump();
	}
}
