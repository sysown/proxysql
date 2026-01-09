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

// Platform compatibility
#ifndef EFD_CLOEXEC
#define EFD_CLOEXEC 0200000
#endif
#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK 04000
#endif

// Define the array of variable names for the GenAI module
static const char* genai_thread_variables_names[] = {
	"genai_threads",
	"genai_embedding_uri",
	"genai_rerank_uri",
	"genai_embedding_timeout_ms",
	"genai_rerank_timeout_ms",
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

#ifdef HAVE_LIBCURL
	curl_global_init(CURL_GLOBAL_ALL);
#endif

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

#ifdef HAVE_LIBCURL
	curl_global_cleanup();
#endif
}

void GenAI_Threads_Handler::init(unsigned int num, size_t stack) {
	proxy_info("Initializing GenAI Threads Handler\n");

	// Use variable value if num is 0
	if (num == 0) {
		num = variables.genai_threads;
	}

	num_threads = num;
	shutdown_ = 0;

	// Create epoll for async I/O
	epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
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

	if (!strcmp(name, "genai_threads")) {
		char buf[64];
		sprintf(buf, "%d", variables.genai_threads);
		return strdup(buf);
	}
	if (!strcmp(name, "genai_embedding_uri")) {
		return strdup(variables.genai_embedding_uri ? variables.genai_embedding_uri : "");
	}
	if (!strcmp(name, "genai_rerank_uri")) {
		return strdup(variables.genai_rerank_uri ? variables.genai_rerank_uri : "");
	}
	if (!strcmp(name, "genai_embedding_timeout_ms")) {
		char buf[64];
		sprintf(buf, "%d", variables.genai_embedding_timeout_ms);
		return strdup(buf);
	}
	if (!strcmp(name, "genai_rerank_timeout_ms")) {
		char buf[64];
		sprintf(buf, "%d", variables.genai_rerank_timeout_ms);
		return strdup(buf);
	}

	return NULL;
}

bool GenAI_Threads_Handler::set_variable(char* name, const char* value) {
	if (!name || !value)
		return false;

	if (!strcmp(name, "genai_threads")) {
		int val = atoi(value);
		if (val < 1 || val > 256) {
			proxy_error("Invalid value for genai_threads: %d (must be 1-256)\n", val);
			return false;
		}
		variables.genai_threads = val;
		return true;
	}
	if (!strcmp(name, "genai_embedding_uri")) {
		if (variables.genai_embedding_uri)
			free(variables.genai_embedding_uri);
		variables.genai_embedding_uri = strdup(value);
		return true;
	}
	if (!strcmp(name, "genai_rerank_uri")) {
		if (variables.genai_rerank_uri)
			free(variables.genai_rerank_uri);
		variables.genai_rerank_uri = strdup(value);
		return true;
	}
	if (!strcmp(name, "genai_embedding_timeout_ms")) {
		int val = atoi(value);
		if (val < 100 || val > 300000) {
			proxy_error("Invalid value for genai_embedding_timeout_ms: %d (must be 100-300000)\n", val);
			return false;
		}
		variables.genai_embedding_timeout_ms = val;
		return true;
	}
	if (!strcmp(name, "genai_rerank_timeout_ms")) {
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

	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = client_fd;
	if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
		proxy_error("Failed to add client fd %d to epoll: %s\n", client_fd, strerror(errno));
		return false;
	}

	client_fds_.insert(client_fd);
	proxy_debug(PROXY_DEBUG_GENAI, 3, "Registered GenAI client fd %d\n", client_fd);
	return true;
}

void GenAI_Threads_Handler::unregister_client(int client_fd) {
	std::lock_guard<std::mutex> lock(clients_mutex_);

	if (epoll_fd_ >= 0) {
		epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, client_fd, NULL);
	}

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

#ifdef HAVE_LIBCURL

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

#endif // HAVE_LIBCURL

// ============================================================================
// Public API methods
// ============================================================================

GenAI_EmbeddingResult GenAI_Threads_Handler::embed_documents(const std::vector<std::string>& documents) {
#ifdef HAVE_LIBCURL
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
#else
	proxy_error("GenAI module compiled without libcurl support\n");
	status_variables.failed_requests++;
	return GenAI_EmbeddingResult();
#endif
}

GenAI_RerankResultArray GenAI_Threads_Handler::rerank_documents(const std::string& query,
																const std::vector<std::string>& documents,
																uint32_t top_n) {
#ifdef HAVE_LIBCURL
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
#else
	proxy_error("GenAI module compiled without libcurl support\n");
	status_variables.failed_requests++;
	return GenAI_RerankResultArray();
#endif
}

// ============================================================================
// Worker and listener loops (for future socket pair integration)
// ============================================================================

void GenAI_Threads_Handler::listener_loop() {
	proxy_debug(PROXY_DEBUG_GENAI, 3, "GenAI listener thread started\n");

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
