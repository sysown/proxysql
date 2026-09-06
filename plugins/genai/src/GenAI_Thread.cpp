#ifdef PROXYSQL40


#include "proxysql.h"
#include "GenAI_Thread.h"
#include "AI_Features_Manager.h"
#include "LLM_Bridge.h"  // direct include after Step 5 stopped pulling
                          // it in transitively via proxysql.h.
#include "proxysql_debug.h"
#include <cstring>
#include <sstream>
#include <algorithm>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#ifdef __linux__
#include <sys/eventfd.h>
#endif
#include <chrono>
#include <random>
#include <thread>
#include <poll.h>
#include "json.hpp"

using json = nlohmann::json;

// Global AI Features Manager - needed for NL2SQL operations
extern AI_Features_Manager *GloAI;

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
	// Original GenAI variables
	"threads",
	"embedding_uri",
	"embedding_model",
	"rerank_uri",
	"embedding_timeout_ms",
	"rerank_timeout_ms",

	// AI Features master switches
	"enabled",
	"llm_enabled",
	"anomaly_enabled",

	// LLM bridge configuration
	"llm_provider",
	"llm_provider_url",
	"llm_provider_model",
	"llm_provider_key",
	"llm_cache_similarity_threshold",
	"llm_cache_enabled",
	"llm_timeout_ms",

	// Anomaly detection configuration
	"anomaly_risk_threshold",
	"anomaly_similarity_threshold",
	"anomaly_rate_limit",
	"anomaly_auto_block",
	"anomaly_log_only",

	// Hybrid model routing
	"prefer_local_models",
	"daily_budget_usd",
	"max_cloud_requests_per_hour",

	// Vector storage configuration
	"vector_db_path",
	"vector_dimension",

	// RAG configuration
	"rag_enabled",
	"rag_k_max",
	"rag_candidates_max",
	"rag_query_max_bytes",
	"rag_response_max_bytes",
	"rag_timeout_ms",

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
	variables.genai_embedding_model = strdup("");
	variables.genai_embedding_timeout_ms = 30000;
	variables.genai_rerank_timeout_ms = 30000;

	// AI Features master switches
	variables.genai_enabled = false;
	variables.genai_llm_enabled = false;
	variables.genai_anomaly_enabled = false;

	// LLM bridge configuration
	variables.genai_llm_provider = strdup("openai");
	variables.genai_llm_provider_url = strdup("http://localhost:11434/v1/chat/completions");
	variables.genai_llm_provider_model = strdup("llama3.2");
	variables.genai_llm_provider_key = NULL;
	variables.genai_llm_cache_similarity_threshold = 85;
	variables.genai_llm_cache_enabled = true;
	variables.genai_llm_timeout_ms = 30000;

	// Anomaly detection configuration
	variables.genai_anomaly_risk_threshold = 70;
	variables.genai_anomaly_similarity_threshold = 80;
	variables.genai_anomaly_rate_limit = 100;
	variables.genai_anomaly_auto_block = true;
	variables.genai_anomaly_log_only = false;

	// Hybrid model routing
	variables.genai_prefer_local_models = true;
	variables.genai_daily_budget_usd = 10.0;
	variables.genai_max_cloud_requests_per_hour = 100;

	// Vector storage configuration
	variables.genai_vector_db_path = strdup("/var/lib/proxysql/ai_features.db");
	variables.genai_vector_dimension = 1536;  // OpenAI text-embedding-3-small

	// RAG configuration
	variables.genai_rag_enabled = false;
	variables.genai_rag_k_max = 50;
	variables.genai_rag_candidates_max = 500;
	variables.genai_rag_query_max_bytes = 8192;
	variables.genai_rag_response_max_bytes = 5000000;
	variables.genai_rag_timeout_ms = 2000;

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
	if (variables.genai_embedding_model)
		free(variables.genai_embedding_model);

	// Free LLM bridge string variables
	if (variables.genai_llm_provider)
		free(variables.genai_llm_provider);
	if (variables.genai_llm_provider_url)
		free(variables.genai_llm_provider_url);
	if (variables.genai_llm_provider_model)
		free(variables.genai_llm_provider_model);
	if (variables.genai_llm_provider_key)
		free(variables.genai_llm_provider_key);

	// Free vector storage string variables
	if (variables.genai_vector_db_path)
		free(variables.genai_vector_db_path);

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

	// Original GenAI variables
	if (!strcmp(name, "threads")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_threads);
		return strdup(buf);
	}
	if (!strcmp(name, "embedding_uri")) {
		return strdup(variables.genai_embedding_uri ? variables.genai_embedding_uri : "");
	}
	if (!strcmp(name, "rerank_uri")) {
		return strdup(variables.genai_rerank_uri ? variables.genai_rerank_uri : "");
	}
	if (!strcmp(name, "embedding_model")) {
		return strdup(variables.genai_embedding_model ? variables.genai_embedding_model : "");
	}
	if (!strcmp(name, "embedding_timeout_ms")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_embedding_timeout_ms);
		return strdup(buf);
	}
	if (!strcmp(name, "rerank_timeout_ms")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_rerank_timeout_ms);
		return strdup(buf);
	}

	// AI Features master switches
	if (!strcmp(name, "enabled")) {
		return strdup(variables.genai_enabled ? "true" : "false");
	}
	if (!strcmp(name, "llm_enabled")) {
		return strdup(variables.genai_llm_enabled ? "true" : "false");
	}
	if (!strcmp(name, "anomaly_enabled")) {
		return strdup(variables.genai_anomaly_enabled ? "true" : "false");
	}

	// LLM configuration
	if (!strcmp(name, "llm_provider")) {
		return strdup(variables.genai_llm_provider ? variables.genai_llm_provider : "");
	}
	if (!strcmp(name, "llm_provider_url")) {
		return strdup(variables.genai_llm_provider_url ? variables.genai_llm_provider_url : "");
	}
	if (!strcmp(name, "llm_provider_model")) {
		return strdup(variables.genai_llm_provider_model ? variables.genai_llm_provider_model : "");
	}
	if (!strcmp(name, "llm_provider_key")) {
		return strdup(variables.genai_llm_provider_key ? variables.genai_llm_provider_key : "");
	}
	if (!strcmp(name, "llm_cache_similarity_threshold")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_llm_cache_similarity_threshold);
		return strdup(buf);
	}
	if (!strcmp(name, "llm_cache_enabled")) {
		return strdup(variables.genai_llm_cache_enabled ? "true" : "false");
	}
	if (!strcmp(name, "llm_timeout_ms")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_llm_timeout_ms);
		return strdup(buf);
	}

	// Anomaly detection configuration
	if (!strcmp(name, "anomaly_risk_threshold")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_anomaly_risk_threshold);
		return strdup(buf);
	}
	if (!strcmp(name, "anomaly_similarity_threshold")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_anomaly_similarity_threshold);
		return strdup(buf);
	}
	if (!strcmp(name, "anomaly_rate_limit")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_anomaly_rate_limit);
		return strdup(buf);
	}
	if (!strcmp(name, "anomaly_auto_block")) {
		return strdup(variables.genai_anomaly_auto_block ? "true" : "false");
	}
	if (!strcmp(name, "anomaly_log_only")) {
		return strdup(variables.genai_anomaly_log_only ? "true" : "false");
	}

	// Hybrid model routing
	if (!strcmp(name, "prefer_local_models")) {
		return strdup(variables.genai_prefer_local_models ? "true" : "false");
	}
	if (!strcmp(name, "daily_budget_usd")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%.2f", variables.genai_daily_budget_usd);
		return strdup(buf);
	}
	if (!strcmp(name, "max_cloud_requests_per_hour")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_max_cloud_requests_per_hour);
		return strdup(buf);
	}

	// Vector storage configuration
	if (!strcmp(name, "vector_db_path")) {
		return strdup(variables.genai_vector_db_path ? variables.genai_vector_db_path : "");
	}
	if (!strcmp(name, "vector_dimension")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_vector_dimension);
		return strdup(buf);
	}

	// RAG configuration
	if (!strcmp(name, "rag_enabled")) {
		return strdup(variables.genai_rag_enabled ? "true" : "false");
	}
	if (!strcmp(name, "rag_k_max")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_rag_k_max);
		return strdup(buf);
	}
	if (!strcmp(name, "rag_candidates_max")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_rag_candidates_max);
		return strdup(buf);
	}
	if (!strcmp(name, "rag_query_max_bytes")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_rag_query_max_bytes);
		return strdup(buf);
	}
	if (!strcmp(name, "rag_response_max_bytes")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_rag_response_max_bytes);
		return strdup(buf);
	}
	if (!strcmp(name, "rag_timeout_ms")) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", variables.genai_rag_timeout_ms);
		return strdup(buf);
	}

	return NULL;
}

bool GenAI_Threads_Handler::set_variable(char* name, const char* value) {
	if (!name || !value)
		return false;

	// Original GenAI variables
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
	if (!strcmp(name, "embedding_model")) {
		if (variables.genai_embedding_model)
			free(variables.genai_embedding_model);
		variables.genai_embedding_model = strdup(value);
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

	// AI Features master switches
	if (!strcmp(name, "enabled")) {
		variables.genai_enabled = (strcmp(value, "true") == 0);
		return true;
	}
	if (!strcmp(name, "llm_enabled")) {
		variables.genai_llm_enabled = (strcmp(value, "true") == 0);
		return true;
	}
	if (!strcmp(name, "anomaly_enabled")) {
		variables.genai_anomaly_enabled = (strcmp(value, "true") == 0);
		return true;
	}

	// LLM configuration
	if (!strcmp(name, "llm_provider")) {
		if (variables.genai_llm_provider)
			free(variables.genai_llm_provider);
		variables.genai_llm_provider = strdup(value);
		return true;
	}
	if (!strcmp(name, "llm_provider_url")) {
		if (variables.genai_llm_provider_url)
			free(variables.genai_llm_provider_url);
		variables.genai_llm_provider_url = strdup(value);
		return true;
	}
	if (!strcmp(name, "llm_provider_model")) {
		if (variables.genai_llm_provider_model)
			free(variables.genai_llm_provider_model);
		variables.genai_llm_provider_model = strdup(value);
		return true;
	}
	if (!strcmp(name, "llm_provider_key")) {
		if (variables.genai_llm_provider_key)
			free(variables.genai_llm_provider_key);
		variables.genai_llm_provider_key = strdup(value);
		return true;
	}
	if (!strcmp(name, "llm_cache_similarity_threshold")) {
		int val = atoi(value);
		if (val < 0 || val > 100) {
			proxy_error("Invalid value for genai_llm_cache_similarity_threshold: %d (must be 0-100)\n", val);
			return false;
		}
		variables.genai_llm_cache_similarity_threshold = val;
		return true;
	}
	if (!strcmp(name, "llm_cache_enabled")) {
		variables.genai_llm_cache_enabled = (strcmp(value, "true") == 0);
		return true;
	}
	if (!strcmp(name, "llm_timeout_ms")) {
		int val = atoi(value);
		if (val < 1000 || val > 600000) {
			proxy_error("Invalid value for genai_llm_timeout_ms: %d (must be 1000-600000)\n", val);
			return false;
		}
		variables.genai_llm_timeout_ms = val;
		return true;
	}

	// Anomaly detection configuration
	if (!strcmp(name, "anomaly_risk_threshold")) {
		int val = atoi(value);
		if (val < 0 || val > 100) {
			proxy_error("Invalid value for genai_anomaly_risk_threshold: %d (must be 0-100)\n", val);
			return false;
		}
		variables.genai_anomaly_risk_threshold = val;
		return true;
	}
	if (!strcmp(name, "anomaly_similarity_threshold")) {
		int val = atoi(value);
		if (val < 0 || val > 100) {
			proxy_error("Invalid value for genai_anomaly_similarity_threshold: %d (must be 0-100)\n", val);
			return false;
		}
		variables.genai_anomaly_similarity_threshold = val;
		return true;
	}
	if (!strcmp(name, "anomaly_rate_limit")) {
		int val = atoi(value);
		if (val < 1 || val > 10000) {
			proxy_error("Invalid value for genai_anomaly_rate_limit: %d (must be 1-10000)\n", val);
			return false;
		}
		variables.genai_anomaly_rate_limit = val;
		return true;
	}
	if (!strcmp(name, "anomaly_auto_block")) {
		variables.genai_anomaly_auto_block = (strcmp(value, "true") == 0);
		return true;
	}
	if (!strcmp(name, "anomaly_log_only")) {
		variables.genai_anomaly_log_only = (strcmp(value, "true") == 0);
		return true;
	}

	// Hybrid model routing
	if (!strcmp(name, "prefer_local_models")) {
		variables.genai_prefer_local_models = (strcmp(value, "true") == 0);
		return true;
	}
	if (!strcmp(name, "daily_budget_usd")) {
		double val = atof(value);
		if (val < 0 || val > 10000) {
			proxy_error("Invalid value for genai_daily_budget_usd: %.2f (must be 0-10000)\n", val);
			return false;
		}
		variables.genai_daily_budget_usd = val;
		return true;
	}
	if (!strcmp(name, "max_cloud_requests_per_hour")) {
		int val = atoi(value);
		if (val < 0 || val > 100000) {
			proxy_error("Invalid value for genai_max_cloud_requests_per_hour: %d (must be 0-100000)\n", val);
			return false;
		}
		variables.genai_max_cloud_requests_per_hour = val;
		return true;
	}

	// Vector storage configuration
	if (!strcmp(name, "vector_db_path")) {
		if (variables.genai_vector_db_path)
			free(variables.genai_vector_db_path);
		variables.genai_vector_db_path = strdup(value);
		return true;
	}
	if (!strcmp(name, "vector_dimension")) {
		int val = atoi(value);
		if (val < 1 || val > 100000) {
			proxy_error("Invalid value for genai_vector_dimension: %d (must be 1-100000)\n", val);
			return false;
		}
		variables.genai_vector_dimension = val;
		return true;
	}

	// RAG configuration
	if (!strcmp(name, "rag_enabled")) {
		variables.genai_rag_enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
		return true;
	}
	if (!strcmp(name, "rag_k_max")) {
		int val = atoi(value);
		if (val < 1 || val > 1000) {
			proxy_error("Invalid value for rag_k_max: %d (must be 1-1000)\n", val);
			return false;
		}
		variables.genai_rag_k_max = val;
		return true;
	}
	if (!strcmp(name, "rag_candidates_max")) {
		int val = atoi(value);
		if (val < 1 || val > 5000) {
			proxy_error("Invalid value for rag_candidates_max: %d (must be 1-5000)\n", val);
			return false;
		}
		variables.genai_rag_candidates_max = val;
		return true;
	}
	if (!strcmp(name, "rag_query_max_bytes")) {
		int val = atoi(value);
		if (val < 1 || val > 1000000) {
			proxy_error("Invalid value for rag_query_max_bytes: %d (must be 1-1000000)\n", val);
			return false;
		}
		variables.genai_rag_query_max_bytes = val;
		return true;
	}
	if (!strcmp(name, "rag_response_max_bytes")) {
		int val = atoi(value);
		if (val < 1 || val > 10000000) {
			proxy_error("Invalid value for rag_response_max_bytes: %d (must be 1-10000000)\n", val);
			return false;
		}
		variables.genai_rag_response_max_bytes = val;
		return true;
	}
	if (!strcmp(name, "rag_timeout_ms")) {
		int val = atoi(value);
		if (val < 1 || val > 60000) {
			proxy_error("Invalid value for rag_timeout_ms: %d (must be 1-60000)\n", val);
			return false;
		}
		variables.genai_rag_timeout_ms = val;
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

bool GenAI_Threads_Handler::has_variable(const char* name) {
	if (!name)
		return false;

	// Check if name exists in genai_thread_variables_names
	for (int i = 0; genai_thread_variables_names[i]; i++) {
		if (!strcmp(name, genai_thread_variables_names[i]))
			return true;
	}

	return false;
}

void GenAI_Threads_Handler::print_version() {
	fprintf(stderr, "GenAI Threads Handler rev. %s -- %s -- %s\n", GENAI_THREAD_VERSION, __FILE__, __TIMESTAMP__);
}

/**
 * @brief Register a client file descriptor for async GenAI communication
 *
 * This function is called by MySQL_Session to register the GenAI side of a
 * socketpair for receiving async GenAI requests. The fd is added to the
 * GenAI module's epoll instance so the listener thread can monitor it for
 * incoming requests.
 *
 * Registration flow:
 * 1. MySQL_Session creates socketpair(fds)
 * 2. MySQL_Session keeps fds[0] for reading responses
 * 3. MySQL_Session calls this function with fds[1] (GenAI side)
 * 4. This function adds fds[1] to client_fds_ set and to epoll_fd_
 * 5. GenAI listener can now receive requests via fds[1]
 *
 * The fd is set to non-blocking mode to prevent the listener from blocking
 * on a slow client.
 *
 * @param client_fd The GenAI side file descriptor from socketpair (typically fds[1])
 * @return true if successfully registered and added to epoll, false on error
 *
 * @see unregister_client(), listener_loop()
 */
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

/**
 * @brief Unregister a client file descriptor from GenAI module
 *
 * This function is called when a MySQL session ends or an error occurs
 * to clean up the socketpair connection. It removes the fd from the
 * GenAI module's epoll instance and closes the connection.
 *
 * Cleanup flow:
 * 1. Remove fd from epoll_fd_ monitoring
 * 2. Remove fd from client_fds_ set
 * 3. Close the file descriptor
 *
 * This is typically called when:
 * - MySQL session ends (client disconnect)
 * - Socketpair communication error occurs
 * - Session cleanup during shutdown
 *
 * @param client_fd The GenAI side file descriptor to remove (typically fds[1])
 *
 * @see register_client(), listener_loop()
 */
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

/**
 * @brief Generate embeddings for multiple documents via HTTP to llama-server
 *
 * This function sends a batch embedding request to the configured embedding service
 * (genai_embedding_uri) via libcurl. The request is sent as JSON with an "input" array
 * containing all documents to embed.
 *
 * Request format:
 * ```json
 * {
 *   "input": ["document 1", "document 2", ...]
 * }
 * ```
 *
 * Response format (parsed):
 * ```json
 * {
 *   "results": [
 *     {"embedding": [0.1, 0.2, ...]},
 *     {"embedding": [0.3, 0.4, ...]}
 *   ]
 * }
 * ```
 *
 * The function handles:
 * - JSON escaping for special characters (quotes, backslashes, newlines, tabs)
 * - HTTP POST request with Content-Type: application/json
 * - Timeout enforcement via genai_embedding_timeout_ms
 * - JSON response parsing to extract embedding arrays
 * - Contiguous memory allocation for result embeddings
 *
 * Error handling:
 * - On curl error: returns empty result, increments failed_requests
 * - On parse error: returns empty result, increments failed_requests
 * - On success: increments completed_requests
 *
 * @param texts Vector of document texts to embed (each can be up to several KB)
 * @return GenAI_EmbeddingResult containing all embeddings with metadata.
 *         The caller takes ownership of the returned data and must free it.
 *         Returns empty result (data==nullptr || count==0) on error.
 *
 * @note This is a BLOCKING call (curl_easy_perform blocks). Should only be called
 *       from worker threads, not MySQL threads. Use embed_documents() wrapper instead.
 * @see embed_documents(), call_llama_rerank()
 */
GenAI_EmbeddingResult GenAI_Threads_Handler::call_llama_batch_embedding(const std::vector<std::string>& texts) {
	GenAI_EmbeddingResult result;
	CURL* curl = curl_easy_init();

	if (!curl) {
		proxy_error("Failed to initialize curl\n");
		status_variables.failed_requests++;
		return result;
	}

	// Build JSON request using nlohmann/json
	json payload;
	payload["input"] = texts;
	payload["model"] = std::string(variables.genai_embedding_model);
	std::string json_str = payload.dump();

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

	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		proxy_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		status_variables.failed_requests++;
	} else {
		// Parse JSON response using nlohmann/json
		try {
			json response_json = json::parse(response_data);

			std::vector<std::vector<float>> all_embeddings;

			// Handle different response formats
			if (response_json.contains("results") && response_json["results"].is_array()) {
				// Format: {"results": [{"embedding": [...]}, ...]}
				for (const auto& result_item : response_json["results"]) {
					if (result_item.contains("embedding") && result_item["embedding"].is_array()) {
						std::vector<float> embedding = result_item["embedding"].get<std::vector<float>>();
						all_embeddings.push_back(std::move(embedding));
					}
				}
			} else if (response_json.contains("data") && response_json["data"].is_array()) {
				// Format: {"data": [{"embedding": [...]}]}
				for (const auto& item : response_json["data"]) {
					if (item.contains("embedding") && item["embedding"].is_array()) {
						std::vector<float> embedding = item["embedding"].get<std::vector<float>>();
						all_embeddings.push_back(std::move(embedding));
					}
				}
			} else if (response_json.contains("embeddings") && response_json["embeddings"].is_array()) {
				// Format: {"embeddings": [[...], ...]}
				all_embeddings = response_json["embeddings"].get<std::vector<std::vector<float>>>();
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
		} catch (const json::parse_error& e) {
			proxy_error("Failed to parse embedding response JSON: %s\n", e.what());
			status_variables.failed_requests++;
		} catch (const std::exception& e) {
			proxy_error("Error processing embedding response: %s\n", e.what());
			status_variables.failed_requests++;
		}
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	return result;
}

/**
 * @brief Rerank documents based on query relevance via HTTP to llama-server
 *
 * This function sends a reranking request to the configured reranking service
 * (genai_rerank_uri) via libcurl. The request is sent as JSON with a query
 * and documents array. The service returns documents sorted by relevance to the query.
 *
 * Request format:
 * ```json
 * {
 *   "query": "search query here",
 *   "documents": ["doc 1", "doc 2", ...]
 * }
 * ```
 *
 * Response format (parsed):
 * ```json
 * {
 *   "results": [
 *     {"index": 3, "relevance_score": 0.95},
 *     {"index": 0, "relevance_score": 0.82},
 *     ...
 *   ]
 * }
 * ```
 *
 * The function handles:
 * - JSON escaping for special characters in query and documents
 * - HTTP POST request with Content-Type: application/json
 * - Timeout enforcement via genai_rerank_timeout_ms
 * - JSON response parsing to extract results array
 * - Optional top_n limiting of results
 *
 * Error handling:
 * - On curl error: returns empty result, increments failed_requests
 * - On parse error: returns empty result, increments failed_requests
 * - On success: increments completed_requests
 *
 * @param query Query string to rerank against (e.g., search query, user question)
 * @param texts Vector of document texts to rerank (typically search results)
 * @param top_n Maximum number of top results to return (0 = return all sorted results)
 * @return GenAI_RerankResultArray containing results sorted by relevance.
 *         Each result includes the original document index and a relevance score.
 *         The caller takes ownership of the returned data and must free it.
 *         Returns empty result (data==nullptr || count==0) on error.
 *
 * @note This is a BLOCKING call (curl_easy_perform blocks). Should only be called
 *       from worker threads, not MySQL threads. Use rerank_documents() wrapper instead.
 * @see rerank_documents(), call_llama_batch_embedding()
 */
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

	// Build JSON request using nlohmann/json
	json payload;
	payload["query"] = query;
	payload["documents"] = texts;
	std::string json_str = payload.dump();

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
		// Parse JSON response using nlohmann/json
		try {
			json response_json = json::parse(response_data);

			std::vector<GenAI_RerankResult> results;

			// Handle different response formats
			if (response_json.contains("results") && response_json["results"].is_array()) {
				// Format: {"results": [{"index": 0, "relevance_score": 0.95}, ...]}
				for (const auto& result_item : response_json["results"]) {
					GenAI_RerankResult r;
					r.index = result_item.value("index", 0);
					// Support both "relevance_score" and "score" field names
					if (result_item.contains("relevance_score")) {
						r.score = result_item.value("relevance_score", 0.0f);
					} else {
						r.score = result_item.value("score", 0.0f);
					}
					results.push_back(r);
				}
			} else if (response_json.contains("data") && response_json["data"].is_array()) {
				// Alternative format: {"data": [...]}
				for (const auto& result_item : response_json["data"]) {
					GenAI_RerankResult r;
					r.index = result_item.value("index", 0);
					// Support both "relevance_score" and "score" field names
					if (result_item.contains("relevance_score")) {
						r.score = result_item.value("relevance_score", 0.0f);
					} else {
						r.score = result_item.value("score", 0.0f);
					}
					results.push_back(r);
				}
			}

			// Apply top_n limit if specified
			if (!results.empty() && top_n > 0 && top_n < results.size()) {
				result.count = top_n;
				result.data = new GenAI_RerankResult[top_n];
				std::copy(results.begin(), results.begin() + top_n, result.data);
			} else if (!results.empty()) {
				result.count = results.size();
				result.data = new GenAI_RerankResult[results.size()];
				std::copy(results.begin(), results.end(), result.data);
			}

			if (!results.empty()) {
				status_variables.completed_requests++;
			} else {
				status_variables.failed_requests++;
			}
		} catch (const json::parse_error& e) {
			proxy_error("Failed to parse rerank response JSON: %s\n", e.what());
			status_variables.failed_requests++;
		} catch (const std::exception& e) {
			proxy_error("Error processing rerank response: %s\n", e.what());
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
// Worker and listener loops (for async socket pair integration)
// ============================================================================

/**
 * @brief GenAI listener thread main loop
 *
 * This function runs in a dedicated thread and monitors registered client file
 * descriptors via epoll for incoming GenAI requests from MySQL sessions.
 *
 * Workflow:
 * 1. Wait for events on epoll_fd_ (100ms timeout for shutdown check)
 * 2. When event occurs on client fd:
 *    - Read GenAI_RequestHeader
 *    - Read JSON query (if query_len > 0)
 *    - Build GenAI_Request and queue to request_queue_
 *    - Notify worker thread via condition variable
 * 3. Handle client disconnection and errors
 *
 * Communication protocol:
 * - Client sends: GenAI_RequestHeader (fixed size) + JSON query (variable size)
 * - Header includes: request_id, operation, query_len, flags, top_n
 *
 * This thread ensures that MySQL sessions never block - they send requests
 * via socketpair and immediately return to handling other queries. The actual
 * blocking HTTP calls to llama-server happen in worker threads.
 *
 * @note Runs in dedicated listener_thread_ created during init()
 * @see worker_loop(), register_client(), process_json_query()
 */
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

			int client_fd = events[i].data.fd;

			// Read request header
			GenAI_RequestHeader header;
			ssize_t n = read(client_fd, &header, sizeof(header));

			if (n < 0) {
				// Check for non-blocking read - not an error, just no data yet
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					continue;
				}
				// Real error - log and close connection
				proxy_error("GenAI: Error reading from client fd %d: %s\n",
							client_fd, strerror(errno));
				epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, client_fd, nullptr);
				close(client_fd);
				{
					std::lock_guard<std::mutex> lock(clients_mutex_);
					client_fds_.erase(client_fd);
				}
				continue;
			}

			if (n == 0) {
				// Client disconnected (EOF)
				epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, client_fd, nullptr);
				close(client_fd);
				{
					std::lock_guard<std::mutex> lock(clients_mutex_);
					client_fds_.erase(client_fd);
				}
				continue;
			}

			if (n != sizeof(header)) {
				proxy_error("GenAI: Incomplete header read from fd %d: got %zd, expected %zu\n",
							client_fd, n, sizeof(header));
				continue;
			}

			// Read JSON query if present
			std::string json_query;
			if (header.query_len > 0) {
				json_query.resize(header.query_len);
				size_t total_read = 0;
				while (total_read < header.query_len) {
					ssize_t r = read(client_fd, &json_query[total_read],
									 header.query_len - total_read);
					if (r <= 0) {
						if (errno == EAGAIN || errno == EWOULDBLOCK) {
							usleep(1000);  // Wait 1ms and retry
							continue;
						}
						proxy_error("GenAI: Error reading JSON query from fd %d: %s\n",
									client_fd, strerror(errno));
						break;
					}
					total_read += r;
				}
			}

			// Build request and queue it
			GenAI_Request req;
			req.client_fd = client_fd;
			req.request_id = header.request_id;
			req.operation = header.operation;
			req.top_n = header.top_n;
			req.json_query = json_query;

			{
				std::lock_guard<std::mutex> lock(queue_mutex_);
				request_queue_.push(std::move(req));
			}

			queue_cv_.notify_one();

			proxy_debug(PROXY_DEBUG_GENAI, 3,
						"GenAI: Queued request %lu from fd %d (op=%u, query_len=%u)\n",
						header.request_id, client_fd, header.operation, header.query_len);
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

/**
 * @brief GenAI worker thread main loop
 *
 * This function runs in worker thread pool and processes GenAI requests
 * from the request queue. Each worker handles:
 * - JSON query parsing
 * - HTTP requests to embedding/reranking services (via libcurl)
 * - Response formatting and sending back via socketpair
 *
 * Workflow:
 * 1. Wait on request_queue_ with condition variable (shutdown-safe)
 * 2. Dequeue GenAI_Request
 * 3. Process the JSON query via process_json_query()
 *    - This may involve HTTP calls to llama-server (blocking in worker thread)
 * 4. Format response as GenAI_ResponseHeader + JSON result
 * 5. Write response back to client via socketpair
 * 6. Update status variables (completed_requests, failed_requests)
 *
 * The blocking HTTP calls (curl_easy_perform) happen in this worker thread,
 * NOT in the MySQL thread. This is the key to non-blocking behavior - MySQL
 * sessions can continue processing other queries while workers wait for HTTP responses.
 *
 * Error handling:
 * - On write error: cleanup request and mark as failed
 * - On process_json_query error: send error response
 * - Client fd cleanup on any error
 *
 * @param worker_id Worker thread identifier (0-based index for logging)
 *
 * @note Runs in worker_threads_[worker_id] created during init()
 * @see listener_loop(), process_json_query(), GenAI_Request
 */
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
		// Check shutdown again before processing (in case shutdown was signaled while we were waiting)
		if (shutdown_) {
			// Close client_fd to avoid leaking it
			close(req.client_fd);
			{
				std::lock_guard<std::mutex> client_lock(clients_mutex_);
				client_fds_.erase(req.client_fd);
			}
			break;
		}
		lock.unlock();  // Release the lock (not release() which would detach without unlocking)

		// Process request
		auto start_time = std::chrono::steady_clock::now();

		proxy_debug(PROXY_DEBUG_GENAI, 3,
					"Worker %d processing request %lu (op=%u)\n",
					worker_id, req.request_id, req.operation);

		// Process the JSON query
		std::string json_result = process_json_query(req.json_query);

		auto end_time = std::chrono::steady_clock::now();
		int processing_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			end_time - start_time).count();

		// Prepare response header
		GenAI_ResponseHeader resp;
		resp.request_id = req.request_id;
		resp.status_code = json_result.empty() ? 1 : 0;
		resp.result_len = json_result.length();
		resp.processing_time_ms = processing_time_ms;
		resp.result_ptr = 0;  // Not using shared memory
		resp.result_count = 0;
		resp.reserved = 0;

		// Send response header
		ssize_t written = write(req.client_fd, &resp, sizeof(resp));
		if (written != sizeof(resp)) {
			proxy_error("GenAI: Failed to write response header to fd %d: %s\n",
						req.client_fd, strerror(errno));
			status_variables.failed_requests++;
			close(req.client_fd);
			{
				std::lock_guard<std::mutex> lock(clients_mutex_);
				client_fds_.erase(req.client_fd);
			}
			continue;
		}

		// Send JSON result
		if (resp.result_len > 0) {
			size_t total_written = 0;
			while (total_written < json_result.length()) {
				ssize_t w = write(req.client_fd,
								  json_result.data() + total_written,
								  json_result.length() - total_written);
				if (w <= 0) {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						usleep(1000);  // Wait 1ms and retry
						continue;
					}
					proxy_error("GenAI: Failed to write JSON result to fd %d: %s\n",
								req.client_fd, strerror(errno));
					status_variables.failed_requests++;
					break;
				}
				total_written += w;
			}
		}

		status_variables.completed_requests++;

		proxy_debug(PROXY_DEBUG_GENAI, 3,
					"Worker %d completed request %lu (status=%u, result_len=%u, time=%dms)\n",
					worker_id, req.request_id, resp.status_code, resp.result_len, processing_time_ms);
	}

	proxy_debug(PROXY_DEBUG_GENAI, 3, "GenAI worker thread %d stopped\n", worker_id);
}

/**
 * @brief Execute SQL query to retrieve documents for reranking
 *
 * This helper function is used by the document_from_sql feature to execute
 * a SQL query and retrieve documents from a database for reranking.
 *
 * The SQL query should return a single column containing document text.
 * For example:
 * ```sql
 * SELECT content FROM posts WHERE category = 'tech'
 * ```
 *
 * Note: This function is currently a stub and needs MySQL connection handling
 * to be implemented. The document_from_sql feature cannot be used until this
 * is implemented.
 *
 * @param sql_query SQL query string to execute (should select document text)
 * @return Pair of (success, vector of documents). On success, returns (true, documents).
 *         On failure, returns (false, empty vector).
 *
 * @todo Implement MySQL connection handling for document_from_sql feature
 */
static std::pair<bool, std::vector<std::string>> execute_sql_for_documents(const std::string& sql_query) {
	std::vector<std::string> documents;

	// TODO: Implement MySQL connection handling
	// For now, return error indicating this needs MySQL connectivity
	return {false, {}};
}

/**
 * @brief Process JSON query autonomously (handles embed/rerank/document_from_sql)
 *
 * This method is the main entry point for processing GenAI JSON queries from
 * MySQL sessions. It parses the JSON, determines the operation type, and routes
 * to the appropriate handler (embedding or reranking).
 *
 * Supported query formats:
 *
 * 1. Embed operation:
 * ```json
 * {
 *   "type": "embed",
 *   "documents": ["doc1 text", "doc2 text", ...]
 * }
 * ```
 * Response: `{"columns": ["embedding"], "rows": [["0.1,0.2,..."], ...]}`
 *
 * 2. Rerank with direct documents:
 * ```json
 * {
 *   "type": "rerank",
 *   "query": "search query",
 *   "documents": ["doc1", "doc2", ...],
 *   "top_n": 5,
 *   "columns": 3
 * }
 * ```
 * Response: `{"columns": ["index", "score", "document"], "rows": [[0, 0.95, "doc1"], ...]}`
 *
 * 3. Rerank with SQL documents (not yet implemented):
 * ```json
 * {
 *   "type": "rerank",
 *   "query": "search query",
 *   "document_from_sql": {"query": "SELECT content FROM posts WHERE ..."},
 *   "top_n": 5
 * }
 * ```
 *
 * Response format:
 * - Success: `{"columns": [...], "rows": [[...], ...]}`
 * - Error: `{"error": "error message"}`
 *
 * The response format matches MySQL resultset format for easy conversion to
 * MySQL result packets in MySQL_Session.
 *
 * @param json_query JSON query string from client (must be valid JSON)
 * @return JSON string result with columns and rows formatted for MySQL resultset.
 *         Returns error JSON string on failure.
 *
 * @note This method is called from worker threads as part of async request processing.
 *       The blocking HTTP calls (embed_documents, rerank_documents) occur in the
 *       worker thread, not the MySQL thread.
 *
 * @see embed_documents(), rerank_documents(), worker_loop()
 */
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

		// Handle llm operation
		if (op_type == "llm") {
			// Check if AI manager is available
			if (!GloAI) {
				result["error"] = "AI features manager is not initialized";
				return result.dump();
			}

			// Extract prompt
			if (!query_json.contains("prompt") || !query_json["prompt"].is_string()) {
				result["error"] = "LLM operation requires a 'prompt' string";
				return result.dump();
			}
			std::string prompt = query_json["prompt"].get<std::string>();

			if (prompt.empty()) {
				result["error"] = "LLM prompt cannot be empty";
				return result.dump();
			}

			// Extract optional system message
			std::string system_message;
			if (query_json.contains("system_message") && query_json["system_message"].is_string()) {
				system_message = query_json["system_message"].get<std::string>();
			}

			// Extract optional cache flag
			bool allow_cache = true;
			if (query_json.contains("allow_cache") && query_json["allow_cache"].is_boolean()) {
				allow_cache = query_json["allow_cache"].get<bool>();
			}

			// Get LLM bridge
			LLM_Bridge* llm_bridge = GloAI->get_llm_bridge();
			if (!llm_bridge) {
				result["error"] = "LLM bridge is not initialized";
				return result.dump();
			}

			// Build LLM request
			LLMRequest req;
			req.prompt = prompt;
			req.system_message = system_message;
			req.allow_cache = allow_cache;
			req.max_latency_ms = 0; // No specific latency requirement

			// Process (this will use cache if available)
			LLMResult llm_result = llm_bridge->process(req);

			if (!llm_result.error_code.empty()) {
				result["error"] = "LLM processing failed: " + llm_result.error_details;
				return result.dump();
			}

			// Build result - return as single row with text_response
			result["columns"] = json::array({"text_response", "explanation", "cached", "provider"});

			json rows = json::array();
			json row = json::array();
			row.push_back(llm_result.text_response);
			row.push_back(llm_result.explanation);
			row.push_back(llm_result.cached ? "true" : "false");
			row.push_back(llm_result.provider_used);

			rows.push_back(row);
			result["rows"] = rows;

			return result.dump();
		}

		// Unknown operation type
		result["error"] = "Unknown operation type: " + op_type + ". Use 'embed', 'rerank', or 'llm'";
		return result.dump();

	} catch (const json::parse_error& e) {
		result["error"] = std::string("JSON parse error: ") + e.what();
		return result.dump();
	} catch (const std::exception& e) {
		result["error"] = std::string("Error: ") + e.what();
		return result.dump();
	}
}

std::vector<std::pair<std::string, std::string>> GenAI_Threads_Handler::collect_status_variables() {
	std::vector<std::pair<std::string, std::string>> vars;
	vars.push_back({"genai_threads_initialized", std::to_string(status_variables.threads_initialized)});
	vars.push_back({"genai_active_requests", std::to_string(status_variables.active_requests)});
	vars.push_back({"genai_completed_requests", std::to_string(status_variables.completed_requests)});
	vars.push_back({"genai_failed_requests", std::to_string(status_variables.failed_requests)});
	return vars;
}

#endif /* PROXYSQL40 */
