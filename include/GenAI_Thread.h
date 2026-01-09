#ifndef __CLASS_GENAI_THREAD_H
#define __CLASS_GENAI_THREAD_H

#include "proxysql.h"
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <unordered_set>
#include <thread>
#include <sys/socket.h>

#ifdef epoll_create1
#include <sys/epoll.h>
#endif

#include "curl/curl.h"

#define GENAI_THREAD_VERSION "0.1.0"

/**
 * @brief GenAI operation types
 */
enum GenAI_Operation : uint32_t {
	GENAI_OP_EMBEDDING = 0,  ///< Generate embeddings for documents
	GENAI_OP_RERANK = 1,     ///< Rerank documents by relevance to query
	GENAI_OP_JSON = 2,       ///< Autonomous JSON query processing (handles embed/rerank/document_from_sql)
};

/**
 * @brief Document structure for passing document data
 */
struct GenAI_Document {
	const char* text;     ///< Pointer to document text (owned by caller)
	size_t text_size;     ///< Length of text in bytes

	GenAI_Document() : text(nullptr), text_size(0) {}
	GenAI_Document(const char* t, size_t s) : text(t), text_size(s) {}
};

/**
 * @brief Embedding result structure
 */
struct GenAI_EmbeddingResult {
	float* data;          ///< Pointer to embedding vector
	size_t embedding_size;///< Number of floats per embedding
	size_t count;         ///< Number of embeddings

	GenAI_EmbeddingResult() : data(nullptr), embedding_size(0), count(0) {}
	~GenAI_EmbeddingResult();

	// Disable copy
	GenAI_EmbeddingResult(const GenAI_EmbeddingResult&) = delete;
	GenAI_EmbeddingResult& operator=(const GenAI_EmbeddingResult&) = delete;

	// Move semantics
	GenAI_EmbeddingResult(GenAI_EmbeddingResult&& other) noexcept;
	GenAI_EmbeddingResult& operator=(GenAI_EmbeddingResult&& other) noexcept;
};

/**
 * @brief Rerank result structure
 */
struct GenAI_RerankResult {
	uint32_t index;  ///< Original document index
	float score;     ///< Relevance score
};

/**
 * @brief Rerank result array structure
 */
struct GenAI_RerankResultArray {
	GenAI_RerankResult* data;  ///< Pointer to result array
	size_t count;              ///< Number of results

	GenAI_RerankResultArray() : data(nullptr), count(0) {}
	~GenAI_RerankResultArray();

	// Disable copy
	GenAI_RerankResultArray(const GenAI_RerankResultArray&) = delete;
	GenAI_RerankResultArray& operator=(const GenAI_RerankResultArray&) = delete;

	// Move semantics
	GenAI_RerankResultArray(GenAI_RerankResultArray&& other) noexcept;
	GenAI_RerankResultArray& operator=(GenAI_RerankResultArray&& other) noexcept;
};

/**
 * @brief Request structure for internal queue
 */
struct GenAI_Request {
	int client_fd;              ///< Client file descriptor
	uint64_t request_id;         ///< Request ID
	uint32_t operation;          ///< Operation type
	std::string query;           ///< Query for rerank (empty for embedding)
	uint32_t top_n;              ///< Top N results for rerank
	std::vector<GenAI_Document> documents;  ///< Documents to process
	std::string json_query;      ///< Raw JSON query from client (for autonomous processing)
};

/**
 * @brief Request header for socketpair communication
 *
 * Sent from MySQL_Session to GenAI listener via socketpair
 */
struct GenAI_RequestHeader {
	uint64_t request_id;      ///< Client's correlation ID
	uint32_t operation;       ///< Operation type (GENAI_OP_*)
	uint32_t query_len;       ///< Length of JSON query (0 for none)
	uint32_t flags;           ///< Reserved for future use
	uint32_t top_n;           ///< For rerank: number of top results
};

/**
 * @brief Response header for socketpair communication
 *
 * Sent from GenAI worker back to MySQL_Session via socketpair
 */
struct GenAI_ResponseHeader {
	uint64_t request_id;        ///< Echo client's request ID
	uint32_t status_code;       ///< 0=success, >0=error
	uint32_t result_len;        ///< Length of JSON result
	uint32_t processing_time_ms;///< Time taken to process
	uint64_t result_ptr;        ///< Pointer to result data (for shared memory, unused=0)
	uint32_t result_count;      ///< Number of results
	uint32_t reserved;          ///< Reserved for future use
};

/**
 * @brief GenAI Threads Handler class for managing GenAI module
 *
 * This class handles the GenAI module's configuration variables, lifecycle,
 * and provides embedding and reranking functionality via external services.
 */
class GenAI_Threads_Handler
{
private:
	int shutdown_;
	pthread_rwlock_t rwlock;

	// Threading components
	std::vector<pthread_t> worker_threads_;
	std::thread listener_thread_;
	std::queue<GenAI_Request> request_queue_;
	std::mutex queue_mutex_;
	std::condition_variable queue_cv_;
	std::unordered_set<int> client_fds_;
	std::mutex clients_mutex_;

	// epoll for async I/O
	int epoll_fd_;
	int event_fd_;

	// Worker methods
	void worker_loop(int worker_id);
	void listener_loop();

	// HTTP client methods
	GenAI_EmbeddingResult call_llama_embedding(const std::string& text);
	GenAI_EmbeddingResult call_llama_batch_embedding(const std::vector<std::string>& texts);
	GenAI_RerankResultArray call_llama_rerank(const std::string& query,
												const std::vector<std::string>& texts,
												uint32_t top_n);
	static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);

public:
	/**
	 * @brief Structure holding GenAI module configuration variables
	 */
	struct {
		// Thread configuration
		int genai_threads;              ///< Number of worker threads (default: 4)

		// Service endpoints
		char* genai_embedding_uri;      ///< URI for embedding service (default: http://127.0.0.1:8013/embedding)
		char* genai_rerank_uri;         ///< URI for reranking service (default: http://127.0.0.1:8012/rerank)

		// Timeouts (in milliseconds)
		int genai_embedding_timeout_ms; ///< Timeout for embedding requests (default: 30000)
		int genai_rerank_timeout_ms;    ///< Timeout for reranking requests (default: 30000)
	} variables;

	struct {
		int threads_initialized = 0;
		int active_requests = 0;
		int completed_requests = 0;
		int failed_requests = 0;
	} status_variables;

	unsigned int num_threads;

	/**
	 * @brief Default constructor for GenAI_Threads_Handler
	 */
	GenAI_Threads_Handler();

	/**
	 * @brief Destructor for GenAI_Threads_Handler
	 */
	~GenAI_Threads_Handler();

	/**
	 * @brief Initialize the GenAI module
	 *
	 * Starts worker threads and listener for processing requests.
	 *
	 * @param num Number of threads (uses genai_threads variable if 0)
	 * @param stack Stack size for threads (unused, reserved)
	 */
	void init(unsigned int num = 0, size_t stack = 0);

	/**
	 * @brief Shutdown the GenAI module
	 *
	 * Stops all threads and cleans up resources.
	 */
	void shutdown();

	/**
	 * @brief Acquire write lock on variables
	 */
	void wrlock();

	/**
	 * @brief Release write lock on variables
	 */
	void wrunlock();

	/**
	 * @brief Get the value of a variable as a string
	 *
	 * @param name The name of the variable (without 'genai-' prefix)
	 * @return Dynamically allocated string with the value, or NULL if not found
	 */
	char* get_variable(char* name);

	/**
	 * @brief Set the value of a variable
	 *
	 * @param name The name of the variable (without 'genai-' prefix)
	 * @param value The new value to set
	 * @return true if successful, false if variable not found or value invalid
	 */
	bool set_variable(char* name, const char* value);

	/**
	 * @brief Get a list of all variable names
	 *
	 * @return Dynamically allocated array of strings, terminated by NULL
	 */
	char** get_variables_list();

	/**
	 * @brief Print the version information
	 */
	void print_version();

	/**
	 * @brief Register a client file descriptor with GenAI
	 *
	 * @param client_fd File descriptor to monitor (from socketpair)
	 * @return true if successful, false otherwise
	 */
	bool register_client(int client_fd);

	/**
	 * @brief Unregister a client file descriptor
	 *
	 * @param client_fd File descriptor to remove
	 */
	void unregister_client(int client_fd);

	/**
	 * @brief Get current queue depth (number of pending requests)
	 *
	 * @return Number of requests in the queue
	 */
	size_t get_queue_size();

	// Public API methods for embedding and reranking
	// These methods can be called directly without going through socket pairs

	/**
	 * @brief Generate embeddings for multiple documents
	 *
	 * @param documents Vector of document texts to embed
	 * @return EmbeddingResult containing all embeddings
	 */
	GenAI_EmbeddingResult embed_documents(const std::vector<std::string>& documents);

	/**
	 * @brief Rerank documents based on query relevance
	 *
	 * @param query Query string to rerank against
	 * @param documents Vector of document texts to rerank
	 * @param top_n Maximum number of results to return (0 for all)
	 * @return RerankResultArray containing top N results
	 */
	GenAI_RerankResultArray rerank_documents(const std::string& query,
											 const std::vector<std::string>& documents,
											 uint32_t top_n = 0);

	/**
	 * @brief Process JSON query autonomously (handles embed/rerank/document_from_sql)
	 *
	 * @param json_query JSON query string from client
	 * @return JSON string result with columns and rows
	 */
	std::string process_json_query(const std::string& json_query);
};

// Global instance of the GenAI Threads Handler
extern GenAI_Threads_Handler *GloGATH;

#endif // __CLASS_GENAI_THREAD_H
