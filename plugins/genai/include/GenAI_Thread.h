#ifndef PROXYSQL_GENAI_THREAD_H
#define PROXYSQL_GENAI_THREAD_H

#ifdef PROXYSQL40

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
#include <utility>

#define GENAI_THREAD_VERSION "0.1.0"

/**
 * @brief GenAI operation types
 */
enum GenAI_Operation : uint32_t {
	GENAI_OP_EMBEDDING = 0,  ///< Generate embeddings for documents
	GENAI_OP_RERANK = 1,     ///< Rerank documents by relevance to query
	GENAI_OP_JSON = 2,       ///< Autonomous JSON query processing (handles embed/rerank/document_from_sql)
	GENAI_OP_LLM = 3,        ///< Generic LLM bridge processing
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
 * @brief Request header for socketpair communication between MySQL_Session and GenAI
 *
 * This structure is sent from MySQL_Session to the GenAI listener via socketpair
 * when making async GenAI requests. It contains all the metadata needed to process
 * the request without blocking the MySQL thread.
 *
 * Communication flow:
 * 1. MySQL_Session creates socketpair()
 * 2. MySQL_Session sends GenAI_RequestHeader + JSON query via its fd
 * 3. GenAI listener reads from socketpair via epoll
 * 4. GenAI worker processes request (blocking curl in worker thread)
 * 5. GenAI worker sends GenAI_ResponseHeader + JSON result back via socketpair
 * 6. MySQL_Session receives response via epoll notification
 *
 * @see GenAI_ResponseHeader
 */
struct GenAI_RequestHeader {
	uint64_t request_id;      ///< Client's correlation ID for matching requests/responses
	uint32_t operation;       ///< Operation type (GENAI_OP_EMBEDDING, GENAI_OP_RERANK, GENAI_OP_JSON)
	uint32_t query_len;       ///< Length of JSON query that follows this header (0 if no query)
	uint32_t flags;           ///< Reserved for future use (must be 0)
	uint32_t top_n;           ///< For rerank operations: maximum number of results to return (0 = all)
};

/**
 * @brief Response header for socketpair communication from GenAI to MySQL_Session
 *
 * This structure is sent from the GenAI worker back to MySQL_Session via socketpair
 * after processing completes. It contains status information and metadata about
 * the results, followed by the JSON result payload.
 *
 * Response format:
 * - GenAI_ResponseHeader (this structure)
 * - JSON result data (result_len bytes if result_len > 0)
 *
 * @see GenAI_RequestHeader
 */
struct GenAI_ResponseHeader {
	uint64_t request_id;        ///< Echo of client's request ID for request/response matching
	uint32_t status_code;       ///< Status code: 0=success, >0=error occurred
	uint32_t result_len;        ///< Length of JSON result payload that follows this header
	uint32_t processing_time_ms;///< Time taken by GenAI worker to process the request (milliseconds)
	uint64_t result_ptr;        ///< Reserved for future shared memory optimizations (must be 0)
	uint32_t result_count;      ///< Number of results in the response (e.g., number of embeddings/reranks)
	uint32_t reserved;          ///< Reserved for future use (must be 0)
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
	std::atomic<int> shutdown_;
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
		char* genai_embedding_model;    ///< Embedding model name (default: empty)

		// Timeouts (in milliseconds)
		int genai_embedding_timeout_ms; ///< Timeout for embedding requests (default: 30000)
		int genai_rerank_timeout_ms;    ///< Timeout for reranking requests (default: 30000)

		// AI Features master switches
		bool genai_enabled;              ///< Master enable for all AI features (default: false)
		bool genai_llm_enabled;          ///< Enable LLM bridge feature (default: false)
		bool genai_anomaly_enabled;      ///< Enable anomaly detection (default: false)

		// LLM bridge configuration
		char* genai_llm_provider;            ///< Provider format: "openai" or "anthropic" (default: "openai")
		char* genai_llm_provider_url;        ///< LLM endpoint URL (default: http://localhost:11434/v1/chat/completions)
		char* genai_llm_provider_model;       ///< Model name (default: "llama3.2")
		char* genai_llm_provider_key;         ///< API key (default: NULL)
		int genai_llm_cache_similarity_threshold; ///< Semantic cache threshold 0-100 (default: 85)
		int genai_llm_cache_enabled;          ///< Enable semantic cache (default: true)
		int genai_llm_timeout_ms;             ///< LLM request timeout in ms (default: 30000)

		// Anomaly detection configuration
		int genai_anomaly_risk_threshold;      ///< Risk score threshold for blocking 0-100 (default: 70)
		int genai_anomaly_similarity_threshold; ///< Similarity threshold 0-100 (default: 80)
		int genai_anomaly_rate_limit;          ///< Max queries per minute (default: 100)
		bool genai_anomaly_auto_block;         ///< Auto-block suspicious queries (default: true)
		bool genai_anomaly_log_only;           ///< Log-only mode (default: false)

		// Hybrid model routing
		bool genai_prefer_local_models;        ///< Prefer local Ollama over cloud (default: true)
		double genai_daily_budget_usd;         ///< Daily cloud spend limit (default: 10.0)
		int genai_max_cloud_requests_per_hour; ///< Cloud API rate limit (default: 100)

		// Vector storage configuration
		char* genai_vector_db_path;            ///< Vector database file path (default: /var/lib/proxysql/ai_features.db)
		int genai_vector_dimension;            ///< Embedding dimension (default: 1536)

		// RAG configuration
		bool genai_rag_enabled;                ///< Enable RAG features (default: false)
		int genai_rag_k_max;                   ///< Maximum k for search results (default: 50)
		int genai_rag_candidates_max;          ///< Maximum candidates for hybrid search (default: 500)
		int genai_rag_query_max_bytes;         ///< Maximum query length in bytes (default: 8192)
		int genai_rag_response_max_bytes;      ///< Maximum response size in bytes (default: 5000000)
		int genai_rag_timeout_ms;              ///< RAG operation timeout in ms (default: 2000)
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
	 * @brief Check if a variable exists
	 *
	 * @param name The name of the variable to check
	 * @return true if the variable exists, false otherwise
	 */
	bool has_variable(const char* name);

	/**
	 * @brief Print the version information
	 */
	void print_version();

	/**
	 * @brief Register a client file descriptor with GenAI module for async communication
	 *
	 * Registers the GenAI side of a socketpair with the GenAI epoll instance.
	 * This allows the GenAI listener to receive requests from MySQL sessions asynchronously.
	 *
	 * Usage flow:
	 * 1. MySQL_Session creates socketpair(fds)
	 * 2. MySQL_Session keeps fds[0] for reading responses
	 * 3. MySQL_Session calls register_client(fds[1]) to register GenAI side
	 * 4. GenAI listener adds fds[1] to its epoll for reading requests
	 * 5. When request is received, it's queued to worker threads
	 *
	 * @param client_fd The GenAI side file descriptor from socketpair (typically fds[1])
	 * @return true if successfully registered and added to epoll, false on error
	 *
	 * @see unregister_client()
	 */
	bool register_client(int client_fd);

	/**
	 * @brief Unregister a client file descriptor from GenAI module
	 *
	 * Removes a previously registered client fd from the GenAI epoll instance
	 * and closes the connection. Called when a MySQL session ends or an error occurs.
	 *
	 * @param client_fd The GenAI side file descriptor to remove
	 *
	 * @see register_client()
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
	 * Sends the documents to the embedding service (configured via genai_embedding_uri)
	 * and returns the resulting embedding vectors. This method blocks until the
	 * embedding service responds (typically 10-100ms per document depending on model size).
	 *
	 * For async non-blocking behavior, use the socketpair-based async API via
	 * MySQL_Session's GENAI: query handler instead.
	 *
	 * @param documents Vector of document texts to embed (each can be up to several KB)
	 * @return GenAI_EmbeddingResult containing all embeddings with metadata.
	 *         The caller takes ownership of the returned data and must free it.
	 *         On error, returns an empty result (data==nullptr || count==0).
	 *
	 * @note This is a BLOCKING call. For async operation, use GENAI: queries through MySQL_Session.
	 * @see rerank_documents(), process_json_query()
	 */
	GenAI_EmbeddingResult embed_documents(const std::vector<std::string>& documents);

	/**
	 * @brief Rerank documents based on query relevance
	 *
	 * Sends the query and documents to the reranking service (configured via genai_rerank_uri)
	 * and returns the documents sorted by relevance to the query. This method blocks
	 * until the reranking service responds (typically 20-50ms for most models).
	 *
	 * For async non-blocking behavior, use the socketpair-based async API via
	 * MySQL_Session's GENAI: query handler instead.
	 *
	 * @param query Query string to rerank against (e.g., search query, user question)
	 * @param documents Vector of document texts to rerank (typically search results or candidates)
	 * @param top_n Maximum number of top results to return (0 = return all sorted results)
	 * @return GenAI_RerankResultArray containing results sorted by relevance.
	 *         Each result includes the original document index and a relevance score.
	 *         The caller takes ownership of the returned data and must free it.
	 *         On error, returns an empty result (data==nullptr || count==0).
	 *
	 * @note This is a BLOCKING call. For async operation, use GENAI: queries through MySQL_Session.
	 * @see embed_documents(), process_json_query()
	 */
	GenAI_RerankResultArray rerank_documents(const std::string& query,
											 const std::vector<std::string>& documents,
											 uint32_t top_n = 0);

	/**
	 * @brief Process JSON query autonomously (handles embed/rerank/document_from_sql)
	 *
	 * This method processes JSON queries that describe embedding or reranking operations.
	 * It autonomously parses the JSON, determines the operation type, and routes to the
	 * appropriate handler. This is the main entry point for the async GENAI: query syntax.
	 *
	 * Supported query formats:
	 * - {"type": "embed", "documents": ["doc1", "doc2", ...]}
	 * - {"type": "rerank", "query": "...", "documents": [...], "top_n": 5}
	 * - {"type": "rerank", "query": "...", "document_from_sql": {"query": "SELECT ..."}}
	 *
	 * The response format is a JSON object with "columns" and "rows" arrays:
	 * - {"columns": ["col1", "col2"], "rows": [["val1", "val2"], ...]}
	 * - Error responses: {"error": "error message"}
	 *
	 * @param json_query JSON query string from client (must be valid JSON)
	 * @return JSON string result with columns and rows formatted for MySQL resultset.
	 *         Returns empty string on error.
	 *
	 * @note This method is called from worker threads as part of async request processing.
	 *       The blocking HTTP calls occur in the worker thread, not the MySQL thread.
	 *
	 * @see embed_documents(), rerank_documents()
	 */
	std::string process_json_query(const std::string& json_query);

	std::vector<std::pair<std::string, std::string>> collect_status_variables();
};

// Global instance of the GenAI Threads Handler
extern GenAI_Threads_Handler *GloGATH;

#endif /* PROXYSQL40 */

#endif // __CLASS_GENAI_THREAD_H
