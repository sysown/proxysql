#ifndef PROXYSQL_AI_VECTOR_STORAGE_H
#define PROXYSQL_AI_VECTOR_STORAGE_H

#ifdef PROXYSQL40

#define AI_VECTOR_STORAGE_VERSION "0.1.0"

#include "proxysql.h"
#include <string>
#include <vector>

/**
 * @brief AI Vector Storage
 *
 * Handles vector operations for NL2SQL cache and anomaly detection
 * using SQLite with sqlite-vec extension.
 *
 * Phase 1: Stub implementation
 * Phase 2: Full implementation with embedding generation and similarity search
 */
class AI_Vector_Storage {
private:
	std::string db_path;

public:
	AI_Vector_Storage(const char* path);
	~AI_Vector_Storage();

	int init();
	void close();

	// Vector operations (Phase 2)
	int store_embedding(const std::string& text, const std::vector<float>& embedding);
	std::vector<float> generate_embedding(const std::string& text);
	std::vector<std::pair<std::string, float>> search_similar(
		const std::string& query,
		float threshold,
		int limit
	);
};

#endif /* PROXYSQL40 */

#endif // __CLASS_AI_VECTOR_STORAGE_H
