/**
 * @file vector_db_performance-t.cpp
 * @brief Deterministic vector-cache correctness and completion checks.
 */

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include "tap.h"

using std::string;
using std::vector;

namespace {

constexpr size_t EMBEDDING_DIMENSIONS = 1536;

uint64_t fnv1a(const string& text) {
	uint64_t hash = UINT64_C(14695981039346656037);
	for (unsigned char character : text) {
		hash ^= character;
		hash *= UINT64_C(1099511628211);
	}
	return hash;
}

uint64_t splitmix64(uint64_t& state) {
	state += UINT64_C(0x9e3779b97f4a7c15);
	uint64_t value = state;
	value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
	return value ^ (value >> 31);
}

vector<float> mock_generate_embedding(const string& text) {
	uint64_t state = fnv1a(text);
	vector<float> embedding;
	embedding.reserve(EMBEDDING_DIMENSIONS);

	for (size_t index = 0; index < EMBEDDING_DIMENSIONS; ++index) {
		const uint32_t sample = static_cast<uint32_t>(splitmix64(state) >> 40);
		const float normalized = static_cast<float>(sample) / 8388607.5f - 1.0f;
		embedding.push_back(normalized);
	}
	return embedding;
}

double cosine_similarity(const vector<float>& left, const vector<float>& right) {
	if (left.empty() || left.size() != right.size()) return 0.0;

	double dot_product = 0.0;
	double left_norm = 0.0;
	double right_norm = 0.0;
	for (size_t index = 0; index < left.size(); ++index) {
		dot_product += static_cast<double>(left[index]) * right[index];
		left_norm += static_cast<double>(left[index]) * left[index];
		right_norm += static_cast<double>(right[index]) * right[index];
	}
	if (left_norm == 0.0 || right_norm == 0.0) return 0.0;
	return dot_product / (std::sqrt(left_norm) * std::sqrt(right_norm));
}

struct MockCacheEntry {
	string natural_language;
	string generated_sql;
	vector<float> embedding;
};

struct LookupResult {
	long long elapsed_microseconds;
	string sql;
	double similarity;
	size_t embedding_dimensions;
};

class MockVectorDB {
public:
	explicit MockVectorDB(size_t maximum_entries = 10000)
		: max_entries(maximum_entries) {
		entries.reserve(maximum_entries);
	}

	void store_entry(const string& query, const string& sql) {
		if (entries.size() >= max_entries) entries.erase(entries.begin());
		entries.push_back({query, sql, mock_generate_embedding(query)});
	}

	LookupResult lookup_entry(const string& query, double threshold = 0.85) const {
		const auto start = std::chrono::steady_clock::now();
		const vector<float> query_embedding = mock_generate_embedding(query);
		double best_similarity = -1.0;
		string best_sql;

		for (const MockCacheEntry& entry : entries) {
			const double similarity = cosine_similarity(query_embedding, entry.embedding);
			if (similarity >= threshold && similarity > best_similarity) {
				best_similarity = similarity;
				best_sql = entry.generated_sql;
			}
		}

		const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::steady_clock::now() - start);
		return {
			elapsed.count(), best_sql, best_similarity, query_embedding.size()
		};
	}

	size_t size() const { return entries.size(); }

private:
	vector<MockCacheEntry> entries;
	size_t max_entries;
};

void test_embedding_contract() {
	const vector<float> first = mock_generate_embedding("distinct query 0");
	const vector<float> repeated = mock_generate_embedding("distinct query 0");
	const vector<float> distinct = mock_generate_embedding("distinct query 1");

	ok(first.size() == EMBEDDING_DIMENSIONS,
	   "Mock embedding has the full %zu-dimensional shape", EMBEDDING_DIMENSIONS);
	ok(first == repeated, "Identical text produces an identical deterministic embedding");
	ok(first != distinct, "Distinct text changes the deterministic embedding");

	const double self_similarity = cosine_similarity(first, repeated);
	const double distinct_similarity = cosine_similarity(first, distinct);
	ok(self_similarity > 0.999999 && self_similarity <= 1.000001,
	   "Identical embeddings have unit similarity (got %.8f)", self_similarity);
	ok(distinct_similarity < 0.99,
	   "Distinct embeddings stay below the 0.99 match threshold (got %.8f)",
	   distinct_similarity);
}

void test_distinct_query_regression() {
	MockVectorDB database;
	database.store_entry("distinct query 0", "SELECT 0");
	ok(database.size() == 1, "Regression fixture stores one vector entry");

	const LookupResult result = database.lookup_entry("distinct query 1", 0.99);
	ok(result.sql.empty(),
	   "Distinct query does not reuse an unrelated result at 0.99 similarity");
}

void test_workload(const char* label, size_t entry_count, size_t target) {
	MockVectorDB database(entry_count);
	const auto insert_start = std::chrono::steady_clock::now();
	for (size_t index = 0; index < entry_count; ++index) {
		database.store_entry(
			"Workload query " + std::to_string(index),
			"SELECT * FROM workload WHERE id=" + std::to_string(index));
	}
	const auto insert_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - insert_start);

	const LookupResult result = database.lookup_entry(
		"Workload query " + std::to_string(target), 0.99);
	const string expected_sql =
		"SELECT * FROM workload WHERE id=" + std::to_string(target);

	ok(database.size() == entry_count,
	   "%s workload stores all %zu entries", label, entry_count);
	ok(result.sql == expected_sql,
	   "%s workload returns the exact query result", label);
	ok(result.embedding_dimensions == EMBEDDING_DIMENSIONS,
	   "%s lookup uses the full vector shape", label);
	ok(result.similarity > 0.999999 && result.similarity <= 1.000001,
	   "%s exact lookup reports unit similarity (got %.8f)", label, result.similarity);
	ok(insert_elapsed.count() < 120000,
	   "%s workload completes insertion within 120 seconds (took %lld ms)",
	   label, static_cast<long long>(insert_elapsed.count()));
	ok(result.elapsed_microseconds < 30000000,
	   "%s workload completes lookup within 30 seconds (took %lld us)",
	   label, result.elapsed_microseconds);
}

} // namespace

int main() {
	plan(25);

	test_embedding_contract();
	test_distinct_query_regression();
	test_workload("small", 100, 50);
	test_workload("medium", 1000, 500);
	test_workload("large", 10000, 5000);

	return exit_status();
}
