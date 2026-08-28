#ifndef PROXYSQL_QUERY_DIGEST_TOPK_H
#define PROXYSQL_QUERY_DIGEST_TOPK_H

#include <cstdint>
#include <string>
#include <vector>

/**
 * @file query_digest_topk.h
 * @brief Shared API types for in-memory query digest Top-K retrieval.
 *
 * These types are intentionally isolated from `query_processor.h` so they can
 * be consumed by Admin, MCP, and future modules without introducing include
 * cycles between `proxysql_admin.h` and Query Processor headers.
 */

/**
 * @brief Sort modes for query digest Top-K retrieval.
 *
 * The selected metric is used as the primary descending sort key.
 * Secondary deterministic tie-breakers are applied by the implementation
 * to keep output ordering stable across calls.
 */
enum class query_digest_sort_by_t {
	count_star,   ///< Sort by execution count.
	avg_time,     ///< Sort by average latency (`sum_time / count_star`).
	sum_time,     ///< Sort by cumulative latency.
	max_time,     ///< Sort by maximum observed latency.
	rows_sent     ///< Sort by cumulative rows sent.
};

/**
 * @brief Filter set for in-memory query digest Top-K lookup.
 *
 * All string filters are exact matches. Numeric filters are inclusive minima.
 */
struct query_digest_filter_opts_t {
	std::string schemaname {};        ///< Optional schema/database exact filter.
	std::string username {};          ///< Optional username exact filter.
	int hostgroup {-1};               ///< Optional hostgroup exact filter (`-1` disables).
	std::string match_digest_text {}; ///< Optional substring filter for digest text.
	bool digest_text_case_sensitive {false}; ///< Match mode for @ref match_digest_text.
	bool has_digest {false};          ///< Whether @ref digest filter is active.
	uint64_t digest {0};              ///< Optional digest exact filter.
	uint32_t min_count {0};           ///< Optional minimum `count_star`.
	uint64_t min_avg_time_us {0};     ///< Optional minimum average latency in microseconds.
};

/**
 * @brief Single query digest row returned by Top-K lookup.
 */
struct query_digest_topk_row_t {
	int hid {0};
	std::string schemaname {};
	std::string username {};
	std::string client_address {};
	uint64_t digest {0};
	std::string digest_text {};
	uint32_t count_star {0};
	uint64_t first_seen {0};          ///< Epoch seconds.
	uint64_t last_seen {0};           ///< Epoch seconds.
	uint64_t sum_time {0};
	uint64_t min_time {0};
	uint64_t max_time {0};
	uint64_t rows_affected {0};
	uint64_t rows_sent {0};
};

/**
 * @brief Result of in-memory query digest Top-K lookup.
 */
struct query_digest_topk_result_t {
	std::vector<query_digest_topk_row_t> rows {};  ///< Paged rows after sort/offset/limit.
	uint64_t matched_count {0};                    ///< Rows matching filters before pagination.
	uint64_t matched_total_queries {0};            ///< Sum of `count_star` over matched rows.
	uint64_t matched_total_time_us {0};            ///< Sum of `sum_time` over matched rows.
};

#endif /* __PROXYSQL_QUERY_DIGEST_TOPK_H */
