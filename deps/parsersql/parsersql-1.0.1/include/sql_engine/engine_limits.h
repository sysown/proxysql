#ifndef SQL_ENGINE_ENGINE_LIMITS_H
#define SQL_ENGINE_ENGINE_LIMITS_H

// engine_limits.h -- safety caps for materializing operators.
//
// Several operators (Sort, Aggregate, HashJoin, NestedLoopJoin, Distinct,
// SetOp, Window) materialize their input or build state into in-memory
// collections. Without a cap, a runaway query can exhaust available memory
// and bring down the whole process via SIGKILL.
//
// We don't have spill-to-disk yet. As a defensive measure, every
// materializing operator enforces a hard row-count cap and throws a clear
// std::runtime_error when it's exceeded. This converts a "process killed,
// no message" failure into "query exceeds engine memory limit".
//
// The cap is intentionally generous (10 million rows) so existing
// well-behaved queries are unaffected, but it's small enough that a single
// query can't allocate tens of gigabytes of row state. For operators with
// unusual storage shapes (HashJoin's hash table, Aggregate's group map)
// the same cap applies to the number of distinct entries, which is what
// actually drives memory usage.
//
// The cap can be raised globally by defining
// SQL_ENGINE_MAX_OPERATOR_ROWS at compile time, and individual call sites
// can pass a per-operator override via a setter (not currently exposed).

#include <cstddef>
#include <stdexcept>
#include <string>

namespace sql_engine {

#ifdef SQL_ENGINE_MAX_OPERATOR_ROWS
inline constexpr std::size_t kDefaultMaxOperatorRows = SQL_ENGINE_MAX_OPERATOR_ROWS;
#else
inline constexpr std::size_t kDefaultMaxOperatorRows = 10'000'000;
#endif

// Throws std::runtime_error with a clear message when an operator's
// materialized row/state count is about to exceed the cap. The op_name
// argument is the operator class name (used in the error message) so users
// can tell which operator hit the limit.
inline void check_operator_row_limit(std::size_t current_count,
                                     std::size_t limit,
                                     const char* op_name) {
    if (current_count >= limit) {
        throw std::runtime_error(
            std::string(op_name) +
            ": exceeded engine row limit (" + std::to_string(limit) +
            " rows / state entries). The engine does not yet spill large "
            "intermediate results to disk; raise the limit by defining "
            "SQL_ENGINE_MAX_OPERATOR_ROWS at compile time, or rewrite the "
            "query to bound the intermediate state.");
    }
}

} // namespace sql_engine

#endif // SQL_ENGINE_ENGINE_LIMITS_H
