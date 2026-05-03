#ifndef SQL_ENGINE_RESULT_SET_H
#define SQL_ENGINE_RESULT_SET_H

#include "sql_engine/row.h"
#include <vector>
#include <deque>
#include <memory>
#include <string>
#include <algorithm>
#include <utility>

namespace sql_engine {

class Operator;  // forward decl — ResultSet may extend operator lifetime

struct ResultSet {
    std::vector<Row> rows;
    std::vector<std::string> column_names;
    uint16_t column_count = 0;

    // Heap storage for row values and string data owned by this ResultSet.
    // Used by remote executors to avoid arena lifetime issues.
    std::vector<Value*> owned_value_arrays;

    // owned_strings MUST be a container with stable element addresses across
    // push_back. Previously this was std::vector<std::string>, which silently
    // corrupted any StringRef captured before a vector reallocation:
    // short strings (SSO) live INSIDE the std::string object, so when the
    // vector resized and move-constructed each std::string at a new address,
    // every previously-handed-out StringRef became a dangling pointer to
    // freed memory. That matches the garbled output observed in benchmarks
    // for short text columns. std::deque does not reallocate or move
    // existing elements on push_back, so pointers stay valid.
    std::deque<std::string> owned_strings;

    // Operators that produced rows in this ResultSet may own heap or
    // arena storage that the rows' Value* / StringRef pointers reference
    // (notably RemoteScanOperator's internal ResultSet returned from a
    // remote backend). Without keeping those operators alive past
    // PlanExecutor's stack scope, rows would dangle the moment
    // execute_query returned. Keeping them as opaque shared_ptr<void>
    // here avoids a circular include with operator.h while still
    // extending their lifetime to match this ResultSet.
    std::vector<std::shared_ptr<void>> backing_lifetimes;

    ResultSet() = default;
    ~ResultSet() {
        for (auto* arr : owned_value_arrays) ::operator delete(arr);
    }

    // Move-only (owns heap arrays)
    ResultSet(ResultSet&& o) noexcept
        : rows(std::move(o.rows)),
          column_names(std::move(o.column_names)),
          column_count(o.column_count),
          owned_value_arrays(std::move(o.owned_value_arrays)),
          owned_strings(std::move(o.owned_strings)),
          backing_lifetimes(std::move(o.backing_lifetimes)) {
        o.column_count = 0;
    }

    ResultSet& operator=(ResultSet&& o) noexcept {
        if (this != &o) {
            for (auto* arr : owned_value_arrays) ::operator delete(arr);
            rows = std::move(o.rows);
            column_names = std::move(o.column_names);
            column_count = o.column_count;
            owned_value_arrays = std::move(o.owned_value_arrays);
            owned_strings = std::move(o.owned_strings);
            backing_lifetimes = std::move(o.backing_lifetimes);
            o.column_count = 0;
        }
        return *this;
    }

    // Disable copy to prevent double-free of owned arrays
    ResultSet(const ResultSet&) = delete;
    ResultSet& operator=(const ResultSet&) = delete;

    size_t row_count() const { return rows.size(); }
    bool empty() const { return rows.empty(); }

    // Allocate a heap-owned row and append it to rows. Returns a reference
    // to the Row (which points into owned_value_arrays).
    Row& add_heap_row(uint16_t col_count) {
        Value* vals = static_cast<Value*>(::operator new(sizeof(Value) * col_count));
        for (uint16_t i = 0; i < col_count; ++i) vals[i] = value_null();
        owned_value_arrays.push_back(vals);
        rows.push_back(Row{vals, col_count});
        return rows.back();
    }

    // Store a string and return a StringRef pointing into the stored copy.
    // The pointer remains valid for the lifetime of this ResultSet (deque
    // guarantees stable element addresses across push_back).
    sql_parser::StringRef own_string(const char* data, uint32_t len) {
        owned_strings.emplace_back(data, len);
        const std::string& s = owned_strings.back();
        return sql_parser::StringRef{s.c_str(), static_cast<uint32_t>(s.size())};
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_RESULT_SET_H
