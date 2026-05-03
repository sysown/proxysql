#ifndef SQL_ENGINE_OPERATORS_MERGE_SORT_OP_H
#define SQL_ENGINE_OPERATORS_MERGE_SORT_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/value.h"
#include "sql_engine/row.h"
#include "sql_engine/thread_pool.h"
#include <vector>
#include <queue>
#include <functional>
#include <cstring>
#include <future>

namespace sql_engine {

// N-way merge sort operator.
// Takes N child operators, each returning pre-sorted rows, and performs
// an N-way merge using a min-heap to produce globally sorted output.
class MergeSortOperator : public Operator {
public:
    MergeSortOperator(std::vector<Operator*> children,
                      const uint16_t* sort_col_indices,
                      const uint8_t* directions,
                      uint16_t key_count,
                      bool parallel_open = false,
                      ThreadPool* pool = nullptr)
        : children_(std::move(children)), key_count_(key_count),
          parallel_open_(parallel_open), pool_(pool)
    {
        sort_cols_.assign(sort_col_indices, sort_col_indices + key_count);
        directions_.assign(directions, directions + key_count);
    }

    void open() override {
        heads_.resize(children_.size());
        has_row_.assign(children_.size(), false);

        if (parallel_open_ && children_.size() > 1) {
            // Parallel execution: open all children concurrently and
            // fetch their first row. Uses thread pool when available
            // (~1-2us dispatch) vs std::async (~200us thread creation).
            std::vector<std::future<void>> futures;
            futures.reserve(children_.size());
            for (size_t i = 0; i < children_.size(); ++i) {
                auto launcher = [this, i]{
                    children_[i]->open();
                    Row row{};
                    if (children_[i]->next(row)) {
                        heads_[i] = row;
                        has_row_[i] = true;
                    }
                };
                if (pool_) {
                    futures.push_back(pool_->submit(std::move(launcher)));
                } else {
                    futures.push_back(std::async(std::launch::async, std::move(launcher)));
                }
            }
            for (auto& f : futures) f.get();
        } else {
            // Sequential path
            for (size_t i = 0; i < children_.size(); ++i) {
                children_[i]->open();
                Row row{};
                if (children_[i]->next(row)) {
                    heads_[i] = row;
                    has_row_[i] = true;
                }
            }
        }

        // Build min-heap using std::function comparator
        // Comparator: returns true if a should come AFTER b in the output
        // (priority_queue is max-heap, so we invert)
        std::function<bool(size_t, size_t)> cmp = [this](size_t a, size_t b) -> bool {
            return compare_rows(heads_[a], heads_[b]) > 0;
        };

        heap_ = HeapType(cmp);
        for (size_t i = 0; i < children_.size(); ++i) {
            if (has_row_[i]) {
                heap_.push(i);
            }
        }
    }

    bool next(Row& out) override {
        if (heap_.empty()) return false;

        size_t idx = heap_.top();
        heap_.pop();

        out = heads_[idx];

        // Advance that child
        Row row{};
        if (children_[idx]->next(row)) {
            heads_[idx] = row;
            heap_.push(idx);
        } else {
            has_row_[idx] = false;
        }

        return true;
    }

    void close() override {
        for (auto* child : children_) {
            child->close();
        }
        // Clear the heap by assigning an empty one
        while (!heap_.empty()) heap_.pop();
    }

private:
    std::vector<Operator*> children_;
    std::vector<uint16_t> sort_cols_;
    std::vector<uint8_t> directions_;
    uint16_t key_count_;
    bool parallel_open_;
    ThreadPool* pool_ = nullptr;

    std::vector<Row> heads_;
    std::vector<bool> has_row_;

    using HeapType = std::priority_queue<size_t, std::vector<size_t>,
                                         std::function<bool(size_t, size_t)>>;
    HeapType heap_{[](size_t, size_t) { return false; }};

    // Compare two rows according to sort keys.
    // Returns <0 if a < b, 0 if equal, >0 if a > b.
    int compare_rows(const Row& a, const Row& b) const {
        for (uint16_t k = 0; k < key_count_; ++k) {
            uint16_t col = sort_cols_[k];
            Value va = (col < a.column_count) ? a.get(col) : value_null();
            Value vb = (col < b.column_count) ? b.get(col) : value_null();
            int cmp = compare_values(va, vb);
            if (cmp == 0) continue;
            bool asc = (directions_[k] == 0);
            return asc ? cmp : -cmp;
        }
        return 0;
    }

    static int compare_values(const Value& a, const Value& b) {
        if (a.is_null() && b.is_null()) return 0;
        if (a.is_null()) return -1;
        if (b.is_null()) return 1;

        if (a.is_numeric() && b.is_numeric()) {
            double da = a.to_double(), db = b.to_double();
            return da < db ? -1 : (da > db ? 1 : 0);
        }

        if (a.tag == Value::TAG_STRING && b.tag == Value::TAG_STRING) {
            uint32_t minlen = a.str_val.len < b.str_val.len ? a.str_val.len : b.str_val.len;
            int cmp = std::memcmp(a.str_val.ptr, b.str_val.ptr, minlen);
            if (cmp != 0) return cmp;
            return a.str_val.len < b.str_val.len ? -1 : (a.str_val.len > b.str_val.len ? 1 : 0);
        }

        return 0;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_MERGE_SORT_OP_H
