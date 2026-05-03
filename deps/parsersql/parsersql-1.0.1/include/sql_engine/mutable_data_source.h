#ifndef SQL_ENGINE_MUTABLE_DATA_SOURCE_H
#define SQL_ENGINE_MUTABLE_DATA_SOURCE_H

#include "sql_engine/data_source.h"
#include "sql_engine/catalog.h"
#include "sql_engine/row.h"
#include "sql_engine/value.h"
#include "sql_parser/arena.h"
#include <vector>
#include <functional>
#include <cstring>

namespace sql_engine {

// MutableDataSource extends DataSource with write operations.
class MutableDataSource : public DataSource {
public:
    virtual bool insert(const Row& row) = 0;
    virtual uint64_t delete_where(std::function<bool(const Row&)> predicate) = 0;
    virtual uint64_t update_where(std::function<bool(const Row&)> predicate,
                                   std::function<void(Row&)> updater) = 0;
};

// In-memory mutable data source backed by std::vector<Row>.
class InMemoryMutableDataSource : public MutableDataSource {
public:
    InMemoryMutableDataSource(const TableInfo* table, sql_parser::Arena& arena)
        : table_(table), arena_(arena), cursor_(0) {}

    InMemoryMutableDataSource(const TableInfo* table, sql_parser::Arena& arena,
                               std::vector<Row> initial_rows)
        : table_(table), arena_(arena), rows_(std::move(initial_rows)), cursor_(0) {}

    // DataSource interface (read)
    const TableInfo* table_info() const override { return table_; }

    void open() override { cursor_ = 0; }

    bool next(Row& out) override {
        if (cursor_ >= rows_.size()) return false;
        out = rows_[cursor_++];
        return true;
    }

    void close() override { cursor_ = 0; }

    // MutableDataSource interface (write)
    bool insert(const Row& row) override {
        // Deep-copy the row values into our arena
        Row copy = make_row(arena_, row.column_count);
        for (uint16_t i = 0; i < row.column_count; ++i) {
            copy.set(i, copy_value(row.get(i)));
        }
        rows_.push_back(copy);
        return true;
    }

    uint64_t delete_where(std::function<bool(const Row&)> predicate) override {
        uint64_t removed = 0;
        // Iterate backward to avoid index issues
        for (size_t i = rows_.size(); i > 0; --i) {
            if (predicate(rows_[i - 1])) {
                rows_.erase(rows_.begin() + static_cast<ptrdiff_t>(i - 1));
                ++removed;
            }
        }
        return removed;
    }

    uint64_t update_where(std::function<bool(const Row&)> predicate,
                           std::function<void(Row&)> updater) override {
        uint64_t updated = 0;
        for (auto& row : rows_) {
            if (predicate(row)) {
                updater(row);
                ++updated;
            }
        }
        return updated;
    }

    // Utility
    size_t row_count() const { return rows_.size(); }

    const std::vector<Row>& rows() const { return rows_; }

private:
    const TableInfo* table_;
    sql_parser::Arena& arena_;
    std::vector<Row> rows_;
    size_t cursor_;

    // Deep-copy a Value, arena-allocating string data
    Value copy_value(const Value& v) {
        if (v.tag == Value::TAG_STRING || v.tag == Value::TAG_DECIMAL ||
            v.tag == Value::TAG_BYTES || v.tag == Value::TAG_JSON) {
            if (v.str_val.ptr && v.str_val.len > 0) {
                char* buf = static_cast<char*>(arena_.allocate(v.str_val.len));
                std::memcpy(buf, v.str_val.ptr, v.str_val.len);
                Value copy = v;
                copy.str_val = sql_parser::StringRef{buf, v.str_val.len};
                return copy;
            }
        }
        return v;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_MUTABLE_DATA_SOURCE_H
