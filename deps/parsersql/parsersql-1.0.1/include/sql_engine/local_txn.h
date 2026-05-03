#ifndef SQL_ENGINE_LOCAL_TXN_H
#define SQL_ENGINE_LOCAL_TXN_H

#include "sql_engine/transaction_manager.h"
#include "sql_engine/mutable_data_source.h"
#include "sql_engine/value.h"
#include "sql_engine/row.h"
#include "sql_parser/arena.h"

#include <vector>
#include <string>
#include <unordered_map>
#include <cstring>
#include <memory>

namespace sql_engine {

// Owned copy of a Value — deep-copies string data so it survives arena resets.
struct OwnedValue {
    Value::Tag tag = Value::TAG_NULL;
    int64_t numeric_val = 0;      // covers bool, int64, uint64, date, time, etc.
    double double_val = 0.0;
    std::string str_data;

    OwnedValue() = default;

    static OwnedValue from_value(const Value& v) {
        OwnedValue ov;
        ov.tag = v.tag;
        switch (v.tag) {
            case Value::TAG_NULL:      break;
            case Value::TAG_BOOL:      ov.numeric_val = v.bool_val ? 1 : 0; break;
            case Value::TAG_INT64:     ov.numeric_val = v.int_val; break;
            case Value::TAG_UINT64:    ov.numeric_val = static_cast<int64_t>(v.uint_val); break;
            case Value::TAG_DOUBLE:    ov.double_val = v.double_val; break;
            case Value::TAG_DATE:      ov.numeric_val = v.date_val; break;
            case Value::TAG_TIME:      ov.numeric_val = v.time_val; break;
            case Value::TAG_DATETIME:  ov.numeric_val = v.datetime_val; break;
            case Value::TAG_TIMESTAMP: ov.numeric_val = v.timestamp_val; break;
            case Value::TAG_STRING:
            case Value::TAG_DECIMAL:
            case Value::TAG_BYTES:
            case Value::TAG_JSON:
                if (v.str_val.ptr && v.str_val.len > 0)
                    ov.str_data.assign(v.str_val.ptr, v.str_val.len);
                break;
        }
        return ov;
    }

    Value to_value(sql_parser::Arena& arena) const {
        Value v = value_null();
        v.tag = tag;
        switch (tag) {
            case Value::TAG_NULL:      break;
            case Value::TAG_BOOL:      v.bool_val = (numeric_val != 0); break;
            case Value::TAG_INT64:     v.int_val = numeric_val; break;
            case Value::TAG_UINT64:    v.uint_val = static_cast<uint64_t>(numeric_val); break;
            case Value::TAG_DOUBLE:    v.double_val = double_val; break;
            case Value::TAG_DATE:      v.date_val = static_cast<int32_t>(numeric_val); break;
            case Value::TAG_TIME:      v.time_val = numeric_val; break;
            case Value::TAG_DATETIME:  v.datetime_val = numeric_val; break;
            case Value::TAG_TIMESTAMP: v.timestamp_val = numeric_val; break;
            case Value::TAG_STRING:
            case Value::TAG_DECIMAL:
            case Value::TAG_BYTES:
            case Value::TAG_JSON:
                if (!str_data.empty()) {
                    char* buf = static_cast<char*>(arena.allocate(
                        static_cast<uint32_t>(str_data.size())));
                    std::memcpy(buf, str_data.data(), str_data.size());
                    v.str_val = sql_parser::StringRef{
                        buf, static_cast<uint32_t>(str_data.size())};
                } else {
                    v.str_val = sql_parser::StringRef{nullptr, 0};
                }
                break;
        }
        return v;
    }
};

// A row stored with owned (heap-allocated) values.
struct OwnedRow {
    std::vector<OwnedValue> columns;

    static OwnedRow from_row(const Row& row) {
        OwnedRow or_;
        or_.columns.reserve(row.column_count);
        for (uint16_t i = 0; i < row.column_count; ++i)
            or_.columns.push_back(OwnedValue::from_value(row.get(i)));
        return or_;
    }

    Row to_row(sql_parser::Arena& arena) const {
        uint16_t n = static_cast<uint16_t>(columns.size());
        Row r = make_row(arena, n);
        for (uint16_t i = 0; i < n; ++i)
            r.set(i, columns[i].to_value(arena));
        return r;
    }
};

// Snapshot of a table's rows at a point in time.
struct TableSnapshot {
    std::vector<OwnedRow> rows;

    static TableSnapshot capture(InMemoryMutableDataSource* src) {
        TableSnapshot snap;
        const auto& rows = src->rows();
        snap.rows.reserve(rows.size());
        for (auto& r : rows)
            snap.rows.push_back(OwnedRow::from_row(r));
        return snap;
    }

    void restore(InMemoryMutableDataSource* src, sql_parser::Arena& arena) const {
        // Delete all current rows
        src->delete_where([](const Row&) { return true; });
        // Re-insert snapshot rows
        for (auto& or_ : rows) {
            Row r = or_.to_row(arena);
            src->insert(r);
        }
    }
};

// LocalTransactionManager manages transactions for InMemoryMutableDataSource
// using table snapshots for rollback support.
//
// On BEGIN: snapshots all registered tables.
// On COMMIT: discards snapshots (data already applied).
// On ROLLBACK: restores tables from snapshots.
// On SAVEPOINT: takes a new snapshot at the current point.
class LocalTransactionManager : public TransactionManager {
public:
    explicit LocalTransactionManager(sql_parser::Arena& arena)
        : arena_(arena) {}

    // Register a mutable data source. Must be called before begin().
    void register_source(const char* table_name, InMemoryMutableDataSource* source) {
        sources_[table_name] = source;
    }

    bool begin() override {
        snapshots_.clear();
        savepoint_snapshots_.clear();
        // Snapshot all registered tables
        for (auto& kv : sources_)
            snapshots_[kv.first] = TableSnapshot::capture(kv.second);
        in_txn_ = true;
        return true;
    }

    bool commit() override {
        snapshots_.clear();
        savepoint_snapshots_.clear();
        in_txn_ = false;
        return true;
    }

    bool rollback() override {
        if (!in_txn_) return false;
        // Restore all tables from BEGIN snapshot
        for (auto& kv : snapshots_) {
            auto sit = sources_.find(kv.first);
            if (sit != sources_.end())
                kv.second.restore(sit->second, arena_);
        }
        snapshots_.clear();
        savepoint_snapshots_.clear();
        in_txn_ = false;
        return true;
    }

    bool savepoint(const char* name) override {
        if (!in_txn_) return false;
        std::unordered_map<std::string, TableSnapshot> snap;
        for (auto& kv : sources_)
            snap[kv.first] = TableSnapshot::capture(kv.second);
        savepoint_snapshots_[name] = std::move(snap);
        savepoint_order_.push_back(name);
        return true;
    }

    bool rollback_to(const char* name) override {
        if (!in_txn_) return false;
        auto it = savepoint_snapshots_.find(name);
        if (it == savepoint_snapshots_.end()) return false;
        // Restore tables to savepoint state
        for (auto& kv : it->second) {
            auto sit = sources_.find(kv.first);
            if (sit != sources_.end())
                kv.second.restore(sit->second, arena_);
        }
        // Remove savepoints created after this one
        bool found = false;
        for (auto oit = savepoint_order_.begin(); oit != savepoint_order_.end(); ) {
            if (*oit == name) { found = true; ++oit; continue; }
            if (found) {
                savepoint_snapshots_.erase(*oit);
                oit = savepoint_order_.erase(oit);
            } else {
                ++oit;
            }
        }
        return true;
    }

    bool release_savepoint(const char* name) override {
        if (!in_txn_) return false;
        auto it = savepoint_snapshots_.find(name);
        if (it == savepoint_snapshots_.end()) return false;
        savepoint_snapshots_.erase(it);
        savepoint_order_.erase(
            std::remove(savepoint_order_.begin(), savepoint_order_.end(), name),
            savepoint_order_.end());
        return true;
    }

    bool in_transaction() const override { return in_txn_; }
    bool is_auto_commit() const override { return auto_commit_; }
    void set_auto_commit(bool ac) override { auto_commit_ = ac; }

private:
    sql_parser::Arena& arena_;
    std::unordered_map<std::string, InMemoryMutableDataSource*> sources_;

    // Snapshot at BEGIN time
    std::unordered_map<std::string, TableSnapshot> snapshots_;
    // Savepoint snapshots
    std::unordered_map<std::string,
        std::unordered_map<std::string, TableSnapshot>> savepoint_snapshots_;
    std::vector<std::string> savepoint_order_;

    bool in_txn_ = false;
    bool auto_commit_ = true;
};

} // namespace sql_engine

#endif // SQL_ENGINE_LOCAL_TXN_H
