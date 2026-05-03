#ifndef SQL_ENGINE_DISTRIBUTED_TXN_H
#define SQL_ENGINE_DISTRIBUTED_TXN_H

#include "sql_engine/transaction_manager.h"
#include "sql_engine/remote_executor.h"
#include "sql_engine/remote_session.h"
#include "sql_engine/shard_map.h"
#include "sql_engine/durable_txn_log.h"
#include "sql_parser/common.h"

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <random>
#include <cstdio>

namespace sql_engine {

// DistributedTransactionManager implements two-phase commit (2PC) for
// transactions spanning multiple backends.
//
// MySQL XA protocol:
//   XA START 'txn_id'  → begin on each participant
//   XA END 'txn_id'    → mark end of work
//   XA PREPARE 'txn_id' → phase 1
//   XA COMMIT 'txn_id'  → phase 2 (success)
//   XA ROLLBACK 'txn_id' → phase 2 (failure)
//
// PostgreSQL:
//   BEGIN → PREPARE TRANSACTION 'txn_id' → COMMIT PREPARED 'txn_id'
class DistributedTransactionManager : public TransactionManager {
public:
    // Backend dialect for 2PC protocol selection
    enum class BackendDialect : uint8_t { MYSQL, POSTGRESQL };

    DistributedTransactionManager(RemoteExecutor& executor,
                                   BackendDialect dialect = BackendDialect::MYSQL)
        : executor_(executor), dialect_(dialect) {}

    // Attach a durable write-ahead log for 2PC recovery. Optional but
    // strongly recommended for any real workload: without it, a crash
    // between phase 1 and phase 2 leaves prepared transactions on every
    // backend with no automatic recovery path.
    //
    // The log pointer must outlive this manager. Pass nullptr to disable
    // logging (the default -- matches pre-existing behavior).
    void set_durable_log(DurableTransactionLog* log) { txn_log_ = log; }

    // Require the WAL to succeed for commits to proceed. Default: false.
    // When true, if log_decision() fails, we refuse to start phase 2 and
    // roll back instead -- trading availability for durability. When
    // false, a log write failure is logged to stderr but the commit
    // continues (caller might prefer availability over durability).
    void set_require_durable_log(bool required) { require_durable_log_ = required; }

    // Set a tight per-phase statement timeout (in milliseconds).
    //
    // PostgreSQL:
    //   Before PREPARE TRANSACTION and COMMIT/ROLLBACK PREPARED, the manager
    //   issues SET statement_timeout = <ms> on the participant session
    //   immediately before the phase SQL. This gives a deterministic
    //   session-level timeout on the same connection used for the phase
    //   statement.
    //
    // MySQL:
    //   XA control statements are not bounded by max_execution_time, so we do
    //   not emit a misleading per-phase SQL timeout. MySQL protection comes
    //   from the connection read/write timeouts configured on the executor.
    //
    // 0 (default) means "don't override". PostgreSQL then falls back to the
    // backend/session defaults, and MySQL continues to rely on connection
    // read/write timeouts only.
    void set_phase_statement_timeout_ms(uint32_t ms) {
        phase_statement_timeout_ms_ = ms;
    }

    // Auto-compact the durable log every N successful completions. When > 0,
    // the manager calls txn_log_->compact() after every Nth completed txn.
    // 0 (default) = disabled. Callers should pick a value balancing compaction
    // cost vs. log growth (e.g., 100-10000 depending on txn rate).
    void set_auto_compact_threshold(uint32_t n) {
        auto_compact_threshold_ = n;
    }

    bool begin() override {
        txn_id_ = generate_txn_id();
        participants_.clear();
        prepared_.clear();
        started_.clear();
        sessions_.clear();
        active_ = true;
        return true;
    }

    // Enlist a backend as a transaction participant. Called when DML is
    // executed against a backend. Checks out a pinned session for the
    // backend and issues XA START / BEGIN on it. The session stays
    // checked out for the whole transaction so phase 1 (XA END + XA
    // PREPARE / PREPARE TRANSACTION) runs on the same physical
    // connection, which is what MySQL XA and PostgreSQL 2PC require.
    bool enlist_backend(const char* backend_name) {
        if (!active_) return false;
        std::string name(backend_name);
        if (started_.count(name)) return true;  // already enlisted

        // Acquire a pinned session. If the executor doesn't support
        // pinning (returns nullptr), only executors that explicitly
        // declare unpinned 2PC safe are allowed to use the legacy path.
        std::unique_ptr<RemoteSession> session = executor_.checkout_session(backend_name);

        bool ok = false;
        if (session) {
            // Pinned path.
            std::string sql;
            if (dialect_ == BackendDialect::MYSQL) {
                sql = "XA START '" + txn_id_ + "'";
            } else {
                sql = "BEGIN";
            }
            DmlResult r = session->execute_dml(
                sql_parser::StringRef{sql.c_str(),
                    static_cast<uint32_t>(sql.size())});
            ok = r.success;
            if (ok) {
                sessions_[name] = std::move(session);
            }
        } else {
            // Unpinned fallback is valid only for executors that
            // explicitly guarantee one durable connection per backend.
            if (!executor_.allows_unpinned_distributed_2pc()) {
                return false;
            }
            if (dialect_ == BackendDialect::MYSQL) {
                std::string sql = "XA START '" + txn_id_ + "'";
                ok = send_sql(backend_name, sql);
            } else {
                ok = send_sql(backend_name, "BEGIN");
            }
        }

        if (ok) {
            participants_.push_back(name);
            started_.insert(name);
        }
        return ok;
    }

    // Execute DML on a participant's pinned session, enlisting the
    // backend first if it isn't already. This is the correct way for
    // in-transaction DML to be routed when the caller knows which
    // participant owns the affected rows. Returns a DmlResult; if the
    // backend isn't enlisted and can't be enlisted, the result is an
    // error.
    //
    // External DML routing: Session::execute_statement() now routes DML
    // through this method when a distributed transaction is active and
    // sharding is configured. This ensures DML inside a distributed
    // transaction goes through the pinned session and is part of the 2PC.
    DmlResult execute_participant_dml(const char* backend_name,
                                      sql_parser::StringRef sql) {
        DmlResult r;
        if (!active_) {
            r.error_message = "no active distributed transaction";
            return r;
        }
        if (!enlist_backend(backend_name)) {
            r.error_message = "failed to enlist backend";
            return r;
        }
        auto it = sessions_.find(backend_name);
        if (it != sessions_.end() && it->second) {
            return it->second->execute_dml(sql);
        }
        // Legacy-safe single-connection fallback.
        return executor_.execute_dml(backend_name, sql);
    }

    bool commit() override {
        if (!active_) return false;
        if (participants_.empty()) {
            active_ = false;
            sessions_.clear();
            return true;
        }

        // Phase 1: prepare all participants
        if (!phase1_prepare()) {
            if (!log_decision_or_fail(DurableTransactionLog::Decision::ROLLBACK)) {
                active_ = false;
                sessions_.clear();
                return false;
            }
            phase2_rollback();
            maybe_log_complete();
            active_ = false;
            sessions_.clear();
            return false;
        }

        if (!log_decision_or_fail(DurableTransactionLog::Decision::COMMIT)) {
            active_ = false;
            sessions_.clear();
            return false;
        }

        bool ok = phase2_commit();
        if (ok) {
            maybe_log_complete();
        } else {
            std::fprintf(stderr,
                "[DistributedTransactionManager] phase 2 commit failed for "
                "txn %s; leaving in-doubt in the WAL for recovery.\n",
                txn_id_.c_str());
        }
        active_ = false;
        // Drop pinned sessions. After phase 2 the XA transactions are
        // either committed or in-doubt; recovery (if needed) will use
        // a fresh session on any connection because XA COMMIT /
        // COMMIT PREPARED don't require session stickiness once PREPARE
        // has succeeded.
        sessions_.clear();
        return ok;
    }

    bool rollback() override {
        if (!active_) return false;
        (void)log_decision_or_fail(DurableTransactionLog::Decision::ROLLBACK);
        phase2_rollback();
        maybe_log_complete();
        active_ = false;
        sessions_.clear();
        return true;
    }

    // Savepoints are not supported for distributed transactions.
    bool savepoint(const char*) override { return false; }
    bool rollback_to(const char*) override { return false; }
    bool release_savepoint(const char*) override { return false; }

    bool in_transaction() const override { return active_; }
    bool is_auto_commit() const override { return auto_commit_; }
    void set_auto_commit(bool ac) override { auto_commit_ = ac; }

    bool is_distributed() const override { return true; }

    DmlResult route_dml(const char* backend_name,
                        sql_parser::StringRef sql) override {
        return execute_participant_dml(backend_name, sql);
    }

    const std::string& txn_id() const { return txn_id_; }
    const std::vector<std::string>& participants() const { return participants_; }

private:
    RemoteExecutor& executor_;
    BackendDialect dialect_;

    std::string txn_id_;
    std::vector<std::string> participants_;
    std::unordered_set<std::string> started_;
    std::unordered_map<std::string, bool> prepared_;
    // Pinned sessions, one per enlisted backend. Checked out from the
    // RemoteExecutor during enlist_backend and held for the lifetime of
    // the transaction; released when commit/rollback finishes. This is
    // what ensures XA START / XA END / XA PREPARE all go to the same
    // physical connection -- the required behavior for MySQL XA and
    // PostgreSQL PREPARE TRANSACTION.
    std::unordered_map<std::string, std::unique_ptr<RemoteSession>> sessions_;
    bool active_ = false;
    bool auto_commit_ = true;

    DurableTransactionLog* txn_log_ = nullptr;
    bool require_durable_log_ = false;
    uint32_t phase_statement_timeout_ms_ = 0;

    // Auto-compaction: count completions, fire compact when counter hits threshold.
    uint32_t auto_compact_threshold_ = 0;
    uint32_t completions_since_compact_ = 0;

    // Write the phase-2 decision to the durable log before dispatching.
    // Returns true if the commit/rollback can proceed:
    // - log not configured: true (log-less mode preserves legacy behavior)
    // - log configured and write succeeded: true
    // - log configured and write failed:
    //     - require_durable_log_: false (abort, don't risk a crash
    //       window without a recoverable decision)
    //     - !require_durable_log_: true (write failure logged to stderr,
    //       commit proceeds at the caller's risk)
    bool log_decision_or_fail(DurableTransactionLog::Decision d) {
        if (!txn_log_) return true;
        if (txn_log_->log_decision(txn_id_, d, participants_)) return true;
        if (require_durable_log_) {
            std::fprintf(stderr,
                "[DistributedTransactionManager] WAL write failed for txn %s; "
                "refusing to proceed with phase 2 because require_durable_log is set.\n",
                txn_id_.c_str());
            return false;
        }
        std::fprintf(stderr,
            "[DistributedTransactionManager] WAL write failed for txn %s; "
            "proceeding without durability (set require_durable_log to refuse instead).\n",
            txn_id_.c_str());
        return true;
    }

    void maybe_log_complete() {
        if (!txn_log_) return;
        txn_log_->log_complete(txn_id_);
        if (auto_compact_threshold_ > 0) {
            ++completions_since_compact_;
            if (completions_since_compact_ >= auto_compact_threshold_) {
                completions_since_compact_ = 0;
                txn_log_->compact();
            }
        }
    }

    // Generate a unique transaction ID.
    static std::string generate_txn_id() {
        auto now = std::chrono::steady_clock::now();
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count();
        // Use random suffix to avoid collisions
        static thread_local std::mt19937 rng(
            static_cast<unsigned>(std::chrono::system_clock::now()
                .time_since_epoch().count()));
        std::uniform_int_distribution<uint32_t> dist(0, 999999);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "parsersql_%ld_%06u",
                      static_cast<long>(ns), dist(rng));
        return buf;
    }

    bool send_sql(const char* backend, const std::string& sql) {
        auto r = executor_.execute_dml(backend,
            sql_parser::StringRef{sql.c_str(),
                static_cast<uint32_t>(sql.size())});
        return r.success;
    }

    // Phase 1: XA END + XA PREPARE on all participants (MySQL)
    //          PREPARE TRANSACTION on all participants (PostgreSQL)
    //
    // MUST use the pinned session for each participant (when available)
    // because the XA END / XA PREPARE can only be issued on the same
    // connection that issued XA START. Falls back to the unpinned path
    // only for participants that were enlisted in unpinned mode.
    bool phase1_prepare() {
        bool all_ok = true;
        for (auto& p : participants_) {
            maybe_set_statement_timeout_participant(p);

            bool ok = false;
            if (dialect_ == BackendDialect::MYSQL) {
                std::string end_sql = "XA END '" + txn_id_ + "'";
                ok = send_sql_participant(p, end_sql);
                if (ok) {
                    std::string prep_sql = "XA PREPARE '" + txn_id_ + "'";
                    ok = send_sql_participant(p, prep_sql);
                }
            } else {
                std::string prep_sql = "PREPARE TRANSACTION '" + txn_id_ + "'";
                ok = send_sql_participant(p, prep_sql);
            }
            prepared_[p] = ok;
            if (!ok) {
                // A phase-1 failure leaves the connection in a bad
                // state on MySQL (still holding XA START, can't issue
                // other XA commands). Poison the session so it won't
                // be returned to the pool.
                auto sit = sessions_.find(p);
                if (sit != sessions_.end() && sit->second) {
                    sit->second->poison();
                }
                all_ok = false;
            }
        }
        return all_ok;
    }

    // Phase 2 (success): XA COMMIT / COMMIT PREPARED on all participants.
    //
    // After a successful PREPARE, XA COMMIT / COMMIT PREPARED can be
    // issued on ANY connection (the transaction is globally named). We
    // still prefer the pinned session since we already have it; this
    // avoids one extra round-trip through the pool.
    bool phase2_commit() {
        bool all_ok = true;
        for (auto& p : participants_) {
            maybe_set_statement_timeout_participant(p);

            bool ok = false;
            if (dialect_ == BackendDialect::MYSQL) {
                std::string sql = "XA COMMIT '" + txn_id_ + "'";
                ok = send_sql_participant(p, sql);
            } else {
                std::string sql = "COMMIT PREPARED '" + txn_id_ + "'";
                ok = send_sql_participant(p, sql);
            }
            if (!ok) all_ok = false;
        }
        return all_ok;
    }

    // Phase 2 (failure): XA ROLLBACK on all participants. For ones that
    // never made it to PREPARE, we also issue XA END first.
    void phase2_rollback() {
        for (auto& p : participants_) {
            if (dialect_ == BackendDialect::MYSQL) {
                if (prepared_.count(p) && prepared_[p]) {
                    std::string sql = "XA ROLLBACK '" + txn_id_ + "'";
                    send_sql_participant(p, sql);
                } else if (started_.count(p)) {
                    std::string end_sql = "XA END '" + txn_id_ + "'";
                    send_sql_participant(p, end_sql);
                    std::string rb_sql = "XA ROLLBACK '" + txn_id_ + "'";
                    send_sql_participant(p, rb_sql);
                }
            } else {
                if (prepared_.count(p) && prepared_[p]) {
                    std::string sql = "ROLLBACK PREPARED '" + txn_id_ + "'";
                    send_sql_participant(p, sql);
                } else if (started_.count(p)) {
                    send_sql_participant(p, "ROLLBACK");
                }
            }
        }
    }

    // Send a SQL statement to a participant, using the pinned session if
    // one exists for this backend, or falling back to the unpinned
    // execute_dml path otherwise.
    bool send_sql_participant(const std::string& participant, const std::string& sql) {
        auto it = sessions_.find(participant);
        if (it != sessions_.end() && it->second) {
            DmlResult r = it->second->execute_dml(
                sql_parser::StringRef{sql.c_str(),
                    static_cast<uint32_t>(sql.size())});
            return r.success;
        }
        return send_sql(participant.c_str(), sql);
    }

    // Set a participant-scoped phase timeout immediately before the phase SQL.
    // PostgreSQL gets a real session-level statement_timeout on the same
    // connection. MySQL returns true without emitting SQL because XA control
    // statements are bounded by connection read/write timeouts, not by
    // max_execution_time.
    bool maybe_set_statement_timeout_participant(const std::string& participant) {
        if (phase_statement_timeout_ms_ == 0) return true;
        if (dialect_ == BackendDialect::MYSQL) return true;
        std::string sql = "SET statement_timeout = " +
                          std::to_string(phase_statement_timeout_ms_);
        return send_sql_participant(participant, sql);
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_DISTRIBUTED_TXN_H
