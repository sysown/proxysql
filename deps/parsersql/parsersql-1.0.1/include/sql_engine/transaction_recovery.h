#ifndef SQL_ENGINE_TRANSACTION_RECOVERY_H
#define SQL_ENGINE_TRANSACTION_RECOVERY_H

// Startup recovery of in-doubt 2PC transactions.
//
// When the distributed transaction coordinator crashes between phase 1
// (PREPARE) and the end of phase 2, some participants may be left with
// prepared transactions that must be either committed or rolled back.
// The DurableTransactionLog records every COMMIT/ROLLBACK decision
// before phase 2 starts, so on restart we can tell exactly which
// transactions need to be resolved and how.
//
// This file provides TransactionRecovery, which consumes the list of
// in-doubt transactions from DurableTransactionLog::scan_in_doubt() and
// drives each one to completion by re-issuing the phase-2 SQL to the
// listed participants. When every participant for a given txn_id
// acknowledges the recovery action, we write a COMPLETE record so the
// transaction is no longer in-doubt.
//
// IDEMPOTENT: safe to call repeatedly. If recovery itself crashes
// midway through, the next run picks up where the previous one left
// off, because the log still has the decision record but no COMPLETE.
// Backends will return "transaction not found" (or equivalent) for
// transactions that were already committed on a previous recovery pass;
// we treat that as success since the end state is correct.
//
// CALLER RESPONSIBILITIES:
// - Open the log before calling recover() (so COMPLETE records can be
//   appended to the same file that was scanned).
// - Wire up a RemoteExecutor that knows every participant backend name
//   the log references. If a backend is unknown or unreachable, its
//   transaction stays in-doubt and recovery moves on to the next one.

#include "sql_engine/durable_txn_log.h"
#include "sql_engine/remote_executor.h"
#include "sql_engine/distributed_txn.h"
#include "sql_parser/common.h"

#include <cstdio>
#include <string>
#include <vector>

namespace sql_engine {

class TransactionRecovery {
public:
    using BackendDialect = DistributedTransactionManager::BackendDialect;

    struct Report {
        // Transactions recovered successfully (every participant acked,
        // COMPLETE record written).
        std::vector<std::string> recovered_commit;
        std::vector<std::string> recovered_rollback;

        // Transactions where at least one participant failed to respond
        // correctly. These remain in-doubt in the log; a subsequent
        // recovery pass will retry them.
        std::vector<std::string> still_in_doubt;

        // Total number of participants contacted across all transactions.
        // Useful for observability.
        size_t participants_contacted = 0;

        // Number of SQL calls that returned an error (which we may still
        // have counted as idempotent success if the message looks like
        // "transaction not found"). Present mainly for logging.
        size_t participant_errors = 0;
    };

    TransactionRecovery(RemoteExecutor& executor,
                        DurableTransactionLog& log,
                        BackendDialect dialect = BackendDialect::MYSQL)
        : executor_(executor), log_(log), dialect_(dialect) {}

    // Drive every in-doubt transaction in the log to completion and
    // return a summary. Reads the decisions from the log path that the
    // log was opened with.
    Report recover() {
        Report report;
        auto entries = log_.scan_in_doubt();
        for (auto& e : entries) {
            if (recover_one(e, report)) {
                if (e.decision == DurableTransactionLog::Decision::COMMIT) {
                    report.recovered_commit.push_back(e.txn_id);
                } else {
                    report.recovered_rollback.push_back(e.txn_id);
                }
                // Mark the transaction as no longer in-doubt. If this
                // write fails we'll reprocess the transaction next time,
                // which is fine -- the backend calls are idempotent.
                log_.log_complete(e.txn_id);
            } else {
                report.still_in_doubt.push_back(e.txn_id);
            }
        }
        return report;
    }

private:
    RemoteExecutor& executor_;
    DurableTransactionLog& log_;
    BackendDialect dialect_;

    // Try to finish one in-doubt transaction. Returns true iff every
    // participant acknowledged its phase-2 SQL (or returned an "already
    // resolved" error, which we treat as success).
    bool recover_one(const DurableTransactionLog::InDoubtEntry& entry,
                     Report& report) {
        bool all_ok = true;
        for (const auto& participant : entry.participants) {
            ++report.participants_contacted;
            if (!send_phase2(participant, entry.txn_id, entry.decision,
                             report)) {
                all_ok = false;
            }
        }
        return all_ok;
    }

    bool send_phase2(const std::string& backend,
                     const std::string& txn_id,
                     DurableTransactionLog::Decision decision,
                     Report& report) {
        std::string sql;
        if (dialect_ == BackendDialect::MYSQL) {
            sql = (decision == DurableTransactionLog::Decision::COMMIT)
                    ? "XA COMMIT '"   + txn_id + "'"
                    : "XA ROLLBACK '" + txn_id + "'";
        } else {
            sql = (decision == DurableTransactionLog::Decision::COMMIT)
                    ? "COMMIT PREPARED '"   + txn_id + "'"
                    : "ROLLBACK PREPARED '" + txn_id + "'";
        }

        auto result = executor_.execute_dml(
            backend.c_str(),
            sql_parser::StringRef{sql.c_str(),
                static_cast<uint32_t>(sql.size())});

        if (result.success) return true;

        // A non-success result is not always a real failure: if this
        // recovery pass (or a previous crash) already committed/rolled
        // back the prepared transaction on the backend, the call will
        // return an error like "XAER_NOTA: Unknown XID" (MySQL) or
        // "transaction not found" / "does not exist" (PostgreSQL). We
        // treat those as idempotent success since the desired end state
        // is already achieved.
        ++report.participant_errors;
        if (looks_like_already_resolved(result.error_message)) {
            return true;
        }
        std::fprintf(stderr,
            "[TransactionRecovery] %s failed for txn %s on %s: %s\n",
            (decision == DurableTransactionLog::Decision::COMMIT
                ? "commit" : "rollback"),
            txn_id.c_str(), backend.c_str(),
            result.error_message.c_str());
        return false;
    }

    // Heuristic: backend error messages that mean "this transaction is
    // no longer in the prepared state, so there's nothing for me to
    // commit/rollback". Matches both MySQL XA and PostgreSQL's prepared
    // transaction error text.
    static bool looks_like_already_resolved(const std::string& err) {
        // MySQL XA: XAER_NOTA when the XID is not found.
        if (err.find("XAER_NOTA") != std::string::npos) return true;
        if (err.find("Unknown XID") != std::string::npos) return true;
        // PostgreSQL: prepared transaction not found.
        if (err.find("does not exist") != std::string::npos) return true;
        if (err.find("not found") != std::string::npos) return true;
        // Defensive catch-all phrase we might see from mock executors.
        if (err.find("already") != std::string::npos) return true;
        return false;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_TRANSACTION_RECOVERY_H
