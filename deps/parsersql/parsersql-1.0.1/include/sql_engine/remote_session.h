#ifndef SQL_ENGINE_REMOTE_SESSION_H
#define SQL_ENGINE_REMOTE_SESSION_H

// RemoteSession -- a pinned physical connection to a backend.
//
// Why this exists: two-phase commit requires that the "work" phase of a
// transaction (BEGIN, the actual DML, and PREPARE) all happen on the same
// physical connection.
//
//   MySQL XA: "Once XA START has been issued, the XA transaction is
//              associated with the current session." XA END and XA PREPARE
//              must therefore be issued on the same connection as XA START,
//              or the backend will reject them with XAER_NOTA.
//
//   PostgreSQL: The transaction that PREPARE TRANSACTION operates on is the
//               one currently active in the session. You can't BEGIN on one
//               connection and PREPARE on another -- the second connection
//               would just see "no transaction in progress".
//
// The previous DistributedTransactionManager code routed every SQL through
// RemoteExecutor::execute_dml, which on ThreadSafeMultiRemoteExecutor checks
// out a fresh pooled connection for each call. That silently broke 2PC
// against real backends (the unit tests passed only because
// MockDistributedExecutor doesn't enforce session identity). This class is
// the fix: callers acquire a session for a backend, issue every transaction
// statement through it, and release it when the transaction is done.
//
// After PREPARE succeeds, the transaction becomes detached from the session
// (MySQL XA drops it to "idle" state, PostgreSQL's prepared txn is
// durable-across-restart). At that point COMMIT/ROLLBACK can actually go to
// any connection -- including a pooled one. But it's simpler and strictly
// correct to keep using the pinned session for phase 2 until the caller
// explicitly releases it, which is what the 2PC coordinator does.

#include "sql_engine/result_set.h"
#include "sql_engine/dml_result.h"
#include "sql_parser/common.h"

namespace sql_engine {

class RemoteSession {
public:
    virtual ~RemoteSession() = default;

    // Execute a SELECT-like statement on this session's pinned connection.
    virtual ResultSet execute(sql_parser::StringRef sql) = 0;

    // Execute a DML / admin / 2PC control statement on this session's
    // pinned connection.
    virtual DmlResult execute_dml(sql_parser::StringRef sql) = 0;

    // Mark the underlying connection as broken so it won't be returned to
    // the pool. Useful when the session observed an error that might have
    // left the connection in an indeterminate state (e.g. a failed XA
    // PREPARE -- the connection may still have an open XA transaction).
    virtual void poison() = 0;
};

} // namespace sql_engine

#endif // SQL_ENGINE_REMOTE_SESSION_H
