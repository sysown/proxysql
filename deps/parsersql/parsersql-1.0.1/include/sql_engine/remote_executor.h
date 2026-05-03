#ifndef SQL_ENGINE_REMOTE_EXECUTOR_H
#define SQL_ENGINE_REMOTE_EXECUTOR_H

#include "sql_engine/result_set.h"
#include "sql_engine/dml_result.h"
#include "sql_engine/remote_session.h"
#include "sql_parser/common.h"

#include <memory>

namespace sql_engine {

class RemoteExecutor {
public:
    virtual ~RemoteExecutor() = default;
    virtual ResultSet execute(const char* backend_name, sql_parser::StringRef sql) = 0;
    virtual DmlResult execute_dml(const char* backend_name, sql_parser::StringRef sql) {
        (void)backend_name;
        (void)sql;
        DmlResult r;
        r.error_message = "execute_dml not implemented";
        return r;
    }

    // Returns true only when this executor can safely run distributed 2PC
    // without pinned sessions. This is valid for executors that keep one
    // durable physical connection per backend for the full lifetime of the
    // executor. Pooled executors must return false and rely on
    // checkout_session() instead.
    virtual bool allows_unpinned_distributed_2pc() const { return false; }

    // Check out a pinned session for `backend_name`. The returned session
    // owns a specific physical connection for its lifetime; every call on
    // it goes to that same connection. On destruction the connection is
    // returned to the pool (or closed if the session was poisoned).
    //
    // REQUIRED for correct pooled 2PC behavior: MySQL XA and PostgreSQL
    // PREPARE TRANSACTION both need the transaction's DML and PREPARE to
    // share a session. Executors may return nullptr only if they also
    // override allows_unpinned_distributed_2pc() to declare the legacy
    // single-connection fallback safe for their execution model.
    virtual std::unique_ptr<RemoteSession> checkout_session(const char* backend_name) {
        (void)backend_name;
        return nullptr;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_REMOTE_EXECUTOR_H
