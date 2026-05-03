#ifndef SQL_ENGINE_TRANSACTION_MANAGER_H
#define SQL_ENGINE_TRANSACTION_MANAGER_H

#include "sql_engine/dml_result.h"
#include "sql_parser/common.h"

namespace sql_engine {

// Abstract interface for transaction management.
// Implementations: LocalTransactionManager, SingleBackendTransactionManager,
// DistributedTransactionManager.
class TransactionManager {
public:
    virtual ~TransactionManager() = default;

    // Transaction lifecycle
    virtual bool begin() = 0;
    virtual bool commit() = 0;
    virtual bool rollback() = 0;

    // Savepoints
    virtual bool savepoint(const char* name) = 0;
    virtual bool rollback_to(const char* name) = 0;
    virtual bool release_savepoint(const char* name) = 0;

    // State
    virtual bool in_transaction() const = 0;
    virtual bool is_auto_commit() const = 0;
    virtual void set_auto_commit(bool ac) = 0;

    // Distributed transaction support. Override in DistributedTransactionManager.
    virtual bool is_distributed() const { return false; }

    // Route DML through the transaction's pinned session for a given backend.
    // Default: returns DmlResult with success=false.
    // DistributedTransactionManager overrides to route through execute_participant_dml.
    virtual DmlResult route_dml(const char* /*backend_name*/,
                                sql_parser::StringRef /*sql*/) {
        DmlResult r;
        r.error_message = "route_dml not supported by this transaction manager";
        return r;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_TRANSACTION_MANAGER_H
