# MySQL transaction errors (#6611, #6612)

Approved scope: the preceding investigation and the user's request to implement it.

For #6611, share hostgroup persistence updates between successful and failed query completion. Preserve the existing uncertainty latch, including the prepared-statement cleanup fix from #6481. Do not change autocommit defaults or transaction_persistent=0 behavior.

For #6612, parse all characteristics before mutation. An unscoped SET TRANSACTION in a definitely active transaction returns ER_CANT_CHANGE_TX_CHARACTERISTICS (1568, SQLSTATE 25001) immediately and leaves both SQL_NEXT values and the backend untouched. SESSION/LOCAL remain permitted. If only uncertainty suggests a transaction, forward the original SET to that retained backend and trust its response, without a permanent hostgroup lock. A successful forwarded SET must keep its next-transaction state on that backend until consumption is confirmed. DO and constant SELECT do not consume it. Successful DML or an explicit transaction boundary releases the hold; ambiguous reads retain it conservatively until a later boundary or disconnect. On 1568 during next-characteristic synchronization, retain the healthy backend and transaction, clear the rejected next-characteristic batch, and finish the affected client request exactly once. Do not retry transactional work on another connection.

Alternatives: rejecting whenever NumActiveTransactions()>0 is smaller but rejects valid SETs after unrelated errors or with autocommit_false_is_transaction enabled. Forwarding all SET TRANSACTION statements loses the existing multiplexing optimization. Keep the local fast path when no backend has a possibly active transaction and use backend validation for uncertainty.

Validation: real C API TAP regressions with two logical hostgroups, text/prepared duplicate-key failures, statement-local 1568, committed/rolled-back data and backend identity, parser 0/1 × SET algorithms 2/3, SESSION/LOCAL and idle-autocommit controls. Existing transaction/parser tests remain applicable. No PostgreSQL change: the failures are in MySQL-specific routing and SET replay.
