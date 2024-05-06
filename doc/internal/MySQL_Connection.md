### Flowchart of `MySQL_Connection::async_query()`

This function asynchronously executes a query on the MySQL connection.  
It handles various states of the asynchronous query execution process and returns appropriate status codes indicating the result of the execution.

Returns an integer status code indicating the result of the query execution:
- 0: Query execution completed successfully.
- -1: Query execution failed.
- 1: Query execution in progress.
- 2: Processing a multi-statement query, control needs to be transferred to MySQL_Session.
- 3: In the middle of processing a multi-statement query.


```mermaid
---
title: MySQL_Connection::async_query()
---
flowchart TD
Assert["assert()"]
ValidConnection{Valid Connection}
ValidConnection -- no --> Assert
IsServerOffline{"IsServerOffline()"}
ValidConnection -- yes --> IsServerOffline
IsServerOffline -- yes --> ReturnMinus1
asyncStateMachine1{async_state_machine}
asyncStateMachine2{async_state_machine}
IsServerOffline -- no --> asyncStateMachine1
asyncStateMachine1 -- ASYNC_QUERY_END --> Return0
handler["handler()"]
asyncStateMachine1 --> handler
handler --> asyncStateMachine2
asyncStateMachine2 -- ASYNC_QUERY_END --> mysql_error{"mysql_error"}
asyncStateMachine2 -- ASYNC_STMT_EXECUTE_END --> mysql_error
asyncStateMachine2 -- ASYNC_STMT_PREPARE_FAILED --> ReturnMinus1
asyncStateMachine2 -- ASYNC_STMT_PREPARE_SUCCESSFUL --> Return0
mysql_error -- yes --> ReturnMinus1
mysql_error -- no --> Return0
asyncStateMachine2 -- ASYNC_NEXT_RESULT_START --> Return2
processing_multi_statement{"processing_multi_statement"}
asyncStateMachine2 --> processing_multi_statement
processing_multi_statement -- yes --> Return3
processing_multi_statement -- no --> Return1
ReturnMinus1["return -1"]
Return0["return 0"]
Return1["return 1"]
Return2["return 2"]
Return3["return 3"]
```

### Flowchart of `MySQL_Connection::IsServerOffline()`

```mermaid
---
title: MySQL_Connection::IsServerOffline()
---
flowchart TD
True[true]
False[false]
SS1{"server_status"}
SA{"shunned_automatic"}
SB{"shunned_and_kill_all_connections"}
SS1 -- OFFLINE_HARD --> True
SS1 -- REPLICATION_LAG --> True
SS1 -- SHUNNED --> SA
SA -- yes --> SB
SB -- yes --> True
SA -- no --> False
SB -- no --> False
SS1 --> False
```
