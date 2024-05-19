### Flowchart of `MySQL_Session::RunQuery()`

This function mostly calls `MySQL_Connection::async_query()` with the right arguments.  
Returns an integer status code indicating the result of the query execution:
- 0: Query execution completed successfully.
- -1: Query execution failed.
- 1: Query execution in progress.
- 2: Processing a multi-statement query, control needs to be transferred to MySQL_Session.
- 3: In the middle of processing a multi-statement query.

```mermaid
---
title: MySQL_Session::RunQuery()
---
flowchart TD
RQ["MySQL_Connection::async_query()"]
BEGIN --> RQ
RQ --> END
```

### Flowchart of `MySQL_Session::handler()`

WORK IN PROGRESS

```mermaid
---
title: MySQL_Session::handler()
---
flowchart TD
RQ["rc = RunQuery()"]
RC{rc}
CBCS["rc1 = handler_ProcessingQueryError_CheckBackendConnectionStatus()"]
RC1{rc1}
RQ --> RC
RC -- 0 --> OK
RC -- -1 --> CBCS
CBCS --> RC1
CS["CONNECTING_SERVER"]
ReturnMinus1["return -1"]
RC1 -- -1 --> ReturnMinus1
RC1 -- 1 --> CS
HM1CLE1["handler_minus1_ClientLibraryError()"]
HM1CLE2["handler_minus1_ClientLibraryError()"]
myerr1{"myerr >= 2000
&&
myerr < 3000"}
RC1 --> myerr1
myerr1 -- yes --> HM1CLE1
HM1CLE1 -- true --> CS
HM1CLE1 -- false --> ReturnMinus1
HM1LEDQ1["handler_minus1_LogErrorDuringQuery()"]
myerr1 -- no --> HM1LEDQ1
HM1HEC1["handler_minus1_HandleErrorCodes()"]
HM1LEDQ1 --> HM1HEC1
HM1HEC1 -- true --> HR1{"handler_ret"}
HR1 -- 0 --> CS
HR1 --> RHR1["return handler_ret"]
HM1GEM1["handler_minus1_GenerateErrorMessage()"]
HM1HEC1 -- false --> HM1GEM1
RE["RequestEnd()"]
HM1HBC1["handler_minus1_HandleBackendConnection()"]
HM1GEM1 --> RE
RE --> HM1HBC1
```


### Flowchart of `MySQL_Session::handler_ProcessingQueryError_CheckBackendConnectionStatus()`
TODO
