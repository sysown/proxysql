# **ProxySQL Prepared Statement Parameter Tracking Reference Manual**
This document describes the changes made to the logging of prepared statement parameters in ProxySQL.  
Two logging formats are supported:
- **Binary Format (Format 1)** via `write_query_format_1()`
- **JSON Format (Format 2)** via `write_query_format_2_json()` (also using `extractStmtExecuteMetadataToJson()`)
## **1. Overview**
ProxySQL logs query events in two different formats.  
For prepared statements (i.e. `COM_STMT_EXECUTE` events), the logging functions now log extra parameter details.  
Both formats encode the number of parameters and, for each parameter, log its type and a human-readable string value, with special handling for `NULL` values.
## **2. Binary Format Details (**`write_query_format_1()`**)**
When logging a prepared statement execution in binary format, the following steps occur:
- **Encoded Basic Query Data:**
Standard fields such as event type, thread ID, username, schema name, client/server info, timestamps, query digest, and the query text itself are encoded using a variable-length encoding scheme.
- **Logging Prepared Statement Parameters:**
If the event type is `PROXYSQL_COM_STMT_EXECUTE` and valid statement metadata is present:

- The number of parameters is encoded using `mysql_encode_length()`.
- A **null bitmap** is constructed with one bit per parameter (set when the parameter is `NULL`).
- For each parameter:
  - Two bytes are written to store the parameter's type.
  - If the parameter is not `NULL`, the function `getValueForBind()` is used to convert the binary data into a human-readable string.
  - The length of the converted value is encoded (again using `mysql_encode_length()`), and then the raw bytes of the converted value are written.
- **Sequential Write Process:**
All the fields are written sequentially. First, the total length of the event record is written (as a fixed-size 8-byte field), then each encoded field and the additional prepared statement parameter details.
## **3. JSON Format Details (**`write_query_format_2_json()`**)**
In JSON format, the logging function produces a JSON object that includes all standard query details plus additional fields for prepared statement parameters:
- **Base JSON Object Information:**
The JSON object includes key fields such as thread_id, username, schemaname, client, server information (if available), timestamps (starttime, endtime), duration, digest, etc.
- **Event Type:**
Depending on the event type, the field `"event"` is set to `"COM_STMT_EXECUTE"` (or `"COM_STMT_PREPARE"` / `"COM_QUERY"`) accordingly.
- **Logging Prepared Statement Parameters:**
If the event type is `PROXYSQL_COM_STMT_EXECUTE` and the session contains valid statement metadata:

- The helper function `extractStmtExecuteMetadataToJson(json &j)` is called.
- This function iterates over each parameter:
  - For `NULL` parameters, it logs `"type": "NULL"` and `"value": null`.
  - For non-`NULL` parameters, it uses getValueForBind() to obtain the parameter type (e.g., `"INT24"`, `"VARCHAR"`) and its string representation.
- The result is a JSON array attached to the key `"parameters"`, where each element is an object with keys `"type"` and `"value"`.
- **Output:**
Finally the JSON object is dumped as a single line in the log file using `j.dump()`.
## **4. Detailed Example**
For example, consider a prepared statement with two parameters. The resulting JSON log might look like:

```json
{
    "hostgroup_id": 3,
    "thread_id": 12345,
    "event": "COM_STMT_EXECUTE",
    "username": "dbuser",
    "schemaname": "production",
    "client": "192.0.2.1",
    "server": "10.0.0.5",
    "rows_affected": 1,
    "query": "INSERT INTO foo (bar1, bar2) VALUES (?, ?)",
    "starttime_timestamp_us": 1617181920000000,
    "starttime": "2021-03-31 12:32:00.000000"
    "endtime_timestamp_us": 1617181921000000,
    "endtime": "2021-03-31 12:32:01.000000",
    "duration_us": 1000000,
    "digest": "0x0000000000000001", "client_stmt_id": 101,
    "parameters": [
        {
            "type": "INT24",
            "value": "42"
        },
        {
            "type": "VARCHAR",
            "value": "example value"
        }
    ]
}
```

This JSON structure clearly shows each parameter’s type and value, which aids in debugging and analysis.
## **5. Usage Considerations**
- **Debuggability:**
The enhanced logging allows administrators to see the full details of the parameters that are bound to a prepared statement. This is crucial for troubleshooting and performance analysis.
- **Variable-Length Encoding:**
Both binary and JSON formats rely on helper functions (`mysql_encode_length()` and `getValueForBind()`) to ensure that variable-length integers and parameter values are handled efficiently and unambiguously.
- **Thread Safety and Performance:**
The logging functions acquire write locks just before writing to disk to minimize contention. The design ensures that logging does not adversely impact performance while retaining detailed information.
## **6. Summary**
The changes in both `write_query_format_1()` and `write_query_format_2_json()` provide a comprehensive way to log prepared statement parameters:
- In **binary format**, parameters are logged with a parameter count, a null bitmap, a two-byte parameter type, and then a variable-length encoded value.
- In **JSON format**, parameters appear as an array of objects under the `"parameters"` key, with each object containing `"type"` and `"value"` fields.

These enhancements aim to improve troubleshooting capabilities and ensure that all necessary information is captured for later analysis.