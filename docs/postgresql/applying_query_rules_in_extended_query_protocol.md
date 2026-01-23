# Applying Query Rules in the PostgreSQL Extended Query Protocol

Starting with **ProxySQL v3.0.3**, the PostgreSQL module introduces support for the **Extended Query Protocol**.  
This protocol consists of multiple message types — **Parse**, **Bind**, **Describe**, **Execute**, **Close**, and **Sync** — which require special handling when applying query rules.  
The implementation includes specific logic to determine how these rules are evaluated and applied throughout the extended query message flow.

### Query Routing Behavior

- **Host Group Selection:** The first message in the extended query pipeline that triggers query processing determines which host group will handle the entire query sequence.
- **Connection Persistence:** Once a backend connection is established, it remains consistent for all messages in the extended query pipeline (until `Sync` message).
- **Fallback:** If no matching query rule exists, queries are routed to the default host group.

### Important: Bind and Close Statement Handling
- **No Query Processing:** Bind and Close messages do **NOT** trigger query processing or hostgroup selection.
- **Deferred Routing:** If Bind or Close is the first message in a sequence, the **NEXT** message that triggers query processing (Parse, Execute, Describe) will determine the hostgroup.

### Query Rules Application
The following query rule actions are applied at different stages of the extended query flow:

#### Parse Message Stage
These actions are evaluated and applied when the Parse packet is received:

**Messages That Can Determine Hostgroup (IF First in Pipeline)**
- Parse 
- Describe
- Execute

**Parse Message Processing**
- **Query Rewrite**: SQL text can be modified before parsing (`pgsql_query_rules -> replace_pattern`).
- **Max Packet Size**: If a packet is larger than `pgsql-max_allowed_packet` value, reject the query.
- **Block Query**: Reject query with defined error message (`pgsql_query_rules -> error_msg`).

#### Execute Message Processing
These actions are applied during the Execute phase:
- **OK Message**: Return success response to client without executing query on backend server (`pgsql_query_rules -> OK_msg`).

---

### Sequence 1: Standard Extended Query
```mermaid
sequenceDiagram
    participant C as Client
    participant P as ProxySQL
    participant B as Backend (Persistent Connection → Selected Hostgroup)

    C->>P: Parse (SELECT ... WHERE user_id=$1)
    Note over P: Apply query rules<br>• Hostgroup selection<br>• Rewrite/Block/Max packet check<br>• Backend connection established
    P->>B: Forward Parse
    B->>P: ParseComplete

    C->>P: Bind (param=123)
    Note over P: No query processing<br>Deferred if first message
    P->>P: Queue Bind

    C->>P: Describe
    Note over P: Forward only
    P->>B: Forward Describe
    B->>P: ParamDescription, RowDescription

    C->>P: Execute
    Note over P: OK_msg check
    P->>B: Forward queued Bind + Execute
    B->>P: DataRow, CommandComplete

    C->>P: Sync
    P->>B: Forward Sync
    B->>P: ReadyForQuery
```

### Sequence 2: Bind as First Message
```mermaid
sequenceDiagram
    participant C as Client
    participant P as ProxySQL
    participant B as Backend (Persistent Connection → Selected Hostgroup)

    C->>P: Bind (with prepared statement)
    Note over P: No query processing<br>Hostgroup not selected yet
    P->>P: Queue Bind

    C->>P: Execute
    Note over P: Query rules applied <br>• Hostgroup selected here <br>• Backend connection established
    P->>B: Forward queued Bind + Execute
    B->>P: Results

    C->>P: Sync
    P->>B: Forward Sync
    B->>P: ReadyForQuery
```

### Sequence 3: Multi-Statement Pipeline
```mermaid
sequenceDiagram
    participant C as Client
    participant P as ProxySQL
    participant B as Backend (Persistent Connection → HG2)

    C->>P: Parse (UPDATE users SET last_login=$1 WHERE id=$2)
    Note over P,B: Hostgroup selected → HG2<br>• Backend connection established
    P->>B: Forward Parse (same connection)

    C->>P: Parse (SELECT * FROM users WHERE id=$1)
    Note over P,B: Would normally route to HG1,<br> but uses same backend connection
    P->>B: Forward Parse

    C->>P: Bind (for UPDATE)
    Note over P,B: No query processing
    P->>P: Queue Bind

    C->>P: Execute (for UPDATE)
    P->>B: Forward Execute

    C->>P: Bind (for SELECT)
    P->>B: Forward Bind

    C->>P: Execute (for SELECT)
    P->>B: Forward Execute

    C->>P: Sync
    P->>B: Forward Sync
    B->>P: ReadyForQuery
```
