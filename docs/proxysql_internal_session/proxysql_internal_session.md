# 'PROXYSQL INTERNAL SESSION'

PROXYSQL INTERNAL SESSION is a command that is available for each MySQL connection connected to ProxySQL. It's
a powerfull tool that can be used while debugging a particular application flow for discovering how ProxySQL
is interacting with a client or a particular workload. It exposes many details about the `MySQL` session
within ProxySQL being queried, it's also an internal tool used for testing and development.

It holds information about the whole current `MySQL_Session`, including:

1. Information about the session object itself.
2. Information about the current backends connections the session is using.
3. Information about the client in use of the session.
4. Information about the client connection ('conn').
5. Information about the QPO (Query Processor Rules) output.

### 1. 'session_info' object

- **address**: The address of the session object itself, useful for debugging purposes.
- **age_ms**: The age of the session in ms.
- **autocommit**: Boolean, report if 'autocommit' is set in the session.
- **autocommit_on_hostgroup**: Reports in which hostgroup the transaction is currently active:
  - This information is obtained searching the backends hold by the 'MySQL_Session'. Since only one active
    transaction should be happening at a time `MySQL_Session::FindOneActiveTransaction` performs the hostgroup
    search.
- **backends**: An array with the information related with the server connections. This array is filled when
  the connections are actually created, the representation of the connection changes in case of being pulled
  and returned to the connection pull (multiplexing) or if the connection is fixed to the session because some
  condition has disabled multiplexing. For more information see "backend connection".
- **client**: Information about the client that is using the session. It has the following fields. More
  informaction on section "Object: client".
- **conn**: Information about the client connection. "Object: conn".
- **current_hostgroup**: Current hostgroup to which the MySQL_Session is locked, if any.
- **default_hostgroup**: The default hostgroup for this session as configured in ProxySQL for the particular
  user.
- **default_schema**: The default schema for this session as configured in ProxySQL for the particular user.
- **gtid**: Object containing GTID information of the current session:
  - **hdi**: The hostgroup id in which the last GITD was processed for the current session.
  - **last**: The last processed GITD for the current session.
- **last_HG_affected_rows**: Last hostgroup in which rows were affected by a query.
- **last_insert_id**: The last insert id of the last performed insert.
- **locked_on_hostgroup**: Hostgroup in which the session has been locked, if this value is other than '-1',
  it means that multiplexing has been disabled for current session. For reasons on why multiplexing can be
  disabled please check: [https://proxysql.com/Multiplexing/][1].
- **status**: The current internal status that ProxySQL holds for the session, the map for this values can be
  checked in `enum session_status`.
- **thread**: Memory address of the current thread hadling the session. Used for debugging purposes.
- **thread_session_id**: The internal id ProxySQL assings to the thread being used for the current session.
- **transaction_persistence**: The 'transaction_persistence' setting for the current user.

### 2. Backend object

Array holding information about each backend connection that this MySQL session is using. Many of the elements
of this object are shared with the client 'conn' object, this section only targets the elements specific to
backend 'conn' object:

#### 2.1 Backend 'conn' object

Many of the elements of this object are shared with the client 'conn' object, this section only targets the
elements specific to backend 'conn' object:

- **MultiplexDisabled**: Boolean reporting if multiplexing has been disabled for the connection due to
    `status_flags` or `auto_increment_delay_token`.
- **MultiplexDisabled_ext**: Extension of the previous flag. It also takes into account if the connection
    meets the conditions for a 'potential transaction'.
- **address**: The current address of the 'MySQL_Connection' object handling this connection.
- **auto_increment_delay_token**: Number of queries in which `multiplexing` will be disabled due to a previous
    insertion using auto-increment.
- **bytes_recv**: Bytes received from the backend by the connection (`MySQL_Connection` object).
- **bytes_recv**: Bytes sent to the backend by the connection (`MySQL_Connection` object).
- **init_connect**: The 'init_connect' query sent by ProxySQL whent he connection was started.
- **init_connect_sent**: True if 'init_connect' was succesfully sent when the connection started.
- **myconnpoll_get**: Number of times the connection has been requested from the connection pool.
- **myconnpoll_put**: Number of times the connection has been returned to the connection pool.

#### 2.1.1 'mysql' connection object

- **address**: The current address of the 'MySQL\*' object handling this connection.
- **affected_rows**: Number of rows affected by previous query, as reported by 'MySQL'.
- **charset**: The MySQL connection charset id.
- **charset_name**: The MySQL connection charset name.
- **db**: The current select 'db' in use for the MySQL connection.
- **host**: String representing the server hostname.
- **host_info**: String representing the server hostname and the connection type.
- **insert_id**: The last insert id returned by the last insert operation.
- **net**: Object exposing network information about the connection object 'MySQL\*->net' being used:
  - **fd**: Current 'fd' used.
  - **last_errno**: The last errno set.
  - **max_packet_size**: The `max_packet_size` specified.
  - **sqlstate**: The `sqlstate` reported.
- **options**: Object exposing certain options present connection object 'MySQL\*->options' being used:
  - **charset_name**: The `charset_name` option.
  - **use_ssl**: The `use_ssl` option.
- **port**: The server port being used for this connection.
- **server_status**: The server status reported by the 'MYSQL\*' connection object.
- **server_version**: A string holding the server verion.
- **thread_id**: The thread ID of the current connection
- **unix_socket**: The unix socket being used for the connection, if any.
- **user**: The name of the user currently using the connection.

#### 2.1.1 'ps' connection object

Similar to the prepared statement object present in the 'conn' object for the client connection, it holds:

- **backend_stmt_to_global_ids**: Map from the backend prepared statements to the globally registered prepared
  statements ids.
- **global_stmt_to_backend_ids**: Map from the globally registered prepared statements to the backend prepared
  statements.

#### 2.1.1 'status' connection object

Exposes the 'status_flags' held in the current 'MySQL_Connection\*' object:

- **found_rows**: Boolean holding if flag STATUS_MYSQL_CONNECTION_FOUND_ROWS is set.
- **get_lock**: Boolean holding if flag STATUS_MYSQL_CONNECTION_GET_LOCK is set.
- **has_savepoint**: Boolean holding if flag STATUS_MYSQL_CONNECTION_FOUND_ROWS is set.
- **lock_tables**: Boolean holding if flag STATUS_MYSQL_CONNECTION_LOCK_TABLES is set.
- **no_multiplex**: Boolean holding if flag STATUS_MYSQL_CONNECTION_NO_MULTIPLEX is set.
- **temporary_table**: Boolean holding if flag STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE is set.
- **user_variable**: Boolean holding if flag SSTATUS_MYSQL_CONNECTION_USER_VARIABLE is set.

#### 2.1.2 'stream' connection object

Exposes several values from the internal 'MySQL_Data_Stream' connection object:

- **DSS**: Internal MySQL datastream status (mysql_data_stream_status).
- **address**: Pointer address of the MySQL datastream. For debugging purposes.
- **bytes_recv**: Bytes received by this particular 'MySQL_Data_Stream' from the backend.
- **bytes_sent**: Bytes sent by this particular 'MySQL_Data_Stream' to the backend.
- **myconnpoll_get**: Number of times a connection has been attached to the datastream.
- **myconnpoll_put**: Number of times a connection has been detached from the datastream.
- **questions**: Number of queries that has been executed through this particular 'MySQL_Data_Stream'.

### 3. Client Object

This object holds information related to the MySQL session client:

- **DSS**: Stands for 'Data Stream Status'. Describes in which state the connection `datastream` is found.
  Could be one of the status described in the enumeration `mysql_data_stream_status`.
- **client_addr**: Object describing the client address of the current session.
  - **address**: The client ip address.
  - **port**: The client port.
- **encrypted**: Boolean flag stating if the client connection is encrypted.
- **proxy_addr**: Object describing ProxySQL address.
  - **address**: ProxySQL current address.
  - **port**: ProxySQL current port number.
- **stream**: Object holding information about the information send and received to the client.
  - **bytes_recv**: The number of bytes received from the client connection.
  - **bytes_sent**: THe number of bytes sent to the client.
  - **pkts_recv**: The number of packets received from the client.
  - **pkts_sent**: The number of packets sent to the client.
- **userinfo**: Object holding session user info.
  - **password**: Best password it's known, cleartext if possible.
  - **username**: Username.

### 4. Connection object (conn)

This object holds information related to the MySQL session connection itself. Most of the elements present in
this object are tracked **per session**, this means that it's expected to see many of them either empty, or
with default values if they haven't explicitly set during the session:

- **autocommit**: Displays if autocommit is enabled for the connection. Either "ON" or "OFF".
- **client_flag**: Holds information about different client flags used in the connection.
  - **client_found_rows**: Displays the contents of the `CLIENT_FOUND_ROWS` flag.
  - **client_multi_results**: Display the contents of the `CLIENT_MULTI_RESULTS` flag.
  - **client_multi_statements**: Display the contents of the `CLIENT_MULTI_STATEMENTS` flag.
  - **value**: Total value of the `client_flag` parameter holding all the specifies flag for the connection.
- **names**: Value of the internally tracked variable for `SET_NAMES`. IMPORTANT: This value is never updated,
  as ProxySQL never trackes this value directly, but instead with `character_*`, `COLLATION_CONNECTION` and
  related variables.
- **ps**: Object holding information about prepared statements.
  - **client_stmt_to_global_ids**: Map associating 'client_stmt_ids' to 'global_stmt_id' for this session.
    This map gets populated when clients request prepared statements.

#### MyQSL session variables:

- **action**: The last performed action by ProxySQL setting the charset. Values can be:
  - 0: UNKNOWN
  - 1: 'SET NAMES'
  - 2: 'SET CHARACETER SET'
  - 3: Charset set during connection start.
- **character_set_client**: Displays `CHARACTER_SET_CLIENT` session variable.
- **character_set_connection**: Displays `CHARACTER_SET_CONNECTION` session variable.
- **character_set_database**: Displays `CHARACTER_SET_DATABASE` session variable.
- **character_set_results**: Displays `CHARACTER_SET_RESULTS` session variable.
- **charset**: Displays the currently setted `CHARACTER SET`.
- **collation_connection**: Displays the `COLLATION` selected for the connection.
- **max_join_size**: Displays the setted value for `MAX_JOIN_SIZE` session variable.
- **no_backslash_escapes**: Keeps track of if `SQL_MODE` `NO_BACKSLASH_ESCAPES` is being set or not.
- **session_track_gtids**: Displays the value of the `SESSION_TRACK_GTID` variable.
- **sql_auto_is_null**: Displays the `SQL_SQL_AUTO_IS_NULL` session variable.
- **sql_log_bin**: Displays the `SQL_LOG_BIN` session variable.
- **sql_mode**: Displays the `SQL_SQL_MODE` session variable.
- **sql_safe_updates**: Displays the `SQL_SAFE_UPDATES` session variable.
- **sql_select_limit**: Displays the `SQL_SELECT_LIMIT` session variable.
- **status**: Holds information about the status of the connection.
  - **compression**: Boolean flag. Displays if connection is compressed.
- **time_zone**: Displays the `SQL_TIME_ZONE` session variable.
- **transaction_read**: Displays the `SQL_TRANSACTION_READ` session variable.
- **wsrep_sync_wait**: Displays the `SQL_WSREP_SYNC_WAIT` session variable.
- **group_concat_max_len**: Displays `GROUP_CONCAT_MAX_LEN` variable value.
- **isolation_level**: Displays the `TRANSACTION_ISOLATION` currently set.

### 5. QPO (Query Processor Output) object

Holds the information extracted from last query after it has been processed by the 'Query_Processor':

#### Query rules related:

This are the values that derive directly from the application of the query rules _to last query_:

- **cache_timeout**: Time a query will wait up resulset to be avaiable in query cache before running on
  backend.
- **firewall_whitelist_mode**: Mode in which the firewall whitelist is operating.
- **max_lag_ms**: Specifies if the query annotation `query_delay` was used.
- **multiplex**: Specifies if `multiplex` has been set by a query rule.
- **reconnect**: Specifies if `reconnect` has been set by a query rule.
- **retries**: Specifies if `retries` has been set by a query rule.
- **sticky_conn**: Specifies if `sticky_conn` has been set by a query rule.
- **timeout**: Specifies if `timeout` has been set by a query rule.

For extra information about these values and their meaning please refer to: [mysql_query_rules][3]

#### Query annotations related:

This are the values from 'query annotations' extracted by the 'Query_Processor' for the last query:

- **create_new_connection**: Query annotation `create_new_connection`.
- **delay**: Query annotation `query_delay`.
- **destination_hostgroup**: Query annotation `destination`.
- **max_lag_ms**: Query annotation `query_delay`.

For extra information about these values and their meaning please refer to: [query_annotations][4]

#### Specials:

- **cache_ttl**: Specifies the `cache_ttl` derived from the query rules for the last query, or the
  **cache_ttl** imposed by a `query annotation` in the last query.

[1]: https://proxysql.com/Multiplexing/
[2]: https://github.com/sysown/proxysql/issues/1599
[3]: https://proxysql.com/main-runtime/#mysql_query_rules
[4]: https://proxysql.com/query-annotations
