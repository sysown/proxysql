-- AI Group MCP Configuration
-- This SQL is executed by the test runner to configure MCP for AI tests
-- Variables are substituted using envsubst before execution

-- Configure MCP variables
SET mcp-port='${TAP_MCP_PORT}';
SET mcp-use_ssl='false';
SET mcp-config_endpoint_auth='${TAP_MCP_AUTH_TOKEN_SQL}';
SET mcp-stats_endpoint_auth='${TAP_MCP_AUTH_TOKEN_SQL}';
SET mcp-query_endpoint_auth='${TAP_MCP_AUTH_TOKEN_SQL}';
SET mcp-admin_endpoint_auth='${TAP_MCP_AUTH_TOKEN_SQL}';
SET mcp-cache_endpoint_auth='${TAP_MCP_AUTH_TOKEN_SQL}';
SET mcp-ai_endpoint_auth='${TAP_MCP_AUTH_TOKEN_SQL}';
SET mcp-rag_endpoint_auth='${TAP_MCP_AUTH_TOKEN_SQL}';
SET mcp-enabled='false';
LOAD MCP VARIABLES TO RUNTIME;
SAVE MCP VARIABLES TO DISK;

-- Initialize the AI feature manager before the MCP listener constructs the
-- AI and RAG endpoint handlers.
SET genai-enabled='true';
LOAD GENAI VARIABLES TO RUNTIME;
SAVE GENAI VARIABLES TO DISK;

-- Configure MySQL servers for MCP
DELETE FROM mysql_servers WHERE hostgroup_id IN (0, ${MCP_MYSQL_HOSTGROUP_ID});
INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, comment)
    VALUES (0, '${TAP_MYSQLHOST}', ${TAP_MYSQLPORT}, 'ONLINE', 1, 'ai local mysql');
INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, comment)
    VALUES (${MCP_MYSQL_HOSTGROUP_ID}, '${TAP_MYSQLHOST}', ${TAP_MYSQLPORT}, 'ONLINE', 1, 'ai mcp mysql');
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

-- Configure PostgreSQL servers for MCP
DELETE FROM pgsql_servers WHERE hostgroup_id IN (${MCP_PGSQL_HOSTGROUP_ID});
INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, weight, comment)
    VALUES (${MCP_PGSQL_HOSTGROUP_ID}, '${TAP_PGSQLSERVER_HOST}', ${TAP_PGSQLSERVER_PORT}, 'ONLINE', 1, 'ai mcp pgsql');
LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;

-- Configure frontend users for TAP tests
INSERT OR REPLACE INTO mysql_users (username, password, active, default_hostgroup, comment)
    VALUES ('${TAP_MYSQLUSERNAME}', '${TAP_MYSQLPASSWORD}', 1, 0, 'ai local');
INSERT OR REPLACE INTO mysql_users (username, password, active, default_hostgroup, comment)
    VALUES ('testuser', 'testuser', 1, 0, 'ai local');
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;

-- Configure MCP auth profiles
DELETE FROM mcp_auth_profiles WHERE auth_profile_id IN ('${MCP_AUTH_PROFILE_ID}', '${MCP_PGSQL_AUTH_PROFILE_ID}');
INSERT INTO mcp_auth_profiles (auth_profile_id, db_username, db_password, default_schema, use_ssl, ssl_mode, comment)
    VALUES ('${MCP_AUTH_PROFILE_ID}', '${TAP_MYSQLUSERNAME}', '${TAP_MYSQLPASSWORD}', '${MYSQL_DATABASE}', 0, '', 'ai mysql mcp auth');
INSERT INTO mcp_auth_profiles (auth_profile_id, db_username, db_password, default_schema, use_ssl, ssl_mode, comment)
    VALUES ('${MCP_PGSQL_AUTH_PROFILE_ID}', '${TAP_PGSQLSERVER_USERNAME}', '${TAP_PGSQLSERVER_PASSWORD}', '${PGSQL_DATABASE}', 0, '', 'ai pgsql mcp auth');

-- Configure MCP target profiles
DELETE FROM mcp_target_profiles WHERE target_id IN ('${MCP_TARGET_ID}', '${MCP_PGSQL_TARGET_ID}');
INSERT INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id, description, max_rows, timeout_ms, allow_explain, allow_discovery, active, comment)
    VALUES ('${MCP_TARGET_ID}', 'mysql', ${MCP_MYSQL_HOSTGROUP_ID}, '${MCP_AUTH_PROFILE_ID}', 'AI local MySQL target', 200, 5000, 1, 1, 1, 'ai local');
INSERT INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id, description, max_rows, timeout_ms, allow_explain, allow_discovery, active, comment)
    VALUES ('${MCP_PGSQL_TARGET_ID}', 'pgsql', ${MCP_PGSQL_HOSTGROUP_ID}, '${MCP_PGSQL_AUTH_PROFILE_ID}', 'AI local PostgreSQL target', 200, 5000, 1, 1, 1, 'ai local');

LOAD MCP PROFILES TO RUNTIME;
SAVE MCP PROFILES TO DISK;

-- Enable MCP
SET mcp-enabled='true';
LOAD MCP VARIABLES TO RUNTIME;
SAVE MCP VARIABLES TO DISK;
