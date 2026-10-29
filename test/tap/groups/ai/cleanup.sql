-- AI Group MCP Cleanup
-- Removes MCP configuration after tests complete
-- Variables are substituted using envsubst before execution

SET mcp-enabled='false';
LOAD MCP VARIABLES TO RUNTIME;
SAVE MCP VARIABLES TO DISK;

SET genai-enabled='false';
LOAD GENAI VARIABLES TO RUNTIME;
SAVE GENAI VARIABLES TO DISK;

DELETE FROM mcp_target_profiles WHERE target_id IN ('${MCP_TARGET_ID}', '${MCP_PGSQL_TARGET_ID}');
DELETE FROM mcp_auth_profiles WHERE auth_profile_id IN ('${MCP_AUTH_PROFILE_ID}', '${MCP_PGSQL_AUTH_PROFILE_ID}');
LOAD MCP PROFILES TO RUNTIME;
SAVE MCP PROFILES TO DISK;

DELETE FROM mysql_servers WHERE hostgroup_id IN (${MCP_MYSQL_HOSTGROUP_ID});
DELETE FROM pgsql_servers WHERE hostgroup_id IN (${MCP_PGSQL_HOSTGROUP_ID});
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;
