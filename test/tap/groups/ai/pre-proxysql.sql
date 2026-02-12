# Enable MCP module for AI test group
SET mcp-enabled=true;
SET mcp-port=6071;

# Configure MCP to use MySQL backend from infra-default
# Backend hostname: mysql1.infra-default (Docker network hostname)
SET mcp-mysql_hosts='mysql1.infra-default';
SET mcp-mysql_ports='3306';
SET mcp-mysql_user='root';
SET mcp-mysql_password='root';

# Apply configuration
LOAD MCP VARIABLES TO RUNTIME;
SAVE MCP VARIABLES TO DISK;
