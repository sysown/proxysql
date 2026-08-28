#!/usr/bin/env python3
"""
ProxySQL MCP stdio Bridge

Translates between stdio-based MCP (for Claude Code) and ProxySQL's HTTPS MCP endpoint.

Usage:
    export PROXYSQL_MCP_ENDPOINT="https://127.0.0.1:6071/mcp/query"
    export PROXYSQL_MCP_TOKEN="your_token"  # optional
    python proxysql_mcp_stdio_bridge.py

Or configure in Claude Code's MCP settings:
    {
      "mcpServers": {
        "proxysql": {
          "command": "python3",
          "args": ["/path/to/proxysql_mcp_stdio_bridge.py"],
          "env": {
            "PROXYSQL_MCP_ENDPOINT": "https://127.0.0.1:6071/mcp/query",
            "PROXYSQL_MCP_TOKEN": "your_token"
          }
        }
      }
    }
"""

import asyncio
import json
import os
import sys
from typing import Any, Dict, Optional
from datetime import datetime

import httpx

# Minimal logging to file for debugging
# Log path can be configured via PROXYSQL_MCP_BRIDGE_LOG environment variable
_log_file_path = os.getenv("PROXYSQL_MCP_BRIDGE_LOG", "/tmp/proxysql_mcp_bridge.log")
_log_file = open(_log_file_path, "a", buffering=1)
def _log(msg):
    _log_file.write(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}\n")
    _log_file.flush()


class ProxySQLMCPEndpoint:
    """Client for ProxySQL's HTTPS MCP endpoint."""

    def __init__(self, endpoint: str, auth_token: Optional[str] = None, verify_ssl: bool = True):
        self.endpoint = endpoint
        self.auth_token = auth_token
        self.verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None
        self._initialized = False

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=120.0,
            verify=self.verify_ssl,
        )
        # Initialize connection
        await self._initialize()
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    async def _initialize(self):
        """Initialize the MCP connection."""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "proxysql-mcp-stdio-bridge",
                    "version": "1.0.0"
                }
            }
        }
        response = await self._call(request)
        self._initialized = True
        return response

    async def _call(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Make a JSON-RPC call to ProxySQL MCP endpoint."""
        if not self._client:
            raise RuntimeError("Client not initialized")

        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        try:
            r = await self._client.post(self.endpoint, json=request, headers=headers)
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"HTTP error: {e.response.status_code}",
                    "data": str(e)
                },
                "id": request.get("id", "")
            }
        except httpx.RequestError as e:
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32002,
                    "message": f"Request to ProxySQL failed: {e}"
                },
                "id": request.get("id", "")
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                },
                "id": request.get("id", "")
            }

    async def tools_list(self) -> Dict[str, Any]:
        """List available tools."""
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        return await self._call(request)

    async def tools_call(self, name: str, arguments: Dict[str, Any], req_id: str) -> Dict[str, Any]:
        """Call a tool."""
        request = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }
        return await self._call(request)


class StdioMCPServer:
    """stdio-based MCP server that bridges to ProxySQL's HTTPS MCP."""

    def __init__(self, proxysql_endpoint: str, auth_token: Optional[str] = None, verify_ssl: bool = True):
        self.proxysql_endpoint = proxysql_endpoint
        self.auth_token = auth_token
        self.verify_ssl = verify_ssl
        self._proxysql: Optional[ProxySQLMCPEndpoint] = None
        self._request_id = 1

    async def run(self):
        """Main server loop."""
        async with ProxySQLMCPEndpoint(self.proxysql_endpoint, self.auth_token, self.verify_ssl) as client:
            self._proxysql = client

            # Send initialized notification
            await self._write_notification("notifications/initialized")

            # Main message loop
            while True:
                try:
                    line = await self._readline()
                    if not line:
                        break

                    message = json.loads(line)
                    response = await self._handle_message(message)

                    if response:
                        await self._writeline(response)

                except json.JSONDecodeError as e:
                    await self._write_error(-32700, f"Parse error: {e}", "")
                except asyncio.CancelledError:
                    raise  # Re-raise to allow proper task cancellation
                except Exception as e:
                    await self._write_error(-32603, f"Internal error: {e}", "")

    async def _readline(self) -> Optional[str]:
        """Read a line from stdin."""
        loop = asyncio.get_running_loop()
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            return None
        return line.strip()

    async def _writeline(self, data: Any):
        """Write JSON data to stdout."""
        loop = asyncio.get_running_loop()
        output = json.dumps(data, ensure_ascii=False) + "\n"
        _log(f"WRITE stdout: {len(output)} bytes: {repr(output[:200])}")
        await loop.run_in_executor(None, sys.stdout.write, output)
        await loop.run_in_executor(None, sys.stdout.flush)
        _log(f"WRITE stdout: flushed")

    async def _write_notification(self, method: str, params: Optional[Dict[str, Any]] = None):
        """Write a notification (no id)."""
        notification = {
            "jsonrpc": "2.0",
            "method": method
        }
        if params:
            notification["params"] = params
        await self._writeline(notification)

    async def _write_response(self, result: Any, req_id: str):
        """Write a response."""
        response = {
            "jsonrpc": "2.0",
            "result": result,
            "id": req_id
        }
        await self._writeline(response)

    async def _write_error(self, code: int, message: str, req_id: str):
        """Write an error response."""
        response = {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message
            },
            "id": req_id
        }
        await self._writeline(response)

    async def _handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle an incoming message."""
        method = message.get("method")
        req_id = message.get("id", "")
        params = message.get("params", {})

        if method == "initialize":
            return await self._handle_initialize(req_id, params)
        elif method == "tools/list":
            return await self._handle_tools_list(req_id)
        elif method == "tools/call":
            return await self._handle_tools_call(req_id, params)
        elif method == "ping":
            return {"jsonrpc": "2.0", "result": {"status": "ok"}, "id": req_id}
        else:
            await self._write_error(-32601, f"Method not found: {method}", req_id)
            return None

    async def _handle_initialize(self, req_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initialize request."""
        return {
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "proxysql-mcp-stdio-bridge",
                    "version": "1.0.0"
                }
            },
            "id": req_id
        }

    async def _handle_tools_list(self, req_id: str) -> Dict[str, Any]:
        """Handle tools/list request - forward to ProxySQL."""
        if not self._proxysql:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "ProxySQL client not initialized"},
                "id": req_id
            }

        response = await self._proxysql.tools_list()

        # The response from ProxySQL is the full JSON-RPC response
        # We need to extract the result and return it in our format
        if "error" in response:
            return {
                "jsonrpc": "2.0",
                "error": response["error"],
                "id": req_id
            }

        return {
            "jsonrpc": "2.0",
            "result": response.get("result", {}),
            "id": req_id
        }

    async def _handle_tools_call(self, req_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/call request - forward to ProxySQL."""
        name = params.get("name", "")
        arguments = params.get("arguments", {})
        _log(f"tools/call: name={name}, id={req_id}")

        if not self._proxysql:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "ProxySQL client not initialized"},
                "id": req_id
            }

        response = await self._proxysql.tools_call(name, arguments, req_id)
        _log(f"tools/call: response from ProxySQL: {json.dumps(response)[:500]}")

        if "error" in response:
            return {
                "jsonrpc": "2.0",
                "error": response["error"],
                "id": req_id
            }

        # ProxySQL MCP server now returns MCP-compliant format with content array
        # Just pass through the result directly
        result = response.get("result", {})
        _log(f"tools/call: returning result: {json.dumps(result)[:500]}")
        return {
            "jsonrpc": "2.0",
            "result": result,
            "id": req_id
        }


async def main():
    # Get configuration from environment
    endpoint = os.getenv("PROXYSQL_MCP_ENDPOINT", "https://127.0.0.1:6071/mcp/query")
    token = os.getenv("PROXYSQL_MCP_TOKEN", "")
    insecure_ssl = os.getenv("PROXYSQL_MCP_INSECURE_SSL", "0").lower() in ("1", "true", "yes")

    _log(f"START: endpoint={endpoint}, insecure_ssl={insecure_ssl}")

    # Validate endpoint
    if not endpoint:
        sys.stderr.write("Error: PROXYSQL_MCP_ENDPOINT environment variable is required\n")
        sys.exit(1)

    # Run the server
    server = StdioMCPServer(endpoint, token or None, verify_ssl=not insecure_ssl)

    try:
        _log("Starting server.run()")
        await server.run()
    except KeyboardInterrupt:
        _log("KeyboardInterrupt")
    except Exception as e:
        _log(f"Error: {e}")
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
