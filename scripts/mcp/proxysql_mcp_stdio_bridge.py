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

# DON'T redirect stderr - it may interfere with stdout/stdin pipes
# Commented out to test if this is causing the issue
# LOG_FILE = "/tmp/proxysql_mcp_bridge.log"
# stderr_log_file = open(LOG_FILE, "a", buffering=1)
# sys.stderr = stderr_log_file
# sys.__stderr__ = stderr_log_file

# Debug logging - write to file instead of stderr to avoid pipe interference
LOG_FILE = "/tmp/proxysql_mcp_bridge.log"
_log_file = open(LOG_FILE, "a", buffering=1)

def log_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def debug_log(msg: str):
    """Write to log file instead of stderr."""
    timestamp = log_timestamp()
    _log_file.write(f"[{timestamp}] {msg}\n")
    _log_file.flush()

def log_separator(char="=", length=80):
    _log_file.write(char * length + "\n")
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
        log_separator("=")
        debug_log("[ProxySQLMCPEndpoint] Initializing connection to ProxySQL MCP server")
        log_separator("=")

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

        log_separator("=")
        debug_log("[ProxySQLMCPEndpoint] Initialization complete")
        log_separator("=")
        return response

    async def _call(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Make a JSON-RPC call to ProxySQL MCP endpoint."""
        if not self._client:
            raise RuntimeError("Client not initialized")

        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        log_separator("-")
        debug_log(f"[HTTP REQUEST TO PROXYSQL MCP SERVER]")
        debug_log(f"  URL: {self.endpoint}")
        debug_log(f"  Headers: {json.dumps(headers)}")
        debug_log(f"  Body: {json.dumps(request, indent=2)}")
        log_separator("-")

        try:
            r = await self._client.post(self.endpoint, json=request, headers=headers)
            r.raise_for_status()
            response = r.json()

            log_separator("-")
            debug_log(f"[HTTP RESPONSE FROM PROXYSQL MCP SERVER]")
            debug_log(f"  Status: {r.status_code}")
            debug_log(f"  Headers: {dict(r.headers)}")
            debug_log(f"  Body: {json.dumps(response, indent=2)}")
            log_separator("-")

            return response
        except httpx.HTTPStatusError as e:
            error_resp = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"HTTP error: {e.response.status_code}",
                    "data": str(e)
                },
                "id": request.get("id", "")
            }
            log_separator("-")
            debug_log(f"[HTTP ERROR FROM PROXYSQL MCP SERVER]")
            debug_log(f"  Status: {e.response.status_code}")
            debug_log(f"  Response: {e.response.text}")
            debug_log(f"  Error Response: {json.dumps(error_resp, indent=2)}")
            log_separator("-")
            return error_resp
        except Exception as e:
            error_resp = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                },
                "id": request.get("id", "")
            }
            log_separator("-")
            debug_log(f"[EXCEPTION DURING HTTP REQUEST]")
            debug_log(f"  Exception: {type(e).__name__}: {e}")
            debug_log(f"  Error Response: {json.dumps(error_resp, indent=2)}")
            log_separator("-")
            return error_resp

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
        log_separator("=")
        debug_log("[PROXYSQL MCP STDIO BRIDGE STARTING]")
        debug_log(f"  Endpoint: {self.proxysql_endpoint}")
        debug_log(f"  Auth Token: {'***SET***' if self.auth_token else 'NONE'}")
        debug_log(f"  Verify SSL: {self.verify_ssl}")
        log_separator("=")

        async with ProxySQLMCPEndpoint(self.proxysql_endpoint, self.auth_token, self.verify_ssl) as client:
            self._proxysql = client

            # Send initialized notification
            await self._write_notification("notifications/initialized")

            # Main message loop
            msg_count = 0
            while True:
                try:
                    line = await self._readline()
                    if not line:
                        debug_log("[STDIN CLOSED - RECEIVED EOF]")
                        break

                    msg_count += 1
                    log_separator("=")
                    debug_log(f"[MESSAGE #{msg_count} - RECEIVED FROM STDIN]")
                    debug_log(f"  Raw line: {repr(line)}")
                    debug_log(f"  Parsed JSON:")
                    try:
                        message = json.loads(line)
                        debug_log(f"    {json.dumps(message, indent=4)}")
                    except json.JSONDecodeError as e:
                        debug_log(f"    [INVALID JSON - {e}]")
                        raise
                    log_separator("=")

                    response = await self._handle_message(message)

                    if response:
                        log_separator("=")
                        debug_log(f"[MESSAGE #{msg_count} - SENDING TO STDOUT]")
                        debug_log(f"  Response JSON:")
                        debug_log(f"    {json.dumps(response, indent=4)}")
                        log_separator("=")
                        await self._writeline(response)
                    else:
                        debug_log(f"[MESSAGE #{msg_count} - NO RESPONSE (notification only)]")

                except json.JSONDecodeError as e:
                    debug_log(f"[JSON DECODE ERROR]: {e}")
                    debug_log(f"  Invalid line: {repr(line)}")
                    await self._write_error(-32700, f"Parse error: {e}", "")
                except Exception as e:
                    debug_log(f"[HANDLER ERROR]: {e}")
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    await self._write_error(-32603, f"Internal error: {e}", "")

    async def _readline(self) -> Optional[str]:
        """Read a line from stdin."""
        loop = asyncio.get_event_loop()
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            return None
        return line.strip()

    async def _writeline(self, data: Any):
        """Write JSON data to stdout."""
        output = json.dumps(data, ensure_ascii=False) + "\n"
        output_bytes = output.encode('utf-8')

        debug_log(f"[_writeline] Writing {len(output_bytes)} bytes to stdout")
        debug_log(f"[_writeline] sys.stdout: {sys.stdout}")
        debug_log(f"[_writeline] sys.stdout.buffer: {sys.stdout.buffer}")

        # Write directly to the binary buffer to avoid any TextIOWrapper issues
        # This bypasses Python's text encoding layer and writes raw bytes
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, sys.stdout.buffer.write, output_bytes)
        await loop.run_in_executor(None, sys.stdout.buffer.flush)

        debug_log(f"[_writeline] Flush complete")

    async def _write_notification(self, method: str, params: Optional[Dict[str, Any]] = None):
        """Write a notification (no id)."""
        notification = {
            "jsonrpc": "2.0",
            "method": method
        }
        if params:
            notification["params"] = params
        debug_log(f"[NOTIFICATION] Sending: {json.dumps(notification, indent=4)}")
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

        debug_log(f"[HANDLE MESSAGE] method='{method}', id='{req_id}'")

        if method == "initialize":
            return await self._handle_initialize(req_id, params)
        elif method == "tools/list":
            return await self._handle_tools_list(req_id)
        elif method == "tools/call":
            return await self._handle_tools_call(req_id, params)
        elif method == "ping":
            debug_log(f"[ping] Responding with status=ok")
            return {"jsonrpc": "2.0", "result": {"status": "ok"}, "id": req_id}
        else:
            debug_log(f"[HANDLE MESSAGE] Unknown method: {method}")
            await self._write_error(-32601, f"Method not found: {method}", req_id)
            return None

    async def _handle_initialize(self, req_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initialize request."""
        debug_log(f"[initialize] Handling request with id={req_id}")
        debug_log(f"[initialize] Client params: {json.dumps(params, indent=4)}")

        result = {
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
        debug_log(f"[initialize] Sending response: {json.dumps(result['result'], indent=4)}")
        return result

    async def _handle_tools_list(self, req_id: str) -> Dict[str, Any]:
        """Handle tools/list request - forward to ProxySQL."""
        if not self._proxysql:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "ProxySQL client not initialized"},
                "id": req_id
            }

        response = await self._proxysql.tools_list()

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
        if not self._proxysql:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "ProxySQL client not initialized"},
                "id": req_id
            }

        name = params.get("name", "")
        arguments = params.get("arguments", {})

        debug_log(f"[tools/call] Calling tool='{name}' with args: {json.dumps(arguments)}")

        response = await self._proxysql.tools_call(name, arguments, req_id)

        if "error" in response:
            debug_log(f"[tools/call] Error from ProxySQL: {response['error']}")
            return {
                "jsonrpc": "2.0",
                "error": response["error"],
                "id": req_id
            }

        # Simply pass through the result - no wrapping, no unwrapping
        debug_log(f"[tools/call] Returning result: {json.dumps(response.get('result', {}))}")
        return {
            "jsonrpc": "2.0",
            "result": response.get("result", {}),
            "id": req_id
        }


async def main():
    log_separator("=")
    debug_log("[PROXYSQL MCP STDIO BRIDGE - MAIN STARTING]")
    log_separator("=")

    # Get configuration from environment
    endpoint = os.getenv("PROXYSQL_MCP_ENDPOINT", "https://127.0.0.1:6071/mcp/query")
    token = os.getenv("PROXYSQL_MCP_TOKEN", "")
    insecure_ssl = os.getenv("PROXYSQL_MCP_INSECURE_SSL", "0").lower() in ("1", "true", "yes")

    debug_log(f"[CONFIG] PROXYSQL_MCP_ENDPOINT: {endpoint}")
    debug_log(f"[CONFIG] PROXYSQL_MCP_TOKEN: {'***SET***' if token else 'NOT SET'}")
    debug_log(f"[CONFIG] PROXYSQL_MCP_INSECURE_SSL: {insecure_ssl}")
    debug_log(f"[CONFIG] LOG_FILE: {LOG_FILE}")
    log_separator("=")

    # Validate endpoint
    if not endpoint:
        sys.stderr.write("Error: PROXYSQL_MCP_ENDPOINT environment variable is required\n")
        sys.exit(1)

    # Run the server
    server = StdioMCPServer(endpoint, token or None, verify_ssl=not insecure_ssl)

    try:
        await server.run()
    except KeyboardInterrupt:
        debug_log("[MAIN] Interrupted by KeyboardInterrupt")
    except Exception as e:
        debug_log(f"[MAIN] ERROR: {e}")
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
