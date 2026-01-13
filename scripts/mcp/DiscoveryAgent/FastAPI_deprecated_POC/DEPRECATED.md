# DEPRECATED - Proof of Concept Only

This FastAPI implementation was an initial prototype and **is not working**.

The MCP protocol implementation here is incorrect - it attempts to call tool names directly as JSON-RPC methods instead of using the proper `tools/call` wrapper.

## Use the Rich CLI Instead

For a working implementation, use the **Rich CLI** version in the `../Rich/` directory:
- `Rich/discover_cli.py` - Working async CLI with Rich TUI
- Proper MCP `tools/call` JSON-RPC method
- Full tracing and debugging support

## Status

- Do NOT attempt to run this code
- Kept for reference/archival purposes only
- May be removed in future commits
