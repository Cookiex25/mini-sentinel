"""Works with both versions of the MCP Python SDK.

MCP SDK v2 renamed FastMCP to MCPServer. CrewAI still installs v1, so we
accept either. Both have the same @server.tool() decorator and .run().
"""
try:
    from mcp.server.mcpserver import MCPServer  # MCP SDK v2
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer  # MCP SDK v1

__all__ = ["MCPServer"]
