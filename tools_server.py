"""The RAW MCP server: exposes the tools with NO policy checks.

Agents are meant to connect through gateway_server.py instead. Connecting
here directly is the "MCP bypass" attack in attacks.py.
"""
import tools_impl
from mcp_compat import MCPServer

server = MCPServer("raw-tools", log_level="WARNING")


@server.tool()
def list_files() -> str:
    """List the files in the data folder."""
    return tools_impl.list_files()


@server.tool()
def read_file(path: str) -> str:
    """Read a text file from the data folder."""
    return tools_impl.read_file(path)


@server.tool()
def fetch_url(url: str) -> str:
    """Fetch a web page."""
    return tools_impl.fetch_url(url)


@server.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return tools_impl.send_email(to, subject, body)


@server.tool()
def delete_file(path: str) -> str:
    """Delete a file from the data folder."""
    return tools_impl.delete_file(path)


if __name__ == "__main__":
    server.run()  # stdio by default; use server.run("streamable-http") for HTTP
