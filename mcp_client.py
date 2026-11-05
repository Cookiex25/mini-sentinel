"""Helpers for connecting to an MCP server over stdio and calling its tools."""
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE = Path(__file__).resolve().parent


def server_params(script: str, extra_env: dict | None = None) -> StdioServerParameters:
    """How to launch a server script as a subprocess (the stdio transport)."""
    env = {**os.environ, **(extra_env or {})}
    return StdioServerParameters(
        command=sys.executable, args=[str(BASE / script)], env=env, cwd=str(BASE)
    )


def gateway_params(agent_name: str, role: str, extra_env: dict | None = None):
    """Each agent gets its own gateway process, so the gateway knows who it is."""
    return server_params(
        "gateway_server.py", {"AGENT_NAME": agent_name, "AGENT_ROLE": role, **(extra_env or {})}
    )


@asynccontextmanager
async def connect(params: StdioServerParameters):
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def call(session: ClientSession, tool: str, args: dict) -> str:
    result = await session.call_tool(tool, args)
    return "\n".join(c.text for c in result.content if getattr(c, "text", None))
