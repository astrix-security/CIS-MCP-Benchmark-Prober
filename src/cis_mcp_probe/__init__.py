"""CIS MCP Benchmark probe — connect to an MCP server and grade it against the
CIS MCP Benchmark, producing a per-level compliance stamp."""

from .cli import main

__all__ = ["main"]
