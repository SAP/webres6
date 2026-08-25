# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import hishel
import hishel.httpx as hishel_httpx
import httpx

from mcp.server.caching import CacheHint
from mcp.server.mcpserver import MCPServer

_HTTP_CACHE_TTL = float(os.environ.get("WEBRES6_HTTP_CACHE_TTL", "600"))

# Created at module load; lifespan closes it properly on shutdown.
# Reports are content-addressed and the API/S3 send `Cache-Control: public,
# immutable`, so a process-local cache massively reduces redundant fetches.
# We cap entry lifetime at WEBRES6_HTTP_CACHE_TTL so upstream "immutable"
# headers don't pin entries for weeks.
_cache_dir = Path(tempfile.mkdtemp(prefix="webres6-mcp-cache-"))

http_client: httpx.AsyncClient = hishel_httpx.AsyncCacheClient(
    storage=hishel.AsyncSqliteStorage(
        database_path=_cache_dir / "http.db",
        default_ttl=_HTTP_CACHE_TTL,
    ),
    follow_redirects=True,
    timeout=30,
)


@dataclass
class AppState:
    """Lifespan state passed to tools via ctx.request_context.lifespan_context."""
    http_client: httpx.AsyncClient


@asynccontextmanager
async def lifespan(_server: MCPServer):
    try:
        yield AppState(http_client=http_client)
    finally:
        await http_client.aclose()
        shutil.rmtree(_cache_dir, ignore_errors=True)


mcp = MCPServer(
    "webres6",
    instructions=(
        "Tools for checking IPv6-only readiness of web pages and DNS hostnames. "
        "Use check_website_ipv6_readiness to analyse a full URL, resolve_dns_v6only to probe a "
        "single hostname, get_website_scoreboard to see recent results, and get_report to "
        "retrieve a previously stored report by ID. "
        "NAT64 addresses in reports are an artifact of the test environment and should be treated as IPv4."
    ),
    lifespan=lifespan,
    # Tell MCP clients they may cache resources/read responses. Reports are
    # content-addressed so 600 s is safe; scope=public allows sharing across
    # auth contexts (the API has no per-user data).
    cache_hints={"resources/read": CacheHint(ttl_ms=600_000, scope="public")},
)
