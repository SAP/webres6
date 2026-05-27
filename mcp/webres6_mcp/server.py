# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import atexit
import os
import shutil
import tempfile
from pathlib import Path

import hishel
import hishel.httpx as hishel_httpx
import httpx

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "webres6",
    instructions=(
        "Tools for checking IPv6-only readiness of web pages and DNS hostnames. "
        "Use check_website_ipv6_readiness to analyse a full URL, resolve_dns_v6only to probe a "
        "single hostname, get_website_scoreboard to see recent results, and get_report to "
        "retrieve a previously stored report by ID. "
        "NAT64 addresses in reports are an artifact of the test environment and should be treated as IPv4."
    ),
    host=os.environ.get("FASTMCP_HOST", "::1"),
    port=int(os.environ.get("FASTMCP_PORT", "6470")),
    stateless_http=True,
)

# Shared HTTP client used by every tool and resource. Reports are
# content-addressed and the API/S3 send `Cache-Control: public, immutable` for
# them, so a process-local cache massively reduces redundant fetches when an
# agent reads multiple resources on the same report. We cap entry lifetime at
# WEBRES6_HTTP_CACHE_TTL (default 600s) so the upstream's "weeks-long"
# immutable values can't pin the cache. Non-cacheable responses (202s from the
# crawl polling endpoint, anything without explicit cacheability) pass through
# untouched per HTTP spec.
_HTTP_CACHE_TTL = float(os.environ.get("WEBRES6_HTTP_CACHE_TTL", "600"))
_cache_dir = Path(tempfile.mkdtemp(prefix="webres6-mcp-cache-"))
atexit.register(shutil.rmtree, _cache_dir, ignore_errors=True)

http_client: httpx.AsyncClient = hishel_httpx.AsyncCacheClient(
    storage=hishel.AsyncSqliteStorage(
        database_path=_cache_dir / "http.db",
        default_ttl=_HTTP_CACHE_TTL,
    ),
    follow_redirects=True,
    timeout=30,
)
