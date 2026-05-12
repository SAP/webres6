# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "webres6",
    instructions=(
        "Tools for checking IPv6-only readiness of web pages and DNS hostnames. "
        "Use check_website_ipv6_readiness to analyse a full URL, resolve_dns_v6only to probe a "
        "single hostname, get_website_scoreboard to see recent results, and get_report to "
        "retrieve a previously stored report by ID."
    ),
)
