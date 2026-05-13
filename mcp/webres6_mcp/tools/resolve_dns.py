# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import httpx

from webres6_mcp.server import mcp
from webres6_mcp.config import DNSPROBE_URL


@mcp.tool()
def resolve_dns_v6only(hostname: str) -> dict:
    """Probe whether a hostname resolves over IPv6-only DNS.

    Uses the webres6 dnsprobe service (libunbound, IPv6-only resolver) to perform
    a real AAAA lookup. Returns the AAAA records found, the DNS response code, and
    whether the hostname is considered IPv6-only ready.

    For hosts that are not IPv6-only ready or the test was inconclusive, 
    the report will contain a "unbound_trace" field with the full libunbound
    trace of the DNS resolution process to allow debugging and reasoning on the failure cause.
    This trace is base64 encoded and usually quite large.
    These traces can be large — skip them during initial processing and only
    decode them when investigating specific DNS problems.
    Reading the unbound_trace from end towards start in ~50l chunks works well to find
    the relevant query and response without loading the entire trace into memory.
    """
    with httpx.Client(follow_redirects=True, timeout=15) as client:
        r = client.get(f"{DNSPROBE_URL}/dnsprobe/resolve6only({hostname})")
        r.raise_for_status()
        return r.json()
