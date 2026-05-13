# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import httpx

from webres6_mcp.server import mcp
from webres6_mcp.config import WEBRES6_API_URL


@mcp.tool()
def get_report(report_id: str) -> dict:
    """Retrieve a previously stored webres6 report by its ID.

    The report ID is returned in the 'ID' field of every check_website_ipv6_readiness
    result and the 'report_id' field of the get_websites_scoreboard tool.
    Returns the full report JSON, or an error if the report has expired or does not exist.

    See check_website_ipv6only_readiness for the full response structure, jq snippets,
    and notes on NAT64 addresses, whois information, and parsing unbound_trace fields.
    """
    with httpx.Client(follow_redirects=True, timeout=30) as client:
        r = client.get(f"{WEBRES6_API_URL}/report/{report_id}")
        r.raise_for_status()
        data = r.json()
    data.pop("screenshot", None)
    return data
