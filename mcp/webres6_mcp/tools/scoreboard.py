# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import httpx

from webres6_mcp.server import mcp
from webres6_mcp.config import WEBRES6_API_URL


@mcp.tool()
def get_website_scoreboard(limit: int = 12) -> dict:
    """Return the most recent webres6 check results from the scoreboard.

    Each entry contains the URL, domain, IPv6-only readiness flag, score, and
    timestamp of the last check. The limit parameter caps the number of entries
    returned (maximum 12).
    """
    with httpx.Client(follow_redirects=True, timeout=30) as client:
        r = client.get(f"{WEBRES6_API_URL}/scoreboard", params={"limit": min(limit, 12)})
        r.raise_for_status()
        return r.json()
