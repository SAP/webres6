# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

from webres6_mcp.server import mcp, http_client
from webres6_mcp.config import WEBRES6_API_URL


@mcp.tool()
async def get_websites_IPv6only_scoreboard(limit: int = 12) -> dict:
    """Return the most recent webres6 check results from the scoreboard.

    Each entry contains the URL, domain, IPv6-only readiness flag, score, and
    timestamp of the last check. The limit parameter defaults to 12 and may be limited by the backing API.
    """
    r = await http_client.get(f"{WEBRES6_API_URL}/scoreboard", params={"limit": min(limit, 1024)})
    r.raise_for_status()
    return r.json()
