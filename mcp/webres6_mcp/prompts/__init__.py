# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

from typing import Annotated

from webres6_mcp.server import mcp


@mcp.prompt()
def check_ipv6_readiness(
    url: Annotated[str, "The URL of the website to check"],
) -> str:
    """Prompt to check and explain a website's IPv6-only readiness."""
    return f"""Check the IPv6-only readiness of {url}.

Ask the user whether the result should be added to the public scoreboard before running the check.

Once you have the report, present the findings as follows:
1. State the overall verdict (ready / not ready) and the score as a percentage.
2. Show a table of all hosts grouped by address family (IPv6 / IPv4), with the number of
   resources loaded from each host and the hosting provider from WHOIS data.
   If the address family is NAT64, treat it as IPv4 and remove '64:ff9b::' prefix from the IP address for better readability.
3. For hosts that are not IPv6-only ready, explain who owns them (first-party vs. third-party)
   and give hints about what it would take to fix the issue.
4. Summarize what a user on a strict-IPv6-only network would be unable to load.
"""
