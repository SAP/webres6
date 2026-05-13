# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import time
from typing import Annotated

import httpx
from urllib.parse import quote

from webres6_mcp.server import mcp
from webres6_mcp.config import WEBRES6_API_URL


@mcp.tool()
def check_website_ipv6only_readiness(
    url: Annotated[str, "The URL of the website to check. Include the scheme (http:// or https://)."],
    scoreboard: Annotated[bool, "Whether to add this result to the public scoreboard. Ask the user before setting this to true."] = False,
) -> dict:
    """Check the IPv6-only readiness of a web page.

    Drives a real Chrome browser through the webres6 API, captures every network
    request and classifies each host as IPv6-only, dual-stack, or IPv4-only.
    Returns the full report including per-host connection and DNS results enriched
    with WHOIS data for each IP address.

    May take up to 30 seconds for a fresh crawl.

    NAT64 addresses (address_family "NAT64") are an artifact of the test environment
    and should be treated as IPv4-only hosts.

    If IPv6-only DNS resolution is not possible or inconclusive, the report still
    contains observed HTTP connections. For those hosts with DNS issues, 
    the 'dns' dict will contain an 'unbound_trace' field (base64-encoded).
    The 'dns' section of the trace is identical to the output of the
    resolve_dns_v6only tool for the same hostname, so the same analysis techniques apply.

    The WHOIS data gives a hint about the nature of the host (e.g. CDN, cloud provider, ISP, corporate, etc.)
    and can be useful to identify patterns in IPv6 readiness or investigate 3rd party dependencies.
    However, the accuracy of WHOIS data can vary and it should not be solely relied upon for critical decisions.
    Especially for cloud providers, the same ASN does not imply whether the website operator has control over the host
    or the host is a 3rd party dependency.

    Useful jq snippets:
      jq '{ipv6_only_ready, ipv6_only_score, ipv6_only_http_score, ipv6_only_dns_score}'  # overall result + scores
      jq '.hosts | map_values(.ips | keys)'         # IPs per host
      jq '.hosts | map_values(.urls | length)'      # resource count per host

    Response structure (fields may be absent depending on crawl results and API params):
    {
      "ID": str,                    # unique report ID
      "error_code": int,            # HTTP status of the crawl (200 = success)
      "ts": str,                    # ISO-8601 timestamp
      "url": str,                   # crawled URL
      "domain": str,                # eTLD+1
      "ipv6_only_ready": bool,      # true only if ALL hosts are IPv6-only ready
      "ipv6_only_score": float,     # fraction of resources from IPv6-only hosts (0.0–1.0)
      "ipv6_only_http_score": float,# score based on observed HTTP connections only
      "ipv6_only_dns_score": float, # score based on DNS resolution only
      "hosts": {
        "<hostname>": {
          "urls": [str],            # all URLs loaded from this host
          "ips": {
            "<ip>": {
              "address_family": str,      # "IPv6", "IPv4", or "NAT64"
              "transport": [[str, str]],  # e.g. [["h2", "TLS 1.3"]] or [["h3", "QUIC"]]
              "whois": {
                "asn": str, "asn_description": str, "asn_country": str,
                "network": { "name": str, "cidr": str, "country": str | null }
              }
            }
          },
          "dns": {
            "success": bool,
            "rcode": str,                    # e.g. "no error" or "nxdomain"
            "canonical_name": str | null,
            "aaaa_records": [str] | null,
            "ipv6_only_ready": bool | null
          }
        }
      },
      "scoreboard_entry": bool,
      "timings": { "init": float, "crawl": float, "extract": float,
                   "dnsprobe": float, "whois": float, "finalize": float }
    }
    """
    with httpx.Client(follow_redirects=True, timeout=30) as client:
        encoded = quote(url, safe="")
        endpoint = f"{WEBRES6_API_URL}/url({encoded})"
        params = {"screenshot": "false", "whois": "true", "scoreboard": str(scoreboard).lower()}

        for _ in range(10):
            r = client.get(endpoint, params=params)

            if r.status_code == 202:
                delay = int(r.headers.get("Refresh", "15"))
                time.sleep(delay)
                continue

            r.raise_for_status()
            data = r.json()
            # remove screenshot, and subject_alt_names from the report to reduce size
            data.pop("screenshot", None)
            for host in data.get("hosts", {}).values():
                host.pop("subject_alt_names", None)
            return data

    return {"error": "Crawl did not complete after 10 retries", "url": url}
