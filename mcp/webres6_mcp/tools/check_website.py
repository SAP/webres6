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
def check_website_ipv6_readiness(
    url: Annotated[str, "The URL of the website to check. Include the scheme (http:// or https://)."],
    scoreboard: Annotated[bool, "Whether to add this result to the public scoreboard. Ask the user before setting this to true."] = False,
) -> dict:
    """Check the IPv6-only readiness of a web page.

    Drives a real Chrome browser through the webres6 API, captures every network
    request and classifies each host as IPv6-only, dual-stack, or IPv4-only.
    Returns the full report including per-host connection and DNS results.

    The report is enriched with Whois information for each IP address encountered
    to allow reasoning on the hosting provider and operational ownership.

    If the report contains a NAT64 address, these need to be treated as IPv4 addresses
    as it is only an artifact of the testing environment.

    A list of all hosts and their ips can me extracted by using
    `jq '.hosts | map_values(.ips | keys)'` on the report JSON.

    A the number of resources loaded from  hosts can be extracted by using
    `jq '.hosts | map_values(.urls| length)'` on the report JSON.

    If IPv6-only DNS resolution is not possible, the report will still contain 
    the observed HTTP connections to estimate what would be missing from an IPv6-only perspective.
    For these hosts, the 'dns' dictionary will contain a field 'unbound_trace' with a 
    detailed base64 encoded trace of the DNS resolution process, which can be used to diagnose why 
    IPv6-only resolution failed or was inconclusive. As these traces can be quite large,
    excluding them from initial processing and parsing then from bottom when 
    going into specific hosts of interest is recommended.

    May take up to 30 seconds for a fresh crawl.

    Response JSON structure:
    {
      "ID": str,                    # unique report ID
      "webres6_version": str,
      "browser": {                  # Chrome capabilities used
        "browserName": str,
        "browserVersion": str,
        "platformName": str,
        "acceptInsecureCerts": bool
      },
      "error_code": int,            # HTTP status of the crawl (200 = success)
      "ts": str,                    # ISO-8601 timestamp of the crawl
      "url": str,                   # crawled URL
      "domain": str,                # eTLD+1 of the crawled URL
      "ipv6_only_ready": bool,      # true if ALL hosts are IPv6-only ready
      "ipv6_only_score": float,     # fraction of hosts that are IPv6-only ready (0.0–1.0)
      "ipv6_only_http_score": float,# score based on observed HTTP connections only
      "ipv6_only_dns_score": float, # score based on DNS resolution only (may be absent)
      "hosts": {                    # one entry per hostname contacted by the browser
        "<hostname>": {
          "local_part": str,        # subdomain prefix of hostname (empty for apex)
          "domain_part": str,       # eTLD+1 of hostname
          "urls": [str],            # all URLs loaded from this host
          "ips": {                  # one entry per IP address actually connected to
            "<ip-address>": {
              "address_family": str,  # "IPv6", "IPv4", or "NAT64"
              "transport": [[str, str]], # list of [protocol, tls_version] pairs,
                                        # e.g. [["h2", "TLS 1.3"]] or [["h3", "QUIC"]]
              "whois": {            # WHOIS data for this IP (present when whois=true)
                "ts": str,
                "asn": str,
                "asn_description": str,
                "asn_country": str,
                "network": {
                  "name": str,
                  "handle": str,
                  "country": str | null,
                  "cidr": str
                }
              }
            }
          },
          "dns": {                  # DNS probe result for this hostname
            "hostname": str,
            "success": bool,
            "time_elapsed": float,
            "ts": str,
            "rcode": str,           # DNS response code, e.g. "no error" or "nxdomain"
            "nxdomain": bool,
            "canonical_name": str | null,  # CNAME target if applicable
            "aaaa_records": [str] | null,  # IPv6 addresses from DNS; null if IPv4-only
            "ipv6_only_ready": bool | null # true if DNS resolves to at least one
                                           # IPv6 or NAT64 address; null if unknown
          },
        }
      },
      "scoreboard_entry": bool,     # true if this result was added to the scoreboard
      "timings": {                  # per-phase wall-clock durations in seconds
        "init": float, "crawl": float, "extract": float,
        "dnsprobe": float, "whois": float, "finalize": float
      },
      "doh_template": str,          # DNS-over-HTTPS template used by the probe
      "webres6_origin": str         # API server identifier
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
