# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from typing import Annotated, Literal

from urllib.parse import quote

from mcp.types import ContentBlock, ResourceLink, TextContent

from webres6_mcp.server import mcp, http_client
from webres6_mcp.config import WEBRES6_API_URL, WEBRES6_VIEWER_URL
from webres6_mcp.tools.resolve_dns import dns_hint

common_hints = """
    NAT64 addresses (address_family "NAT64") are an artifact of the test environment
    and should be treated as IPv4-only hosts.
""" + dns_hint + """

    The WHOIS data gives a hint about the nature of the host (e.g. CDN, cloud provider, ISP, corporate, etc.)
    and can be useful to identify patterns in IPv6 readiness or investigate 3rd party dependencies.
    However, the accuracy of WHOIS data can vary and it should not be solely relied upon for critical decisions.
    Especially for cloud providers, the same ASN does not imply whether the website operator has control over the host
    or the host is a 3rd party dependency.

    The trimmed report has heavy fields removed to keep token use low. To get more
    detail, read one of these MCP resources (the report's `ID` is the report_id):

      webres6://report/{report_id}                 - the full trimmed report
      webres6://report/{report_id}/summary         - just top-level scores and counts
      webres6://report/{report_id}/host/{hostname} - full untrimmed host subtree
                                                     (urls, subject_alt_names, full whois)
      webres6://report/{report_id}/host/{hostname}/dns_trace
                                                   - the base64 unbound trace for one host
      webres6://report/{report_id}/screenshot      - PNG screenshot (if `screenshot_available`)

    Resource links pointing at the per-host detail, DNS-trace, and screenshot
    resources are emitted alongside the trimmed report, so a capable client can
    present them directly without needing to construct URIs.

    The trimmed result also includes browsable URLs:
      `viewer_url` - human-friendly UI for the report (use this when sharing with users)
      `api_url`    - raw JSON of the full untrimmed report (HTTPS)

    Trimmed report shape (per host, fields differ from the full report):
    {
      "ID": str,                    # report ID (use as report_id for resources above)
      "viewer_url": str,            # browsable URL for the report (UI)
      "api_url": str,               # HTTPS URL returning the full untrimmed report JSON
      "error_code": int,            # HTTP status of the crawl (200 = success)
      "ts": str,                    # ISO-8601 timestamp
      "url": str,                   # crawled URL
      "domain": str,                # eTLD+1
      "ipv6_only_ready": bool,      # true only if ALL hosts are IPv6-only ready
      "ipv6_only_score": float,     # fraction of resources from IPv6-only hosts (0.0–1.0)
      "ipv6_only_http_score": float,# score based on observed HTTP connections only
      "ipv6_only_dns_score": float, # score based on DNS resolution only
      "screenshot_available": bool, # if true, fetch via the screenshot resource
      "hosts": {
        "<hostname>": {
          "urls_count": int,                   # number of URLs loaded from this host (was urls[])
          "subject_alt_names_count": int,      # number of TLS SANs (was subject_alt_names[])
          "ips": {
            "<ip>": {
              "address_family": str,           # "IPv6", "IPv4", or "NAT64"
              "transport": [[str, str]],       # e.g. [["h2", "TLS 1.3"]] or [["h3", "QUIC"]]
              "whois": {
                "asn": str, "asn_description": str, "asn_country": str
                # Full whois (incl. network block) available via the host detail resource.
              }
            }
          },
          "dns": {
            "success": bool,
            "rcode": str,                      # e.g. "no error" or "nxdomain"
            "canonical_name": str | null,
            "aaaa_records": [str] | null,
            "ipv6_only_ready": bool | null,
            "unbound_trace_available": bool    # if true, fetch via dns_trace resource
          }
        }
      },
      "scoreboard_entry": bool,
      "timings": { ... }
    }

"""


def _collapse_whois(whois: dict | None) -> dict | None:
    if not whois:
        return whois
    return {k: whois[k] for k in ("asn", "asn_description", "asn_country") if k in whois}


def _trim_report(report: dict) -> dict:
    """Strip heavy fields from a report in-place and return it.

    Drops `screenshot` outright (replaced with a presence flag). For each host:
    `urls` and `subject_alt_names` become counts; per-IP `whois` is collapsed;
    `dns.unbound_trace` is replaced with a presence flag. The host detail,
    dns_trace, and screenshot resources expose the full data.
    """
    screenshot = report.pop("screenshot", None)
    report["screenshot_available"] = bool(screenshot)
    rid = report.get("ID")
    if rid:
        report["viewer_url"] = f"{WEBRES6_VIEWER_URL}/#report:{rid}"
        report["api_url"] = f"{WEBRES6_API_URL}/report/{rid}"

    for host in report.get("hosts", {}).values():
        urls = host.pop("urls", None)
        host["urls_count"] = len(urls) if urls is not None else 0

        sans = host.pop("subject_alt_names", None)
        host["subject_alt_names_count"] = len(sans) if sans is not None else 0

        for ip_entry in host.get("ips", {}).values():
            if "whois" in ip_entry:
                ip_entry["whois"] = _collapse_whois(ip_entry["whois"])

        dns = host.get("dns")
        if isinstance(dns, dict):
            trace = dns.pop("unbound_trace", None)
            dns["unbound_trace_available"] = bool(trace)

    return report


async def fetch_full_report(report_id: str) -> dict:
    """Fetch the full untrimmed report from the API. Used by the resources.

    Goes through the shared cached client (`webres6_mcp.server.http_client`),
    which honors the upstream `Cache-Control` headers but caps every entry at
    `WEBRES6_HTTP_CACHE_TTL` seconds (default 600s).
    """
    r = await http_client.get(f"{WEBRES6_API_URL}/report/{report_id}")
    r.raise_for_status()
    return r.json()


def _resource_links(report: dict) -> list[ResourceLink]:
    rid = report.get("ID")
    if not rid:
        return []

    links: list[ResourceLink] = [
        ResourceLink(
            type="resource_link",
            uri=f"webres6://report/{rid}",
            name=f"report {rid}",
            description="Full trimmed report (same shape as this tool result).",
            mimeType="application/json",
        ),
        ResourceLink(
            type="resource_link",
            uri=f"webres6://report/{rid}/summary",
            name=f"report {rid} summary",
            description="Top-level scores and host counts only.",
            mimeType="application/json",
        ),
    ]
    if report.get("screenshot_available"):
        links.append(ResourceLink(
            type="resource_link",
            uri=f"webres6://report/{rid}/screenshot",
            name=f"screenshot: {report.get('url', rid)}",
            description="PNG screenshot of the crawled page.",
            mimeType="image/png",
        ))
    for hostname, host in report.get("hosts", {}).items():
        links.append(ResourceLink(
            type="resource_link",
            uri=f"webres6://report/{rid}/host/{hostname}",
            name=f"host detail: {hostname}",
            description="Full untrimmed host subtree (urls, subject_alt_names, full whois).",
            mimeType="application/json",
        ))
        if host.get("dns", {}).get("unbound_trace_available"):
            links.append(ResourceLink(
                type="resource_link",
                uri=f"webres6://report/{rid}/host/{hostname}/dns_trace",
                name=f"DNS trace: {hostname}",
                description="Base64-encoded libunbound trace for this host's DNS resolution.",
                mimeType="text/plain",
            ))
    return links


@mcp.tool()
async def check_website_ipv6only_readiness(
    url: Annotated[str, "The URL of the website to check. Include the scheme (http:// or https://)."],
    scoreboard: Annotated[bool, "Whether to add this result to the public scoreboard. Ask the user before setting this to true."] = False,
    screenshot: Annotated[Literal["none", "small", "medium", "full"], "Take a PNG screenshot of the page. 'small' = 1024x768 viewport, 'medium' = 2048x1152, 'full' = full scrollable page. Retrieve via the screenshot resource."] = "none",
):
    """Check the IPv6-only readiness of a web page.

    Drives a real Chrome browser through the webres6 API, captures every network
    request and classifies each host as IPv6-only, dual-stack, or IPv4-only.
    Returns a trimmed report; per-host details, the DNS unbound trace, and the
    page screenshot (if requested) are available as MCP resources (see resource
    links in the result).

    May take up to 30 seconds for a fresh crawl.

    """ + common_hints
    encoded = quote(url, safe="")
    endpoint = f"{WEBRES6_API_URL}/url({encoded})"
    params = {"screenshot": screenshot, "whois": "true", "scoreboard": str(scoreboard).lower()}

    report: dict | None = None
    for _ in range(10):
        r = await http_client.get(endpoint, params=params)
        if r.status_code == 202:
            delay = int(r.headers.get("Refresh", "15"))
            await asyncio.sleep(delay)
            continue
        r.raise_for_status()
        report = r.json()
        break

    if report is None:
        return [TextContent(type="text", text=json.dumps({"error": "Crawl did not complete after 10 retries", "url": url}))]

    trimmed = _trim_report(report)
    blocks: list[ContentBlock] = [TextContent(type="text", text=json.dumps(trimmed))]
    blocks.extend(_resource_links(trimmed))
    return blocks
