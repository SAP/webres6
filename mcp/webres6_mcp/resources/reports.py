# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import base64

from webres6_mcp.server import mcp
from webres6_mcp.tools.reports import _trim_report, fetch_full_report


@mcp.resource(
    "webres6://report/{report_id}",
    name="webres6 report (trimmed)",
    description="Full trimmed report. Same shape as the check_website_ipv6only_readiness result.",
    mime_type="application/json",
)
async def report(report_id: str) -> dict:
    return _trim_report(await fetch_full_report(report_id))


@mcp.resource(
    "webres6://report/{report_id}/summary",
    name="webres6 report summary",
    description="Top-level scores and host counts only. Smallest payload.",
    mime_type="application/json",
)
async def report_summary(report_id: str) -> dict:
    full = await fetch_full_report(report_id)
    hosts = full.get("hosts", {})
    return {
        "ID": full.get("ID"),
        "ts": full.get("ts"),
        "url": full.get("url"),
        "domain": full.get("domain"),
        "ipv6_only_ready": full.get("ipv6_only_ready"),
        "ipv6_only_score": full.get("ipv6_only_score"),
        "ipv6_only_http_score": full.get("ipv6_only_http_score"),
        "ipv6_only_dns_score": full.get("ipv6_only_dns_score"),
        "host_count": len(hosts),
        "ipv6_only_host_count": sum(1 for h in hosts.values() if h.get("dns", {}).get("ipv6_only_ready")),
        "screenshot_available": bool(full.get("screenshot")),
        "error_code": full.get("error_code"),
    }


@mcp.resource(
    "webres6://report/{report_id}/host/{hostname}",
    name="webres6 host detail",
    description="Full untrimmed host subtree (urls, subject_alt_names, full whois, dns).",
    mime_type="application/json",
)
async def report_host(report_id: str, hostname: str) -> dict:
    full = await fetch_full_report(report_id)
    host = full.get("hosts", {}).get(hostname)
    if host is None:
        return {"error": f"hostname {hostname!r} not found in report {report_id}"}
    # strip the unbound_trace; it has its own resource
    if isinstance(host.get("dns"), dict):
        host["dns"].pop("unbound_trace", None)
    return host


@mcp.resource(
    "webres6://report/{report_id}/host/{hostname}/dns_trace",
    name="webres6 DNS unbound trace",
    description="Base64-encoded libunbound resolver trace for one host's DNS resolution.",
    mime_type="text/plain",
)
async def report_dns_trace(report_id: str, hostname: str) -> str:
    full = await fetch_full_report(report_id)
    host = full.get("hosts", {}).get(hostname, {})
    return host.get("dns", {}).get("unbound_trace") or ""


@mcp.resource(
    "webres6://report/{report_id}/screenshot",
    name="webres6 report screenshot",
    description="PNG screenshot of the crawled page. Only present if the crawl was run with screenshot != none.",
    mime_type="image/png",
)
async def report_screenshot(report_id: str) -> bytes:
    full = await fetch_full_report(report_id)
    encoded = full.get("screenshot")
    if not encoded:
        return b""
    return base64.b64decode(encoded)
