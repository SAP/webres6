# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

**webres6** checks IPv6-only readiness of web pages. It drives a Chrome browser via Selenium, captures every network request's remote IP, and classifies each host as IPv6-only, dual-stack, or IPv4-only. NAT64 addresses (RFC 7050) are treated as IPv6-capable.

## Architecture

Four independently deployable services:

| Service | Directory | Port | Stack |
|---------|-----------|------|-------|
| API server | `api/` | 6400 | Python/Flask + Gunicorn + Selenium |
| Web viewer | `viewer/` | 6480 | Static HTML/JS served by nginx |
| CLI client | `cli/` | — | Python/urllib3 |
| MCP server | `mcp/` | stdio | Python/FastMCP |

### API server

See @api/AGENTS.md for API server architecture details

### Viewer frontend (`viewer/`)
jQuery SPA. All result rows are rendered by cloning hidden `<template>`-class DOM elements. API base URL is discovered from `<link rel="x-webres6-api">` in the HTML. Supports drag-and-drop of JSON report files for offline analysis.

### MCP server (`mcp/`)
FastMCP server that wraps the webres6 API for use with AI assistants (Claude Code, etc.).
Supports two transports:
- **stdio** (default): the host process launches `webres6-mcp` directly.
- **streamable-http**: long-running HTTP server, mounted on `/mcp`. Used by the
  Helm chart and `docker-compose.dev.yml` to provide a shared remote MCP endpoint.

Mode is selected by `--transport {stdio,http}` (CLI flag) or `WEBRES6_MCP_TRANSPORT` env var.
The flag overrides the env var.

**Run manually:**
```bash
cd mcp && source .venv/bin/activate
webres6-mcp                                # stdio (default)
webres6-mcp --transport http               # HTTP on FASTMCP_HOST:FASTMCP_PORT
```

**Configuration (environment variables):**
| Variable | Default | Purpose |
|----------|---------|---------|
| `WEBRES6_API_URL` | `https://webres6.dev.sap/res6` | API endpoint for crawl requests |
| `DNSPROBE_API_URL` | `https://webres6.dev.sap/dnsprobe` | DNS probe endpoint |
| `WEBRES6_VIEWER_URL` | derived from `WEBRES6_API_URL` (strips `/res6`) | Browsable UI base, used in `viewer_url` field of trimmed reports |
| `WEBRES6_MCP_TRANSPORT` | `stdio` | Transport: `stdio` or `http` |
| `WEBRES6_HTTP_CACHE_TTL` | `600` | Max seconds to cache upstream API responses (caps `Cache-Control` from upstream so immutable headers don't pin entries for weeks). Set to `0` to disable. |
| `FASTMCP_HOST` | `127.0.0.1` | Listen address (HTTP mode) |
| `FASTMCP_PORT` | `8000` | Listen port (HTTP mode) |

**Exposed tools:** `check_website_ipv6_readiness`, `resolve_dns_v6only`, `get_websites_IPv6only_scoreboard`

**Exposed resources** (templated, addressed by URI):
- `webres6://report/{report_id}` — full trimmed report
- `webres6://report/{report_id}/summary` — top-level scores + counts only
- `webres6://report/{report_id}/host/{hostname}` — full untrimmed host subtree
- `webres6://report/{report_id}/host/{hostname}/dns_trace` — base64 libunbound trace
- `webres6://report/{report_id}/screenshot` — PNG screenshot of the page (when the crawl was run with `screenshot != none`)

The `check_website_ipv6_readiness` tool returns a trimmed report (heavy fields like
`urls`, `subject_alt_names`, full `whois.network`, `dns.unbound_trace`, and `screenshot`
collapsed to counts/flags) plus `resource_link` content blocks pointing at the per-host
detail, DNS-trace, and screenshot resources for drill-down. The tool's `screenshot`
parameter (`none`/`small`/`medium`/`full`, default `none`) controls whether a screenshot
is captured.

## Commands

See @api/AGENTS.md for API server related commands

### Development setup
```bash
./create-virtualenvs.sh          # create api/.venv, cli/.venv, and mcp/.venv; also registers .githooks
```

### Run the CLI
```bash
cd cli && source .venv/bin/activate
./webres6_cli.py https://example.com
```

### Docker
```bash
docker-compose build webres6-api
docker-compose build webres6-viewer
docker-compose up                     # full stack (requires IPv6-capable Docker)
```
`docker-compose.yml` symlinks to `docker-compose.dev.yml`. `docker-compose.host.yml` is for production (host networking, Traefik, longer TTLs, `./data/` volumes).

### Helm
A Helm chart in `helm/` is available for Kubernetes deployments. It covers the API, viewer, and dnsprobe services, plus ingress, HPA, and a scoreboard-backup job.

```bash
helm install webres6 ./helm -f helm/values.yaml
```

After any change to `helm/`, always lint and validate rendering:
```bash
helm lint helm/
helm template webres6 helm/ -f helm/values.yaml > /dev/null
```

## Integration testing

To do proper integration testing, build the latest docker containers and start them using `docker-compose.dev.yml`.
Then run `curl http://localhost:6400/res6/url(URL)` and analyze the output.

## Versioning

The canonical version lives in `VERSION`. The pre-commit hook (registered by `create-virtualenvs.sh`) enforces that `api/webres6_api.py`, `api/pyproject.toml`, `mcp/pyproject.toml`, and both `version` and `appVersion` fields in `helm/Chart.yaml` all match `VERSION`. Update all of them when bumping the version.