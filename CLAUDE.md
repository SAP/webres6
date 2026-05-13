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
Communicates over stdio; the host process launches it directly.

**Run manually:**
```bash
cd mcp && source .venv/bin/activate
webres6-mcp
```

**Configuration (environment variables):**
| Variable | Default | Purpose |
|----------|---------|---------|
| `WEBRES6_API_URL` | `https://webres6.dev.sap/res6` | API endpoint for crawl requests |
| `DNSPROBE_API_URL` | `https://webres6.dev.sap/dnsprobe` | DNS probe endpoint |

**Exposed tools:** `check_website_ipv6_readiness`, `resolve_dns_v6only`, `get_website_scoreboard`, `get_report`

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

## Integration testing

To do proper integration testing, build the latest docker containers and start them using `docker-compose.dev.yml`.
Then run `curl http://localhost:6400/res6/url(URL)` and analyze the output.

## Versioning

The canonical version lives in `VERSION`. The pre-commit hook (registered by `create-virtualenvs.sh`) enforces that `api/webres6_api.py` and both `version` and `appVersion` fields in `helm/Chart.yaml` all match `VERSION`. Update all three when bumping the version.