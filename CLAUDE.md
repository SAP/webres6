# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

**webres6** checks IPv6-only readiness of web pages. It drives a Chrome browser via Selenium, captures every network request's remote IP, and classifies each host as IPv6-only, dual-stack, or IPv4-only. NAT64 addresses (RFC 7050) are treated as IPv6-capable.

## Commands

### Development setup
```bash
./create-virtualenvs.sh          # create api/.venv and cli/.venv and install deps
```

### Run the API server locally
```bash
cd api && source .venv/bin/activate
./webres6_api.py --debug --port 6400
```

### Run the CLI
```bash
cd cli && source .venv/bin/activate
./webres6-cli.py https://example.com
```

### Tests (api only — no tests for other components)
```bash
cd api
./run_tests.sh                        # all tests
./run_tests.sh -v                     # verbose
./run_tests.sh -c                     # with coverage (opens htmlcov/index.html on macOS)
./run_tests.sh -t test_webres6_api.py # single file
pytest test_webres6_api.py::ClassName::test_method  # single test
```
Tests use mocked Selenium, Valkey, S3, and DNSProbe — no real services required - but therefore ignore important code paths.

### Docker
```bash
docker-compose build webres6-api
docker-compose build webres6-viewer
docker-compose build webres6-dnsprobe
docker-compose up                     # full stack (requires IPv6-capable Docker)
```
`docker-compose.yml` symlinks to `docker-compose.dev.yml`. `docker-compose.host.yml` is for production (host networking, Traefik, longer TTLs, `./data/` volumes).

## Architecture

Four independently deployable services:

| Service | Directory | Port | Stack |
|---------|-----------|------|-------|
| API server | `api/` | 6400 | Python/Flask + Gunicorn + Selenium |
| Web viewer | `viewer/` | 6480 | Static HTML/JS served by nginx |
| DNS probe | `dnsprobe/` | 6453 | Python/Flask + libunbound (built from source) |
| CLI client | `cli/` | — | Python/urllib3 |

### Request flow
1. CLI or viewer calls `GET /res6/url(<url>)` on the API.
2. API calls `init_webdriver()` → Selenium (remote or local Chrome).
3. `crawl_page()` drives the browser and captures performance logs.
4. `get_hostinfo()` parses `Network.responseReceived` CDP events to extract `remoteIPAddress` per resource.
5. `add_dnsprobe_info()` calls the DNS probe for each hostname to check IPv6-only resolution.
6. `get_ipv6_only_score()` classifies each host; `gen_json()` assembles the report.
7. Report stored via `StorageManager`; ID returned to client.

### NAT64 detection
`api/webres6_api.py` monkey-patches `ipaddress.IPv6Address` with `.is_nat64` and `.nat64_extract_ipv4`. NAT64 prefixes default to `64:ff9b::/96` and are configurable via `NAT64_PREFIXES`. This makes NAT64 addresses count as IPv6-capable throughout the codebase.

### Storage abstraction (`api/webres6_storage.py`)
`StorageManager` base class with four implementations selected at startup:
- `LocalStorageManager` — filesystem only
- `ValkeyStorageManager` — Valkey/Redis only
- `ValkeyFileHybridStorageManager` — Valkey for cache, filesystem for archives
- `ValkeyS3HybridStorageManager` — Valkey for cache, S3 for archives

All WHOIS results, crawl reports, and scoreboards go through this layer. Storage backend is chosen by which environment variables are set at startup.

### Extension system
`api/serverconfig/webres6_extension.py` is a swappable file (variants in same dir: `loadcrx.py`, `googledns.py`, `debug_output.py`). It exposes hooks called at each stage of the Selenium crawl: `get_extensions()`, `init_selenium_options()`, `prepare_selenium_crawl()`, `operate_selenium_crawl()`, `cleanup_selenium_crawl()`, `finalize_report()`.

### DNS probe (`dnsprobe/`)
Uses libunbound's Python bindings (`import unbound`) to perform DNS resolution over IPv6 only (per `unbound.v6only.conf`). The Dockerfile builds unbound from source (two-stage): builder stage compiles with `--with-pyunbound`; runtime stage copies `/usr/local/lib/` and runs `ldconfig`. The `MAX_TARGET_NX` constant is increased to handle CDN DNS delegation chains.

### Viewer frontend (`viewer/`)
jQuery SPA. All result rows are rendered by cloning hidden `<template>`-class DOM elements. API base URL is discovered from `<link rel="x-webres6-api">` in the HTML. Supports drag-and-drop of JSON report files for offline analysis.

## Key environment variables

| Variable | Component | Purpose |
|----------|-----------|---------|
| `SELENIUM_REMOTE_URL` | api | Remote WebDriver URL; omit for local ChromeDriver |
| `NAT64_PREFIXES` | api | Comma-separated NAT64 prefixes |
| `ADMIN_API_KEY` | api | Required for `/metrics`, `/admin/*` endpoints |
| `ENABLE_WHOIS` | api | Enable WHOIS lookups |
| `VALKEY_URL` | api | Valkey/Redis URL |
| `S3_BUCKET`, `S3_ENDPOINT` | api | S3 storage backend |
| `WEBRES6_API_URL` | cli | Override API endpoint |
| `DEBUG` | api/dnsprobe | Comma-separated flags: `whois`, `hostinfo`, `unbound` |

## CLI exit codes
- `0` — all hosts IPv6-only ready
- `1` — at least one host has IPv4 addresses
- `2` — analysis failed

## Integration testing

To to proper integration testing, build the latest docker containers and start them using `docker-compose.dev.yml`.
Then run `curl http://localhost:6400/res6/url(URL)` and analyze the output.