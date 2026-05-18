# AGENTS.md

This file provides guidance for coding agents about the API server components

## Commands

All commands are relativ to the directory this file resides in

### Run the API server locally
```bash
source .venv/bin/activate
./webres6_api.py --debug --port 6400
```

### Tests (api only — no tests for other components)
```bash
source .venv/bin/activate
./run_tests.sh                        # all tests
./run_tests.sh -v                     # verbose
./run_tests.sh -c                     # with coverage (opens htmlcov/index.html on macOS)
./run_tests.sh -t test_webres6_api.py # single file
pytest test_webres6_api.py::ClassName::test_method  # single test
```
Tests use mocked Selenium, Valkey, S3, and DNSProbe — no real services required - but therefore ignore important code paths.

## Architecture

### Request flow
1. CLI or viewer calls `GET /res6/url(<url>)` on the API.
2. API calls `init_webdriver()` → Selenium (remote or local Chrome).
3. `crawl_page()` in `webres6_crawler.py` drives the browser and captures performance logs.
4. `get_hostinfo()` in `webres6_crawler.py` parses `Network.responseReceived` CDP events to extract `remoteIPAddress` per resource.
5. `add_dnsprobe_info()` calls the DNS probe for each hostname to check IPv6-only resolution.
6. `get_ipv6_only_score()` classifies each host; `gen_json()` assembles the report.
7. Report stored via `StorageManager`; ID returned to client.

### NAT64 detection
`api/webres6_nat64.py` monkey-patches `ipaddress.IPv6Address` with `.is_nat64` and `.nat64_extract_ipv4`. NAT64 prefixes default to `64:ff9b::/96` and are configurable via `NAT64_PREFIXES`. This makes NAT64 addresses count as IPv6-capable throughout the codebase. `webres6_api.py` activates the patch with a bare `import webres6_nat64`.

### Storage abstraction (`api/webres6_storage.py`)
`StorageManager` base class with four implementations selected at startup based on which environment variables are set:
- `LocalStorageManager` — filesystem only (no `VALKEY_URL`); uses `LOCAL_CACHE_DIR` for cache and `ARCHIVE_DIR` for archives
- `ValkeyStorageManager` — Valkey/Redis only (`VALKEY_URL` set, no `S3_BUCKET` or `ARCHIVE_DIR`)
- `ValkeyFileHybridStorageManager` — Valkey for cache, filesystem for archives (`VALKEY_URL` + `ARCHIVE_DIR`)
- `ValkeyS3HybridStorageManager` — Valkey for cache, S3 for archives (`VALKEY_URL` + `S3_BUCKET`); delivery via `S3_DELIVERY_STRATEGY` (`public`, `presigned`, or `private`)

All WHOIS results, crawl reports, and scoreboards go through this layer.

For local S3 development using LocalStack, see `doc/s3-localstack.md` in the repo root.

### Extension system
`serverconfig/webres6_extension.py` is a swappable file (variants in same dir: `loadcrx.py`, `googledns.py`, `debug_output.py`). It exposes hooks called at each stage of the Selenium crawl: `get_extensions()`, `init_selenium_options()`, `prepare_selenium_crawl()`, `operate_selenium_crawl()`, `cleanup_selenium_crawl()`, `finalize_report()`.

### DNS probe
DNS resolution logic lives in `webres6_dnsprobe.py` (shared module used by both the API and the DNS probe service). It uses libunbound's Python bindings (`import unbound`) to perform DNS resolution over IPv6 only (per `unbound.v6only.conf`). The Dockerfile builds unbound from source (two-stage): builder stage compiles with `--with-pyunbound`; runtime stage copies `/usr/local/lib/` and runs `ldconfig`. The `MAX_TARGET_NX` constant is increased to handle CDN DNS delegation chains.

The API runs a built-in DNS probe by default. In Docker Compose (`docker-compose.dev.yml`), a dedicated `webres6-dnsprobe` container is optionally used instead (started with `--dnsprobe-only`); the API connects to it via `DNSPROBE_API_URL`. This mirrors a detached dnsprobe deployment for integration testing purposes.

## Key environment variables

The API emits OpenTelemetry traces (OTLP) and exposes Prometheus metrics. An example collector config is at `otel-collector-config.yaml` in the repo root. Tracing is enabled automatically when `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set.

| Variable | Purpose |
|----------|---------|
| `SELENIUM_REMOTE_URL` | Remote WebDriver URL; omit for local ChromeDriver |
| `NAT64_PREFIXES` | Comma-separated NAT64 prefixes |
| `ADMIN_API_KEY` | Required for `/admin/*` endpoints (open when unset, intentional for trusted networks) |
| `ENABLE_WHOIS` | Enable WHOIS lookups |
| `VALKEY_URL` | Valkey/Redis URL |
| `S3_BUCKET`, `S3_ENDPOINT` | S3 storage backend |
| `S3_DELIVERY_STRATEGY` | `public`, `presigned`, or `private` (default: `public`) |
| `ARCHIVE_DIR` | Filesystem-based report storage directory |
| `LOCAL_CACHE_DIR` | Filesystem-based cache directory |
| `SELENIUM_TIMEOUT_MAX` | Max timeout for Selenium operations in seconds (default: `90`) |
| `SELENIUM_TIMEOUT_MIN` | Min timeout for Selenium operations in seconds (default: `20`) |
| `CRAWL_JOBS` | Number of background crawl worker threads (default: `4`) |
| `CRAWL_TIMEOUT` | Timeout for the entire crawl including dnsprobe and whois (default: `4*SELENIUM_TIMEOUT_MAX`) |
| `ERROR_CACHE_TTL` | TTL in seconds for caching error responses (default: `180`) |
| `CLIENT_RETRY_BASE` | Minimum interval between retries to fetch in-progress crawl results |
| `DEBUG` | Comma-separated flags: `whois`, `hostinfo`, `flask`, `viewer`, `trace`, `unbound` |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | OTLP endpoint for trace export (enables tracing when set) |
| `OTEL_TRACING_ENABLED` | Override tracing on/off (`true`/`false`; defaults to `true` if endpoint is set) |
| `OTEL_SERVICE_NAME` | Service name reported in traces (default: `webres6-api`) |
