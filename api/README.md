# WebRes6 API Server

This is the REST API server component of the IPv6 Web Resource Checker (webres6). It provides endpoints for analyzing web page IPv6 readiness using Selenium WebDriver automation.
For overall setup & requirements, please see [top level README.md](../README.md)

- [WebRes6 API Server](#webres6-api-server)
  - [Usage](#usage)
  - [API Server Configuration](#api-server-configuration)
  - [Architecture](#architecture)
  - [Extension Mechanisms](#extension-mechanisms)
    - [Hooking Functions](#hooking-functions)
    - [Example Extensions:](#example-extensions)
      - [Chrome Extension Loader (`serverconfig/webres6_selenium_extension.py`)](#chrome-extension-loader-serverconfigwebres6_selenium_extensionpy)
      - [DNS-over-HTTPS Configuration (`serverconfig/webres6_selenium_extension.googledns.py`)](#dns-over-https-configuration-serverconfigwebres6_selenium_extensiongooglednspy)

## Usage

```bash
# Start web service
./webres6_api.py [options]

Options:
  -h, --help                  Show this help message and exit
  --port PORT                 Port to listen on (default: 6400)
  --debug                     Enable debugging output
  --dnsprobe-only             Start in DNS-probe-only mode, serving only the /dnsprobe/* endpoints
  --export-scoreboard sb.json Export scoreboard entries to JSON file and exit
  --import-scoreboard sb.json Import scoreboard entries from JSON file and exit
  --export-reports /to/dir/   Export all archived reports to the given directory and exit
  --import-reports /from/dir  Import all archived reports from the given directory and exit
  --expire                    Expire local cache entries and exit

Environment variables:
  ADMIN_API_KEY               API key required for /admin/* endpoints. When unset, those endpoints are open (intentional, for trusted networks).
  DEBUG                       Comma-separated debug flags: whois, hostinfo, flask, viewer, trace, unbound
  SELENIUM_REMOTE_URL         Use a remote Selenium server instead of starting Selenium for each request
  SELENIUM_USERNAME           Basic-auth username for SELENIUM_REMOTE_URL (optional)
  SELENIUM_PASSWORD           Basic-auth password for SELENIUM_REMOTE_URL (optional)
  HEADLESS_SELENIUM           Run Selenium in headless mode (default: false)
  SELENIUM_TIMEOUT_MIN        Min timeout for Selenium operations in seconds (default: 20)
  SELENIUM_TIMEOUT_MAX        Max timeout for Selenium operations in seconds (default: 90)
  CRAWL_JOBS                  Number of background crawl worker threads (default: 4)
  CRAWL_TIMEOUT               Timeout for the entire crawl including dnsprobe and whois (default: 4*SELENIUM_TIMEOUT_MAX)
  CLIENT_RETRY_BASE           Min seconds before clients retry fetching an in-progress report (default: 6)
  NAT64_PREFIXES              Comma-separated list of NAT64 prefixes (default: 64:ff9b::/96)
  ENABLE_DNSPROBE             Check DNS entries encountered during the crawl for IPv6-only readiness (default: true)
  DNSPROBE_API_URL            Use external DNS-probe service at this URL (uses internal implementation if unset)
  DNSPROBE_JOBS               Number of parallel DNS probe lookups per crawl (default: 8)
  DNSPROBE_WORKERS            Number of unbound resolver workers (default: 4)
  DNSPROBE_CACHE_TTL          DNS-probe in-process result cache TTL in seconds (default: 60)
  DNSPROBE_TIMEOUT            DNS-probe per-query timeout in seconds (default: 30)
  UNBOUND_DEBUG_LEVEL         libunbound verbosity, apples to DEBUG="unbound" and DNS failure reports (default: 4)
  UNBOUND_V6ONLY_CONF         Path to the unbound v6-only config (default: <api>/unbound.v6only.conf)
  VALKEY_URL                  URL for Valkey/Redis cache; also stores reports if S3_BUCKET/ARCHIVE_DIR are unset
  S3_BUCKET                   Name of S3 bucket to use for report storage (requires VALKEY_URL)
  S3_ENDPOINT                 S3 endpoint to use for report storage
  S3_DELIVERY_STRATEGY        'public'    - redirect to S3 bucket using a public URL
                              'presigned' - redirect to S3 bucket using a presigned URL
                              'private'   - fetch object from S3 and deliver from API (default: public)
  ARCHIVE_DIR                 Directory for optional filesystem-based report storage
  LOCAL_CACHE_DIR             Directory for optional local filesystem-based cache if VALKEY_URL is unset
  ENABLE_WHOIS                Enable clients to request WHOIS lookups (default: true)
  WHOIS_CACHE_TTL             Expiry time for WHOIS cache in seconds (default: 270000)
  WHOIS_JOBS                  Number of parallel WHOIS lookups per crawl (default: 8)
  RESULT_CACHE_TTL            Expiry time for result cache in seconds (default: 900)
  RESULT_ARCHIVE_TTL          Expiry time for result archive in seconds (default: 90 days)
  ERROR_CACHE_TTL             TTL for caching error responses in seconds (default: 180)
  ENABLE_SCOREBOARD           Maintain a scoreboard of public results (default: true)
  SCOREBOARD_REQUEST_LIMIT    Max scoreboard entries returned per request (default: 1024)
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT  OTLP endpoint for trace export (enables tracing when set)
  OTEL_EXPORTER_OTLP_ENDPOINT Fallback OTLP endpoint if *_TRACES_ENDPOINT unset
  OTEL_TRACING_ENABLED        Override tracing on/off (defaults to true if an endpoint is set)
  OTEL_CONSOLE_EXPORTER_ENABLED  Mirror traces to stderr (defaults to true when DEBUG=trace)
  OTEL_SERVICE_NAME           Service name reported in traces (default: webres6-api)
  OTEL_DEPLOYMENT_ENVIRONMENT Deployment-environment attribute on traces (default: production)

API endpoints:
  /ping                       liveliness probe (just answers ok)
  /healthz                    readiness probe (checks backend availability)
  /res6/ping                  liveliness probe scoped to the /res6 namespace
  /res6/$metadata             OData metadata document
  /res6/serverconfig          list available extensions, screenshot modes, whois support, ...
  /res6/url(URL)              JSON results for the given URL (kicks off a crawl if needed)
  /res6/report/<report_id>    fetch a previously generated report by ID
  /res6/scoreboard            current scoreboard entries
  /dnsprobe/ping              liveliness probe for DNS-probe logic
  /dnsprobe/resolve6only(host)  resolve AAAA records for the given hostname IPv6-only
  /metrics                    Prometheus-compatible metrics
  /admin/expire               tell storage manager to expire old whois cache and scoreboard entries (requires ADMIN_API_KEY if set)
  /admin/persist              tell storage manager to persist data to disk (requires ADMIN_API_KEY if set)
  /[#URL]                     Web app to initiate analysis and display results
```

## API Server Configuration

All configuration is either done by environment variables (see above) or files in the `serverconfig/` directory.

 - `serverconfig/MESSAGE` - Welcome/warning message to put on top of the Web App
 - `serverconfig/PRIVACY` – Privacy policy to include in the Web App footer
 - `serverconfig/url-blocklist` - list of URL patterns to block (passed to Chromium's Network.setBlockedURLs)

## Architecture

The API server is built with Flask and uses Selenium WebDriver to crawl web pages and analyze their IPv6 readiness. It consists of several key components:

- **Main API endpoints** (`webres6_api.py`) - Flask application providing REST endpoints
- **Selenium crawler** (`webres6_crawler.py`) - Selenium WebDriver management, page crawling, and host extraction from performance logs; also owns the URL blocklist and public suffix list
- **NAT64 support** (`webres6_nat64.py`) - Monkey-patches `ipaddress.IPv6Address` with NAT64 detection; loaded at startup via `import webres6_nat64`
- **DNS probe client/server** (`webres6_dnsprobe.py`) - `DNSprobe` class used by the API to resolve hostnames over IPv6-only; also shared with the `dnsprobe/` service
- **Storage management** (`webres6_storage.py`) - Handles result caching and persistence
- **WHOIS integration** (`webres6_whois.py`) - Provides IP address ownership information
- **Custom extensions** (`webres6_extension.py`) - Hooks to modify browser automation framework

## Extension Mechanisms

The IPv6 Web Resource checker can be extended by adding custom selenium/python logic into `webres6_selenium_extension.py`. 
This, for example, enables adding Chrome extensions, custom DNS configurations, and specialized crawling behaviors.

- **Default Implementation**: The base `webres6_extension.py` provides a no-op template
- **Custom Implementations**: Place custom `serverconfig/webres6_extension.py` to override default behavior (`serverconfig/` dir is prepended to the PYTHON-PATH during startup)

See `webres6_extension.py` for descriptions of the hooking functions. 

### Example Extensions:

#### Chrome Extension Loader (`serverconfig/webres6_extension.loadcrx.py`)
- Discovers Chrome extensions from `.crx` files in the `serverconfig/` directory
- Presents list of discovered extensions through the `/res6/serverconfig` API endpoint 
- Loads requested extension via `ChromeOptions.add_extension()`

#### DNS-over-HTTPS Configuration (`serverconfig/webres6_extension.googledns.py`)
- Configures Chrome to use DNS-over-HTTPS with Google DNS
- Sets secure DNS mode with IPv6-capable DNS64 endpoint
- Adds DOH template URL to the report
