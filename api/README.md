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
./webres6-server.py [options]

Options:
  -h, --help                  Show this help message and exit
  --port PORT                 Port to listen on (default: 6400)
  --debug                     Enable debugging output
  --export-scoreboard sb.json export scoreboard entries to JSON file and exit
  --import-scoreboard sb.json import scoreboard entries from JSON file and exit
  --export-reports /to/dir/   export all archived reports to the given directory and exit
  --import-reports /from/dir  import all archived reports from the given directory and exit

Environment variables:
  ADMIN_API_KEY               API Key to call privileged functions
  TIMEOUT                     Maximum timeout value in seconds
  NAT64_PREFIXES              Comma-separated list of NAT64 prefixes
  SELENIUM_REMOTE_URL         Use remote Selenium server instead of starting selenium for each request
  DNSPROBE_API_URL            Enable DNS checking using specified dns probe service
  VALKEY_URL                  URL for optional VALKEY cache, will also store reports if S3_BUCKET/ARCHIVE_DIR are not set
  S3_BUCKET                   Name of S3 bucket to use for report storage (requires valkey to be set)
  S3_ENDPOINT                 S3 Endpoint to use for report storage
  S3_DELIVERY_STRATEGY        'public'    - redirect to S3 bucket using a public URL
                              'presigned' - redirect to S3 bucket using a presigned URL
                              'private'   - fetch object from S3 and deliver from API
  ARCHIVE_DIR                 DIR for optional filesystem-based report storage
  LOCAL_CACHE_DIR             DIR for optional LOCAL filesystem-based cache
  ENABLE_WHOIS                Enable clients to request whois lookups
  WHOIS_CACHE_TTL             Expiry time for whois cache
  RESULT_CACHE_TTL            Expiry time for result cache
  RESULT_ARCHIVE_TTL          Expiry time for result archive

API endpoints:
  /ping                       liveness probe endpoint
  /res6/$metadata             get OData metadata document
  /res6/srvconfig             list available extensions, screenshot-modes, whois support, ...
  /res6/url(URL)              get JSON results for URL provided
  /res6/scoreboard            get current scoreboard entries
  /metrics                    Prometheus compatible metrics (requires ADMIN_API_KEY if set)
  /admin/expire               tell stoarge manager to expire old whois cache and scoreboard entries (requires ADMIN_API_KEY if set)
  /admin/persist              tell storage manager to persists data to disk (requires ADMIN_API_KEY if set)
  /[#URL]                     Web app to initiate analysis and display results
```

## API Server Configuration

All configuration is either done by environment variables (see above) or files in the `serverconfig/` directory.

 - `serverconfig/MESSAGE` - Welcome/warning message to put on top of the Web App
 - `serverconfig/PRIVACY` – Privacy policy to include in the Web App footer
 - `serverconfig/url-blocklist` - list of URL patterns to block (passed to Chromium's Network.setBlockedURLs)

## Architecture

The API server is built with Flask and uses Selenium WebDriver to crawl web pages and analyze their IPv6 readiness. It consists of several key components:

- **Main API endpoints** (`webres6-api.py`) - Flask application providing REST endpoints
- **Storage management** (`webres6_storage.py`) - Handles result caching and persistence  
- **WHOIS integration** (`webres6_whois.py`) - Provides IP address ownership information
- **Custom extensions** (`webres6_extension.py`) - Hooks to modify browser automation framework
- **DNSprobe** – External API to check IPv6-only readiness of the DNS records (see top level `dnsprobe` directory)

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
