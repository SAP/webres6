[![REUSE status](https://api.reuse.software/badge/github.com/SAP/webres6)](https://api.reuse.software/info/github.com/SAP/webres6)

# IPv6 Web Resource Checker (webres6)

- [IPv6 Web Resource Checker (webres6)](#ipv6-web-resource-checker-webres6)
  - [About this project](#about-this-project)
    - [Features](#features)
    - [Known limitations](#known-limitations)
  - [Requirements and Setup](#requirements-and-setup)
    - [REST API server (webres6-server.py)](#rest-api-server-webres6-serverpy)
      - [Requirements:](#requirements)
      - [Setup (development):](#setup-development)
      - [Setup (docker compose):](#setup-docker-compose)
    - [CLI Client](#cli-client)
      - [Requirements](#requirements-1)
      - [Setup (development):](#setup-development-1)
    - [Web App](#web-app)
      - [Requirements](#requirements-2)
      - [Setup](#setup)
  - [Usage](#usage)
    - [REST API server](#rest-api-server)
    - [CLI Client](#cli-client-1)
  - [Support, Feedback, Contributing](#support-feedback-contributing)
  - [Security / Disclosure](#security--disclosure)
  - [Code of Conduct](#code-of-conduct)
  - [Licensing](#licensing)

## About this project

The *IPv6 Web Resource Chceker (webres6)* is a small tool/api to checks IPv6-only readiness of a Web page or app.
It loads a given URL using Selenium and displays the IP addresses and protocols of all hosts it fetches resources from and comes with a CLI and Web client.

A pubic demo system is available at [webres6.dev.sap](https://webres6.dev.sap).

The tool is inspired by Paul Marks' [IPvFoo](https://github.com/pmarks-net/ipvfoo) browser extension. While *IPvFoo* is more flexible and interactive, *Webres6* can be run as a service and allows IPv6-only testing without installation or IPv6 on the users' client as well as automated analysis.

### Features

- Fetches a web site/app using Selenium and extracts host names and IP addresses from the performance log.
- Shows IPv4 and IPv6 addresses for all hosts used and whether the website is ready for IPv6-only clients.
- Can take screenshots from the pages crawled for debugging purpose.
- Can add WHOIS data to provide a hint about the infrastructure behind the resources.
- Can load Chrome extensions to manage cookie consent
- Can handle NAT64 on the API server side.
- Exports data using a REST API as JSON for further analysis.

The tool can be accessed using a [CLI Client](#cli) and a built-in [Web app](#web-app).

### Known limitations

Only works if Selenium is running on a dual-stack hosts (or on an IPv6-only host with NAT64).
  - If the host is IPv4-only, everything will be reported in red even if the web sites are IPv6 ready – This limitation is going to stay.
  - If the host is IPv6-only without NAT64, all IPv4-only resources are missed out. 

No auto-detection of NAT64 prefixes - prefixes other than the well-known prefix `64:ff9b::/96` need to be statically configured.

The Selenium automation is quite simple and just loads the URL. 
As modern Web pages tend to be complex, this will most likely result in many resources not getting loaded/analyzed a normal browser would load.
 - No efforts are taken to hide this being a robot
 - No delayed on-scroll content loading takes place
 - Limited Cookie consent interactions are supported through plugins -  use an extension like consent-o-matic for that.
 - Because we don't have long-term cooke state, we [expect that some advertisements and analytics may not be loaded](https://doi.org/10.48550/arXiv.2506.11947).
 - No authentication/login takes place

Without *dnsprobe*, it ignores DNS aspects: Even if this tool reports green, it is still necessary to check the whole DNS delegation chain of all hosts involved for IPv6-only realness.
With the *dnsprobe* microservice included in the project, DNS testing is a little fragile, especially in containerized environments.
A tool for more thorough DNS IPv6-only testing is [ready.chair6.net](/https://ready.chair6.net/).


## Requirements 

### API server (webres6-api)
<a id="api"/>

- Python 3.7+  
- Flask 3.1.2+
- Selenium 4.33+ with [ChromeDriver](https://chromedriver.chromium.org/) and Python support
- A dual-stack or IPv6-only host with NAT64 connectivity to run Selenium on

### CLI Client
<a id="cli"/>

- Python 3.7+  
- URLib3 2.5.0+ with URLlib3-future 2.13.906+

### Web App 

- jquery-3.7.1
- 72 web font

### DNS probe

- libunbound with python bindings
- Flask 3.1.2+
- A dual-stack or IPv6-only host with clean outbound DNS connectivity / no DNS mingling

## Setup (development):

First, you need to have Selenium installed or 
available as a service and have ```SELENIUM_REMOTE_URL``` environment variable pointing to it.

Run the following script to build virtualenvs for API and CLI: ```bash create-virtualenvs.sh ```

The *api* and *cli* code can be found in the respective folders.
Don't forget to run ```bash source .venv/bin/activate``` within the respective folder before trying to execute the python code.

## Setup (docker compose):

```bash docker-compose build``` should build the containers for the APi server and an NGNIX container serving the Web app.

```bash docker-compose up``` launches a demo environment with Selenium deployed in a separate docker container. Please note that this only works properly if your docker setup supports IPv6, which is still challenging (especially on MacOS).

## Setup (kubernetes):

There is a helm chart available in the `helm` directory with a deployment example in the `deploy` folder.

## Usage

### API server 

```bash
# Start web service
./webres6-server.py [options]

Options:
  -h, --help                  Show this help message and exit
  --port PORT                 Port to listen on (default: 6400)
  --debug                     Enable debugging output

Environment variables:
  ADMIN_API_KEY               API Key to call privileged functions
  TIMEOUT                     Maximum timeout value in seconds
  NAT64_PREFIXES              Comma-separated list of NAT64 prefixes
  SELENIUM_REMOTE_URL         Use remote Selenium server instead of starting selenium for each request
  DNSPROBE_API_URL            Enable DNS checking using specified dns probe service
  REDIS_URL                   URL for optional REDIS cache
  LOCAL_CACHE_DIR             DIR for optional LOCAL filesystem-based cache
  ENABLE_WHOIS                Enable clients to request whois lookups
  WHOIS_CACHE_TTL             Expiry time for whois cache
  RESULT_CACHE_TTL            Expiry time for result cache
  RESULT_ARCHIVE_TTL          Expiry time for result archive

API endpoints:
  /ping                       liveness probe endpoint
  /favicon.EXT                send favicon
  /res6/$metadata             get OData metadata document
  /res6/srvconfig             list available extensions, screenshot-modes, whois support, ...
  /res6/url(URL)              get JSON results for URL provided
  /metrics                    Prometheus compatible metrics
  /adm/whois/expire           expire old whois cache entries (requires ADMIN_API_KEY if set)
  /[#URL]                     Web app to initiate analysis and display results
```

### CLI Client

```bash
./webres6-cli.py [options] URL

Options:
  -h, --help                Show this help message and exit
      --api API             Base API endpoint overriding WEBRES6_API_URL env
      --srvconfig           Show server configuration - incl. supported extensions and screenshot modes - and exit
  -r, --read-json FILE.json Read JSON input from file ignoring URL argument
  -o, --save-json FILE.json Save JSON output to file
  -w, --wait WAIT           Wait time for page settle (seconds)
  -t, --timeout TIMEOUT     Timeout for page load (seconds)
  -e, --extension EXTENSION Extension to use (must be available on server)
  -s, --screenshot MODE     Request a screenshot from the server (default: none)
  -S, --display-screenshot  Display screenshot in terminal (implies --screenshot)
  -m, --hide-proto          Hide protocol columns
  -a, --show-asn            Show AS Number column
  -A, --show-asd            Show AS Description column
  -n, --show-network        Show whois network name
  -q, --quiet               Do not print the host list to stdout

Environment variables:
  WEBRES6_API_URL           Override the default API endpoint

Exit codes:
   0 - Success: All hosts are IPv6-only
   1 - At least one host has an IPv4 address
   2 - Error occurred (see stderr)
```

## Support, Feedback, Contributing

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://github.com/SAP/webres6/issues). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](CONTRIBUTING.md).

## Security / Disclosure
If you find any bug that may be a security problem, please follow our instructions at [in our security policy](https://github.com/SAP/webres6/security/policy) on how to report it. Please do not create GitHub issues for security-related doubts or problems.

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](https://github.com/SAP/.github/blob/main/CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2025 SAP SE or an SAP affiliate company and webres6 contributors. Please see our [LICENSE](LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available [via the REUSE tool](https://api.reuse.software/info/github.com/SAP/webres6).