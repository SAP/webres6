#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import os
import time
import json
from os import getenv
from ipaddress import ip_address
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.client_config import ClientConfig, AuthType
from selenium.common.exceptions import WebDriverException, TimeoutException
import urllib3
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from prometheus_client import Counter

from webres6_extension import init_selenium_options, prepare_selenium_crawl, operate_selenium_crawl, cleanup_selenium_crawl

# config
app_home          = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
srvconfig_dir     = os.path.join(app_home, 'serverconfig')
selenium_remote     = getenv("SELENIUM_REMOTE_URL", None)
selenium_username   = getenv("SELENIUM_USERNAME", None)
selenium_password   = getenv("SELENIUM_PASSWORD", None)
# Auth mode for the API -> Selenium connection: "basic" (shared username/password)
# or "bearer" (workload-identity token, e.g. a projected Kubernetes ServiceAccount
# token that the kubelet rotates).
selenium_auth_mode  = getenv("SELENIUM_AUTH_MODE", "basic").lower()
selenium_token_file = getenv("SELENIUM_TOKEN_FILE", "/var/run/secrets/tokens/selenium/token")
headless_selenium   = getenv("HEADLESS_SELENIUM", False)
debug_hostinfo      = 'hostinfo' in getenv("DEBUG", '').lower().split(',')


def build_selenium_client_config():
    """Build a fresh ClientConfig for the remote Selenium connection.

    The config is built per connection rather than cached at import time so that
    a rotating bearer token (SELENIUM_AUTH_MODE=bearer) is re-read from disk on
    every new WebDriver session — kubelet-projected ServiceAccount tokens are
    refreshed roughly hourly, and a cached token would eventually be rejected.

    Returns (client_config, error). client_config is None when no remote server
    is configured (local Chrome) or when the bearer token cannot be read.
    """
    if not selenium_remote:
        return None, None

    if selenium_auth_mode == "bearer":
        try:
            with open(selenium_token_file) as f:
                token = f.read().strip()
        except OSError as e:
            return None, f"Could not read Selenium bearer token from {selenium_token_file}: {e}"
        if not token:
            return None, f"Selenium bearer token at {selenium_token_file} is empty"
        return ClientConfig(
            remote_server_addr=selenium_remote,
            auth_type=AuthType.BEARER,
            token=token,
        ), None

    # default: HTTP Basic auth with a shared username/password
    return ClientConfig(
        remote_server_addr=selenium_remote,
        username=selenium_username if selenium_username else 'admin',
        password=selenium_password if selenium_password else 'admin',
    ), None

# URL blocklist — defaults plus optional override file
url_blocklist = ["*://localhost/*", "*://localhost.localdomain/*", "*://*.local/*", "*://*.internal/*"]

def add_url_blocklist(entries):
    """Append additional URL patterns to the active blocklist."""
    url_blocklist.extend(entries)

# Public suffix list
public_suffixes = None
def load_public_suffix_list(public_suffix_file):
    global public_suffixes
    if os.path.exists(public_suffix_file):
        print(f"Loading public suffix list from '{public_suffix_file}'...", end='', file=sys.stderr)
        with open(public_suffix_file) as f:
            public_suffixes = set()
            for line in f:
                line = line.strip()
                if line and not line.startswith('//'):
                    public_suffixes.add(line)
        print(f"done ({len(public_suffixes)} entries).", file=sys.stderr)
    else:
        print(f"WARNING: Public suffix list file not found at {public_suffix_file}.", file=sys.stderr)

# Prometheus metrics
webres6_hostinfo_parsed = Counter('webres6_hostinfo_parsed_total', 'Total number of hostinfo entries parsed', ['type'])
webres6_resources_total = Counter('webres6_resources_total', 'Total number of resources per protocol', ['protocol'])

# Tracer
tracer = trace.get_tracer(__name__)


@tracer.start_as_current_span("selenium.init_webdriver")
def init_webdriver(log_prefix='', implicit_wait=0.5, extension=None, extension_data=None):
    """ Initializes the Selenium WebDriver with the necessary options.
    """
    span = trace.get_current_span()
    span.set_attributes({
        "webres6.selenium.remote": selenium_remote is not None,
        "webres6.selenium.headless": headless_selenium,
        "webres6.extension": extension or "none",
    })

    options = webdriver.ChromeOptions()
    options.enable_bidi = True
    options.enable_webextensions = True
    options.page_load_strategy = 'normal'
    options.unhandled_prompt_behavior = 'dismiss'
    options.add_argument('--disable-gpu')
    options.add_argument('--disable-webrtc')
    options.add_argument('--disable-notifications')
    # use Chrome's Happy Eyeballs v3 connection engine (HttpStreamPool / HttpStreamAttempt)
    options.add_argument('--enable-features=HappyEyeballsV3')
    # enableNetwork delivers Network.* events; also enable Chrome's net-log
    # (DNS, TCP connect attempts, Happy Eyeballs connect-job racing) to be fed
    # into the performance log
    options.add_experimental_option('perfLoggingPrefs', { 'enableNetwork' : True, 'traceCategories' : 'netlog' })
    options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

    if headless_selenium:
        options.headless = True
        options.add_argument('--headless=new')

    # initialize extension if needed
    if not init_selenium_options(options, extension, extension_data=extension_data, log_prefix=log_prefix):
        return None

    driver = None
    try:
        if selenium_remote:
            client_config, err = build_selenium_client_config()
            if err:
                print(f"{log_prefix}ERROR: {err}", file=sys.stderr)
                span.set_status(Status(StatusCode.ERROR, err))
                return None, err
            print(f"{log_prefix}connecting to remote Selenium server at {selenium_remote} (auth={selenium_auth_mode})", file=sys.stderr)
            driver = webdriver.Remote(command_executor=selenium_remote, options=options, client_config=client_config)
        else:
            print(f"{log_prefix}starting local Selenium", file=sys.stderr)
            driver = webdriver.Chrome(options=options)

        # set implicit wait for almost all actions
        driver.implicitly_wait(implicit_wait)

        # apply block list
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": url_blocklist})

        caps = driver.capabilities
        span.set_attributes({
            "webres6.browser.name": caps.get('browserName', 'unknown'),
            "webres6.browser.version": caps.get('browserVersion', 'unknown'),
            "webres6.browser.platform": caps.get('platformName', 'unknown'),
        })

    except urllib3.exceptions.MaxRetryError as e:
        print(f"{log_prefix}ERROR: Could not connect to Selenium server at {selenium_remote}: {e}", file=sys.stderr)
        span.set_status(Status(StatusCode.ERROR, "Could not connect to selenium"))
        return None, "Could not connect to selenium"

    except TimeoutException as e:
        print(f"{log_prefix}ERROR: Selenium WebDriver initialization timed out: {e.msg}", file=sys.stderr)
        span.set_status(Status(StatusCode.ERROR, "Timeout getting selenium instance"))
        return None, "Timeout getting selenium instance"

    except WebDriverException as e:
        print(f"{log_prefix}ERROR: failed initializing Selenium WebDriver: {e.msg}", file=sys.stderr)
        span.set_status(Status(StatusCode.ERROR, "Selenium initialization failed"))
        return None, "Selenium initialization failed"

    return driver, None


@tracer.start_as_current_span("selenium.crawl_page")
def crawl_page(url, driver=None, extension=None, extension_data=None, wait=2, timeout=10, log_prefix=''):
    """ Fetches the web page at the given URL using Selenium WebDriver.
    """
    span = trace.get_current_span()
    span.set_attributes({
        "webres6.url": url,
        "webres6.wait_time": wait,
        "webres6.timeout": timeout,
        "webres6.extension": extension or "none",
    })

    start_time = None
    try:
        # initialize page load timeout
        driver.set_page_load_timeout(timeout)

        # prepare for crawl
        span.add_event("prepare_selenium_crawl")
        success, err = prepare_selenium_crawl(driver, url, extension=extension, extension_data=extension_data, log_prefix=log_prefix)
        if not success:
            span.set_status(Status(StatusCode.ERROR, err or "Unknown error"))
            return False, err

        # start crawl
        span.add_event("page_load_start")
        start_time = time.time()
        driver.get(url)

        # wait requested settle time
        span.add_event("settle_wait_start", {"wait_seconds": wait})
        time.sleep(wait)

        # operate after crawl
        span.add_event("operate_selenium_crawl")
        success, err = operate_selenium_crawl(driver, url, extension=extension, extension_data=extension_data, log_prefix=log_prefix)
        if not success:
            span.set_status(Status(StatusCode.ERROR, err or "Unknown error"))
            return False, err

        # wait for page load complete if time budget allows
        span.add_event("wait_for_page_ready")
        page_ready = False
        while time.time() - start_time < timeout:
            if driver.execute_script("return document.readyState") == "complete":
                span.add_event("page_ready", {"elapsed_seconds": time.time() - start_time})
                page_ready = True
                break
            time.sleep(0.5)

        # check for error page
        if driver.current_url.startswith("chrome-error://"):
            error_page = driver.current_url.replace("chrome-error://", "")
            span.set_status(Status(StatusCode.ERROR, "chrome error page encountered: " + error_page))
            return False, f"Error page encountered: {error_page}"

        # check for certificate error interstitial ("Your connection is not private")
        if driver.execute_script("return typeof window.certificateErrorPageController !== 'undefined'"):
            span.set_status(Status(StatusCode.ERROR, "certificate error"))
            return False, "Certificate error — connection is not private"

        # check if page was ready within the timeout
        if not page_ready:
            span.set_status(Status(StatusCode.ERROR, "page not ready within timeout"))
            return False, f"Page not ready after {time.time() - start_time:.2f} seconds"

    except TimeoutException as e:
        span.record_exception(e)
        span.set_status(Status(StatusCode.ERROR, "page rendering timed out"))
        return False, f"Page rendering timed out after {time.time() - start_time:.2f} seconds"
    except WebDriverException as e:
        span.record_exception(e)
        span.set_status(Status(StatusCode.ERROR, e.msg))
        return False, e.msg.replace('unknown error: ', '')
    except Exception as e:
        span.record_exception(e)
        span.set_status(Status(StatusCode.ERROR, str(e)))
        return False, str(e)

    return True, None


@tracer.start_as_current_span("selenium.take_screenshot")
def take_screenshot(driver, mode='full', log_prefix=''):
    """ Takes a screenshot of the current page and returns it as a base64-encoded string.
    """
    if mode in ['none', None]:
        return None

    try:
        if mode == 'full':
            # get the page scroll dimensions
            width = driver.execute_script("return document.body.parentNode.scrollWidth")
            height = driver.execute_script("return document.body.parentNode.scrollHeight")
            # set the window size to the scroll dimensions (with some reasonable limits to avoid OOM issues)
            if width < 1:
                width = 2048
            elif width > 16384:
                width = 16384
            if height < 1:
                height = 1152
            elif height > 32768:
                height = 32768
            driver.set_window_size(width, height)
            full_body_element = driver.find_element(By.TAG_NAME, "body")
            return full_body_element.screenshot_as_base64
        elif mode == 'medium':
            driver.set_window_size(2048, 1152)
            return driver.get_screenshot_as_base64()
        else: # small for all other cases
            driver.set_window_size(1024, 768)
            return driver.get_screenshot_as_base64()

    except WebDriverException as e:
        span = trace.get_current_span()
        span.record_exception(e)
        span.set_status(Status(StatusCode.ERROR, e.msg or str(e)))
        print(f"{log_prefix}ERROR: failed acquiring screenshot: {e.msg}", file=sys.stderr)
        return None


def split_hostname(hostname):
    """ Splits the hostname into local part and domain part.
    """
    if public_suffixes is None:
        parts = hostname.rsplit('.', 2)
        domain_part = '.'.join(parts[-2:]) if len(parts) > 1 else hostname
        local_part = (parts[0] + '.') if len(parts) > 2 else ''
    else:
        parts = hostname.split('.')
        for i in range(1, len(parts)+1):
            domain_part = '.'.join(parts[-i:])
            local_part  = '.'.join(parts[:-i]) + ('.' if len(parts[:-i]) > 0 else '')
            if domain_part not in public_suffixes:
                break

    return local_part, domain_part


# net-log trace-event name prefixes worth keeping for Happy Eyeballs analysis.
# Chrome runs Happy Eyeballs v3 (--enable-features=HappyEyeballsV3), whose connection
# racing lives in the HTTP_STREAM_POOL attempt-manager and the per-family
# TCP_STREAM_ATTEMPT / TLS_STREAM_ATTEMPT wrappers (the legacy CONNECT_JOB model is
# gone). We keep those, plus DNS resolution, the low-level socket connect, UDP/QUIC
# for HTTP/3, and URL_REQUEST/CANCELLED for context. Everything else (HTTP/2 window
# updates, byte counters, cache lookups) is dropped to bound memory per crawl.
NETLOG_CONNECT_PREFIXES = (
    'URL_REQUEST',
    'HOST_RESOLVER',
    'HTTP_STREAM_POOL',
    'TCP_STREAM_ATTEMPT',
    'TLS_STREAM_ATTEMPT',
    'TCP_CONNECT',
    'UDP_CONNECT',
    'QUIC_SESSION_CREATED',
    'CANCELLED',
)


def ip_family(ip):
    """Classify an ip_address as 'IPv4'/'IPv6'/'NAT64'/'IPv4_Mapped'/'Unknown'.

    NAT64 and IPv4-mapped v6 addresses are reported distinctly (they are not native
    IPv6 connectivity). Shared by get_hostinfo, _endpoint_family and the happy_eyeballs
    aggregation so the family labels stay consistent everywhere.
    """
    match ip.version:
        case 4:
            return 'IPv4'
        case 6 if ip.is_nat64():
            return 'NAT64'
        case 6 if ip.ipv4_mapped:
            return 'IPv4_Mapped'
        case 6:
            return 'IPv6'
        case _:
            return 'Unknown'


@tracer.start_as_current_span("selenium.get_hostinfo")
def get_hostinfo(driver, log_prefix=''):
    """ Extracts host information using Selenium/Chromium network performance logs.

    Returns (hosts, netlog_events): the per-host summary dict and the list of
    net-log trace events (filtered to NETLOG_CONNECT_PREFIXES) harvested from the
    same performance log for Happy Eyeballs analysis.
    """
    span = trace.get_current_span()

    # check if public suffix list is available
    if public_suffixes is None:
        print(f"{log_prefix}WARNING: public suffix list not found, domain part extraction will always use the 2nd level domain.", file=sys.stderr)

    # Ask selenium for performance logs
    span.add_event("fetching_performance_logs_start")
    try:
        # ugly work-around as >>> # perfs = driver.get_log('performance') <<< does not work with remote driver
        perfs = driver.execute('getLog', {'type': 'performance'})['value']
    except WebDriverException as e:
        span.add_event("fetching_performance_logs_error", {"error": e.msg})
        print(f"Error fetching performance logs: {e.msg}", file=sys.stderr)
        return None, []

    span.add_event("fetching_performance_logs_end")

    # dictionary to hold host-level summaries and helper functions for parsing the data
    hosts = {}
    def _parse_response_received(obj):

        # Check for valid IP in response
        response = obj['message']['params']['response']
        remote_ip = response.get('remoteIPAddress', None)
        if not remote_ip:
            webres6_hostinfo_parsed.labels(type='without_ip').inc()
            if debug_hostinfo:
                print(f"{log_prefix}WARNING: No valid IP address found in {response}", file=sys.stderr)
                span.add_event("log.missing_ip", {"response": str(response)})
            return # skip this entry if no valid IP is found
        # Strip brackets from IPv6 addresses
        if remote_ip and remote_ip.startswith('[') and remote_ip.endswith(']'):
            remote_ip = remote_ip[1:-1]
        # Parse the IP address
        try:
            ip = ip_address(remote_ip)
            webres6_hostinfo_parsed.labels(type='valid_ip').inc()
        except ValueError as e:
            webres6_hostinfo_parsed.labels(type='invalid_ip').inc()
            print(f"{log_prefix}WARNING: Error parsing IP address: {remote_ip} - {e}", file=sys.stderr)
            span.add_event("log.invalid_ip", {"ip_address": remote_ip, "error": str(e)})
            ip = None
            return # skip the entry
        # add resource statistics
        webres6_resources_total.labels(protocol=ip_family(ip)).inc()

        # Extract remainder of the response details
        url = urlparse(response.get('url'))
        security_details = response.get('securityDetails', None)
        security_protocol = security_details.get('protocol') if security_details else None
        protocols = response.get('protocol'), security_protocol

        # print debugging information if needed
        if debug_hostinfo:
            print(f"{log_prefix}Response URL: {response.get('url')}", file=sys.stderr)
            print(f"{log_prefix}Response Status: {response.get('status')}", file=sys.stderr)
            print(f"{log_prefix}Response Host: {url.hostname}", file=sys.stderr)
            print(f"{log_prefix}Response IP: {response.get('remoteIPAddress')}", file=sys.stderr)
            print(f"{log_prefix}Response Protocol: {response.get('protocol')}", file=sys.stderr)
            if security_details:
                print(f"{log_prefix}Security Protocol: {security_details.get('protocol')}", file=sys.stderr)
                print(f"{log_prefix}Subject Alt Names: {security_details.get('sanList')}", file=sys.stderr)
            print(f"{log_prefix}Response Headers: {response.get('headers')}", file=sys.stderr)

        # Update the hosts dictionary with the response details
        if not url.hostname:
            webres6_hostinfo_parsed.labels(type='without_hostname').inc()
            if debug_hostinfo:
                print(f"{log_prefix}WARNING: No valid hostname found in URL {response.get('url')}", file=sys.stderr)
                span.add_event("log.missing_hostname", {"url": response.get('url')})
            return # skip this entry if no valid hostname is found

        # Create a new host entry if it does not exist yet
        if url.hostname not in hosts:
            local_part, domain_part = split_hostname(url.hostname)
            hosts[url.hostname] = {
                'domain_part': domain_part,
                'local_part': local_part,
                'ips': {},   # ip -> { (protocol, security_protocol): [urls] }
                'subject_alt_names': set()
            }
            span.add_event("host.new", {"hostname": url.hostname, "domain_part": domain_part, "local_part": local_part})
        else:
            span.add_event("host.update", {"hostname": url.hostname})

        # Persist which (ip, protocol) served this url
        hosts[url.hostname]['ips'].setdefault(ip, {}).setdefault(protocols, []).append(url.geturl())
        # Update subject alt names if they are not already set
        if security_details:
            hosts[url.hostname]['subject_alt_names'].update(security_details.get('sanList'))

        # done processing this response entry

    # net-log trace events harvested alongside the Network.* events
    netlog_events = []
    event_types = set()
    def _parse_netlog_event(obj):
        params = obj['message'].get('params', {})
        event_types.add(params.get('name', ''))
        if params.get('name', '').startswith(NETLOG_CONNECT_PREFIXES):
            netlog_events.append(params)
            #if debug_hostinfo:
            #    print(f"{log_prefix}Tracing data name={params.get('name', '')}:  {json.dumps(obj['message'])}", file=sys.stderr)

    # Extract host info from performance logs
    perfs_done = 0
    resp_recv_done = 0
    for perf in perfs:
        # parse log entry
        try:
            msg = perf.get('message')
            obj = json.loads(msg)
        except Exception as e:
            print(f"{log_prefix}ERROR: failed parsing log entry: {e}", file=sys.stderr)
            span.add_event("log.parse_error", {"log_entry": str(e)})
            webres6_hostinfo_parsed.labels(type='error').inc()
            continue

        # show progress for every 100 performance log entries if debug is enabled
        perfs_done += 1

        # Harvest net-log trace events (delivered via traceCategories='netlog')
        if obj.get('message', {}).get('method') == 'Tracing.dataCollected':
            _parse_netlog_event(obj)
            continue

        # Harvest Network.responseReceived events
        if  obj.get('message', {}).get('method') == 'Network.responseReceived':
            resp_recv_done += 1
            if debug_hostinfo and resp_recv_done % 100 == 0:
                print(f"{log_prefix}Processed {resp_recv_done} Network.responseReceived events", file=sys.stderr)
            _parse_response_received(obj)
            continue

        # Increment the skipped counter for non-relevant log entries
        webres6_hostinfo_parsed.labels(type='skipped').inc()

    # dump list of event types if debug is enabled
    span.add_event("performance_logs_parsed", {
        "perfs_done": perfs_done,
        "response_received_events": resp_recv_done,
        "netlog_events": len(netlog_events)
    })
    if debug_hostinfo:
        print(f"{log_prefix}Processed {perfs_done} of {len(perfs)} performance log entries – {resp_recv_done} responseReceived events, {len(netlog_events)} netlog events", file=sys.stderr)
        print(f"{log_prefix}Netlog event types encountered:\n\t{"\n\t".join(sorted(list(event_types)))}", file=sys.stderr)

    # enrich each host with its Happy Eyeballs race summary
    analyze_happy_eyeballs(hosts, netlog_events)

    return hosts, netlog_events


def _endpoint_family(address):
    """Return the ip_family of an 'ip:port' net-log endpoint, or None if unparseable."""
    if not address:
        return None
    host = address
    if host.startswith('['):                 # [2606:4700::1]:443
        host = host[1:host.index(']')] if ']' in host else host[1:]
    elif host.count(':') == 1:               # 192.0.2.1:443
        host = host.rsplit(':', 1)[0]
    # otherwise an unbracketed IPv6 literal — leave as-is
    try:
        return ip_family(ip_address(host))
    except ValueError:
        return None


def _new_attempt(ip_endpoint, protocol, start_us):
    return {
        'ip_endpoint': ip_endpoint,
        'family': _endpoint_family(ip_endpoint),
        'protocol': protocol,
        'start_us': start_us,
        'end_us': None,
        'net_error': None,
        'succeeded': None,
    }


def _event_hostname(params):
    """Pull the destination hostname from an attempt-manager / QUIC-attempt event.

    The attempt manager carries it as a URL under stream_key.destination (e.g.
    'https://fonts.gstatic.com'); QUIC attempts carry it as metadata.target_name.
    Returns a bare hostname or None.
    """
    dest = (params.get('stream_key') or {}).get('destination') or params.get('destination')
    if dest:
        return urlparse(dest).hostname or dest
    return (params.get('metadata') or {}).get('target_name') or params.get('target_name')


def analyze_happy_eyeballs(hosts, netlog_events):
    """Reconstruct Happy Eyeballs v3 races and fold a per-host summary into hosts.

    Under HappyEyeballsV3 the race is run by an HTTP_STREAM_POOL attempt manager.
    Events are grouped by net-log source id (id2.local); each group yields a
    connection record (keyed to a hostname via the manager's destination) with:
      - dns_endpoints: the resolved candidate endpoints (DNS_RESOLUTION_FINISHED)
      - attempts: one unified list of connection attempts, each with ip_endpoint,
        family ('IPv4'/'IPv6'), protocol ('QUIC' for HTTP/3, else 'TCP'; the trace
        does not carry the negotiated H2/H1 — that lives in response.protocol),
        start/end timing and net_error outcome

    TCP START/END are instant ('n') events carrying ip_endpoint and (on END)
    net_error; several attempts may target the same endpoint, so START→END are
    paired FIFO per endpoint, and unmatched START/END are tolerated. A TCP attempt
    succeeded iff its END net_error == 0. QUIC attempts come from
    HTTP_STREAM_POOL_QUIC_ATTEMPT_ALIVE begin/end and carry no outcome on their own
    source, so their succeeded stays None — whether a family actually served a host
    is derived from the response IPs, not from attempt outcomes.

    Each host's attempts (aggregated across its net-log sources) are stored on the
    matching host as a happy_eyeballs summary (mutates hosts in place): the raw
    attempts plus ipv4_succeeded/ipv6_succeeded (a connection of that family either
    established in the race or actually served the host). ipv6_available (from
    HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK) is returned, not stored per host
    — it is a machine-global fact, not a host fact.
    """
    # group every event by its net-log source id (id2.local), in timestamp order
    by_source = {}
    for e in netlog_events:
        sid = (e.get('id2') or {}).get('local')
        if sid is None:
            continue
        by_source.setdefault(sid, []).append(e)
    for evs in by_source.values():
        evs.sort(key=lambda e: e.get('ts', 0))

    ipv6_available = None
    for e in netlog_events:
        if e.get('name') == 'HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK':
            val = (e.get('args', {}).get('params') or {}).get('ipv6_available')
            if val is not None:
                ipv6_available = val
                break

    connections = []
    for sid, evs in by_source.items():
        dns_endpoints = None
        hostname = None
        attempts = []
        open_by_endpoint = {}   # ip_endpoint -> FIFO of open TCP attempts
        open_quic = []          # FIFO of open QUIC attempts
        for e in evs:
            name, ph = e.get('name'), e.get('ph')
            params = e.get('args', {}).get('params', {}) or {}

            if name == 'HTTP_STREAM_POOL_ATTEMPT_MANAGER_ALIVE':
                # the manager's own source carries the destination, so no
                # source-dependency chasing is needed to key the race to a host.
                hostname = hostname or _event_hostname(params)

            elif name == 'HTTP_STREAM_POOL_ATTEMPT_MANAGER_DNS_RESOLUTION_FINISHED':
                dns_endpoints = params.get('endpoints', dns_endpoints)

            elif name == 'HTTP_STREAM_POOL_TCP_BASED_ATTEMPT_START':
                ep = params.get('ip_endpoint')
                attempt = _new_attempt(ep, 'TCP', e.get('ts'))
                attempts.append(attempt)
                open_by_endpoint.setdefault(ep, []).append(attempt)

            elif name == 'HTTP_STREAM_POOL_TCP_BASED_ATTEMPT_END':
                ep = params.get('ip_endpoint')
                queue = open_by_endpoint.get(ep)
                attempt = queue.pop(0) if queue else None
                if attempt is None:     # END without a captured START
                    attempt = _new_attempt(ep, 'TCP', None)
                    attempts.append(attempt)
                ne = params.get('net_error')
                attempt['end_us'] = e.get('ts')
                attempt['net_error'] = ne
                attempt['succeeded'] = (ne == 0)

            elif name == 'HTTP_STREAM_POOL_QUIC_ATTEMPT_ALIVE' and ph == 'b':
                hostname = hostname or _event_hostname(params)   # QUIC sources carry the host too
                attempt = _new_attempt(params.get('ip_endpoint'), 'QUIC', e.get('ts'))
                attempts.append(attempt)
                open_quic.append(attempt)
            elif name == 'HTTP_STREAM_POOL_QUIC_ATTEMPT_ALIVE' and ph == 'e' and open_quic:
                open_quic.pop(0)['end_us'] = e.get('ts')

        if dns_endpoints is None and not attempts:
            continue  # not an attempt-manager source

        # Store connection record for this source.
        connections.append({
            'source_id': sid,
            'hostname': hostname,
            'dns_endpoints': dns_endpoints,
            'attempts': attempts,
        })

    # Attach a happy_eyeballs summary to every host. A host's activity is split across
    # several net-log sources — the TCP attempt manager and each QUIC attempt are
    # separate sources (hence separate connection records) that all resolve to the
    # same hostname — so we aggregate every source's attempts per host. Hosts served
    # over a coalesced/reused connection have no own race (attempts == []) but are
    # still summarised via the response data.
    #
    # *_succeeded means a family's connection either established in the race or
    # actually served the host. For TCP the race gives net_error == 0 (which catches
    # even racing losers that established before being cancelled); as a secondary
    # signal, any family that actually served a response (used_families, from the
    # response IPs) also counts — this covers QUIC/h3 (no usable outcome in the trace)
    # and connections reused via coalescing, which have no own race.
    by_host = {}
    for conn in connections:
        h = conn.get('hostname')
        if h in hosts:
            by_host.setdefault(h, []).extend(conn['attempts'])
    for h, info in hosts.items():
        attempts = by_host.get(h, [])
        used_families = {ip_family(ip) for ip in info['ips'] if hasattr(ip, 'version')}
        v4_like = {'IPv4', 'NAT64', 'IPv4_Mapped'}
        info['happy_eyeballs'] = {
            'attempts': attempts,
            'ipv4_succeeded': any(a['family'] in v4_like and a['succeeded'] for a in attempts)
                              or bool(used_families & v4_like),
            'ipv6_succeeded': any(a['family'] == 'IPv6' and a['succeeded'] for a in attempts)
                              or 'IPv6' in used_families,
        }

    return ipv6_available


@tracer.start_as_current_span("selenium.cleanup_crawl")
def cleanup_crawl(driver, extension=None, extension_data=None, log_prefix=''):
    """Cleans up the Selenium WebDriver instance by safely quitting it."""
    try:
        cleanup_selenium_crawl(driver, extension=extension, extension_data=extension_data, log_prefix=log_prefix)
        driver.quit()
    except WebDriverException as e:
        span = trace.get_current_span()
        span.record_exception(e)
        span.set_status(Status(StatusCode.ERROR, e.msg or str(e)))
        print(f"{log_prefix}ERROR: failed quitting WebDriver: {e.msg}", file=sys.stderr)
    return


@tracer.start_as_current_span("check_selenium")
def check_selenium(log_prefix=''):
    """ Checks if Selenium is available and working properly.
    """
    try:
        driver, err = init_webdriver(log_prefix=log_prefix, implicit_wait=0.5)
        if driver:
            browser_name = driver.capabilities.get('browserName', 'unknown')
            browser_version = driver.capabilities.get('browserVersion', 'unknown')
            cleanup_crawl(driver, log_prefix=log_prefix)
            return True, f'ok: {browser_name} {browser_version}'
        else:
            return False, f'error: {err}'
    except Exception as e:
        return False, f'error: {str(e)}'


# vim: set ts=4 sw=4 et:
# vim: set fileencoding=utf-8:
# vim: set filetype=python:
