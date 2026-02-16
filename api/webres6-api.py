#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

# load system modules
import sys
import argparse
import json
import os
import signal
import platform
import time
import uuid
from os import getenv
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.client_config import ClientConfig
from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException
from urllib.parse import urlparse
import urllib3
import flask
from flask import Flask, redirect, request, jsonify, send_from_directory
from prometheus_client import Counter, Gauge, Histogram ,disable_created_metrics, generate_latest, CONTENT_TYPE_LATEST

# config/flag variables
webres6_version   = "1.3.3"
debug_whois       = 'whois'    in getenv("DEBUG", '').lower().split(',')
debug_hostinfo    = 'hostinfo' in getenv("DEBUG", '').lower().split(',')
debug_flask       = 'flask'    in getenv("DEBUG", '').lower().split(',')
debug_viewer      = 'viewer'   in getenv("DEBUG", '').lower().split(',')
admin_api_key     = getenv("ADMIN_API_KEY", None)
selenium_remote   = getenv("SELENIUM_REMOTE_URL", None)
selenium_username = getenv("SELENIUM_USERNAME", None)
selenium_password = getenv("SELENIUM_PASSWORD", None)
headless_selenium = getenv("HEADLESS_SELENIUM", False)
dnsprobe_api_url  = getenv("DNSPROBE_API_URL", None)
valkey_url        = getenv("VALKEY_URL", None)
s3_bucket         = getenv("S3_BUCKET", None)
s3_endpoint       = getenv("S3_ENDPOINT", None)
s3_strategy       = getenv("S3_DELIVERY_STRATEGY", "public")
archive_dir       = getenv("ARCHIVE_DIR", None)
result_cache_ttl  = int(getenv("RESULT_CACHE_TTL", 900))  # Default 15min
result_archive_ttl = int(getenv("RESULT_ARCHIVE_TTL", 3600*24*90))  # Default 3 month
app_home          = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
viewer_dir        = os.path.join(app_home, '..', 'viewer')
srvconfig_dir     = os.path.join(app_home, 'serverconfig')
local_cache_dir   = getenv("LOCAL_CACHE_DIR", os.path.join(app_home, '..', 'local_cache'))
min_timeout       = int(getenv("TIMEOUT_MIN", 20))
max_timeout       = int(getenv("TIMEOUT", 180))//2
max_wait          = max_timeout//3
enable_whois      = getenv("ENABLE_WHOIS", 'true').lower() in ['true', '1', 'yes']
whois_cache_ttl   = int(getenv("WHOIS_CACHE_TTL", 270000)) # seconds
enable_scoreboard = getenv("ENABLE_SCOREBOARD", 'true').lower() in ['true', '1', 'yes']
scoreboard_request_limit = int(getenv("SCOREBOARD_REQUEST_LIMIT", 1024))
screenshot_modes  = ['none', 'small', 'medium', 'full']

# load custom modules (allows overrides in serverconfig directory)
sys.path.insert(0, srvconfig_dir)
from webres6_storage import StorageManager, LocalStorageManager, ValkeyStorageManager, ValkeyFileHybridStorageManager, ValkeyS3HybridStorageManager, Scoreboard, export_scoreboard_entries, import_scoreboard_entries, export_archived_reports, import_archived_reports
from webres6_whois import get_whois_info
from webres6_extension import check_extension_parameter, get_extensions, init_selenium_options, prepare_selenium_crawl, operate_selenium_crawl, cleanup_selenium_crawl, finalize_report

# get nodename for report id
report_node = platform.node().split('.')[0]
if len(report_node) >12 or '-' in report_node:
    report_node = sha256(report_node.encode()).hexdigest()[:12]
print(f"report node is set to '{report_node}'.", file=sys.stderr)

# load NAT64 prefixes
for nat64 in [ip_network(p) for p in getenv("NAT64_PREFIXES", "").split(",") if p]:
    if nat64.version == 6 or nat64.prefixlen == 96:
        IPv6Address.nat64_networks.append(nat64)
    else:
        print(f"ERROR: Invalid NAT64 prefix {nat64}. Must be an IPv6 network with a /96 prefix length.", file=sys.stderr)
        sys.exit(2)

# load privacy policy
privacy_policy = None
privacy_file = os.path.join(srvconfig_dir, 'PRIVACY')
if os.path.exists(privacy_file):
    with open(privacy_file) as f:
        privacy_policy = f.read()

# load server message
srv_message = None
srv_message_file = os.path.join(srvconfig_dir, 'MESSAGE')
if os.path.exists(srv_message_file):
    with open(srv_message_file) as f:
        srv_message = f.read()

# load blocklist
url_blocklist = ["*://*.local/*", "*://*.internal/*"]
url_blocklist_file = os.path.join(srvconfig_dir, 'url-blocklist')
if os.path.exists(url_blocklist_file):
    with open(url_blocklist_file) as f:
        url_blocklist = f.read().splitlines()

# initialize selenium auth if needed
selenium_client_config = None
if selenium_remote:
    selenium_client_config = ClientConfig(
        remote_server_addr=selenium_remote,
        username=selenium_username if selenium_username else 'admin',
        password=selenium_password if selenium_password else 'admin',
    )

# read public suffix list
public_suffixes = None
if os.path.exists(os.path.join(app_home, 'public_suffix_list.dat')):
    with open(os.path.join(app_home, 'public_suffix_list.dat')) as f:
        public_suffixes = set()
        for line in f:
            line = line.strip()
            if line and not line.startswith('//'):
                public_suffixes.add(line)
    print(f"loaded {len(public_suffixes)} public suffixes.", file=sys.stderr)
else:
    print(f"WARNING: public suffix list not found, domain part extraction will always use the 2nd level domain.", file=sys.stderr)

# inialize storage manager
storage_manager = None
if valkey_url and valkey_url.strip() != '':
    if s3_bucket and s3_bucket.strip() != '':
        print("Valkey client and S3 endpoint configured, using ValkeyS3HybridStorageManager", file=sys.stderr)
        storage_manager = ValkeyS3HybridStorageManager(whois_cache_ttl=whois_cache_ttl, result_archive_ttl=result_archive_ttl,
                                              valkey_url=valkey_url, s3_bucket=s3_bucket, s3_endpoint=s3_endpoint, s3_delivery_strategy=s3_strategy)
    elif archive_dir and archive_dir.strip() != '':
        print("Valkey client and local archive dir configured, using ValkeyFileHybridStorageManager", file=sys.stderr)
        storage_manager = ValkeyFileHybridStorageManager(whois_cache_ttl=whois_cache_ttl, result_archive_ttl=result_archive_ttl,
                                                            valkey_url=valkey_url, archive_dir=archive_dir)
    else:
        print("Valkey client configured, using ValkeyStorageManager", file=sys.stderr)
        storage_manager = ValkeyStorageManager(whois_cache_ttl=whois_cache_ttl, result_archive_ttl=result_archive_ttl, valkey_url=valkey_url)
else:
    print("Valkey client not configured, using LocalStorageManager", file=sys.stderr)
    LocalStorageManager.print_warnings(None)
    storage_manager = LocalStorageManager(whois_cache_ttl=whois_cache_ttl, result_archive_ttl=result_archive_ttl, cache_dir=local_cache_dir, archive_dir=archive_dir)

# initialize scoreboard if enabled
scoreboard = None
if storage_manager.can_archive() and enable_scoreboard:
    scoreboard = Scoreboard(storage_manager=storage_manager)


# create connection pool for dnsprobe if needed
dnsprobe = None
if dnsprobe_api_url:
    print(f"DNSProbe API URL is set to {dnsprobe_api_url}.", file=sys.stderr)
    dnsprobe = urllib3.PoolManager(
        maxsize=10, block=True,
        timeout=urllib3.Timeout(connect=5.0, total=15.0), retries=False,
    )

# whois enabled?
print(f"whois lookups are {'enabled with TTL ' + str(whois_cache_ttl) + 's' if enable_whois else 'disabled'}.", file=sys.stderr)

# Prometheus metrics
disable_created_metrics()
webres6_tested_total = Counter('webres6_tested_total', 'Total number of checks performed')
webres6_tested_results = Counter('webres6_results_total', 'Total number of results for checks performed', ['result'])
webres6_scores_total = Histogram('webres6_scores_total', 'Histogram of scores results ', ['score_type'], buckets=(0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0))
webres6_cache_hits_total = Counter('webres6_cache_hits_total', 'Total number of cache hits')
webres6_archive_total = Counter('webres6_archive_hits_total', 'Total number of archive hits', ['result'])
webres6_time_spent = Counter('webres6_time_spent_seconds_total', 'Time spent in different processing phases', ['phase'])
webres6_response_time = Histogram('webres6_response_time_seconds_total', 'Response time for checks performed', ['whois', 'screenshot'], buckets=(0.2, 0.5, 1, 2, 5, 10, 20, 30, 60, 90, 120, 150, 180))
webres6_hostinfo_parsed = Counter('webres6_hostinfo_parsed_total', 'Total number of hostinfo entries parsed', ['type'])
webres6_resources_total = Counter('webres6_resources_total', 'Total number of resources per protocol', ['protocol'])
webres6_whois_cache_size = Gauge('webres6_whois_cache_size_total', 'Number of entries in whois cache')
webres6_whois_cache_size.set_function(lambda: storage_manager.whois_cache_size() if storage_manager else 0)

# patch ip address object to support NAT64 detection
def _is_nat64(self):
    """ Check if the IP address is a NAT64 address.
        NAT64 addresses are in the range 64:ff9b::/96.
    """
    return self.version == 6 and any(self in net for net in self.nat64_networks)

def _nat64_extract_ipv4(self):
        """Extract the embedded IPv4 address from a NAT64 IPv6 address.

        Returns:
            An IPv4Address object representing the embedded IPv4 address,
            or None if the address is not a NAT64 address.

        """
        if not self.is_nat64():
            return None
        low_order_bits = self._ip & 0xFFFFFFFF
        return ip_address(low_order_bits)

def _nat64_ipv6_to_str(self):
        """Return convenient text representation of NAT64 address

        Returns:
            A string, 'x:x:x:x:x:x:d.d.d.d', where the 'x's are the hexadecimal values of
            the six high-order 16-bit pieces of the address, and the 'd's are
            the decimal values of the four low-order 8-bit pieces of the
            address (standard IPv4 representation) as defined in RFC 4291 2.2 p.3.

        """
        high_order_bits = self._ip & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000
        low_order_bits = self._ip & 0xFFFFFFFF
        return self._string_from_ip_int(high_order_bits) + '.'.join(map(str, low_order_bits.to_bytes(4, 'big')))

def _nat64_aware__str__(self):
        ipv4_mapped = self.ipv4_mapped
        if ipv4_mapped is not  None:
            ip_str = self._ipv4_mapped_ipv6_to_str()
            return ip_str + '%' + self._scope_id if self._scope_id else ip_str
        elif self.is_nat64():
            ip_str = self._nat64_ipv6_to_str()
            return ip_str + '%' + self._scope_id if self._scope_id else ip_str
        else:
            return super(IPv6Address, self).__str__()

IPv6Address.nat64_networks = [
    ip_network('64:ff9b::/96'), # well-known NAT64 prefix
    ]
IPv6Address.is_nat64 = _is_nat64
IPv6Address.nat64_extract_ipv4 = _nat64_extract_ipv4
IPv6Address._nat64_ipv6_to_str = _nat64_ipv6_to_str
IPv6Address.__str__ = _nat64_aware__str__

# end patch

def is_ip(address):
    """ Check if the given address is an IP address object (IPv4 or IPv6).
    """
    return isinstance(address, IPv4Address) or isinstance(address, IPv6Address)


# Custom JSON encoders
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class FlaskJSONProvider(flask.json.provider.DefaultJSONProvider):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def init_webdriver(log_prefix='', implicit_wait=0.5, extension=None, extension_data=None):
    """ Initializes the Selenium WebDriver with the necessary options.
    """
    options = webdriver.ChromeOptions()
    options.enable_bidi = True
    options.enable_webextensions = True
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-webrtc")
    options.add_argument("--disable-notifications")
    # options.add_argument("--start-maximized")
    options.add_experimental_option('perfLoggingPrefs', { 'enableNetwork' : True })
    options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

    if headless_selenium:
        options.headless = True
        options.add_argument("--headless=new")

    # initialize extension if needed
    if not init_selenium_options(options, extension, extension_data=extension_data, log_prefix=log_prefix):
        return None

    # If SELENIUM_REMOTE_URL is set, use it to connect to a remote Selenium server
    driver = None

    try:
        if selenium_remote:
            print(f"{log_prefix}connecting to remote Selenium server at {selenium_remote}", file=sys.stderr)
            client_config = ClientConfig
            driver = webdriver.Remote(command_executor=selenium_remote, options=options, client_config=selenium_client_config)
        else:
            print(f"{log_prefix}starting local Selenium", file=sys.stderr)
            driver = webdriver.Chrome(options=options)

        # set implicit wait for almost all actions
        driver.implicitly_wait(implicit_wait)

        # add block list
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": url_blocklist })

    except urllib3.exceptions.MaxRetryError as e:
        print(f"{log_prefix}ERROR: Could not connect to Selenium server at {selenium_remote}: {e}", file=sys.stderr)
        return None, "Could not connect to selenium"

    except TimeoutException as e:
        print(f"{log_prefix}ERROR: Selenium WebDriver initialization timed out: {e.msg}", file=sys.stderr)
        return None, "Timeout getting selenium instance"

    except WebDriverException as e:
        print(f"{log_prefix}ERROR: failed initializing Selenium WebDriver: {e.msg}", file=sys.stderr)
        return None, "Selenium initialization failed"

    return driver, None


def crawl_page(url, driver=None, extension=None, extension_data=None, wait=2, timeout=10, log_prefix=''):
    """ Fetches the web page at the given URL using Selenium WebDriver.
    """

    start_time = None
    try:
        # initialize page load timeout
        driver.set_page_load_timeout(timeout)

        # prepare for crawl
        success, err = prepare_selenium_crawl(driver, url, extension=extension, extension_data=extension_data, log_prefix=log_prefix)
        if not success:
            return False, err

        # start crawl
        start_time = time.time()
        driver.get(url)

        # wait requested settle time
        time.sleep(wait)

        # operate after crawl
        success, err = operate_selenium_crawl(driver, url, extension=extension, extension_data=extension_data, log_prefix=log_prefix)
        if not success:
            return False, err

        # wait for page load complete if time budget allows
        while time.time() - start_time < timeout:
            if driver.execute_script("return document.readyState") == "complete":
                break
            time.sleep(0.5)

    except TimeoutException as e:
        return False, f"Page rendering timed out after {time.time() - start_time:.2f} seconds"
    except WebDriverException as e:
        return False, e.msg.replace('unknown error: ', '')
    except Exception as e:
        return False, str(e)

    return True, None


def take_screenshot(driver, mode='full', log_prefix=''):
    """ takes a screenshot of the current page and returns it as a base64-encoded string.
    """

    if mode in ['none', None]:
        return None

    # Ask selenium to navigate to the URL and fetch performance logs
    try:
        if mode == 'full':
            # get the page scroll dimensions
            width = driver.execute_script("return document.body.parentNode.scrollWidth")
            height = driver.execute_script("return document.body.parentNode.scrollHeight")
            driver.set_window_size(width, height)
            # get the full body element
            full_body_element = driver.find_element(By.TAG_NAME, "body")
            return full_body_element.screenshot_as_base64
        elif mode == 'medium':
            # set a reasonable window size for a partial screenshot
            driver.set_window_size(2048, 1152)
            return driver.get_screenshot_as_base64()
        else: # small for all other cases
            # set a reasonable window size for a partial screenshot
            driver.set_window_size(1024, 768)
            return driver.get_screenshot_as_base64()

    except WebDriverException as e:
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

def get_hostinfo(driver, log_prefix=''):
    """ extracts host information using Selenium/Chromium network performance logs.
    """

    # Ask selenium for performance logs
    try:
        # ugly work-around as >>> # perfs = driver.get_log('performance') <<< does not work with remote driver
        perfs = driver.execute('getLog', {'type': 'performance'})['value']
    except WebDriverException as e:
        print(f"Error fetching performance logs: {e.msg}", file=sys.stderr)
        return None

    # dictionary to hold host-level summaries
    hosts = {}

    # Extract host info from performance logs
    for perf in perfs:
        # parse log entry
        try:
            msg = perf.get('message')
            obj = json.loads(msg)
        except Exception as e:
            print(f"{log_prefix}ERROR: failed parsing log entry: {e}", file=sys.stderr)
            webres6_hostinfo_parsed.labels(type='error').inc()
            continue

        # We are only interested in Network.responseReceived events
        if 'message' not in obj or obj['message'].get('method') != 'Network.responseReceived':
            webres6_hostinfo_parsed.labels(type='skipped').inc()
            continue

        # Check for valid IP in response
        response = obj['message']['params']['response']
        remote_ip = response.get('remoteIPAddress', None)
        if not remote_ip:
            webres6_hostinfo_parsed.labels(type='without_ip').inc()
            if debug_hostinfo:
                print(f"{log_prefix}WARNING: No valid IP address found in {response}", file=sys.stderr)
            continue
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
            ip = None
        # add resource statistics
        match ip.version:
            case 4:
                webres6_resources_total.labels(protocol='IPv4').inc()
            case 6 if ip.is_nat64():
                webres6_resources_total.labels(protocol='NAT64').inc()
            case 6 if ip.ipv4_mapped:
                webres6_resources_total.labels(protocol='IPv4_Mapped').inc()
            case 6:
                webres6_resources_total.labels(protocol='IPv6').inc()
            case _:
                webres6_resources_total.labels(protocol='Unknown').inc()

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
            continue

        # Create a new host entry if it does not exist yet
        if url.hostname not in hosts:
            local_part, domain_part = split_hostname(url.hostname)
            hosts[url.hostname] = {
                'domain_part': domain_part,
                'local_part': local_part,
                'urls': set(),
                'ips': set(),
                'protocols': {},
                'subject_alt_names': set()
            }

        # Add the URLs and additional IPs
        hosts[url.hostname]['urls'].add(url.geturl())
        hosts[url.hostname]['ips'].add(ip)
        # Update protocol ifs they are not already set
        if ip not in hosts[url.hostname]['protocols']:
            hosts[url.hostname]['protocols'][ip] = [protocols]
        elif protocols not in hosts[url.hostname]['protocols'][ip]:
            hosts[url.hostname]['protocols'][ip].append(protocols)
        # Update subject alt names if they are not already set
        if security_details:
            hosts[url.hostname]['subject_alt_names'].update(security_details.get('sanList'))

    return hosts


def cleanup_crawl(driver, extension=None, extension_data=None, log_prefix=''):
    """Cleans up the Selenium WebDriver instance by safely quitting it.

    Args:
        driver: The Selenium WebDriver instance to be cleaned up
        extension (str, optional): The extension name being used. Defaults to None.
        log_prefix (str, optional): Prefix to add to error log messages. Defaults to ''.

    Returns:
        None

    """
    try:
        cleanup_selenium_crawl(driver, extension=extension, extension_data=extension_data, log_prefix=log_prefix)
        driver.quit()
    except WebDriverException as e:
        print(f"{log_prefix}ERROR: failed quitting WebDriver: {e.msg}", file=sys.stderr)
    return


def add_dnsprobe_info(hosts):
    """ Adds DNSProbe information for each unique IP address in the hosts dictionary.
    """

    total = 0
    success = 0
    noerror = 0
    servfail = 0

    for hostname, info in hosts.items():
        dnsprobe_data = {}
        try:
            response = dnsprobe.request('GET', f"{dnsprobe_api_url}/dnsprobe/resolve6only({hostname})", timeout=10)
            if response.status == 200:
                dnsprobe_data = response.json()
                dnsprobe_data['ts'] = datetime.fromisoformat(dnsprobe_data['ts'])
                total += 1
            else:
                print(f"\tWARNING: DNSProbe lookup failed for {hostname}: HTTP {response.status}", file=sys.stderr)
            if dnsprobe_data.get('success', False):
                success += 1
                dnsprobe_data['ipv6_only_ready'] = True
            elif dnsprobe_data.get('rcode', '') == 'no error':
                noerror += 1
                dnsprobe_data['ipv6_only_ready'] = True
            elif dnsprobe_data.get('rcode', '') == 'serv fail':
                servfail += 1
                dnsprobe_data['ipv6_only_ready'] = False
        except Exception as e:
            print(f"\tWARNING: DNSProbe lookup failed for {hostname}: {e}", file=sys.stderr)
            dnsprobe_data = None

        # Add DNSProbe data to host info
        info['dns'] = dnsprobe_data

    return total, success, noerror, servfail


def get_ipv6_only_score(hosts):
    """ Checks if any host in the dictionary has an IPv4 address.
    """

    if not hosts or len(hosts) == 0:
        return None, None, None, False

    ipv6_only_ready = True
    resources_total = 0
    resources_ipv6_http = 0
    resources_ipv6_dns = 0
    resources_ipv6_overall = 0
    has_dnsinfo = True
    for hostname, info in hosts.items():
        # calculate http score
        has_ipv6 = False
        resources = len(info.get('urls', []))
        resources_total += resources
        for ip in info.get('ips', []):
            if not is_ip(ip):
                pass # ignore non-ip addresses
            elif ip.version == 6 and not ip.is_nat64() and not ip.ipv4_mapped:
                has_ipv6 = True
        if not has_ipv6:
            ipv6_only_ready = False
        else:
            resources_ipv6_http += resources
        # calculate dns score
        if info.get('dns', None) and 'ipv6_only_ready' in info['dns']:
            if info['dns'].get('ipv6_only_ready'):
                resources_ipv6_dns += resources
            else:
                ipv6_only_ready = False
                has_ipv6 = False
        else:
            has_dnsinfo = False
        # calculate overall score
        if has_ipv6:
            resources_ipv6_overall += resources

    overall_score = resources_ipv6_overall / resources_total if resources_total > 0 else None
    http_score = resources_ipv6_http / resources_total if resources_total > 0 else None
    dns_score = resources_ipv6_dns / resources_total if resources_total > 0 and has_dnsinfo else None

    return overall_score, http_score, dns_score, ipv6_only_ready


def add_whois_info(hosts):
    """Adds WHOIS information for each unique IP address in the hosts dictionary.

    Args:
        hosts (dict): Dictionary containing host information

    Returns:
        tuple: A tuple containing statistics about the WHOIS lookups:
            - global_cache_hits (int): Number of global cache hits
            - local_cache_hits (int): Number of local cache hits
            - whois_lookups (int): Number of actual WHOIS lookups performed
            - whois_failed (int): Number of WHOIS lookups that failed
    """

    # Cache stats
    stats = {'global_cache_hit': 0, 'local_cache_hit': 0, 'whois_lookup': 0, 'whois_failed': 0}

    # Cache WHOIS lookups by network CIDR locally
    local_cache = {4: {}, 6: {}}

    # Iterate over all hosts and their IPs to fetch WHOIS information
    for hostname, info in hosts.items():
        whois_data = {}
        for ip_in in info.get('ips', []):

            # normalize IP address for lookup
            if ip_in.version == 6 and ip_in.is_nat64():
                ip = ip_in.nat64_extract_ipv4()
            elif ip_in.version == 6 and ip_in.ipv4_mapped:
                ip = ip_in.ipv4_mapped
            else:
                ip = ip_in

            if debug_whois:
                print(f"\taquiring whois info for {ip_in} lookup {ip}", file=sys.stderr)

            whois_info, source = get_whois_info(ip, local_cache, storage_manager, debug=debug_whois)
            whois_data[ip_in] = whois_info
            stats[source] += 1

        # Add WHOIS data to host info
        info['whois'] = whois_data

    return stats['global_cache_hit'], stats['local_cache_hit'], stats['whois_lookup'], stats['whois_failed']


def gen_json(url, domain=None, hosts={}, ipv6_only_ready=None, score=None, http_score=None, dns_score=None, screenshot=None,
             report_id=None, timestamp=datetime.now(timezone.utc), timings=None, extension=None, browser_info=None, scoreboard_entry=False,
             error=None, error_code=200):
    """ prepare the hosts dictionary to be dumped as a JSON object.
    """

    def gen_json_ips(ip, v):
        if not is_ip(ip):
            address_family = 'None'
        else:
            match ip.version:
                case 4:
                    address_family = 'IPv4'
                case 6 if ip.is_nat64():
                    address_family = 'NAT64'
                case 6 if ip.ipv4_mapped:
                    address_family = 'IPv4'
                case 6:
                    address_family = 'IPv6'
                case _:
                    address_family = 'Unknown'

        return {
            'address_family': address_family,
            'transport': [ [tp , sp] for tp, sp in v['protocols'][ip] ],
            'whois': v['whois'].get(ip, None) if v.get('whois', None) else None
        }

    return { 'ID': report_id,
             'webres6_version': webres6_version,
             'browser': browser_info,
             'error': error,
             'error_code': error_code,
             'ts': timestamp,
             'url': url.geturl(),
             'domain': domain,
             'ipv6_only_ready': ipv6_only_ready,
             'ipv6_only_score': score,
             'ipv6_only_http_score': http_score,
             'ipv6_only_dns_score': dns_score,
             'hosts': { k: {
                 'local_part': str(v['local_part']),
                 'domain_part': str(v['domain_part']),
                 'urls': list(v['urls']),
                 'ips': {
                     str(ip): gen_json_ips(ip, v) for ip in v['ips']
                 },
                 'dns': v.get('dns', None),
                 'subject_alt_names': sorted(v['subject_alt_names'])
                 } for k, v in hosts.items()
             },
             'screenshot': screenshot,
             'extension': extension,
             'scoreboard_entry': bool(scoreboard_entry),
             'timings': timings if timings else {} }


def gen_report_id(url, wait, timeout, ext, screenshot_mode, lookup_whois, ts, report_node):
    """ Generates a unique report ID based on the input parameters.
    """
    subject = sha256(f"{url.geturl()}:{wait}:{timeout}:{ext}:{screenshot_mode}:{lookup_whois}".encode('utf-8')).hexdigest()
    return f"{int(ts.timestamp()):x}-{subject}-{report_node}"


def crawl_and_analyze_url(url, wait=2, timeout=10, scoreboard_entry=False,
                          ext=None, screenshot_mode=None,
                          lookup_whois=False, report_id = None, report_node='unknown'):
    """ Crawls and analyzes the given URL, returning the results as a JSON object.
    """

    # collect timing stats
    timings = {}
    ts = datetime.now(timezone.utc)
    last_ts = ts

    def push_timing(key):
        nonlocal last_ts
        now = datetime.now(timezone.utc)
        spent = (now - last_ts).total_seconds()
        timings[key] = spent
        webres6_time_spent.labels(phase=key).inc(spent)
        last_ts = now

    # init logging
    if not report_id:
        report_id = gen_report_id(url, wait, timeout, ext, screenshot_mode, lookup_whois, ts, report_node)
    lp = f"res6 {report_id:.25} "
    webres6_tested_total.inc()
    print(f"{lp}testing {url.geturl().translate(str.maketrans('','', ''.join([chr(i) for i in range(1, 32)])))}", file=sys.stderr)
    print(f"{lp}options: wait={wait}s, timeout={timeout}s, scoreboard={scoreboard_entry}, extension={ext}, screenshot={screenshot_mode}, whois={lookup_whois}", file=sys.stderr)

    # initialize webdriver
    extension_data = {}
    driver, err = init_webdriver(log_prefix=lp, extension=ext, extension_data=extension_data)
    if not driver:
        webres6_tested_results.labels(result='errors').inc()
        return gen_json(url, report_id=report_id, error=f'Could not initialize selenium: {err}', error_code=503), 503
    browser_info = { 
            'browserName': driver.capabilities.get('browserName', 'unknown'),
            'browserVersion': driver.capabilities.get('browserVersion', 'unknown'),
            'platformName': driver.capabilities.get('platformName', 'unknown'),
            'acceptInsecureCerts': driver.capabilities.get('acceptInsecureCerts', False),
        }
    push_timing('init')

    # perform crawl
    crawl, err = crawl_page(url.geturl(), driver, extension=ext, extension_data=extension_data, wait=wait, timeout=timeout, log_prefix=lp);
    if crawl:
        print(f"{lp}page crawl done", file=sys.stderr)
    push_timing('crawl')

    # take screenshot if requested
    screenshot = None
    if screenshot_mode:
        screenshot = take_screenshot(driver, mode=screenshot_mode, log_prefix=lp)
        push_timing('screenshot')
    elif not crawl:
        screenshot = take_screenshot(driver, mode='small', log_prefix=lp)
        push_timing('screenshot')

    # handle crawl errors
    if not crawl:
        print(f"{lp}ERROR: fetching page failed: {err.replace('\n', ' --- ')}", file=sys.stderr)
        cleanup_crawl(driver, extension=ext, extension_data=extension_data, log_prefix=lp)
        webres6_tested_results.labels(result='errors').inc()
        return gen_json(url, report_id=report_id, screenshot=screenshot, timestamp=ts, timings=timings, error=err, error_code=200), 200


    # collect host info and analyze
    hosts = get_hostinfo(driver, log_prefix=lp)
    print(f"{lp}found {len(hosts)} hosts", file=sys.stderr)
    cleanup_crawl(driver, extension=ext, extension_data=extension_data, log_prefix=lp)
    push_timing('extract')

    # add dnsprobe info if configured
    if dnsprobe:
        total, success, noerror, servfail = add_dnsprobe_info(hosts)
        print(f"{lp}dnsprobe lookups completed: {total} total, {noerror} no error, {success} success, {servfail} servfail", file=sys.stderr)
        push_timing('dnsprobe')

    if lookup_whois and enable_whois:
        gch, lch, qs, qf = add_whois_info(hosts)
        print(f"{lp}whois lookups: {qs} successful, {qf} failed, {gch} global cache hits, {lch} local cache hits", file=sys.stderr)
        push_timing('whois')

    # report statistics
    score, http_score, dns_score, ipv6_only_ready = get_ipv6_only_score(hosts)
    print(f"{lp}website is {'' if ipv6_only_ready else 'NOT '}ipv6-only ready (overall={f"{score*100:.1f}%" if score is not None else 'N/A'}, http={f"{http_score*100:.1f}%" if http_score is not None else 'N/A'}, dns={f"{dns_score*100:.1f}%" if dns_score is not None else 'N/A'})", file=sys.stderr)
    if ipv6_only_ready is True:
        webres6_tested_results.labels(result='ipv6_only_ready').inc()
    else:
        webres6_tested_results.labels(result='not_ipv6_only_ready').inc()

    if http_score is not None:
        webres6_scores_total.labels(score_type='http').observe(http_score)
    if dns_score is not None:
        webres6_scores_total.labels(score_type='dns').observe(dns_score)
    if score is not None:
        webres6_scores_total.labels(score_type='overall').observe(score)

    # generate final report
    _, domain = split_hostname(url.hostname)
    report = gen_json(url, domain=domain, report_id=report_id, hosts=hosts, ipv6_only_ready=ipv6_only_ready,
                    score=score, http_score=http_score, dns_score=dns_score,
                    screenshot=screenshot, timestamp=ts, extension=ext, scoreboard_entry=scoreboard_entry, browser_info=browser_info, timings=timings)

    # call extension finalization if needed
    finalize_report(report, extension=ext, extension_data=extension_data, log_prefix=lp)

    # remove None values from report
    for key in list(report.keys()):
        if report[key] is None:
            del report[key]

    push_timing('finalize')
    print(f"{lp}time spent: total={sum(timings.values()):.2f}s " +
          ' '.join([f"{k}={v:.3f}s" for k, v in timings.items()]), file=sys.stderr)

    # send response
    return report, 200


def get_archived_report(report_id):
    """ Retrieves a cached report from storage if available.
    """

    if not storage_manager and not storage_manager.can_archive():
        # storge manager not configured - send error
        return jsonify({ 'error': 'Archive links are not supported in this deployment', 'report_id': report_id }), 200

    lp = f"res6 {report_id:.25} "

    if report_url := storage_manager.retrieve_result_url(report_id):
        # redirect to external report URL to improve client caching
        print(f"{lp}sending archived report {report_id} via redirect to {report_url}", file=sys.stderr)
        webres6_archive_total.labels(result='success').inc()
        rr = redirect(report_url)
        rr.headers['Cache-Control'] = f"public, max-age={storage_manager.url_expiry}"
        return rr, 303

    if report := storage_manager.retrieve_result(report_id):
        ttl = report['ts'] + timedelta(seconds=result_archive_ttl) - datetime.now(timezone.utc)
        print(f"{lp}sending archived report {report_id}", file=sys.stderr)
        webres6_archive_total.labels(result='success').inc()
        res = jsonify(report)
        res.headers['Cache-Control'] = f"public, max-age={ttl.total_seconds():.0f}"
        return res, 200

    # report not found
    print(f"{lp}WARNING: cached report {report_id} not found in archive", file=sys.stderr)
    webres6_archive_total.labels(result='not_found').inc()
    return jsonify({ 'error': 'Report not found in archive', 'report_id': report_id }), 404


def crawl_and_analyze_url_cached(url, wait=2, timeout=10, scoreboard_entry=True,
                                 ext=None, screenshot_mode=None,
                                 lookup_whois=False, report_node='unknown'):
    """ Crawls and analyzes the given URL, using cached results if available.
    """

    if not storage_manager or not storage_manager.can_archive():
        # Valkey is not configured, skip cache lookup
        return crawl_and_analyze_url(url, wait=wait, timeout=timeout, ext=ext, scoreboard_entry=scoreboard_entry,
                                      screenshot_mode=screenshot_mode,
                                      lookup_whois=lookup_whois, report_node=report_node)

    def redirect_to_report(report_id, ttl, storage_manager):
        rr = redirect(storage_manager.url_template.replace('{report_id}', report_id))
        rr.headers['Cache-Control'] = f"private, max-age={ttl:.0f}"
        return rr, 303

    # Try to lookup in Valkey cache first if available
    cache_key = sha256(f"{url}:{wait}:{timeout}:{ext}:{screenshot_mode}:{lookup_whois}".encode('utf-8')).hexdigest()
    json_result = storage_manager.get_result_cacheline(cache_key)
    if json_result:
        # update statistics
        webres6_cache_hits_total.inc()
        # update logging
        ts = json_result.get('ts')
        report_id = json_result.get('report_id', 'unknown')
        lp = f"res6 {report_id:.25} "
        cache_age = datetime.now(timezone.utc) - ts
        type = json_result.get('type', None)
        data = json_result.get('data', None)
        print(f"{lp}sending cached {type} age={cache_age.total_seconds():.1f}s {url.geturl().translate(str.maketrans('','', ''.join([chr(i) for i in range(1, 32)])))}", file=sys.stderr)
        print(f"{lp}options: wait={wait}s, timeout={timeout}s, extension={ext}, screenshot={screenshot_mode}, whois={lookup_whois}", file=sys.stderr)
        if type == 'sentinel':
            response = jsonify({ 'error': 'Crawl in progress - please come back later', 'report_id': report_id })
            response.headers['Refresh'] = '15'
            return response, 202
        elif type == 'report':
            # redirect to report URL to improve client caching
            return redirect_to_report(report_id, max(0, result_cache_ttl - cache_age.total_seconds()), storage_manager)
        else:
            print(f"{lp}WARNING: unknown cached result type {type}", file=sys.stderr)

    # generate report id for logging
    ts = datetime.now(timezone.utc)
    report_id = gen_report_id(url, wait, timeout, ext, screenshot_mode, lookup_whois, ts, report_node)
    lp = f"res6 {report_id} "

    # Put a sentinel entry into the cache to avoid multiple concurrent crawls for the same URL
    sentinel = { 'type': 'sentinel', 'ts': ts, 'report_id': report_id,
                    'data': "crawl in progress - please come back later"}
    storage_manager.put_result_cacheline(cache_key, sentinel, max_timeout, False)

    # Perform actual crawl
    json_result, error_code = crawl_and_analyze_url(url, wait=wait, timeout=timeout, ext=ext, scoreboard_entry=scoreboard_entry,
                                   screenshot_mode=screenshot_mode,
                                   lookup_whois=lookup_whois, report_id=report_id, report_node=report_node)

    # Handle internal errors where crawl logic faild to prevent caching of error results as valid reports.
    # Non-exisiting URLs still prodce a valid crawl (200) with error details in the JSON result.
    if error_code != 200:
        # remove sentinel in case of crawl error to allow retries
        storage_manager.delete_result_cacheline(cache_key)
        return json_result, error_code

    # Archive the result in storage
    archived = storage_manager.archive_result(report_id, json_result)

    # Cache the result in storage if archiving was successful
    storage_manager.delete_result_cacheline(cache_key)  # remove sentinel
    if archived:
        # put cache line pointing to archived report
        cache_line = { 'type': 'report', 'ts': ts, 'report_id': report_id,
                        'data': "./reports/" + report_id }
        storage_manager.put_result_cacheline(cache_key, cache_line, result_cache_ttl, True)

        # enter scoreboard entry
        if scoreboard and scoreboard_entry and json_result.get('error', None) is None:
            scoreboard.enter(json_result)

        # redirect to report URL to improve client caching
        return redirect_to_report(report_id, result_cache_ttl, storage_manager)

    else:
        return json_result, error_code


def check_auth(request):
    """ Check if the request is authorized.
    """
    auth = request.authorization
    if not admin_api_key or (auth and auth.password == admin_api_key) or request.args.get('key') == admin_api_key:
        return True
    return False


def create_http_app():
    """ Start HTTP API server to serve host information.

    All api endpoints are created here.

    Returns:
        Flask app instance
    """


    # Start a simple HTTP API server using Flask
    app = Flask(__name__, static_folder=app_home)
    app.config['JSON_AS_ASCII'] = False
    app.json_provider_class = FlaskJSONProvider
    app.json = app.json_provider_class(app)

    print("creating endpoints:", file=sys.stderr)

    print("\t/ping                liveliness probe endpoint", file=sys.stderr)
    @app.route('/ping', methods=['GET'])
    def ping():
        return jsonify({'status': 'ok', 'ts': datetime.now(timezone.utc).isoformat()}), 200

    print("\t/res6/$metadata      get OData metadata document", file=sys.stderr)
    @app.route('/res6/$metadata', methods=['GET'])
    def res6_metadata():
        return send_from_directory(app_home, 'webres6-api-metadata.xml', mimetype='application/xml')

    print("\t/res6/serverconfig   list available extensions, screenshot-modes, whois support, ...", file=sys.stderr)
    @app.route('/res6/serverconfig', methods=['GET'])
    def res6_serverconfig():
        res = jsonify({'version': webres6_version,
                        'message': srv_message, 'privacy_policy': privacy_policy,
                        'max_wait': max_wait, 'extensions': get_extensions(),
                        'whois': enable_whois, 'screenshot_modes': screenshot_modes,
                        'archive': storage_manager.can_archive(),
                        'archive_url_template': storage_manager.url_template if storage_manager and storage_manager.can_archive() else None,
                        'scoreboard': scoreboard is not None,
                        })
        res.headers['Cache-Control'] = 'public, max-age=900'
        return res, 200

    print("\t/res6/url(URL)       get JSON results for URL provided", file=sys.stderr)
    @app.route('/res6/url(<path:url>)', methods=['GET'])
    def res6_url(url):
        ts = datetime.now(timezone.utc)

        # parse url
        if not url:
            return jsonify({'error': 'URL parameter is required'}), 400
        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme == '':
                # try adding https scheme if missing
                parsed_url = urlparse('https://' + url)
            if not parsed_url.scheme or parsed_url.scheme not in ['http', 'https'] or not parsed_url.netloc:
                print(f"ERROR: invalid URL provided: {url} --> {parsed_url}", file=sys.stderr)
                return jsonify({'error': 'Invalid URL provided'}), 400
        except Exception as e:
            return jsonify({'error': f'Invalid URL provided: {e}'}), 400
        # parse other parameters
        wait = float(request.args.get('wait')) if request.args.get('wait') else 2
        if wait > max_wait:
            wait = max_wait
        timeout = float(request.args.get('timeout')) if request.args.get('timeout') else max(3*wait, min_timeout)
        if timeout > max_timeout:
            timeout = max_timeout
        scoreboard_entry = request.args.get('scoreboard', 'false').lower() in ['1', 'true', 'yes', 'on']
        ext = request.args.get('ext')
        if ext:
            ext_ok, ext_error = check_extension_parameter(ext)
            if not ext_ok:
                return jsonify({'error': ext_error}), 400
        screenshot_mode = request.args.get('screenshot', 'none').lower()
        if screenshot_mode == 'none' or screenshot_mode not in screenshot_modes:
            screenshot_mode = None
        lookup_whois = False
        if enable_whois and request.args.get('whois', 'false').lower() in ['1', 'true', 'yes', 'on']:
            lookup_whois = True

        response, error_code = crawl_and_analyze_url_cached(parsed_url, wait=wait, timeout=timeout, scoreboard_entry=scoreboard_entry,
                                          ext=ext, screenshot_mode=screenshot_mode, lookup_whois=lookup_whois,
                                          report_node=report_node)
        webres6_response_time.labels(whois=str(lookup_whois), screenshot=str(screenshot_mode)).observe((datetime.now(timezone.utc) - ts).total_seconds())
        return response, error_code

    print("\t/res6/report/ID      get archived JSON results for report ID provided", file=sys.stderr)
    @app.route('/res6/report/<string:report_id>', methods=['GET'])
    def res6_report(report_id):
        # check record id - only allow alphanumeric characters and hyphens
        if not report_id.replace('-', '').isalnum() or len(report_id) > 255:
            return jsonify({'error': 'Invalid report ID.'}), 400
        return get_archived_report(report_id)

    if scoreboard:
        print("\t/res6/scoreboard     get current scoreboard entries", file=sys.stderr)
        @app.route('/res6/scoreboard', methods=['GET'])
        def res6_scoreboard():
            try:
                limit = int(request.args.get('limit'))
            except (TypeError, ValueError):
                limit = 12
            if limit > scoreboard_request_limit:
                limit = scoreboard_request_limit
            res = jsonify(scoreboard.get_entries(limit=limit))
            res.headers['Cache-Control'] = 'public, max-age=60'
            return res, 200

    print("\t/metrics             get Prometheus compatible metrics", file=sys.stderr)
    @app.route('/metrics', methods=['GET'])
    def metrics():
        if check_auth(request):
            return app.response_class(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
        else:
            return app.response_class('Authentication required', mimetype='text/plain', status=401, headers={'WWW-Authenticate': 'Basic realm="webres6 admin"'})

    if storage_manager and hasattr(storage_manager, 'can_persist') and storage_manager.can_persist():
        print("\t/admin/persist       persist local cache to disk", file=sys.stderr)
        @app.route('/admin/persist', methods=['GET'])
        def admin_persist():
            if check_auth(request):
                result = storage_manager.persist()
                if result:
                    return jsonify({'status': 'ok', 'message': 'Local cache persisted to disk'}), 200
                else:
                    return jsonify({'status': 'error', 'message': 'Failed persisting local cache to disk'}), 500
            else:
                return app.response_class('Authentication required', mimetype='text/plain', status=401, headers={'WWW-Authenticate': 'Basic realm="webres6 admin"'})

    if storage_manager and hasattr(storage_manager, 'expire'):
        print("\t/admin/expire        expire local cache entries", file=sys.stderr)
        @app.route('/admin/expire', methods=['GET'])
        def admin_expire():
            if check_auth(request):
                result = storage_manager.expire()
                print(f"Expired {result} cache entries", file=sys.stderr)
                return jsonify({'status': 'ok', 'message': f'Expired {result} cache entries'}), 200
            else:
                return app.response_class('Authentication required', mimetype='text/plain', status=401, headers={'WWW-Authenticate': 'Basic realm="webres6 admin"'})

    if os.path.isdir(viewer_dir):
        print("\t/viewer/<path:file>  send viewer files", file=sys.stderr)
        @app.route('/viewer/<path:file>', methods=['GET'])
        def send_viewer_file(file):
            return send_from_directory(viewer_dir, file)

        print("\t/viewer/[#url:URL]   serve viewer.html as index", file=sys.stderr)
        print("\t/viewer/[#report:ID] serve viewer.html as index", file=sys.stderr)
        @app.route('/viewer/', methods=['GET'])
        def viewer_index():
            return send_from_directory(viewer_dir, 'viewer.html')

        if debug_viewer:
            print("\t/.well-known/appspecific/com.chrome.devtools.json\n\t                     serve viewer debug info for Chrome DevTools", file=sys.stderr)
            @app.route('/.well-known/appspecific/com.chrome.devtools.json', methods=['GET'])
            def viewer_debug():
                return jsonify({
                    "workspace": {
                        "root": f"{viewer_dir}/",
                        "uuid": uuid.uuid4(),
                    }}), 200

        print("\t/                    redirect to /viewer", file=sys.stderr)
        @app.route('/', methods=['GET'])
        def index():
            return redirect('/viewer', code=302)

    return app

# signal handler for graceful shutdown
def signal_handler(sig, frame):
    print(f"Received signal {sig}, shutting down...", file=sys.stderr)
    if storage_manager and storage_manager.can_persist():
        print("Persisting local cache to disk...", file=sys.stderr)
        storage_manager.persist()
    sys.exit(0)

# main entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="A small web service inspired by Paul Marks' IPvFoo that loads a website\n"\
            " and displays ip addresses it fetched resources from",
            epilog="For production use, consider running in gunicorn behind a reverse proxy.\n")
    parser.add_argument("--port", type=int, metavar='6400', default=6400, help="start a simple HTTP API server at given port")
    parser.add_argument("--debug", action="store_true", help="enable flask debugging output for the HTTP API server")
    parser.add_argument("--export-scoreboard", type=str, metavar='scoreboard.json', help="export scoreboard entries to JSON file and exit")
    parser.add_argument("--import-scoreboard", type=str, metavar='scoreboard.json', help="import scoreboard entries from JSON file and exit")
    parser.add_argument("--export-reports", type=str, metavar='/path/to/dir', help="export all archived reports to the given directory and exit")
    parser.add_argument("--import-reports", type=str, metavar='/path/from/dir', help="import all archived reports from the given directory and exit")
    parser.add_argument("--expire", action="store_true", help="expire local cache entries and exit")
    args = parser.parse_args()

    # dump scoreboard if requested and exit
    if args.export_scoreboard:
        if not scoreboard:
            print("Scoreboard is not enabled in this deployment.", file=sys.stderr)
            sys.exit(1)
        export_scoreboard_entries(storage_manager, args.export_scoreboard)
        sys.exit(0)

    # import scoreboard if requested and exit
    if args.import_scoreboard:
        if not scoreboard:
            print("Scoreboard is not enabled in this deployment.", file=sys.stderr)
            sys.exit(1)
        if import_scoreboard_entries(storage_manager, args.import_scoreboard):
            sys.exit(0)
        else:
            sys.exit(1)

    # export archived reports if requested and exit
    if args.export_reports:
        if export_archived_reports(storage_manager, args.export_reports, result_archive_ttl):
            sys.exit(0)
        else:
            sys.exit(1)

    # import archived reports if requested and exit
    if args.import_reports:
        if import_archived_reports(storage_manager, args.import_reports, result_archive_ttl):
            sys.exit(0)
        else:
            sys.exit(1)

    # expire local cache entries if requested and exit
    if args.expire:
        if storage_manager and hasattr(storage_manager, 'expire'):
            result = storage_manager.expire()
            print(f"Expired {result} cache entries", file=sys.stderr)
            if storage_manager.can_persist():
                print("Persisting local cache to disk...", file=sys.stderr)
                storage_manager.persist()
            sys.exit(0)
        else:
            print("Storage manager does not support expiring cache entries.", file=sys.stderr)
            sys.exit(1)

    # Process store-only arguments
    if args.debug:
        debug_flask = True
        debug_viewer = True
        print("Debugging mode is ON. This will print a lot of information to stderr.", file=sys.stderr)

    # register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Check if URL is provided and valid
    print(f"Starting HTTP API server on port {args.port}", file=sys.stderr)
    app = create_http_app()
    app.run(debug=debug_flask, host='::1', port=args.port, threaded=False)


# vim: set ts=4 sw=4 et:
# vim: set fileencoding=utf-8:
# vim: set filetype=python: