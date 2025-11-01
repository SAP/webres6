#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import argparse
import json
from os import getenv
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException
from urllib.parse import urlparse
from flask import Flask, redirect, request, jsonify, send_from_directory
import os
import platform
import time
from ipwhois import IPWhois

# config/flag variables
webres6_version  = "0.8.0"
debug_whois      = 'whois'    in getenv("DEBUG", '').lower().split(',')
debug_hostinfo   = 'hostinfo' in getenv("DEBUG", '').lower().split(',')
debug_flask      = 'flask'    in getenv("DEBUG", '').lower().split(',')
admin_api_key    = getenv("ADMIN_API_KEY", None)
selenium_remote  = getenv("SELENIUM_REMOTE_URL", None)
headless_selenium = getenv("HEADLESS_SELENIUM", False)
app_home         = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
extensions_dir   = os.path.join(app_home, 'extensions')
viewer_dir       = os.path.join(app_home, '..', 'viewer')
srvconfig_dir    = os.path.join(app_home, 'serverconfig')
max_timeout      = int(getenv("TIMEOUT", 180))//2
max_wait         = max_timeout//3
enable_whois     = getenv("ENABLE_WHOIS", '').lower() in ['true', '1', 'yes']
whois_cache_ttl  = int(getenv("WHOIS_TTL", 270000)) # seconds
screenshot_modes = ['none', 'small', 'medium', 'full']

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

# global whois cache
whois_cache = {}
whois_cache_stats = {'local_hits': 0, 'global_hits': 0, 'lookups': 0, 'failed': 0}

#statistsics
time_total_spent = {'init': 0.0, 'crawl': 0.0, 'screenshot': 0.0, 'extract': 0.0, 'whois': 0.0}
check_results_total = {'tested': 0, 'ipv6_only_ready': 0, 'not_ipv6_only_ready': 0, 'errors': 0}
hostinfo_parsed_total = {'without_ip': 0, 'valid_ip': 0, 'invalid_ip': 0, 'without_hostname': 0, 'skipped': 0, 'error': 0}

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


def init_webdriver(headless=False, log_prefix='', implicit_wait=0.5, extension=None):
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

    if headless:
        options.headless = True
        options.add_argument("--headless=new")

    # load extension if requested
    if extension:
        ext = os.path.normpath(os.path.join(extensions_dir, os.path.basename(extension)))
        if not ext.startswith(extensions_dir):
            print(f"{log_prefix}ERROR: requested extension {ext} is outside of extensions directory", file=sys.stderr)
            driver.quit()
            return None
        elif os.path.exists(ext):
            print(f"{log_prefix}adding requested extension {ext} to browser", file=sys.stderr)
            try:
                options.add_extension(ext)
            except WebDriverException as e:
                print(f"{log_prefix}ERROR: failed adding extension {ext} to browser: {e}", file=sys.stderr)
                driver.quit()
                return None
        else:
            print(f"{log_prefix}ERROR: extension {ext} does not exist", file=sys.stderr)
            driver.quit()
            return None

    # If SELENIUM_REMOTE_URL is set, use it to connect to a remote Selenium server
    driver = None

    try:
        if selenium_remote:
            print(f"{log_prefix}connecting to remote Selenium server at {selenium_remote}", file=sys.stderr)
            driver = webdriver.Remote(command_executor=selenium_remote, options=options)
        else:
            print(f"{log_prefix}starting local Selenium", file=sys.stderr)
            driver = webdriver.Chrome(options=options)

        # set implicit wait for almost all actions
        driver.implicitly_wait(implicit_wait)

        # add block list
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": url_blocklist })

    except WebDriverException as e:
        print(f"{log_prefix}ERROR: failed initializing Selenium WebDriver: {e.msg}", file=sys.stderr)
        driver = None

    return driver


def crawl_page(url, driver=None, wait=2, timeout=10, log_prefix=''):
    """ Fetches the web page at the given URL using Selenium WebDriver.
    """

    try:
        start_time = time.time()
        driver.get(url)
        while time.time() - start_time < timeout:
            time.sleep(wait)
            state = driver.execute_script("return document.readyState")
            if state == "complete":
                break

    except WebDriverException as e:
        return False, e.msg.replace('unknown error: ', '')

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
            hostinfo_parsed_total['error'] += 1
            continue

        # We are only interested in Network.responseReceived events
        if 'message' not in obj or obj['message'].get('method') != 'Network.responseReceived':
            hostinfo_parsed_total['skipped'] += 1
            continue

        # Check for valid IP in response
        response = obj['message']['params']['response']
        remote_ip = response.get('remoteIPAddress', None)
        if not remote_ip:
            hostinfo_parsed_total['without_ip'] += 1
            if debug_hostinfo:
                print(f"{log_prefix}WARNING: No valid IP address found in {response}", file=sys.stderr)
            continue
        # Strip brackets from IPv6 addresses
        if remote_ip and remote_ip.startswith('[') and remote_ip.endswith(']'):
            remote_ip = remote_ip[1:-1]
        # Parse the IP address
        try:
            ip = ip_address(remote_ip)
            hostinfo_parsed_total['valid_ip'] += 1
        except ValueError as e:
            hostinfo_parsed_total['invalid_ip'] += 1
            print(f"{log_prefix}WARNING: Error parsing IP address: {remote_ip} - {e}", file=sys.stderr)
            ip = None

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
            hostinfo_parsed_total['without_hostname'] += 1
            if debug_hostinfo:
                print(f"{log_prefix}WARNING: No valid hostname found in URL {response.get('url')}", file=sys.stderr)
            continue

        # Create a new host entry if it does not exist yet
        if url.hostname not in hosts:
            parts = url.hostname.rsplit('.', 2)
            hosts[url.hostname] = {
                'domain_part': '.'.join(parts[-2:]) if len(parts) > 1 else url.hostname,
                'local_part': (parts[0] + '.') if len(parts) > 2 else '',
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

def cleanup_crawl(driver, log_prefix=''):
    """Cleans up the Selenium WebDriver instance by safely quitting it.

    Args:
        driver: The Selenium WebDriver instance to be cleaned up
        log_prefix (str, optional): Prefix to add to error log messages. Defaults to ''.

    Returns:
        None

    """
    try:
        driver.quit()
    except WebDriverException as e:
        print(f"{log_prefix}ERROR: failed quitting WebDriver: {e.msg}", file=sys.stderr)
    return

def check_ipv6_only_ready(hosts):
    """ Checks if any host in the dictionary has an IPv4 address.
    """

    if not hosts or len(hosts) == 0:
        return None

    for hostname, info in hosts.items():
        has_ipv6 = False
        for ip in info.get('ips', []):
            if not is_ip(ip):
                pass # ignore non-ip addresses
            elif ip.version == 6 and not ip.is_nat64() and not ip.ipv4_mapped:
                has_ipv6 = True
        if not has_ipv6:
            return False
    return True

def get_whois_info(ip, local_cache, global_cache):
    """ Fetches WHOIS information for the given IP address using local and global caches.

    Args:
        ip (ipaddress.IPv4Address or ipaddress.IPv6Address): The IP address to look up

    Returns:
        dict: The WHOIS information for the IP address, or None if not found.
    """

    def push_to_local_cache(whois_info):
        try:
            for cidr in whois_info['network']['cidr'].split(','):
                ipn = ip_network(cidr.strip())
                local_cache[ipn] = whois_info
        except (ValueError, KeyError) as e:
            print(f"\tWARNING: local cache push failed for whois info {whois_info}: {e}", file=sys.stderr)

    def lookup_local_cache(ip):
        for network_cidr, cached_data in local_cache[ip.version].items():
            if ip in network_cidr:
                if debug_whois:
                    print(f"\twhois cache local hit for {ip} in network {network_cidr}", file=sys.stderr)
                return cached_data
        return None

    def lookup_whois(ip):
        # Perform WHOIS lookup using ipwhois library last
        try:
            obj = IPWhois(str(ip))
            result = obj.lookup_rdap(depth=1)
            
            # Extract network CIDR
            network_cidr = result.get("network", {}).get("cidr")
            if not network_cidr:
                print(f"\tWARNING: whois lookup failed for {ip}: {e}", file=sys.stderr)
                return None

            whois_info = {
                'ts': datetime.now(),
                'asn': result.get("asn"),
                'asn_description': result.get("asn_description"),
                'asn_country': result.get("asn_country_code"),
                'network': {
                    "name": result.get("network", {}).get("name"),
                    "handle": result.get("network", {}).get("handle"),
                    "country": result.get("network", {}).get("country"),
                    "cidr": network_cidr
                }
            }

            if debug_whois:
                print(f"\twhois lookup for {ip}: {whois_info}", file=sys.stderr)

            return whois_info

        except Exception as e:
            print(f"\tWARNING: whois lookup failed for {ip}: {e}", file=sys.stderr)
            return None

    # Check global cache (exact ip match) first
    if (whois_info := global_cache.get(ip, None)):
        if debug_whois:
            print(f"\twhois global cache hit for {ip}", file=sys.stderr)
        # Cache the result locally
        push_to_local_cache(global_cache[ip])
        # store result
        whois_cache_stats['global_hits']+=1
        return whois_info, 'global_cache_hit'

    # Check if IP falls into any locally cached network afterwards
    elif (whois_info := lookup_local_cache(ip)):
        # Cache the result globally
        global_cache[ip] = whois_info
        # store result
        whois_cache_stats['lookups']+=1
        return whois_info, 'local_cache_hit'

    # finally do a real whois lookup
    elif (whois_info := lookup_whois(ip)):
        # Cache the result locally using network CIDR
        push_to_local_cache(whois_info)
        # Cache the result globally
        global_cache[ip] = whois_info
        # store result
        whois_cache_stats['lookups']+=1
        return whois_info, 'whois_lookup'
    else:
        # store result
        whois_cache_stats['failed']+=1
        return None, 'whois_failed'


def expire_whois_cache():
    """ Expires old entries from the global whois cache.

    Returns:
        int: Number of expired entries
    """

    now = datetime.now()
    expired_keys = [ip for ip, data in whois_cache.items() if (now - data['ts']).total_seconds() > whois_cache_ttl]
    for ip in expired_keys:
        del whois_cache[ip]
    if debug_whois and expired_keys:
        print(f"Expired {len(expired_keys)} entries from whois cache.", file=sys.stderr)
    return len(expired_keys)


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

            whois_info, source = get_whois_info(ip, local_cache, whois_cache)
            whois_data[ip_in] = whois_info
            stats[source] += 1

        # Add WHOIS data to host info
        info['whois'] = whois_data

    return stats['global_cache_hit'], stats['local_cache_hit'], stats['whois_lookup'], stats['whois_failed']


def gen_json(url, hosts={}, ipv6_only_ready=None, screenshot=None, report_id=None, timestamp=datetime.now(), timings=None, extension=None, error=None):
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
             'url': url,
             'error': error, 
             'ts': timestamp.isoformat(),
             'ipv6_only_ready': ipv6_only_ready,
             'extension': extension,
             'hosts': { k: {
                 'local_part': str(v['local_part']),
                 'domain_part': str(v['domain_part']),
                 'urls': list(v['urls']),
                 'ips': {
                     str(ip): gen_json_ips(ip, v) for ip in v['ips']
                 },
                 'subject_alt_names': sorted(v['subject_alt_names'])
                 } for k, v in hosts.items()
             },
             'screenshot': screenshot,
             'timings': timings if timings else {} }


def crawl_and_analyze(url, wait=2, timeout=10, ext=None, screenshot_mode=None, lookup_whois=False,
                      report_node='unknown', headless_selenium=False):

        # collect timing stats
        timings = {}
        ts = datetime.now()
        last_ts = ts

        def push_timing(key):
            nonlocal last_ts
            now = datetime.now()
            spent = (now - last_ts).total_seconds()
            timings[key] = spent
            time_total_spent[key] += spent
            last_ts = now

        # init logging
        report_id = f"{int(ts.timestamp())}-{hash(url) % 2**sys.hash_info.width}-{report_node}"
        lp = f"res6 {report_id} "
        check_results_total['tested'] += 1
        print(f"{lp}testing {url.translate(str.maketrans('','', ''.join([chr(i) for i in range(1, 32)])))}", file=sys.stderr)
        push_timing('init')

        # initialize webdriver and crawl page
        driver = init_webdriver(headless=headless_selenium, log_prefix=lp, extension=ext)
        if not driver:
            check_results_total['errors'] += 1
            return jsonify({'error': 'Could not initialize selenium with the requested extension'}), 400
        crawl, err = crawl_page(url, driver, wait=wait, timeout=timeout, log_prefix=lp);
        push_timing('crawl')

        # take screenshot if requested
        screenshot = None
        if screenshot_mode:
            screenshot = take_screenshot(driver, mode=screenshot_mode, log_prefix=lp)
            push_timing('screenshot')

        if not crawl:
            print(f"{lp}ERROR: fetching page failed: {err.replace('\n', ' --- ')}", file=sys.stderr)
            cleanup_crawl(driver)
            check_results_total['errors'] += 1
            return gen_json(url, report_id=report_id, screenshot=screenshot, timestamp=ts, timings=timings, error=err)

        # collect host info and analyze
        hosts = get_hostinfo(driver, log_prefix=lp)
        print(f"{lp}found {len(hosts)} hosts", file=sys.stderr)
        cleanup_crawl(driver)
        ipv6_only_ready = check_ipv6_only_ready(hosts)
        print(f"{lp}website is {'' if ipv6_only_ready else 'NOT '}ipv6-only ready", file=sys.stderr)
        push_timing('extract')

        if lookup_whois:
            gch, lch, qs, qf = add_whois_info(hosts)
            print(f"{lp}whois lookups: {qs} successful, {qf} failed, {gch} global cache hits, {lch} local cache hits", file=sys.stderr)
            push_timing('whois')

        # report statistics
        if ipv6_only_ready is True:
            check_results_total['ipv6_only_ready'] += 1
        else:
            check_results_total['not_ipv6_only_ready'] += 1

        # send response
        return gen_json(url, report_id=report_id, hosts=hosts, ipv6_only_ready=ipv6_only_ready,
                             screenshot=screenshot, timestamp=ts, extension=ext, timings=timings)


def discover_extensions():
    """ Discovers available extensions in the extensions directory.
    """
    extensions = []
    if os.path.exists(extensions_dir):
        for ext in os.listdir(extensions_dir):
            ext_path = os.path.join(extensions_dir, ext)
            if os.path.isfile(ext_path) and ext.endswith('.crx'):
                extensions.append(ext)
                print(f"\t{ext} (packed)", file=sys.stderr)
    return extensions

def render_metrics():
    """ Renders collected timing metrics.
    """

    yield "# HELP webres6_tested_total Total number of checks performed\n"
    yield "# TYPE webres6_tested_total counter\n"
    yield f"webres6_tested_total {check_results_total['tested']}\n"

    yield "# HELP webres6_tested_results Total number of results for checks performed\n"
    yield "# TYPE webres6_tested_results counter\n"
    yield f"webres6_tested_results{{result=\"ipv6_only_ready\"}} {check_results_total['ipv6_only_ready']}\n"
    yield f"webres6_tested_results{{result=\"not_ipv6_only_ready\"}} {check_results_total['not_ipv6_only_ready']}\n"
    yield f"webres6_tested_results{{result=\"errors\"}} {check_results_total['errors']}\n"

    yield "# HELP webres6_time_spent Time spent in different processing phases\n"
    yield "# UNIT seconds\n"
    yield "# TYPE webres6_time_spent counter\n"
    for phase, seconds in time_total_spent.items():
        yield f"webres6_time_spent{{phase=\"{phase}\"}} {seconds}\n"

    yield "# HELP webres6_hostinfo_parsed_total Total number of hostinfo entries parsed\n"
    yield "# TYPE webres6_hostinfo_parsed_total counter\n"
    for key, count in hostinfo_parsed_total.items():
        yield f"webres6_hostinfo_parsed{{type=\"{key}\"}} {count}\n"

    yield "# HELP webres6_whois_lookups Successful whois lookups performed\n"
    yield "# TYPE webres6_whois_lookups counter\n"
    yield f"webres6_whois_lookups{{type=\"whois-success\"}} {whois_cache_stats['lookups']}\n"
    yield f"webres6_whois_lookups{{type=\"whois-fail\"}} {whois_cache_stats['failed']}\n"
    yield f"webres6_whois_lookups{{type=\"cache-local\"}} {whois_cache_stats['local_hits']}\n"
    yield f"webres6_whois_lookups{{type=\"cache-global\"}} {whois_cache_stats['global_hits']}\n"

    yield "# HELP webres6_whois_cache_size Number of entries in whois cache\n"
    yield "# TYPE webres6_whois_cache_size gauge\n"
    yield f"webres6_whois_cache_size {len(whois_cache)}\n"


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

    # Discover extensions available in the extensions directory
    print(f"loading extensions from {extensions_dir}.", file=sys.stderr)
    extensions = discover_extensions()

    # get nodename for report id
    report_node = platform.node()

    # whois enabled?
    print(f"whois lookups are {'enabled with TTL ' + str(whois_cache_ttl) + 's' if enable_whois else 'disabled'}.", file=sys.stderr)

    # Start a simple HTTP API server using Flask
    app = Flask(__name__, static_folder=app_home)
    app.config['RESTFUL_JSON'] = {'ensure_ascii': False}

    print("creating endpoints:", file=sys.stderr)

    print("\t/ping                liveliness probe endpoint", file=sys.stderr)
    @app.route('/ping', methods=['GET'])
    def ping():
        return jsonify({'status': 'ok', 'ts': datetime.now().isoformat()}), 200

    print("\t/res6/$metadata      get OData metadata document", file=sys.stderr)
    @app.route('/res6/$metadata', methods=['GET'])
    def res6_metadata():
        return send_from_directory(app_home, 'webres6-api-metadata.xml', mimetype='application/xml')

    print("\t/res6/serverconfig   list available extensions, screenshot-modes, whois support, ...", file=sys.stderr)
    @app.route('/res6/serverconfig', methods=['GET'])
    def res6_serverconfig():
        return jsonify({'version': webres6_version, 
                        'message': srv_message, 'privacy_policy': privacy_policy,
                        'max_wait': max_wait, 'extensions': extensions,
                        'whois': enable_whois, 'screenshot_modes': screenshot_modes}), 200

    print("\t/res6/url(URL)       get JSON results for URL provided", file=sys.stderr)
    @app.route('/res6/url(<path:url>)', methods=['GET'])
    def res6_url(url):
        # parse url
        if not url:
            return jsonify({'error': 'URL parameter is required'}), 400
        if not url.lower().startswith('http'):
            url = 'https://' + url
        # parse other parameters
        wait = float(request.args.get('wait')) if request.args.get('wait') else 2
        if wait > max_wait:
            wait = max_wait
        timeout = float(request.args.get('timeout')) if request.args.get('timeout') else 3*wait
        if timeout > max_timeout:
            timeout = max_timeout
        ext = request.args.get('ext')
        if ext and ext not in extensions:
            return jsonify({'error': f'Extension {ext} not found.'}), 400
        screenshot_mode = request.args.get('screenshot', 'none').lower()
        if screenshot_mode == 'none' or screenshot_mode not in screenshot_modes:
            screenshot_mode = None
        lookup_whois = False
        if enable_whois and request.args.get('whois', 'false').lower() in ['1', 'true', 'yes', 'on']:
            lookup_whois = True

        return jsonify(crawl_and_analyze(url, wait=wait, timeout=timeout, ext=ext,
                                          screenshot_mode=screenshot_mode, lookup_whois=lookup_whois,
                                          headless_selenium=headless_selenium, report_node=report_node)), 200

    print("\t/adm/whois/expire    expire old whois cache entries", file=sys.stderr)
    @app.route('/adm/whois/expire', methods=['GET'])
    def expwhois():
        if check_auth(request):
            expired = expire_whois_cache()
            print(f"{int(datetime.now().timestamp())}-whois/expire-{report_node} expired {expired} whois cache entries", file=sys.stderr)
            return jsonify({'status': 'ok', 'expired': expired}), 200
        else:
            resp = jsonify({'status': 'unauthorized'})
            resp.mimetype = 'text/json'
            resp.status_code = 401
            resp.headers['WWW-Authenticate'] = 'Basic realm="webres6 admin"'
            return resp

    print("\t/metrics             open telemetry compatible metrics", file=sys.stderr)
    @app.route('/metrics', methods=['GET'])
    def metrics():
        if check_auth(request):
            return app.response_class(render_metrics(), mimetype='application/openmetrics-text')
        else:
            return app.response_class('Authentication required', mimetype='text/plain', status=401, headers={'WWW-Authenticate': 'Basic realm="webres6 admin"'})

    if os.path.isdir(viewer_dir):
        print("\t/viewer/<path:file>  send viewer files", file=sys.stderr)
        @app.route('/viewer/<path:file>', methods=['GET'])
        def send_viewer_file(file):
            return send_from_directory(viewer_dir, file)

        print("\t/viewer/[#URL]       serve viewer.html as index", file=sys.stderr)
        @app.route('/viewer/', methods=['GET'])
        def viewer_index():
            return send_from_directory(viewer_dir, 'viewer.html')

        print("\t/                    redirect to /viewer", file=sys.stderr)
        @app.route('/', methods=['GET'])
        def index():
            return redirect('/viewer', code=302)

    return app

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="A small web service inspired by Paul Marks' IPvFoo that loads a website\n"\
            " and displays ip addresses it fetched resources from",
            epilog="For production use, consider running in gunicorn behind a reverse proxy.\n")
    parser.add_argument("--port", type=int, metavar='6400', help="start a simple HTTP API server at given port")
    parser.add_argument("--debug", action="store_true", help="enable flask debugging output for the HTTP API server")
    args = parser.parse_args()

    # Process store-only arguments
    if args.debug:
        debug_hostinfo = True
        debug_whois = True
        debug_flask = True
        print("Debugging mode is ON. This will print a lot of information to stderr.", file=sys.stderr)

    for nat64 in [ip_network(p) for p in getenv("NAT64_PREFIXES", "").split(",") if p]:
        if nat64.version == 6 or nat64.prefixlen == 96:
            IPv6Address.nat64_networks.append(nat64)
        else:
            print(f"ERROR: Invalid NAT64 prefix {nat64}. Must be an IPv6 network with a /96 prefix length.", file=sys.stderr)
            sys.exit(2)

    # Check if URL is provided and valid
    print(f"Starting HTTP API server on port {args.port}", file=sys.stderr)
    app = create_http_app()
    app.run(debug=debug_flask, host='::1', port=args.port, threaded=False)


# vim: set ts=4 sw=4 et:
# vim: set fileencoding=utf-8:
# vim: set filetype=python: