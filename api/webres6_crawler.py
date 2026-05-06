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
from selenium.webdriver.remote.client_config import ClientConfig
from selenium.common.exceptions import WebDriverException, TimeoutException
import urllib3
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from prometheus_client import Counter

from webres6_extension import init_selenium_options, prepare_selenium_crawl, operate_selenium_crawl, cleanup_selenium_crawl

# config
app_home          = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
srvconfig_dir     = os.path.join(app_home, 'serverconfig')
selenium_remote   = getenv("SELENIUM_REMOTE_URL", None)
selenium_username = getenv("SELENIUM_USERNAME", None)
selenium_password = getenv("SELENIUM_PASSWORD", None)
headless_selenium = getenv("HEADLESS_SELENIUM", False)
debug_hostinfo    = 'hostinfo' in getenv("DEBUG", '').lower().split(',')

# Selenium client config for remote driver
selenium_client_config = None
if selenium_remote:
    selenium_client_config = ClientConfig(
        remote_server_addr=selenium_remote,
        username=selenium_username if selenium_username else 'admin',
        password=selenium_password if selenium_password else 'admin',
    )

# URL blocklist — defaults plus optional override file
url_blocklist = ["*://*.local/*", "*://*.internal/*"]

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
    options.add_experimental_option('perfLoggingPrefs', { 'enableNetwork' : True })
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
            print(f"{log_prefix}connecting to remote Selenium server at {selenium_remote}", file=sys.stderr)
            driver = webdriver.Remote(command_executor=selenium_remote, options=options, client_config=selenium_client_config)
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
        while time.time() - start_time < timeout:
            if driver.execute_script("return document.readyState") == "complete":
                span.add_event("page_ready", {"elapsed_seconds": time.time() - start_time})
                break
            time.sleep(0.5)

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


@tracer.start_as_current_span("selenium.get_hostinfo")
def get_hostinfo(driver, log_prefix=''):
    """ Extracts host information using Selenium/Chromium network performance logs.
    """
    span = trace.get_current_span()

    # Ask selenium for performance logs
    try:
        # ugly work-around as >>> # perfs = driver.get_log('performance') <<< does not work with remote driver
        perfs = driver.execute('getLog', {'type': 'performance'})['value']
    except WebDriverException as e:
        print(f"Error fetching performance logs: {e.msg}", file=sys.stderr)
        return None

    # dictionary to hold host-level summaries
    hosts = {}

    # check if public suffix list is available
    if public_suffixes is None: 
        print(f"{log_prefix}WARNING: public suffix list not found, domain part extraction will always use the 2nd level domain.", file=sys.stderr)

    # Extract host info from performance logs
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
                span.add_event("log.missing_ip", {"response": str(response)})
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
            span.add_event("log.invalid_ip", {"ip_address": remote_ip, "error": str(e)})
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
                span.add_event("log.missing_hostname", {"url": response.get('url')})
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
            span.add_event("host.new", {"hostname": url.hostname, "domain_part": domain_part, "local_part": local_part})
        else:
            span.add_event("host.update", {"hostname": url.hostname})

        # Add the URLs and additional IPs
        hosts[url.hostname]['urls'].add(url.geturl())
        hosts[url.hostname]['ips'].add(ip)
        # Update protocols if they are not already set
        if ip not in hosts[url.hostname]['protocols']:
            hosts[url.hostname]['protocols'][ip] = [protocols]
        elif protocols not in hosts[url.hostname]['protocols'][ip]:
            hosts[url.hostname]['protocols'][ip].append(protocols)
        # Update subject alt names if they are not already set
        if security_details:
            hosts[url.hostname]['subject_alt_names'].update(security_details.get('sanList'))

    return hosts


@tracer.start_as_current_span("selenium.cleanup_crawl")
def cleanup_crawl(driver, extension=None, extension_data=None, log_prefix=''):
    """Cleans up the Selenium WebDriver instance by safely quitting it."""
    try:
        cleanup_selenium_crawl(driver, extension=extension, extension_data=extension_data, log_prefix=log_prefix)
        driver.quit()
    except WebDriverException as e:
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
