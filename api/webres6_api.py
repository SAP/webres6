#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

# load system modules
import sys
import argparse
import functools
import json
import os
import signal
import platform
import time
import uuid
from os import getenv
from ipaddress import IPv4Address, IPv6Address
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from tempfile import mkdtemp
from shutil import rmtree
from urllib.parse import urlparse
import flask
from flask import Flask, redirect, request, jsonify, send_from_directory
from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry, multiprocess, disable_created_metrics, generate_latest, CONTENT_TYPE_LATEST

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION, DEPLOYMENT_ENVIRONMENT
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor
from opentelemetry.trace import Status, StatusCode

import webres6_nat64  # noqa: F401 — applies NAT64 monkey-patch to IPv6Address and loads NAT64_PREFIXES

# config/flag variables
webres6_version   = "1.5.0"
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
enable_dnsprobe   = getenv("ENABLE_DNSPROBE", 'true').lower() in ['true', '1', 'yes']
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
check_selenium_health = True
check_dnsprobe_health = True
check_storage_health  = True

# OpenTelemetry configuration
debug_trace        = 'trace' in getenv("DEBUG", '').lower().split(',')
otel_endpoint      = getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", getenv("OTEL_EXPORTER_OTLP_ENDPOINT", None))
otel_enabled       = getenv("OTEL_TRACING_ENABLED", "true" if otel_endpoint else "false").lower() in ['true', '1', 'yes']
otel_console       = getenv("OTEL_CONSOLE_EXPORTER_ENABLED", "true" if debug_trace else "false").lower() in ['true', '1', 'yes']
otel_service_name  = getenv("OTEL_SERVICE_NAME", "webres6-api")

# get nodename for report
report_node = platform.node().split('.')[0]
if len(report_node) >12 or '-' in report_node:
    report_node = sha256(report_node.encode()).hexdigest()[:12]
print(f"report node is set to '{report_node}'.", file=sys.stderr)

# Initialize OpenTelemetry tracing
def init_tracing():
    """Initialize OpenTelemetry tracing."""
    if not otel_enabled:
        print("OpenTelemetry tracing is disabled.", file=sys.stderr)
        return trace.get_tracer(__name__)  # Return a no-op tracer to avoid errors in tracing calls

    try:
        # Create resource with service information
        resource = Resource.create({
            SERVICE_NAME: otel_service_name,
            SERVICE_VERSION: webres6_version,
            DEPLOYMENT_ENVIRONMENT: getenv("OTEL_DEPLOYMENT_ENVIRONMENT", "production"),
            "service.namespace": "webres6",
            "host.name": report_node,
        })

        # Create tracer provider
        provider = TracerProvider(resource=resource)

        # Add OTLP exporter if endpoint configured
        if otel_endpoint:
            # Let OTLPSpanExporter read from environment variables
            # It will automatically use OTEL_EXPORTER_OTLP_TRACES_ENDPOINT or OTEL_EXPORTER_OTLP_ENDPOINT
            otlp_exporter = OTLPSpanExporter()
            provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
            print(f"OpenTelemetry OTLP exporter configured: {otel_endpoint}", file=sys.stderr)

        # Add console exporter if debugging
        if otel_console:
            console_exporter = ConsoleSpanExporter()
            provider.add_span_processor(BatchSpanProcessor(console_exporter))
            print("OpenTelemetry console exporter enabled", file=sys.stderr)

        # Set global tracer provider
        trace.set_tracer_provider(provider)

        print("OpenTelemetry tracing initialized successfully", file=sys.stderr)

    except Exception as e:
        print(f"WARNING: Failed to initialize OpenTelemetry: {e}", file=sys.stderr)

    return trace.get_tracer(__name__)  # Returns a no-op tracer if initialization failed

# Initialize tracing
tracer = init_tracing()

# Prometheus metrics
prometheus_mp_temp_dir = None
disable_created_metrics()
webres6_tested_total = Counter('webres6_tested_total', 'Total number of checks performed')
webres6_tested_results = Counter('webres6_results_total', 'Total number of results for checks performed', ['result'])
webres6_scores_total = Histogram('webres6_scores_total', 'Histogram of scores results ', ['score_type'], buckets=(0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0))
webres6_cache_hits_total = Counter('webres6_cache_hits_total', 'Total number of cache hits')
webres6_archive_total = Counter('webres6_archive_hits_total', 'Total number of archive hits', ['result'])
webres6_time_spent = Counter('webres6_time_spent_seconds_total', 'Time spent in different processing phases', ['phase'])
webres6_response_time = Histogram('webres6_response_time_seconds_total', 'Response time for checks performed', ['whois', 'screenshot'], buckets=(0.2, 0.5, 1, 2, 5, 10, 20, 30, 60, 90, 120, 150, 180))
webres6_whois_cache_size = Gauge('webres6_whois_cache_size_total', 'Number of entries in whois cache')
webres6_whois_cache_size.set_function(lambda: storage_manager.whois_cache_size() if storage_manager else 0)
webres6_dnsprobe_results_total = Counter('webres6_dnsprobe_results_total', 'Total number of DNSProbe results', ['rcode'])

# allow overrides in serverconfig directory)
sys.path.insert(0, srvconfig_dir)
from webres6_extension import check_extension_parameter, get_extensions, init_selenium_options, prepare_selenium_crawl, operate_selenium_crawl, cleanup_selenium_crawl, finalize_report, health_check

# load additional modules after setting up config and tracing
from webres6_storage import StorageManager, LocalStorageManager, ValkeyStorageManager, ValkeyFileHybridStorageManager, ValkeyS3HybridStorageManager, Scoreboard, export_scoreboard_entries, import_scoreboard_entries, export_archived_reports, import_archived_reports
from webres6_dnsprobe import DNSprobe
from webres6_whois import get_whois_info
from webres6_crawler import init_webdriver, crawl_page, load_public_suffix_list, take_screenshot, split_hostname, get_hostinfo, cleanup_crawl, check_selenium, add_url_blocklist


# declare global variables for storage manager and scoreboard, will be initialized later based on configuration
storage_manager = None
scoreboard = None

# configure DNSProbe
dnsprobe = None
if not enable_dnsprobe:
    dnsprobe = None
elif dnsprobe_api_url and dnsprobe_api_url.strip() != '':
    dnsprobe = DNSprobe(remote=dnsprobe_api_url)
else:
    dnsprobe = DNSprobe(local=True)

# helper function to check if an address is an IP address (IPv4 or IPv6)
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


@tracer.start_as_current_span("add_dnsprobe_info")
def add_dnsprobe_info(hosts, log_prefix=''):
    """ Adds DNSProbe information for each unique IP address in the hosts dictionary.
    """
    total = 0
    success = 0
    noerror = 0
    servfail = 0
    other_rcode = 0

    for hostname, info in hosts.items():
        total += 1
        dnsprobe_data = dnsprobe.res_v6only(hostname)
        webres6_dnsprobe_results_total.labels(rcode=dnsprobe_data.get('rcode', 'unknown')).inc()
        if dnsprobe_data.get('success', False):
            success += 1
            dnsprobe_data['ipv6_only_ready'] = True
        elif dnsprobe_data.get('rcode', '') == 'no error':
            noerror += 1
            dnsprobe_data['ipv6_only_ready'] = True
        elif dnsprobe_data.get('rcode', '') == 'serv fail':
            servfail += 1
            dnsprobe_data['ipv6_only_ready'] = False
        else:
            other_rcode += 1
            # inconclusive answer, don't set ipv6_only_ready flag
        info['dns'] = dnsprobe_data

    print(f"{log_prefix}dnsprobe lookups completed: {total} total, {noerror} no error, {success} success, {servfail} servfail, {other_rcode} inconclusive", file=sys.stderr)
    return total


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


@tracer.start_as_current_span("add_whois_info")
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


@tracer.start_as_current_span("crawl_and_analyze_url")
def crawl_and_analyze_url(url, wait, timeout, scoreboard_entry, ext,
                          screenshot_mode, lookup_whois,
                          report_id, report_node):
    """ Internal implementation of crawl_and_analyze_url with optional span parameter.
    """

    # initialize otel span
    span = trace.get_current_span()
    span.set_attributes({
        "webres6.url": url.geturl(),
        "webres6.wait_time": wait,
        "webres6.timeout": timeout,
        "webres6.screenshot_mode": screenshot_mode or "none",
        "webres6.whois_enabled": lookup_whois,
        "webres6.extension": ext or "none",
        "webres6.scoreboard_entry": scoreboard_entry,
    })

    # collect timing stats
    timings = {}
    ts = datetime.now(timezone.utc)
    last_ts = ts

    def push_timing(key):
        nonlocal last_ts
        nonlocal span
        now = datetime.now(timezone.utc)
        spent = (now - last_ts).total_seconds()
        timings[key] = spent
        webres6_time_spent.labels(phase=key).inc(spent)
        last_ts = now

    # init logging
    if not report_id:
        report_id = gen_report_id(url, wait, timeout, ext, screenshot_mode, lookup_whois, ts, report_node)
    span.set_attribute("webres6.report_id", report_id)
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
    span.set_attributes({
        "webres6.browser.name": browser_info.get('browserName', 'unknown'),
        "webres6.browser.version": browser_info.get('browserVersion', 'unknown'),
        "webres6.browser.platform": browser_info.get('platformName', 'unknown'),
        "webres6.browser.accept_insecure_certs": browser_info.get('acceptInsecureCerts', False),
    })

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
        add_dnsprobe_info(hosts, log_prefix=lp)
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
        span.set_attribute("webres6.ipv6_only_ready", True)
    else:
        webres6_tested_results.labels(result='not_ipv6_only_ready').inc()
        span.set_attribute("webres6.ipv6_only_ready", False)

    if http_score is not None:
        webres6_scores_total.labels(score_type='http').observe(http_score)
        span.set_attribute("webres6.http_score", http_score)
    if dns_score is not None:
        webres6_scores_total.labels(score_type='dns').observe(dns_score)
        span.set_attribute("webres6.dns_score", dns_score)
    if score is not None:
        webres6_scores_total.labels(score_type='overall').observe(score)
        span.set_attribute("webres6.overall_score", score)

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

    # initialize otel
    span = trace.get_current_span()

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
        span.add_event("webres6.cache_hit", {
            "webres6.cache_hit_type": type,
            "webres6.cache_age_seconds": cache_age.total_seconds(),
        })
        span.set_attribute("webres6.report_id", report_id)

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
    span.set_attribute("webres6.report_id", report_id)

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
        span.add_event("webres6.crawl_error", {"error_code": error_code})
        return json_result, error_code

    # Archive the result in storage
    archived = storage_manager.archive_result(report_id, json_result)
    span.add_event("webres6.crawl_success", attributes={"archived": archived})

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
        span.add_event("webres6.redirect_to_archive", {"report_id": report_id, "result_cache_ttl": result_cache_ttl})
        return redirect_to_report(report_id, result_cache_ttl, storage_manager)

    else:
        span.add_event("webres6.return_result_direct", {"report_id": report_id, "error_code": error_code})
        return json_result, error_code



##############################################################################
# flask app factory and helpers
##############################################################################

def validate_url(url):
    """Validate URL with security and format checks.

    Args:
        url: URL string to validate

    Returns:
        tuple: (parsed_url, error_message) where error_message is None on success
    """

    # Length check (prevent DoS)
    if len(url) > 2048:
        return None, 'URL too long (max 2048 characters)'

    # Parse URL
    try:
        parsed_url = urlparse(url)
    except Exception as e:
        return None, f'Invalid URL format: {e}'

    # Scheme validation
    if not parsed_url.scheme or parsed_url.scheme not in ['http', 'https']:
        return None, 'Invalid URL scheme. Only http:// and https:// are supported'

    # Netloc validation
    if not parsed_url.netloc:
        return None, 'Invalid URL: missing hostname'

    if parsed_url.netloc.startswith(':') or '//' in parsed_url.netloc:
        return None, 'Invalid URL: malformed hostname'

    # Extract hostname and port
    hostname = parsed_url.hostname

    # Port validation (urlparse.port raises ValueError for invalid ports)
    try:
        port = parsed_url.port
    except ValueError as e:
        return None, f'Invalid URL: {str(e)}'

    # Hostname validation
    if not hostname:
        return None, 'Invalid URL: missing hostname'

    # Check for spaces or control characters in hostname
    if any(c.isspace() or ord(c) < 32 for c in hostname):
        return None, 'Invalid URL: hostname contains invalid characters'

    # Port validation (additional range check if port is present)
    if port is not None:
        if port < 1 or port > 65535:
            return None, f'Invalid URL: port {port} out of range (1-65535)'

    return parsed_url, None


def check_auth(request):
    """ Check if the request is authorized.
    """
    auth = request.authorization
    if not admin_api_key or (auth and auth.password == admin_api_key) or request.args.get('key') == admin_api_key:
        return True
    return False


def check_component_health():
    """ Check health of all backend services (storage, DNS, selenium) and extensions.

    Returns:
        tuple: (status_dict, all_healthy)
    """
    ts = datetime.now(timezone.utc)
    status = {'ts': ts}
    lp = f"{int(ts.timestamp()):x}-health "
    all_healthy = True

    # Check storage availability
    if check_storage_health:
        try:
            if storage_manager:
                storage_manager.check_health()
                status['storage'] = 'ok'
            else:
                status['storage'] = 'not configured'
        except Exception as e:
            status['storage'] = f'error: {str(e)}'
            all_healthy = False

    # Check DNS probe availability
    if check_dnsprobe_health:
        if dnsprobe:
            try:
                ok, error = dnsprobe.ping()
                if ok:
                    status['dnsprobe'] = 'ok'
                else:
                    status['dnsprobe'] = f'error: {error}'
                    all_healthy = False
            except Exception as e:
                status['dnsprobe'] = f'error: {str(e)}'
                all_healthy = False
        else:
            status['dnsprobe'] = 'not configured'

    # Check selenium availability
    if check_selenium_health:
        selenium_ok,  status['selenium'] = check_selenium(log_prefix=lp)
        if not selenium_ok:
            all_healthy = False

    # check extensions health if needed
    extension_health_check = globals().get('health_check')
    if extension_health_check and callable(extension_health_check):
        if not extension_health_check(log_prefix=lp, status=status):
            all_healthy = False

    print(f"{lp}{'OK' if all_healthy else 'DEGRADED'} ({', '.join([f'{k}: {v}' for k, v in status.items() if k != 'ts'])})", file=sys.stderr)

    return status, all_healthy


def create_http_app():
    """ Common setup for Flask app instance, including instrumentation, endpoints, and configuration.

    Returns:
        Flask app instance
    """

    # Start a simple HTTP API server using Flask
    app = Flask(__name__, static_folder=app_home)
    app.config['JSON_AS_ASCII'] = False
    app.json_provider_class = FlaskJSONProvider
    app.json = app.json_provider_class(app)

    # Instrument Flask with OpenTelemetry
    if otel_enabled and tracer:
        FlaskInstrumentor().instrument_app(app)
        print("\tOpenTelemetry Flask instrumentation enabled", file=sys.stderr)

    # Create API endpoints
    print("creating endpoints:", file=sys.stderr)

    print("\t/healthz                      readiness endpoint (checks health of backend services storage, DNS, selenium)", file=sys.stderr)
    @app.route('/healthz', methods=['GET'])
    def health():
        status, all_healthy = check_component_health()
        if all_healthy:
            status['status'] = 'ok'
            return jsonify(status), 200
        else:
            status['status'] = 'degraded'
            return jsonify(status), 503
    
    print("\t/ping                         liveliness endpoint", file=sys.stderr)
    @app.route('/ping', methods=['GET'])
    def ping():
        return jsonify({'status': 'ok', 'ts': datetime.now(timezone.utc).isoformat()}), 200

    print("\t/metrics                      get Prometheus compatible metrics", file=sys.stderr)
    @app.route('/metrics', methods=['GET'])
    def metrics():
        if check_auth(request):
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
            return app.response_class(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)
        else:
            return app.response_class('Authentication required', mimetype='text/plain', status=401, headers={'WWW-Authenticate': 'Basic realm="webres6 admin"'})

    return app


def setup_res6_endpoints(app, srv_message=None, privacy_policy=None):
    """ Set up WebRes6 related endpoints.
    """

    print("\t/res6/ping                    liveliness endpoint", file=sys.stderr)
    @app.route('/res6/ping', methods=['GET'])
    def res6_ping():
        return jsonify({'status': 'ok', 'ts': datetime.now(timezone.utc).isoformat()}), 200

    print("\t/res6/$metadata               get OData metadata document", file=sys.stderr)
    @app.route('/res6/$metadata', methods=['GET'])
    def res6_metadata():
        return send_from_directory(app_home, 'webres6-api-metadata.xml', mimetype='application/xml')

    print("\t/res6/serverconfig            list available extensions, screenshot-modes, whois support, ...", file=sys.stderr)
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

    print("\t/res6/url(URL)                get JSON results for URL provided", file=sys.stderr)
    @app.route('/res6/url(<path:url>)', methods=['GET'])
    def res6_url(url):
        ts = datetime.now(timezone.utc)

        # parse url
        if not url:
            return jsonify({'error': 'URL parameter is required'}), 400

        parsed_url, error = validate_url(url)
        if error:
            print(f"ERROR: invalid URL provided: {url} --> {error}", file=sys.stderr)
            return jsonify({'error': error}), 400

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

    print("\t/res6/report/ID               get archived JSON results for report ID provided", file=sys.stderr)
    @app.route('/res6/report/<string:report_id>', methods=['GET'])
    def res6_report(report_id):
        # check record id - only allow alphanumeric characters and hyphens
        if not report_id.replace('-', '').isalnum() or len(report_id) > 255:
            return jsonify({'error': 'Invalid report ID.'}), 400
        return get_archived_report(report_id)

    if scoreboard:
        print("\t/res6/scoreboard              get current scoreboard entries", file=sys.stderr)
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

    if storage_manager and hasattr(storage_manager, 'can_persist') and storage_manager.can_persist():
        print("\t/admin/persist                persist local cache to disk", file=sys.stderr)
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
        print("\t/admin/expire                 expire local cache entries", file=sys.stderr)
        @app.route('/admin/expire', methods=['GET'])
        def admin_expire():
            if check_auth(request):
                result = storage_manager.expire()
                print(f"Expired {result} cache entries", file=sys.stderr)
                return jsonify({'status': 'ok', 'message': f'Expired {result} cache entries'}), 200
            else:
                return app.response_class('Authentication required', mimetype='text/plain', status=401, headers={'WWW-Authenticate': 'Basic realm="webres6 admin"'})

    if os.path.isdir(viewer_dir):
        print("\t/viewer/<path:file>           send viewer files", file=sys.stderr)
        @app.route('/viewer/<path:file>', methods=['GET'])
        def send_viewer_file(file):
            return send_from_directory(viewer_dir, file)

        print("\t/viewer/[#url:URL]            serve viewer.html as index", file=sys.stderr)
        print("\t/viewer/[#report:ID]          serve viewer.html as index", file=sys.stderr)
        @app.route('/viewer/', methods=['GET'])
        def viewer_index():
            return send_from_directory(viewer_dir, 'viewer.html')

        if debug_viewer:
            print("\t/.well-known/appspecific/com.chrome.devtools.json\n\t                              serve viewer debug info for Chrome DevTools", file=sys.stderr)
            @app.route('/.well-known/appspecific/com.chrome.devtools.json', methods=['GET'])
            def viewer_debug():
                return jsonify({
                    "workspace": {
                        "root": f"{viewer_dir}/",
                        "uuid": uuid.uuid4(),
                    }}), 200

        print("\t/                             redirect to /viewer", file=sys.stderr)
        @app.route('/', methods=['GET'])
        def index():
            return redirect('/viewer', code=302)


def setup_dnsprobe_endpoints(app):
    """ Set up DNSProbe related endpoints if DNSProbe is enabled and available.
    """
    print("\t/dnsprobe/ping                liveliness probe endpoint", file=sys.stderr)
    @app.route('/dnsprobe/ping', methods=['GET'])
    def dnsprobe_ping():
        return jsonify({'status': 'ok', 'ts': datetime.now(timezone.utc).isoformat()}), 200

    print("\t/dnsprobe/resolve6only(host)  resolve AAAA records for given hostname", file=sys.stderr)
    @app.route('/dnsprobe/resolve6only(<string:hostname>)', methods=['GET'])
    def resolve6only(hostname):
        result = dnsprobe.res_v6only(hostname)
        resp = jsonify(result)
        resp.headers['Cache-Control'] = f"public, max-age={dnsprobe.cache_ttl}"
        return resp, 200


def create_webres6_app():
    """ Start default HTTP API server serving the /res6/* and (if enabled) /dnsprobe/* endpoints.

    Returns:
        Flask app instance
    """

    # inialize storage manager
    global storage_manager
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
    global scoreboard
    if storage_manager.can_archive() and enable_scoreboard:
        scoreboard = Scoreboard(storage_manager=storage_manager)

    # Report whois configuration
    print(f"Whois lookups are {'enabled with TTL ' + str(whois_cache_ttl) + 's' if enable_whois else 'disabled'}.", file=sys.stderr)

    # Load URL blocklist if available
    _url_blocklist_file = os.path.join(srvconfig_dir, 'url-blocklist')
    if os.path.exists(_url_blocklist_file):
        with open(_url_blocklist_file) as f:
            url_blocklist = f.read().splitlines()
            print(f"Loaded URL blocklist with {len(url_blocklist)} entries from '{_url_blocklist_file}'", file=sys.stderr)
            add_url_blocklist(url_blocklist)

    # load public suffix list for domain parsing
    load_public_suffix_list(os.path.join(app_home, 'public_suffix_list.dat'))

    # Load privacy policy
    privacy_policy = None
    privacy_file = os.path.join(srvconfig_dir, 'PRIVACY')
    if os.path.exists(privacy_file):
        print(f"Loading privacy policy file '{privacy_file}'...", end='', file=sys.stderr)
        with open(privacy_file) as f:
            privacy_policy = f.read()
        print("done.", file=sys.stderr)

    # Load server message
    srv_message = None
    srv_message_file = os.path.join(srvconfig_dir, 'MESSAGE')
    if os.path.exists(srv_message_file):
        print(f"Loading server message file '{srv_message_file}'...", end='', file=sys.stderr)
        with open(srv_message_file) as f:
            srv_message = f.read()
        print("done.", file=sys.stderr)

    # configure component health checks to only check DNSProbe for this app
    global check_storage_health, check_dnsprobe_health, check_selenium_health
    check_storage_health = True
    check_dnsprobe_health = True
    check_selenium_health = True

    # create app and common endpoints
    app = create_http_app()

    # set up DNSProbe endpoints if enabled and not remote
    if dnsprobe and dnsprobe.is_local():
        setup_dnsprobe_endpoints(app)

    # set up main webres6 endpoints
    setup_res6_endpoints(app, srv_message=srv_message, privacy_policy=privacy_policy)

    return app


def create_dnsprobe_app():
    """ Start dnsprobe HTTP API server serving /dnsprobe/* endpoints only.

    Returns:
        Flask app instance
    """

    # Only start DNSProbe API if dnsprobe is configured and local
    if not dnsprobe or not dnsprobe.is_local():
        return None

    # configure component health checks to only check DNSProbe for this app
    global check_storage_health, check_dnsprobe_health, check_selenium_health
    check_storage_health = False
    check_dnsprobe_health = True
    check_selenium_health = False

    # create app and common endpoints
    app = create_http_app()

    # set up DNSProbe endpoints if enabled and not remote
    setup_dnsprobe_endpoints(app)

    return app


# signal handler for graceful shutdown
def signal_handler(sig, frame):
    print(f"Received signal {sig}, shutting down...", file=sys.stderr)
    if storage_manager and storage_manager.can_persist():
        print("Persisting local cache to disk...", file=sys.stderr)
        storage_manager.persist()
    if prometheus_mp_temp_dir:
        print(f"Removing temporary directory {prometheus_mp_temp_dir}", file=sys.stderr)
        rmtree(prometheus_mp_temp_dir)
    sys.exit(0)

# hadnle worker exit in gunicorn
def child_exit(server, worker):
    # tell prometheus client
    multiprocess.mark_process_dead(worker.pid)

# main entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="A small web service inspired by Paul Marks' IPvFoo that loads a website\n"\
            " and displays ip addresses it fetched resources from",
            epilog="For production use, consider running in gunicorn behind a reverse proxy.\n")
    parser.add_argument("--port", type=int, metavar='6400', default=6400, help="start a simple HTTP API server at given port")
    parser.add_argument("--debug", action="store_true", help="enable flask debugging output for the HTTP API server")
    parser.add_argument("--dnsprobe-only", action="store_true", help="start in DNSProbe-only mode, serving only the /dnsprobe/* endpoints")
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

    # set PROMETHEUS_MULTIPROC_DIR to temp dir if not set
    if not os.getenv('PROMETHEUS_MULTIPROC_DIR'):
        prometheus_mp_temp_dir = mkdtemp(prefix=f"webres6-{os.getpid()}-prometheus-")
        os.environ['PROMETHEUS_MULTIPROC_DIR'] = prometheus_mp_temp_dir
        print(f"Set PROMETHEUS_MULTIPROC_DIR to temporary directory {prometheus_mp_temp_dir}", file=sys.stderr)

    # create and run app
    if args.dnsprobe_only:
        app = create_dnsprobe_app()
    else:
        app = create_webres6_app()
    app.run(debug=debug_flask, host='::1', port=args.port, threaded=False)

# vim: set ts=4 sw=4 et:
# vim: set fileencoding=utf-8:
# vim: set filetype=python:
