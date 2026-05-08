#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import threading
import multiprocessing
import concurrent.futures
import importlib.util
import os
from os import getenv
from datetime import datetime
import urllib3

from opentelemetry import trace
from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor
from opentelemetry.trace import Status, StatusCode

# Initialize tracer and instrument urllib3 for automatic tracing of remote calls
tracer = trace.get_tracer(__name__)
URLLib3Instrumentor().instrument()

unbound_available = importlib.util.find_spec('unbound') is not None

from prometheus_client import Gauge as _Gauge
_dnsprobe_jobs = _Gauge('webres6_dnsprobe_jobs_total', 'DNS probe jobs running/queued', ['state'])

# config/flag variables
app_home            = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
dnsprobe_cache_ttl  = int(getenv("DNSPROBE_CACHE_TTL", "60"))
dnsprobe_workers    = int(getenv("DNSPROBE_WORKERS", "4"))
dnsprobe_timeout    = int(getenv("DNSPROBE_TIMEOUT", "30"))
debug_unbound       = 'unbound'    in getenv("DEBUG", '').lower().split(',')
# log algorithm choices by default – see https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-verbosity
unbound_debug_level = int(getenv("UNBOUND_DEBUG_LEVEL", "4"))
unbound_v6_conf     = getenv("UNBOUND_V6ONLY_CONF", os.path.join(app_home, "unbound.v6only.conf"))

##############################################################################
# helpers to run unbound resolution in a subprocess and to track worker pool
##############################################################################

def _res_v6only_subprocess(hostname, conf, debug_level, debug):
    """Resolve AAAA records using a private ub_ctx in an isolated subprocess.

    Runs in a spawned worker process so no ub_ctx state is shared between
    concurrent callers. All arguments are plain values; the return value is a
    plain dict so both are picklable across the process boundary.
    """
    import unbound  # imported here because workers are spawned fresh
    from tempfile import NamedTemporaryFile
    from datetime import datetime, timezone
    from ipaddress import ip_address
    from base64 import b64encode

    stat = datetime.now(timezone.utc)
    debug_temp_file = NamedTemporaryFile(mode='w+', delete=True, buffering=1)

    unbound_v6ctx = unbound.ub_ctx()
    unbound_v6ctx.set_option('logfile:', '/dev/null')
    unbound_v6ctx.config(conf)
    unbound_v6ctx.set_option('logfile:', debug_temp_file.name)
    unbound_v6ctx.debuglevel(debug_level)

    status, result = unbound_v6ctx.resolve(hostname, unbound.RR_TYPE_AAAA, unbound.RR_CLASS_IN)
    unbound_v6ctx.wait()
    unbound_v6ctx.set_option('logfile:', '/dev/null')
    unbound_v6ctx = None

    rcode_str = result.rcode_str if result else unbound.ub_strerror(status)
    ts = datetime.now(timezone.utc)
    elapsed = (ts - stat).total_seconds()

    ips = []
    if status == 0 and result.havedata:
        try:
            ips = [ip_address(raw) for raw in result.data.as_raw_data()]
        except ValueError:
            print(f"WARNING: could not parse resolved IP addresses for {hostname}", file=sys.stderr)

    jsres = {
        'hostname': hostname,
        'success': bool(status == 0 and result.havedata),
        'time_elapsed': elapsed,
        'ts': ts,
    }

    if rcode_str in ['serv fail'] or debug:
        debug_temp_file.seek(0)
        debug_trace_stripped = ''
        for line in debug_temp_file:
            if 'request has exceeded the maximum number of fallback nxdomain nameserver lookups' in line \
            or 'request has exceeded the maximum number of nxdomain nameserver lookups' in line:
                rcode_str = 'nameserver nxdomain limit exceeded'
            parts = line.split(' ')
            if len(parts) > 3:
                debug_trace_stripped += parts[0] + ' ' + ' '.join(parts[3:])
            else:
                debug_trace_stripped += line
        jsres['unbound_trace'] = b64encode(debug_trace_stripped.encode('utf-8')).decode('ascii')

    if debug:
        print(f"_res_v6only_subprocess {ts.isoformat()} {hostname} >>> unbound debug output >>>", file=sys.stderr)
        debug_temp_file.seek(0)
        for line in debug_temp_file:
            print("\t" + line, end='', file=sys.stderr)
        print(f"\n{ts.isoformat()} _res_v6only_subprocess {hostname} <<< unbound debug output <<<", file=sys.stderr)

    jsres['rcode'] = rcode_str
    if result:
        jsres['nxdomain'] = bool(result.nxdomain)
        jsres['canonical_name'] = result.canonname
    if ips:
        jsres['aaaa_records'] = [str(ip) for ip in ips]

    return jsres


class _JobMetrics:
    """Tracks running/queued/idle state derived from a single in-flight counter.

    ProcessPoolExecutor dispatches tasks to worker processes eagerly, so:
      running = min(in_flight, capacity)
      queued  = max(0, in_flight - capacity)
      idle    = max(0, capacity - in_flight)
    All three labels are updated atomically under a lock.
    """

    def __init__(self, capacity):
        self._capacity = capacity
        self._in_flight = 0
        self._lock = threading.Lock()
        _dnsprobe_jobs.labels(state='running').set(0)
        _dnsprobe_jobs.labels(state='queued').set(0)

    def on_submit(self):
        with self._lock:
            self._in_flight += 1
            self._update()

    def on_done(self):
        with self._lock:
            self._in_flight -= 1
            self._update()

    def _update(self):
        cap = self._capacity
        n = self._in_flight
        _dnsprobe_jobs.labels(state='running').set(min(n, cap))
        _dnsprobe_jobs.labels(state='queued').set(max(0, n - cap))


##############################################################################
# DNSProbe class with remote and local resolution implementations
##############################################################################

class DNSprobe:
    """DNSProbe to check IPv6-only readiness of a host. It supports remote HTTP and local unbound-based resolution."""

    def __init__(self, remote=None, local=False, cache_ttl=dnsprobe_cache_ttl):
        self.remote = remote
        self.local = local
        self.cache_ttl = cache_ttl

        if self.remote:
            print(f"DNSProbe API URL is set to {self.remote}.", file=sys.stderr)
            self.remote_pool = urllib3.PoolManager(
                maxsize=10, block=True,
                timeout=urllib3.Timeout(connect=5.0, total=15.0), retries=False,
            )
            self.is_local = lambda: False
            self.res_v6only = self._res_v6only_remote
            self.ping = self._ping_remote
        elif unbound_available:
            print(f"DNSprobe local unbound using config file '{unbound_v6_conf}' with debug level {unbound_debug_level} ({dnsprobe_workers} workers)", file=sys.stderr)
            mp_ctx = multiprocessing.get_context('spawn')
            self._executor = concurrent.futures.ProcessPoolExecutor(
                max_workers=dnsprobe_workers, mp_context=mp_ctx, 
            )
            self._job_metrics = _JobMetrics(dnsprobe_workers)
            self.is_local = lambda: True
            self.res_v6only = self._res_v6only_local
            self.ping = lambda: (True, None)  # local mode always available if unbound is present
        else:
            print("DNSprobe unavailable - unbound module not found", file=sys.stderr)
            self.is_local = lambda: False
            self.res_v6only = lambda _: {}
            self.ping = lambda: (False, "unbound module not found")

    @tracer.start_as_current_span("dnsprobe.resolve6only_remote")
    def _res_v6only_remote(self, hostname):
        span = trace.get_current_span()
        request_url = f"{self.remote}/dnsprobe/resolve6only({hostname})"
        try:
            response = self.remote_pool.request('GET', request_url, timeout=10)
            if response.status == 200:
                dnsprobe_data = response.json()
                dnsprobe_data['ts'] = datetime.fromisoformat(dnsprobe_data['ts'])
                span.set_attributes({
                    "dnsprobe.success": dnsprobe_data.get('success', False),
                    "dnsprobe.rcode": dnsprobe_data.get('rcode', 'unknown'),
                    "dnsprobe.aaaa_count": len(dnsprobe_data.get('aaaa_records', [])),
                    "dnsprobe.elapsed": dnsprobe_data.get('time_elapsed', -1),
                })
                return dnsprobe_data
            else:
                span.set_status(trace.Status(StatusCode.ERROR, f"HTTP {response.status}"))
                print(f"{log_prefix}WARNING: dnsprobe lookup failed for {hostname}: GET {request_url} => {response.status}", file=sys.stderr)
                return {}
        except Exception as e:
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, f"Exception during DNSProbe lookup: {str(e)}"))
            print(f"{log_prefix}WARNING: dnsprobe lookup failed for {hostname}: {e}", file=sys.stderr)
            return {}

    @tracer.start_as_current_span("dnsprobe.ping_remote")
    def _ping_remote(self):
        print("Pinging DNSProbe API...", file=sys.stderr)
        request_url = f"{self.remote}/dnsprobe/ping"
        try:
            response = self.remote_pool.request('GET', request_url, timeout=5)
            if response.status == 200:
                return True, None
            else:
                return False, f"HTTP {response.status}"
        except Exception as e:
            return False, str(e)

    @tracer.start_as_current_span("dnsprobe.resolve6only_local")
    def _res_v6only_local(self, hostname):
        span = trace.get_current_span()
        self._job_metrics.on_submit()
        future = self._executor.submit(
            _res_v6only_subprocess,
            hostname, unbound_v6_conf, unbound_debug_level, debug_unbound
        )
        future.add_done_callback(lambda _: self._job_metrics.on_done())
        jsres = future.result(timeout=dnsprobe_timeout)
        span.set_attributes({
            "dnsprobe.success": jsres.get('success', False),
            "dnsprobe.rcode": jsres.get('rcode', 'unknown'),
            "dnsprobe.aaaa_count": len(jsres.get('aaaa_records', [])),
            "dnsprobe.elapsed": jsres.get('time_elapsed', -1),
        })
        return jsres


# vim: set ts=4 sw=4 et:
# vim: set fileencoding=utf-8:
# vim: set filetype=python:
