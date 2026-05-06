#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import json
import os
from os import getenv
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from datetime import datetime, timezone, timedelta
from base64 import b64encode
from tempfile import NamedTemporaryFile
import urllib3

from opentelemetry import trace
from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor
from opentelemetry.trace import Status, StatusCode

# Initialize tracer and instrument urllib3 for automatic tracing of remote calls
tracer = trace.get_tracer(__name__) 
URLLib3Instrumentor().instrument()

try:
    import unbound
    unbound_available = True
except ImportError:
    unbound_available = False

# config/flag variables
app_home            = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
dnsprobe_cache_ttl  = int(getenv("DNSPROBE_CACHE_TTL", "60"))
debug_unbound       = 'unbound'    in getenv("DEBUG", '').lower().split(',')
# log algorithm choices by default – see https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-verbosity
unbound_debug_level = int(getenv("UNBOUND_DEBUG_LEVEL", "4")) 
unbound_v6_conf     = getenv("UNBOUND_V6ONLY_CONF", os.path.join(app_home, "unbound.v6only.conf"))

class DNSprobe:

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
            self.ping = self._ping_remote()
        elif unbound_available:
            print(f"DNSprobe local unbound using config file '{unbound_v6_conf}' with debug level {unbound_debug_level}", file=sys.stderr)
            self.is_local = lambda: True
            self.res_v6only = self._res_v6only_local
            self.ping = lambda: (True, None)  # local mode always available if unbound is present
        else:
            print("DNSprobe unavailable - unbound module not found", file=sys.stderr)
            self.is_local = lambda: False
            self.res_v6only = lambda self, hostname: {}
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
        def ping():
            request_url = f"{self.remote}/dnsprobe/ping"
            try:
                response = dnsprobe.request('GET', request_url, timeout=5)
                if response.status == 200:
                    return True, None
                else:
                    return False, f"HTTP {response.status}"
            except Exception as e:
                return False, str(e)
        return ping

    @tracer.start_as_current_span("dnsprobe.resolve6only_local")
    def _res_v6only_local(self, hostname):
        """ Resolve AAAA records for given hostname using unbound.
        Args:
            hostname (str): hostname to resolve
        Returns:
                dict with result information

        Warnings:
            This function depends on the unbound configuration file 'unbound.conf'
            being configured to prevent using IPv4 in the resolution process.
        """

        span = trace.get_current_span()
        stat = datetime.now(timezone.utc)

        # set up unbound context
        debug_temp_file = NamedTemporaryFile(mode='w+', delete=True, buffering=1)
        unbound_v6ctx = unbound.ub_ctx()
        unbound_v6ctx.config(unbound_v6_conf)
        unbound_v6ctx.set_option('logfile:', debug_temp_file.name)
        unbound_v6ctx.debuglevel(unbound_debug_level)
        span.add_event("unbound_initialized", {"unbound_config": unbound_v6_conf, "unbound_debug_level": unbound_debug_level})

        # do query and close context
        status, result = unbound_v6ctx.resolve(hostname, unbound.RR_TYPE_AAAA, unbound.RR_CLASS_IN)
        unbound_v6ctx.process()
        unbound_v6ctx = None
        rcode_str = result.rcode_str if result else unbound.ub_strerror(status)
        span.add_event("unbound_query_completed", {"unbound_status": status, "unbound_rcode": rcode_str})

        # record elapsed time 
        ts = datetime.now(timezone.utc)
        elapsed = (ts - stat).total_seconds()

        # prepare output information
        ips = []
        if status==0 and result.havedata:
            try:
                ips = [ip_address(raw) for raw in result.data.as_raw_data()]
            except ValueError:
                print(f"WARNING: could not parse resolved IP addresses for {hostname}", file=sys.stderr)

        # initialize result dict
        jsres = {
            'hostname': hostname,
            'success': bool(status==0 and result.havedata),
            'time_elapsed': elapsed,
            'ts': ts,
        }

        # check unbound debug log for additional information in case of SERVFAIL or if debugging is enabled
        if rcode_str in ['serv fail'] or debug_unbound:
            span.add_event("unbound_debug_log_parse_started")
            debug_temp_file.seek(0)
            debug_trace_stripped = ''
            for line in debug_temp_file:
                # check unbound log for nxdomain fallback limit exceeded message indicating
                # inconclusive results due to too many IPv4-only nameservers in the rotation
                if 'request has exceeded the maximum number of fallback nxdomain nameserver lookups' in line \
                or 'request has exceeded the maximum number of nxdomain nameserver lookups' in line:
                    rcode_str = 'nameserver nxdomain limit exceeded'
                # strip log
                parts = line.split(' ')
                if len(parts) > 3:
                    debug_trace_stripped += parts[0] + ' ' + ' '.join(parts[3:])
                else:
                    debug_trace_stripped += line
            jsres['unbound_trace'] = b64encode((debug_trace_stripped).encode('utf-8')).decode('ascii')
            span.add_event("unbound_debug_log_parse_completed")

        # set span attributes for observability
        span.set_attributes({
            "dnsprobe.success": jsres.get('success', False),
            "dnsprobe.rcode": rcode_str,
            "dnsprobe.aaaa_count": len(ips),
            "dnsprobe.elapsed": elapsed,
        })

        # log information to stderr
        print(f"{ts.isoformat()} res_v6only {hostname} elapsed={elapsed:.2f} status={status} rcode={rcode_str.replace(' ', '_')} {(('ips=['+' '.join([str(ip) for ip in ips])+']') if len(ips) >0 else '' )}", file=sys.stderr)
        if debug_unbound:
            print(f"{ts.isoformat()} res_v6only {hostname} >>> unbound debug output >>>", file=sys.stderr)
            debug_temp_file.seek(0)
            for line in debug_temp_file:
                print("\t" + line, end='', file=sys.stderr)
            print(f"\n{ts.isoformat()} res_v6only {hostname} <<< unbound debug output <<<", file=sys.stderr)

        # add additional information to result dict
        jsres['rcode'] = rcode_str
        if result:
            jsres['nxdomain'] = bool(result.nxdomain)
            jsres['canonical_name'] = result.canonname
        if len(ips)>0:
            jsres['aaaa_records'] = [str(ip) for ip in ips]

        return jsres


# vim: set ts=4 sw=4 et:
# vim: set fileencoding=utf-8:
# vim: set filetype=python:
