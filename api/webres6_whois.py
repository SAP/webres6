#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
from datetime import datetime, timezone
from ipaddress import ip_network
from ipwhois import IPWhois
from prometheus_client import Counter

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.instrumentation.urllib import URLLibInstrumentor

# Get tracer instance
tracer = trace.get_tracer(__name__)
URLLibInstrumentor().instrument()

webres6_whois_lookups = Counter('webres6_whois_lookups_total', 'WHOIS lookups performed', ['type'])

@tracer.start_as_current_span("whois.lookup")
def get_whois_info(ip, local_cache, local_cache_lock, storage_manager, debug=False):
    """ Fetches WHOIS information for the given IP address using local and global caches.

    Args:
        ip (ipaddress.IPv4Address or ipaddress.IPv6Address): The IP address to look up

    Returns:
        dict: The WHOIS information for the IP address, or None if not found.
    """

    # otel tracing span attributes
    span = trace.get_current_span()
    span.set_attributes({
        "whois.ip": str(ip),
        "whois.ip_version": ip.version,
    })


    # helper functions for cache management and whois lookup
    def push_to_local_cache(whois_info):
        with local_cache_lock:
            try:
                for cidr in whois_info['network']['cidr'].split(','):
                    ipn = ip_network(cidr.strip())
                    local_cache[ip.version][ipn] = whois_info
            except (ValueError, KeyError) as e:
                print(f"\tWARNING: local cache push failed for whois info {whois_info}: {e}", file=sys.stderr)

    def lookup_local_cache(ip):
        with local_cache_lock:
            for network_cidr, cached_data in local_cache[ip.version].items():
                if ip in network_cidr:
                    if debug:
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
                print(f"\tWARNING: whois lookup failed for {ip}: no network CIDR found in whois result", file=sys.stderr)
                span.add_event("whois_lookup_failed", {"error": "no network CIDR in whois result"})
                return None

            whois_info = {
                'ts': datetime.now(timezone.utc),
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

            if debug:
                print(f"\twhois lookup for {ip}: {whois_info}", file=sys.stderr)

            return whois_info

        except Exception as e:
            print(f"\tWARNING: whois lookup failed for {ip}: {e}", file=sys.stderr)
            span.add_event("whois_lookup_failed", {"error": str(e)})
            return None


    # Check global cache (exact ip match) first
    # This also "warms up" the local cache for subsequent lookups 
    # of IPs from the same whois object
    if (whois_info := storage_manager.get_whois_cacheline(ip)):
        if debug:
            print(f"\twhois global cache hit for {ip}", file=sys.stderr)
        # Cache the result locally
        push_to_local_cache(whois_info)
        # store result
        webres6_whois_lookups.labels(type='cache-global').inc()
        span.set_attributes({
            "whois.source": 'global_cache',
            "whois.success": True
        })
        return whois_info, 'global_cache_hit'

    # Check if IP falls into any locally cached network afterwards
    elif (whois_info := lookup_local_cache(ip)):
        # Cache the result globally
        storage_manager.put_whois_cacheline(ip, whois_info)
        # store result
        webres6_whois_lookups.labels(type='cache-local').inc()
        span.set_attributes({
            "whois.source": 'local_cache',
            "whois.success": True
        })
        return whois_info, 'local_cache_hit'

    # finally do a real whois lookup
    elif (whois_info := lookup_whois(ip)):
        # Cache the result locally using network CIDR
        push_to_local_cache(whois_info)
        # Cache the result globally
        storage_manager.put_whois_cacheline(ip, whois_info)
        # store result
        webres6_whois_lookups.labels(type='whois-success').inc()
        span.set_attributes({
            "whois.source": 'whois_lookup',
            "whois.success": True
        })
        return whois_info, 'whois_lookup'
    else:
        # store result
        webres6_whois_lookups.labels(type='whois-fail').inc()
        span.set_attributes({
            "whois.source": 'whois_lookup',
            "whois.success": False
        })
        return None, 'whois_failed'
