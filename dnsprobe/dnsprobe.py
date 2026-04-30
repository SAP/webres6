#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import argparse
import json
import os
from os import getenv
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from datetime import datetime, timezone, timedelta
from time import sleep
from base64 import b64encode
from tempfile import NamedTemporaryFile
import flask
from flask import Flask, jsonify
import unbound

# config/flag variables
webres6_version  = "1.4.0"
app_home            = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
debug_unbound       = 'unbound'    in getenv("DEBUG", '').lower().split(',')
debug_flask         = 'flask'      in getenv("DEBUG", '').lower().split(',')
unbound_v6_conf     = getenv("UNBOUND_V6ONLY_CONF", os.path.join(app_home, "unbound.v6only.conf"))
# log algorithm choices by default – see https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-verbosity
unbound_debug_level = int(getenv("UNBOUND_DEBUG_LEVEL", "4")) 
cache_ttl           = int(getenv("DNSPROBE_CACHE_TTL", "60"))

# custom json provider
class FlaskJSONProvider(flask.json.provider.DefaultJSONProvider):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def res_v6only(hostname):
    """ Resolve AAAA records for given hostname using unbound.
    Args:
        hostname (str): hostname to resolve
    Returns:
            dict with result information

    Warnings:
        This function depends on the unbound configuration file 'unbound.conf'
        being configured to prevent using IPv4 in the resolution process.
    """

    stat = datetime.now(timezone.utc)

    # set up unbound context
    debug_temp_file = NamedTemporaryFile(mode='w+', delete=True, buffering=1)
    unbound_v6ctx = unbound.ub_ctx()
    unbound_v6ctx.config(unbound_v6_conf)
    unbound_v6ctx.set_option('logfile:', debug_temp_file.name)
    unbound_v6ctx.debuglevel(unbound_debug_level)

    # do query and close context
    status, result = unbound_v6ctx.resolve(hostname, unbound.RR_TYPE_AAAA, unbound.RR_CLASS_IN)
    unbound_v6ctx.process()
    unbound_v6ctx = None

    # record elapsed time 
    ts = datetime.now(timezone.utc)
    elapsed = (ts - stat).total_seconds()

    # prepare output information
    rcode_str = result.rcode_str if result else unbound.ub_strerror(status)
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

def create_http_app():
    """ Start HTTP API server to serve host information.

    All api endpoints are created here.

    Returns:
        Flask app instance
    """

    # Start a simple HTTP API server using Flask
    app = Flask(__name__, static_folder=app_home)
    app.config['RESTFUL_JSON'] = {'ensure_ascii': False}
    app.json_provider_class = FlaskJSONProvider
    app.json = app.json_provider_class(app)

    print("creating endpoints:", file=sys.stderr)

    print("\t/ping                         liveliness probe endpoint", file=sys.stderr)
    @app.route('/ping', methods=['GET'])
    @app.route('/dnsprobe/ping', methods=['GET'])
    def ping():
        return jsonify({'status': 'ok', 'ts': datetime.now(timezone.utc).isoformat()}), 200

    print("\t/dnsprobe/resolve6only(host)  resolve AAAA records for given hostname", file=sys.stderr)
    @app.route('/dnsprobe/resolve6only(<string:hostname>)', methods=['GET'])
    def resolve6only(hostname):
        result = res_v6only(hostname)
        resp = jsonify(result)
        resp.headers['Cache-Control'] = f"public, max-age={cache_ttl}"
        return resp, 200

    print("\t/healthz                      check health of services", file=sys.stderr)
    @app.route('/healthz', methods=['GET'])
    def health():
        result = res_v6only('www.google.com')
        if not result['success']:
            return jsonify({'status': 'error', 'ts': datetime.now(timezone.utc).isoformat(), 'details': result}), 503
        return jsonify({'status': 'ok', 'ts': datetime.now(timezone.utc).isoformat()}), 200

    return app

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="A dns probe using unbound's python DNS library",
            epilog="For production use, consider running in gunicorn behind a reverse proxy.\n")
    parser.add_argument("--port", type=int, default='6453', help="start a simple HTTP API server at given port (default: 6453)")
    parser.add_argument("--debug", action="store_true", help="enable flask debugging output for the HTTP API server")
    args = parser.parse_args()

    # Process store-only arguments
    if args.debug:
        debug_flask = True
        debug_unbound = True
        print("Debugging mode is ON. This will print a lot of information to stderr.", file=sys.stderr)


    # Check if URL is provided and valid
    print(f"Starting HTTP API server on port {args.port}", file=sys.stderr)
    app = create_http_app()
    app.run(debug=debug_flask, host='::1', port=args.port, threaded=False)


# vim: set ts=4 sw=4 et:
# vim: set fileencoding=utf-8:
# vim: set filetype=python:
