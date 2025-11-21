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
import flask
from flask import Flask, jsonify
import unbound

# config/flag variables
webres6_version  = "0.1.0"
app_home         = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
debug_unbound    = 'unbound'    in getenv("DEBUG", '').lower().split(',')
unbound_v6_conf  = getenv("UNBOUND_V6ONLY_CONF", os.path.join(app_home, "unbound.v6only.conf"))

# unbound context
unbound_v6ctx = unbound.ub_ctx()
unbound_v6ctx.debuglevel(2)
unbound_v6ctx.config(unbound_v6_conf)

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
    status, result = unbound_v6ctx.resolve(hostname, unbound.RR_TYPE_AAAA, unbound.RR_CLASS_IN)

    ts = datetime.now(timezone.utc)
    elapsed = (ts - stat).total_seconds()

    ips = []
    if status==0 and result.havedata:
        try:
            ips = [ip_address(raw) for raw in result.data.as_raw_data()]
        except ValueError:
            print(f"WARNING: could not parse resolved IP addresses for {hostname}", file=sys.stderr)

    print(f"{ts.isoformat()} res_v6only {hostname} elapsed={elapsed:.2f} status={status} rcode={result.rcode_str.replace(' ', '_')} {(('ips=['+' '.join([str(ip) for ip in ips])+']') if len(ips) >0 else '' )}", file=sys.stderr)

    result = {
        'hostname': hostname,
        'success': bool(status==0 and result.havedata),
        'rcode': result.rcode_str,
        'time_elapsed': elapsed,
        'ts': ts,
    }
    if len(ips)>0:
        result['aaaa_records'] = [str(ip) for ip in ips]

    return result


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
    def ping():
        return jsonify({'status': 'ok', 'ts': datetime.now(timezone.utc).isoformat()}), 200

    print("\t/dnsprobe/resolve6only(host)  resolve AAAA records for given hostname", file=sys.stderr)
    @app.route('/dnsprobe/resolve6only(<string:hostname>)', methods=['GET'])
    def resolve6only(hostname):
        result = res_v6only(hostname)
        return jsonify(result), 200 

    return app

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="A dns probe using unbound's python DNS library",
            epilog="For production use, consider running in gunicorn behind a reverse proxy.\n")
    parser.add_argument("--port", type=int, metavar='6453', help="start a simple HTTP API server at given port")
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
