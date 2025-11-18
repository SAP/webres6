#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

from os import environ
import sys
import argparse
import json
from ipaddress import ip_address, ip_network
import urllib3 
from urllib.parse import urlparse, quote_plus as encodeURIComponent

api_url = environ.get('WEBRES6_API_URL', 'http://localhost:6400/res6')
http = urllib3.PoolManager(happy_eyeballs=True)

# Define ANSI color codes for terminal output
color = {
    'reset': "\033[0m",
    'local_part': "\033[90m",        # dark gray
    'domain_part': "\033[0m",        # reset
    'proto': "\033[90m",             # dark gray
    'highlight_local': "\033[36m",   # dark cyan
    'highlight_domain': "\033[96m",  # bright cyan
    'asn': "\033[35m",               # purple
    'ipv6': "\033[32m",              # green
    'ipv4': "\033[31m",              # red
    'success': "\033[32m",           # green
    'fail': "\033[31m"               # red
}

def fetch_res6_json(api_url, url, ext=None, screenshot='none', whois=False, wait=None, timeout=None):
    params = {}
    if whois:
        params['whois'] = "true"
    if ext:
        params['ext'] = ext
    if wait:
        params['wait'] = wait
    if screenshot:
        params['screenshot'] = screenshot
    if timeout:
        params['timeout'] = timeout
    r = http.request("GET", f"{api_url}/url({encodeURIComponent(url)})", fields=params)
    return r.json()

def fetch_res6_serverconfig(api_url):
    r = http.request("GET", f"{api_url}/serverconfig")
    return r.json()

def gen_fancy_hostlist(hosts, original_host=None, show_proto=False, 
                         show_asn=True, show_asd=True, show_prfxinfo=False):
    """
    Generates a table of host names and IP addresses from the hosts dictionary.
    IPv4 addresses are colored red, IPv6 addresses are colored green.
    """

    def host_sort_key(item):
        hostname = item[0]
        parts = hostname.rsplit('.', 2)
        # Sort by main domain and then prefix
        # e.g. www.example.com -> ('example', 'com', 'www')
        return (parts[1], parts[2], parts[0]) if len(parts) > 2 else (hostname, '', '')

    def get_prefixinfo(whois_info, ipstr):
        nonlocal show_prfxinfo
        if show_prfxinfo and whois_info and whois_info.get('network', None):
            try:
                ip = ip_address(ipstr.replace("64:ff9b::", ""))
                netname = whois_info['network'].get('name', "n/a")
                for nc in whois_info['network'].get('cidr', "").split(","):
                    if ip in ip_network(nc):
                        return '/' + nc.split('/')[1] + ' ' + netname
                return ""
            except Exception as e:
                print(f"get_prefixinfo: {e}")
                return ""
        else:
            return ""

    if not hosts:
        yield("No hosts found.")
        return

    # record column widths
    max_ip_length = 24
    max_domain_length = 12
    max_local_length = 12
    max_tp_length = 0
    max_sp_length = 0
    max_asn_length = 6 if show_asn else 0
    max_asd_length = 8 if show_asd else 0

    # Prepare the output lines
    lines = []
    for hostname, info in sorted(hosts.items(), key=host_sort_key):
        # split hostname for nicer output
        domain_part = info.get('domain_part')
        max_domain_length = max(max_domain_length, len(domain_part))
        local_part = info.get('local_part')
        max_local_length = max(max_local_length, len(local_part))
        # format IPs
        for ip in sorted(info.get('ips').keys()):
            ip_str = str(ip)
            ip_prfx = get_prefixinfo(info['ips'][ip].get('whois'), ip)
            max_ip_length = max(max_ip_length, len(ip_str+ip_prfx))
            if info['ips'][ip]['address_family'] == 'IPv6':
                ip_color = color['ipv6']
            else:
                ip_color = color['ipv4']

            asn = ""
            if show_asn and info['ips'][ip].get('whois'):
                asn = info['ips'][ip]['whois'].get('asn', "") + " "
                max_asn_length = max(max_asn_length, len(asn))

            asd = ""
            if show_asd and info['ips'][ip].get('whois'):
                asd = info['ips'][ip]['whois'].get('asn_description', "") + " "
                max_asd_length = max(max_asd_length, len(asd))

            if show_proto:
                for tp, sp in info['ips'][ip]['transport']:
                    sp = "/"+sp if sp else ""
                    max_tp_length = max(max_tp_length, len(tp))
                    max_sp_length = max(max_sp_length, len(sp))
                    lines.append((hostname, local_part, domain_part, tp, sp, asn, asd, ip_str, ip_prfx, ip_color))
                    # Clear same parts to make the table clearer
                    local_part = ""
                    domain_part = ""
                    asn = ""
                    asd = ""
                    ip_str = ""
                    ip_prfx = ""
            else:
                lines.append((hostname, local_part, domain_part, "", "", asn, asd, ip_str, ip_prfx, ip_color))
                # Clear same parts to make the table clearer
                local_part = ""
                domain_part = ""

    rule_length = max_local_length + max_domain_length + max_tp_length + max_sp_length + max_asn_length + max_asd_length + max_ip_length + 2
    max_proto_length = max_tp_length + max_sp_length
    max_asx_length = max_asn_length + max_asd_length
    yield(rule_length)
    yield("-" * rule_length)
    yield(f"{'Hostname':<{max_local_length+max_domain_length}} {'Proto':<{max_proto_length}.{max_proto_length}} {'AS':<{max_asx_length}.{max_asx_length}}{'IP Address':<{max_ip_length}}")
    yield("-" * rule_length)
    for hostname, local_part, domain_part, tp, sp, asn, asd, ip, prfx, ip_color in lines:
        # Format for length
        local_part  = f"{local_part:>{max_local_length}}"
        domain_part = f"{domain_part:<{max_domain_length}}"
        tp          = f"{tp:>{max_tp_length}}"
        sp          = f"{sp:<{max_sp_length}}"
        asn         = f"{asn:>{max_asn_length}}"
        asd         = f"{asd:<{max_asd_length}}"
        if hostname == original_host:
            yield(f"{color['highlight_local']}{local_part}{color['reset']}"
                  f"{color['highlight_domain']}{domain_part}{color['reset']} "
                  f"{color['proto']}{tp}{sp}{color['reset']} "
                  f"{color['asn']}{asn}{asd}{color['reset']}"
                  f"{ip_color}{ip}{color['asn']}{prfx}{color['reset']}")
        else:
            yield(f"{color['local_part']}{local_part}{color['reset']}"
                  f"{color['domain_part']}{domain_part}{color['reset']} "
                  f"{color['proto']}{tp}{sp}{color['reset']} "
                  f"{color['asn']}{asn}{asd}{color['reset']}"
                  f"{ip_color}{ip}{color['asn']}{prfx}{color['reset']}")
    yield("-" * rule_length)


def display_image_in_iterm2(image_data, filename="screenshot", width=None):
    """Display an image using the imgcat protocol.
 
    Args:
        image_data (str): Base64 encoded image data
        filename (str): Name to display for the image
        with (int): Width of the image in characters (optional)
    """
    # image protocol escape sequences
    if environ.get('TERM', '').startswith("screen") or environ.get('TERM', '').startswith("tmux"):
        OSC = '\033Ptmux;\033\033]'
        ST = '\007\033\\'
    else:
        OSC = '\033]'
        ST = '\007'

    # Split image data into chunks of 200 characters
    chunks = [image_data[i:i+200] for i in range(0, len(image_data), 200)]
    if len(chunks) > 1:
        print("Trying to display screenshot in terminal:", file=sys.stderr)
        print(f"{OSC}1337;MultipartFile=name={filename};{'width='+str(width)+';' if width else ''}inline=1{ST}")
        for chunk in chunks:
            print(f"{OSC}1337;FilePart={chunk}{ST}")
        print(f"{OSC}1337;FileEnd{ST}")
    else:
        print(f"{OSC}1337;File=name={filename};{'width='+str(width)+';' if width else ''}inline=1:{image_data}{ST}\n")


def print_timings(timings):
    print("Time spent:", end=' ')
    for key in ['crawl', 'screenshot', 'extract', 'whois']:
        if key in timings:
            print(f"{key}={timings[key]:.2f}s", end=' ')
    print()


def display_results(res, args):
    """Display the results from the API response"""
    if res.get('ts'):
        print(f"Timestamp: {res['ts']}")

    if res.get('url'):
        print(f"URL: {res['url']}")

    if http_score := res.get('ipv6_only_http_score'): 
        print(f"IPv6-Only HTTP score: {http_score*100:.1f}%")

    # generate output
    output_lines = gen_fancy_hostlist(res.get('hosts', {}), original_host=urlparse(args.url).hostname,
                                    show_proto=not(args.hide_proto), show_prfxinfo = args.show_network,
                                    show_asn=args.show_asn, show_asd=args.show_asd)
    width = next(output_lines)  # first line is rule length

    # print screenshot if available
    if args.display_screenshot and res.get('screenshot'):
        display_image_in_iterm2(res['screenshot'], filename="screenshot.png", width=width)
    elif res.get('screenshot'):
        print("Got a screenshot - you may use '-o >(jq -r .screenshot | base64 -d > screenshot.png)' to save the image", file=sys.stderr)

    # print host list
    for output_line in output_lines:
        print(output_line)

    # print timings
    if res.get('timings'):
        print_timings(res['timings'])

    # print verdict
    ipv6_only_ready = res.get('ipv6_only_ready')
    if ipv6_only_ready:
        print(f"Conclusion: {color['success']}SUCCESS{color['reset']} - No hosts with IPv4 addresses found.")
    else:
        print(f"Conclusion: {color['fail']}NOT THERE YET{color['reset']} - At least one host has only IPv4 addresses.")


def main():
    parser = argparse.ArgumentParser(
        description=" IPv6 Web Resource Checker CLI client. Uses /res6 api and renders host info locally.")
    parser.add_argument("--api", default=api_url, help=f"Base API endpoint overriding WEBRES6_API_URL env (default: {api_url})")
    parser.add_argument("--serverconfig", action="store_true", help="Show server configuration - incl. supported extensions and screenshot modes - and exit")
    parser.add_argument("-r", "--read-json", type=argparse.FileType('r', encoding='utf-8'), metavar="FILE.json", help="Read JSON input from file ignoring URL argument")
    parser.add_argument("-o", "--save-json", action="append", type=argparse.FileType('w', encoding='utf-8'), metavar="FILE.json", help="Save JSON output to file")
    parser.add_argument("-w", "--wait", type=float, help="Wait time for page settle (seconds)")
    parser.add_argument("-t", "--timeout", type=float, help="Timeout for page load (seconds)")
    parser.add_argument("-e", "--extension", type=str, help="Extension to use (must be available on server)")
    parser.add_argument("-s", "--screenshot", type=str, default=None, metavar="MODE", help="Request a screenshot from the server (default: none)")
    parser.add_argument("-S", "--display-screenshot", type=str, default=None, metavar="MODE", help="Display screenshot in terminal (implies --screenshot)")
    parser.add_argument("-m", "--hide-proto", action="store_true", help="Hide protocol columns")
    parser.add_argument("-a", "--show-asn", action="store_true", help="Show AS Number column")
    parser.add_argument("-A", "--show-asd", action="store_true", help="Show AS Description column")
    parser.add_argument("-n", "--show-network", action="store_true", help="Show whois network name")
    parser.add_argument("-q", "--quiet", action="store_true", help="Do not print the host list to stdout")
    parser.add_argument("url", nargs='?', help="URL to analyze (will be passed to /res6)")
    args = parser.parse_args()

    # check arguments
    if not args.read_json and not args.serverconfig and not args.url:
        print("ERROR: URL argument is required.", file=sys.stderr)
        sys.exit(2)

    # implied arguments
    if args.display_screenshot and not args.screenshot:
        args.screenshot = args.display_screenshot

    # gather server config if requested (and exit)
    if args.serverconfig:
        try:
            res = fetch_res6_serverconfig(args.api)
            json.dump(res, sys.stdout, sort_keys=False, indent=4, default=str)
            sys.exit(0)
        except Exception as e:
            print(f"ERROR: Failed to fetch server config from {args.api}: {e}", file=sys.stderr)
            sys.exit(2)
    
    # gather results from JSON or server
    if args.read_json:
        print(f"Reading JSON input from: {args.read_json.name}", file=sys.stderr)
        try:
            res = json.load(args.read_json)
        except Exception as e:
            print(f"ERROR: Failed to read JSON from {args.read_json.name}: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        print(f"API endpoint: {args.api}", file=sys.stderr)
        print(f"Fetching results for: {args.url} ...", file=sys.stderr, end=' ', flush=True)
        try:
            res = fetch_res6_json(args.api, args.url, ext=args.extension, screenshot=args.screenshot,
                                  whois=(args.show_asn or args.show_asd or args.show_network),
                                  wait=args.wait, timeout=args.timeout)
            print("done", file=sys.stderr)
        except Exception as e:
            print(f"ERROR: Failed to fetch from {args.api}: {e}", file=sys.stderr)
            sys.exit(2)

    # save JSON if requested
    if args.save_json:
        for f in args.save_json:
            json.dump(res, f)
            print(f"JSON dump saved to: {f}", file=sys.stderr)

    # display results unless quiet
    if not args.quiet:
        display_results(res, args)

    # exit code 0 if ipv6-only ready, 1 otherwise
    if res.get('ipv6_only_ready'):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
