#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# This webres6_extension module is just an empty template 

import sys

doh_template = "https://dns64.dns.google/dns-query{?dns}"

def get_extensions():
    return []

def check_extension_parameter(extension):
    if extension and extension != '':
        return False, f'No extensions supported in this configuration.'
    return True, ''

def init_selenium_options(options, extension=None, extension_data=None, log_prefix=""):
    print(f"{log_prefix}injecting DoH config for Google DNS into the browser", file=sys.stderr)
    local_state = {
        "dns_over_https.mode": "secure",
        "dns_over_https.templates": doh_template,
    }
    options.add_experimental_option('localState', local_state)
    return True

def prepare_selenium_crawl(driver, url, extension=None, extension_data=None, log_prefix=""):
    return True, ''

def operate_selenium_crawl(driver, url, extension=None, extension_data=None, log_prefix=""):
    return True, ''

def cleanup_selenium_crawl(driver, extension=None, extension_data=None, log_prefix=""):
    return

def finalize_report(report, extension=None, extension_data=None, log_prefix=""):
    report['doh_template'] = doh_template
    return

def health_check(log_prefix="", status={}):
    return True
