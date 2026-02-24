#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# This webres6_extension module allows loading Chromium extensions 
# into the browser before crawling. It demonstrates how to extend webres6 with 
# custom Selenium functionality.

import sys
import json
from webres6_storage import DateTimeEncoder

def get_extensions():
    return []

def check_extension_parameter(extension):
    return False, 'No extensions available.'

def init_selenium_options(options, extension=None, extension_data=None, log_prefix=""):
    print(f"{log_prefix}selenium options extension", file=sys.stderr)
    return True

def prepare_selenium_crawl(driver, url, extension=None, extension_data=None, log_prefix=""):
    print(f"{log_prefix}selenium driver capabilities:", file=sys.stderr)
    for line in json.dumps(driver.capabilities, cls=DateTimeEncoder, indent=2, sort_keys=True).splitlines():
        print(f"{log_prefix}| {line}", file=sys.stderr)
    return True, ''

def operate_selenium_crawl(driver, url, extension=None, extension_data=None, log_prefix=""):
    print(f"{log_prefix}operate selenium extension", file=sys.stderr)
    return True, ''

def cleanup_selenium_crawl(driver, extension=None, extension_data=None, log_prefix=""):
    print(f"{log_prefix}cleanup selenium extension", file=sys.stderr)
    return

def finalize_report(report, extension=None, extension_data=None, log_prefix=""):
    print (f"{log_prefix}final report:", file=sys.stderr)
    for line in json.dumps(report, cls=DateTimeEncoder, indent=2, sort_keys=True).splitlines():
        print(f"{log_prefix}| {line}", file=sys.stderr)
    return

def health_check(log_prefix="", status={}):
    print(f"{log_prefix}health check:", file=sys.stderr)
    for line in json.dumps(status, cls=DateTimeEncoder, indent=2, sort_keys=True).splitlines():
        print(f"{log_prefix}| {line}", file=sys.stderr)
    return True
