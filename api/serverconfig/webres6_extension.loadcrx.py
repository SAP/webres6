#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# This webres6_extension module allows loading Chromium extensions 
# into the browser before crawling. It demonstrates how to extend webres6 with 
# custom Selenium functionality.

import os
import sys
from selenium.common.exceptions import WebDriverException

extensions_dir   = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))

# Discover chromium extensions available in the serverconfig directory
print(f"loading extensions from {extensions_dir}.", file=sys.stderr)
extensions = []
if os.path.exists(extensions_dir):
    for ext in os.listdir(extensions_dir):
        ext_path = os.path.join(extensions_dir, ext)
        if os.path.isfile(ext_path) and ext.endswith('.crx'):
            extensions.append(ext)
            print(f"\t{ext} (packed)", file=sys.stderr)

def get_extensions():
    return extensions

def check_extension_parameter(extension):
    if extension not in extensions:
        return False, f'Extension {extension} not found.'
    return True, ''

def init_selenium_options(options, extension=None, extension_data=None, log_prefix=""):
    if extension:
        ext = os.path.normpath(os.path.join(extensions_dir, os.path.basename(extension)))
        if not ext.startswith(extensions_dir):
            print(f"{log_prefix}ERROR: requested extension {ext} is outside of extensions directory", file=sys.stderr)
            driver.quit()
            return False
        elif os.path.exists(ext):
            print(f"{log_prefix}adding requested extension {ext} to browser", file=sys.stderr)
            try:
                options.add_extension(ext)
                print(f"{log_prefix}marked extension {ext} for loading", file=sys.stderr)
            except WebDriverException as e:
                print(f"{log_prefix}ERROR: failed adding extension {ext} to browser: {e}", file=sys.stderr)
                driver.quit()
                return False
        else:
            print(f"{log_prefix}ERROR: extension {ext} does not exist", file=sys.stderr)
            driver.quit()
            return False
    return True

def prepare_selenium_crawl(driver, url, extension=None, extension_data=None, log_prefix=""):
    return True, ''

def operate_selenium_crawl(driver, url, extension=None, extension_data=None, log_prefix=""):
    return True, ''

def cleanup_selenium_crawl(driver, extension=None, extension_data=None, log_prefix=""):
    return

def finalize_report(report, extension=None, extension_data=None, log_prefix=""):
    return

def health_check(log_prefix="", status={}):
    return True
