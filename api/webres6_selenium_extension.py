#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import sys
from selenium.common.exceptions import WebDriverException

app_home         = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
extensions_dir   = os.path.join(app_home, 'extensions')

# Discover extensions available in the extensions directory
print(f"loading extensions from {extensions_dir}.", file=sys.stderr)
extensions = []
if os.path.exists(extensions_dir):
    for ext in os.listdir(extensions_dir):
        ext_path = os.path.join(extensions_dir, ext)
        if os.path.isfile(ext_path) and ext.endswith('.crx'):
            extensions.append(ext)
            print(f"\t{ext} (packed)", file=sys.stderr)


def get_selenium_extensions():
    """ Get the list of available selenium extensions.
        Returns:
                list of extension names to put in the UI
    """
    return extensions


def check_extension_parameter(extension):
    """ Check if the given extension parameter is valid.
        Args:
            extension (str): extension name to check
        Returns:
                tuple (bool, str): True if extension is valid, False otherwise; error message if invalid
    """
    if extension not in extensions:
        return False, f'Extension {extension} not found.'
    return True, ''


def init_selenium_options(options, extension=None, log_prefix=""):
    """ Initialize selenium options to load the given extension.
        Args:
            options: selenium webdriver options instance
            extension (str): extension name to load
            log_prefix (str): prefix for logging messages
        Returns:
                bool: True if extension was loaded successfully or no extension requested, False otherwise
    """
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


def prepare_selenium_crawl(driver, extension=None, log_prefix=""):
    """ Perform any preparation before driver.get(url) is called.
        Args:
            driver: selenium webdriver instance
            extension (str): extension name being used
            log_prefix (str): prefix for logging messages
        Returns:
                bool: True if preparation was successful, False otherwise
    """
    return True, ''


def operate_selenium_crawl(driver, url, extension=None, log_prefix=""):
    """ Perform any operations after driver.get(url) is called.
        Args:
            driver: selenium webdriver instance
            url (str): URL to crawl
            extension (str): extension name being used
            log_prefix (str): prefix for logging messages
        Returns:
                bool: True if operations were successful, False otherwise
    """
    return True, ''
