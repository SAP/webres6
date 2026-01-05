#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# This webres6_selenium_extension module is just an empty template 

import sys

def get_selenium_extensions():
    """ Get the list of options provided by this selenium extension module.
        Returns:
                list of extension names to put in the UI
    """
    return []


def check_extension_parameter(extension):
    """ Check if the given extension parameter is valid.
        Args:
            extension (str): extension name to check
        Returns:
                tuple (bool, str): True if extension is valid, False otherwise; error message if invalid
    """
    if extension and extension != '':
        return False, f'No extensions supported in this configuration.'
    return True, ''


def init_selenium_options(options, extension=None, log_prefix=""):
    """ Initialize selenium options 
        Args:
            options: selenium webdriver options instance
            extension (str): extension name to load
            log_prefix (str): prefix for logging messages
        Returns:
                bool: True if extension was loaded successfully or no extension requested, False otherwise
    """
    print(f"{log_prefix}injecting DoH config for Google DNS into the browser", file=sys.stderr)
    local_state = {
        "dns_over_https.mode": "secure",
        "dns_over_https.templates": "https://dns64.dns.google/dns-query{?dns}",
    }
    options.add_experimental_option('localState', local_state)
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


def cleanup_selenium_extension(driver, extension=None, log_prefix=""):
    """ Perform any cleanup after the crawl is done.
        Args:
            driver: selenium webdriver instance
            extension (str): extension name being used
            log_prefix (str): prefix for logging messages
    """
    return