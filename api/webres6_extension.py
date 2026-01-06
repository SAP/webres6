#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# This webres6_extension module is just an empty template


def get_extensions():
    """ Get the list of options provided by this selenium extension module.
        Returns:
                A list of supported extension parameters to be displayed to the user.
    """
    return []


def check_extension_parameter(extension):
    """ Check if the given extension parameter is valid.
        Args:
            extension (str): extension parameter provided by the user
        Returns:
                tuple (bool, str): True if the parameter is acceptable, False otherwise; error message to display to the user
    """
    if extension != '':
        return False, f'No extensions supported in this configuration.'
    return True, ''


def init_selenium_options(options, extension=None, extension_data=None, log_prefix=""):
    """ Add selenium options before initializing the webdriver.
        Args:
            options: selenium webdriver options instance
            extension (str): extension parameter provided by the user
            extension_data (any): dictionary to store extension-specific per-crawl data
            log_prefix (str): prefix for logging messages
        Returns:
                bool: True if extension was loaded successfully or no extension requested, False otherwise
    """
    return True, ''


def prepare_selenium_crawl(driver, url, extension=None, extension_data=None, log_prefix=""):
    """ Perform any preparation before driver.get(url) is called.
        Args:
            driver: selenium webdriver instance
            url (str): URL that will be crawled
            extension (str): extension parameter provided by the user
            extension_data (any): dictionary to store extension-specific per-crawl data
            log_prefix (str): prefix for logging messages
        Returns:
                bool: True if preparation was successful, False otherwise
    """
    return True, ''


def operate_selenium_crawl(driver, url, extension=None, extension_data=None, log_prefix=""):
    """ Perform any operations after driver.get(url) is called.
        Args:
            driver: selenium webdriver instance
            url (str): URL to that was crawled
            extension (str): extension parameter provided by the user
            extension_data (any): dictionary to store extension-specific per-crawl data
            log_prefix (str): prefix for logging messages
        Returns:
                bool: True if operations were successful, False otherwise
    """
    return True, ''


def cleanup_selenium_crawl(driver, extension=None, extension_data=None, log_prefix=""):
    """ Perform any cleanup after the crawl is done.
        Args:
            driver: selenium webdriver instance
            extension (str): extension parameter provided by the user
            extension_data (any): dictionary to store extension-specific per-crawl data
            log_prefix (str): prefix for logging messages
    """
    return


def finalize_report(report, extension=None, extension_data=None, log_prefix=""):
    """ Modify the final report before it is returned to the user.
        Args:
            report (dict): the report dictionary to finalize
            extension (str): extension parameter provided by the user
            extension_data (any): dictionary to store extension-specific per-crawl data
            log_prefix (str): prefix for logging messages
    """
    return