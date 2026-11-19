#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Unit tests for webres6_crawler.py

Tests the pure-logic helpers that don't require a live Selenium session.
"""

import os
import tempfile
import unittest
from ipaddress import ip_address
from unittest import mock

import webres6_nat64  # noqa: F401 — monkey-patches IPv6Address.is_nat64 used by ip_family
import webres6_crawler
from selenium.webdriver.remote.client_config import AuthType
from webres6_crawler import build_selenium_client_config, split_hostname, ip_family


class TestIpFamily(unittest.TestCase):

    def test_ipv4(self):
        self.assertEqual(ip_family(ip_address('192.0.2.1')), 'IPv4')

    def test_ipv6(self):
        self.assertEqual(ip_family(ip_address('2001:db8::1')), 'IPv6')

    def test_nat64(self):
        self.assertEqual(ip_family(ip_address('64:ff9b::192.0.2.1')), 'NAT64')

    def test_ipv4_mapped(self):
        self.assertEqual(ip_family(ip_address('::ffff:192.0.2.1')), 'IPv4_Mapped')


class TestSplitHostname(unittest.TestCase):

    def test_simple(self):
        local, domain = split_hostname('www.example.com')
        self.assertEqual(local, 'www.')
        self.assertEqual(domain, 'example.com')

    def test_subdomain(self):
        local, domain = split_hostname('api.staging.example.com')
        self.assertEqual(local, 'api.staging.')
        self.assertEqual(domain, 'example.com')

    def test_no_subdomain(self):
        local, domain = split_hostname('example.com')
        self.assertEqual(local, '')
        self.assertEqual(domain, 'example.com')


class TestBuildSeleniumClientConfig(unittest.TestCase):
    """Covers the per-connection ClientConfig builder for both auth modes."""

    REMOTE = 'http://hub:4444/wd/hub'

    def _set(self, **kwargs):
        """Patch webres6_crawler module globals for the duration of the test."""
        for name, value in kwargs.items():
            patcher = mock.patch.object(webres6_crawler, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _token_file(self, contents):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f:
            f.write(contents)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def test_local_no_remote_returns_none(self):
        self._set(selenium_remote=None)
        self.assertEqual(build_selenium_client_config(), (None, None))

    def test_basic_defaults_to_admin(self):
        self._set(selenium_remote=self.REMOTE, selenium_auth_mode='basic',
                  selenium_username=None, selenium_password=None)
        cfg, err = build_selenium_client_config()
        self.assertIsNone(err)
        self.assertEqual(cfg.auth_type, AuthType.BASIC)
        self.assertEqual(cfg.username, 'admin')
        self.assertEqual(cfg.password, 'admin')

    def test_basic_uses_configured_credentials(self):
        self._set(selenium_remote=self.REMOTE, selenium_auth_mode='basic',
                  selenium_username='user', selenium_password='pass')
        cfg, err = build_selenium_client_config()
        self.assertIsNone(err)
        self.assertEqual(cfg.username, 'user')
        self.assertEqual(cfg.password, 'pass')

    def test_bearer_reads_and_strips_token(self):
        path = self._token_file('  tok-123\n')
        self._set(selenium_remote=self.REMOTE, selenium_auth_mode='bearer',
                  selenium_token_file=path)
        cfg, err = build_selenium_client_config()
        self.assertIsNone(err)
        self.assertEqual(cfg.auth_type, AuthType.BEARER)
        self.assertEqual(cfg.token, 'tok-123')

    def test_bearer_missing_file_returns_error(self):
        self._set(selenium_remote=self.REMOTE, selenium_auth_mode='bearer',
                  selenium_token_file='/nonexistent/token')
        cfg, err = build_selenium_client_config()
        self.assertIsNone(cfg)
        self.assertIn('Could not read', err)

    def test_bearer_empty_file_returns_error(self):
        path = self._token_file('   \n')
        self._set(selenium_remote=self.REMOTE, selenium_auth_mode='bearer',
                  selenium_token_file=path)
        cfg, err = build_selenium_client_config()
        self.assertIsNone(cfg)
        self.assertIn('empty', err)


if __name__ == '__main__':
    unittest.main()
