#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Unit tests for webres6_nat64.py

Tests the NAT64 detection monkey-patch on IPv6Address:
is_nat64(), nat64_extract_ipv4(), and the custom __str__().
"""

import unittest
from ipaddress import IPv6Address, ip_address, ip_network


import webres6_nat64  # noqa: F401 — activates the monkey-patch


WELL_KNOWN_PREFIX = ip_network('64:ff9b::/96')

# 64:ff9b::1.2.3.4
NAT64_ADDR = IPv6Address('64:ff9b::102:304')
# plain global unicast
PLAIN_ADDR = IPv6Address('2001:db8::1')
# IPv4-mapped ::ffff:1.2.3.4
IPV4_MAPPED = IPv6Address('::ffff:1.2.3.4')
# loopback
LOOPBACK = IPv6Address('::1')


class TestIsNat64(unittest.TestCase):

    def test_well_known_nat64_prefix(self):
        self.assertTrue(NAT64_ADDR.is_nat64())

    def test_plain_ipv6_is_not_nat64(self):
        self.assertFalse(PLAIN_ADDR.is_nat64())

    def test_ipv4_mapped_is_not_nat64(self):
        self.assertFalse(IPV4_MAPPED.is_nat64())

    def test_loopback_is_not_nat64(self):
        self.assertFalse(LOOPBACK.is_nat64())

    def test_boundary_first_address_in_prefix(self):
        self.assertTrue(IPv6Address('64:ff9b::0.0.0.0').is_nat64())

    def test_boundary_last_address_in_prefix(self):
        self.assertTrue(IPv6Address('64:ff9b::255.255.255.255').is_nat64())

    def test_address_just_outside_prefix(self):
        # 64:ff9b:0:1:: is outside 64:ff9b::/96
        self.assertFalse(IPv6Address('64:ff9b:0:1::').is_nat64())


class TestNat64ExtractIpv4(unittest.TestCase):

    def test_extracts_embedded_ipv4(self):
        result = NAT64_ADDR.nat64_extract_ipv4()
        self.assertEqual(result, ip_address('1.2.3.4'))

    def test_non_nat64_returns_none(self):
        self.assertIsNone(PLAIN_ADDR.nat64_extract_ipv4())

    def test_loopback_returns_none(self):
        self.assertIsNone(LOOPBACK.nat64_extract_ipv4())

    def test_extract_all_zeros(self):
        addr = IPv6Address('64:ff9b::0.0.0.0')
        self.assertEqual(addr.nat64_extract_ipv4(), ip_address('0.0.0.0'))

    def test_extract_broadcast(self):
        addr = IPv6Address('64:ff9b::255.255.255.255')
        self.assertEqual(addr.nat64_extract_ipv4(), ip_address('255.255.255.255'))


class TestNat64AwareStr(unittest.TestCase):

    def test_nat64_str_shows_embedded_ipv4(self):
        s = str(NAT64_ADDR)
        self.assertIn('1.2.3.4', s)

    def test_plain_ipv6_str_unchanged(self):
        self.assertEqual(str(PLAIN_ADDR), '2001:db8::1')

    def test_loopback_str_unchanged(self):
        self.assertEqual(str(LOOPBACK), '::1')

    def test_ipv4_mapped_str_unchanged(self):
        # IPv4-mapped has its own existing __str__ path; must not regress
        self.assertIn('1.2.3.4', str(IPV4_MAPPED))


class TestCustomNat64Prefix(unittest.TestCase):

    def setUp(self):
        self._orig = list(IPv6Address.nat64_networks)

    def tearDown(self):
        IPv6Address.nat64_networks = self._orig

    def test_custom_prefix_detected(self):
        custom = ip_network('64:ff9b:1::/96')
        IPv6Address.nat64_networks.append(custom)
        addr = IPv6Address('64:ff9b:1::1.2.3.4')
        self.assertTrue(addr.is_nat64())

    def test_custom_prefix_extract(self):
        custom = ip_network('64:ff9b:1::/96')
        IPv6Address.nat64_networks.append(custom)
        addr = IPv6Address('64:ff9b:1::1.2.3.4')
        self.assertEqual(addr.nat64_extract_ipv4(), ip_address('1.2.3.4'))

    def test_original_prefix_still_works_after_adding_custom(self):
        custom = ip_network('64:ff9b:1::/96')
        IPv6Address.nat64_networks.append(custom)
        self.assertTrue(NAT64_ADDR.is_nat64())


if __name__ == '__main__':
    unittest.main()
