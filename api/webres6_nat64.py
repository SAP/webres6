#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
from os import getenv
from ipaddress import IPv6Address, ip_address, ip_network


# patch ip address object to support NAT64 detection
def _is_nat64(self):
    return self.version == 6 and any(self in net for net in self.nat64_networks)

def _nat64_extract_ipv4(self):
        if not self.is_nat64():
            return None
        low_order_bits = self._ip & 0xFFFFFFFF
        return ip_address(low_order_bits)

def _nat64_ipv6_to_str(self):
        high_order_bits = self._ip & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000
        low_order_bits = self._ip & 0xFFFFFFFF
        return self._string_from_ip_int(high_order_bits) + '.'.join(map(str, low_order_bits.to_bytes(4, 'big')))

def _nat64_aware__str__(self):
        ipv4_mapped = self.ipv4_mapped
        if ipv4_mapped is not None:
            ip_str = self._ipv4_mapped_ipv6_to_str()
            return ip_str + '%' + self._scope_id if self._scope_id else ip_str
        elif self.is_nat64():
            ip_str = self._nat64_ipv6_to_str()
            return ip_str + '%' + self._scope_id if self._scope_id else ip_str
        else:
            return super(IPv6Address, self).__str__()

IPv6Address.nat64_networks = [
    ip_network('64:ff9b::/96'), # well-known NAT64 prefix
    ]
IPv6Address.is_nat64 = _is_nat64
IPv6Address.nat64_extract_ipv4 = _nat64_extract_ipv4
IPv6Address._nat64_ipv6_to_str = _nat64_ipv6_to_str
IPv6Address.__str__ = _nat64_aware__str__

# load additional NAT64 prefixes from environment
for nat64 in [ip_network(p) for p in getenv("NAT64_PREFIXES", "").split(",") if p]:
    if nat64.version == 6 and nat64.prefixlen == 96:
        IPv6Address.nat64_networks.append(nat64)
    else:
        print(f"ERROR: Invalid NAT64 prefix {nat64}. Must be an IPv6 network with a /96 prefix length.", file=sys.stderr)
        sys.exit(2)


# vim: set ts=4 sw=4 et:
# vim: set fileencoding=utf-8:
# vim: set filetype=python:
