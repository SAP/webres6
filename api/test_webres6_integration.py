#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Optional integration tests that drive a REAL Selenium/Chrome browser.

These are opt-in: the whole module is skipped unless WEBRES6_INTEGRATION is set,
so the network-less GitHub Actions run (and a plain ``./run_tests.sh``) never
executes them. They cover the full live crawl path that the mocked unit tests
cannot — init_webdriver -> crawl_page -> get_hostinfo -> analyze_happy_eyeballs —
and in particular verify that Chrome's Happy Eyeballs v3 net-log actually flows
through the performance log into the per-host ``happy_eyeballs`` summary.

Run them with a local headless Chrome:

    WEBRES6_INTEGRATION=1 ./run_tests.sh -i
    WEBRES6_INTEGRATION=1 pytest test_webres6_integration.py -v

or against a remote Selenium grid:

    SELENIUM_REMOTE_URL=https://user:pass@grid/wd/hub \\
        WEBRES6_INTEGRATION=1 pytest test_webres6_integration.py -v

Target URL defaults to https://www.google.com; override with
WEBRES6_INTEGRATION_URL. Set HEADLESS_SELENIUM=0 to watch the browser.
"""

import os
import unittest
from urllib.parse import urlparse

import webres6_nat64  # noqa: F401 — NAT64 monkey-patch relied on across the crawler

INTEGRATION_ENABLED = bool(os.getenv("WEBRES6_INTEGRATION"))
INTEGRATION_URL = os.getenv("WEBRES6_INTEGRATION_URL", "https://www.google.com")
V4_LIKE = {'IPv4', 'NAT64', 'IPv4_Mapped'}


@unittest.skipUnless(
    INTEGRATION_ENABLED,
    "live Selenium integration test — set WEBRES6_INTEGRATION=1 to run (needs a browser and network)",
)
class TestLiveCrawl(unittest.TestCase):
    """Run one real crawl in setUpClass and assert on the shared result.

    A single browser session is reused across every test method so Chrome is
    launched only once. Browser startup problems skip (environment not capable);
    a crawl that reaches the browser but fails is a hard error.
    """

    crawler = None
    driver = None
    hosts = None
    netlog_events = None

    @classmethod
    def setUpClass(cls):
        import webres6_crawler
        cls.crawler = webres6_crawler

        # default to headless so the suite needs no display; HEADLESS_SELENIUM=0 overrides
        if os.getenv("HEADLESS_SELENIUM", "1").lower() not in ("0", "false", "no", ""):
            webres6_crawler.headless_selenium = True

        result = webres6_crawler.init_webdriver(log_prefix="[itest] ")
        driver, err = result if isinstance(result, tuple) else (result, "init_webdriver returned no driver")
        if driver is None:
            raise unittest.SkipTest(f"could not start Selenium browser: {err}")
        cls.driver = driver

        ok, err = webres6_crawler.crawl_page(
            INTEGRATION_URL, driver=driver, wait=2, timeout=30, log_prefix="[itest] "
        )
        if not ok:
            raise AssertionError(f"crawl_page({INTEGRATION_URL!r}) failed: {err}")

        cls.hosts, cls.netlog_events = webres6_crawler.get_hostinfo(driver, log_prefix="[itest] ")
        if cls.hosts is None:
            raise AssertionError("get_hostinfo returned no hosts (performance-log fetch failed)")

    @classmethod
    def tearDownClass(cls):
        if cls.driver is not None and cls.crawler is not None:
            cls.crawler.cleanup_crawl(cls.driver, log_prefix="[itest] ")
            cls.driver = None

    def test_hosts_captured(self):
        self.assertIsInstance(self.hosts, dict)
        self.assertGreater(len(self.hosts), 0, "expected at least one host from a real crawl")

    def test_main_host_present(self):
        main = urlparse(INTEGRATION_URL).hostname
        self.assertIn(main, self.hosts, f"main host {main} missing from {list(self.hosts)}")

    def test_host_structure(self):
        """Every host carries the ips shape get_hostinfo builds: ip -> {(proto, sec): [urls]}."""
        for name, info in self.hosts.items():
            self.assertIn('ips', info, f"{name} has no 'ips'")
            self.assertIsInstance(info['ips'], dict)
            for ip, proto_map in info['ips'].items():
                self.assertTrue(hasattr(ip, 'version'), f"{name}: ip key {ip!r} was not parsed")
                self.assertIsInstance(proto_map, dict)
                for proto_key, urls in proto_map.items():
                    self.assertEqual(len(proto_key), 2, f"{name}: protocol key {proto_key!r} not a (proto, sec) pair")
                    self.assertIsInstance(urls, list)
                    self.assertGreater(len(urls), 0)

    def test_netlog_events_flowing(self):
        """The crucial plumbing check: traceCategories='netlog' + HappyEyeballsV3 must
        deliver net-log trace events through the performance log, including the
        HTTP_STREAM_POOL attempt-manager events the HE analysis is built on."""
        self.assertIsInstance(self.netlog_events, list)
        self.assertGreater(len(self.netlog_events), 0, "no netlog trace events captured from the performance log")
        names = {e.get('name', '') for e in self.netlog_events}
        self.assertTrue(
            any(n.startswith('HTTP_STREAM_POOL') for n in names),
            f"no HappyEyeballs HTTP_STREAM_POOL events in netlog; saw {sorted(names)[:20]}",
        )

    def test_happy_eyeballs_summary_present(self):
        for name, info in self.hosts.items():
            he = info.get('happy_eyeballs')
            self.assertIsNotNone(he, f"no happy_eyeballs summary for {name}")
            self.assertIn('attempts', he)
            self.assertIn('ipv4_succeeded', he)
            self.assertIn('ipv6_succeeded', he)
            self.assertIsInstance(he['attempts'], list)
            self.assertIsInstance(he['ipv4_succeeded'], bool)
            self.assertIsInstance(he['ipv6_succeeded'], bool)

    def test_some_connectivity_detected(self):
        """A reachable real page must leave at least one host with an established family."""
        detected = any(
            info['happy_eyeballs']['ipv4_succeeded'] or info['happy_eyeballs']['ipv6_succeeded']
            for info in self.hosts.values()
        )
        self.assertTrue(detected, "no host showed a successful IPv4 or IPv6 connection")

    def test_attempt_records_well_formed(self):
        """Any captured attempt must carry a family + protocol and a coherent outcome."""
        for name, info in self.hosts.items():
            for a in info['happy_eyeballs']['attempts']:
                self.assertIn(a['protocol'], ('TCP', 'QUIC'), f"{name}: bad protocol {a['protocol']!r}")
                self.assertIn(a['family'], V4_LIKE | {'IPv6', 'Unknown', None}, f"{name}: bad family {a['family']!r}")
                if a['succeeded'] is not None:
                    self.assertIsInstance(a['succeeded'], bool)
                    # a decided outcome implies the END event was seen, so end_us is set
                    self.assertIsNotNone(a['end_us'], f"{name}: decided attempt has no end_us")


if __name__ == '__main__':
    unittest.main()
