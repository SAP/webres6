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
executes them. They cover the full live path the mocked unit tests cannot:

- TestLiveCrawl         — the crawler primitives: init_webdriver -> crawl_page ->
                          get_hostinfo, asserting the Happy Eyeballs net-log is
                          captured and analysed.
- TestCrawlAndAnalyze   — the API orchestrator crawl_and_analyze_url end to end
                          WITHOUT storage, dnsprobe or whois, asserting the
                          assembled report JSON.

Run them with a local headless Chrome:

    WEBRES6_INTEGRATION=1 ./run_tests.sh -i
    WEBRES6_INTEGRATION=1 pytest test_webres6_integration.py -v

or against a remote Selenium grid (a dedicated variable, NOT SELENIUM_REMOTE_URL,
so these tests are immune to the env other test modules set for their mocks):

    WEBRES6_INTEGRATION=1 WEBRES6_INTEGRATION_REMOTE_URL=https://user:pass@grid/wd/hub \\
        pytest test_webres6_integration.py -v

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

_SKIP_REASON = "live Selenium integration test — set WEBRES6_INTEGRATION=1 to run (needs a browser and network)"


def _configure_integration_selenium(webres6_crawler):
    """Pin the crawler's Selenium target for the live tests.

    Other test modules set SELENIUM_REMOTE_URL in os.environ for their mocks, which
    leaks into webres6_crawler.selenium_remote (read at import) and would send these
    live tests at a non-existent grid. So we drive the target explicitly from a
    dedicated WEBRES6_INTEGRATION_REMOTE_URL (empty/unset => local Chrome), ignoring
    whatever SELENIUM_REMOTE_URL happens to hold, and default to headless.
    """
    webres6_crawler.selenium_remote = os.getenv("WEBRES6_INTEGRATION_REMOTE_URL") or None
    if os.getenv("HEADLESS_SELENIUM", "1").lower() not in ("0", "false", "no", ""):
        webres6_crawler.headless_selenium = True


@unittest.skipUnless(INTEGRATION_ENABLED, _SKIP_REASON)
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
        _configure_integration_selenium(webres6_crawler)

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


@unittest.skipUnless(INTEGRATION_ENABLED, _SKIP_REASON)
class TestCrawlAndAnalyze(unittest.TestCase):
    """Drive the API orchestrator crawl_and_analyze_url against a live browser,
    WITHOUT storage, dnsprobe or whois, and assert on the assembled report.

    Isolation is achieved by construction, not by mocking: crawl_and_analyze_url
    never touches the storage manager (only the caching wrapper does); dnsprobe is
    gated on the module global ``dnsprobe`` which stays None because init_dnsprobe()
    is never called; and whois is gated on lookup_whois, which we pass as False.
    """

    api = None
    crawler = None
    report = None
    status = None
    _saved = None

    @classmethod
    def setUpClass(cls):
        import webres6_crawler
        import webres6_api
        cls.crawler = webres6_crawler
        cls.api = webres6_api
        _configure_integration_selenium(webres6_crawler)

        # Force the excluded dependencies off deterministically, regardless of what
        # other test modules (e.g. the app factory in test_webres6_api) already
        # initialised in this process: dnsprobe=None makes crawl_and_analyze_url skip
        # the `if dnsprobe:` branch, and storage_manager=None proves the call never
        # touches storage (any access would raise). Restored in tearDownClass.
        cls._saved = (webres6_api.dnsprobe, webres6_api.storage_manager)
        webres6_api.dnsprobe = None
        webres6_api.storage_manager = None

        report, status = webres6_api.crawl_and_analyze_url(
            urlparse(INTEGRATION_URL),
            wait=2, timeout=30,
            scoreboard_entry=False,
            ext=None,
            screenshot_mode=None,
            lookup_whois=False,
            report_id=None,
            report_node='itest',
        )
        cls.report, cls.status = report, status

    @classmethod
    def tearDownClass(cls):
        if cls._saved is not None and cls.api is not None:
            cls.api.dnsprobe, cls.api.storage_manager = cls._saved
            cls._saved = None

    def test_status_ok(self):
        self.assertEqual(self.status, 200)
        self.assertNotIn('error', self.report, f"crawl reported an error: {self.report.get('error')}")

    def test_report_metadata(self):
        self.assertEqual(self.report['webres6_version'], self.api.webres6_version)
        self.assertIn('ID', self.report)
        self.assertIn(urlparse(INTEGRATION_URL).hostname, self.report['url'])
        self.assertIsInstance(self.report['ipv6_only_ready'], bool)
        self.assertFalse(self.report['scoreboard_entry'], "scoreboard_entry should reflect the False we passed")

    def test_hosts_in_report(self):
        hosts = self.report['hosts']
        self.assertIsInstance(hosts, dict)
        self.assertGreater(len(hosts), 0, "expected at least one host in the report")
        main = urlparse(INTEGRATION_URL).hostname
        self.assertIn(main, hosts, f"main host {main} missing from report hosts {list(hosts)}")
        entry = hosts[main]
        self.assertIn('happy_eyeballs', entry)
        self.assertIn('ips', entry)
        self.assertIsInstance(entry['urls'], list)

    def test_happy_eyeballs_in_report(self):
        for name, entry in self.report['hosts'].items():
            he = entry['happy_eyeballs']
            self.assertIsNotNone(he, f"no happy_eyeballs for {name}")
            self.assertIn('attempts', he)
            self.assertIsInstance(he['ipv4_succeeded'], bool)
            self.assertIsInstance(he['ipv6_succeeded'], bool)

    def test_connectivity_detected(self):
        detected = any(
            e['happy_eyeballs']['ipv4_succeeded'] or e['happy_eyeballs']['ipv6_succeeded']
            for e in self.report['hosts'].values()
        )
        self.assertTrue(detected, "no host showed a successful IPv4 or IPv6 connection")

    def test_dnsprobe_not_run(self):
        """dnsprobe disabled -> no host carries dns info and there is no DNS score."""
        self.assertIsNone(self.api.dnsprobe)
        for name, entry in self.report['hosts'].items():
            self.assertIsNone(entry['dns'], f"{name} carries dns info but dnsprobe was disabled")
        self.assertIsNone(self.report.get('ipv6_only_dns_score'), "DNS score present without dnsprobe")

    def test_whois_not_run(self):
        """whois disabled -> every per-ip entry carries whois None."""
        for name, entry in self.report['hosts'].items():
            for ipstr, ipinfo in entry['ips'].items():
                self.assertIsNone(ipinfo['whois'], f"{name}/{ipstr} carries whois but whois was disabled")

    def test_storage_not_used(self):
        """The report was assembled with storage_manager forced to None, so a 200
        result proves crawl_and_analyze_url has no storage dependency."""
        self.assertIsNone(self.api.storage_manager)
        self.assertEqual(self.status, 200)


if __name__ == '__main__':
    unittest.main()
