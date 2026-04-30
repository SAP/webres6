#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Unit tests for webres6-api.py

These tests cover the main API endpoints and functionality.
They use mocks for external services (Selenium, DNSProbe) to allow
testing in isolation.
"""

import unittest
import json
import os
import sys
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address

# Add parent directory to path to import the API module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Mock environment variables before importing the API
test_env = {
    'SELENIUM_REMOTE_URL': 'http://localhost:4444/wd/hub',
    'DNSPROBE_API_URL': 'https://webres6.dev.sap/',
    'VALKEY_URL': '',
    'ENABLE_WHOIS': 'false',
    'ENABLE_SCOREBOARD': 'false',
}

for key, value in test_env.items():
    os.environ[key] = value

# Import the API module (rename from webres6-api.py to webres6_api for import)
import importlib.util
spec = importlib.util.spec_from_file_location("webres6_api", "webres6-api.py")
webres6_api = importlib.util.module_from_spec(spec)
sys.modules['webres6_api'] = webres6_api
spec.loader.exec_module(webres6_api)

from webres6_api import create_http_app, check_component_health, gen_report_id, gen_json, get_ipv6_only_score


class TestWebres6APIEndpoints(unittest.TestCase):
    """Test API endpoints"""

    @classmethod
    def setUpClass(cls):
        """Set up Flask test client"""
        cls.app = create_http_app()
        cls.client = cls.app.test_client()
        cls.app.config['TESTING'] = True

    def test_ping_endpoint(self):
        """Test /ping endpoint returns OK"""
        response = self.client.get('/ping')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'ok')
        self.assertIn('ts', data)

    def test_res6_ping_endpoint(self):
        """Test /res6/ping endpoint returns OK"""
        response = self.client.get('/res6/ping')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'ok')
        self.assertIn('ts', data)

    @patch('webres6_api.check_component_health')
    def test_healthz_endpoint_healthy(self, mock_health):
        """Test /healthz endpoint when all services are healthy"""
        mock_health.return_value = ({
            'ts': datetime.now(timezone.utc),
            'storage': 'ok',
            'dnsprobe': 'ok',
            'selenium': 'ok',
        }, True)

        response = self.client.get('/healthz')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'ok')
        self.assertEqual(data['storage'], 'ok')
        self.assertEqual(data['dnsprobe'], 'ok')
        self.assertEqual(data['selenium'], 'ok')

    @patch('webres6_api.check_component_health')
    def test_healthz_endpoint_degraded(self, mock_health):
        """Test /healthz endpoint when a service is down"""
        mock_health.return_value = ({
            'ts': datetime.now(timezone.utc),
            'storage': 'ok',
            'dnsprobe': 'error: connection refused',
            'selenium': 'ok',
        }, False)

        response = self.client.get('/healthz')
        self.assertEqual(response.status_code, 503)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'degraded')
        self.assertIn('error', data['dnsprobe'])

    def test_serverconfig_endpoint(self):
        """Test /res6/serverconfig endpoint"""
        response = self.client.get('/res6/serverconfig')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Check required fields
        self.assertIn('version', data)
        self.assertIn('extensions', data)
        self.assertIn('screenshot_modes', data)
        self.assertIn('whois', data)
        self.assertIn('archive', data)
        self.assertIn('scoreboard', data)
        self.assertIn('max_wait', data)

        # Check types
        self.assertIsInstance(data['extensions'], list)
        self.assertIsInstance(data['screenshot_modes'], list)
        self.assertIsInstance(data['whois'], bool)
        self.assertIsInstance(data['archive'], bool)

        # Check cache control header
        self.assertIn('Cache-Control', response.headers)
        self.assertIn('max-age=900', response.headers['Cache-Control'])

    def test_metadata_endpoint(self):
        """Test /res6/$metadata endpoint"""
        response = self.client.get('/res6/$metadata')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/xml; charset=utf-8')

    def test_url_endpoint_missing_parameter(self):
        """Test /res6/url endpoint with missing URL"""
        response = self.client.get('/res6/url()')
        self.assertEqual(response.status_code, 404)

    def test_url_endpoint_invalid_url(self):
        """Test /res6/url endpoint with invalid URL"""
        # Test with URL that has malformed netloc
        response = self.client.get('/res6/url(://invalid)')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)

    def test_url_endpoint_invalid_scheme(self):
        """Test /res6/url endpoint with invalid scheme"""
        response = self.client.get('/res6/url(ftp://example.com)')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('scheme', data['error'].lower())

    def test_url_endpoint_url_too_long(self):
        """Test /res6/url endpoint with URL that is too long"""
        long_url = 'https://example.com/' + 'a' * 3000
        response = self.client.get(f'/res6/url({long_url})')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('too long', data['error'].lower())

    def test_url_endpoint_invalid_port(self):
        """Test /res6/url endpoint with invalid port"""
        response = self.client.get('/res6/url(https://example.com:99999)')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('port', data['error'].lower())

    def test_url_endpoint_hostname_with_spaces(self):
        """Test /res6/url endpoint with hostname containing spaces"""
        response = self.client.get('/res6/url(https://example .com)')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('invalid characters', data['error'].lower())

    @patch('webres6_api.init_webdriver')
    def test_url_endpoint_selenium_unavailable(self, mock_init):
        """Test /res6/url endpoint when Selenium is unavailable"""
        mock_init.return_value = (None, 'Could not connect to selenium')

        response = self.client.get('/res6/url(https://example.com)')
        self.assertEqual(response.status_code, 503)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('selenium', data['error'].lower())

    def test_report_endpoint_invalid_id(self):
        """Test /res6/report endpoint with invalid ID"""
        response = self.client.get('/res6/report/invalid-id-with-special-chars!@#')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)

    @patch('webres6_api.check_auth')
    def test_metrics_endpoint_unauthorized(self, mock_auth):
        """Test /metrics endpoint without authorization"""
        mock_auth.return_value = False
        response = self.client.get('/metrics')
        self.assertEqual(response.status_code, 401)

    @patch('webres6_api.check_auth')
    def test_metrics_endpoint_authorized(self, mock_auth):
        """Test /metrics endpoint with authorization"""
        mock_auth.return_value = True
        response = self.client.get('/metrics')
        self.assertEqual(response.status_code, 200)
        # Prometheus metrics are plain text
        self.assertIn('text/plain', response.content_type)


class TestHealthCheckFunctions(unittest.TestCase):
    """Test health check functions"""

    @patch('webres6_api.storage_manager')
    @patch('webres6_api.dnsprobe')
    @patch('webres6_api.check_selenium')
    def test_check_component_health_all_ok(self, mock_selenium, mock_dnsprobe, mock_storage):
        """Test health check when all components are healthy"""
        mock_storage.check_health.return_value = True
        mock_selenium.return_value = (True, 'ok: chrome 120.0')

        # Mock dnsprobe
        mock_response = Mock()
        mock_response.status = 200
        mock_dnsprobe.request.return_value = mock_response

        status, all_healthy = check_component_health()

        self.assertTrue(all_healthy)
        self.assertEqual(status['storage'], 'ok')
        self.assertEqual(status['dnsprobe'], 'ok')
        self.assertIn('ok', status['selenium'])

    @patch('webres6_api.storage_manager')
    @patch('webres6_api.dnsprobe')
    @patch('webres6_api.check_selenium')
    def test_check_component_health_storage_error(self, mock_selenium, mock_dnsprobe, mock_storage):
        """Test health check when storage fails"""
        mock_storage.check_health.side_effect = Exception('Connection refused')
        mock_selenium.return_value = (True, 'ok: chrome 120.0')

        mock_response = Mock()
        mock_response.status = 200
        mock_dnsprobe.request.return_value = mock_response

        status, all_healthy = check_component_health()

        self.assertFalse(all_healthy)
        self.assertIn('error', status['storage'])
        self.assertIn('Connection refused', status['storage'])

    @patch('webres6_api.storage_manager')
    @patch('webres6_api.dnsprobe')
    @patch('webres6_api.check_selenium')
    def test_check_component_health_selenium_error(self, mock_selenium, mock_dnsprobe, mock_storage):
        """Test health check when Selenium fails"""
        mock_storage.check_health.return_value = True
        mock_selenium.return_value = (False, 'error: Could not connect to selenium')

        mock_response = Mock()
        mock_response.status = 200
        mock_dnsprobe.request.return_value = mock_response

        status, all_healthy = check_component_health()

        self.assertFalse(all_healthy)
        self.assertIn('error', status['selenium'])


class TestReportGeneration(unittest.TestCase):
    """Test report generation functions"""

    def test_gen_report_id(self):
        """Test report ID generation"""
        from urllib.parse import urlparse
        url = urlparse('https://example.com')
        ts = datetime.now(timezone.utc)

        report_id = gen_report_id(url, wait=2, timeout=10, ext=None,
                                   screenshot_mode='none', lookup_whois=False,
                                   ts=ts, report_node='testnode')

        self.assertIsInstance(report_id, str)
        self.assertIn('-', report_id)
        # Should contain hex timestamp
        self.assertTrue(report_id.split('-')[0].isalnum())

    def test_gen_report_id_deterministic(self):
        """Test that same inputs produce same report ID"""
        from urllib.parse import urlparse
        url = urlparse('https://example.com')
        ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        id1 = gen_report_id(url, 2, 10, None, 'none', False, ts, 'node1')
        id2 = gen_report_id(url, 2, 10, None, 'none', False, ts, 'node1')

        self.assertEqual(id1, id2)

    def test_gen_json_structure(self):
        """Test generated JSON structure"""
        from urllib.parse import urlparse
        url = urlparse('https://example.com')
        ts = datetime.now(timezone.utc)

        result = gen_json(url, domain='example.com', hosts={},
                         ipv6_only_ready=True, score=1.0,
                         http_score=1.0, dns_score=1.0,
                         report_id='test-report-id',
                         timestamp=ts)

        # Check required fields
        self.assertEqual(result['ID'], 'test-report-id')
        self.assertEqual(result['url'], 'https://example.com')
        self.assertEqual(result['domain'], 'example.com')
        self.assertTrue(result['ipv6_only_ready'])
        self.assertEqual(result['ipv6_only_score'], 1.0)
        self.assertIsInstance(result['hosts'], dict)

    def test_gen_json_with_error(self):
        """Test JSON generation with error"""
        from urllib.parse import urlparse
        url = urlparse('https://example.com')
        ts = datetime.now(timezone.utc)

        result = gen_json(url, report_id='test-id', timestamp=ts,
                         error='Connection timeout', error_code=503)

        self.assertEqual(result['error'], 'Connection timeout')
        self.assertEqual(result['error_code'], 503)


class TestIPv6Scoring(unittest.TestCase):
    """Test IPv6-only readiness scoring"""

    def test_get_ipv6_only_score_empty_hosts(self):
        """Test scoring with no hosts"""
        score, http_score, dns_score, ready = get_ipv6_only_score({})

        self.assertIsNone(score)
        self.assertIsNone(http_score)
        self.assertIsNone(dns_score)
        self.assertFalse(ready)

    def test_get_ipv6_only_score_ipv6_only(self):
        """Test scoring with IPv6-only hosts"""
        hosts = {
            'example.com': {
                'urls': ['https://example.com/'],
                'ips': {ip_address('2001:db8::1'): {}},
                'dns': {'ipv6_only_ready': True}
            }
        }

        score, http_score, dns_score, ready = get_ipv6_only_score(hosts)

        self.assertEqual(score, 1.0)
        self.assertEqual(http_score, 1.0)
        self.assertEqual(dns_score, 1.0)
        self.assertTrue(ready)

    def test_get_ipv6_only_score_mixed(self):
        """Test scoring with mixed IPv4/IPv6 hosts"""
        hosts = {
            'ipv6.example.com': {
                'urls': ['https://ipv6.example.com/image.png'],
                'ips': {ip_address('2001:db8::1'): {}},
                'dns': {'ipv6_only_ready': True}
            },
            'ipv4.example.com': {
                'urls': ['https://ipv4.example.com/script.js'],
                'ips': {ip_address('192.0.2.1'): {}},
                'dns': {'ipv6_only_ready': False}
            }
        }

        score, http_score, dns_score, ready = get_ipv6_only_score(hosts)

        self.assertEqual(http_score, 0.5)  # 1 IPv6 resource out of 2
        self.assertEqual(dns_score, 0.5)   # 1 IPv6 DNS out of 2
        self.assertEqual(score, 0.5)       # Overall 50%
        self.assertFalse(ready)  # Not ready because of IPv4 host

    def test_get_ipv6_only_score_nat64(self):
        """Test scoring with NAT64 addresses (should count as IPv4)"""
        hosts = {
            'nat64.example.com': {
                'urls': ['https://nat64.example.com/'],
                'ips': {ip_address('64:ff9b::192.0.2.1'): {}},
                'dns': {'ipv6_only_ready': True}
            }
        }

        score, http_score, dns_score, ready = get_ipv6_only_score(hosts)

        self.assertEqual(http_score, 0.0)  # NAT64 doesn't count as native IPv6
        self.assertFalse(ready)


class TestAuthorizationCheck(unittest.TestCase):
    """Test authorization checking"""

    @patch('webres6_api.admin_api_key', 'secret-key')
    def test_check_auth_with_valid_key(self):
        """Test authorization with valid API key"""
        from flask import Flask
        from werkzeug.test import EnvironBuilder
        from werkzeug.wrappers import Request

        app = Flask(__name__)
        with app.test_request_context('/?key=secret-key'):
            from flask import request
            from webres6_api import check_auth
            self.assertTrue(check_auth(request))

    @patch('webres6_api.admin_api_key', 'secret-key')
    def test_check_auth_with_invalid_key(self):
        """Test authorization with invalid API key"""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/?key=wrong-key'):
            from flask import request
            from webres6_api import check_auth
            self.assertFalse(check_auth(request))

    @patch('webres6_api.admin_api_key', None)
    def test_check_auth_no_key_configured(self):
        """Test authorization when no key is configured (should allow)"""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/'):
            from flask import request
            from webres6_api import check_auth
            self.assertTrue(check_auth(request))


class TestHelperFunctions(unittest.TestCase):
    """Test helper functions"""

    def test_validate_url_valid_http(self):
        """Test URL validation with valid HTTP URL"""
        from webres6_api import validate_url
        parsed, error = validate_url('http://example.com')
        self.assertIsNone(error)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.scheme, 'http')

    def test_validate_url_valid_https(self):
        """Test URL validation with valid HTTPS URL"""
        from webres6_api import validate_url
        parsed, error = validate_url('https://example.com')
        self.assertIsNone(error)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.scheme, 'https')

    def test_validate_url_with_port(self):
        """Test URL validation with valid port"""
        from webres6_api import validate_url
        parsed, error = validate_url('https://example.com:8080')
        self.assertIsNone(error)
        self.assertEqual(parsed.port, 8080)

    def test_validate_url_invalid_scheme(self):
        """Test URL validation rejects invalid schemes"""
        from webres6_api import validate_url
        _, error = validate_url('ftp://example.com')
        self.assertIsNotNone(error)
        self.assertIn('scheme', error.lower())

    def test_validate_url_too_long(self):
        """Test URL validation rejects URLs that are too long"""
        from webres6_api import validate_url
        long_url = 'https://example.com/' + 'a' * 3000
        _, error = validate_url(long_url)
        self.assertIsNotNone(error)
        self.assertIn('too long', error.lower())

    def test_validate_url_invalid_port(self):
        """Test URL validation rejects invalid ports"""
        from webres6_api import validate_url
        _, error = validate_url('https://example.com:99999')
        self.assertIsNotNone(error)
        self.assertIn('port', error.lower())

    def test_validate_url_negative_port(self):
        """Test URL validation rejects negative ports"""
        from webres6_api import validate_url
        _, error = validate_url('https://example.com:-1')
        self.assertIsNotNone(error)
        self.assertIn('port', error.lower())

    def test_validate_url_hostname_with_spaces(self):
        """Test URL validation rejects hostnames with spaces"""
        from webres6_api import validate_url
        _, error = validate_url('https://exam ple.com')
        self.assertIsNotNone(error)
        self.assertIn('invalid characters', error.lower())

    def test_split_hostname_simple(self):
        """Test hostname splitting"""
        from webres6_api import split_hostname

        local, domain = split_hostname('www.example.com')
        self.assertEqual(local, 'www.')
        self.assertEqual(domain, 'example.com')

    def test_split_hostname_subdomain(self):
        """Test hostname splitting with subdomain"""
        from webres6_api import split_hostname

        local, domain = split_hostname('api.staging.example.com')
        self.assertEqual(local, 'api.staging.')
        self.assertEqual(domain, 'example.com')

    def test_split_hostname_no_subdomain(self):
        """Test hostname splitting without subdomain"""
        from webres6_api import split_hostname

        local, domain = split_hostname('example.com')
        self.assertEqual(local, '')
        self.assertEqual(domain, 'example.com')


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
