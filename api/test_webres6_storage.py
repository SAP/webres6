#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Unit tests for webres6_storage.py

These tests cover the storage manager implementations.
"""

import unittest
import os
import sys
import tempfile
import shutil
import json
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webres6_storage import (
    LocalStorageManager,
    ValkeyStorageManager,
    ValkeyFileHybridStorageManager,
    ValkeyS3HybridStorageManager,
    Scoreboard
)


class TestLocalStorageManager(unittest.TestCase):
    """Test LocalStorageManager"""

    def setUp(self):
        """Create temporary directories for testing"""
        self.test_dir = tempfile.mkdtemp()
        self.cache_dir = os.path.join(self.test_dir, 'cache')
        self.archive_dir = os.path.join(self.test_dir, 'reports')
        os.makedirs(self.cache_dir)
        os.makedirs(self.archive_dir)

        self.storage = LocalStorageManager(
            whois_cache_ttl=3600,
            result_archive_ttl=86400,
            cache_dir=self.cache_dir,
            archive_dir=self.archive_dir
        )

    def tearDown(self):
        """Clean up temporary directories"""
        shutil.rmtree(self.test_dir)

    def test_can_archive(self):
        """Test that local storage can archive"""
        self.assertTrue(self.storage.can_archive())

    def test_can_persist(self):
        """Test that local storage can persist"""
        self.assertTrue(self.storage.can_persist())

    def test_check_health_success(self):
        """Test health check when directories are accessible"""
        result = self.storage.check_health()
        self.assertTrue(result)

    def test_check_health_missing_archive_dir(self):
        """Test health check when archive directory is missing"""
        shutil.rmtree(self.archive_dir)
        with self.assertRaises(Exception) as ctx:
            self.storage.check_health()
        self.assertIn('not accessible', str(ctx.exception))

    def test_check_health_missing_cache_dir(self):
        """Test health check when cache directory is missing"""
        shutil.rmtree(self.cache_dir)
        with self.assertRaises(Exception) as ctx:
            self.storage.check_health()
        self.assertIn('not accessible', str(ctx.exception))

    def test_whois_cache_operations(self):
        """Test WHOIS cache put and get operations"""
        ip = ip_address('192.0.2.1')
        data = {
            'asn': 'AS12345',
            'asn_description': 'Example AS',
            'ts': datetime.now(timezone.utc)
        }

        # Put data
        result = self.storage.put_whois_cacheline(ip, data)
        self.assertTrue(result)

        # Get data
        cached = self.storage.get_whois_cacheline(ip)
        self.assertIsNotNone(cached)
        self.assertEqual(cached['asn'], 'AS12345')

    def test_whois_cache_expiry(self):
        """Test WHOIS cache expiry"""
        ip = ip_address('192.0.2.1')
        old_time = datetime.now(timezone.utc) - timedelta(seconds=7200)
        data = {
            'asn': 'AS12345',
            'ts': old_time
        }

        self.storage.put_whois_cacheline(ip, data)

        # Should return None for expired entry
        cached = self.storage.get_whois_cacheline(ip)
        self.assertIsNone(cached)

    def test_whois_cache_size(self):
        """Test WHOIS cache size reporting"""
        # Clear any existing cache first
        self.storage.whois_cache.clear()
        self.assertEqual(self.storage.whois_cache_size(), 0)

        ip = ip_address('192.0.2.1')
        data = {'asn': 'AS12345', 'ts': datetime.now(timezone.utc)}
        self.storage.put_whois_cacheline(ip, data)

        self.assertEqual(self.storage.whois_cache_size(), 1)

    def test_result_cache_operations(self):
        """Test result cache put and get operations"""
        cache_key = 'test-cache-key'
        data = {
            'type': 'report',
            'ts': datetime.now(timezone.utc),
            'report_id': 'test-report-123'
        }

        # Put data
        result = self.storage.put_result_cacheline(cache_key, data, ttl=900)
        self.assertTrue(result)

        # Get data
        cached = self.storage.get_result_cacheline(cache_key)
        self.assertIsNotNone(cached)
        self.assertEqual(cached['report_id'], 'test-report-123')

    def test_result_cache_expiry(self):
        """Test result cache expiry"""
        cache_key = 'test-cache-key'
        data = {
            'type': 'report',
            'ts': datetime.now(timezone.utc),
            'report_id': 'test-report-123',
            'expiry': datetime.now(timezone.utc) - timedelta(seconds=10)
        }

        self.storage.result_cache[cache_key] = data

        # Should return None for expired entry
        cached = self.storage.get_result_cacheline(cache_key)
        self.assertIsNone(cached)

    def test_archive_result(self):
        """Test archiving a result"""
        report_id = 'test-report-123'
        data = {
            'ID': report_id,
            'url': 'https://example.com',
            'ts': datetime.now(timezone.utc),
            'ipv6_only_ready': True
        }

        result = self.storage.archive_result(report_id, data)
        self.assertTrue(result)

        # Verify file was created
        filename = os.path.join(self.archive_dir, f'report-{report_id}.json')
        self.assertTrue(os.path.exists(filename))

    def test_retrieve_result(self):
        """Test retrieving an archived result"""
        report_id = 'test-report-456'
        data = {
            'ID': report_id,
            'url': 'https://example.com',
            'ts': datetime.now(timezone.utc),
            'ipv6_only_ready': True
        }

        # Archive first
        self.storage.archive_result(report_id, data)

        # Retrieve
        retrieved = self.storage.retrieve_result(report_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved['ID'], report_id)
        self.assertEqual(retrieved['url'], 'https://example.com')

    def test_list_archived_reports(self):
        """Test listing archived reports"""
        # Archive multiple reports
        for i in range(3):
            report_id = f'test-report-{i}'
            data = {'ID': report_id, 'ts': datetime.now(timezone.utc)}
            self.storage.archive_result(report_id, data)

        # List reports
        reports = self.storage.list_archived_reports()
        self.assertEqual(len(reports), 3)
        self.assertIn('test-report-0', reports)

    def test_scorecard_operations(self):
        """Test scorecard put and get operations"""
        scorecard = {
            'report_id': 'test-123',
            'ts': datetime.now(timezone.utc),
            'url': 'https://example.com',
            'domain': 'example.com',
            'ipv6_only_score': 1.0,
            'ipv6_only_ready': True
        }

        result = self.storage.put_scorecard(scorecard)
        self.assertTrue(result)

        scorecards = self.storage.get_scorecards(max_entries=10)
        self.assertEqual(len(scorecards), 1)
        self.assertEqual(scorecards[0]['report_id'], 'test-123')

    def test_persist_and_load(self):
        """Test persisting and loading cache"""
        # Add some data
        ip = ip_address('192.0.2.1')
        whois_data = {'asn': 'AS12345', 'ts': datetime.now(timezone.utc)}
        self.storage.put_whois_cacheline(ip, whois_data)

        # Persist
        result = self.storage.persist()
        self.assertTrue(result)

        # Create new storage manager and load
        new_storage = LocalStorageManager(
            cache_dir=self.cache_dir,
            archive_dir=self.archive_dir
        )

        # Verify data was loaded
        self.assertEqual(new_storage.whois_cache_size(), 1)

    def test_expire(self):
        """Test expiring old cache entries"""
        # Clear any existing cache entries first for test isolation
        self.storage.whois_cache.clear()
        self.storage.result_cache.clear()
        self.storage.scorecards.clear()

        # Add expired WHOIS entry
        ip = ip_address('192.0.2.1')
        old_time = datetime.now(timezone.utc) - timedelta(days=10)
        whois_data = {'asn': 'AS12345', 'ts': old_time}
        self.storage.whois_cache[ip] = whois_data

        # Verify entry exists before expiry
        self.assertEqual(self.storage.whois_cache_size(), 1)

        # Run expire
        expired_count = self.storage.expire()
        self.assertGreaterEqual(expired_count, 1)  # At least 1 expired (the one we added)

        # Verify entry was removed
        self.assertEqual(self.storage.whois_cache_size(), 0)


class TestValkeyStorageManager(unittest.TestCase):
    """Test ValkeyStorageManager"""

    def setUp(self):
        """Set up mock Valkey client"""
        self.mock_valkey = MagicMock()

        with patch('webres6_storage.valkey.from_url', return_value=self.mock_valkey):
            self.storage = ValkeyStorageManager(
                whois_cache_ttl=3600,
                result_archive_ttl=86400,
                valkey_url='valkey://localhost:6379'
            )

    def test_can_archive(self):
        """Test that Valkey storage can archive"""
        self.assertTrue(self.storage.can_archive())

    def test_check_health_success(self):
        """Test health check when Valkey is accessible"""
        self.mock_valkey.ping.return_value = True
        result = self.storage.check_health()
        self.assertTrue(result)
        self.mock_valkey.ping.assert_called_once()

    def test_check_health_ping_false(self):
        """Test health check when ping returns False"""
        self.mock_valkey.ping.return_value = False
        with self.assertRaises(Exception) as ctx:
            self.storage.check_health()
        self.assertIn('ping returned False', str(ctx.exception))

    def test_check_health_no_client(self):
        """Test health check when client is not initialized"""
        self.storage.valkey_client = None
        with self.assertRaises(Exception) as ctx:
            self.storage.check_health()
        self.assertIn('not initialized', str(ctx.exception))

    def test_whois_cache_operations(self):
        """Test WHOIS cache operations with Valkey"""
        ip = ip_address('192.0.2.1')
        data = {
            'asn': 'AS12345',
            'asn_description': 'Example AS',
            'ts': datetime.now(timezone.utc)
        }

        # Put data
        self.mock_valkey.set.return_value = True
        result = self.storage.put_whois_cacheline(ip, data)
        self.assertTrue(result)
        self.mock_valkey.set.assert_called_once()

    def test_archive_result(self):
        """Test archiving a result to Valkey"""
        report_id = 'test-report-123'
        data = {
            'ID': report_id,
            'url': 'https://example.com',
            'ts': datetime.now(timezone.utc)
        }

        self.mock_valkey.set.return_value = True
        result = self.storage.archive_result(report_id, data)
        self.assertTrue(result)
        self.mock_valkey.set.assert_called_once()


class TestValkeyFileHybridStorageManager(unittest.TestCase):
    """Test ValkeyFileHybridStorageManager"""

    def setUp(self):
        """Set up mock Valkey client and temp directories"""
        self.test_dir = tempfile.mkdtemp()
        self.archive_dir = os.path.join(self.test_dir, 'reports')
        os.makedirs(self.archive_dir)

        self.mock_valkey = MagicMock()
        self.mock_valkey.ping.return_value = True

        with patch('webres6_storage.valkey.from_url', return_value=self.mock_valkey):
            self.storage = ValkeyFileHybridStorageManager(
                whois_cache_ttl=3600,
                result_archive_ttl=86400,
                valkey_url='valkey://localhost:6379',
                archive_dir=self.archive_dir
            )

    def tearDown(self):
        """Clean up temp directories"""
        shutil.rmtree(self.test_dir)

    def test_check_health_both_backends(self):
        """Test health check validates both Valkey and local storage"""
        self.mock_valkey.ping.return_value = True
        result = self.storage.check_health()
        self.assertTrue(result)

    def test_check_health_valkey_fails(self):
        """Test health check when Valkey fails"""
        self.mock_valkey.ping.return_value = False
        with self.assertRaises(Exception):
            self.storage.check_health()

    def test_check_health_file_storage_fails(self):
        """Test health check when file storage fails"""
        self.mock_valkey.ping.return_value = True
        shutil.rmtree(self.archive_dir)
        with self.assertRaises(Exception):
            self.storage.check_health()


class TestValkeyS3HybridStorageManager(unittest.TestCase):
    """Test ValkeyS3HybridStorageManager"""

    def setUp(self):
        """Set up mock Valkey and S3 clients"""
        self.mock_valkey = MagicMock()
        self.mock_valkey.ping.return_value = True

        self.mock_s3 = MagicMock()
        self.mock_s3.meta.endpoint_url = 'https://s3.example.com'

        with patch('webres6_storage.valkey.from_url', return_value=self.mock_valkey):
            with patch('webres6_storage.boto3.client', return_value=self.mock_s3):
                self.storage = ValkeyS3HybridStorageManager(
                    whois_cache_ttl=3600,
                    result_archive_ttl=86400,
                    valkey_url='valkey://localhost:6379',
                    s3_bucket='test-bucket',
                    s3_endpoint='https://s3.example.com'
                )

    def test_check_health_both_backends(self):
        """Test health check validates both Valkey and S3"""
        self.mock_valkey.ping.return_value = True
        self.mock_s3.head_bucket.return_value = {}

        result = self.storage.check_health()
        self.assertTrue(result)
        self.mock_s3.head_bucket.assert_called_once_with(Bucket='test-bucket')

    def test_check_health_s3_fails(self):
        """Test health check when S3 fails"""
        self.mock_valkey.ping.return_value = True
        self.mock_s3.head_bucket.side_effect = Exception('Access Denied')

        with self.assertRaises(Exception) as ctx:
            self.storage.check_health()
        self.assertIn('not accessible', str(ctx.exception))

    def test_archive_result_to_s3(self):
        """Test archiving to S3"""
        report_id = 'test-report-123'
        data = {
            'ID': report_id,
            'url': 'https://example.com',
            'ts': datetime.now(timezone.utc)
        }

        self.mock_s3.put_object.return_value = {}
        result = self.storage.archive_result(report_id, data)
        self.assertTrue(result)
        self.mock_s3.put_object.assert_called_once()


class TestScoreboard(unittest.TestCase):
    """Test Scoreboard class"""

    def setUp(self):
        """Set up mock storage manager"""
        self.mock_storage = MagicMock()
        self.scoreboard = Scoreboard(storage_manager=self.mock_storage)

    def test_enter_valid_report(self):
        """Test entering a valid report to scoreboard"""
        report = {
            'ID': 'test-123',
            'ts': datetime.now(timezone.utc),
            'url': 'https://example.com',
            'domain': 'example.com',
            'ipv6_only_score': 1.0,
            'ipv6_only_ready': True
        }

        self.mock_storage.put_scorecard.return_value = True
        result = self.scoreboard.enter(report)
        self.assertTrue(result)
        self.mock_storage.put_scorecard.assert_called_once()

    def test_enter_report_with_error(self):
        """Test that reports with errors are not entered"""
        report = {
            'ID': 'test-123',
            'ts': datetime.now(timezone.utc),
            'error': 'Connection timeout'
        }

        self.scoreboard.enter(report)
        # Should not call put_scorecard
        self.mock_storage.put_scorecard.assert_not_called()

    def test_get_entries(self):
        """Test getting scoreboard entries"""
        expected_entries = [
            {'report_id': 'test-1', 'score': 1.0},
            {'report_id': 'test-2', 'score': 0.9}
        ]
        self.mock_storage.get_scorecards.return_value = expected_entries

        entries = self.scoreboard.get_entries(limit=10)
        self.assertEqual(len(entries), 2)
        self.mock_storage.get_scorecards.assert_called_once_with(max_entries=10)


if __name__ == '__main__':
    unittest.main(verbosity=2)
