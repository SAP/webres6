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


class TestValkeyStorageManagerCacheOps(unittest.TestCase):
    """Test ValkeyStorageManager cache and archive operations not covered elsewhere"""

    def setUp(self):
        self.mock_valkey = MagicMock()
        with patch('webres6_storage.valkey.from_url', return_value=self.mock_valkey):
            self.storage = ValkeyStorageManager(
                whois_cache_ttl=3600,
                result_archive_ttl=86400,
                valkey_url='valkey://localhost:6379'
            )

    def test_list_archived_reports(self):
        self.mock_valkey.keys.return_value = [
            b'webres6:archive:report-abc',
            b'webres6:archive:report-def',
        ]
        result = self.storage.list_archived_reports()
        self.assertEqual(sorted(result), ['report-abc', 'report-def'])

    def test_list_archived_reports_valkey_error(self):
        self.mock_valkey.keys.side_effect = Exception('connection refused')
        result = self.storage.list_archived_reports()
        self.assertEqual(result, [])

    def test_retrieve_result_found(self):
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        data = {'ID': 'abc', 'url': 'https://example.com', 'ts': ts.isoformat()}
        self.mock_valkey.get.return_value = json.dumps(data).encode('utf-8')
        result = self.storage.retrieve_result('abc')
        self.assertEqual(result['ID'], 'abc')
        self.assertIsInstance(result['ts'], datetime)

    def test_retrieve_result_not_found(self):
        self.mock_valkey.get.return_value = None
        result = self.storage.retrieve_result('missing')
        self.assertIsNone(result)

    def test_retrieve_result_valkey_error(self):
        self.mock_valkey.get.side_effect = Exception('timeout')
        result = self.storage.retrieve_result('abc')
        self.assertIsNone(result)

    def test_put_result_cacheline(self):
        self.mock_valkey.set.return_value = True
        result = self.storage.put_result_cacheline('key1', {'ts': datetime.now(timezone.utc)}, ttl=60)
        self.assertTrue(result)
        self.mock_valkey.set.assert_called_once()

    def test_get_result_cacheline_found(self):
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        data = {'ts': ts.isoformat(), 'value': 42}
        self.mock_valkey.get.return_value = json.dumps(data).encode('utf-8')
        result = self.storage.get_result_cacheline('key1')
        self.assertEqual(result['value'], 42)
        self.assertIsInstance(result['ts'], datetime)

    def test_get_result_cacheline_miss(self):
        self.mock_valkey.get.return_value = None
        result = self.storage.get_result_cacheline('key1')
        self.assertIsNone(result)

    def test_delete_result_cacheline(self):
        self.mock_valkey.delete.return_value = 1
        result = self.storage.delete_result_cacheline('key1')
        self.assertTrue(result)
        self.mock_valkey.delete.assert_called_once()

    def test_delete_result_cacheline_error(self):
        self.mock_valkey.delete.side_effect = Exception('error')
        result = self.storage.delete_result_cacheline('key1')
        self.assertFalse(result)

    def test_put_scorecard(self):
        self.mock_valkey.lpush.return_value = 1
        result = self.storage.put_scorecard({'score': 1.0, 'ts': datetime.now(timezone.utc)})
        self.assertTrue(result)

    def test_get_scorecards(self):
        ts = datetime.now(timezone.utc)
        raw = [json.dumps({'score': 1.0, 'ts': ts.isoformat()}).encode('utf-8')]
        self.mock_valkey.lrange.return_value = raw
        result = self.storage.get_scorecards(max_entries=10)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0]['ts'], datetime)

    def test_get_scorecards_expired_filtered(self):
        old_ts = datetime(2000, 1, 1, tzinfo=timezone.utc)
        raw = [json.dumps({'score': 0.5, 'ts': old_ts.isoformat()}).encode('utf-8')]
        self.mock_valkey.lrange.return_value = raw
        result = self.storage.get_scorecards(max_entries=10)
        self.assertEqual(result, [])

    def test_whois_mem_cache_eviction(self):
        self.storage.whois_mem_cache_size_max = 2
        ip1 = ip_address('1.1.1.1')
        ip2 = ip_address('2.2.2.2')
        ip3 = ip_address('3.3.3.3')
        ts = datetime.now(timezone.utc)
        self.mock_valkey.set.return_value = True
        self.storage.put_whois_cacheline(ip1, {'ts': ts, 'asn': 'AS1'})
        self.storage.put_whois_cacheline(ip2, {'ts': ts, 'asn': 'AS2'})
        # this should trigger eviction of the in-memory cache
        self.storage.put_whois_cacheline(ip3, {'ts': ts, 'asn': 'AS3'})
        # cache should have been flushed and only ip3 added back
        self.assertIn(ip3, self.storage.whois_mem_cache)


class TestValkeyS3HybridManagerExtra(unittest.TestCase):
    """Test ValkeyS3HybridStorageManager methods not covered in existing tests"""

    def setUp(self):
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
                    s3_endpoint='https://s3.example.com',
                    s3_delivery_strategy='presigned',
                )

    def test_list_archived_reports(self):
        self.mock_s3.list_objects_v2.return_value = {
            'Contents': [
                {'Key': 'report-abc123.json'},
                {'Key': 'report-def456.json'},
                {'Key': 'other-file.txt'},  # should be ignored
            ]
        }
        result = self.storage.list_archived_reports()
        self.assertIn('abc123', result)
        self.assertIn('def456', result)
        self.assertEqual(len(result), 2)

    def test_list_archived_reports_empty_bucket(self):
        self.mock_s3.list_objects_v2.return_value = {}
        result = self.storage.list_archived_reports()
        self.assertEqual(result, [])

    def test_list_archived_reports_s3_error(self):
        self.mock_s3.list_objects_v2.side_effect = Exception('Access Denied')
        result = self.storage.list_archived_reports()
        self.assertEqual(result, [])

    def test_retrieve_result_found_gzip(self):
        from compression import gzip
        import json as _json
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        data = {'ID': 'abc', 'ts': ts.isoformat(), 'url': 'https://example.com'}
        body_bytes = gzip.compress(_json.dumps(data).encode('utf-8'))
        mock_body = MagicMock()
        mock_body.read.return_value = body_bytes
        self.mock_s3.get_object.return_value = {'Body': mock_body, 'ContentEncoding': 'gzip'}
        result = self.storage.retrieve_result('abc')
        self.assertEqual(result['ID'], 'abc')
        self.assertIsInstance(result['ts'], datetime)

    def test_retrieve_result_not_found(self):
        self.mock_s3.get_object.return_value = {}
        result = self.storage.retrieve_result('abc')
        self.assertIsNone(result)

    def test_retrieve_result_s3_error(self):
        self.mock_s3.get_object.side_effect = Exception('NoSuchKey')
        result = self.storage.retrieve_result('abc')
        self.assertIsNone(result)

    def test_retrieve_result_url_public(self):
        with patch('webres6_storage.valkey.from_url', return_value=self.mock_valkey):
            with patch('webres6_storage.boto3.client', return_value=self.mock_s3):
                storage = ValkeyS3HybridStorageManager(
                    whois_cache_ttl=3600, result_archive_ttl=86400,
                    valkey_url='valkey://localhost:6379',
                    s3_bucket='test-bucket', s3_endpoint='https://s3.example.com',
                    s3_delivery_strategy='public',
                )
        url = storage.retrieve_result_url('abc')
        self.assertIn('abc', url)
        self.assertIn('test-bucket', url)

    def test_retrieve_result_url_private_returns_none(self):
        with patch('webres6_storage.valkey.from_url', return_value=self.mock_valkey):
            with patch('webres6_storage.boto3.client', return_value=self.mock_s3):
                storage = ValkeyS3HybridStorageManager(
                    whois_cache_ttl=3600, result_archive_ttl=86400,
                    valkey_url='valkey://localhost:6379',
                    s3_bucket='test-bucket', s3_endpoint='https://s3.example.com',
                    s3_delivery_strategy='private',
                )
        self.assertIsNone(storage.retrieve_result_url('abc'))

    def test_retrieve_result_url_presigned(self):
        self.mock_valkey.get.return_value = None  # no cached URL
        self.mock_s3.generate_presigned_url.return_value = 'https://presigned.url/abc'
        self.mock_valkey.set.return_value = True
        url = self.storage.retrieve_result_url('abc')
        self.assertEqual(url, 'https://presigned.url/abc')
        self.mock_s3.generate_presigned_url.assert_called_once()

    def test_retrieve_result_url_presigned_cached(self):
        cached = {'ts': datetime.now(timezone.utc).isoformat()}
        # simulate a cached presigned URL response in valkey
        self.mock_valkey.get.return_value = json.dumps('https://cached.url/abc').encode('utf-8')
        url = self.storage.retrieve_result_url('abc')
        # cached value is returned as-is
        self.assertIsNotNone(url)
        self.mock_s3.generate_presigned_url.assert_not_called()


class TestExportImportFunctions(unittest.TestCase):
    """Test export_scoreboard_entries, import_scoreboard_entries,
    export_archived_reports, and import_archived_reports"""

    def setUp(self):
        from webres6_storage import export_scoreboard_entries, import_scoreboard_entries
        from webres6_storage import export_archived_reports, import_archived_reports
        self.export_scoreboard = export_scoreboard_entries
        self.import_scoreboard = import_scoreboard_entries
        self.export_archived = export_archived_reports
        self.import_archived = import_archived_reports

        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_export_scoreboard_to_file(self):
        mock_storage = MagicMock()
        ts = datetime.now(timezone.utc)
        mock_storage.get_scorecards.return_value = [
            {'score': 1.0, 'ts': ts, 'url': 'https://example.com'}
        ]
        out_file = os.path.join(self.test_dir, 'scoreboard.json')
        self.export_scoreboard(mock_storage, file=out_file)
        with open(out_file, 'r') as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['score'], 1.0)

    def test_export_scoreboard_to_stdout(self):
        mock_storage = MagicMock()
        mock_storage.get_scorecards.return_value = [
            {'score': 0.5, 'ts': datetime.now(timezone.utc)}
        ]
        out_file = os.path.join(self.test_dir, 'scoreboard_stdout.json')
        self.export_scoreboard(mock_storage, file=out_file)
        with open(out_file, 'r') as f:
            data = json.load(f)
        self.assertEqual(data[0]['score'], 0.5)

    def test_import_scoreboard_from_file(self):
        mock_storage = MagicMock()
        ts = datetime.now(timezone.utc)
        entries = [{'score': 1.0, 'ts': ts.isoformat(), 'url': 'https://example.com'}]
        in_file = os.path.join(self.test_dir, 'scoreboard.json')
        with open(in_file, 'w') as f:
            json.dump(entries, f)
        self.import_scoreboard(mock_storage, file=in_file)
        mock_storage.put_scorecard.assert_called_once()
        call_arg = mock_storage.put_scorecard.call_args[0][0]
        self.assertIsInstance(call_arg['ts'], datetime)

    def test_export_archived_reports_no_archive(self):
        mock_storage = MagicMock()
        mock_storage.can_archive.return_value = False
        result = self.export_archived(mock_storage, self.test_dir, 86400)
        self.assertFalse(result)

    def test_export_archived_reports_nonexistent_dir(self):
        mock_storage = MagicMock()
        mock_storage.can_archive.return_value = True
        result = self.export_archived(mock_storage, '/nonexistent/path', 86400)
        self.assertFalse(result)

    def test_export_archived_reports_empty(self):
        mock_storage = MagicMock()
        mock_storage.can_archive.return_value = True
        mock_storage.list_archived_reports.return_value = []
        result = self.export_archived(mock_storage, self.test_dir, 86400)
        self.assertTrue(result)

    def test_export_archived_reports_copies_reports(self):
        src_dir = os.path.join(self.test_dir, 'src')
        dst_dir = os.path.join(self.test_dir, 'dst')
        os.makedirs(src_dir)
        os.makedirs(dst_dir)
        src_storage = LocalStorageManager(result_archive_ttl=86400, archive_dir=src_dir)
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        src_storage.archive_result('report-001', {'ID': 'report-001', 'ts': ts, 'url': 'https://example.com'})
        result = self.export_archived(src_storage, dst_dir, 86400)
        self.assertTrue(result)
        dst_storage = LocalStorageManager(result_archive_ttl=86400, archive_dir=dst_dir)
        self.assertIn('report-001', dst_storage.list_archived_reports())

    def test_import_archived_reports_no_archive(self):
        mock_storage = MagicMock()
        mock_storage.can_archive.return_value = False
        result = self.import_archived(mock_storage, self.test_dir, 86400)
        self.assertFalse(result)

    def test_import_archived_reports_nonexistent_dir(self):
        mock_storage = MagicMock()
        mock_storage.can_archive.return_value = True
        result = self.import_archived(mock_storage, '/nonexistent/path', 86400)
        self.assertFalse(result)

    def test_import_archived_reports_empty(self):
        mock_storage = MagicMock()
        mock_storage.can_archive.return_value = True
        src_dir = os.path.join(self.test_dir, 'empty')
        os.makedirs(src_dir)
        result = self.import_archived(mock_storage, src_dir, 86400)
        self.assertTrue(result)

    def test_import_archived_copies_reports(self):
        src_dir = os.path.join(self.test_dir, 'src')
        dst_dir = os.path.join(self.test_dir, 'dst')
        os.makedirs(src_dir)
        os.makedirs(dst_dir)
        src_storage = LocalStorageManager(result_archive_ttl=86400, archive_dir=src_dir)
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        src_storage.archive_result('report-002', {'ID': 'report-002', 'ts': ts, 'url': 'https://example.com'})
        dst_storage = LocalStorageManager(result_archive_ttl=86400, archive_dir=dst_dir)
        result = self.import_archived(dst_storage, src_dir, 86400)
        self.assertTrue(result)
        self.assertIn('report-002', dst_storage.list_archived_reports())


if __name__ == '__main__':
    unittest.main(verbosity=2)
