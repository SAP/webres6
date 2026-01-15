#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

from hashlib import sha256
import json
import math
import os
import sys
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address
import valkey
import boto3 

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

# Storage abstraction for cache/archive
class StorageManager:

    whois_cache_ttl = 3600
    result_archive_ttl = 3600*24

    def can_archive(self):
        pass

    def can_persist(self):
        pass
    
    def archive_result(self, report_id, data):
        pass

    def list_archived_reports(self):
        pass

    def retrieve_result(self, report_id):
        pass

    def retrieve_result_url(self, report_id):
        return None
    
    def put_result_cacheline(self, cache_key, data, ttl, overwrite=True):
        pass

    def delete_result_cacheline(self, cache_key):
        pass

    def get_result_cacheline(self, cache_key):
        pass

    def put_whois_cacheline(self, ip, data):
        pass

    def get_whois_cacheline(self, ip):
        pass

    def whois_cache_size(self):
        pass

    def put_scorecard(self, scorecard):
        pass

    def get_scorecards(self, max_entries=23):
        pass


# Local storage manager for file based cache/archive
class LocalStorageManager(StorageManager):

    whois_cache = {}
    result_cache = {}
    local_cache_dir = None
    local_archive_dir = None
    max_scorecards = 0
    scorecards = []

    def __init__(self, whois_cache_ttl=3600*24, result_archive_ttl=3600*24, cache_dir=None, archive_dir=None, max_scorecards=128):
        self.whois_cache_ttl = whois_cache_ttl
        self.result_archive_ttl = result_archive_ttl
        self.max_scorecards = max_scorecards
        # check cache dir
        if cache_dir and os.path.isdir(cache_dir):
            self.local_cache_dir = cache_dir
            self._load()
        elif cache_dir:
            print(f"WARNING: local cache dir \"{cache_dir}\" does not exist - deactivating cache-persist", file=sys.stderr)
        # setup archive dir in cache dir if not specified
        if not archive_dir and cache_dir:
            archive_dir = os.path.join(cache_dir, 'reports')
            if not os.path.exists(archive_dir):
                os.makedirs(archive_dir)
                print(f"created local archive dir \"{archive_dir}\"", file=sys.stderr)
                # migrate existing report files in cache dir if any
                for file in os.listdir(cache_dir):
                    if file.startswith("report-") and file.endswith(".json"):
                        src = os.path.join(cache_dir, file)
                        dst = os.path.join(archive_dir, file)
                        os.rename(src, dst)
                        print(f"migrated report file \"{src}\" to \"{dst}\"", file=sys.stderr)
        if archive_dir and os.path.isdir(archive_dir):
            self.local_archive_dir = archive_dir
        else:
            print(f"WARNING: local archive dir \"{archive_dir}\" does not exist - deactivating archive", file=sys.stderr)

    def print_warnings(self):
        # warn about limitations
        print("WARNING: LocalStorageManager is not suitable for production use!", file=sys.stderr)
        print("         - No multi-instance synchronization", file=sys.stderr)
        print("         - Use /admin/persist to manually persists cache", file=sys.stderr)
        print("         - Use /admin/expire or --expire to manually expire cache", file=sys.stderr)

    def can_archive(self):
        return self.local_archive_dir is not None

    def archive_result(self, report_id, data):
        if not self.local_archive_dir:
            return False
        try:
            file = os.path.join(self.local_archive_dir, f"report-{report_id}.json")
            with open(file, 'w', encoding='utf-8') as f:
                json.dump(data, f, cls=DateTimeEncoder, ensure_ascii=False)
                f.close()
            return True
        except Exception as e:
            print(f"WARNING: failed archiving result {report_id} to local cache: {e}", file=sys.stderr)
            return False

    def list_archived_reports(self):
        if not self.local_archive_dir:
            return []
        try:
            files = os.listdir(self.local_archive_dir)
            report_ids = [file[len("report-"):-len(".json")] for file in files if file.startswith("report-") and file.endswith(".json")]
            return report_ids
        except Exception as e:
            print(f"WARNING: failed listing archived reports from local storage: {e}", file=sys.stderr)
            return []

    def retrieve_result(self, report_id):
        if not self.local_archive_dir:
            return None
        try:
            file = os.path.join(self.local_archive_dir, f"report-{report_id}.json")
            if os.path.exists(file):
                with open(file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    data['ts'] = datetime.fromisoformat(data['ts'])
                    f.close()
                return data
            else:
                return None
        except Exception as e:
            print(f"WARNING: failed retrieving archived result {report_id} from local storage: {e}", file=sys.stderr)
            return None

    def put_result_cacheline(self, cache_key, data, ttl, overwrite=True):
        if overwrite or cache_key not in self.result_cache:
            data['expiry'] = datetime.now(timezone.utc) + timedelta(seconds=ttl)
            self.result_cache[cache_key] = data
            return True
        return False

    def delete_result_cacheline(self, cache_key):
        if cache_key in self.result_cache:
            del self.result_cache[cache_key]
        return True

    def get_result_cacheline(self, cache_key):
        if cache_key in self.result_cache:
            result = self.result_cache[cache_key]
            if datetime.now(timezone.utc) > result['expiry']:
                del self.result_cache[cache_key]
                return None
            return self.result_cache[cache_key]
        return None

    def put_whois_cacheline(self, ip, data):
        self.whois_cache[ip] = data
        return True

    def get_whois_cacheline(self, ip):
        if ip in self.whois_cache:
            result = self.whois_cache[ip]
            if datetime.now(timezone.utc) > result['ts'] + timedelta(seconds=self.whois_cache_ttl):
                del self.whois_cache[ip]
                return None
            return self.whois_cache[ip]
        return None

    def whois_cache_size(self):
        return len(self.whois_cache)

    def put_scorecard(self, scorecard):
        self.scorecards.append(scorecard)
        # keep only the latest max_scorecards entries
        if len(self.scorecards) > self.max_scorecards:
            self.scorecards.pop(0)
        return True

    def get_scorecards(self, max_entries=0):
        if max_entries == 0 or max_entries >= len(self.scorecards):
            return self.scorecards
        return self.scorecards[-max_entries:]

    def can_persist(self):
        """ check if local cache persistence is enabled """
        return self.local_cache_dir is not None

    def persist(self):
        """ persist local cache to disk """
        if not self.local_cache_dir:
            return False
        try:
            file = os.path.join(self.local_cache_dir, f"whois-cache.json")
            with open(file, 'w', encoding='utf-8') as f:
                whois_out = {}
                for ip in self.whois_cache:
                    whois_out[str(ip)] = self.whois_cache[ip]
                json.dump(whois_out, f, cls=DateTimeEncoder, ensure_ascii=False)
                f.close()
            file = os.path.join(self.local_cache_dir, f"result-cache.json")
            with open(file, 'w', encoding='utf-8') as f:
                json.dump(self.result_cache, f, cls=DateTimeEncoder, ensure_ascii=False)
                f.close()
            file = os.path.join(self.local_cache_dir, f"scorecards.json")
            with open(file, 'w', encoding='utf-8') as f:
                json.dump(self.scorecards, f, cls=DateTimeEncoder, ensure_ascii=False)
                f.close()
            return True 
        except Exception as e:
            print(f"WARNING: failed persisting whois cache to local storage: {e}", file=sys.stderr)
            return False

    def expire(self):
        # expire old result cache entries
        print ("Expiring result cache entries... ", file=sys.stderr, end='', flush=True)
        now = datetime.now(timezone.utc)
        result_cache_expired = 0
        for key in [key for key in self.result_cache.keys() if now > self.result_cache[key]['expiry']]:
            del self.result_cache[key]
            result_cache_expired += 1
        print(f"done, expired {result_cache_expired} entries.", file=sys.stderr)

        # expire old whois cache entries
        print ("Expiring whois cache entries... ", file=sys.stderr, end='', flush=True)
        threshold = now - timedelta(seconds=self.whois_cache_ttl)
        whois_cache_expired = 0
        for key in [key for key in self.whois_cache.keys() if self.whois_cache[key]['ts'] < threshold]:
            del self.whois_cache[key]
            whois_cache_expired += 1
        print(f"done, expired {whois_cache_expired} entries.", file=sys.stderr)

        # expire old scorecards
        print ("Expiring scorecards... ", file=sys.stderr, end='', flush=True)
        deadline = now - timedelta(seconds=self.result_archive_ttl)
        scorecards_expired = 0
        for scorecard in [scorecard for scorecard in self.scorecards if scorecard['ts'] < deadline]:
            self.scorecards.remove(scorecard)
            scorecards_expired += 1
        print(f"done, expired {scorecards_expired} entries.", file=sys.stderr)

        # expire old archive files
        print ("Expiring archived report files", file=sys.stderr, end='', flush=True)
        threshold = now - timedelta(seconds=self.result_archive_ttl)
        report_cached_expired = 0
        if self.local_archive_dir:
            for file in os.listdir(self.local_archive_dir):
                if file.startswith("report-") and file.endswith(".json"):
                    file_path = os.path.join(self.local_archive_dir, file)
                    print('.', end='', flush=True)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            data['ts'] = datetime.fromisoformat(data['ts'])
                            f.close()
                        if data['ts'] < threshold:
                            os.remove(file_path)
                            report_cached_expired += 1
                    except Exception as e:
                        print(f"WARNING: failed expiring archived report file {file_path}: {e}", file=sys.stderr)
        print(f" done, expired {report_cached_expired} entries.", file=sys.stderr)

        # return number of expired entries
        return result_cache_expired + whois_cache_expired + scorecards_expired + report_cached_expired

    def _load(self):
        """ load local cache from disk """
        if not self.local_cache_dir:
            return False
        try:
            # read whois cache
            file = os.path.join(self.local_cache_dir, f"whois-cache.json")
            if os.path.exists(file):
                with open(file, 'r', encoding='utf-8') as f:
                    whois_in = json.load(f)
                    for ip_str in whois_in:
                        ip = ip_address(ip_str)
                        self.whois_cache[ip] = whois_in[ip_str]
                    f.close()
                print(f"read {len(self.whois_cache)} whois cache entries from local storage", file=sys.stderr)
                # fix timestamps in whois cache
                for ip in self.whois_cache:
                    self.whois_cache[ip]['ts'] = datetime.fromisoformat(self.whois_cache[ip]['ts'])
            # read result cache
            file = os.path.join(self.local_cache_dir, f"result-cache.json")
            if os.path.exists(file):
                with open(file, 'r', encoding='utf-8') as f:
                    self.result_cache = json.load(f)
                    f.close()
                print(f"read {len(self.result_cache)} result cache entries from local storage", file=sys.stderr)
                # fix timestamps in result cache
                for key in self.result_cache:
                    self.result_cache[key]['ts'] = datetime.fromisoformat(self.result_cache[key]['ts'])
                    self.result_cache[key]['expiry'] = datetime.fromisoformat(self.result_cache[key]['expiry'])
            # read scorecards
            file = os.path.join(self.local_cache_dir, f"scorecards.json")
            if os.path.exists(file):
                with open(file, 'r', encoding='utf-8') as f:
                    self.scorecards = json.load(f)
                    f.close()
                print(f"read {len(self.scorecards)} scorecards from local storage", file=sys.stderr)
                # fix timestamps in scorecards
                for scorecard in self.scorecards:
                    scorecard['ts'] = datetime.fromisoformat(scorecard['ts'])
            return True
        except Exception as e:
            print(f"WARNING: failed loading whois cache from local storage: {e}", file=sys.stderr)
            return False


# Valkey storage manager for cache/archive
class ValkeyStorageManager(StorageManager):

    valkey_client = None
    whois_mem_cache = {}
    whois_mem_cache_size_max = 0

    def __init__(self, whois_cache_ttl, result_archive_ttl, valkey_url, whois_mem_cache_size_max=2048):
        self.whois_cache_ttl = whois_cache_ttl
        self.result_archive_ttl = result_archive_ttl
        self.whois_mem_cache_size_max = whois_mem_cache_size_max
        # initialize valkey client if valkey url is set
        if valkey_url and valkey_url.strip() != '':
            self.valkey_client = valkey.from_url(valkey_url, decode_responses=False)
        if not self.valkey_client:
            print("ERROR: ValkeyStorageManager requires a valid Valkey URL!", file=sys.stderr)
            return None

    def can_archive(self):
        return True

    def archive_result(self, report_id, data):
        try:
            self.valkey_client.set(f"webres6:archive:{report_id}", json.dumps(data, cls=DateTimeEncoder).encode('utf-8'), ex=self.result_archive_ttl)
            return True
        except Exception as e:
            print(f"WARNING: failed archiving result {report_id} to valkey: {e}", file=sys.stderr)
            return False

    def list_archived_reports(self):
        try:
            keys = self.valkey_client.keys("webres6:archive:*")
            report_ids = [key.decode('utf-8').split(":")[-1] for key in keys]
            return report_ids
        except Exception as e:
            print(f"WARNING: failed listing archived reports from valkey: {e}", file=sys.stderr)
            return []

    def retrieve_result(self, report_id):
        try:
            cached_data = self.valkey_client.get(f"webres6:archive:{report_id}")
            if cached_data:
                data = json.loads(cached_data)
                data['ts'] = datetime.fromisoformat(data['ts'])
                return data
            else:
                return None
        except Exception as e:
            print(f"WARNING: failed retrieving archived result {report_id} from valkey: {e}", file=sys.stderr)
            return None

    def put_result_cacheline(self, cache_key, data, ttl, overwrite=True):
        try:
            self.valkey_client.set(f"webres6:cache:{cache_key}", json.dumps(data, cls=DateTimeEncoder).encode('utf-8'), ex=ttl, nx=(not overwrite))
            return True
        except Exception as e:
            print(f"WARNING: failed putting cacheline {cache_key} to valkey: {e}", file=sys.stderr)
            return False

    def delete_result_cacheline(self, cache_key):
        try:
            self.valkey_client.delete(f"webres6:cache:{cache_key}")
            return True
        except Exception as e:
            print(f"WARNING: failed deleting cacheline {cache_key} from valkey: {e}", file=sys.stderr)
            return False

    def get_result_cacheline(self, cache_key):
        try:
            cached_data = self.valkey_client.get(f"webres6:cache:{cache_key}")
            if cached_data:
                data = json.loads(cached_data)
                # understand why this may be a list
                # if isinstance(data, list):
                #    print(f"WARNING: found a list in cache for key {cache_key}, taking first element", file=sys.stderr)
                #    data = data[0]
                data['ts'] = datetime.fromisoformat(data['ts'])
                return data
            else:
                return None
        except Exception as e:
            print(f"WARNING: failed getting cacheline {cache_key} from valkey: {e}", file=sys.stderr)
            return None

    def put_whois_cacheline(self, ip, data):
        # calculate TTL based on timestamp in data
        age = datetime.now(timezone.utc) - data['ts']
        ttl = max(0, self.whois_cache_ttl - int(age.total_seconds()))
        # add to in-memory cache 
        self._put_whois_mem_cacheline(ip, data)
        # add to valkey cache
        try:
            self.valkey_client.set(f"webres6:whois:{ip}", json.dumps(data, cls=DateTimeEncoder).encode('utf-8'), ex=ttl)
            return True
        except Exception as e:
            print(f"WARNING: failed putting whois cacheline for {ip} to valkey: {e}", file=sys.stderr)
            return False

    def _put_whois_mem_cacheline(self, ip, data):
        # if cache is full, evict expired and oldest entries
        if self.whois_mem_cache_size_max == 0:
            return False
        if len(self.whois_mem_cache) >= self.whois_mem_cache_size_max:
            # just flush the cache -- re-filling it from valkey is not too expensive
            self.whois_mem_cache.clear()
        self.whois_mem_cache[ip] = data
        return True

    def get_whois_cacheline(self, ip):
        # check in-memory cache first
        if ip in self.whois_mem_cache:
            result = self.whois_mem_cache[ip]
            if datetime.now(timezone.utc) > result['ts'] + timedelta(seconds=self.whois_cache_ttl):
                del self.whois_mem_cache[ip]
            else:
                return result
        # check valkey cache next
        try:
            cached_data = self.valkey_client.get(f"webres6:whois:{ip}")
            if cached_data:
                data = json.loads(cached_data)
                data['ts'] = datetime.fromisoformat(data['ts'])
                return data
            else:
                return None
        except Exception as e:
            print(f"WARNING: failed getting whois cacheline for {ip} from valkey: {e}", file=sys.stderr)
            return None

    def whois_cache_size(self):
        return len(self.whois_mem_cache)
    
    def put_scorecard(self, scorecard):
        try:
            self.valkey_client.lpush("webres6:scorecards", json.dumps(scorecard, cls=DateTimeEncoder).encode('utf-8'))
            return True
        except Exception as e:
            print(f"WARNING: failed putting scorecard to valkey: {e}", file=sys.stderr)
            return False
        
    def get_scorecards(self, max_entries=23):
        deadline = datetime.now(timezone.utc) - timedelta(seconds=self.result_archive_ttl)
        try:
            raw_scorecards = self.valkey_client.lrange("webres6:scorecards", 0, max_entries - 1)
            scorecards = []
            for raw in raw_scorecards:
                scorecard = json.loads(raw)
                scorecard['ts'] = datetime.fromisoformat(scorecard['ts'])
                # only include non-expired scorecards
                if scorecard['ts'] > deadline:
                    scorecards.append(scorecard)
            return scorecards
        except Exception as e:
            print(f"WARNING: failed getting scorecards from valkey: {e}", file=sys.stderr)
            return []

    def _expire_scorecards(self):
        try:
            deadline = datetime.now(timezone.utc) - timedelta(seconds=self.result_archive_ttl)
            len = self.valkey_client.llen("webres6:scorecards")
            idx = len // 2
            while len > 1:
                if item := self.valkey_client.lindex("webres6:scorecards", idx):
                    scorecard = json.loads(item)
                    scorecard_ts = datetime.fromisoformat(scorecard['ts'])
                    if scorecard_ts < deadline:
                        # remove this and all older entries
                        self.valkey_client.ltrim("webres6:scorecards", idx, - 1)
                        # continue binary search in left half
                        len = len//2
                        idx -= len//2
                    else:
                        # move to right half
                        len = len//2
                        idx += len//2
                else:
                    print(f"WARNING: failed getting scorecard at index {idx} from valkey during expiry", file=sys.stderr)
                    break
            return len-idx
        except Exception as e:
            print(f"WARNING: failed expiring scorecards from valkey: {e}", file=sys.stderr)
            return None

    def expire(self):
        # Valkey handles expiration automatically via TTLs
        # only need to clear old scorecards
        return self._expire_scorecards()

class ValkeyFileHybridStorageManager(ValkeyStorageManager):
    """ Hybrid storage manager that uses Valkey for main storage
        and file system for persistence of the result archive. 
    """

    local_storage_manager = None

    def __init__(self, whois_cache_ttl, result_archive_ttl, valkey_url, archive_dir=None, whois_mem_cache_size_max=2048):
        super().__init__(whois_cache_ttl, result_archive_ttl, valkey_url, whois_mem_cache_size_max)
        if archive_dir and os.path.isdir(archive_dir):
            self.local_storage_manager = LocalStorageManager(whois_cache_ttl=whois_cache_ttl, result_archive_ttl=result_archive_ttl,
                                                              cache_dir=None, archive_dir=archive_dir)

    def can_archive(self):
        return self.local_storage_manager.can_archive()

    def archive_result(self, report_id, data):
        return self.local_storage_manager.archive_result(report_id, data)

    def list_archived_reports(self):
        return self.local_storage_manager.list_archived_reports()

    def retrieve_result(self, report_id):
        return self.local_storage_manager.retrieve_result(report_id)

    def expire(self):
        expired = super().expire()
        expired += self.local_storage_manager.expire()
        return expired


class ValkeyS3HybridStorageManager(ValkeyStorageManager):
    """ Hybrid storage manager that uses Valkey for cache and S3 for archive.
    """

    s3_client = None
    s3_bucket = None
    s3_presigned_url_expiry = 3600

    def __init__(self, whois_cache_ttl, result_archive_ttl, valkey_url, s3_bucket, s3_endpoint=None, s3_presigned_url_expiry=3600, whois_mem_cache_size_max=2048):
        super().__init__(whois_cache_ttl, result_archive_ttl, valkey_url, whois_mem_cache_size_max)
        if s3_endpoint and s3_endpoint.strip() != '':
            self.s3_client = boto3.client('s3', endpoint_url=s3_endpoint)
        else:
            self.s3_client = boto3.client('s3')
        self.s3_bucket = s3_bucket
        self.s3_presigned_url_expiry = s3_presigned_url_expiry

    def can_archive(self):
        return True

    def _make_s3_key(self, report_id):
        return f"report-{report_id}.json"

    def archive_result(self, report_id, data):
        date = datetime.now(timezone.utc) + timedelta(seconds=self.result_archive_ttl)
        try:
            self.s3_client.put_object(Bucket=self.s3_bucket, Key=self._make_s3_key(report_id),
                                      Body=json.dumps(data, cls=DateTimeEncoder).encode('utf-8'),
                                      ContentType='application/json', Expires=date)
            return True
        except Exception as e:
            print(f"WARNING: failed archiving result {report_id} to S3: {e}", file=sys.stderr)
            return False

    def list_archived_reports(self):
        try:
            response = self.s3_client.list_objects_v2(Bucket=self.s3_bucket, Prefix='report-')
            report_ids = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    key = obj['Key']
                    if key.startswith("report-") and key.endswith(".json"):
                        report_id = key[len("report-"):-len(".json")]
                        report_ids.append(report_id)
            return report_ids
        except Exception as e:
            print(f"WARNING: failed listing archived reports from S3: {e}", file=sys.stderr)
            return []

    def retrieve_result(self, report_id):
        try:
            response = self.s3_client.get_object(Bucket=self.s3_bucket, Key=self._make_s3_key(report_id))
            if 'Body' in response:
                body = response['Body'].read()
                data = json.loads(body)
                data['ts'] = datetime.fromisoformat(data['ts'])
                return data
            else:
                return None
        except Exception as e:
            print(f"WARNING: failed retrieving archived result {report_id} from S3: {e}", file=sys.stderr)
            return None

    def retrieve_result_url(self, report_id):
        try:
            response = self.s3_client.generate_presigned_url('get_object',
                                                        Params={'Bucket': self.s3_bucket, 'Key': self._make_s3_key(report_id)},
                                                        ExpiresIn=self.s3_presigned_url_expiry)
            return response
        except Exception as e:
            print(f"WARNING: failed getting presigned archive url for {report_id} from S3: {e}", file=sys.stderr)
            return None


# Scoreboard management
class Scoreboard:
    def __init__(self, storage_manager=None):
        self.storage_manager = storage_manager

    def enter(self, report):
        """ Enter a new report into the scoreboard.
            If the scoreboard exceeds max_entries, remove the oldest entry.
        """

        if report.get('error', None) is not None:
            return  # do not enter errored reports

        scorecard = {
            'report_id': report.get('ID', None),
            'ts': report.get('ts', None),
            'url': report.get('url', None),
            'domain': report.get('domain', None),
            'ipv6_only_score': report.get('ipv6_only_score', 0),
            'ipv6_only_dns_score': report.get('ipv6_only_dns_score', 0),
            'ipv6_only_http_score': report.get('ipv6_only_http_score', 0),
            'ipv6_only_ready': report.get('ipv6_only_ready', False),
        }

        return self.storage_manager.put_scorecard(scorecard)

    def get_entries(self, limit=12):
        """ Return the current scoreboard entries.
        """
        return self.storage_manager.get_scorecards(max_entries=limit)

    def export_entries(self, file=None):
        """ Export the current scoreboard entries to stdout as JSON.
        """
        entries = self.get_entries(limit=0)
        with (sys.stdout if file is None else open(file, 'w', encoding='utf-8')) as f:
            f.write(json.dumps(entries, indent=2, cls=DateTimeEncoder, ensure_ascii=False))

    def import_entries(self, file):
        """ Import scoreboard entries from the given JSON file.
        """
        with open(file, 'r', encoding='utf-8') as f:
            entries = json.load(f)
            for entry in entries:
                entry['ts'] = datetime.fromisoformat(entry['ts'])
                self.storage_manager.put_scorecard(entry)


def export_archived_reports(storage_manager, export_dir):
    """ Export all archived reports to the given directory.
    """

    if not storage_manager or not storage_manager.can_archive():
        print("Archiving is not enabled in this deployment.", file=sys.stderr)
        return False
    if not os.path.exists(export_dir):
        print(f"Export directory {export_dir} does not exist - aborting.", file=sys.stderr)
        return False
    print(f"Exporting archived reports to {export_dir}: ", file=sys.stderr, end='')
    report_ids = storage_manager.list_archived_reports()
    if not report_ids or len(report_ids) == 0:
        print("No archived reports found.", file=sys.stderr)
        return True
    export_storage_manager = LocalStorageManager(archive_dir=export_dir)
    for report_id in report_ids:
        report = storage_manager.retrieve_result(report_id)
        if not report:
            print(f"WARNING: could not retrieve report {report_id} from archive", file=sys.stderr)
            continue
        archived = export_storage_manager.archive_result(report_id, report)
        if not archived:
            print(f"\nWARNING: could not export report {report_id}", file=sys.stderr)
        else:
            print(".", file=sys.stderr, end='', flush=True)
    print(" export completed.", file=sys.stderr)
    return True


def import_archived_reports(storage_manager, import_dir):
    """ Import all archived reports from the given directory.
    """

    if not storage_manager or not storage_manager.can_archive():
        print("Archiving is not enabled in this deployment.", file=sys.stderr)
        return False
    if not os.path.exists(import_dir):
        print(f"Import directory {import_dir} does not exist - aborting.", file=sys.stderr)
        return False
    print(f"Importing archived reports from {import_dir}: ", file=sys.stderr, end='')
    import_storage_manager = LocalStorageManager(archive_dir=import_dir)
    report_ids = import_storage_manager.list_archived_reports()
    if not report_ids or len(report_ids) == 0:
        print("No archived reports found in import directory.", file=sys.stderr)
        return True
    for report_id in report_ids:
        report = import_storage_manager.retrieve_result(report_id)
        if not report:
            print(f"WARNING: could not retrieve report {report_id} from import archive", file=sys.stderr)
            continue
        archived = storage_manager.archive_result(report_id, report)
        if not archived:
            print(f"\nWARNING: could not import report {report_id}", file=sys.stderr)
        else:
            print(".", file=sys.stderr, end='', flush=True)
    print(" import completed.", file=sys.stderr)
    return True