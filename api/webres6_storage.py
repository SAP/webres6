#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import math
import os
import sys
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address
import redis

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

    def retrieve_result(self, report_id):
        pass

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
    max_scorecards = 0
    scorecards = []

    def __init__(self, whois_cache_ttl, result_archive_ttl, cache_dir=None, max_scorecards=128):
        self.whois_cache_ttl = whois_cache_ttl
        self.result_archive_ttl = result_archive_ttl
        if cache_dir and os.path.isdir(cache_dir):
            self.local_cache_dir = cache_dir
            print(f"local cache dir \"{cache_dir}\" exists\nenabling result archive and cache-persist", file=sys.stderr)
            self._load()
        else:
            print(f"local cache dir \"{cache_dir}\" does not exist\ndeactivating result archive and cache-persist", file=sys.stderr)
        self.max_scorecards = max_scorecards
        # warn about limitations
        print("WARNING: LocalStorageManager is not suitable for production use!", file=sys.stderr)
        print("         - No multi-instance synchronization", file=sys.stderr)
        print("         - Use /admin/persist to manually persists cache", file=sys.stderr)
        print("         - Use /admin/expire to manually expire cache", file=sys.stderr)
        print("         - Consider setting up a cron job to expire archive files", file=sys.stderr)

    def can_archive(self):
        return self.local_cache_dir is not None

    def archive_result(self, report_id, data):
        if not self.local_cache_dir:
            return False
        try:
            file = os.path.join(self.local_cache_dir, f"report-{report_id}.json")
            with open(file, 'w', encoding='utf-8') as f:
                json.dump(data, f, cls=DateTimeEncoder, ensure_ascii=False)
                f.close()
            return True
        except Exception as e:
            print(f"WARNING: failed archiving result {report_id} to local cache: {e}", file=sys.stderr)
            return False

    def retrieve_result(self, report_id):
        if not self.local_cache_dir:
            return None
        try:
            file = os.path.join(self.local_cache_dir, f"report-{report_id}.json")
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

    def get_scorecards(self, max_entries=None):
        if max_entries is None or max_entries >= len(self.scorecards):
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
        expired_count = 0
        # expire old result cache entries
        now = datetime.now(timezone.utc)
        for key in [key for key in self.result_cache.keys() if now > self.result_cache[key]['expiry']]:
            del self.result_cache[key]
            expired_count += 1
        # expire old whois cache entries
        threshold = now - timedelta(seconds=self.whois_cache_ttl)
        for key in [key for key in self.whois_cache.keys() if self.whois_cache[key]['ts'] < threshold]:
            del self.whois_cache[key]
            expired_count += 1
        return expired_count

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


# Redis storage manager for cache/archive
class RedisStorageManager(StorageManager):

    redis_client = None
    whois_mem_cache = {}
    whois_mem_cache_size_max = 0

    def __init__(self, whois_cache_ttl, result_archive_ttl, redis_url, whois_mem_cache_size_max=2048):
        self.whois_cache_ttl = whois_cache_ttl
        self.result_archive_ttl = result_archive_ttl
        self.whois_mem_cache_size_max = whois_mem_cache_size_max
        # initialize redis client if redis url is set
        if redis_url and redis_url.strip() != '':
            self.redis_client = redis.from_url(redis_url, decode_responses=False)
        if not self.redis_client:
            print("ERROR: RedisStorageManager requires a valid Redis URL!", file=sys.stderr)
            return None

    def can_archive(self):
        return True

    def archive_result(self, report_id, data):
        try:
            self.redis_client.set(f"webres6:archive:{report_id}", json.dumps(data, cls=DateTimeEncoder).encode('utf-8'), ex=self.result_archive_ttl)
            return True
        except Exception as e:
            print(f"WARNING: failed archiving result {report_id} to redis: {e}", file=sys.stderr)
            return False

    def retrieve_result(self, report_id):
        try:
            cached_data = self.redis_client.get(f"webres6:archive:{report_id}")
            if cached_data:
                data = json.loads(cached_data)
                return data
            else:
                return None
        except Exception as e:
            print(f"WARNING: failed retrieving archived result {report_id} from redis: {e}", file=sys.stderr)
            return None

    def put_result_cacheline(self, cache_key, data, ttl, overwrite=True):
        try:
            self.redis_client.set(f"webres6:cache:{cache_key}", json.dumps(data, cls=DateTimeEncoder).encode('utf-8'), ex=ttl, nx=(not overwrite))
            return True
        except Exception as e:
            print(f"WARNING: failed putting cacheline {cache_key} to redis: {e}", file=sys.stderr)
            return False

    def delete_result_cacheline(self, cache_key):
        try:
            self.redis_client.delete(f"webres6:cache:{cache_key}")
            return True
        except Exception as e:
            print(f"WARNING: failed deleting cacheline {cache_key} from redis: {e}", file=sys.stderr)
            return False

    def get_result_cacheline(self, cache_key):
        try:
            cached_data = self.redis_client.get(f"webres6:cache:{cache_key}")
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
            print(f"WARNING: failed getting cacheline {cache_key} from redis: {e}", file=sys.stderr)
            return None

    def put_whois_cacheline(self, ip, data):
        # calculate TTL based on timestamp in data
        age = datetime.now(timezone.utc) - data['ts']
        ttl = max(0, self.whois_cache_ttl - int(age.total_seconds()))
        # add to in-memory cache 
        self._put_whois_mem_cacheline(ip, data)
        # add to redis cache
        try:
            self.redis_client.set(f"webres6:whois:{ip}", json.dumps(data, cls=DateTimeEncoder).encode('utf-8'), ex=ttl)
            return True
        except Exception as e:
            print(f"WARNING: failed putting whois cacheline for {ip} to redis: {e}", file=sys.stderr)
            return False

    def _put_whois_mem_cacheline(self, ip, data):
        # if cache is full, evict expired and oldest entries
        if self.whois_mem_cache_size_max == 0:
            return False
        if len(self.whois_mem_cache) >= self.whois_mem_cache_size_max:
            # just flush the cache -- re-filling it from redis is not too expensive
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
        # check redis cache next
        try:
            cached_data = self.redis_client.get(f"webres6:whois:{ip}")
            if cached_data:
                data = json.loads(cached_data)
                data['ts'] = datetime.fromisoformat(data['ts'])
                return data
            else:
                return None
        except Exception as e:
            print(f"WARNING: failed getting whois cacheline for {ip} from redis: {e}", file=sys.stderr)
            return None

    def whois_cache_size(self):
        return len(self.whois_mem_cache)
    
    def put_scorecard(self, scorecard):
        try:
            self.redis_client.lpush("webres6:scorecards", json.dumps(scorecard, cls=DateTimeEncoder).encode('utf-8'))
            return True
        except Exception as e:
            print(f"WARNING: failed putting scorecard to redis: {e}", file=sys.stderr)
            return False
        
    def get_scorecards(self, max_entries=23):
        deadline = datetime.now(timezone.utc) - timedelta(self.result_archive_ttl)
        try:
            raw_scorecards = self.redis_client.lrange("webres6:scorecards", 0, max_entries - 1)
            scorecards = []
            for raw in raw_scorecards:
                scorecard = json.loads(raw)
                scorecard['ts'] = datetime.fromisoformat(scorecard['ts'])
                # only include non-expired scorecards
                if scorecard['ts'] > deadline:
                    scorecards.append(scorecard)
            return scorecards
        except Exception as e:
            print(f"WARNING: failed getting scorecards from redis: {e}", file=sys.stderr)
            return []

    def _expire_scorecards(self):
        try:
            deadline = datetime.now(timezone.utc) - timedelta(self.result_archive_ttl)
            len = self.redis_client.llen("webres6:scorecards")
            idx = len // 2
            while len > 1:
                if item := self.redis_client.lindex("webres6:scorecards", idx):
                    scorecard = json.loads(item)
                    scorecard_ts = datetime.fromisoformat(scorecard['ts'])
                    if scorecard_ts < deadline:
                        # remove this and all older entries
                        self.redis_client.ltrim("webres6:scorecards", idx, - 1)
                        # continue binary search in left half
                        len = len//2
                        idx -= len//2
                    else:
                        # move to right half
                        len = len//2
                        idx += len//2
                else:
                    print(f"WARNING: failed getting scorecard at index {idx} from redis during expiry", file=sys.stderr)
                    break
        except Exception as e:
            print(f"WARNING: failed expiring scorecards from redis: {e}", file=sys.stderr)

    def expire(self):
        # Redis handles expiration automatically via TTLs
        # only need to clear old scorecards
        self._expire_scorecards()


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
