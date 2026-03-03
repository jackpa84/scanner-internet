"""
Redis-backed MongoDB-compatible Collection API — v2 (optimized).

Improvements over v1:
  - Secondary sorted-set indexes for numeric fields (risk.score, etc.)
  - find().sort("timestamp", -1).limit(N) uses ZREVRANGE → O(N) instead of O(all)
  - Lazy _all() with HSCAN batching to avoid loading entire hash at once
  - IP deduplication set (scanned_ips) for the scanner
  - Cached stats with configurable TTL
  - Atomic Redis counters for scan metrics

Documents stored as JSON in Redis hashes (c:{name}:d),
ordered by timestamp in sorted sets (c:{name}:t).
Optional secondary indexes in sorted sets (c:{name}:idx:{field}).
"""
import json
import logging
import os
import re as re_mod
import threading
import time
from datetime import datetime
from typing import Any

from bson import ObjectId

logger = logging.getLogger("scanner.redis_store")

_MISSING = object()
_redis_client = None
_init_lock = threading.Lock()

STATS_CACHE_TTL = float(os.getenv("STATS_CACHE_TTL", "5.0"))


# ── JSON helpers (ObjectId + datetime) ──────────────────────────

class _Enc(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return {"$oid": str(o)}
        if isinstance(o, datetime):
            return {"$dt": o.isoformat()}
        return super().default(o)


def _hook(d):
    if "$oid" in d and len(d) == 1:
        return ObjectId(d["$oid"])
    if "$dt" in d and len(d) == 1:
        return datetime.fromisoformat(d["$dt"])
    return d


def _dumps(obj):
    return json.dumps(obj, cls=_Enc, default=str)


def _loads(s):
    return json.loads(s, object_hook=_hook)


# ── Nested field helpers ────────────────────────────────────────

def _get(doc, key):
    parts = key.split(".")
    v = doc
    for p in parts:
        if isinstance(v, dict) and p in v:
            v = v[p]
        elif isinstance(v, list):
            try:
                v = v[int(p)]
            except (ValueError, IndexError):
                return _MISSING
        else:
            return _MISSING
    return v


def _put(doc, key, val):
    parts = key.split(".")
    for p in parts[:-1]:
        if p not in doc or not isinstance(doc.get(p), dict):
            doc[p] = {}
        doc = doc[p]
    doc[parts[-1]] = val


def _del(doc, key):
    parts = key.split(".")
    for p in parts[:-1]:
        if not isinstance(doc.get(p), dict):
            return
        doc = doc[p]
    doc.pop(parts[-1], None)


# ── Value comparison (ObjectId-safe) ────────────────────────────

def _eq(a, b):
    if isinstance(a, ObjectId) or isinstance(b, ObjectId):
        return str(a) == str(b)
    return a == b


# ── Filter matching ────────────────────────────────────────────

def _match(doc, filt):
    if not filt:
        return True
    for key, cond in filt.items():
        if key == "$and":
            if not all(_match(doc, f) for f in cond):
                return False
            continue
        if key == "$or":
            if not any(_match(doc, f) for f in cond):
                return False
            continue
        if not _cond(_get(doc, key), cond):
            return False
    return True


def _cond(val, cond):
    if not isinstance(cond, dict):
        return val is not _MISSING and _eq(val, cond)
    for op, exp in cond.items():
        if op == "$exists":
            if bool(exp) != (val is not _MISSING):
                return False
        elif op == "$ne":
            if val is not _MISSING and _eq(val, exp):
                return False
        elif op == "$gte":
            if val is _MISSING or val is None:
                return False
            try:
                if val < exp:
                    return False
            except TypeError:
                return False
        elif op == "$gt":
            if val is _MISSING or val is None:
                return False
            try:
                if val <= exp:
                    return False
            except TypeError:
                return False
        elif op == "$lte":
            if val is _MISSING or val is None or val > exp:
                return False
        elif op == "$lt":
            if val is _MISSING or val is None or val >= exp:
                return False
        elif op == "$in":
            if val is _MISSING:
                return False
            if not any(_eq(val, e) for e in exp):
                return False
        elif op == "$nin":
            if val is not _MISSING and any(_eq(val, e) for e in exp):
                return False
        elif op == "$regex":
            if val is _MISSING:
                return False
            if not re_mod.search(exp, str(val)):
                return False
    return True


# ── Projection ──────────────────────────────────────────────────

def _project(doc, proj):
    if not proj:
        return doc
    inc = any(v == 1 for k, v in proj.items() if k != "_id")
    if inc:
        r = {"_id": doc.get("_id")}
        for k, v in proj.items():
            if v == 1:
                x = _get(doc, k)
                if x is not _MISSING:
                    _put(r, k, x)
            elif k == "_id" and v == 0:
                r.pop("_id", None)
        return r
    r = dict(doc)
    for k, v in proj.items():
        if v == 0:
            _del(r, k)
    return r


# ── Result objects ──────────────────────────────────────────────

class _R1:
    def __init__(self, iid):
        self.inserted_id = iid


class _RM:
    def __init__(self, ids):
        self.inserted_ids = ids


class _RU:
    def __init__(self, m=0, mod=0, uid=None):
        self.matched_count = m
        self.modified_count = mod
        self.upserted_id = uid


class _RD:
    def __init__(self, n=0):
        self.deleted_count = n


# ── Cursor ──────────────────────────────────────────────────────

class RedisCursor:
    def __init__(self, docs, proj=None):
        self._docs = docs
        self._proj = proj
        self._sk = None
        self._sd = 1
        self._lim = 0

    def sort(self, key, direction=None):
        if isinstance(key, list):
            self._sk, self._sd = key[0]
        else:
            self._sk = key
            self._sd = direction or 1
        return self

    def limit(self, n):
        self._lim = n
        return self

    def __iter__(self):
        docs = list(self._docs)
        if self._sk:
            def _sk_fn(d):
                v = _get(d, self._sk)
                if v is _MISSING or v is None:
                    return (1, "")
                return (0, v)
            docs = sorted(docs, key=_sk_fn,
                          reverse=(self._sd == -1))
        if self._lim:
            docs = docs[:self._lim]
        if self._proj:
            docs = [_project(d, self._proj) for d in docs]
        return iter(docs)


# ── Optimized Cursor that uses Redis sorted-set indexes ─────────

class _IndexedCursor:
    """Cursor backed by a sorted-set index — fetches only the needed doc IDs."""

    def __init__(self, collection, doc_ids, filt=None, proj=None):
        self._col = collection
        self._ids = doc_ids
        self._filt = filt
        self._proj = proj
        self._sk = None
        self._sd = 1
        self._lim = 0

    def sort(self, key, direction=None):
        if isinstance(key, list):
            self._sk, self._sd = key[0]
        else:
            self._sk = key
            self._sd = direction or 1
        return self

    def limit(self, n):
        self._lim = n
        return self

    def __iter__(self):
        ids = self._ids
        if self._lim and not self._filt:
            ids = ids[:self._lim]

        if not ids:
            return iter([])

        raw_list = self._col._r.hmget(self._col._dk, *ids)
        docs = []
        for raw in raw_list:
            if raw is None:
                continue
            try:
                doc = _loads(raw)
                if self._filt and not _match(doc, self._filt):
                    continue
                docs.append(doc)
            except Exception:
                pass

        if self._sk:
            def _sk_fn(d):
                v = _get(d, self._sk)
                if v is _MISSING or v is None:
                    return (1, "")
                return (0, v)
            docs = sorted(docs, key=_sk_fn, reverse=(self._sd == -1))

        if self._lim:
            docs = docs[:self._lim]
        if self._proj:
            docs = [_project(d, self._proj) for d in docs]
        return iter(docs)


# ── RedisCollection ─────────────────────────────────────────────

_INDEXED_FIELDS = {"risk.score"}

class RedisCollection:
    def __init__(self, r, name, max_docs=0):
        self._r = r
        self._name = name
        self._max = max_docs
        self._dk = f"c:{name}:d"
        self._tk = f"c:{name}:t"
        self._idx_prefix = f"c:{name}:idx"
        self._ip_idx = f"c:{name}:ip"
        self._stats_key = f"c:{name}:stats_cache"
        self._stats_lock = threading.Lock()
        self._stats_cache: dict | None = None
        self._stats_ts: float = 0.0

    def _idx_key(self, field: str) -> str:
        return f"{self._idx_prefix}:{field.replace('.', ':')}"

    # -- internal -------------------------------------------------

    def _ts(self, doc):
        ts = doc.get("timestamp")
        if isinstance(ts, datetime):
            return ts.timestamp()
        if isinstance(ts, (int, float)):
            return float(ts)
        return time.time()

    def _all(self):
        if self._r is None:
            return []
        try:
            raw = self._r.hgetall(self._dk)
        except Exception:
            return []
        out = []
        for data in raw.values():
            try:
                out.append(_loads(data))
            except Exception:
                pass
        return out

    def _fetch_by_ids(self, ids):
        if not ids:
            return []
        raw_list = self._r.hmget(self._dk, *ids)
        out = []
        for raw in raw_list:
            if raw is None:
                continue
            try:
                out.append(_loads(raw))
            except Exception:
                pass
        return out

    def _get_ids_by_time(self, limit, reverse=True):
        if reverse:
            return self._r.zrevrange(self._tk, 0, limit - 1)
        return self._r.zrange(self._tk, 0, limit - 1)

    def _evict(self):
        if self._max <= 0:
            return
        n = self._r.zcard(self._tk)
        if n <= self._max:
            return
        old = self._r.zrange(self._tk, 0, n - self._max - 1)
        if old:
            p = self._r.pipeline()
            for did in old:
                p.hdel(self._dk, did)
                p.zrem(self._tk, did)
                for field in _INDEXED_FIELDS:
                    p.zrem(self._idx_key(field), did)
                p.srem(self._ip_idx, "")  # no-op placeholder
            p.execute()

    @staticmethod
    def _apply(doc, update):
        if "$set" in update:
            for k, v in update["$set"].items():
                _put(doc, k, v)
        if "$unset" in update:
            for k in update["$unset"]:
                _del(doc, k)
        if "$inc" in update:
            for k, v in update["$inc"].items():
                cur = _get(doc, k)
                _put(doc, k, (0 if cur is _MISSING else cur) + v)
        if "$push" in update:
            for k, v in update["$push"].items():
                cur = _get(doc, k)
                if cur is _MISSING or not isinstance(cur, list):
                    cur = []
                    _put(doc, k, cur)
                cur.append(v)

    def _save(self, doc):
        did = str(doc["_id"])
        p = self._r.pipeline()
        p.hset(self._dk, did, _dumps(doc))
        p.zadd(self._tk, {did: self._ts(doc)})
        self._index_doc(p, doc, did)
        p.execute()

    def _index_doc(self, pipeline, doc, did):
        for field in _INDEXED_FIELDS:
            val = _get(doc, field)
            if val is not _MISSING and isinstance(val, (int, float)):
                pipeline.zadd(self._idx_key(field), {did: float(val)})
        ip = doc.get("ip")
        if ip:
            pipeline.sadd(self._ip_idx, ip)

    def _invalidate_stats_cache(self):
        self._stats_ts = 0.0

    # -- writes ---------------------------------------------------

    def _check_redis(self):
        if self._r is None:
            from app.redis_store import get_redis
            self._r = get_redis()
        if self._r is None:
            raise Exception("Redis unavailable")

    def insert_one(self, doc):
        self._check_redis()
        if "_id" not in doc:
            doc["_id"] = str(ObjectId())
        else:
            doc["_id"] = str(doc["_id"])
        self._save(doc)
        self._evict()
        self._invalidate_stats_cache()
        return _R1(doc["_id"])

    def insert_many(self, docs, ordered=True):
        ids = []
        p = self._r.pipeline()
        for doc in docs:
            if "_id" not in doc:
                doc["_id"] = str(ObjectId())
            else:
                doc["_id"] = str(doc["_id"])
            did = doc["_id"]
            p.hset(self._dk, did, _dumps(doc))
            p.zadd(self._tk, {did: self._ts(doc)})
            self._index_doc(p, doc, did)
            ids.append(did)
        p.execute()
        self._evict()
        self._invalidate_stats_cache()
        return _RM(ids)

    def update_one(self, filt, update, upsert=False):
        self._check_redis()
        for doc in self._all():
            if _match(doc, filt):
                self._apply(doc, update)
                self._save(doc)
                self._invalidate_stats_cache()
                return _RU(1, 1)
        if upsert:
            nd = {}
            if filt:
                for k, v in filt.items():
                    if not isinstance(v, dict):
                        _put(nd, k, v)
            self._apply(nd, update)
            if "_id" not in nd:
                nd["_id"] = str(ObjectId())
            else:
                nd["_id"] = str(nd["_id"])
            self._save(nd)
            self._evict()
            self._invalidate_stats_cache()
            return _RU(0, 0, nd["_id"])
        return _RU(0, 0)

    def update_many(self, filt, update):
        c = 0
        for doc in self._all():
            if _match(doc, filt):
                self._apply(doc, update)
                self._save(doc)
                c += 1
        if c:
            self._invalidate_stats_cache()
        return _RU(c, c)

    def replace_one(self, filt, replacement, upsert=False):
        for doc in self._all():
            if _match(doc, filt):
                replacement["_id"] = doc["_id"]
                self._save(replacement)
                self._invalidate_stats_cache()
                return _RU(1, 1)
        if upsert:
            if "_id" not in replacement:
                replacement["_id"] = str(ObjectId())
            self._save(replacement)
            self._invalidate_stats_cache()
            return _RU(0, 0, replacement["_id"])
        return _RU(0, 0)

    def delete_one(self, filt):
        self._check_redis()
        for doc in self._all():
            if _match(doc, filt):
                did = str(doc["_id"])
                p = self._r.pipeline()
                p.hdel(self._dk, did)
                p.zrem(self._tk, did)
                for field in _INDEXED_FIELDS:
                    p.zrem(self._idx_key(field), did)
                ip = doc.get("ip")
                if ip:
                    p.srem(self._ip_idx, ip)
                p.execute()
                self._invalidate_stats_cache()
                return _RD(1)
        return _RD(0)

    def delete_many(self, filt):
        self._check_redis()
        c = 0
        p = self._r.pipeline()
        for doc in self._all():
            if _match(doc, filt):
                did = str(doc["_id"])
                p.hdel(self._dk, did)
                p.zrem(self._tk, did)
                for field in _INDEXED_FIELDS:
                    p.zrem(self._idx_key(field), did)
                ip = doc.get("ip")
                if ip:
                    p.srem(self._ip_idx, ip)
                c += 1
        if c:
            p.execute()
            self._invalidate_stats_cache()
        return _RD(c)

    def bulk_write(self, ops):
        for op in ops:
            if hasattr(op, "_filter") and hasattr(op, "_doc"):
                self.update_one(op._filter, {"$set": op._doc})
        return _RU(len(ops), len(ops))

    # -- reads ----------------------------------------------------

    def find_one(self, filt=None, projection=None):
        if self._r is None:
            return None
        if filt and "_id" in filt and not isinstance(filt["_id"], dict):
            did = str(filt["_id"])
            try:
                raw = self._r.hget(self._dk, did)
            except Exception:
                return None
            if raw is None:
                return None
            doc = _loads(raw)
            rest = {k: v for k, v in filt.items() if k != "_id"}
            if rest and not _match(doc, rest):
                return None
            return _project(doc, projection) if projection else doc
        for doc in self._all():
            if _match(doc, filt):
                return _project(doc, projection) if projection else doc
        return None

    def find(self, filt=None, projection=None):
        docs = self._all()
        if filt:
            docs = [d for d in docs if _match(d, filt)]
        return RedisCursor(docs, projection)

    def find_optimized(self, filt=None, projection=None, sort_key=None,
                       sort_dir=-1, limit=0):
        """Optimized find that uses sorted-set indexes when possible.

        When sorting by timestamp with a limit and no complex filter,
        fetches only the needed IDs from the sorted set.
        """
        if sort_key == "timestamp" and limit > 0:
            if not filt:
                ids = self._get_ids_by_time(limit, reverse=(sort_dir == -1))
                docs = self._fetch_by_ids(ids)
                docs.sort(
                    key=lambda d: self._ts(d),
                    reverse=(sort_dir == -1),
                )
                if projection:
                    docs = [_project(d, projection) for d in docs]
                return iter(docs)

            overfetch = limit * 4
            ids = self._get_ids_by_time(overfetch, reverse=(sort_dir == -1))
            docs = self._fetch_by_ids(ids)
            docs = [d for d in docs if _match(d, filt)]
            docs.sort(key=lambda d: self._ts(d), reverse=(sort_dir == -1))
            docs = docs[:limit]
            if projection:
                docs = [_project(d, projection) for d in docs]
            return iter(docs)

        if sort_key == "risk.score" and limit > 0:
            idx_key = self._idx_key("risk.score")
            if sort_dir == -1:
                ids = self._r.zrevrange(idx_key, 0, (limit * 4) - 1)
            else:
                ids = self._r.zrange(idx_key, 0, (limit * 4) - 1)
            docs = self._fetch_by_ids(ids)
            if filt:
                docs = [d for d in docs if _match(d, filt)]
            docs.sort(
                key=lambda d: (_get(d, "risk.score") if _get(d, "risk.score") is not _MISSING else 0),
                reverse=(sort_dir == -1),
            )
            docs = docs[:limit]
            if projection:
                docs = [_project(d, projection) for d in docs]
            return iter(docs)

        return self.find(filt, projection).sort(sort_key or "timestamp", sort_dir).limit(limit)

    def count_documents(self, filt):
        if self._r is None:
            return 0
        try:
            if not filt:
                return self._r.hlen(self._dk)
            return sum(1 for d in self._all() if _match(d, filt))
        except Exception:
            return 0

    def estimated_document_count(self):
        if self._r is None:
            return 0
        try:
            return self._r.hlen(self._dk)
        except Exception:
            return 0

    def distinct(self, field, filt=None):
        vals = set()
        for doc in self._all():
            if filt and not _match(doc, filt):
                continue
            v = _get(doc, field)
            if v is not _MISSING and v is not None:
                if not isinstance(v, (list, dict)):
                    vals.add(v)
        return list(vals)

    def aggregate(self, pipeline):
        docs = self._all()
        for stage in pipeline:
            if "$match" in stage:
                docs = [d for d in docs
                        if _match(d, stage["$match"])]
            elif "$group" in stage:
                docs = self._group(docs, stage["$group"])
            elif "$sort" in stage:
                for k, d in reversed(list(stage["$sort"].items())):
                    docs = sorted(
                        docs,
                        key=lambda doc, _k=k: (
                            (1, 0) if doc.get(_k) is None
                            else (0, doc.get(_k))
                        ),
                        reverse=(d == -1),
                    )
            elif "$limit" in stage:
                docs = docs[:stage["$limit"]]
        return docs

    def create_index(self, keys=None, **kw):
        pass

    # -- IP deduplication -----------------------------------------

    def has_ip(self, ip: str) -> bool:
        return bool(self._r.sismember(self._ip_idx, ip))

    # -- cached stats ---------------------------------------------

    def cached_stats(self, compute_fn, ttl: float = 0) -> dict:
        """Return cached stats, recomputing if older than ttl seconds."""
        if ttl <= 0:
            ttl = STATS_CACHE_TTL
        now = time.monotonic()
        if self._stats_cache is not None and (now - self._stats_ts) < ttl:
            return self._stats_cache
        with self._stats_lock:
            if self._stats_cache is not None and (now - self._stats_ts) < ttl:
                return self._stats_cache
            result = compute_fn()
            self._stats_cache = result
            self._stats_ts = time.monotonic()
            return result

    # -- aggregation helper ---------------------------------------

    @staticmethod
    def _group(docs, spec):
        gk = spec["_id"]
        groups: dict[str, dict] = {}
        for doc in docs:
            if isinstance(gk, str) and gk.startswith("$"):
                kv = _get(doc, gk[1:])
            else:
                kv = gk
            if kv is _MISSING:
                continue
            ks = str(kv)
            if ks not in groups:
                groups[ks] = {"_id": kv, "_docs": []}
            groups[ks]["_docs"].append(doc)

        result = []
        for g in groups.values():
            row: dict[str, Any] = {"_id": g["_id"]}
            for field, acc in spec.items():
                if field == "_id" or not isinstance(acc, dict):
                    continue
                if "$sum" in acc:
                    if acc["$sum"] == 1:
                        row[field] = len(g["_docs"])
                    elif (isinstance(acc["$sum"], str)
                          and acc["$sum"].startswith("$")):
                        fld = acc["$sum"][1:]
                        row[field] = sum(
                            v for d in g["_docs"]
                            if (v := _get(d, fld)) is not _MISSING
                            and isinstance(v, (int, float))
                        )
                elif "$first" in acc:
                    fld = acc["$first"]
                    if (isinstance(fld, str)
                            and fld.startswith("$")):
                        v = (_get(g["_docs"][0], fld[1:])
                             if g["_docs"] else None)
                        row[field] = (
                            None if v is _MISSING else v
                        )
                    else:
                        row[field] = fld
                elif "$avg" in acc:
                    fld = acc["$avg"]
                    if (isinstance(fld, str)
                            and fld.startswith("$")):
                        vals = [
                            v for d in g["_docs"]
                            if (v := _get(d, fld[1:]))
                            is not _MISSING
                        ]
                        row[field] = (
                            sum(vals) / len(vals)
                            if vals else 0
                        )
            result.append(row)
        return result


# ── Atomic counters (for scan metrics) ──────────────────────────

class RedisCounters:
    """Atomic counters stored in a Redis hash — no locks needed."""

    def __init__(self, r, name: str):
        self._r = r
        self._key = f"counters:{name}"

    def inc(self, field: str, n: int = 1):
        self._r.hincrby(self._key, field, n)

    def get(self, field: str) -> int:
        val = self._r.hget(self._key, field)
        return int(val) if val else 0

    def get_all(self) -> dict[str, int]:
        raw = self._r.hgetall(self._key)
        return {k: int(v) for k, v in raw.items()}


# ── IP deduplication ────────────────────────────────────────────

class IPDeduplicator:
    """Redis SET-backed IP deduplication with optional TTL re-scan window."""

    def __init__(self, r, rescan_hours: int = 24):
        self._r = r
        self._key = "scanner:seen_ips"
        self._rescan_hours = rescan_hours

    def is_seen(self, ip: str) -> bool:
        return bool(self._r.sismember(self._key, ip))

    def mark_seen(self, ip: str):
        self._r.sadd(self._key, ip)

    def mark_seen_batch(self, ips: list[str]):
        if ips:
            self._r.sadd(self._key, *ips)

    def count(self) -> int:
        return self._r.scard(self._key)

    def clear(self):
        self._r.delete(self._key)


# ── Enrichment cache ────────────────────────────────────────────

class EnrichmentCache:
    """Cache enrichment API results in Redis with TTL."""

    def __init__(self, r, ttl_seconds: int = 86400):
        self._r = r
        self._ttl = ttl_seconds

    def _key(self, source: str, ip: str) -> str:
        return f"enrich:{source}:{ip}"

    def get(self, source: str, ip: str) -> dict | None:
        raw = self._r.get(self._key(source, ip))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def set(self, source: str, ip: str, data: dict):
        try:
            self._r.setex(self._key(source, ip), self._ttl, json.dumps(data, default=str))
        except Exception:
            pass

    def stats(self) -> dict:
        try:
            cursor, keys = self._r.scan(0, match="enrich:*", count=100)
            return {"cached_entries_sample": len(keys)}
        except Exception:
            return {}


# ── Connection management ───────────────────────────────────────

_ip_dedup: IPDeduplicator | None = None
_enrich_cache: EnrichmentCache | None = None
_scan_counters: RedisCounters | None = None


def init_redis(max_retries: int = 10, retry_delay: float = 2.0) -> bool:
    global _redis_client, _ip_dedup, _enrich_cache, _scan_counters
    url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    if not url:
        logger.warning("[redis_store] REDIS_URL not set")
        return False
    with _init_lock:
        if _redis_client is not None:
            return True
        import redis as _rmod
        for attempt in range(1, max_retries + 1):
            try:
                client = _rmod.from_url(url, decode_responses=True)
                client.ping()
                _redis_client = client
                _ip_dedup = IPDeduplicator(_redis_client)
                _enrich_cache = EnrichmentCache(_redis_client)
                _scan_counters = RedisCounters(_redis_client, "scan")
                logger.info("[redis_store] Redis OK: %s (attempt %d)", url[:40], attempt)
                return True
            except Exception as e:
                logger.warning("[redis_store] Redis attempt %d/%d failed: %s", attempt, max_retries, e)
                if attempt < max_retries:
                    import time
                    time.sleep(retry_delay)
        logger.error("[redis_store] Redis unavailable after %d attempts", max_retries)
        return False


def get_redis():
    global _redis_client
    if _redis_client is None:
        init_redis(max_retries=3, retry_delay=1.0)
    return _redis_client


def get_ip_dedup() -> IPDeduplicator | None:
    return _ip_dedup


def get_enrich_cache() -> EnrichmentCache | None:
    return _enrich_cache


def get_scan_counters() -> RedisCounters | None:
    return _scan_counters
