"""Acesso a dados: Redis (primary) + MongoDB (optional, reports)."""
import logging
import os

from pymongo import MongoClient
from pymongo.errors import (
    ConnectionFailure,
    ServerSelectionTimeoutError,
)

from app.redis_store import RedisCollection, init_redis, get_redis

MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://admin:admin%40321@34.193.59.58:27017"
    "/admin?authSource=admin",
)

logger = logging.getLogger("scanner.db")

_client = None
_mongodb_ok = False


# ── MongoDB (optional — only for final report persistence) ──────

def get_client():
    global _client
    if _client is None:
        _client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=3000,
            socketTimeoutMS=10000,
            retryWrites=True,
            maxPoolSize=10,
        )
    return _client


def get_mongodb_reports():
    """MongoDB collection for HackerOne report persistence."""
    if not _mongodb_ok:
        return None
    try:
        return get_client().get_default_database()["reports"]
    except Exception:
        return None


# ── Redis-backed collections (primary) ──────────────────────────

def get_scan_results():
    return RedisCollection(get_redis(), "scan_results", max_docs=5000)


def get_vuln_results():
    return RedisCollection(get_redis(), "vuln_results", max_docs=2000)


def get_bounty_programs():
    return RedisCollection(get_redis(), "bounty_programs")


def get_bounty_targets():
    return RedisCollection(get_redis(), "bounty_targets")


def get_bounty_changes():
    return RedisCollection(
        get_redis(), "bounty_changes", max_docs=1000,
    )


def get_submitted_reports():
    return RedisCollection(get_redis(), "submitted_reports", max_docs=500)


# ── init ────────────────────────────────────────────────────────

def init_db():
    """Init Redis (required) and try MongoDB (optional)."""
    global _mongodb_ok

    if not init_redis():
        logger.error("[DB] Redis unavailable")
        return

    try:
        get_client().admin.command("ping")
        _mongodb_ok = True
        logger.info("[DB] MongoDB OK (reports)")
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        _mongodb_ok = False
        logger.warning(
            "[DB] MongoDB off (%s) — Redis only",
            str(e)[:80],
        )
    except Exception as e:
        _mongodb_ok = False
        logger.warning("[DB] MongoDB off (%s)", str(e)[:80])

    # create_index = no-op on Redis, kept for compat
    col = get_scan_results()
    col.create_index("timestamp", name="idx_timestamp")
    col.create_index("ip", name="idx_ip", unique=False)
    col.create_index("risk.score", name="idx_risk_score")
    col.create_index("vulns", name="idx_vulns")
    col.create_index("geo.country", name="idx_geo_country")
    col.create_index(
        "threat_intel.known_threat",
        name="idx_threat", sparse=True,
    )
    col.create_index(
        "network.proxy", name="idx_proxy", sparse=True,
    )

    vcol = get_vuln_results()
    vcol.create_index("ip", name="vidx_ip")
    vcol.create_index("severity", name="vidx_severity")
    vcol.create_index("template_id", name="vidx_template")
    vcol.create_index("timestamp", name="vidx_timestamp")
    vcol.create_index(
        "scan_result_id", name="vidx_scan_ref", sparse=True,
    )
    vcol.create_index("tool", name="vidx_tool")

    bcol = get_bounty_programs()
    bcol.create_index("name", name="bidx_name")
    bcol.create_index("platform", name="bidx_platform")
    bcol.create_index("status", name="bidx_status")

    tcol = get_bounty_targets()
    tcol.create_index("program_id", name="tidx_program")
    tcol.create_index("domain", name="tidx_domain")
    tcol.create_index(
        [("program_id", 1), ("domain", 1)],
        name="tidx_prog_domain", unique=True,
    )
    tcol.create_index("alive", name="tidx_alive")
    tcol.create_index("status", name="tidx_status")
    tcol.create_index("is_new", name="tidx_is_new", sparse=True)

    ccol = get_bounty_changes()
    ccol.create_index("program_id", name="cidx_program")
    ccol.create_index("timestamp", name="cidx_timestamp")

    rcol = get_submitted_reports()
    rcol.create_index("program_id", name="ridx_program")
    rcol.create_index("target_id", name="ridx_target")
    rcol.create_index("timestamp", name="ridx_timestamp")
    rcol.create_index("status", name="ridx_status")

    logger.info(
        "[DB] Storage ready: Redis primary | MongoDB %s",
        "OK" if _mongodb_ok else "OFF",
    )
