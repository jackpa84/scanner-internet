"""
Gap 1: Bounty Program Targeting (v2) - Redis-first Architecture

Pipeline Redis → Pub/Sub → MongoDB:
  1. IP matching results saved to Redis cache first (fast)
  2. Pub/Sub notifications for real-time frontend updates
  3. Background workers process important data → MongoDB
  4. Frontend subscribes to channels for live updates

Architecture:
  - Redis: Primary cache, queues, sessions
  - Pub/Sub: Real-time notifications (programs:matched, vulns:enriched, reports:filtered)
  - MongoDB: Persistent storage (important matches, reports ready for H1)
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any

from app.database import (
    get_bounty_programs, get_scan_results, get_vuln_results,
    get_redis,
)

logger = logging.getLogger("scanner.program_matcher_async")

# Redis keys
REDIS_KEY_IP_PROGRAMS = "cache:ip_programs:{ip}"  # Hash: IP → [programs]
REDIS_KEY_MAPPING = "cache:mapping:ip_programs"  # Hash: all IPs → programs
REDIS_KEY_QUEUE_MATCH = "queue:program_match"  # List: IPs to match
REDIS_KEY_QUEUE_ENRICH = "queue:vuln_enrich"  # List: vulns to enrich
REDIS_KEY_STATS = "stats:program_matcher"  # Hash: statistics
REDIS_KEY_LAST_SYNC = "stats:last_sync"

# Pub/Sub channels
CHANNEL_PROGRAMS_MATCHED = "programs:matched"  # {ip, programs, count}
CHANNEL_VULNS_ENRICHED = "vulns:enriched"  # {vuln_id, programs}
CHANNEL_REPORTS_FILTERED = "reports:filtered"  # {report_id, programs}
CHANNEL_STATS = "stats:updated"  # overall stats

_stats = {
    "ips_matched": 0,
    "vulns_enriched": 0,
    "reports_filtered": 0,
    "queue_processed": 0,
    "last_update": None,
}
_stats_lock = threading.Lock()


def _pub_message(channel: str, data: dict) -> None:
    """Publish message to Pub/Sub channel."""
    redis = get_redis()
    try:
        redis.publish(channel, json.dumps(data))
    except Exception as e:
        logger.warning(f"Failed to publish to {channel}: {e}")


def _inc_stat(key: str, n: int = 1) -> None:
    """Increment stat counter."""
    with _stats_lock:
        _stats[key] = _stats.get(key, 0) + n
        _stats["last_update"] = datetime.utcnow().isoformat()


def get_matcher_stats() -> dict[str, Any]:
    """Get program matcher statistics."""
    with _stats_lock:
        return dict(_stats)


# ═══════════════════════════════════════════════════════════════
# IP Matching with Redis Cache + Pub/Sub
# ═══════════════════════════════════════════════════════════════

def match_ip_to_programs_cached(ip: str, use_cache: bool = True) -> list[dict]:
    """
    Match IP to programs with Redis caching.
    
    1. Check Redis cache first
    2. If not in cache, compute and store
    3. Publish via Pub/Sub if new
    """
    from app.program_matcher import match_ip_to_programs
    
    redis = get_redis()
    
    # Check cache
    if use_cache:
        cached = redis.hget(REDIS_KEY_MAPPING, ip)
        if cached:
            try:
                return json.loads(cached)
            except (json.JSONDecodeError, TypeError):
                pass
    
    # Compute match
    programs = match_ip_to_programs(ip)
    
    # Store in Redis cache (24 hour TTL)
    try:
        redis.hset(REDIS_KEY_MAPPING, ip, json.dumps(programs))
        redis.expire(REDIS_KEY_MAPPING, 86400)
    except Exception as e:
        logger.warning(f"Failed to cache IP {ip}: {e}")
    
    # Publish via Pub/Sub
    if programs:
        _pub_message(CHANNEL_PROGRAMS_MATCHED, {
            "ip": ip,
            "programs_count": len(programs),
            "programs": programs,
            "timestamp": datetime.utcnow().isoformat(),
        })
        _inc_stat("ips_matched")
    
    return programs


def queue_ips_for_matching(ips: list[str]) -> int:
    """
    Queue IPs for background matching.
    
    Background worker will process these asynchronously.
    """
    redis = get_redis()
    count = 0
    
    try:
        for ip in ips:
            if redis.rpush(REDIS_KEY_QUEUE_MATCH, ip):
                count += 1
    except Exception as e:
        logger.error(f"Error queueing IPs: {e}")
    
    return count


def process_ip_match_queue(batch_size: int = 50) -> dict[str, Any]:
    """
    Background worker: Process queued IPs for matching.
    
    Returns results ready for persistence to MongoDB (if needed).
    """
    redis = get_redis()
    
    results = {
        "processed": 0,
        "matched": 0,
        "cached": 0,
        "ready_for_mongo": [],
    }
    
    for _ in range(batch_size):
        ip = redis.lpop(REDIS_KEY_QUEUE_MATCH)
        if not ip:
            break
        
        if isinstance(ip, bytes):
            ip = ip.decode("utf-8")
        
        try:
            programs = match_ip_to_programs_cached(ip, use_cache=False)
            results["processed"] += 1
            
            if programs:
                results["matched"] += 1
                
                # If important (e.g., high-value programs), add to MongoDB queue
                important_programs = [
                    p for p in programs
                    if p.get("offers_bounties") and p.get("min_bounty", 0) > 500
                ]
                
                if important_programs:
                    results["ready_for_mongo"].append({
                        "ip": ip,
                        "programs": important_programs,
                        "timestamp": datetime.utcnow(),
                    })
        
        except Exception as e:
            logger.warning(f"Error matching {ip}: {e}")
    
    _inc_stat("queue_processed", results["processed"])
    
    return results


# ═══════════════════════════════════════════════════════════════
# Vulnerability Enrichment with Pub/Sub
# ═══════════════════════════════════════════════════════════════

def enrich_vuln_with_programs_async(vuln_id: str, ip: str) -> dict[str, Any]:
    """
    Enrich single vulnerability and publish via Pub/Sub.
    
    Redis stores the enrichment, Pub/Sub notifies subscribers.
    """
    redis = get_redis()
    
    # Get programs for this IP
    programs = match_ip_to_programs_cached(ip, use_cache=True)
    
    # Store in Redis
    redis_key = f"cache:vuln_programs:{vuln_id}"
    try:
        redis.hset(redis_key, mapping={
            "programs": json.dumps(programs),
            "timestamp": datetime.utcnow().isoformat(),
        })
        redis.expire(redis_key, 604800)  # 7 days
    except Exception as e:
        logger.warning(f"Failed to cache vuln enrichment {vuln_id}: {e}")
    
    # Publish via Pub/Sub
    _pub_message(CHANNEL_VULNS_ENRICHED, {
        "vuln_id": vuln_id,
        "ip": ip,
        "programs_count": len(programs),
        "programs": programs,
        "timestamp": datetime.utcnow().isoformat(),
    })
    
    _inc_stat("vulns_enriched")
    
    return {
        "vuln_id": vuln_id,
        "ip": ip,
        "programs_found": len(programs),
        "programs": programs,
    }


def queue_vulns_for_enrichment(vulns: list[dict]) -> int:
    """
    Queue vulnerabilities for background enrichment.
    
    Args:
        vulns: List of vuln docs with _id and ip
    """
    redis = get_redis()
    count = 0
    
    try:
        for vuln in vulns:
            vuln_id = str(vuln.get("_id", ""))
            ip = vuln.get("ip", "")
            
            if vuln_id and ip:
                payload = json.dumps({"vuln_id": vuln_id, "ip": ip})
                if redis.rpush(REDIS_KEY_QUEUE_ENRICH, payload):
                    count += 1
    except Exception as e:
        logger.error(f"Error queueing vulns: {e}")
    
    return count


def process_vuln_enrich_queue(batch_size: int = 100) -> dict[str, Any]:
    """
    Background worker: Process queued vulnerabilities for enrichment.
    """
    redis = get_redis()
    
    results = {
        "processed": 0,
        "enriched": 0,
        "ready_for_mongo": [],
    }
    
    for _ in range(batch_size):
        item = redis.lpop(REDIS_KEY_QUEUE_ENRICH)
        if not item:
            break
        
        if isinstance(item, bytes):
            item = item.decode("utf-8")
        
        try:
            payload = json.loads(item)
            vuln_id = payload.get("vuln_id", "")
            ip = payload.get("ip", "")
            
            if vuln_id and ip:
                result = enrich_vuln_with_programs_async(vuln_id, ip)
                results["processed"] += 1
                
                if result["programs"]:
                    results["enriched"] += 1
                    
                    # If important, mark for MongoDB persistence
                    if any(p.get("offers_bounties") for p in result["programs"]):
                        results["ready_for_mongo"].append({
                            "vuln_id": vuln_id,
                            "ip": ip,
                            "programs": result["programs"],
                            "timestamp": datetime.utcnow(),
                        })
        
        except Exception as e:
            logger.warning(f"Error enriching vuln from queue: {e}")
    
    return results


# ═══════════════════════════════════════════════════════════════
# Report Filtering with Pub/Sub
# ═══════════════════════════════════════════════════════════════

def filter_report_to_programs_async(report_id: str, ip: str) -> dict[str, Any]:
    """
    Filter report to eligible programs and publish via Pub/Sub.
    """
    from app.report_processor import get_processed_reports
    
    redis = get_redis()
    
    # Get programs for this IP
    programs = match_ip_to_programs_cached(ip, use_cache=True)
    
    if not programs:
        return {"report_id": report_id, "eligible_programs": []}
    
    # Store in Redis
    redis_key = f"cache:report_programs:{report_id}"
    try:
        redis.hset(redis_key, mapping={
            "programs": json.dumps(programs),
            "timestamp": datetime.utcnow().isoformat(),
        })
        redis.expire(redis_key, 604800)  # 7 days
    except Exception as e:
        logger.warning(f"Failed to cache report {report_id}: {e}")
    
    # Publish via Pub/Sub
    _pub_message(CHANNEL_REPORTS_FILTERED, {
        "report_id": report_id,
        "ip": ip,
        "programs_count": len(programs),
        "programs": programs,
        "timestamp": datetime.utcnow().isoformat(),
    })
    
    _inc_stat("reports_filtered")
    
    return {
        "report_id": report_id,
        "ip": ip,
        "eligible_programs": len(programs),
        "programs": programs,
    }


def subscribe_to_channel(channel: str, timeout: int = 60) -> list[dict]:
    """
    Subscribe to a Pub/Sub channel and receive messages.
    
    Used by frontend for real-time updates.
    
    Args:
        channel: Channel name (programs:matched, vulns:enriched, etc)
        timeout: Max seconds to wait for messages
    
    Returns:
        List of messages received
    """
    redis = get_redis()
    pubsub = redis.pubsub()
    messages = []
    
    try:
        pubsub.subscribe(channel)
        
        start = time.time()
        for message in pubsub.listen():
            if time.time() - start > timeout:
                break
            
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    messages.append(data)
                except (json.JSONDecodeError, TypeError, KeyError):
                    pass
    
    finally:
        pubsub.unsubscribe(channel)
        pubsub.close()
    
    return messages


# ═══════════════════════════════════════════════════════════════
# Background Worker Thread
# ═══════════════════════════════════════════════════════════════

_worker_running = False
_worker_lock = threading.Lock()


def start_program_matcher_worker(check_interval: int = 5) -> None:
    """
    Start background worker thread for processing queues.
    
    Continuously:
      1. Processes IP matching queue
      2. Processes vulnerability enrichment queue
      3. Publishes stats updates
      4. Persists important data to MongoDB (optional)
    """
    global _worker_running
    
    with _worker_lock:
        if _worker_running:
            logger.info("[PROGRAM_MATCHER] Worker already running")
            return
        _worker_running = True
    
    def _run_worker():
        logger.info("[PROGRAM_MATCHER] Worker started")
        
        while _worker_running:
            try:
                # Process IP matching queue
                ip_results = process_ip_match_queue(batch_size=50)
                
                # Process vuln enrichment queue
                vuln_results = process_vuln_enrich_queue(batch_size=100)
                
                # Publish stats if anything changed
                if ip_results["processed"] > 0 or vuln_results["processed"] > 0:
                    _pub_message(CHANNEL_STATS, {
                        "ips_processed": ip_results["processed"],
                        "ips_matched": ip_results["matched"],
                        "vulns_processed": vuln_results["processed"],
                        "vulns_enriched": vuln_results["enriched"],
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                
                # Optional: Persist important data to MongoDB
                if ip_results["ready_for_mongo"]:
                    _persist_ip_matches_to_mongo(ip_results["ready_for_mongo"])
                
                if vuln_results["ready_for_mongo"]:
                    _persist_vuln_enrichments_to_mongo(vuln_results["ready_for_mongo"])
            
            except Exception as e:
                logger.error(f"Worker error: {e}")
            
            time.sleep(check_interval)
    
    t = threading.Thread(target=_run_worker, daemon=True)
    t.start()


def _persist_ip_matches_to_mongo(items: list[dict]) -> None:
    """Persist important IP-program matches to MongoDB."""
    try:
        from app.database import get_client
        
        db = get_client().get_default_database()
        col = db["ip_program_matches"]
        
        for item in items:
            col.update_one(
                {"ip": item["ip"]},
                {
                    "$set": {
                        "ip": item["ip"],
                        "programs": item["programs"],
                        "updated_at": item["timestamp"],
                    },
                    "$inc": {"update_count": 1},
                },
                upsert=True,
            )
    
    except Exception as e:
        logger.warning(f"Failed to persist IP matches: {e}")


def _persist_vuln_enrichments_to_mongo(items: list[dict]) -> None:
    """Persist important vuln enrichments to MongoDB."""
    try:
        from app.database import get_client
        
        db = get_client().get_default_database()
        col = db["vuln_program_enrichments"]
        
        for item in items:
            col.update_one(
                {"vuln_id": item["vuln_id"]},
                {
                    "$set": {
                        "vuln_id": item["vuln_id"],
                        "ip": item["ip"],
                        "programs": item["programs"],
                        "updated_at": item["timestamp"],
                    },
                    "$inc": {"update_count": 1},
                },
                upsert=True,
            )
    
    except Exception as e:
        logger.warning(f"Failed to persist vuln enrichments: {e}")
