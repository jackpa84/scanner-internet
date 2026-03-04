"""
Integration with arkadiyt/bounty-targets-data.

Fetches hourly-updated dumps of bug bounty scopes from:
  - HackerOne
  - Bugcrowd
  - Intigriti
  - YesWeHack

Source: https://github.com/arkadiyt/bounty-targets-data

This gives us access to ALL eligible bounty programs across all platforms
without needing individual API keys for each platform.
"""

import json
import logging
import os
import re
import threading
import time
from datetime import datetime
from typing import Any

import requests

from app.database import get_bounty_programs, get_redis

logger = logging.getLogger("scanner.bounty_data")

BOUNTY_DATA_ENABLED = os.getenv("BOUNTY_DATA_ENABLED", "true").lower() in ("1", "true", "yes")
BOUNTY_DATA_INTERVAL = int(os.getenv("BOUNTY_DATA_INTERVAL", "3600"))
BOUNTY_DATA_AUTO_IMPORT = os.getenv("BOUNTY_DATA_AUTO_IMPORT", "true").lower() in ("1", "true", "yes")
BOUNTY_DATA_MIN_BOUNTY = int(os.getenv("BOUNTY_DATA_MIN_BOUNTY", "0"))
BOUNTY_DATA_PLATFORMS = os.getenv("BOUNTY_DATA_PLATFORMS", "hackerone,bugcrowd,intigriti,yeswehack").lower().split(",")

BASE_RAW = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"

DATA_URLS = {
    "hackerone": f"{BASE_RAW}/hackerone_data.json",
    "bugcrowd": f"{BASE_RAW}/bugcrowd_data.json",
    "intigriti": f"{BASE_RAW}/intigriti_data.json",
    "yeswehack": f"{BASE_RAW}/yeswehack_data.json",
    "domains": f"{BASE_RAW}/domains.txt",
    "wildcards": f"{BASE_RAW}/wildcards.txt",
}

_stats = {
    "last_fetch": None,
    "programs_fetched": 0,
    "programs_imported": 0,
    "programs_updated": 0,
    "domains_total": 0,
    "wildcards_total": 0,
    "errors": 0,
    "by_platform": {},
}
_stats_lock = threading.Lock()


def _inc_stat(key: str, n: int = 1) -> None:
    with _stats_lock:
        _stats[key] = _stats.get(key, 0) + n


def get_bounty_data_stats() -> dict[str, Any]:
    with _stats_lock:
        return dict(_stats)


def _fetch_json(url: str) -> Any:
    """Fetch JSON data from GitHub raw URL."""
    resp = requests.get(url, timeout=60, headers={"User-Agent": "ScannerBounty/1.0"})
    resp.raise_for_status()
    return resp.json()


def _fetch_text(url: str) -> str:
    """Fetch text data from GitHub raw URL."""
    resp = requests.get(url, timeout=60, headers={"User-Agent": "ScannerBounty/1.0"})
    resp.raise_for_status()
    return resp.text


# ═══════════════════════════════════════════════════════════════
# Platform parsers
# ═══════════════════════════════════════════════════════════════

def _parse_hackerone(data: list[dict]) -> list[dict]:
    """Parse HackerOne programs from bounty-targets-data format."""
    programs = []
    for prog in data:
        name = prog.get("name", "")
        handle = prog.get("handle", "")
        if not handle:
            continue

        offers_bounties = prog.get("offers_bounties", False)
        targets = prog.get("targets", {})
        in_scope = targets.get("in_scope", [])
        out_scope = targets.get("out_of_scope", [])

        in_scope_domains = []
        asset_types = set()
        for item in in_scope:
            identifier = item.get("asset_identifier", "")
            asset_type = item.get("asset_type", "").lower()
            if identifier:
                in_scope_domains.append(identifier)
            if asset_type:
                asset_types.add(asset_type)

        out_scope_domains = []
        for item in out_scope:
            identifier = item.get("asset_identifier", "")
            if identifier:
                out_scope_domains.append(identifier)

        if not in_scope_domains:
            continue

        programs.append({
            "name": name or handle,
            "handle": handle,
            "platform": "hackerone",
            "url": f"https://hackerone.com/{handle}",
            "in_scope": in_scope_domains,
            "out_of_scope": out_scope_domains,
            "has_bounty": offers_bounties,
            "asset_types": list(asset_types),
            "source": "bounty-targets-data",
        })

    return programs


def _parse_bugcrowd(data: list[dict]) -> list[dict]:
    """Parse Bugcrowd programs."""
    programs = []
    for prog in data:
        name = prog.get("name", "")
        url = prog.get("url", "")
        if not name:
            continue

        targets = prog.get("targets", {})
        in_scope = targets.get("in_scope", [])
        out_scope = targets.get("out_of_scope", [])

        in_scope_domains = []
        for item in in_scope:
            target = item.get("target", "")
            if target:
                in_scope_domains.append(target)

        out_scope_domains = []
        for item in out_scope:
            target = item.get("target", "")
            if target:
                out_scope_domains.append(target)

        if not in_scope_domains:
            continue

        full_url = f"https://bugcrowd.com{url}" if url.startswith("/") else url

        programs.append({
            "name": name,
            "platform": "bugcrowd",
            "url": full_url,
            "in_scope": in_scope_domains,
            "out_of_scope": out_scope_domains,
            "has_bounty": (prog.get("max_payout") or 0) > 0,
            "bounty_max": prog.get("max_payout") or 0,
            "source": "bounty-targets-data",
        })

    return programs


def _parse_intigriti(data: list[dict]) -> list[dict]:
    """Parse Intigriti programs."""
    programs = []
    for prog in data:
        name = prog.get("name", "")
        if not name:
            continue

        targets = prog.get("targets", {})
        in_scope = targets.get("in_scope", [])
        out_scope = targets.get("out_of_scope", [])

        in_scope_domains = []
        for item in in_scope:
            endpoint = item.get("endpoint", "")
            if endpoint:
                in_scope_domains.append(endpoint)

        out_scope_domains = []
        for item in out_scope:
            endpoint = item.get("endpoint", "")
            if endpoint:
                out_scope_domains.append(endpoint)

        if not in_scope_domains:
            continue

        min_bounty = prog.get("min_bounty", {})
        max_bounty = prog.get("max_bounty", {})

        programs.append({
            "name": name,
            "platform": "intigriti",
            "url": prog.get("url", ""),
            "in_scope": in_scope_domains,
            "out_of_scope": out_scope_domains,
            "has_bounty": (max_bounty.get("value", 0) or 0) > 0,
            "bounty_min": min_bounty.get("value"),
            "bounty_max": max_bounty.get("value"),
            "source": "bounty-targets-data",
        })

    return programs


def _parse_yeswehack(data: list[dict]) -> list[dict]:
    """Parse YesWeHack programs."""
    programs = []
    for prog in data:
        name = prog.get("title", "") or prog.get("name", "")
        if not name:
            continue

        targets = prog.get("targets", {})
        in_scope = targets.get("in_scope", [])
        out_scope = targets.get("out_of_scope", [])

        in_scope_domains = []
        for item in in_scope:
            target = item.get("target", "")
            if target:
                in_scope_domains.append(target)

        out_scope_domains = []
        for item in out_scope:
            target = item.get("target", "")
            if target:
                out_scope_domains.append(target)

        if not in_scope_domains:
            continue

        programs.append({
            "name": name,
            "platform": "yeswehack",
            "url": prog.get("url", ""),
            "in_scope": in_scope_domains,
            "out_of_scope": out_scope_domains,
            "has_bounty": prog.get("bounty", False),
            "bounty_min": prog.get("min_bounty"),
            "bounty_max": prog.get("max_bounty"),
            "source": "bounty-targets-data",
        })

    return programs


PARSERS = {
    "hackerone": _parse_hackerone,
    "bugcrowd": _parse_bugcrowd,
    "intigriti": _parse_intigriti,
    "yeswehack": _parse_yeswehack,
}


# ═══════════════════════════════════════════════════════════════
# Fetch & import
# ═══════════════════════════════════════════════════════════════

def fetch_all_programs(platforms: list[str] | None = None) -> dict[str, list[dict]]:
    """Fetch programs from all configured platforms."""
    platforms = platforms or [p.strip() for p in BOUNTY_DATA_PLATFORMS if p.strip()]
    result: dict[str, list[dict]] = {}

    for platform in platforms:
        if platform not in DATA_URLS or platform in ("domains", "wildcards"):
            continue

        parser = PARSERS.get(platform)
        if not parser:
            continue

        try:
            logger.info("[BOUNTY-DATA] Fetching %s data...", platform)
            data = _fetch_json(DATA_URLS[platform])
            programs = parser(data)
            result[platform] = programs
            _inc_stat("programs_fetched", len(programs))
            with _stats_lock:
                _stats["by_platform"][platform] = len(programs)
            logger.info("[BOUNTY-DATA] %s: %d programs parsed", platform, len(programs))
        except Exception as e:
            logger.error("[BOUNTY-DATA] Error fetching %s: %s", platform, e)
            _inc_stat("errors")

    return result


def fetch_domain_lists() -> dict[str, list[str]]:
    """Fetch the global domain and wildcard lists."""
    result: dict[str, list[str]] = {"domains": [], "wildcards": []}

    try:
        text = _fetch_text(DATA_URLS["domains"])
        domains = [d.strip() for d in text.splitlines() if d.strip()]
        result["domains"] = domains
        with _stats_lock:
            _stats["domains_total"] = len(domains)
        logger.info("[BOUNTY-DATA] %d domains loaded", len(domains))
    except Exception as e:
        logger.error("[BOUNTY-DATA] Error fetching domains: %s", e)
        _inc_stat("errors")

    try:
        text = _fetch_text(DATA_URLS["wildcards"])
        wildcards = [w.strip() for w in text.splitlines() if w.strip()]
        result["wildcards"] = wildcards
        with _stats_lock:
            _stats["wildcards_total"] = len(wildcards)
        logger.info("[BOUNTY-DATA] %d wildcards loaded", len(wildcards))
    except Exception as e:
        logger.error("[BOUNTY-DATA] Error fetching wildcards: %s", e)
        _inc_stat("errors")

    return result


def import_programs(
    programs_by_platform: dict[str, list[dict]],
    bounty_only: bool = False,
    min_scope_items: int = 1,
) -> dict[str, Any]:
    """Import programs into the bounty_programs collection."""
    col = get_bounty_programs()
    imported = 0
    updated = 0
    skipped = 0

    for platform, programs in programs_by_platform.items():
        for prog in programs:
            if bounty_only and not prog.get("has_bounty"):
                skipped += 1
                continue

            if len(prog.get("in_scope", [])) < min_scope_items:
                skipped += 1
                continue

            if BOUNTY_DATA_MIN_BOUNTY > 0:
                max_b = prog.get("bounty_max") or 0
                if max_b < BOUNTY_DATA_MIN_BOUNTY:
                    skipped += 1
                    continue

            existing = col.find_one({"name": prog["name"], "platform": prog["platform"]})

            doc = {
                "name": prog["name"],
                "platform": prog["platform"],
                "url": prog.get("url", ""),
                "in_scope": prog["in_scope"],
                "out_of_scope": prog.get("out_of_scope", []),
                "has_bounty": prog.get("has_bounty", False),
                "bounty_min": prog.get("bounty_min"),
                "bounty_max": prog.get("bounty_max"),
                "asset_types": prog.get("asset_types", []),
                "source": "bounty-targets-data",
                "last_data_sync": datetime.utcnow(),
            }

            if existing:
                old_scope = set(existing.get("in_scope", []))
                new_scope = set(prog["in_scope"])
                if old_scope != new_scope:
                    doc["scope_changed"] = True
                    doc["scope_change_detected"] = datetime.utcnow()
                    doc["previous_scope_count"] = len(old_scope)
                col.update_one(
                    {"_id": existing["_id"]},
                    {"$set": doc},
                )
                updated += 1
            else:
                doc["status"] = "active"
                doc["created_at"] = datetime.utcnow()
                doc["stats"] = {}
                col.insert_one(doc)
                imported += 1

    _inc_stat("programs_imported", imported)
    _inc_stat("programs_updated", updated)

    return {
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "total_processed": imported + updated + skipped,
    }


def sync_bounty_targets_data(
    platforms: list[str] | None = None,
    bounty_only: bool = False,
) -> dict[str, Any]:
    """Full sync: fetch all programs + domain lists and import."""
    t0 = time.time()

    programs = fetch_all_programs(platforms)
    domain_lists = fetch_domain_lists()
    import_result = import_programs(programs, bounty_only=bounty_only)

    with _stats_lock:
        _stats["last_fetch"] = datetime.utcnow().isoformat()

    elapsed = time.time() - t0

    platform_counts = {p: len(progs) for p, progs in programs.items()}

    result = {
        **import_result,
        "platforms": platform_counts,
        "domains_count": len(domain_lists.get("domains", [])),
        "wildcards_count": len(domain_lists.get("wildcards", [])),
        "elapsed_seconds": round(elapsed, 1),
    }

    logger.info(
        "[BOUNTY-DATA] Sync complete in %.1fs: imported=%d updated=%d skipped=%d domains=%d wildcards=%d",
        elapsed, import_result["imported"], import_result["updated"],
        import_result["skipped"], result["domains_count"], result["wildcards_count"],
    )

    return result


def search_programs(
    query: str = "",
    platform: str = "",
    bounty_only: bool = False,
    limit: int = 50,
    asset_type: str = "",
    min_scope: int = 0,
    has_wildcards: bool = False,
    sort_by: str = "newest",
    scope_changed: bool = False,
) -> list[dict]:
    """Search imported programs with advanced filters.

    Args:
        query: text search on name + in_scope (regex)
        platform: filter by platform (hackerone, bugcrowd, etc.)
        bounty_only: only programs offering bounties
        limit: max results
        asset_type: filter by asset type (url, domain, wildcard, api, mobile, etc.)
        min_scope: minimum number of in_scope items
        has_wildcards: only programs with wildcard domains (*.example.com)
        sort_by: newest | scope_size | name | bounty_changed
        scope_changed: only programs with recent scope changes
    """
    col = get_bounty_programs()
    filt: dict[str, Any] = {"source": "bounty-targets-data"}

    if platform:
        filt["platform"] = platform
    if bounty_only:
        filt["has_bounty"] = True
    if scope_changed:
        filt["scope_changed"] = True
    if asset_type:
        filt["asset_types"] = {"$regex": asset_type, "$options": "i"}
    if query:
        filt["$or"] = [
            {"name": {"$regex": query, "$options": "i"}},
            {"in_scope": {"$regex": query, "$options": "i"}},
            {"handle": {"$regex": query, "$options": "i"}},
        ]

    sort_map = {
        "newest": ("created_at", -1),
        "name": ("name", 1),
        "scope_size": ("_scope_count", -1),
        "bounty_changed": ("scope_change_detected", -1),
    }
    sort_field, sort_dir = sort_map.get(sort_by, ("created_at", -1))

    # RedisCollection may not support $or/$regex, fall back to manual filter
    try:
        results = list(col.find(filt).sort(sort_field, sort_dir).limit(limit * 3))
    except Exception:
        all_progs = list(col.find({"source": "bounty-targets-data"}).limit(2000))
        results = []
        q = query.lower()
        for p in all_progs:
            if platform and p.get("platform") != platform:
                continue
            if bounty_only and not p.get("has_bounty"):
                continue
            if scope_changed and not p.get("scope_changed"):
                continue
            if asset_type:
                types_str = " ".join(p.get("asset_types", [])).lower()
                if asset_type.lower() not in types_str:
                    continue
            if q:
                name_match = q in (p.get("name", "")).lower()
                scope_match = any(q in s.lower() for s in p.get("in_scope", []))
                handle_match = q in (p.get("handle", "")).lower()
                if not name_match and not scope_match and not handle_match:
                    continue
            results.append(p)

    # Enrich results with computed fields and apply in-memory filters
    enriched = []
    for p in results:
        scope = p.get("in_scope", [])
        scope_count = len(scope)
        wildcard_count = sum(1 for s in scope if s.startswith("*.") or s.startswith("*"))
        p["scope_count"] = scope_count
        p["wildcard_count"] = wildcard_count
        p["scope_preview"] = scope[:8]

        if min_scope > 0 and scope_count < min_scope:
            continue
        if has_wildcards and wildcard_count == 0:
            continue

        enriched.append(p)
        if len(enriched) >= limit:
            break

    # Sort in-memory for computed fields
    if sort_by == "scope_size":
        enriched.sort(key=lambda x: x.get("scope_count", 0), reverse=True)

    return enriched


def get_all_bounty_domains() -> dict[str, list[str]]:
    """Get cached domain/wildcard lists from Redis."""
    try:
        r = get_redis()
        domains = r.get("bounty_data:domains")
        wildcards = r.get("bounty_data:wildcards")
        return {
            "domains": json.loads(domains) if domains else [],
            "wildcards": json.loads(wildcards) if wildcards else [],
        }
    except Exception:
        return {"domains": [], "wildcards": []}


def _cache_domain_lists(domains: list[str], wildcards: list[str]) -> None:
    """Cache domain lists in Redis."""
    try:
        r = get_redis()
        r.setex("bounty_data:domains", 7200, json.dumps(domains))
        r.setex("bounty_data:wildcards", 7200, json.dumps(wildcards))
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
# Background sync loop
# ═══════════════════════════════════════════════════════════════

def _sync_loop() -> None:
    """Background loop to periodically sync bounty-targets-data."""
    time.sleep(30)
    logger.info("[BOUNTY-DATA] Sync loop started (interval=%ds)", BOUNTY_DATA_INTERVAL)

    while True:
        try:
            result = sync_bounty_targets_data(bounty_only=False)

            domain_lists = fetch_domain_lists()
            _cache_domain_lists(
                domain_lists.get("domains", []),
                domain_lists.get("wildcards", []),
            )
        except Exception as e:
            logger.error("[BOUNTY-DATA] Sync loop error: %s", e)
            _inc_stat("errors")

        time.sleep(BOUNTY_DATA_INTERVAL)


def start_bounty_data_sync() -> None:
    """Start the background sync thread."""
    if not BOUNTY_DATA_ENABLED:
        logger.info("[BOUNTY-DATA] Disabled")
        return

    t = threading.Thread(target=_sync_loop, daemon=True)
    t.start()
    logger.info("[BOUNTY-DATA] Sync active (platforms=%s)", ",".join(BOUNTY_DATA_PLATFORMS))
