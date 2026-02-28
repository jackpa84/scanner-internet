"""
Smart program selection: score bounty programs by attractiveness for maximum ROI.

Factors:
  - Bounty amount range (higher = better)
  - Scope size (more assets = more attack surface)
  - Program age (newer = more low-hanging fruit)
  - Response time (faster triage = faster payout)
  - Competition level (less popular = better)
  - Resolution rate (programs that resolve vs N/A)
  - Asset types (web > mobile > hardware)
  - Safe harbor (legal protection)

Also monitors HackerOne for newly launched programs.
"""

import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta
from typing import Any

import requests

from app.database import get_bounty_programs, get_bounty_targets, get_submitted_reports

logger = logging.getLogger("scanner.scorer")

SCORER_ENABLED = os.getenv("PROGRAM_SCORER_ENABLED", "true").lower() in ("1", "true", "yes")
SCORER_INTERVAL = int(os.getenv("PROGRAM_SCORER_INTERVAL", "3600"))
H1_MONITOR_INTERVAL = int(os.getenv("H1_MONITOR_INTERVAL", "1800"))
H1_NEW_PROGRAM_DAYS = int(os.getenv("H1_NEW_PROGRAM_DAYS", "30"))

_scorer_stats = {
    "programs_scored": 0,
    "new_programs_found": 0,
    "last_score_run": None,
    "last_h1_check": None,
}
_stats_lock = threading.Lock()


def _inc_stat(key: str, n: int = 1) -> None:
    with _stats_lock:
        _scorer_stats[key] = _scorer_stats.get(key, 0) + n


def get_scorer_stats() -> dict[str, Any]:
    with _stats_lock:
        return dict(_scorer_stats)


def score_program(program: dict) -> dict[str, Any]:
    """Calculate attractiveness score (0-100) for a bounty program."""
    score = 0.0
    breakdown: dict[str, float] = {}

    # --- Bounty amount (0-30 points) ---
    bounty_max = program.get("bounty_max") or 0
    bounty_min = program.get("bounty_min") or 0
    has_bounty = program.get("has_bounty", False)

    if has_bounty:
        score += 5
        breakdown["has_bounty"] = 5

    if bounty_max >= 50000:
        pts = 30
    elif bounty_max >= 20000:
        pts = 25
    elif bounty_max >= 10000:
        pts = 20
    elif bounty_max >= 5000:
        pts = 15
    elif bounty_max >= 1000:
        pts = 10
    elif bounty_max > 0:
        pts = 5
    else:
        pts = 0
    score += pts
    breakdown["bounty_range"] = pts

    # --- Scope size (0-15 points) ---
    in_scope = program.get("in_scope") or []
    if isinstance(in_scope, str):
        in_scope = [in_scope]
    scope_count = len(in_scope)
    wildcard_count = sum(1 for s in in_scope if s.startswith("*."))

    if scope_count >= 20 or wildcard_count >= 5:
        pts = 15
    elif scope_count >= 10 or wildcard_count >= 3:
        pts = 12
    elif scope_count >= 5 or wildcard_count >= 2:
        pts = 9
    elif scope_count >= 2:
        pts = 6
    elif scope_count >= 1:
        pts = 3
    else:
        pts = 0
    score += pts
    breakdown["scope_size"] = pts

    # --- Program age / freshness (0-15 points) ---
    created_at = program.get("created_at")
    first_recon = program.get("first_recon_at")
    h1_launched = program.get("h1_launched_at")

    ref_date = h1_launched or created_at
    if ref_date and isinstance(ref_date, datetime):
        age_days = (datetime.utcnow() - ref_date).days
        if age_days <= 7:
            pts = 15
        elif age_days <= 30:
            pts = 12
        elif age_days <= 90:
            pts = 8
        elif age_days <= 365:
            pts = 4
        else:
            pts = 1
    else:
        pts = 3
    score += pts
    breakdown["freshness"] = pts

    # --- Target coverage (0-10 points) ---
    stats = program.get("stats") or {}
    alive_count = stats.get("alive", 0)
    subdomain_count = stats.get("subdomains", 0)

    if alive_count >= 100:
        pts = 10
    elif alive_count >= 50:
        pts = 8
    elif alive_count >= 20:
        pts = 6
    elif alive_count >= 5:
        pts = 4
    elif alive_count >= 1:
        pts = 2
    elif subdomain_count >= 10:
        pts = 3
    else:
        pts = 0
    score += pts
    breakdown["target_coverage"] = pts

    # --- Findings potential (0-10 points) ---
    recon_findings = stats.get("recon_findings") if isinstance(stats, dict) else 0
    if not recon_findings:
        recon_findings = 0
    if recon_findings >= 20:
        pts = 10
    elif recon_findings >= 10:
        pts = 7
    elif recon_findings >= 5:
        pts = 4
    elif recon_findings >= 1:
        pts = 2
    else:
        pts = 0
    score += pts
    breakdown["findings_potential"] = pts

    # --- Asset types (0-10 points) ---
    asset_types = program.get("asset_types") or []
    asset_types_lower = [a.lower() for a in asset_types]
    if any(t in asset_types_lower for t in ["url", "web", "domain", "wildcard"]):
        pts = 10
    elif any(t in asset_types_lower for t in ["api", "cidr", "ip"]):
        pts = 7
    elif any(t in asset_types_lower for t in ["mobile", "android", "ios"]):
        pts = 4
    else:
        pts = 5
    score += pts
    breakdown["asset_types"] = pts

    # --- Safe harbor bonus (0-5 points) ---
    if program.get("safe_harbor"):
        score += 5
        breakdown["safe_harbor"] = 5

    # --- Competition penalty ---
    # If many vulns already found by others, less opportunity
    # For now, no penalty (would need H1 data)

    final_score = min(100, max(0, int(score)))

    # Tier classification
    if final_score >= 80:
        tier = "S"
    elif final_score >= 60:
        tier = "A"
    elif final_score >= 40:
        tier = "B"
    elif final_score >= 20:
        tier = "C"
    else:
        tier = "D"

    return {
        "score": final_score,
        "tier": tier,
        "breakdown": breakdown,
        "recommendation": _generate_recommendation(final_score, breakdown, program),
    }


def _generate_recommendation(score: int, breakdown: dict, program: dict) -> str:
    """Generate actionable recommendation based on score."""
    if score >= 80:
        return "HIGH PRIORITY: Focus scanning resources here. Large bounties + wide scope = maximum ROI."
    if score >= 60:
        return "GOOD TARGET: Solid bounty program. Run full recon pipeline with all tools."
    if score >= 40:
        return "MODERATE: Worth scanning but don't prioritize over higher-scoring programs."
    if score >= 20:
        return "LOW PRIORITY: Small scope or low bounties. Scan only if nothing better available."
    return "SKIP: Very low ROI potential. Focus efforts elsewhere."


def score_all_programs() -> list[dict[str, Any]]:
    """Score all programs and update their records with scores."""
    programs_col = get_bounty_programs()
    results = []

    for program in programs_col.find():
        score_data = score_program(program)
        programs_col.update_one(
            {"_id": program["_id"]},
            {"$set": {
                "attractiveness_score": score_data["score"],
                "attractiveness_tier": score_data["tier"],
                "score_breakdown": score_data["breakdown"],
                "score_recommendation": score_data["recommendation"],
                "last_scored": datetime.utcnow(),
            }},
        )
        results.append({
            "program_id": str(program["_id"]),
            "name": program.get("name", "?"),
            **score_data,
        })
        _inc_stat("programs_scored")

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def get_prioritized_programs(min_score: int = 40) -> list[dict[str, Any]]:
    """Get programs ordered by attractiveness score."""
    programs_col = get_bounty_programs()
    programs = list(programs_col.find(
        {"attractiveness_score": {"$gte": min_score}},
    ).sort("attractiveness_score", -1))

    return [{
        "program_id": str(p["_id"]),
        "name": p.get("name", "?"),
        "score": p.get("attractiveness_score", 0),
        "tier": p.get("attractiveness_tier", "?"),
        "recommendation": p.get("score_recommendation", ""),
        "has_bounty": p.get("has_bounty", False),
        "bounty_max": p.get("bounty_max"),
        "alive_targets": (p.get("stats") or {}).get("alive", 0),
    } for p in programs]


def fetch_new_h1_programs() -> list[dict[str, Any]]:
    """Fetch recently launched programs from HackerOne API."""
    username = (os.getenv("HACKERONE_API_USERNAME") or "").strip()
    token = (os.getenv("HACKERONE_API_TOKEN") or "").strip()
    if not username or not token:
        return []

    new_programs = []
    try:
        page_after = None
        pages_fetched = 0
        max_pages = 10

        while pages_fetched < max_pages:
            params: dict[str, Any] = {"page[size]": 100}
            if page_after:
                params["page[after]"] = page_after

            r = requests.get(
                "https://api.hackerone.com/v1/hackers/programs",
                params=params,
                auth=(username, token),
                headers={"Accept": "application/json"},
                timeout=30,
            )

            if r.status_code != 200:
                logger.warning("[SCORER] H1 API returned %d", r.status_code)
                break

            data = r.json() or {}
            programs = data.get("data", [])
            if not programs:
                break

            cutoff = datetime.utcnow() - timedelta(days=H1_NEW_PROGRAM_DAYS)

            for prog in programs:
                attrs = prog.get("attributes", {})
                created_str = attrs.get("created_at", "")
                try:
                    created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00")).replace(tzinfo=None)
                except (ValueError, AttributeError):
                    continue

                if created_dt < cutoff:
                    continue

                handle = attrs.get("handle", "")
                offers_bounties = attrs.get("offers_bounties", False)

                scope_items = []
                rels = prog.get("relationships", {})
                structured_scopes = rels.get("structured_scopes", {}).get("data", [])
                for scope in structured_scopes:
                    scope_attrs = scope.get("attributes", {})
                    if scope_attrs.get("eligible_for_submission", True):
                        identifier = scope_attrs.get("asset_identifier", "")
                        if identifier:
                            scope_items.append(identifier)

                new_programs.append({
                    "handle": handle,
                    "name": attrs.get("name", handle),
                    "url": f"https://hackerone.com/{handle}",
                    "offers_bounties": offers_bounties,
                    "created_at": created_dt,
                    "in_scope": scope_items,
                    "submission_state": attrs.get("submission_state", ""),
                    "state": attrs.get("state", ""),
                })

            links = data.get("links", {})
            next_link = links.get("next")
            if not next_link:
                break
            page_after_match = re.search(r'page%5Bafter%5D=([^&]+)', next_link) or re.search(r'page\[after\]=([^&]+)', next_link)
            if page_after_match:
                page_after = page_after_match.group(1)
            else:
                break
            pages_fetched += 1
            time.sleep(1)

    except Exception as e:
        logger.error("[SCORER] Error fetching H1 programs: %s", e)

    _inc_stat("new_programs_found", len(new_programs))
    return new_programs


def auto_import_new_programs(min_scope_items: int = 1) -> list[dict]:
    """Fetch new H1 programs and auto-import eligible ones."""
    new_programs = fetch_new_h1_programs()
    if not new_programs:
        return []

    programs_col = get_bounty_programs()
    imported = []

    for prog in new_programs:
        if prog.get("state") != "public_mode":
            continue
        if prog.get("submission_state") != "open":
            continue
        if len(prog.get("in_scope", [])) < min_scope_items:
            continue

        existing = programs_col.find_one({"name": prog["name"]})
        if existing:
            continue

        doc = {
            "name": prog["name"],
            "platform": "hackerone",
            "url": prog["url"],
            "in_scope": prog["in_scope"],
            "out_of_scope": [],
            "status": "active",
            "created_at": datetime.utcnow(),
            "h1_launched_at": prog.get("created_at"),
            "has_bounty": prog.get("offers_bounties", False),
            "stats": {},
            "auto_imported": True,
            "import_source": "h1_monitor",
        }

        result = programs_col.insert_one(doc)
        imported.append({
            "id": str(result.inserted_id),
            "name": prog["name"],
            "url": prog["url"],
            "scope_count": len(prog["in_scope"]),
        })
        logger.info("[SCORER] Auto-imported new H1 program: %s (%d scope items)",
                     prog["name"], len(prog["in_scope"]))

    return imported


def _scorer_loop() -> None:
    """Background loop: score programs + monitor for new H1 programs."""
    time.sleep(30)
    logger.info("[SCORER] Program scorer started (score_interval=%ds, h1_monitor=%ds)",
                SCORER_INTERVAL, H1_MONITOR_INTERVAL)

    last_score = 0.0
    last_h1_check = 0.0

    while True:
        try:
            now = time.time()

            if now - last_score >= SCORER_INTERVAL:
                results = score_all_programs()
                with _stats_lock:
                    _scorer_stats["last_score_run"] = datetime.utcnow().isoformat()
                if results:
                    top = results[:3]
                    logger.info("[SCORER] Top programs: %s",
                                ", ".join(f"{r['name']}({r['score']})" for r in top))
                last_score = now

            if now - last_h1_check >= H1_MONITOR_INTERVAL:
                imported = auto_import_new_programs()
                with _stats_lock:
                    _scorer_stats["last_h1_check"] = datetime.utcnow().isoformat()
                if imported:
                    logger.info("[SCORER] Auto-imported %d new programs", len(imported))
                last_h1_check = now

        except Exception as e:
            logger.error("[SCORER] Loop error: %s", e)

        time.sleep(60)


def start_program_scorer() -> None:
    """Start the program scorer background thread."""
    if not SCORER_ENABLED:
        logger.info("[SCORER] Program scorer disabled")
        return

    t = threading.Thread(target=_scorer_loop, daemon=True)
    t.start()
    logger.info("[SCORER] Program scorer active")
