"""
Certificate Transparency (CT) log monitor.

Monitors CT logs for new certificates issued to tracked domains.
Finding new subdomains before anyone else = first-mover advantage in bounty programs.

Sources:
  - crt.sh (Comodo CT search)
  - CertSpotter (SSLMate)
  - Google CT API
"""

import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta
from typing import Any

import requests

from app.database import get_bounty_programs, get_bounty_targets, get_bounty_changes, get_redis

logger = logging.getLogger("scanner.ct_monitor")

CT_MONITOR_ENABLED = os.getenv("CT_MONITOR_ENABLED", "true").lower() in ("1", "true", "yes")
CT_POLL_INTERVAL = int(os.getenv("CT_POLL_INTERVAL", "600"))
CT_LOOKBACK_HOURS = int(os.getenv("CT_LOOKBACK_HOURS", "24"))
CERTSPOTTER_TOKEN = os.getenv("CERTSPOTTER_TOKEN", "").strip()

_stats = {
    "checks_completed": 0,
    "new_certs_found": 0,
    "new_subdomains_found": 0,
    "alerts_sent": 0,
    "errors": 0,
}
_stats_lock = threading.Lock()


def _inc_stat(key: str, n: int = 1) -> None:
    with _stats_lock:
        _stats[key] = _stats.get(key, 0) + n


def get_ct_stats() -> dict[str, Any]:
    with _stats_lock:
        return dict(_stats)


def _get_known_subdomains(program_id: str) -> set[str]:
    """Get all known subdomains for a program from the targets collection."""
    targets_col = get_bounty_targets()
    from bson import ObjectId
    try:
        oid = ObjectId(program_id)
    except Exception:
        return set()
    return {t["domain"] for t in targets_col.find({"program_id": oid}, {"domain": 1})}


def _extract_domains_from_cert(cert_data: dict) -> set[str]:
    """Extract all domain names from a certificate entry."""
    domains = set()

    common_name = cert_data.get("common_name", "")
    if common_name and "." in common_name:
        domains.add(common_name.lower().strip())

    for name in cert_data.get("name_value", "").split("\n"):
        name = name.strip().lower()
        if name and "." in name and not name.startswith("*"):
            domains.add(name)
        elif name.startswith("*."):
            domains.add(name[2:])

    dns_names = cert_data.get("dns_names", [])
    if isinstance(dns_names, list):
        for name in dns_names:
            name = name.strip().lower()
            if name and "." in name and not name.startswith("*"):
                domains.add(name)

    return domains


def query_crtsh(domain: str, hours: int = 24) -> list[dict]:
    """Query crt.sh for recent certificates."""
    try:
        after_date = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d")
        resp = requests.get(
            "https://crt.sh/",
            params={
                "q": f"%.{domain}",
                "output": "json",
                "exclude": "expired",
            },
            timeout=30,
            headers={"User-Agent": "ScannerCTMonitor/1.0"},
        )
        if resp.status_code != 200:
            return []

        certs = resp.json()
        recent = []
        for cert in certs:
            entry_date = cert.get("entry_timestamp", "")
            if entry_date and entry_date[:10] >= after_date:
                recent.append(cert)

        return recent

    except Exception as e:
        logger.debug("[CT] crt.sh error for %s: %s", domain, e)
        _inc_stat("errors")
        return []


def query_certspotter(domain: str) -> list[dict]:
    """Query CertSpotter API for recent certificates."""
    if not CERTSPOTTER_TOKEN:
        return []

    try:
        headers = {"Authorization": f"Bearer {CERTSPOTTER_TOKEN}"}
        after = (datetime.utcnow() - timedelta(hours=CT_LOOKBACK_HOURS)).isoformat() + "Z"

        resp = requests.get(
            "https://api.certspotter.com/v1/issuances",
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
                "after": after,
            },
            headers=headers,
            timeout=30,
        )
        if resp.status_code != 200:
            return []

        return resp.json()

    except Exception as e:
        logger.debug("[CT] CertSpotter error for %s: %s", domain, e)
        _inc_stat("errors")
        return []


def _get_root_domains_from_scope(in_scope: list[str]) -> list[str]:
    """Extract root domains from scope items."""
    domains = []
    for item in in_scope:
        item = item.strip().lower()
        if item.startswith("*."):
            item = item[2:]
        item = re.sub(r'^https?://', '', item)
        item = item.split("/")[0].split(":")[0]
        if "." in item and not item.replace(".", "").isdigit():
            parts = item.split(".")
            if len(parts) >= 2:
                root = ".".join(parts[-2:]) if len(parts[-1]) <= 3 else item
                if root not in domains:
                    domains.append(root)
    return domains


def check_ct_for_program(program_id: str, program: dict) -> dict[str, Any]:
    """Check CT logs for new certificates for a bounty program."""
    in_scope = program.get("in_scope", [])
    if isinstance(in_scope, str):
        in_scope = [in_scope]

    root_domains = _get_root_domains_from_scope(in_scope)
    if not root_domains:
        return {"new_domains": [], "error": "no root domains"}

    known = _get_known_subdomains(program_id)
    new_domains: set[str] = set()

    for domain in root_domains[:5]:
        certs = query_crtsh(domain, CT_LOOKBACK_HOURS)
        _inc_stat("new_certs_found", len(certs))

        for cert in certs:
            cert_domains = _extract_domains_from_cert(cert)
            for d in cert_domains:
                if d.endswith(f".{domain}") or d == domain:
                    if d not in known:
                        new_domains.add(d)

        if CERTSPOTTER_TOKEN:
            cs_certs = query_certspotter(domain)
            for cert in cs_certs:
                dns_names = cert.get("dns_names", [])
                for d in dns_names:
                    d = d.strip().lower()
                    if d.startswith("*."):
                        d = d[2:]
                    if (d.endswith(f".{domain}") or d == domain) and d not in known:
                        new_domains.add(d)

        time.sleep(2)

    _inc_stat("checks_completed")
    _inc_stat("new_subdomains_found", len(new_domains))

    return {
        "program_id": program_id,
        "program_name": program.get("name", "?"),
        "root_domains": root_domains,
        "new_domains": sorted(new_domains),
        "known_count": len(known),
        "checked_at": datetime.utcnow().isoformat(),
    }


def _save_ct_discoveries(program_id: str, program_name: str, new_domains: list[str]) -> None:
    """Save CT discoveries to bounty_changes and notify."""
    if not new_domains:
        return

    changes_col = get_bounty_changes()
    changes_col.insert_one({
        "program_id": program_id,
        "program_name": program_name,
        "timestamp": datetime.utcnow(),
        "source": "ct_monitor",
        "new_subdomains": new_domains,
        "removed_subdomains": [],
        "total_new": len(new_domains),
    })

    logger.info("[CT] NEW DOMAINS for '%s': %s", program_name, ", ".join(new_domains[:10]))

    try:
        r = get_redis()
        alert = json.dumps({
            "type": "ct_new_domains",
            "program": program_name,
            "domains": new_domains,
            "timestamp": datetime.utcnow().isoformat(),
        })
        r.rpush("ct_alerts", alert)
        r.ltrim("ct_alerts", -100, -1)
    except Exception:
        pass


def check_all_programs() -> list[dict]:
    """Check CT logs for all active bounty programs."""
    programs_col = get_bounty_programs()
    results = []

    for program in programs_col.find({"status": {"$in": ["active", None]}}):
        pid = str(program["_id"])
        try:
            result = check_ct_for_program(pid, program)
            if result.get("new_domains"):
                _save_ct_discoveries(pid, program.get("name", "?"), result["new_domains"])
            results.append(result)
        except Exception as e:
            logger.error("[CT] Error checking program '%s': %s", program.get("name", "?"), e)
            _inc_stat("errors")

        time.sleep(3)

    return results


def _ct_monitor_loop() -> None:
    """Background loop for CT monitoring."""
    time.sleep(60)
    logger.info("[CT] Monitor started (interval=%ds, lookback=%dh)",
                CT_POLL_INTERVAL, CT_LOOKBACK_HOURS)

    while True:
        try:
            results = check_all_programs()
            total_new = sum(len(r.get("new_domains", [])) for r in results)
            if total_new > 0:
                logger.info("[CT] Found %d new subdomains across %d programs", total_new, len(results))
        except Exception as e:
            logger.error("[CT] Monitor loop error: %s", e)
            _inc_stat("errors")

        time.sleep(CT_POLL_INTERVAL)


def start_ct_monitor() -> None:
    """Start the CT log monitor background thread."""
    if not CT_MONITOR_ENABLED:
        logger.info("[CT] Monitor disabled")
        return

    t = threading.Thread(target=_ct_monitor_loop, daemon=True)
    t.start()
    logger.info("[CT] Monitor active")
