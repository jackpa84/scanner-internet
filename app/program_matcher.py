"""
Gap 1: Bounty Program Targeting

Maps discovered IPs to eligible bug bounty programs based on:
- Domain scope (in-scope, out-of-scope)
- IP ranges (CIDR blocks)
- ASN ranges
- Wildcard patterns

Pipeline:
  1. Load bug bounty program scopes from bounty_programs/bounty_targets
  2. Resolve discovered IPs to determine program eligibility
  3. Create IP → programs mapping
  4. Link vulnerabilities to eligible programs
  5. Filter reports to only eligible targets
  6. Add program-specific context (bounty amount, pvt vs public, etc)
"""

import ipaddress
import logging
import fnmatch
import re
import socket
import threading
from datetime import datetime
from typing import Any

from app.database import (
    get_bounty_programs, get_bounty_targets, get_scan_results,
    get_vuln_results, get_redis,
)

logger = logging.getLogger("scanner.program_matcher")

_stats = {
    "last_match": None,
    "ips_matched": 0,
    "programs_loaded": 0,
    "ip_program_pairs": 0,
    "errors": 0,
    "by_program": {},
}
_stats_lock = threading.Lock()


def _inc_stat(key: str, n: int = 1) -> None:
    """Increment statistics counter."""
    with _stats_lock:
        _stats[key] = _stats.get(key, 0) + n


def get_matcher_stats() -> dict[str, Any]:
    """Get current matching statistics."""
    with _stats_lock:
        return dict(_stats)


# ═══════════════════════════════════════════════════════════════
# IP Matching Functions
# ═══════════════════════════════════════════════════════════════

def _is_ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """Check if IP is in CIDR range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        cidr = ipaddress.ip_network(cidr_str, strict=False)
        return ip in cidr
    except (ValueError, ipaddress.AddressValueError):
        return False


def _domain_matches_pattern(domain: str, pattern: str) -> bool:
    """Check if domain matches pattern (including wildcards)."""
    # Normalize patterns: *.example.com → *.example.com
    domain = domain.lower().strip()
    pattern = pattern.lower().strip()

    # Remove leading/trailing dots
    domain = domain.strip(".")
    pattern = pattern.strip(".")

    # Match patterns
    if pattern.startswith("*."):
        # Wildcard: *.example.com matches app.example.com, api.example.com, etc
        base = pattern[2:]  # Remove *.
        return domain.endswith(base) or domain == base.strip(".")
    else:
        # Exact match or CIDR
        return fnmatch.fnmatch(domain, pattern)


def _reverse_lookup(ip: str) -> list[str]:
    """Attempt reverse DNS lookup to get hostnames."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return [hostname]
    except (socket.herror, socket.error):
        return []


# ═══════════════════════════════════════════════════════════════
# Program Matching Logic
# ═══════════════════════════════════════════════════════════════

def match_ip_to_programs(ip: str) -> list[dict]:
    """
    Match an IP against all loaded program scopes.
    
    Args:
        ip: IP address to match
        
    Returns:
        List of eligible programs with metadata
        [
            {
                "program_id": str,
                "platform": str,  # "hackerone", "bugcrowd", etc
                "name": str,
                "scope_match": str,  # "domain", "cidr", "asn", etc
                "offers_bounties": bool,
                "min_bounty": int,
                "max_bounty": int,
            },
            ...
        ]
    """
    programs = get_bounty_programs()
    targets = get_bounty_targets()
    redis = get_redis()

    eligible_programs = []

    try:
        # Get all programs from Redis
        prog_docs = programs.find() if hasattr(programs, "find") else []
        if not prog_docs:
            return []

        # Try reverse DNS first
        hostnames = _reverse_lookup(ip)

        for prog_doc in prog_docs:
            program_id = prog_doc.get("_id", "")
            platform = prog_doc.get("platform", "")

            # Get this program's targets
            target_key = f"bounty_targets:{platform}:{program_id}"
            target_doc = redis.hgetall(target_key)

            if not target_doc:
                continue

            # Parse scope from target document
            in_scope = target_doc.get(b"in_scope", b"[]")
            if isinstance(in_scope, bytes):
                in_scope = in_scope.decode("utf-8")

            try:
                import json
                in_scope = json.loads(in_scope) if isinstance(in_scope, str) else in_scope
            except (json.JSONDecodeError, TypeError):
                in_scope = []

            # Check if IP matches any in-scope domain/CIDR
            scope_match = None

            # Check CIDR ranges
            for scope_item in in_scope:
                scope_str = scope_item.get("target", "") if isinstance(scope_item, dict) else str(scope_item)

                # Try CIDR match
                if "/" in scope_str:
                    if _is_ip_in_cidr(ip, scope_str):
                        scope_match = "cidr"
                        break

            # Check reverse DNS against domain patterns
            if not scope_match and hostnames:
                for hostname in hostnames:
                    for scope_item in in_scope:
                        scope_str = scope_item.get("target", "") if isinstance(scope_item, dict) else str(scope_item)
                        if _domain_matches_pattern(hostname, scope_str):
                            scope_match = "domain"
                            break
                    if scope_match:
                        break

            # If IP matched, add program to eligible list
            if scope_match:
                eligible_programs.append({
                    "program_id": str(program_id),
                    "platform": platform,
                    "name": prog_doc.get("name", ""),
                    "handle": prog_doc.get("handle", ""),
                    "scope_match": scope_match,
                    "offers_bounties": prog_doc.get("offers_bounties", False),
                    "min_bounty": prog_doc.get("minimum_bounty", 0),
                    "max_bounty": prog_doc.get("maximum_bounty", 0),
                })

    except Exception as e:
        logger.error(f"Error matching IP {ip}: {e}")
        _inc_stat("errors")

    return eligible_programs


def build_ip_program_mapping(limit: int = None) -> dict[str, Any]:
    """
    Build complete mapping of discovered IPs → eligible programs.
    
    Args:
        limit: Max IPs to process (None = all)
        
    Returns:
        {
            "ips_processed": int,
            "ips_with_matches": int,
            "program_matches": int,
            "mappings": {
                "1.2.3.4": [
                    {"program_id": "...", "name": "...", ...},
                    ...
                ],
                ...
            },
            "stats_by_program": {
                "program_id": {
                    "matched_ips": int,
                    "platform": str,
                },
                ...
            }
        }
    """
    scan_results = get_scan_results()
    redis = get_redis()

    mappings = {}
    stats_by_program = {}
    errors = 0

    try:
        # Get all scanned IPs
        ip_docs = scan_results.find(limit=limit) if hasattr(scan_results, "find") else []
        ips_processed = 0

        for ip_doc in ip_docs:
            ip = ip_doc.get("ip", "")
            if not ip:
                continue

            ips_processed += 1

            # Match this IP against all programs
            eligible = match_ip_to_programs(ip)

            if eligible:
                mappings[ip] = eligible

                # Update stats by program
                for prog in eligible:
                    prog_id = prog["program_id"]
                    if prog_id not in stats_by_program:
                        stats_by_program[prog_id] = {
                            "matched_ips": 0,
                            "platform": prog["platform"],
                            "name": prog["name"],
                        }
                    stats_by_program[prog_id]["matched_ips"] += 1

        # Store mapping in Redis for persistence
        for ip, programs in mappings.items():
            import json
            redis.hset("ip_program_mapping", ip, json.dumps(programs))

        # Update global stats
        _inc_stat("last_match", datetime.utcnow().isoformat())
        _inc_stat("ips_matched", len(mappings))
        _inc_stat("programs_loaded", len(stats_by_program))
        _inc_stat("ip_program_pairs", sum(len(p) for p in mappings.values()))

        return {
            "ips_processed": ips_processed,
            "ips_with_matches": len(mappings),
            "program_matches": sum(len(p) for p in mappings.values()),
            "unique_programs": len(stats_by_program),
            "mappings": mappings,
            "stats_by_program": stats_by_program,
        }

    except Exception as e:
        logger.error(f"Error building IP-program mapping: {e}")
        _inc_stat("errors")
        return {
            "error": str(e),
            "ips_processed": 0,
            "ips_with_matches": 0,
            "program_matches": 0,
            "unique_programs": 0,
        }


# ═══════════════════════════════════════════════════════════════
# Vulnerability Program Assignment
# ═══════════════════════════════════════════════════════════════

def enrich_vulns_with_programs(limit: int = None) -> dict[str, Any]:
    """
    Enrich vulnerabilities with program eligibility information.
    
    For each vulnerability, determine which programs it's eligible for
    submission to based on the target IP.
    
    Args:
        limit: Max vulns to enrich (None = all)
        
    Returns:
        {
            "vulns_processed": int,
            "vulns_with_programs": int,
            "program_assignments": int,
            "errors": int,
        }
    """
    vuln_results = get_vuln_results()
    redis = get_redis()

    vulns_processed = 0
    vulns_with_programs = 0
    program_assignments = 0
    errors = 0

    try:
        # Get cached IP-program mapping
        ip_mapping_raw = redis.hgetall("ip_program_mapping")

        vulns = vuln_results.find(limit=limit) if hasattr(vuln_results, "find") else []

        for vuln_doc in vulns:
            ip = vuln_doc.get("ip", "")
            vuln_id = vuln_doc.get("_id", "")

            if not ip or not vuln_id:
                continue

            vulns_processed += 1

            # Get eligible programs for this IP
            eligible_programs = []

            if ip in ip_mapping_raw:
                import json
                try:
                    eligible_programs = json.loads(ip_mapping_raw[ip])
                except (json.JSONDecodeError, TypeError):
                    eligible_programs = []

            if eligible_programs:
                vulns_with_programs += 1
                program_assignments += len(eligible_programs)

                # Store program data with vulnerability
                vuln_doc["eligible_programs"] = eligible_programs
                vuln_doc["program_count"] = len(eligible_programs)

                # Update in database
                try:
                    vuln_results.save(vuln_doc)
                except Exception as e:
                    logger.warning(f"Failed to update vuln {vuln_id}: {e}")
                    errors += 1

        _inc_stat("last_match", datetime.utcnow().isoformat())

        return {
            "vulns_processed": vulns_processed,
            "vulns_with_programs": vulns_with_programs,
            "program_assignments": program_assignments,
            "errors": errors,
        }

    except Exception as e:
        logger.error(f"Error enriching vulns with programs: {e}")
        _inc_stat("errors")
        return {
            "error": str(e),
            "vulns_processed": 0,
            "vulns_with_programs": 0,
            "program_assignments": 0,
            "errors": 1,
        }


# ═══════════════════════════════════════════════════════════════
# Report Program Filtering
# ═══════════════════════════════════════════════════════════════

def get_programs_for_report(report_id: str) -> list[dict]:
    """
    Get eligible programs for a report (based on report's IP).
    
    Args:
        report_id: Report ObjectId
        
    Returns:
        List of eligible programs ready for submission
    """
    from app.report_processor import get_processed_reports

    try:
        reports = get_processed_reports(limit=100)
        if not reports:
            return []

        # Find our report
        report = None
        for r in reports:
            if str(r.get("_id", "")) == report_id:
                report = r
                break

        if not report:
            return []

        ip = report.get("ip", "")
        if not ip:
            return []

        # Get eligible programs for this IP
        return match_ip_to_programs(ip)

    except Exception as e:
        logger.error(f"Error getting programs for report {report_id}: {e}")
        return []


def filter_reports_by_eligibility(limit: int = None) -> dict[str, Any]:
    """
    Filter generated reports to only those with eligible programs.
    
    Creates a new collection of program-specific reports.
    
    Args:
        limit: Max reports to filter
        
    Returns:
        {
            "total_reports": int,
            "reports_with_programs": int,
            "submitted": int,
            "ready_for_submission": [
                {
                    "report_id": str,
                    "ip": str,
                    "programs": [{"program_id", "name", ...}],
                },
                ...
            ],
        }
    """
    from app.report_processor import get_processed_reports

    try:
        reports = get_processed_reports(limit=limit)
        if not reports:
            return {
                "total_reports": 0,
                "reports_with_programs": 0,
                "submitted": 0,
                "ready_for_submission": [],
            }

        redis = get_redis()
        ready_for_submission = []
        reports_with_programs = 0

        for report in reports:
            ip = report.get("ip", "")
            report_id = str(report.get("_id", ""))
            status = report.get("status", "draft")

            if not ip:
                continue

            # Get eligible programs
            eligible = match_ip_to_programs(ip)

            if eligible:
                reports_with_programs += 1

                ready_for_submission.append({
                    "report_id": report_id,
                    "ip": ip,
                    "severity": report.get("severity", ""),
                    "programs": eligible,
                    "status": status,
                })

        return {
            "total_reports": len(reports),
            "reports_with_programs": reports_with_programs,
            "submitted": sum(1 for r in ready_for_submission if r["status"] == "submitted"),
            "ready_for_submission": ready_for_submission,
        }

    except Exception as e:
        logger.error(f"Error filtering reports by eligibility: {e}")
        return {
            "error": str(e),
            "total_reports": 0,
            "reports_with_programs": 0,
            "submitted": 0,
            "ready_for_submission": [],
        }
