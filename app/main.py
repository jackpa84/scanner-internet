import os
import time
import threading
import logging
import ipaddress
import json
import re
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from bson import ObjectId
import requests
import pymongo.errors

from fastapi.responses import PlainTextResponse

from app.database import (
    init_db, get_scan_results, get_vuln_results,
    get_bounty_programs, get_bounty_targets, get_bounty_changes,
)
from app.scanner import (
    run_scanner, NUM_SCANNER_WORKERS, SCAN_INTERVAL, SHODAN_RPS, SHODAN_ENABLED,
    IPAPI_RPS, IPINFO_RPS,
    compute_risk_profile, get_breaker_status, get_scan_stats,
)
from app.ip_feeds import get_feed_stats
from app.vuln_scanner import (
    start_vuln_scanner, enqueue_ip, get_vuln_scan_stats,
    NUM_VULN_WORKERS, VULN_AUTO_SCAN, NUCLEI_SEVERITY,
    enqueue_bounty_target,
)
from app.bounty import (
    start_bounty_system,
    recon_pipeline,
    generate_report,
    get_recon_stats,
    BOUNTY_MODE,
)
from app.program_scorer import (
    start_program_scorer, score_all_programs,
    get_prioritized_programs, get_scorer_stats,
    auto_import_new_programs, fetch_new_h1_programs,
)
from app.interactsh_client import (
    start_interactsh_poller, get_interactsh_stats,
    get_confirmed_vulns,
)
from app.ct_monitor import start_ct_monitor, get_ct_stats, check_all_programs as ct_check_all
from app.cve_monitor import start_cve_monitor, get_cve_stats, get_recent_cves, process_new_cves
from app.roi_tracker import (
    start_roi_tracker, get_overall_dashboard as roi_dashboard,
    get_earnings_summary, record_earning, get_program_roi,
)
from app.idor_scanner import get_idor_stats
from app.ssrf_scanner import get_ssrf_stats
from app.graphql_scanner import get_graphql_stats
from app.race_condition_scanner import get_race_stats
from app.report_generator import generate_h1_report, deduplicate_findings
from app.vuln_processor_v2 import (
    process_scan_vulnerabilities, deduplicate_vulnerabilities,
    get_processed_vulnerabilities, mark_false_positive, get_processor_stats,
)
from app.report_processor import (
    process_vulnerabilities_to_reports, get_processed_reports,
    mark_report_submitted, get_report_stats,
)
from app.h1_submission import (
    submit_report_to_h1, batch_submit_reports,
    get_submission_stats, get_submission_queue,
)
from app.program_matcher import (
    match_ip_to_programs, build_ip_program_mapping,
    enrich_vulns_with_programs, get_programs_for_report,
    filter_reports_by_eligibility, get_matcher_stats,
)
from app.program_matcher_async import (
    match_ip_to_programs_cached, queue_ips_for_matching, process_ip_match_queue,
    enrich_vuln_with_programs_async, queue_vulns_for_enrichment,
    filter_report_to_programs_async, subscribe_to_channel,
    start_program_matcher_worker,
)
from app.ai_analyzer import (
    AI_ENABLED as AI_ANALYZER_ENABLED,
    ai_write_report, ai_classify_finding, ai_classify_findings_batch,
    ai_analyze_response, ai_parse_scope, ai_analyze_javascript,
    ai_find_vuln_chains, get_ai_stats,
)
from app.bounty_targets_data import (
    start_bounty_data_sync, sync_bounty_targets_data,
    fetch_all_programs as btd_fetch_all, fetch_domain_lists,
    search_programs as btd_search, get_bounty_data_stats,
    get_all_bounty_domains,
)
from app.bug_scraper_integration import sync_bug_scraper_programs
from app.auth import AuthMiddleware, authenticate, AUTH_USERNAME

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
NETWORK_SCANNER_ENABLED = os.getenv("NETWORK_SCANNER_ENABLED", "true").lower() in ("1", "true", "yes")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(message)s",
    datefmt="%H:%M:%S",
)

for noisy in [
    "pymongo", "pymongo.command", "pymongo.connection", "pymongo.serverSelection",
    "pymongo.topology", "urllib3", "urllib3.connectionpool",
    "requests", "charset_normalizer",
]:
    logging.getLogger(noisy).setLevel(logging.WARNING)

logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

logger = logging.getLogger("scanner")

app = FastAPI(title="Scanner Internet API", version="2.0.0")


def _storage_error_handler(request, exc: Exception):
    logger.warning("Storage error: %s", exc)
    return JSONResponse(
        status_code=503,
        content={"detail": "Storage temporarily unavailable"},
    )


app.add_exception_handler(
    pymongo.errors.ServerSelectionTimeoutError,
    _storage_error_handler,
)
app.add_exception_handler(
    pymongo.errors.ConnectionFailure,
    _storage_error_handler,
)
try:
    import redis as _redis_mod
    app.add_exception_handler(
        _redis_mod.exceptions.ConnectionError,
        _storage_error_handler,
    )
    app.add_exception_handler(
        _redis_mod.exceptions.TimeoutError,
        _storage_error_handler,
    )
except ImportError:
    pass


class RequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        ms = (time.perf_counter() - start) * 1000
        path = request.url.path
        if path.startswith("/api/"):
            short = path.replace("/api/", "")
            logger.debug("[API] %s %s -> %s (%.0fms)", request.method, short, response.status_code, ms)
        return response

# CORS: credentials=False permite allow_origins=["*"] (evita 403 no preflight)
# O front usa Bearer no header, não cookies, então credentials não é necessário.
app.add_middleware(RequestLogMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


def _serialize_doc(doc):
    d = dict(doc)
    d["id"] = str(d.pop("_id", ""))
    ts = d.get("timestamp")
    if ts and hasattr(ts, "isoformat"):
        d["timestamp"] = ts.isoformat() + "Z"
    if not isinstance(d.get("risk"), dict):
        d["risk"] = compute_risk_profile(
            d.get("ports") or [],
            d.get("vulns") or [],
            d.get("hostnames") or [],
            d.get("router_info") or [],
        )
    return d


@app.get("/")
def root():
    return {"message": "Scanner Internet API v2", "docs": "/docs"}


@app.get("/api/results")
def api_results():
    col = get_scan_results()
    if hasattr(col, "find_optimized"):
        docs = col.find_optimized(sort_key="timestamp", sort_dir=-1, limit=100)
    else:
        docs = col.find().sort("timestamp", -1).limit(100)
    data = []
    for doc in docs:
        d = _serialize_doc(doc)
        d["router_count"] = len(d.get("router_info") or [])
        data.append(d)
    return data


@app.get("/api/router_info/{scan_id}")
def api_router_info(scan_id: str):
    try:
        oid = ObjectId(scan_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid scan id")
    col = get_scan_results()
    doc = col.find_one({"_id": oid})
    if not doc:
        return []
    router_info = doc.get("router_info") or []
    return [
        {k: v for k, v in i.items() if k in ("port", "service", "banner", "title", "server")}
        for i in router_info
    ]


@app.get("/api/stats")
def api_stats():
    col = get_scan_results()

    def _compute_stats():
        total = col.count_documents({})
        with_ports = col.count_documents({"ports": {"$exists": True, "$ne": []}})
        with_vulns = col.count_documents({"vulns": {"$exists": True, "$ne": []}})
        with_router_info = col.count_documents({"router_info.0": {"$exists": True}})
        with_high_risk = col.count_documents({"risk.score": {"$gte": 70}})
        with_geo = col.count_documents({"geo.country": {"$exists": True, "$ne": ""}})

        top_countries = list(col.aggregate([
            {"$match": {"geo.country": {"$exists": True, "$ne": ""}}},
            {"$group": {"_id": "$geo.country", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10},
        ]))

        return {
            "total": total,
            "with_ports": with_ports,
            "with_vulns": with_vulns,
            "with_router_info": with_router_info,
            "with_high_risk": with_high_risk,
            "with_geo": with_geo,
            "top_countries": [{"country": c["_id"], "count": c["count"]} for c in top_countries],
        }

    if hasattr(col, "cached_stats"):
        return col.cached_stats(_compute_stats, ttl=10.0)
    return _compute_stats()


@app.get("/api/prioritized_findings")
def api_prioritized_findings(limit: int = 20, min_score: int = 40):
    limit = max(1, min(limit, 100))
    min_score = max(0, min(min_score, 100))
    col = get_scan_results()

    if hasattr(col, "find_optimized"):
        docs = col.find_optimized(
            filt={"risk.score": {"$gte": min_score}},
            sort_key="risk.score", sort_dir=-1, limit=limit,
        )
        results = [_serialize_doc(doc) for doc in docs]
    else:
        cursor = col.find({"risk.score": {"$gte": min_score}}).sort("risk.score", -1).limit(limit)
        results = [_serialize_doc(doc) for doc in cursor]

    if not results:
        if hasattr(col, "find_optimized"):
            fallback_docs = col.find_optimized(sort_key="timestamp", sort_dir=-1, limit=300)
        else:
            fallback_docs = col.find().sort("timestamp", -1).limit(300)
        fallback = [_serialize_doc(doc) for doc in fallback_docs]
        fallback = [r for r in fallback if (r.get("risk") or {}).get("score", 0) >= min_score]
        fallback.sort(key=lambda x: (x.get("risk") or {}).get("score", 0), reverse=True)
        results = fallback[:limit]

    return results


@app.post("/api/auth/login")
def api_auth_login(body: dict):
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "").strip()
    token = authenticate(username, password)
    if not token:
        raise HTTPException(status_code=401, detail="Usuario ou senha incorretos")
    return {"token": token, "username": username}


@app.get("/api/health")
def api_health():
    breakers = get_breaker_status()
    blocked = [b for b in breakers if b["blocked"]]
    scan_stats = get_scan_stats()
    feed_stats = get_feed_stats()
    vuln_stats = get_vuln_scan_stats()

    enrich_cache_stats = {}
    try:
        from app.redis_store import get_enrich_cache
        cache = get_enrich_cache()
        if cache:
            enrich_cache_stats = cache.stats()
    except Exception:
        pass

    return {
        "network_scanner_enabled": NETWORK_SCANNER_ENABLED,
        "workers": NUM_SCANNER_WORKERS,
        "scan_interval": SCAN_INTERVAL,
        "shodan_enabled": SHODAN_ENABLED,
        "shodan_rps": SHODAN_RPS,
        "ipapi_rps": IPAPI_RPS,
        "ipinfo_rps": IPINFO_RPS,
        "apis": breakers,
        "blocked_count": len(blocked),
        "scan_stats": scan_stats,
        "feeds": feed_stats,
        "vuln_scanner": vuln_stats,
        "enrich_cache": enrich_cache_stats,
    }


@app.get("/api/db/activity")
def api_db_activity(limit: int = 30):
    """Real-time MongoDB activity log: latest writes across all collections."""
    limit = max(1, min(limit, 100))
    activity: list[dict] = []

    try:
        col = get_scan_results()
        proj = {"ip": 1, "risk.score": 1, "risk.level": 1, "ports": 1, "vulns": 1, "geo.country": 1, "timestamp": 1}
        if hasattr(col, "find_optimized"):
            scan_docs = col.find_optimized(projection=proj, sort_key="timestamp", sort_dir=-1, limit=limit)
        else:
            scan_docs = col.find({}, proj).sort("timestamp", -1).limit(limit)
        for doc in scan_docs:
            ts = doc.get("timestamp")
            activity.append({
                "collection": "scan_results",
                "action": "scan",
                "summary": f"{doc.get('ip', '?')} | risk:{(doc.get('risk') or {}).get('score', 0)} | ports:{len(doc.get('ports', []))} | vulns:{len(doc.get('vulns', []))}",
                "ip": doc.get("ip", ""),
                "risk_level": (doc.get("risk") or {}).get("level", ""),
                "country": (doc.get("geo") or {}).get("country", ""),
                "timestamp": ts.isoformat() + "Z" if ts and hasattr(ts, "isoformat") else "",
            })

        vcol = get_vuln_results()
        for doc in vcol.find({}, {"ip": 1, "severity": 1, "name": 1, "template_id": 1, "tool": 1, "timestamp": 1}).sort("timestamp", -1).limit(limit):
            ts = doc.get("timestamp")
            activity.append({
                "collection": "vuln_results",
                "action": "vuln",
                "summary": f"{doc.get('ip', '?')} | {doc.get('severity', '?')} | {doc.get('name') or doc.get('template_id', '?')}",
                "ip": doc.get("ip", ""),
                "risk_level": doc.get("severity", ""),
                "country": "",
                "timestamp": ts.isoformat() + "Z" if ts and hasattr(ts, "isoformat") else "",
            })

        tcol = get_bounty_targets()
        for doc in tcol.find({}, {"domain": 1, "alive": 1, "status": 1, "is_new": 1, "last_recon": 1}).sort("last_recon", -1).limit(min(limit, 10)):
            ts = doc.get("last_recon")
            tag = "NEW " if doc.get("is_new") else ""
            alive = "alive" if doc.get("alive") else "dead"
            activity.append({
                "collection": "bounty_targets",
                "action": "recon",
                "summary": f"{tag}{doc.get('domain', '?')} | {alive} | {doc.get('status', '')}",
                "ip": "",
                "risk_level": "",
                "country": "",
                "timestamp": ts.isoformat() + "Z" if ts and hasattr(ts, "isoformat") else "",
            })

        activity.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        activity = activity[:limit]
    except Exception as e:
        return {"error": str(e), "activity": [], "counts": {}}

    try:
        counts = {
            "scan_results": get_scan_results().estimated_document_count(),
            "vuln_results": get_vuln_results().estimated_document_count(),
            "bounty_programs": get_bounty_programs().estimated_document_count(),
            "bounty_targets": get_bounty_targets().estimated_document_count(),
            "bounty_changes": get_bounty_changes().estimated_document_count(),
        }
    except Exception:
        counts = {}

    return {"activity": activity, "counts": counts}


# ---------------------------------------------------------------------------
# Vuln scan endpoints
# ---------------------------------------------------------------------------
def _serialize_vuln(doc):
    d = dict(doc)
    d["id"] = str(d.pop("_id", ""))
    if d.get("scan_result_id"):
        d["scan_result_id"] = str(d["scan_result_id"])
    ts = d.get("timestamp")
    if ts and hasattr(ts, "isoformat"):
        d["timestamp"] = ts.isoformat() + "Z"
    d.pop("raw_output", None)
    return d


@app.post("/api/vulns/scan")
def api_vuln_scan_trigger(body: dict):
    """Trigger vuln scan: {"ip": "1.2.3.4"} or {"min_score": 70}."""
    ip = body.get("ip")
    if ip:
        col = get_scan_results()
        doc = col.find_one({"ip": ip}, {"risk.score": 1})
        score = doc.get("risk", {}).get("score", 50) if doc else 50
        sid = str(doc["_id"]) if doc else None
        ok = enqueue_ip(ip, score, sid)
        return {"queued": ok, "ip": ip}

    min_score = body.get("min_score", 70)
    col = get_scan_results()
    cursor = col.find(
        {"risk.score": {"$gte": min_score}},
        {"ip": 1, "risk.score": 1},
    ).sort("risk.score", -1).limit(50)
    enqueued = 0
    for doc in cursor:
        doc_ip = doc.get("ip")
        s = doc.get("risk", {}).get("score", 0)
        if doc_ip and enqueue_ip(doc_ip, s, str(doc["_id"])):
            enqueued += 1
    return {"queued": enqueued, "min_score": min_score}


@app.get("/api/vulns/results")
def api_vuln_results(limit: int = 50, severity: str | None = None, ip: str | None = None):
    limit = max(1, min(limit, 200))
    vcol = get_vuln_results()
    query: dict = {}
    if severity:
        query["severity"] = severity
    if ip:
        query["ip"] = ip
    cursor = vcol.find(query).sort("timestamp", -1).limit(limit)
    return [_serialize_vuln(doc) for doc in cursor]


@app.get("/api/vulns/stats")
def api_vuln_stats():
    vcol = get_vuln_results()
    total = vcol.count_documents({})

    sev_pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    by_severity = {r["_id"]: r["count"] for r in vcol.aggregate(sev_pipeline)}

    tool_pipeline = [
        {"$group": {"_id": "$tool", "count": {"$sum": 1}}},
    ]
    by_tool = {r["_id"]: r["count"] for r in vcol.aggregate(tool_pipeline)}

    top_vulns = list(vcol.aggregate([
        {"$group": {"_id": "$template_id", "name": {"$first": "$name"}, "severity": {"$first": "$severity"}, "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]))

    unique_ips = vcol.distinct("ip")

    scan_stats = get_vuln_scan_stats()

    return {
        "total_vulns": total,
        "unique_ips_scanned": len(unique_ips),
        "by_severity": {
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
            "info": by_severity.get("info", 0),
        },
        "by_tool": by_tool,
        "top_vulns": [{"template_id": v["_id"], "name": v["name"], "severity": v["severity"], "count": v["count"]} for v in top_vulns],
        "scanner": scan_stats,
    }


@app.post("/api/vulns/process")
def api_vuln_process(body: dict | None = None):
    """
    Process vulnerabilities from scan_results → vuln_results.
    
    Enrich with CVSS scores, PoC, remediation, confidence, etc.
    
    Body (optional):
      {
        "scan_id": "optional ObjectId of specific scan",
        "batch_size": 50 (optional)
      }
    """
    body = body or {}
    scan_id = body.get("scan_id")
    batch_size = body.get("batch_size", 50)
    
    results = process_scan_vulnerabilities(scan_id=scan_id, batch_size=batch_size)
    
    return {
        "status": "processed",
        "processed_scans": results["processed_scans"],
        "processed_vulns": results["processed_vulns"],
        "enriched": results["enriched"],
        "skipped_duplicates": results["skipped_duplicates"],
        "errors": results["errors"],
    }


@app.post("/api/vulns/deduplicate")
def api_vuln_deduplicate():
    """Remove duplicate vulnerabilities from vuln_results."""
    results = deduplicate_vulnerabilities()
    
    return {
        "status": "deduplicated",
        "total_vulns": results["total_vulns"],
        "duplicates_found": results["duplicates_found"],
        "removed": results["removed"],
    }


@app.get("/api/vulns/processed")
def api_vuln_processed(limit: int = 100, severity: str | None = None):
    """Get processed and enriched vulnerabilities from vuln_results."""
    limit = max(1, min(limit, 500))
    vulns = get_processed_vulnerabilities(limit=limit, severity=severity)
    
    return {
        "count": len(vulns),
        "vulns": [
            {
                "id": str(v["_id"]),
                "ip": v.get("ip"),
                "title": v.get("title"),
                "severity": v.get("severity"),
                "confidence": v.get("confidence"),
                "cvss_base": v.get("cvss_base"),
                "type": v.get("type"),
                "status": v.get("status"),
                "timestamp": v.get("timestamp").isoformat() if v.get("timestamp") else None,
            }
            for v in vulns
        ]
    }


@app.post("/api/vulns/{vuln_id}/mark-fp")
def api_mark_false_positive(vuln_id: str):
    """Mark a vulnerability as false positive."""
    success = mark_false_positive(vuln_id)
    
    return {
        "status": "marked" if success else "not_found",
        "vuln_id": vuln_id,
    }


@app.get("/api/vulns/processor/stats")
def api_processor_stats():
    """Get vulnerability processor statistics."""
    return get_processor_stats()


@app.post("/api/reports/generate")
def api_generate_reports(body: dict | None = None):
    """
    Generate HackerOne-formatted reports from processed vulnerabilities.
    
    Body (optional):
      {
        "limit": 50 (max vulns to process),
        "severity_threshold": "low" (minimum severity)
      }
    """
    body = body or {}
    limit = body.get("limit", 50)
    severity_threshold = body.get("severity_threshold", "low")
    
    results = process_vulnerabilities_to_reports(limit=limit, severity_threshold=severity_threshold)
    
    return {
        "status": "generated",
        "processed_vulns": results["processed_vulns"],
        "reports_generated": results["reports_generated"],
        "errors": results["errors"],
    }


@app.get("/api/reports")
def api_get_reports(limit: int = 100, status: str = "draft", severity: str | None = None):
    """Get generated reports."""
    limit = max(1, min(limit, 500))
    reports = get_processed_reports(limit=limit, status=status, severity=severity)
    
    return {
        "count": len(reports),
        "reports": [
            {
                "id": str(r["_id"]),
                "ip": r.get("ip"),
                "title": r.get("title"),
                "severity": r.get("severity"),
                "vulnerability_count": r.get("vulnerability_count"),
                "status": r.get("status"),
                "auto_submit_eligible": r.get("auto_submit_eligible"),
                "created_at": r.get("created_at").isoformat() if r.get("created_at") else None,
            }
            for r in reports
        ]
    }


@app.post("/api/reports/{report_id}/submit")
def api_submit_report(report_id: str, body: dict | None = None):
    """Mark a report as submitted to HackerOne."""
    body = body or {}
    submission_id = body.get("h1_submission_id", "")
    
    success = mark_report_submitted(report_id, submission_id)
    
    return {
        "status": "submitted" if success else "not_found",
        "report_id": report_id,
        "h1_submission_id": submission_id,
    }


@app.get("/api/reports/stats")
def api_report_stats():
    """Get report generation statistics."""
    return get_report_stats()


# ---------------------------------------------------------------------------
# HackerOne Submission endpoints
# ---------------------------------------------------------------------------

@app.post("/api/h1/submit/{report_id}")
def api_h1_submit(report_id: str, body: dict | None = None):
    """
    Submit a single report to HackerOne.
    
    Body (optional):
      {
        "dry_run": true (optional, validate without submitting)
      }
    """
    body = body or {}
    dry_run = body.get("dry_run", False)
    
    result = submit_report_to_h1(report_id, dry_run=dry_run)
    
    return result


@app.post("/api/h1/batch-submit")
def api_h1_batch_submit(body: dict | None = None):
    """
    Batch submit reports to HackerOne.
    
    Body (optional):
      {
        "limit": 10 (max reports),
        "auto_only": false (only auto-eligible),
        "dry_run": false (validate without submitting)
      }
    """
    body = body or {}
    limit = body.get("limit", 10)
    auto_only = body.get("auto_only", False)
    dry_run = body.get("dry_run", False)
    
    results = batch_submit_reports(limit=limit, auto_only=auto_only, dry_run=dry_run)
    
    return {
        "status": "batch_submitted",
        "submitted": results["submitted"],
        "duplicates": results["duplicates"],
        "errors": results["errors"],
        "skipped": results["skipped"],
        "details": results["details"],
    }


@app.get("/api/h1/queue")
def api_h1_queue():
    """
    Get reports waiting in submission queue.
    """
    queue = get_submission_queue()
    
    return {
        "count": len(queue),
        "reports": [
            {
                "id": str(r["_id"]),
                "ip": r.get("ip"),
                "title": r.get("title"),
                "severity": r.get("severity"),
                "vulnerability_count": r.get("vulnerability_count"),
            }
            for r in queue
        ]
    }


@app.get("/api/h1/stats")
def api_h1_stats():
    """
    Get HackerOne submission statistics.
    """
    return get_submission_stats()


# ---------------------------------------------------------------------------
# Gap 1: Bounty Program Targeting endpoints
# ---------------------------------------------------------------------------

@app.post("/api/programs/match-ip")
def api_programs_match_ip(body: dict):
    """
    Match a single IP against all loaded bounty programs.
    
    Body:
      {
        "ip": "1.2.3.4"  (required)
      }
    
    Returns:
      [
        {
          "program_id": str,
          "platform": str,
          "name": str,
          "scope_match": str,  ("domain", "cidr", etc)
          "offers_bounties": bool,
          "min_bounty": int,
          "max_bounty": int,
        },
        ...
      ]
    """
    ip = (body.get("ip") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required")
    
    programs = match_ip_to_programs(ip)
    
    return {
        "ip": ip,
        "programs_found": len(programs),
        "programs": programs,
    }


@app.post("/api/programs/build-mapping")
def api_programs_build_mapping(body: dict | None = None):
    """
    Build complete IP → programs mapping for all discovered IPs.
    
    Body (optional):
      {
        "limit": 100  (max IPs to process, None = all)
      }
    
    Returns:
      {
        "ips_processed": int,
        "ips_with_matches": int,
        "program_matches": int,
        "unique_programs": int,
        "mappings": { "ip": [...programs...] },
        "stats_by_program": { "program_id": {...} },
      }
    """
    body = body or {}
    limit = body.get("limit")
    
    result = build_ip_program_mapping(limit=limit)
    
    return result


@app.post("/api/vulns/enrich-with-programs")
def api_vulns_enrich_with_programs(body: dict | None = None):
    """
    Enrich all vulnerabilities with program eligibility information.
    
    For each vulnerability, determine which programs it's eligible for
    based on the target IP's program associations.
    
    Body (optional):
      {
        "limit": 50  (max vulns to enrich, None = all)
      }
    
    Returns:
      {
        "vulns_processed": int,
        "vulns_with_programs": int,
        "program_assignments": int,
        "errors": int,
      }
    """
    body = body or {}
    limit = body.get("limit")
    
    result = enrich_vulns_with_programs(limit=limit)
    
    return result


@app.get("/api/reports/{report_id}/programs")
def api_reports_programs(report_id: str):
    """
    Get eligible programs for a specific report.
    
    Returns programs the report can be submitted to based on the
    report's IP and program scopes.
    """
    programs = get_programs_for_report(report_id)
    
    return {
        "report_id": report_id,
        "programs_eligible": len(programs),
        "programs": programs,
    }


@app.get("/api/reports/by-program")
def api_reports_by_program(body: dict | None = None):
    """
    Filter all generated reports by program eligibility.
    
    Returns program-specific report collections ready for submission.
    
    Returns:
      {
        "total_reports": int,
        "reports_with_programs": int,
        "submitted": int,
        "ready_for_submission": [
          {
            "report_id": str,
            "ip": str,
            "severity": str,
            "programs": [...],
            "status": str,
          },
          ...
        ]
      }
    """
    body = body or {}
    limit = body.get("limit")
    
    result = filter_reports_by_eligibility(limit=limit)
    
    return result


@app.get("/api/programs/matcher/stats")
def api_programs_matcher_stats():
    """
    Get program matching statistics.
    """
    return get_matcher_stats()


# ---------------------------------------------------------------------------
# Gap 1: Async Program Targeting (Redis → Pub/Sub → MongoDB)
# ---------------------------------------------------------------------------

@app.post("/api/programs/match-ip-async")
def api_programs_match_ip_async(body: dict):
    """
    Match IP to programs with Redis caching + Pub/Sub notifications.
    
    1. Checks Redis cache first
    2. If not cached, computes and stores (24hr TTL)
    3. Publishes via Pub/Sub for real-time updates
    4. Fast response from Redis
    
    Body:
      {
        "ip": "1.2.3.4"  (required),
        "use_cache": true  (optional, default: true)
      }
    """
    ip = (body.get("ip") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required")
    
    use_cache = body.get("use_cache", True)
    programs = match_ip_to_programs_cached(ip, use_cache=use_cache)
    
    return {
        "ip": ip,
        "cached": use_cache,
        "programs_found": len(programs),
        "programs": programs,
        "source": "redis_cache",
    }


@app.post("/api/programs/queue-ips")
def api_queue_ips_for_matching(body: dict):
    """
    Queue multiple IPs for background matching (async).
    
    Background worker will process these and publish updates
    via Pub/Sub channel 'programs:matched'.
    
    Body:
      {
        "ips": ["1.2.3.4", "5.6.7.8", ...]  (required)
      }
    
    Returns:
      {
        "queued": int,
        "channel": "programs:matched"
      }
    """
    ips = body.get("ips", [])
    if not isinstance(ips, list) or not ips:
        raise HTTPException(status_code=400, detail="ips must be a non-empty list")
    
    queued = queue_ips_for_matching(ips)
    
    return {
        "queued": queued,
        "channel": "programs:matched",
        "subscribe": "/api/programs/subscribe/matched"
    }


@app.post("/api/programs/process-queue")
def api_process_queue_manual(body: dict | None = None):
    """
    Manually trigger processing of IP matching queue.
    
    Normally runs in background, but can be triggered manually.
    
    Body (optional):
      {
        "batch_size": 50  (default: 50)
      }
    """
    body = body or {}
    batch_size = body.get("batch_size", 50)
    
    result = process_ip_match_queue(batch_size=batch_size)
    
    return {
        "processed": result["processed"],
        "matched": result["matched"],
        "cached": result["cached"],
        "items_ready_for_mongo": len(result["ready_for_mongo"]),
    }


@app.post("/api/vulns/enrich-async")
def api_vulns_enrich_async(body: dict):
    """
    Enrich single vulnerability with programs (async via Pub/Sub).
    
    1. Redis stores the enrichment immediately
    2. Pub/Sub publishes for real-time updates
    3. Background worker may persist to MongoDB
    
    Body:
      {
        "vuln_id": "...",  (required, ObjectId as string)
        "ip": "1.2.3.4"  (required)
      }
    """
    vuln_id = (body.get("vuln_id") or "").strip()
    ip = (body.get("ip") or "").strip()
    
    if not vuln_id or not ip:
        raise HTTPException(status_code=400, detail="vuln_id and ip are required")
    
    result = enrich_vuln_with_programs_async(vuln_id, ip)
    
    return {
        "vuln_id": vuln_id,
        "ip": ip,
        "programs_found": result["programs_found"],
        "programs": result["programs"],
        "source": "redis_cache",
        "channel": "vulns:enriched",
    }


@app.post("/api/vulns/queue-for-enrichment")
def api_queue_vulns_for_enrichment(body: dict):
    """
    Queue vulnerabilities for background enrichment (async).
    
    Body:
      {
        "vulns": [
          {"_id": "...", "ip": "1.2.3.4"},
          ...
        ]
      }
    """
    vulns = body.get("vulns", [])
    if not isinstance(vulns, list) or not vulns:
        raise HTTPException(status_code=400, detail="vulns must be a non-empty list")
    
    queued = queue_vulns_for_enrichment(vulns)
    
    return {
        "queued": queued,
        "channel": "vulns:enriched",
        "subscribe": "/api/programs/subscribe/enriched"
    }


@app.post("/api/reports/{report_id}/filter-programs-async")
def api_filter_report_async(report_id: str, body: dict | None = None):
    """
    Filter report to eligible programs (async via Pub/Sub).
    
    1. Redis stores the filtering immediately
    2. Pub/Sub publishes for real-time updates
    3. Background worker may persist to MongoDB
    """
    body = body or {}
    ip = (body.get("ip") or "").strip()
    
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required in body")
    
    result = filter_report_to_programs_async(report_id, ip)
    
    return {
        "report_id": report_id,
        "ip": ip,
        "eligible_programs": result["eligible_programs"],
        "programs": result["programs"],
        "source": "redis_cache",
        "channel": "reports:filtered",
    }


@app.get("/api/programs/subscribe/{channel}")
def api_subscribe_to_channel(channel: str, timeout: int = 60):
    """
    Subscribe to Pub/Sub channel and receive messages (polling-style).
    
    Supported channels:
      - programs:matched  (IP matching results)
      - vulns:enriched  (Vulnerability enrichments)
      - reports:filtered  (Report filtering results)
      - stats:updated  (Overall statistics updates)
    
    Query params:
      - timeout: Seconds to wait for messages (default: 60)
    
    For real applications, use WebSocket instead of polling.
    """
    if channel not in ["programs:matched", "vulns:enriched", "reports:filtered", "stats:updated"]:
        raise HTTPException(status_code=400, detail=f"Invalid channel: {channel}")
    
    timeout = min(max(1, timeout), 300)  # 1-300 seconds
    messages = subscribe_to_channel(channel, timeout=timeout)
    
    return {
        "channel": channel,
        "messages_received": len(messages),
        "messages": messages,
    }


@app.get("/api/programs/matcher/stats/async")
def api_programs_matcher_stats_async():
    """
    Get program matcher async statistics.
    """
    from app.program_matcher_async import get_matcher_stats as get_async_stats
    return get_async_stats()


@app.get("/api/vulns/ip/{ip}")
def api_vulns_by_ip(ip: str):
    vcol = get_vuln_results()
    cursor = vcol.find({"ip": ip}).sort("timestamp", -1)
    return [_serialize_vuln(doc) for doc in cursor]


# ---------------------------------------------------------------------------
# Bounty endpoints
# ---------------------------------------------------------------------------
def _serialize_bounty_doc(doc):
    d = dict(doc)
    d["id"] = str(d.pop("_id", ""))
    if d.get("program_id"):
        d["program_id"] = str(d["program_id"])
    for key in ("last_recon", "last_recon_start", "created_at", "first_recon_at"):
        ts = d.get(key)
        if ts and hasattr(ts, "isoformat"):
            d[key] = ts.isoformat() + "Z"
    return d


def _normalize_scope_items(items: list[str]) -> list[str]:
    """Normalize scraped scope assets into deduplicated domain/CIDR patterns."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in items:
        s = (raw or "").strip().lower()
        if not s:
            continue
        s = s.split("#", 1)[0].strip()
        if not s:
            continue

        if "://" in s:
            try:
                s = urlparse(s).hostname or s
            except Exception:
                pass
        s = s.split("/", 1)[0].strip()
        if s.startswith("*."):
            s = s[2:]

        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
            normalized = str(net)
        except ValueError:
            if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", s):
                continue
            normalized = s

        if normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def _fallback_scope_from_url(program_url: str) -> list[str]:
    host = (urlparse(program_url).hostname or "").lower().strip()
    host = host[4:] if host.startswith("www.") else host
    if not host or host.endswith("hackerone.com"):
        return []
    return [host, f"*.{host}"]


def _scope_suggest_hackerone(program_url: str) -> dict:
    parsed = urlparse(program_url)
    host = (parsed.hostname or "").lower().strip()
    if "hackerone.com" not in host:
        raise HTTPException(status_code=400, detail="URL must be from hackerone.com")

    path_parts = [p for p in parsed.path.split("/") if p]
    if not path_parts:
        raise HTTPException(status_code=400, detail="Invalid HackerOne program URL")
    handle = path_parts[0]

    in_scope: list[str] = []
    out_scope: list[str] = []
    source = "fallback"

    api_url = f"https://api.hackerone.com/v1/hackers/programs/{handle}"
    h1_user = (os.getenv("HACKERONE_API_USERNAME") or "").strip()
    h1_token = (os.getenv("HACKERONE_API_TOKEN") or "").strip()
    h1_auth = (h1_user, h1_token) if h1_user and h1_token else None
    try:
        resp = requests.get(api_url, auth=h1_auth, timeout=12)
        if resp.ok:
            data = resp.json()
            rel = ((data or {}).get("relationships") or {}).get("structured_scopes") or {}
            scopes = rel.get("data") or []
            for item in scopes:
                attrs = item.get("attributes") or item
                asset = (attrs.get("asset_identifier") or "").strip()
                if not asset:
                    continue
                eligible = attrs.get("eligible_for_submission", True)
                (in_scope if eligible else out_scope).append(asset)
            source = "hackerone_api"
    except Exception:
        pass

    if not in_scope and not out_scope:
        try:
            resp = requests.get(program_url, timeout=12, allow_redirects=True)
            if resp.ok and resp.text:
                html = resp.text
                source = "hackerone_html"
                pattern = re.compile(
                    r'"asset_identifier"\s*:\s*"(?P<asset>[^"]+?)".{0,300}?"eligible_for_submission"\s*:\s*(?P<eligible>true|false)',
                    re.DOTALL,
                )
                for m in pattern.finditer(html):
                    raw_asset = m.group("asset").replace("\\/", "/")
                    try:
                        asset = json.loads(f"\"{raw_asset}\"")
                    except Exception:
                        asset = raw_asset
                    eligible = m.group("eligible") == "true"
                    (in_scope if eligible else out_scope).append(asset)
        except Exception:
            pass

    in_scope_norm = _normalize_scope_items(in_scope)
    out_scope_norm = _normalize_scope_items(out_scope)
    if not in_scope_norm:
        in_scope_norm = _fallback_scope_from_url(program_url)

    return {
        "source": source,
        "handle": handle,
        "in_scope": in_scope_norm,
        "out_of_scope": out_scope_norm,
    }


@app.post("/api/bounty/programs")
def api_bounty_create_program(body: dict):
    """Create or update a bounty program."""
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")

    raw_scope = body.get("in_scope", [])
    if isinstance(raw_scope, str):
        raw_scope = [line.strip() for line in raw_scope.replace("\r", "\n").split("\n") if line.strip()]
    else:
        raw_scope = [s.strip() for s in (raw_scope or []) if s and str(s).strip()]
    in_scope = list({s for s in raw_scope if s})
    if not in_scope:
        raise HTTPException(status_code=400, detail="in_scope is required")

    col = get_bounty_programs()
    from datetime import datetime
    # Optional metadata fields for bounty programs
    policy_url = (body.get("policy_url") or "").strip()
    has_bounty = bool(body.get("has_bounty", False))
    bounty_min = body.get("bounty_min")
    bounty_max = body.get("bounty_max")
    bounty_currency_raw = (body.get("bounty_currency") or "").strip()
    bounty_currency = bounty_currency_raw.upper() if bounty_currency_raw else ""
    asset_types = [str(s).strip() for s in body.get("asset_types", []) if str(s).strip()]
    notes = (body.get("notes") or "").strip()
    priority = (body.get("priority") or "").strip().lower()
    safe_harbor = bool(body.get("safe_harbor", False))

    doc = {
        "name": name,
        "platform": body.get("platform", ""),
        "url": body.get("url", ""),
        "in_scope": in_scope,
        "out_of_scope": [s.strip() for s in body.get("out_of_scope", []) if s.strip()],
        "status": "active",
        "created_at": datetime.utcnow(),
        "stats": {},
        "policy_url": policy_url,
        "has_bounty": has_bounty,
        "bounty_min": bounty_min,
        "bounty_max": bounty_max,
        "bounty_currency": bounty_currency,
        "asset_types": asset_types,
        "notes": notes,
        "priority": priority,
        "safe_harbor": safe_harbor,
    }

    existing = col.find_one({"name": name})
    if existing:
        col.update_one({"_id": existing["_id"]}, {"$set": doc})
        return {"id": str(existing["_id"]), "updated": True}

    result = col.insert_one(doc)
    return {"id": str(result.inserted_id), "created": True}


@app.post("/api/bounty/scope_suggest")
def api_bounty_scope_suggest(body: dict):
    program_url = (body.get("url", "") or "").strip()
    platform = (body.get("platform", "") or "").strip().lower()
    if not program_url:
        raise HTTPException(status_code=400, detail="url is required")

    if platform == "hackerone" or "hackerone.com" in program_url:
        return _scope_suggest_hackerone(program_url)

    # Generic fallback for other platforms.
    in_scope = _fallback_scope_from_url(program_url)
    return {
        "source": "generic_url",
        "in_scope": in_scope,
        "out_of_scope": [],
    }


@app.get("/api/bounty/programs")
def api_bounty_list_programs():
    col = get_bounty_programs()
    programs = []
    for doc in col.find().sort("created_at", -1):
        d = _serialize_bounty_doc(doc)
        tcol = get_bounty_targets()
        d["target_count"] = tcol.count_documents({"program_id": doc["_id"]})
        d["alive_count"] = tcol.count_documents({"program_id": doc["_id"], "alive": True})
        vcol = get_vuln_results()
        target_ips = set()
        for t in tcol.find({"program_id": doc["_id"]}, {"ips": 1}):
            for ip in t.get("ips", []):
                target_ips.add(ip)
        d["vuln_count"] = vcol.count_documents({"ip": {"$in": list(target_ips)}}) if target_ips else 0
        flow = _compute_program_flow(str(doc["_id"]))
        d["flow_step"] = flow.get("current_step", 1)
        programs.append(d)
    return programs


@app.delete("/api/bounty/programs/{program_id}")
def api_bounty_delete_program(program_id: str):
    try:
        oid = ObjectId(program_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid program id")
    col = get_bounty_programs()
    col.delete_one({"_id": oid})
    get_bounty_targets().delete_many({"program_id": oid})
    return {"deleted": True}


@app.delete("/api/bounty/programs")
def api_bounty_delete_all_programs():
    """
    Remove todos os programas de bounty cadastrados e seus respectivos targets.
    Use com cuidado: operação destrutiva.
    """
    pcol = get_bounty_programs()
    tcol = get_bounty_targets()
    deleted_programs = pcol.delete_many({}).deleted_count
    deleted_targets = tcol.delete_many({}).deleted_count
    return {"deleted_programs": deleted_programs, "deleted_targets": deleted_targets}


@app.post("/api/bounty/programs/{program_id}/clear_error")
def api_bounty_clear_error(program_id: str):
    """Clear error state so the program can be retried (e.g. after fixing scope)."""
    try:
        oid = ObjectId(program_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid program id")
    col = get_bounty_programs()
    result = col.update_one(
        {"_id": oid},
        {"$set": {"status": "active"}, "$unset": {"last_recon_error": ""}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Program not found")
    return {"ok": True, "status": "active"}


@app.post("/api/bounty/programs/{program_id}/recon")
def api_bounty_trigger_recon(program_id: str):
    """Trigger recon pipeline for a program (runs in background thread)."""
    try:
        oid = ObjectId(program_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid program id")

    col = get_bounty_programs()
    program = col.find_one({"_id": oid}, {"status": 1})
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    if program.get("status") == "reconning":
        return {"status": "recon_already_running", "program_id": program_id}

    result_holder: dict = {}

    def _run():
        result_holder.update(recon_pipeline(program_id))

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"status": "recon_started", "program_id": program_id}


@app.get("/api/bounty/targets/{program_id}")
def api_bounty_list_targets(program_id: str, alive_only: bool = False):
    try:
        oid = ObjectId(program_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid program id")
    tcol = get_bounty_targets()
    query: dict = {"program_id": oid}
    if alive_only:
        query["alive"] = True
    cursor = tcol.find(query).sort("domain", 1).limit(500)
    return [_serialize_bounty_doc(doc) for doc in cursor]


@app.post("/api/bounty/targets/{target_id}/scan")
def api_bounty_scan_target(target_id: str):
    """Trigger vuln scan for a specific bounty target."""
    try:
        oid = ObjectId(target_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid target id")
    tcol = get_bounty_targets()
    target = tcol.find_one({"_id": oid})
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    domain = target.get("domain", "")
    ips = target.get("ips", [])
    httpx_data = target.get("httpx", {})

    queued = enqueue_bounty_target(domain, ips, httpx_data)
    tcol.update_one({"_id": oid}, {"$set": {"status": "scanning"}})
    return {"queued": queued, "domain": domain}


def _compute_program_flow(program_id: str) -> dict:
    """Compute Fluxo HackerOne steps (1-7) for a program. Returns { steps: [...], current_step: int }."""
    try:
        oid = ObjectId(program_id)
    except Exception:
        return {"steps": [], "current_step": 1}
    pcol = get_bounty_programs()
    tcol = get_bounty_targets()
    program = pcol.find_one({"_id": oid})
    if not program:
        return {"steps": [], "current_step": 1}
    in_scope = program.get("in_scope") or []
    if isinstance(in_scope, str):
        in_scope = [in_scope] if in_scope.strip() else []
    has_scope = len(in_scope) > 0
    has_name = bool((program.get("name") or "").strip())
    has_url = bool((program.get("url") or "").strip())
    step2_done = has_name and has_url and has_scope
    step1_done = step2_done  # assume anotou no H1 se cadastrou aqui

    targets = list(tcol.find({"program_id": oid}))
    has_targets = len(targets) > 0
    last_recon = program.get("last_recon")
    has_recon = last_recon is not None
    any_has_findings = False
    any_ready_for_h1 = False
    for t in targets:
        findings = (t.get("recon_checks") or {}).get("findings") or []
        if findings:
            any_has_findings = True
        for f in findings:
            title_ok = bool((f.get("title") or "").strip())
            evidence_ok = bool((f.get("evidence") or "").strip())
            if title_ok and evidence_ok:
                any_ready_for_h1 = True
                break
        if any_ready_for_h1:
            break
    step3_done = has_recon and has_targets and any_has_findings
    step4_done = step3_done  # priorização disponível
    step5_done = False  # manual: validar
    step6_done = any_ready_for_h1
    step7_done = False  # externo: HackerOne

    labels = [
        "No HackerOne: anotar ativos In scope + Eligible (Scope)",
        "Aqui: + Novo Programa (nome, URL, in_scope)",
        "Recon → esperar targets e coluna Checks",
        "Priorizar: Plano de Caça, filtro somente HIGH",
        "Validar: Abrir target, reproduzir sem sair do escopo",
        "Enviar ao H1 quando o botão habilitar (1 finding + evidência)",
        "No HackerOne: triagem, aceite e pagamento (Rewards)",
    ]
    done_list = [step1_done, step2_done, step3_done, step4_done, step5_done, step6_done, step7_done]
    steps = [{"n": i + 1, "label": labels[i], "done": done_list[i]} for i in range(7)]
    current = 1
    for i, d in enumerate(done_list):
        if not d:
            current = i + 1
            break
    else:
        current = 7
    return {"steps": steps, "current_step": current}


@app.get("/api/bounty/programs/{program_id}/flow")
def api_bounty_program_flow(program_id: str):
    """Return Fluxo HackerOne (1-7) status for the program."""
    return _compute_program_flow(program_id)


@app.get("/api/bounty/report/{program_id}")
def api_bounty_report(program_id: str):
    """Generate markdown report for a bounty program."""
    report = generate_report(program_id)
    return PlainTextResponse(content=report, media_type="text/markdown")


@app.post("/api/bounty/bugscraper/sync")
def api_bounty_bug_scraper_sync():
    """
    Dispara uma sincronização com o Bug Scraper e insere novos programas
    na collection bounty_programs.

    É uma chamada síncrona e pode demorar alguns minutos dependendo
    da configuração do Bug Scraper.
    """
    inserted = sync_bug_scraper_programs()
    return {"inserted": inserted}


@app.get("/api/bounty/programs/{program_id}/changes")
def api_bounty_program_changes(program_id: str, limit: int = 20):
    """Return recent subdomain changes (new/removed) for a bounty program."""
    try:
        oid = ObjectId(program_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid program id")
    ccol = get_bounty_changes()
    cursor = ccol.find({"program_id": oid}).sort("timestamp", -1).limit(max(1, min(limit, 100)))
    results = []
    for doc in cursor:
        d = dict(doc)
        d["id"] = str(d.pop("_id", ""))
        d["program_id"] = str(d.get("program_id", ""))
        ts = d.get("timestamp")
        if ts and hasattr(ts, "isoformat"):
            d["timestamp"] = ts.isoformat() + "Z"
        results.append(d)
    return results


@app.get("/api/bounty/changes/recent")
def api_bounty_recent_changes(limit: int = 50):
    """Return the most recent subdomain changes across all programs."""
    ccol = get_bounty_changes()
    cursor = ccol.find().sort("timestamp", -1).limit(max(1, min(limit, 200)))
    results = []
    for doc in cursor:
        d = dict(doc)
        d["id"] = str(d.pop("_id", ""))
        d["program_id"] = str(d.get("program_id", ""))
        ts = d.get("timestamp")
        if ts and hasattr(ts, "isoformat"):
            d["timestamp"] = ts.isoformat() + "Z"
        results.append(d)
    return results


@app.get("/api/bounty/targets/new")
def api_bounty_new_targets(limit: int = 100):
    """Return targets flagged as new (discovered in the latest recon run)."""
    tcol = get_bounty_targets()
    cursor = tcol.find({"is_new": True, "alive": True}).sort("last_recon", -1).limit(max(1, min(limit, 500)))
    return [_serialize_bounty_doc(doc) for doc in cursor]


def _hackerone_handle_from_url(program_url: str) -> str | None:
    """Extract team handle from HackerOne program URL (e.g. https://hackerone.com/company -> company)."""
    if not program_url or "hackerone.com" not in (program_url or "").lower():
        return None
    parsed = urlparse(program_url)
    path = (parsed.path or "").strip("/")
    parts = [p for p in path.split("/") if p]
    return parts[0] if parts else None


@app.post("/api/bounty/programs/{program_id}/submit_hackerone")
def api_bounty_submit_hackerone(program_id: str, body: dict | None = None):
    """Submit a report to HackerOne for this program. Uses HACKERONE_API_USERNAME + HACKERONE_API_TOKEN."""
    body = body or {}
    try:
        oid = ObjectId(program_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid program id")

    col = get_bounty_programs()
    program = col.find_one({"_id": oid})
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")

    program_url = (program.get("url") or "").strip()
    handle = _hackerone_handle_from_url(program_url)
    if not handle:
        raise HTTPException(
            status_code=400,
            detail="Program URL must be a HackerOne program URL (e.g. https://hackerone.com/company)",
        )

    username = (os.getenv("HACKERONE_API_USERNAME") or "").strip()
    token = (os.getenv("HACKERONE_API_TOKEN") or "").strip()
    if not username or not token:
        raise HTTPException(
            status_code=503,
            detail="Configure HACKERONE_API_USERNAME and HACKERONE_API_TOKEN to submit to HackerOne.",
        )

    title = (body.get("title") or "").strip()
    vulnerability_information = (body.get("vulnerability_information") or "").strip()
    impact = (body.get("impact") or "").strip()
    severity_rating = (body.get("severity_rating") or "medium").strip().lower()
    if severity_rating not in ("none", "low", "medium", "high", "critical"):
        severity_rating = "medium"

    if not title:
        title = f"Bug Bounty Report: {program.get('name', 'Program')}"
    if not vulnerability_information:
        vulnerability_information = generate_report(program_id)

    payload = {
        "data": {
            "type": "report",
            "attributes": {
                "team_handle": handle,
                "title": title[:250],
                "vulnerability_information": vulnerability_information,
                "severity_rating": severity_rating,
            },
        },
    }
    if impact:
        payload["data"]["attributes"]["impact"] = impact[:1000]

    try:
        r = requests.post(
            "https://api.hackerone.com/v1/hackers/reports",
            auth=(username, token),
            json=payload,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=30,
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"HackerOne request failed: {e!s}")

    if r.status_code not in (200, 201):
        err = (r.json() or {}).get("errors", [{}])
        msg = err[0].get("detail", err[0].get("title", r.text)) if err else r.text
        raise HTTPException(status_code=502, detail=f"HackerOne: {msg}")

    data = r.json() or {}
    attrs = (data.get("data") or {}).get("attributes") or {}
    report_id = (data.get("data") or {}).get("id")
    report_url = attrs.get("url") or (f"https://hackerone.com/reports/{report_id}" if report_id else "")
    return {"report_id": report_id, "url": report_url, "ok": True}


# ---------------------------------------------------------------------------
# Submitted Reports (auto-submit history)
# ---------------------------------------------------------------------------

@app.get("/api/bounty/submitted-reports")
def api_submitted_reports(limit: int = 50):
    """List submitted reports from auto-submit and manual submissions."""
    from app.database import get_submitted_reports
    col = get_submitted_reports()
    docs = list(col.find().sort("timestamp", -1).limit(limit))
    for d in docs:
        d["id"] = str(d.pop("_id", ""))
        if "program_id" in d:
            d["program_id"] = str(d["program_id"])
        if "target_id" in d:
            d["target_id"] = str(d["target_id"])
        if "timestamp" in d and hasattr(d["timestamp"], "isoformat"):
            d["timestamp"] = d["timestamp"].isoformat()
    return docs


@app.get("/api/bounty/submitted-reports/stats")
def api_submitted_reports_stats():
    """Summary stats for submitted reports."""
    from app.database import get_submitted_reports
    col = get_submitted_reports()
    docs = list(col.find())
    total = len(docs)
    submitted = sum(1 for d in docs if d.get("status") == "submitted")
    errors = sum(1 for d in docs if d.get("status") == "error")
    pending = sum(1 for d in docs if d.get("status") == "pending")
    by_severity = {}
    for d in docs:
        s = d.get("severity", "medium")
        by_severity[s] = by_severity.get(s, 0) + 1
    return {
        "total": total,
        "submitted": submitted,
        "errors": errors,
        "pending": pending,
        "by_severity": by_severity,
    }


@app.post("/api/bounty/targets/{target_id}/submit-h1")
def api_submit_target_h1(target_id: str):
    """Manually submit a single target to HackerOne."""
    from app.database import get_bounty_targets, get_bounty_programs
    from app.bounty import auto_submit_eligible_targets

    try:
        oid = ObjectId(target_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid target id")

    targets_col = get_bounty_targets()
    target = targets_col.find_one({"_id": oid})
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    program_id = target.get("program_id")
    if not program_id:
        raise HTTPException(status_code=400, detail="Target has no program_id")

    results = auto_submit_eligible_targets(str(program_id))
    target_results = [r for r in results if str(r.get("target_id", "")) == target_id]
    if target_results:
        r = target_results[0]
        return {"ok": r.get("status") == "submitted", "status": r.get("status"), "h1_report_url": r.get("h1_report_url"), "error": r.get("error")}
    return {"ok": False, "status": "skipped", "detail": "Target not eligible or already submitted"}


@app.get("/api/hackerone/me")
def api_hackerone_me():
    """Test HackerOne API credentials by listing programs."""
    username = (os.getenv("HACKERONE_API_USERNAME") or "").strip()
    token = (os.getenv("HACKERONE_API_TOKEN") or "").strip()
    if not username or not token:
        raise HTTPException(
            status_code=503,
            detail="HACKERONE_API_USERNAME and HACKERONE_API_TOKEN not configured in .env",
        )
    try:
        r = requests.get(
            "https://api.hackerone.com/v1/hackers/programs",
            params={"page[size]": "1"},
            auth=(username, token),
            headers={"Accept": "application/json"},
            timeout=15,
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {e!s}")

    if r.status_code == 401:
        raise HTTPException(status_code=401, detail="Invalid HackerOne credentials (check HACKERONE_API_USERNAME and HACKERONE_API_TOKEN)")
    if r.status_code == 403:
        raise HTTPException(status_code=403, detail="Forbidden — your IP may be blocked or token lacks permissions")
    if not r.ok:
        raise HTTPException(status_code=r.status_code, detail=f"HackerOne returned {r.status_code}: {r.text[:300]}")

    data = r.json() or {}
    return {"ok": True, "username": username, "programs": len(data.get("data", []))}


def _hackerone_request(method: str, path: str, params: dict | None = None, json_body: dict | None = None) -> tuple[dict | list, int]:
    """Chama a API HackerOne (hacker). path sem leading slash, ex: 'v1/hackers/reports'."""
    username = (os.getenv("HACKERONE_API_USERNAME") or "").strip()
    token = (os.getenv("HACKERONE_API_TOKEN") or "").strip()
    if not username or not token:
        raise HTTPException(status_code=503, detail="HACKERONE_API_USERNAME and HACKERONE_API_TOKEN not configured")
    url = f"https://api.hackerone.com/{path}" if not path.startswith("http") else path
    try:
        r = requests.request(
            method,
            url,
            params=params,
            json=json_body,
            auth=(username, token),
            headers={"Accept": "application/json"},
            timeout=12,
        )
    except requests.Timeout:
        raise HTTPException(status_code=504, detail="HackerOne API timeout (12s)")
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"HackerOne request failed: {e!s}")
    if r.status_code == 401:
        raise HTTPException(status_code=401, detail="Invalid HackerOne credentials")
    if r.status_code == 403:
        raise HTTPException(status_code=403, detail="Forbidden (IP or token permissions)")
    if r.status_code == 429:
        raise HTTPException(status_code=429, detail="HackerOne rate limit (600/min read, 25/20s write)")
    data = r.json() if r.content else {}
    return data, r.status_code


@app.get("/api/hackerone/reports")
def api_hackerone_reports(page_size: int = 25, page_before: str | None = None, page_after: str | None = None):
    """
    Lista os reports (submissões) do hacker na HackerOne.
    Paginação: page_size (default 25), page_before ou page_after (cursor do link next/prev).
    Requer HACKERONE_API_USERNAME e HACKERONE_API_TOKEN.
    """
    params = {"page[size]": min(max(1, page_size), 100)}
    if page_before:
        params["page[before]"] = page_before
    if page_after:
        params["page[after]"] = page_after
    data, _ = _hackerone_request("GET", "v1/hackers/reports", params=params)
    return data


@app.get("/api/hackerone/earnings")
def api_hackerone_earnings(page_size: int = 25, page_before: str | None = None, page_after: str | None = None):
    """
    Lista os earnings (bounties recebidos) do hacker na HackerOne.
    Paginação: page_size (default 25), page_before ou page_after.
    Requer HACKERONE_API_USERNAME e HACKERONE_API_TOKEN.
    """
    params = {"page[size]": min(max(1, page_size), 100)}
    if page_before:
        params["page[before]"] = page_before
    if page_after:
        params["page[after]"] = page_after
    data, _ = _hackerone_request("GET", "v1/hackers/earnings", params=params)
    return data


@app.get("/api/hackerone/programs")
def api_hackerone_programs(page_size: int = 100, page_before: str | None = None, page_after: str | None = None):
    """
    Lista os programas disponíveis para o hacker (programs onde pode submeter).
    Paginação: page_size, page_before ou page_after.
    """
    params = {"page[size]": min(max(1, page_size), 100)}
    if page_before:
        params["page[before]"] = page_before
    if page_after:
        params["page[after]"] = page_after
    data, _ = _hackerone_request("GET", "v1/hackers/programs", params=params)
    return data


@app.get("/api/bounty/stats")
def api_bounty_stats():
    recon = get_recon_stats()
    pcol = get_bounty_programs()
    tcol = get_bounty_targets()
    ccol = get_bounty_changes()
    from app.ip_feeds import get_feed_stats as _get_feed_stats
    feed = _get_feed_stats()
    return {
        "programs": pcol.count_documents({}),
        "programs_with_bounty": pcol.count_documents({"has_bounty": True}),
        "targets": tcol.count_documents({}),
        "alive_targets": tcol.count_documents({"alive": True}),
        "new_targets": tcol.count_documents({"is_new": True}),
        "total_changes": ccol.count_documents({}),
        "bounty_prefixes": feed.get("bounty_prefixes", 0),
        "recon": recon,
    }


# ---------------------------------------------------------------------------
# Program Scorer endpoints
# ---------------------------------------------------------------------------

@app.post("/api/bounty/score-programs")
def api_score_programs():
    """Score all programs by attractiveness and return ranked list."""
    results = score_all_programs()
    return {"scored": len(results), "programs": results}


@app.get("/api/bounty/prioritized-programs")
def api_prioritized_programs(min_score: int = 40):
    """Get programs ranked by attractiveness score."""
    return get_prioritized_programs(min_score)


@app.get("/api/bounty/scorer/stats")
def api_scorer_stats():
    return get_scorer_stats()


@app.post("/api/bounty/h1-discover")
def api_h1_discover_programs():
    """Discover and auto-import new HackerOne programs."""
    new_programs = fetch_new_h1_programs()
    imported = auto_import_new_programs()
    return {
        "new_programs_found": len(new_programs),
        "auto_imported": len(imported),
        "imported": imported,
        "all_new": new_programs[:20],
    }


# ---------------------------------------------------------------------------
# Advanced Scanner Stats
# ---------------------------------------------------------------------------

@app.get("/api/scanners/stats")
def api_scanner_stats():
    """Get stats from all advanced scanners."""
    return {
        "idor": get_idor_stats(),
        "ssrf": get_ssrf_stats(),
        "graphql": get_graphql_stats(),
        "race_condition": get_race_stats(),
        "interactsh": get_interactsh_stats(),
        "ct_monitor": get_ct_stats(),
        "cve_monitor": get_cve_stats(),
        "scorer": get_scorer_stats(),
        "ai": get_ai_stats(),
        "bounty_data": get_bounty_data_stats(),
    }


# ---------------------------------------------------------------------------
# Interactsh / Blind Vulns
# ---------------------------------------------------------------------------

@app.get("/api/blind-vulns")
def api_blind_vulns():
    """Get confirmed blind vulnerabilities from interactsh callbacks."""
    return get_confirmed_vulns()


# ---------------------------------------------------------------------------
# CT Monitor
# ---------------------------------------------------------------------------

@app.post("/api/ct/check-all")
def api_ct_check():
    """Trigger CT log check for all programs."""
    results = ct_check_all()
    total_new = sum(len(r.get("new_domains", [])) for r in results)
    return {"programs_checked": len(results), "new_domains_found": total_new, "results": results}


@app.get("/api/ct/stats")
def api_ct_stats():
    return get_ct_stats()


# ---------------------------------------------------------------------------
# CVE Monitor
# ---------------------------------------------------------------------------

@app.post("/api/cve/check")
def api_cve_check():
    """Trigger CVE feed check and auto-template generation."""
    return process_new_cves()


@app.get("/api/cve/recent")
def api_cve_recent():
    """Get recent critical/high CVEs."""
    return get_recent_cves()


@app.get("/api/cve/stats")
def api_cve_stats():
    return get_cve_stats()


# ---------------------------------------------------------------------------
# ROI Tracker
# ---------------------------------------------------------------------------

@app.get("/api/roi/dashboard")
def api_roi_dashboard():
    """Get complete ROI dashboard with earnings, programs, and recommendations."""
    return roi_dashboard()


@app.get("/api/roi/earnings")
def api_roi_earnings():
    """Get earnings summary."""
    return get_earnings_summary()


@app.post("/api/roi/record-earning")
def api_record_earning(body: dict):
    """Manually record a bounty earning."""
    amount = body.get("amount", 0)
    if not amount or amount <= 0:
        raise HTTPException(status_code=400, detail="amount must be positive")
    record_earning(
        program_id=body.get("program_id", ""),
        program_name=body.get("program_name", ""),
        amount=float(amount),
        currency=body.get("currency", "USD"),
        vuln_type=body.get("vuln_type", ""),
        report_id=body.get("report_id", ""),
        h1_report_id=body.get("h1_report_id", ""),
    )
    return {"ok": True}


@app.get("/api/roi/program/{program_id}")
def api_roi_program(program_id: str):
    """Get ROI data for a specific program."""
    return get_program_roi(program_id)


# ---------------------------------------------------------------------------
# Enhanced Report Generation
# ---------------------------------------------------------------------------

@app.post("/api/bounty/targets/{target_id}/generate-report")
def api_generate_target_report(target_id: str):
    """Generate a high-quality H1 report for a specific target. Uses AI if available."""
    try:
        oid = ObjectId(target_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid target id")

    tcol = get_bounty_targets()
    target = tcol.find_one({"_id": oid})
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    pcol = get_bounty_programs()
    program = pcol.find_one({"_id": target.get("program_id")})
    program_name = program.get("name", "?") if program else "?"
    program_url = program.get("url", "") if program else ""

    findings = (target.get("recon_checks") or {}).get("findings", [])
    findings = deduplicate_findings(findings)

    if not findings:
        return {"error": "No findings for this target"}

    domain = target.get("domain", "?")

    if AI_ANALYZER_ENABLED:
        ai_report = ai_write_report(domain, findings, program_name, program_url)
        if ai_report:
            ai_report["source"] = "ai"
            ai_report["ai_provider"] = get_ai_stats().get("provider", "")
            return ai_report

    report = generate_h1_report(
        domain=domain,
        findings=findings,
        program_name=program_name,
        program_url=program_url,
    )
    report["source"] = "template"
    return report


# ---------------------------------------------------------------------------
# Bounty Targets Data (arkadiyt/bounty-targets-data)
# ---------------------------------------------------------------------------

@app.post("/api/bounty-data/sync")
def api_bounty_data_sync(body: dict | None = None):
    """Sync programs from bounty-targets-data (HackerOne + Bugcrowd + Intigriti + YesWeHack)."""
    body = body or {}
    platforms = body.get("platforms")
    bounty_only = body.get("bounty_only", False)
    result = sync_bounty_targets_data(platforms=platforms, bounty_only=bounty_only)
    return result


@app.get("/api/bounty-data/stats")
def api_bounty_data_stats():
    """Get bounty-targets-data sync stats."""
    return get_bounty_data_stats()


@app.get("/api/bounty-data/search")
def api_bounty_data_search(q: str = "", platform: str = "", bounty_only: bool = False, limit: int = 50):
    """Search programs from bounty-targets-data."""
    from app.bounty import _serialize_bounty_doc  # noqa: F811
    programs = btd_search(query=q, platform=platform, bounty_only=bounty_only, limit=limit)
    results = []
    for p in programs:
        d = dict(p)
        d["id"] = str(d.pop("_id", ""))
        for k in ("created_at", "last_data_sync", "scope_change_detected"):
            if k in d and hasattr(d[k], "isoformat"):
                d[k] = d[k].isoformat()
        results.append(d)
    return results


@app.get("/api/bounty-data/domains")
def api_bounty_data_domains():
    """Get cached bounty domain/wildcard lists."""
    data = get_all_bounty_domains()
    return {
        "domains_count": len(data.get("domains", [])),
        "wildcards_count": len(data.get("wildcards", [])),
        "domains_sample": data.get("domains", [])[:100],
        "wildcards_sample": data.get("wildcards", [])[:100],
    }


# ---------------------------------------------------------------------------
# Intigriti Researcher API
# ---------------------------------------------------------------------------

INTIGRITI_API_TOKEN = (os.getenv("INTIGRITI_API_TOKEN") or "").strip()
INTIGRITI_API_BASE = "https://api.intigriti.com/external/researcher/v1"


def _intigriti_request(path: str, params: dict | None = None) -> dict | list:
    """Call the Intigriti researcher API."""
    if not INTIGRITI_API_TOKEN:
        raise HTTPException(status_code=503, detail="INTIGRITI_API_TOKEN not configured in .env")
    url = f"{INTIGRITI_API_BASE}{path}"
    try:
        r = requests.get(
            url,
            params=params,
            headers={
                "Authorization": f"Bearer {INTIGRITI_API_TOKEN}",
                "Accept": "application/json",
            },
            timeout=15,
        )
    except requests.Timeout:
        raise HTTPException(status_code=504, detail="Intigriti API timeout")
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Intigriti request failed: {e!s}")
    if r.status_code == 401:
        raise HTTPException(status_code=401, detail="Invalid Intigriti API token")
    if r.status_code == 403:
        raise HTTPException(status_code=403, detail="Intigriti API forbidden")
    if not r.ok:
        raise HTTPException(status_code=r.status_code, detail=f"Intigriti {r.status_code}: {r.text[:200]}")
    return r.json()


@app.get("/api/intigriti/me")
def api_intigriti_me():
    """Test Intigriti API token."""
    if not INTIGRITI_API_TOKEN:
        return {"configured": False, "detail": "Set INTIGRITI_API_TOKEN in .env"}
    try:
        data = _intigriti_request("/programs", {"limit": "1"})
        count = len(data) if isinstance(data, list) else len(data.get("records", []))
        return {"configured": True, "ok": True, "programs_accessible": count}
    except HTTPException as e:
        return {"configured": True, "ok": False, "detail": e.detail}


@app.get("/api/intigriti/programs")
def api_intigriti_programs():
    """List Intigriti programs accessible to the researcher."""
    data = _intigriti_request("/programs")
    return data


@app.get("/api/intigriti/programs/{program_id}")
def api_intigriti_program_detail(program_id: str):
    """Get details of a specific Intigriti program."""
    data = _intigriti_request(f"/programs/{program_id}")
    return data


@app.get("/api/intigriti/activities")
def api_intigriti_activities():[TRUNCATED]
    """Get recent Intigriti program activities (scope changes, etc.)."""
    data = _intigriti_request("/program-activities")
    return data


@app.post("/api/intigriti/import")
def api_intigriti_import():
    """Import all Intigriti programs into bounty_programs collection."""
    if not INTIGRITI_API_TOKEN:
        raise HTTPException(status_code=503, detail="INTIGRITI_API_TOKEN not configured")

    try:
        programs_data = _intigriti_request("/programs")
    except HTTPException:
        raise

    records = programs_data if isinstance(programs_data, list) else programs_data.get("records", [])
    col = get_bounty_programs()
    imported = 0
    updated = 0

    for prog in records:
        prog_id = prog.get("programId") or prog.get("id", "")
        name = prog.get("name") or prog.get("companyHandle", "")
        if not name:
            continue

        in_scope = []
        out_scope = []
        domains = prog.get("domains") or []
        for d in domains:
            domain_val = d.get("endpoint") or d.get("domain", "")
            if domain_val:
                if d.get("type", "").lower() == "out":
                    out_scope.append(domain_val)
                else:
                    in_scope.append(domain_val)

        if not in_scope:
            continue

        max_bounty = prog.get("maxBounty") or prog.get("max_bounty", {})
        max_val = max_bounty.get("value", 0) if isinstance(max_bounty, dict) else max_bounty

        doc = {
            "name": name,
            "platform": "intigriti",
            "url": f"https://app.intigriti.com/researcher/programs/{prog_id}" if prog_id else "",
            "in_scope": in_scope,
            "out_of_scope": out_scope,
            "has_bounty": (max_val or 0) > 0,
            "bounty_max": max_val,
            "source": "intigriti-api",
            "status": "active",
        }

        existing = col.find_one({"name": name, "platform": "intigriti"})
        if existing:
            col.update_one({"_id": existing["_id"]}, {"$set": doc})
            updated += 1
        else:
            from datetime import datetime as _dt
            doc["created_at"] = _dt.utcnow()
            doc["stats"] = {}
            col.insert_one(doc)
            imported += 1

    return {"imported": imported, "updated": updated, "total_programs": len(records)}


# ---------------------------------------------------------------------------
# AI Analyzer Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/ai/stats")
def api_ai_stats():
    """Get AI analyzer stats and configuration."""
    return get_ai_stats()


@app.post("/api/ai/classify-finding")
def api_ai_classify(body: dict):
    """Use AI to classify a finding as true/false positive."""
    if not AI_ANALYZER_ENABLED:
        raise HTTPException(status_code=503, detail="AI not configured. Set AI_PROVIDER + API key in .env")
    finding = body.get("finding")
    if not finding:
        raise HTTPException(status_code=400, detail="finding is required")
    result = ai_classify_finding(finding)
    if not result:
        raise HTTPException(status_code=502, detail="AI classification failed")
    return result


@app.post("/api/ai/classify-target/{target_id}")
def api_ai_classify_target(target_id: str):
    """Use AI to classify all findings of a target, filtering false positives."""
    if not AI_ANALYZER_ENABLED:
        raise HTTPException(status_code=503, detail="AI not configured")
    try:
        oid = ObjectId(target_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid target id")

    tcol = get_bounty_targets()
    target = tcol.find_one({"_id": oid})
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    findings = (target.get("recon_checks") or {}).get("findings", [])
    if not findings:
        return {"original": 0, "filtered": 0, "findings": []}

    classified = ai_classify_findings_batch(findings)

    tcol.update_one({"_id": oid}, {"$set": {
        "recon_checks.findings": classified,
        "recon_checks.total_findings": len(classified),
        "recon_checks.ai_classified": True,
    }})

    return {
        "original": len(findings),
        "filtered": len(classified),
        "removed": len(findings) - len(classified),
        "findings": classified,
    }


@app.post("/api/ai/analyze-response")
def api_ai_analyze_response(body: dict):
    """Use AI to analyze an HTTP response for vulnerabilities."""
    if not AI_ANALYZER_ENABLED:
        raise HTTPException(status_code=503, detail="AI not configured")
    url = body.get("url", "")
    status_code = body.get("status_code", 200)
    headers = body.get("headers", {})
    response_body = body.get("body", "")
    if not url:
        raise HTTPException(status_code=400, detail="url is required")
    result = ai_analyze_response(url, status_code, headers, response_body)
    return {"findings": result or []}


@app.post("/api/ai/parse-scope")
def api_ai_parse_scope(body: dict):
    """Use AI to parse a bounty program description and extract scope."""
    if not AI_ANALYZER_ENABLED:
        raise HTTPException(status_code=503, detail="AI not configured")
    description = body.get("description", "")
    policy = body.get("policy", "")
    if not description:
        raise HTTPException(status_code=400, detail="description is required")
    result = ai_parse_scope(description, policy)
    if not result:
        raise HTTPException(status_code=502, detail="AI scope parsing failed")
    return result


@app.post("/api/ai/analyze-js")
def api_ai_analyze_js(body: dict):
    """Use AI to analyze JavaScript code for secrets and vulnerabilities."""
    if not AI_ANALYZER_ENABLED:
        raise HTTPException(status_code=503, detail="AI not configured")
    code = body.get("code", "")
    source_url = body.get("source_url", "")
    if not code:
        raise HTTPException(status_code=400, detail="code is required")
    result = ai_analyze_javascript(code, source_url)
    return {"findings": result or []}


@app.post("/api/ai/find-chains/{target_id}")
def api_ai_find_chains(target_id: str):
    """Use AI to find vulnerability chains across findings of a target."""
    if not AI_ANALYZER_ENABLED:
        raise HTTPException(status_code=503, detail="AI not configured")
    try:
        oid = ObjectId(target_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid target id")

    tcol = get_bounty_targets()
    target = tcol.find_one({"_id": oid})
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    findings = (target.get("recon_checks") or {}).get("findings", [])
    if len(findings) < 2:
        return {"chains": [], "message": "Need at least 2 findings to find chains"}

    chains = ai_find_vuln_chains(findings, target.get("domain", "?"))
    return {"chains": chains or [], "findings_analyzed": len(findings)}


def start_scanner_thread():
    t = threading.Thread(
        target=run_scanner,
        args=(NUM_SCANNER_WORKERS,),
        daemon=True,
    )
    t.start()


@app.on_event("startup")
def on_startup():
    logger.info(
        "=== Scanner Internet v2 ===\n"
        "    NetScanner: %s\n"
        "    Workers: %s | Intervalo: %.1fs\n"
        "    Shodan: %s | ip-api: %.1f req/s | IPinfo: %.1f req/s\n"
        "    Vuln: %d workers | auto=%s | sev=%s\n"
        "    Bounty: %s\n"
        "    Log: %s | CORS: *",
        NETWORK_SCANNER_ENABLED, NUM_SCANNER_WORKERS, SCAN_INTERVAL,
        "OFF" if not SHODAN_ENABLED else f"{SHODAN_RPS:.0f} req/s",
        IPAPI_RPS, IPINFO_RPS,
        NUM_VULN_WORKERS, VULN_AUTO_SCAN, NUCLEI_SEVERITY, BOUNTY_MODE, LOG_LEVEL,
    )
    init_db()
    if NETWORK_SCANNER_ENABLED:
        start_scanner_thread()
    else:
        logger.info("[STARTUP] Scanner de rede desabilitado por config")
    start_vuln_scanner()
    start_bounty_system()
    start_program_scorer()
    start_interactsh_poller()
    start_ct_monitor()
    start_cve_monitor()
    start_roi_tracker()
    start_bounty_data_sync()
    start_program_matcher_worker()
    logger.info("API pronta em :5000 | VulnScanner + Bounty + Scorer + CT + CVE + ROI + BountyData + ProgramMatcher rodando")
