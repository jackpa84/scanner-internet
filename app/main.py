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
from starlette.middleware.base import BaseHTTPMiddleware
from bson import ObjectId
import requests

from fastapi.responses import PlainTextResponse

from app.database import (
    init_db, get_scan_results, get_vuln_results,
    get_bounty_programs, get_bounty_targets, get_bounty_changes,
)
from app.scanner import (
    run_scanner, NUM_SCANNER_WORKERS, SCAN_INTERVAL, SHODAN_RPS, IPAPI_RPS, IPINFO_RPS,
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

app.add_middleware(RequestLogMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    cursor = col.find().sort("timestamp", -1).limit(100)
    data = []
    for doc in cursor:
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


@app.get("/api/prioritized_findings")
def api_prioritized_findings(limit: int = 20, min_score: int = 40):
    limit = max(1, min(limit, 100))
    min_score = max(0, min(min_score, 100))
    col = get_scan_results()
    cursor = col.find({"risk.score": {"$gte": min_score}}).sort("risk.score", -1).limit(limit)
    results = [_serialize_doc(doc) for doc in cursor]

    if not results:
        fallback = [_serialize_doc(doc) for doc in col.find().sort("timestamp", -1).limit(300)]
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
    return {
        "network_scanner_enabled": NETWORK_SCANNER_ENABLED,
        "workers": NUM_SCANNER_WORKERS,
        "scan_interval": SCAN_INTERVAL,
        "shodan_rps": SHODAN_RPS,
        "ipapi_rps": IPAPI_RPS,
        "ipinfo_rps": IPINFO_RPS,
        "apis": breakers,
        "blocked_count": len(blocked),
        "scan_stats": scan_stats,
        "feeds": feed_stats,
        "vuln_scanner": vuln_stats,
    }


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

    # Try public HackerOne API first; if blocked/unavailable, fallback to HTML parsing.
    api_url = f"https://api.hackerone.com/v1/hackers/programs/{handle}"
    try:
        resp = requests.get(api_url, timeout=12)
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
        "    Shodan: %.0f req/s | ip-api: %.1f req/s | IPinfo: %.1f req/s\n"
        "    Vuln: %d workers | auto=%s | sev=%s\n"
        "    Bounty: %s\n"
        "    Log: %s | CORS: *",
        NETWORK_SCANNER_ENABLED, NUM_SCANNER_WORKERS, SCAN_INTERVAL, SHODAN_RPS, IPAPI_RPS, IPINFO_RPS,
        NUM_VULN_WORKERS, VULN_AUTO_SCAN, NUCLEI_SEVERITY, BOUNTY_MODE, LOG_LEVEL,
    )
    init_db()
    if NETWORK_SCANNER_ENABLED:
        start_scanner_thread()
    else:
        logger.info("[STARTUP] Scanner de rede desabilitado por config")
    start_vuln_scanner()
    start_bounty_system()
    logger.info("API pronta em :5000 | VulnScanner + Bounty rodando")
