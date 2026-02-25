import os
import time
import threading
import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from bson import ObjectId

from app.database import init_db, get_scan_results, get_vuln_results
from app.scanner import (
    run_scanner, NUM_SCANNER_WORKERS, SCAN_INTERVAL, SHODAN_RPS, IPAPI_RPS, IPINFO_RPS,
    compute_risk_profile, get_breaker_status, get_scan_stats,
)
from app.ip_feeds import get_feed_stats
from app.vuln_scanner import (
    start_vuln_scanner, enqueue_ip, get_vuln_scan_stats,
    NUM_VULN_WORKERS, VULN_AUTO_SCAN, NUCLEI_SEVERITY,
)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
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


@app.get("/api/health")
def api_health():
    breakers = get_breaker_status()
    blocked = [b for b in breakers if b["blocked"]]
    scan_stats = get_scan_stats()
    feed_stats = get_feed_stats()
    vuln_stats = get_vuln_scan_stats()
    return {
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
        "    Workers: %s | Intervalo: %.1fs\n"
        "    Shodan: %.0f req/s | ip-api: %.1f req/s | IPinfo: %.1f req/s\n"
        "    Vuln: %d workers | auto=%s | sev=%s\n"
        "    Log: %s | CORS: *",
        NUM_SCANNER_WORKERS, SCAN_INTERVAL, SHODAN_RPS, IPAPI_RPS, IPINFO_RPS,
        NUM_VULN_WORKERS, VULN_AUTO_SCAN, NUCLEI_SEVERITY, LOG_LEVEL,
    )
    init_db()
    start_scanner_thread()
    start_vuln_scanner()
    logger.info("API pronta em :5000 | Scanner + VulnScanner rodando em background")
