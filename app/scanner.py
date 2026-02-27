"""
Scanner de IPs v4 — asyncio-powered (20×+ throughput vs v3).

Melhorias de performance:
  - asyncio.open_connection para port scanning (vs 15 threads/IP)
  - aiohttp.ClientSession para todo HTTP (non-blocking I/O)
  - AsyncTokenBucket rate limiter (cooperativo, sem threads)
  - Enrichment concorrente via asyncio.gather
  - Semáforo global de conexões (evita FD exhaustion)
  - Batch writes assíncronos com timer
  - Zero overhead de threads — tudo no event loop
  - Salva resultados mesmo sem Shodan (scanner standalone)
"""

import asyncio
import logging
import os
import socket
import threading
import time
from datetime import datetime
from typing import Any

import aiohttp

from app.database import get_scan_results
from app.ip_feeds import get_next_ip, start_feeds

logger = logging.getLogger("scanner")

# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════
NUM_SCANNER_WORKERS = int(os.getenv("NUM_WORKERS", "200"))
SCAN_INTERVAL = float(os.getenv("SCAN_INTERVAL", "0"))
SHODAN_RPS = float(os.getenv("SHODAN_RPS", "10"))
SHODAN_ENABLED = os.getenv("SHODAN_ENABLED", "true").lower() in ("1", "true", "yes")
IPAPI_RPS = float(os.getenv("IPAPI_RPS", "0.7"))
IPINFO_RPS = float(os.getenv("IPINFO_RPS", "0.8"))

HTTP_TIMEOUT = 6
SOCKET_TIMEOUT = 2
PRESCAN_TIMEOUT = float(os.getenv("PRESCAN_TIMEOUT", "0.3"))
MAX_RETRIES = 1
HIGH_RISK_PORTS = {
    21, 22, 23, 139, 445, 2375, 2376, 3389, 5900,
    8080, 8443, 8888, 10250, 6443, 11211, 9200,
}
PRESCAN_PORTS = [
    # Web
    80, 443, 8080, 8443, 8000, 8888, 3000, 4443, 9090,
    # Remote access
    22, 23, 3389, 5900,
    # Mail / DNS
    25, 53,
    # Databases
    3306, 5432, 1433, 6379, 27017, 9200, 5984, 9042, 11211,
    # DevOps / Infra
    2375, 2376, 5000, 6443, 8500, 10250, 2181,
    # Admin panels
    5601, 15672, 4848,
    # Legacy / Recon
    139, 445, 111, 161,
]

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))
BATCH_FLUSH_INTERVAL = float(os.getenv("BATCH_FLUSH_INTERVAL", "1.5"))
MAX_CONCURRENT_CONNS = int(os.getenv("MAX_CONCURRENT_CONNS", "5000"))

# ═══════════════════════════════════════════════════════════════════
# Thread-safe stats (accessed from FastAPI in main thread)
# ═══════════════════════════════════════════════════════════════════
_scan_stats: dict[str, Any] = {
    "tested": 0, "alive": 0, "saved": 0, "dead": 0, "rps": 0.0,
}
_stats_lock = threading.Lock()


def _inc_stat(key: str, n: int = 1) -> None:
    with _stats_lock:
        _scan_stats[key] = _scan_stats.get(key, 0) + n


def get_scan_stats() -> dict[str, Any]:
    with _stats_lock:
        return dict(_scan_stats)


# ═══════════════════════════════════════════════════════════════════
# Circuit Breakers (threading.Event for cross-thread safety)
# ═══════════════════════════════════════════════════════════════════
_shodan_ok = threading.Event()
_shodan_ok.set()
_ipinfo_ok = threading.Event()
_ipinfo_ok.set()
_ipapi_ok = threading.Event()
_ipapi_ok.set()
_threatfox_ok = threading.Event()
_threatfox_ok.set()
_breaker_lock = threading.Lock()

_breaker_status: dict[str, dict[str, Any]] = {}

BREAKERS = {
    "Shodan InternetDB": _shodan_ok,
    "IPinfo.io": _ipinfo_ok,
    "ip-api.com": _ipapi_ok,
    "ThreatFox": _threatfox_ok,
}


def get_breaker_status() -> list[dict[str, Any]]:
    now = time.time()
    result = []
    for name, event in BREAKERS.items():
        info = _breaker_status.get(name, {})
        disabled = name == "Shodan InternetDB" and not SHODAN_ENABLED
        blocked = disabled or not event.is_set()
        remaining = 0
        if blocked and "unblock_at" in info and not disabled:
            remaining = max(0, int(info["unblock_at"] - now))
        result.append({
            "name": name,
            "blocked": blocked,
            "disabled": disabled,
            "cooldown": info.get("cooldown", 0),
            "remaining_seconds": remaining,
            "blocked_since": info.get("blocked_since", ""),
        })
    return result


def _trip_breaker(breaker: threading.Event, name: str, cooldown: int) -> None:
    with _breaker_lock:
        if breaker.is_set():
            breaker.clear()
            now = time.time()
            _breaker_status[name] = {
                "cooldown": cooldown,
                "blocked_since": datetime.utcnow().isoformat() + "Z",
                "unblock_at": now + cooldown,
            }
            logger.warning("[RATE] %s bloqueada por %ss (429)", name, cooldown)
            threading.Thread(
                target=_reset_breaker, args=(breaker, name, cooldown), daemon=True,
            ).start()


def _reset_breaker(breaker: threading.Event, name: str, cooldown: int) -> None:
    time.sleep(cooldown)
    breaker.set()
    _breaker_status.pop(name, None)
    logger.info("[RATE] %s liberada", name)


async def _wait_breaker(event: threading.Event) -> None:
    while not event.is_set():
        await asyncio.sleep(0.5)


# ═══════════════════════════════════════════════════════════════════
# AsyncTokenBucket — cooperative rate limiter
# ═══════════════════════════════════════════════════════════════════
class AsyncTokenBucket:
    __slots__ = ("rate", "tokens", "max_tokens", "last_refill", "_lock")

    def __init__(self, rate: float, burst: float = 0):
        self.rate = rate
        self.max_tokens = burst or rate * 3
        self.tokens = min(rate, self.max_tokens)
        self.last_refill = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        interval = min(0.1, 1.0 / max(self.rate, 0.1))
        while True:
            async with self._lock:
                now = time.monotonic()
                if self.last_refill == 0:
                    self.last_refill = now
                elapsed = now - self.last_refill
                self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
                self.last_refill = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(interval)


# ═══════════════════════════════════════════════════════════════════
# Async Port Scanner
# ═══════════════════════════════════════════════════════════════════
_conn_sem: asyncio.Semaphore | None = None


async def _check_port(ip: str, port: int, timeout: float) -> int | None:
    sem = _conn_sem
    if sem is not None:
        await sem.acquire()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None
    finally:
        if sem is not None:
            sem.release()


async def quick_port_scan(ip: str) -> list[int]:
    tasks = [_check_port(ip, p, PRESCAN_TIMEOUT) for p in PRESCAN_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return sorted(p for p in results if isinstance(p, int))


# ═══════════════════════════════════════════════════════════════════
# Async API Queries
# ═══════════════════════════════════════════════════════════════════
async def query_internetdb(
    session: aiohttp.ClientSession, ip: str,
) -> dict[str, Any] | None:
    await _wait_breaker(_shodan_ok)
    url = f"https://internetdb.shodan.io/{ip}"
    for attempt in range(MAX_RETRIES + 1):
        await _wait_breaker(_shodan_ok)
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if data.get("ports") or data.get("vulns"):
                        return data
                    return None
                if resp.status == 404:
                    return None
                if resp.status == 429:
                    _trip_breaker(_shodan_ok, "Shodan InternetDB", 60)
                    await _wait_breaker(_shodan_ok)
                    continue
                logger.warning("InternetDB %s: HTTP %s", ip, resp.status)
        except Exception as e:
            if attempt == MAX_RETRIES:
                logger.debug("InternetDB %s: %s", ip, e)
        if attempt < MAX_RETRIES:
            await asyncio.sleep(0.3)
    return None


async def query_ipinfo(
    session: aiohttp.ClientSession, ip: str, limiter: AsyncTokenBucket,
) -> dict[str, Any]:
    if not _ipinfo_ok.is_set():
        return {}
    if not await limiter.acquire(timeout=1):
        return {}
    url = f"https://ipinfo.io/{ip}/json"
    params = {}
    if IPINFO_TOKEN:
        params["token"] = IPINFO_TOKEN
    try:
        async with session.get(
            url, params=params,
            timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
        ) as resp:
            if resp.status == 200:
                raw = await resp.json(content_type=None)
                loc = raw.get("loc", "")
                lat, lon = (loc.split(",") + ["", ""])[:2]
                return {
                    "city": raw.get("city", ""),
                    "region": raw.get("region", ""),
                    "country": raw.get("country", ""),
                    "lat": lat,
                    "lon": lon,
                    "org": raw.get("org", ""),
                    "timezone": raw.get("timezone", ""),
                }
            if resp.status == 429:
                _trip_breaker(_ipinfo_ok, "IPinfo.io", 120)
    except Exception:
        pass
    return {}


async def query_ipapi(
    session: aiohttp.ClientSession, ip: str, limiter: AsyncTokenBucket,
) -> dict[str, Any]:
    if not _ipapi_ok.is_set():
        return {}
    if not await limiter.acquire(timeout=1):
        return {}
    url = f"http://ip-api.com/json/{ip}"
    fields = "status,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting"
    try:
        async with session.get(
            url, params={"fields": fields},
            timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
        ) as resp:
            if resp.status == 200:
                raw = await resp.json(content_type=None)
                if raw.get("status") == "success":
                    return {
                        "isp": raw.get("isp", ""),
                        "org": raw.get("org", ""),
                        "as": raw.get("as", ""),
                        "mobile": raw.get("mobile", False),
                        "proxy": raw.get("proxy", False),
                        "hosting": raw.get("hosting", False),
                    }
            if resp.status == 429:
                _trip_breaker(_ipapi_ok, "ip-api.com", 90)
            remaining = resp.headers.get("X-Rl", "")
            if remaining and int(remaining) <= 2:
                ttl = int(resp.headers.get("X-Ttl", "60"))
                _trip_breaker(_ipapi_ok, "ip-api.com", ttl)
    except (Exception, ValueError):
        pass
    return {}


async def query_threatfox(
    session: aiohttp.ClientSession, ip: str,
) -> dict[str, Any]:
    if not _threatfox_ok.is_set():
        return {}
    url = "https://threatfox-api.abuse.ch/api/v1/"
    try:
        async with session.post(
            url,
            json={"query": "search_ioc", "search_term": ip},
            timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
        ) as resp:
            if resp.status == 200:
                raw = await resp.json(content_type=None)
                if raw.get("query_status") == "ok" and raw.get("data"):
                    threats = []
                    for entry in raw["data"][:5]:
                        threats.append({
                            "malware": entry.get("malware", ""),
                            "malware_printable": entry.get("malware_printable", ""),
                            "threat_type": entry.get("threat_type", ""),
                            "confidence": entry.get("confidence_level", 0),
                            "first_seen": entry.get("first_seen", ""),
                            "tags": entry.get("tags") or [],
                        })
                    return {"known_threat": True, "threats": threats}
                return {"known_threat": False, "threats": []}
            if resp.status == 429:
                _trip_breaker(_threatfox_ok, "ThreatFox", 120)
    except Exception:
        pass
    return {}


async def query_reverse_dns(ip: str) -> str:
    def _resolve():
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""
    try:
        return await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, _resolve),
            timeout=2,
        )
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════════
# Async Service Probes
# ═══════════════════════════════════════════════════════════════════
async def probe_http(
    session: aiohttp.ClientSession, ip: str, port: int, ssl_flag: bool = False,
) -> dict[str, Any] | None:
    protocol = "https" if ssl_flag else "http"
    url = f"{protocol}://{ip}:{port}"
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=SOCKET_TIMEOUT),
            allow_redirects=True,
        ) as resp:
            chunk = await resp.content.read(10240)
            text = chunk.decode("utf-8", errors="ignore")
            server = (resp.headers.get("Server") or "")[:200]
            title = ""
            if "<title>" in text:
                start = text.find("<title>") + 7
                end = text.find("</title>", start)
                if end > start:
                    title = text[start:end].strip()[:200]
            return {"service": protocol, "port": port, "server": server, "title": title}
    except Exception:
        return None


async def _probe_banner(ip: str, port: int, service: str) -> dict[str, Any] | None:
    sem = _conn_sem
    if sem is not None:
        await sem.acquire()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=SOCKET_TIMEOUT,
        )
        banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=SOCKET_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {
            "service": service,
            "port": port,
            "banner": banner_bytes.decode("utf-8", errors="ignore").strip()[:500],
        }
    except Exception:
        return None
    finally:
        if sem is not None:
            sem.release()


_PROBE_MAP: dict[int, tuple[str, bool]] = {
    80: ("http", False),
    443: ("http", True),
    8080: ("http", False),
    8443: ("http", True),
    8000: ("http", False),
    8888: ("http", False),
    3000: ("http", False),
    4443: ("http", True),
    9090: ("http", False),
    5000: ("http", False),
    5601: ("http", False),
    5984: ("http", False),
    9200: ("http", False),
    15672: ("http", False),
    4848: ("http", False),
    8500: ("http", False),
    22: ("ssh", False),
    23: ("telnet", False),
}


async def probe_router_services(
    session: aiohttp.ClientSession, ip: str, ports: list[int],
) -> list[dict[str, Any]]:
    port_set = set(ports or [])
    tasks = []
    for port, (kind, flag) in _PROBE_MAP.items():
        if port not in port_set:
            continue
        if kind == "http":
            tasks.append(probe_http(session, ip, port, ssl_flag=flag))
        else:
            tasks.append(_probe_banner(ip, port, kind))
    if not tasks:
        return []
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [_norm_router_info(r) for r in results if r and not isinstance(r, Exception)]


def _norm_router_info(info: dict[str, Any]) -> dict[str, Any]:
    return {
        "port": info.get("port"),
        "service": info.get("service", ""),
        "banner": info.get("banner", ""),
        "title": info.get("title", ""),
        "server": info.get("server", ""),
    }


# ═══════════════════════════════════════════════════════════════════
# Risk Scoring
# ═══════════════════════════════════════════════════════════════════
def compute_risk_profile(
    ports: list[int],
    vulns: list[str],
    hostnames: list[str],
    router_info_list: list[dict[str, Any]],
    threat_intel: dict[str, Any] | None = None,
    network_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    if vulns:
        vuln_score = min(60, 20 + len(vulns) * 10)
        score += vuln_score
        reasons.append(f"{len(vulns)} vulnerabilidade(s) reportada(s)")

    risky_open_ports = sorted([p for p in (ports or []) if p in HIGH_RISK_PORTS])
    if risky_open_ports:
        ports_score = min(20, 8 + len(risky_open_ports) * 3)
        score += ports_score
        reasons.append(f"portas sensíveis abertas: {', '.join(map(str, risky_open_ports[:6]))}")

    CRITICAL_PORTS = {2375, 2376, 10250, 6443, 11211, 8888, 5984}
    critical_open = sorted([p for p in (ports or []) if p in CRITICAL_PORTS])
    if critical_open:
        score += min(40, 25 + len(critical_open) * 5)
        reasons.append(f"serviços críticos expostos: {', '.join(map(str, critical_open))}")

    services = {str(i.get("service", "")).lower() for i in (router_info_list or [])}
    if "telnet" in services:
        score += 20
        reasons.append("serviço Telnet detectado")
    if "ssh" in services:
        score += 10
        reasons.append("serviço SSH exposto")
    if "http" in services or "https" in services:
        score += 6
        reasons.append("superfície web exposta")

    if hostnames:
        score += 4
        reasons.append("hostname(s) público(s) associado(s)")

    if threat_intel and threat_intel.get("known_threat"):
        score += 30
        malwares = [t.get("malware_printable", "?") for t in threat_intel.get("threats", [])[:3]]
        reasons.append(f"IOC conhecido (ThreatFox): {', '.join(malwares)}")

    if network_info:
        if network_info.get("proxy"):
            score += 5
            reasons.append("IP identificado como proxy/VPN")
        if network_info.get("hosting"):
            score += 3
            reasons.append("IP de datacenter/hosting")

    score = min(100, score)
    if score >= 70:
        risk_level = "high"
    elif score >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {"score": score, "level": risk_level, "reasons": reasons}


# ═══════════════════════════════════════════════════════════════════
# Batch Writer
# ═══════════════════════════════════════════════════════════════════
_write_buffer: list[dict] = []
_write_buffer_lock = threading.Lock()
_pending_logs: list[dict] = []


def _enqueue_write(doc: dict, log_info: dict | None = None) -> None:
    with _write_buffer_lock:
        _write_buffer.append(doc)
        if log_info:
            _pending_logs.append(log_info)
        if len(_write_buffer) >= BATCH_SIZE:
            _flush_writes_locked()


def _flush_writes_locked() -> None:
    if not _write_buffer:
        return
    batch = _write_buffer[:]
    logs = _pending_logs[:]
    _write_buffer.clear()
    _pending_logs.clear()
    try:
        get_scan_results().insert_many(batch, ordered=False)
        with _stats_lock:
            _scan_stats["saved"] = _scan_stats.get("saved", 0) + len(batch)
        for info in logs:
            logger.info(
                "[+] %-15s  %-5s  %-22s  portas:%-12s  risco:%s(%s)%s",
                info["ip"], info["loc"], info["org"],
                info["ports_str"], info["risk_char"], info["risk_score"],
                info["flag_str"],
            )
    except Exception as e:
        logger.error("[!] Batch write falhou (%d docs): %s", len(batch), e)
        for doc in batch:
            try:
                get_scan_results().insert_one(doc)
                with _stats_lock:
                    _scan_stats["saved"] = _scan_stats.get("saved", 0) + 1
            except Exception:
                pass


async def _batch_writer_task() -> None:
    while True:
        await asyncio.sleep(BATCH_FLUSH_INTERVAL)
        with _write_buffer_lock:
            _flush_writes_locked()


# ═══════════════════════════════════════════════════════════════════
# Rate Tracker
# ═══════════════════════════════════════════════════════════════════
async def _rate_tracker_task() -> None:
    last_tested = 0
    while True:
        await asyncio.sleep(5)
        with _stats_lock:
            current = _scan_stats.get("tested", 0)
        rate = (current - last_tested) / 5.0
        last_tested = current
        with _stats_lock:
            _scan_stats["rps"] = round(rate, 1)


# ═══════════════════════════════════════════════════════════════════
# Scan Pipeline
# ═══════════════════════════════════════════════════════════════════
async def _scan_one(
    session: aiohttp.ClientSession,
    shodan_limiter: AsyncTokenBucket | None,
    ipapi_limiter: AsyncTokenBucket,
    ipinfo_limiter: AsyncTokenBucket,
) -> bool:
    ip = get_next_ip()
    _inc_stat("tested")

    alive_ports = await quick_port_scan(ip)
    if not alive_ports:
        _inc_stat("dead")
        return False

    _inc_stat("alive")

    ports = list(alive_ports)
    vulns: list[str] = []
    hostnames: list[str] = []

    if SHODAN_ENABLED and shodan_limiter:
        await shodan_limiter.acquire()
        data = await query_internetdb(session, ip)
        if data:
            ports = data.get("ports") or ports
            vulns = data.get("vulns") or []
            hostnames = data.get("hostnames") or []

    has_vulns = bool(vulns)
    has_risky_ports = bool(set(ports) & HIGH_RISK_PORTS)
    needs_full = has_vulns or has_risky_ports or len(ports) >= 4

    probe_coro = probe_router_services(session, ip, ports)
    rdns_coro = query_reverse_dns(ip)

    geo: dict[str, Any] = {}
    network_info: dict[str, Any] = {}
    threat_intel: dict[str, Any] = {}

    if needs_full:
        results = await asyncio.gather(
            probe_coro, rdns_coro,
            query_ipinfo(session, ip, ipinfo_limiter),
            query_ipapi(session, ip, ipapi_limiter),
            query_threatfox(session, ip),
            return_exceptions=True,
        )
        router_info_list = results[0] if not isinstance(results[0], Exception) else []
        rdns = results[1] if not isinstance(results[1], Exception) else ""
        geo = results[2] if not isinstance(results[2], Exception) else {}
        network_info = results[3] if not isinstance(results[3], Exception) else {}
        threat_intel = results[4] if not isinstance(results[4], Exception) else {}
    else:
        results = await asyncio.gather(
            probe_coro, rdns_coro,
            return_exceptions=True,
        )
        router_info_list = results[0] if not isinstance(results[0], Exception) else []
        rdns = results[1] if not isinstance(results[1], Exception) else ""

    for info in router_info_list:
        info.pop("timestamp", None)

    if geo and network_info:
        geo["isp"] = network_info.get("isp", "")
        geo["as"] = network_info.get("as", "")
        geo["mobile"] = network_info.get("mobile", False)
        geo["proxy"] = network_info.get("proxy", False)
        geo["hosting"] = network_info.get("hosting", False)

    doc = {
        "ip": ip,
        "ports": ports,
        "vulns": vulns,
        "hostnames": hostnames,
        "rdns": rdns,
        "router_info": router_info_list,
        "geo": geo,
        "network": network_info,
        "threat_intel": threat_intel,
        "risk": compute_risk_profile(
            ports, vulns, hostnames, router_info_list,
            threat_intel=threat_intel,
            network_info=network_info,
        ),
        "timestamp": datetime.utcnow(),
    }

    country = geo.get("country", "??") if geo else "??"
    city = geo.get("city", "") if geo else ""
    org = (geo.get("isp") or geo.get("org") or "")[:22] if geo else ""
    risk = doc["risk"]
    flags = []
    if threat_intel.get("known_threat"):
        flags.append("THREAT")
    if network_info.get("proxy"):
        flags.append("PROXY")
    if network_info.get("hosting"):
        flags.append("HOST")
    loc = country
    if city:
        loc += f"/{city}"
    flag_str = f" [{','.join(flags)}]" if flags else ""

    log_info = {
        "ip": ip,
        "loc": loc,
        "org": org,
        "ports_str": ",".join(map(str, ports[:5])) + (f"+{len(ports)-5}" if len(ports) > 5 else ""),
        "risk_char": risk["level"][0].upper(),
        "risk_score": risk["score"],
        "flag_str": flag_str,
    }

    _enqueue_write(doc, log_info)
    return True


# ═══════════════════════════════════════════════════════════════════
# Worker
# ═══════════════════════════════════════════════════════════════════
async def _worker(
    worker_id: int,
    session: aiohttp.ClientSession,
    shodan_limiter: AsyncTokenBucket | None,
    ipapi_limiter: AsyncTokenBucket,
    ipinfo_limiter: AsyncTokenBucket,
) -> None:
    while True:
        try:
            found = await _scan_one(
                session, shodan_limiter, ipapi_limiter, ipinfo_limiter,
            )
            if not found:
                await asyncio.sleep(0)
            elif SCAN_INTERVAL > 0:
                await asyncio.sleep(SCAN_INTERVAL)
            else:
                await asyncio.sleep(0)
        except Exception as e:
            logger.error("[!] W%s: %s", worker_id, e)
            await asyncio.sleep(0.5)


# ═══════════════════════════════════════════════════════════════════
# Main async event loop
# ═══════════════════════════════════════════════════════════════════
async def _async_scanner(num_workers: int) -> None:
    global _conn_sem
    _conn_sem = asyncio.Semaphore(MAX_CONCURRENT_CONNS)

    connector = aiohttp.TCPConnector(
        limit=500,
        limit_per_host=20,
        ttl_dns_cache=300,
        ssl=False,
        enable_cleanup_closed=True,
        force_close=False,
    )
    default_timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT, connect=3)

    async with aiohttp.ClientSession(
        connector=connector, timeout=default_timeout,
    ) as session:
        shodan_limiter = AsyncTokenBucket(SHODAN_RPS) if SHODAN_ENABLED else None
        ipapi_limiter = AsyncTokenBucket(IPAPI_RPS)
        ipinfo_limiter = AsyncTokenBucket(IPINFO_RPS)

        logger.info(
            "[*] Scanner v4 (asyncio): %d workers | Shodan %s | "
            "prescan %d portas (%.1fs) | batch=%d | max_conns=%d",
            num_workers,
            "OFF" if not SHODAN_ENABLED else f"{SHODAN_RPS}/s",
            len(PRESCAN_PORTS), PRESCAN_TIMEOUT,
            BATCH_SIZE, MAX_CONCURRENT_CONNS,
        )

        tasks: list[asyncio.Task] = []
        for i in range(num_workers):
            tasks.append(asyncio.create_task(
                _worker(i + 1, session, shodan_limiter, ipapi_limiter, ipinfo_limiter),
            ))
        tasks.append(asyncio.create_task(_batch_writer_task()))
        tasks.append(asyncio.create_task(_rate_tracker_task()))

        logger.info("[*] Todos os %d workers ativos", num_workers)
        await asyncio.gather(*tasks)


# ═══════════════════════════════════════════════════════════════════
# Entry point (called from main.py in a thread)
# ═══════════════════════════════════════════════════════════════════
def run_scanner(num_workers: int = NUM_SCANNER_WORKERS, interval: float | None = None) -> None:
    global SCAN_INTERVAL
    if interval is not None:
        SCAN_INTERVAL = interval

    start_feeds()

    logger.info(
        "[*] Iniciando scanner asyncio com %d workers...", num_workers,
    )
    asyncio.run(_async_scanner(num_workers))
