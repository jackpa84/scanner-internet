"""
Scanner de IPs: pre-scan paralelo → Shodan InternetDB → enriquecimento multi-API → MongoDB.

Otimizações v2:
  - Pre-scan TCP paralelo (ThreadPoolExecutor)
  - IPs inteligentes via ip_feeds (CIDR hosting, RIPE BGP, DShield, Blocklist.de, masscan)
  - Rate limiter token-bucket para Shodan
  - Circuit breakers por API com cooldown automático
"""

import os
import random
import requests
import time
import logging
import socket
import threading
from datetime import datetime
from typing import Any

from app.database import get_scan_results
from app.ip_feeds import get_next_ip, start_feeds, get_feed_stats

logger = logging.getLogger("scanner")

requests.packages.urllib3.disable_warnings()

NUM_SCANNER_WORKERS = int(os.getenv("NUM_WORKERS", "200"))
SCAN_INTERVAL = float(os.getenv("SCAN_INTERVAL", "0.2"))
SHODAN_RPS = float(os.getenv("SHODAN_RPS", "10"))
IPAPI_RPS = float(os.getenv("IPAPI_RPS", "0.7"))
IPINFO_RPS = float(os.getenv("IPINFO_RPS", "0.8"))

HTTP_TIMEOUT = 8
SOCKET_TIMEOUT = 4
PRESCAN_TIMEOUT = float(os.getenv("PRESCAN_TIMEOUT", "0.8"))
MAX_RETRIES = 2
HIGH_RISK_PORTS = {21, 22, 23, 445, 3389, 5900, 8080, 8443}
PRESCAN_PORTS = [80, 443, 22, 8080, 23, 21, 3389, 8443, 25, 53]

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

_shodan_tokens = threading.Semaphore(0)
_ipapi_tokens = threading.Semaphore(0)
_ipinfo_tokens = threading.Semaphore(0)
_scan_stats = {"tested": 0, "alive": 0, "saved": 0, "dead": 0}
_stats_lock = threading.Lock()


def _token_refiller() -> None:
    """Repõe tokens para Shodan, ip-api e IPinfo nas taxas configuradas."""
    buckets = [
        (_shodan_tokens, SHODAN_RPS),
        (_ipapi_tokens, IPAPI_RPS),
        (_ipinfo_tokens, IPINFO_RPS),
    ]
    tick = 0.05
    counters = [0.0] * len(buckets)
    while True:
        time.sleep(tick)
        for i, (sem, rps) in enumerate(buckets):
            counters[i] += tick * rps
            while counters[i] >= 1.0:
                counters[i] -= 1.0
                try:
                    sem.release()
                except ValueError:
                    pass


def _inc_stat(key: str) -> None:
    with _stats_lock:
        _scan_stats[key] = _scan_stats.get(key, 0) + 1


def get_scan_stats() -> dict[str, Any]:
    with _stats_lock:
        return dict(_scan_stats)


# ---------------------------------------------------------------------------
# Pre-scan TCP paralelo — threads isoladas por chamada (sem pool compartilhado)
# ---------------------------------------------------------------------------
def quick_port_scan(ip: str) -> list[int]:
    """
    Cria uma thread por porta e testa todas simultaneamente.
    Cada worker cria suas próprias threads → sem contention entre workers.
    Tempo máximo ≈ PRESCAN_TIMEOUT + 0.5s (join timeout).
    """
    open_ports: list[int] = []
    lock = threading.Lock()

    def _check(port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PRESCAN_TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                with lock:
                    open_ports.append(port)
        except OSError:
            pass

    threads = [threading.Thread(target=_check, args=(p,), daemon=True) for p in PRESCAN_PORTS]
    for t in threads:
        t.start()
    deadline = PRESCAN_TIMEOUT + 0.5
    for t in threads:
        t.join(timeout=deadline)
    return sorted(open_ports)


# ---------------------------------------------------------------------------
# Circuit breakers
# ---------------------------------------------------------------------------
_shodan_ok = threading.Event()
_shodan_ok.set()
_ipinfo_ok = threading.Event()
_ipinfo_ok.set()
_ipapi_ok = threading.Event()
_ipapi_ok.set()
_threatfox_ok = threading.Event()
_threatfox_ok.set()
_lock = threading.Lock()

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
        blocked = not event.is_set()
        remaining = 0
        if blocked and "unblock_at" in info:
            remaining = max(0, int(info["unblock_at"] - now))
        result.append({
            "name": name,
            "blocked": blocked,
            "cooldown": info.get("cooldown", 0),
            "remaining_seconds": remaining,
            "blocked_since": info.get("blocked_since", ""),
        })
    return result


def _trip_breaker(breaker: threading.Event, name: str, cooldown: int) -> None:
    with _lock:
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


# ---------------------------------------------------------------------------
# API queries
# ---------------------------------------------------------------------------
def query_internetdb(ip: str) -> dict[str, Any] | None:
    _shodan_ok.wait()
    url = f"https://internetdb.shodan.io/{ip}"
    for attempt in range(MAX_RETRIES + 1):
        _shodan_ok.wait()
        try:
            resp = requests.get(url, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ports") or data.get("vulns"):
                    return data
                return None
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                _trip_breaker(_shodan_ok, "Shodan InternetDB", 60)
                _shodan_ok.wait()
                continue
            logger.warning("InternetDB %s: HTTP %s", ip, resp.status_code)
        except requests.RequestException as e:
            logger.warning("InternetDB tentativa %s para %s: %s", attempt + 1, ip, e)
        if attempt < MAX_RETRIES:
            time.sleep(1)
    return None


def query_ipinfo(ip: str) -> dict[str, Any]:
    if not _ipinfo_ok.is_set():
        return {}
    if not _ipinfo_tokens.acquire(timeout=2):
        return {}
    url = f"https://ipinfo.io/{ip}/json"
    params = {}
    if IPINFO_TOKEN:
        params["token"] = IPINFO_TOKEN
    try:
        resp = requests.get(url, params=params, timeout=5)
        if resp.status_code == 200:
            raw = resp.json()
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
        if resp.status_code == 429:
            _trip_breaker(_ipinfo_ok, "IPinfo.io", 120)
    except requests.RequestException:
        pass
    return {}


def query_ipapi(ip: str) -> dict[str, Any]:
    if not _ipapi_ok.is_set():
        return {}
    if not _ipapi_tokens.acquire(timeout=2):
        return {}
    url = f"http://ip-api.com/json/{ip}"
    fields = "status,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting"
    try:
        resp = requests.get(url, params={"fields": fields}, timeout=5)
        if resp.status_code == 200:
            raw = resp.json()
            if raw.get("status") == "success":
                return {
                    "isp": raw.get("isp", ""),
                    "org": raw.get("org", ""),
                    "as": raw.get("as", ""),
                    "mobile": raw.get("mobile", False),
                    "proxy": raw.get("proxy", False),
                    "hosting": raw.get("hosting", False),
                }
        if resp.status_code == 429:
            _trip_breaker(_ipapi_ok, "ip-api.com", 90)
        remaining = resp.headers.get("X-Rl", "")
        if remaining and int(remaining) <= 2:
            ttl = int(resp.headers.get("X-Ttl", "60"))
            _trip_breaker(_ipapi_ok, "ip-api.com", ttl)
    except (requests.RequestException, ValueError):
        pass
    return {}


def query_threatfox(ip: str) -> dict[str, Any]:
    if not _threatfox_ok.is_set():
        return {}
    url = "https://threatfox-api.abuse.ch/api/v1/"
    try:
        resp = requests.post(
            url, json={"query": "search_ioc", "search_term": ip}, timeout=10,
        )
        if resp.status_code == 200:
            raw = resp.json()
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
        if resp.status_code == 429:
            _trip_breaker(_threatfox_ok, "ThreatFox", 120)
    except requests.RequestException:
        pass
    return {}


def query_reverse_dns(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


# ---------------------------------------------------------------------------
# Service probes
# ---------------------------------------------------------------------------
def probe_http(ip: str, port: int, ssl_flag: bool = False) -> dict[str, Any] | None:
    protocol = "https" if ssl_flag else "http"
    url = f"{protocol}://{ip}:{port}"
    try:
        resp = requests.get(url, timeout=SOCKET_TIMEOUT, verify=False, allow_redirects=True)
        server = (resp.headers.get("Server") or "")[:200]
        title = ""
        if "<title>" in resp.text:
            start = resp.text.find("<title>") + 7
            end = resp.text.find("</title>", start)
            if end > start:
                title = resp.text[start:end].strip()[:200]
        return {"service": protocol, "port": port, "server": server, "title": title}
    except Exception:
        return None


def probe_ssh(ip: str, port: int = 22) -> dict[str, Any] | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:500]
        sock.close()
        return {"service": "ssh", "port": port, "banner": banner}
    except Exception:
        return None


def probe_telnet(ip: str, port: int = 23) -> dict[str, Any] | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:500]
        sock.close()
        return {"service": "telnet", "port": port, "banner": banner}
    except Exception:
        return None


def probe_router_services(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    port_set = set(ports or [])
    if 80 in port_set:
        r = probe_http(ip, 80, ssl_flag=False)
        if r:
            results.append(_norm_router_info(r))
    if 443 in port_set:
        r = probe_http(ip, 443, ssl_flag=True)
        if r:
            results.append(_norm_router_info(r))
    if 8080 in port_set:
        r = probe_http(ip, 8080, ssl_flag=False)
        if r:
            results.append(_norm_router_info(r))
    if 8443 in port_set:
        r = probe_http(ip, 8443, ssl_flag=True)
        if r:
            results.append(_norm_router_info(r))
    if 22 in port_set:
        r = probe_ssh(ip, 22)
        if r:
            results.append(_norm_router_info(r))
    if 23 in port_set:
        r = probe_telnet(ip, 23)
        if r:
            results.append(_norm_router_info(r))
    return results


def _norm_router_info(info: dict[str, Any]) -> dict[str, Any]:
    return {
        "port": info.get("port"),
        "service": info.get("service", ""),
        "banner": info.get("banner", ""),
        "title": info.get("title", ""),
        "server": info.get("server", ""),
    }


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Scan pipeline
# ---------------------------------------------------------------------------
def scan_and_save_once(worker_id: int) -> bool:
    ip = get_next_ip()
    _inc_stat("tested")

    alive_ports = quick_port_scan(ip)
    if not alive_ports:
        _inc_stat("dead")
        logger.debug("[W%s] %s morto (prescan)", worker_id, ip)
        return False

    _inc_stat("alive")

    _shodan_tokens.acquire()

    data = query_internetdb(ip)
    if not data:
        return False

    ports = data.get("ports") or []
    vulns = data.get("vulns") or []
    hostnames = data.get("hostnames") or []

    router_info_list = probe_router_services(ip, ports)
    for info in router_info_list:
        info.pop("timestamp", None)

    geo = query_ipinfo(ip)
    network_info = query_ipapi(ip)
    threat_intel = query_threatfox(ip)
    rdns = query_reverse_dns(ip)

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

    try:
        get_scan_results().insert_one(doc)
        _inc_stat("saved")
        country = geo.get("country", "??") if geo else "??"
        city = geo.get("city", "") if geo else ""
        org = (geo.get("isp") or geo.get("org") or "") if geo else ""
        risk = doc["risk"]
        flags = []
        if threat_intel.get("known_threat"):
            flags.append("THREAT")
        if network_info.get("proxy"):
            flags.append("PROXY")
        if network_info.get("hosting"):
            flags.append("HOST")
        loc = f"{country}"
        if city:
            loc += f"/{city}"
        flag_str = f" [{','.join(flags)}]" if flags else ""
        logger.info(
            "[+] %-15s  %-5s  %s %-20s  portas:%-12s  risco:%s(%s)%s",
            ip, loc, org[:22], "",
            ",".join(map(str, ports[:5])) + (f"+{len(ports)-5}" if len(ports) > 5 else ""),
            risk["level"][0].upper(), risk["score"],
            flag_str,
        )
        return True
    except Exception as e:
        logger.error("[!] Erro ao salvar %s: %s", ip, e)
        return False


def _worker_loop(worker_id: int) -> None:
    while True:
        try:
            scan_and_save_once(worker_id)
        except Exception as e:
            logger.error("[!] W%s: %s", worker_id, e)
        time.sleep(SCAN_INTERVAL)


def run_scanner(num_workers: int = NUM_SCANNER_WORKERS, interval: float | None = None) -> None:
    global SCAN_INTERVAL
    delay = interval if interval is not None else SCAN_INTERVAL
    if delay != SCAN_INTERVAL:
        SCAN_INTERVAL = delay

    start_feeds()

    refiller = threading.Thread(target=_token_refiller, daemon=True)
    refiller.start()

    logger.info(
        "[*] Scanner iniciado: %s workers | %.1fs intervalo | Shodan %s/s | prescan %d portas",
        num_workers, SCAN_INTERVAL, SHODAN_RPS, len(PRESCAN_PORTS),
    )
    threads = []
    for i in range(num_workers):
        t = threading.Thread(target=_worker_loop, args=(i + 1,), daemon=True)
        t.start()
        threads.append(t)
    logger.info("[*] Todos os %s workers ativos", num_workers)
    for t in threads:
        t.join()
