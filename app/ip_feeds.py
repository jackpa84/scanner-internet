"""
Geração inteligente de IPs com múltiplas fontes + ASN discovery para bounty.

Fontes gerais (network scanner):
  1. CIDR blocks densos (hosting/cloud)
  2. RIPE Stat API — prefixos BGP anunciados por ASNs populares
  3. DShield/SANS — top IPs atacando a internet (sem chave)
  4. Blocklist.de — IPs abusivos reportados (sem chave)
  5. AbuseIPDB (opcional, com chave)
  6. masscan (opcional) — SYN scan em massa

Fontes bounty-aware:
  7. ASN discovery — descobre ASNs dos alvos de bounty e enumera prefixos
  8. Bounty target feed — prioriza IPs de organizações com programas ativos

Feedback loop (v4):
  - CIDR scoring: tracks which /16 blocks produce high-risk IPs
  - Weighted random selection favors productive CIDRs
  - Dead CIDRs get deprioritized over time
"""

import ipaddress
import logging
import os
import queue
import random
import shutil
import subprocess
import threading
import time
from typing import Any

import requests

logger = logging.getLogger("scanner.feeds")

ip_queue: queue.Queue[str] = queue.Queue(maxsize=100_000)

_RESERVED = [
    ipaddress.ip_network(n)
    for n in [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    ]
]


def is_public(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 4 and not any(addr in net for net in _RESERVED)
    except ValueError:
        return False


# --- Hosting provider CIDR blocks (alta densidade de hosts ativos) ---
HOSTING_CIDRS = [
    "45.55.0.0/16", "46.101.0.0/16", "64.225.0.0/16", "68.183.0.0/16",
    "104.131.0.0/16", "134.209.0.0/16", "137.184.0.0/16", "138.197.0.0/16",
    "139.59.0.0/16", "143.198.0.0/16", "157.245.0.0/16", "159.65.0.0/16",
    "159.89.0.0/16", "161.35.0.0/16", "165.22.0.0/16", "167.71.0.0/16",
    "167.172.0.0/16", "174.138.0.0/16", "178.128.0.0/16",
    "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "45.77.0.0/16",
    "64.176.0.0/16", "66.42.0.0/16", "78.141.0.0/16", "95.179.0.0/16",
    "108.61.0.0/16", "136.244.0.0/16", "140.82.0.0/16", "149.28.0.0/16",
    "155.138.0.0/16", "207.148.0.0/16",
    "5.9.0.0/16", "78.46.0.0/15", "88.99.0.0/16", "88.198.0.0/16",
    "116.202.0.0/16", "116.203.0.0/16", "135.181.0.0/16", "136.243.0.0/16",
    "138.201.0.0/16", "142.132.0.0/16", "144.76.0.0/16", "148.251.0.0/16",
    "159.69.0.0/16", "167.235.0.0/16", "168.119.0.0/16", "176.9.0.0/16",
    "178.63.0.0/16", "195.201.0.0/16",
    "5.39.0.0/16", "5.135.0.0/16", "5.196.0.0/16", "37.59.0.0/16",
    "37.187.0.0/16", "46.105.0.0/16", "51.38.0.0/16", "51.68.0.0/16",
    "51.75.0.0/16", "51.77.0.0/16", "51.79.0.0/16", "51.83.0.0/16",
    "51.89.0.0/16", "51.91.0.0/16", "54.36.0.0/16", "54.37.0.0/16",
    "54.38.0.0/16", "87.98.0.0/16", "91.121.0.0/16", "137.74.0.0/16",
    "145.239.0.0/16", "147.135.0.0/16", "149.56.0.0/16", "158.69.0.0/16",
    "164.132.0.0/16", "176.31.0.0/16", "178.32.0.0/16", "188.165.0.0/16",
    "45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16", "50.116.0.0/16",
    "139.162.0.0/16", "172.104.0.0/15", "172.232.0.0/14",
    "3.80.0.0/12", "13.52.0.0/14", "18.188.0.0/14", "34.192.0.0/12",
    "44.192.0.0/11", "52.0.0.0/11", "54.64.0.0/11",
    "34.64.0.0/11", "35.184.0.0/13",
    "104.16.0.0/13", "172.64.0.0/13",
    "62.171.128.0/17", "161.97.0.0/16", "167.86.0.0/16", "173.212.192.0/18",
    "178.238.224.0/19", "193.26.156.0/22", "207.180.192.0/18",
    "51.15.0.0/16", "51.158.0.0/16", "51.159.0.0/16", "163.172.0.0/16",
    "212.47.224.0/19",
]

_hosting_networks: list[ipaddress.IPv4Network] = []
for _c in HOSTING_CIDRS:
    try:
        _hosting_networks.append(ipaddress.ip_network(_c, strict=False))
    except ValueError:
        pass

INTERESTING_ASNS = [
    13335, 16509, 15169, 8075, 14061, 20473, 24940, 16276,
    63949, 36351, 14618, 396982, 53667, 4134, 4837, 9808,
    4766, 17676, 4713, 7922, 3320, 12322, 3215, 5607,
    2856, 28573, 18881, 7738, 55286, 209, 22773, 3356,
    174, 6939, 1299, 2914, 3257, 6762, 6461, 701,
]

_discovered_prefixes: list[ipaddress.IPv4Network] = []
_prefixes_lock = threading.Lock()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
MASSCAN_RATE = int(os.getenv("MASSCAN_RATE", "10000"))
MASSCAN_ENABLED = os.getenv("MASSCAN_ENABLED", "auto")

# ---------------------------------------------------------------------------
# Bounty ASN discovery — prefixos de ASNs dos alvos de bounty
# ---------------------------------------------------------------------------
_bounty_prefixes: list[ipaddress.IPv4Network] = []
_bounty_prefixes_lock = threading.Lock()
_bounty_asn_cache: dict[int, list[ipaddress.IPv4Network]] = {}
_bounty_asn_cache_lock = threading.Lock()

_feed_stats: dict[str, Any] = {
    "queue_size": 0,
    "hosting_cidrs": len(_hosting_networks),
    "discovered_prefixes": 0,
    "bounty_prefixes": 0,
    "bounty_asns_discovered": 0,
    "dshield_ips": 0,
    "blocklist_ips": 0,
    "abuseipdb_ips": 0,
    "masscan_ips": 0,
    "masscan_running": False,
    "aws_prefixes": 0,
    "gcp_prefixes": 0,
    "azure_prefixes": 0,
    "ipsum_ips": 0,
    "feodo_ips": 0,
    "et_compromised_ips": 0,
    "spamhaus_nets": 0,
    "tor_exits": 0,
}

# ---------------------------------------------------------------------------
# CDN IP ranges — used for identification, not scanning
# ---------------------------------------------------------------------------
_cdn_networks: list[ipaddress.IPv4Network] = []
_cdn_lock = threading.Lock()

# Cloud provider prefixes — for cross-referencing with bounty targets
_cloud_prefixes: dict[str, list[ipaddress.IPv4Network]] = {
    "aws": [],
    "gcp": [],
    "azure": [],
}
_cloud_lock = threading.Lock()


def get_cloud_prefixes() -> dict[str, int]:
    with _cloud_lock:
        return {k: len(v) for k, v in _cloud_prefixes.items()}


def is_cdn_ip(ip_str: str) -> bool:
    """Check if an IP belongs to a known CDN (Cloudflare, Fastly)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    with _cdn_lock:
        return any(addr in net for net in _cdn_networks)


def identify_cloud_provider(ip_str: str) -> str | None:
    """Identify which cloud provider an IP belongs to."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    with _cloud_lock:
        for provider, nets in _cloud_prefixes.items():
            if any(addr in net for net in nets):
                return provider
    return None
_feed_stats_lock = threading.Lock()

# ---------------------------------------------------------------------------
# CIDR Scoring — feedback loop from scan results
# ---------------------------------------------------------------------------
_cidr_scores: dict[str, dict[str, float]] = {}
_cidr_scores_lock = threading.Lock()
CIDR_SCORE_DECAY = 0.99
CIDR_TOP_N = 50


def report_scan_result(ip: str, alive: bool, risk_score: int) -> None:
    """Called by scanner after each IP scan to update CIDR quality scores.

    Builds a /16 → score mapping that generate_smart_ip uses to prefer
    productive address ranges.
    """
    try:
        parts = ip.split(".")
        cidr_key = f"{parts[0]}.{parts[1]}.0.0/16"
    except (IndexError, ValueError):
        return

    with _cidr_scores_lock:
        if cidr_key not in _cidr_scores:
            _cidr_scores[cidr_key] = {"score": 0.0, "scans": 0, "alive": 0, "high_risk": 0}
        entry = _cidr_scores[cidr_key]
        entry["scans"] += 1
        if alive:
            entry["alive"] += 1
            entry["score"] += 1.0
            if risk_score >= 40:
                entry["score"] += 5.0
            if risk_score >= 70:
                entry["score"] += 15.0
                entry["high_risk"] += 1
        else:
            entry["score"] -= 0.5


def _get_top_cidrs(n: int = CIDR_TOP_N) -> list[str]:
    """Return top N CIDRs by score for weighted IP generation."""
    with _cidr_scores_lock:
        if not _cidr_scores:
            return []
        items = sorted(_cidr_scores.items(), key=lambda x: x[1]["score"], reverse=True)
        return [k for k, v in items[:n] if v["score"] > 0]


def _decay_cidr_scores() -> None:
    """Periodically decay scores so stale CIDRs lose priority."""
    while True:
        time.sleep(600)
        with _cidr_scores_lock:
            to_remove = []
            for key, entry in _cidr_scores.items():
                entry["score"] *= CIDR_SCORE_DECAY
                if entry["score"] < 0.1 and entry["scans"] > 10:
                    to_remove.append(key)
            for key in to_remove:
                del _cidr_scores[key]


def get_cidr_score_stats() -> dict[str, Any]:
    with _cidr_scores_lock:
        total = len(_cidr_scores)
        if not _cidr_scores:
            return {"total_cidrs_tracked": 0, "top_5": []}
        items = sorted(_cidr_scores.items(), key=lambda x: x[1]["score"], reverse=True)
        top = [{"cidr": k, **v} for k, v in items[:5]]
        return {"total_cidrs_tracked": total, "top_5": top}


def get_feed_stats() -> dict[str, Any]:
    with _feed_stats_lock:
        s = dict(_feed_stats)
    s["queue_size"] = ip_queue.qsize()
    with _prefixes_lock:
        s["discovered_prefixes"] = len(_discovered_prefixes)
    with _bounty_prefixes_lock:
        s["bounty_prefixes"] = len(_bounty_prefixes)
    s["cloud"] = get_cloud_prefixes()
    with _cdn_lock:
        s["cdn_ranges"] = len(_cdn_networks)
    s["cidr_scoring"] = get_cidr_score_stats()
    return s


def _inc_feed(key: str, n: int = 1) -> None:
    with _feed_stats_lock:
        _feed_stats[key] = _feed_stats.get(key, 0) + n


def _random_ip_from_cidr(network: ipaddress.IPv4Network) -> str:
    net_int = int(network.network_address)
    host_count = network.num_addresses
    if host_count <= 2:
        return str(ipaddress.IPv4Address(net_int + 1))
    offset = random.randint(1, host_count - 2)
    return str(ipaddress.IPv4Address(net_int + offset))


def _random_public_ip() -> str:
    while True:
        first = random.randint(1, 223)
        if first in (10, 127):
            continue
        ip = f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if is_public(ip):
            return ip


# ---------------------------------------------------------------------------
# ASN discovery utilities (exported for bounty.py)
# ---------------------------------------------------------------------------
def discover_asn_for_ip(ip_str: str) -> dict[str, Any] | None:
    """Query RIPE Stat to find the ASN and holder for a given IP.

    Returns {"asn": int, "holder": str, "prefix": str} or None.
    """
    try:
        url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip_str}"
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {})
        asns = data.get("asns", [])
        if not asns:
            return None
        asn_info = asns[0]
        return {
            "asn": asn_info.get("asn"),
            "holder": asn_info.get("holder", ""),
            "prefix": data.get("resource", ""),
        }
    except Exception:
        return None


def enumerate_asn_prefixes(asn: int) -> list[ipaddress.IPv4Network]:
    """List all announced IPv4 prefixes for an ASN via RIPE Stat.

    Uses an internal cache so repeated calls for the same ASN are free.
    """
    with _bounty_asn_cache_lock:
        if asn in _bounty_asn_cache:
            return list(_bounty_asn_cache[asn])

    prefixes: list[ipaddress.IPv4Network] = []
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return prefixes
        for p in resp.json().get("data", {}).get("prefixes", []):
            try:
                net = ipaddress.ip_network(p.get("prefix", ""), strict=False)
                if net.version == 4 and 16 <= net.prefixlen <= 24:
                    prefixes.append(net)
            except ValueError:
                pass
    except Exception:
        pass

    with _bounty_asn_cache_lock:
        _bounty_asn_cache[asn] = list(prefixes)

    return prefixes


def discover_org_ip_ranges(sample_ips: list[str]) -> list[ipaddress.IPv4Network]:
    """Given sample IPs from a target org, discover all IP ranges owned by that org.

    1. Finds ASNs for each sample IP
    2. Enumerates all prefixes announced by those ASNs
    3. Returns deduplicated list of networks
    """
    seen_asns: set[int] = set()
    all_prefixes: list[ipaddress.IPv4Network] = []

    for ip in sample_ips[:20]:
        asn_info = discover_asn_for_ip(ip)
        if not asn_info or not asn_info.get("asn"):
            continue
        asn = asn_info["asn"]
        if asn in seen_asns:
            continue
        seen_asns.add(asn)
        prefixes = enumerate_asn_prefixes(asn)
        all_prefixes.extend(prefixes)
        logger.info("[FEED] ASN discovery: IP %s → AS%d (%s) → %d prefixes",
                    ip, asn, asn_info.get("holder", "?")[:30], len(prefixes))
        time.sleep(0.5)

    seen_nets: set[str] = set()
    deduped: list[ipaddress.IPv4Network] = []
    for net in all_prefixes:
        key = str(net)
        if key not in seen_nets:
            seen_nets.add(key)
            deduped.append(net)

    return deduped


def register_bounty_prefixes(prefixes: list[ipaddress.IPv4Network]) -> int:
    """Register IP prefixes discovered from bounty targets for prioritized scanning."""
    added = 0
    with _bounty_prefixes_lock:
        existing = {str(p) for p in _bounty_prefixes}
        for p in prefixes:
            key = str(p)
            if key not in existing:
                existing.add(key)
                _bounty_prefixes.append(p)
                added += 1
    if added:
        _inc_feed("bounty_prefixes", added)
        logger.info("[FEED] %d novos prefixos bounty registrados (total=%d)",
                    added, len(_bounty_prefixes))
    return added


# ---------------------------------------------------------------------------
# Smart IP generation (bounty-aware)
# ---------------------------------------------------------------------------
BOUNTY_FEED_MODE = os.getenv("BOUNTY_MODE", "true").lower() in ("1", "true", "yes")


def generate_smart_ip() -> str:
    """Generate an IP with bounty-aware priorities + feedback loop.

    When bounty prefixes exist:
      60% bounty target ASN prefixes
      15% top-scoring CIDRs (feedback loop)
      15% hosting CIDR
      10% random

    Without bounty prefixes:
      40% hosting CIDR
      25% top-scoring CIDRs (feedback loop)
      20% BGP prefixes
      15% random
    """
    roll = random.random()

    with _bounty_prefixes_lock:
        has_bounty = len(_bounty_prefixes) > 0

    top_cidrs = _get_top_cidrs()

    if has_bounty and BOUNTY_FEED_MODE:
        if roll < 0.60:
            with _bounty_prefixes_lock:
                net = random.choice(_bounty_prefixes)
            ip = _random_ip_from_cidr(net)
            if is_public(ip):
                return ip

        if roll < 0.75 and top_cidrs:
            cidr_str = random.choice(top_cidrs)
            try:
                net = ipaddress.ip_network(cidr_str, strict=False)
                ip = _random_ip_from_cidr(net)
                if is_public(ip):
                    return ip
            except ValueError:
                pass

        if roll < 0.90 and _hosting_networks:
            net = random.choice(_hosting_networks)
            ip = _random_ip_from_cidr(net)
            if is_public(ip):
                return ip

        return _random_public_ip()

    if roll < 0.40 and _hosting_networks:
        net = random.choice(_hosting_networks)
        ip = _random_ip_from_cidr(net)
        if is_public(ip):
            return ip

    if roll < 0.65 and top_cidrs:
        cidr_str = random.choice(top_cidrs)
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            ip = _random_ip_from_cidr(net)
            if is_public(ip):
                return ip
        except ValueError:
            pass

    if roll < 0.85:
        with _prefixes_lock:
            if _discovered_prefixes:
                net = random.choice(_discovered_prefixes)
                ip = _random_ip_from_cidr(net)
                if is_public(ip):
                    return ip

    return _random_public_ip()


def get_next_ip() -> str:
    """Pega IP da fila (feeds) ou gera um inteligente."""
    try:
        return ip_queue.get_nowait()
    except queue.Empty:
        return generate_smart_ip()


# ---------------------------------------------------------------------------
# Feed: RIPE Stat — prefixos BGP anunciados (sem chave)
# ---------------------------------------------------------------------------
def _feed_ripe_stat() -> None:
    logger.info("[FEED] RIPE Stat: buscando prefixos de %d ASNs...", len(INTERESTING_ASNS))
    total = 0
    for asn in INTERESTING_ASNS:
        try:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                continue
            prefixes = resp.json().get("data", {}).get("prefixes", [])
            count = 0
            for p in prefixes:
                try:
                    net = ipaddress.ip_network(p.get("prefix", ""), strict=False)
                    if net.version == 4 and 16 <= net.prefixlen <= 24:
                        with _prefixes_lock:
                            _discovered_prefixes.append(net)
                        count += 1
                except ValueError:
                    pass
            total += count
            time.sleep(0.5)
        except Exception:
            pass
    logger.info("[FEED] RIPE Stat: %d prefixos BGP descobertos", total)


# ---------------------------------------------------------------------------
# Feed: DShield / SANS — top attacking IPs (sem chave)
# ---------------------------------------------------------------------------
def _feed_dshield() -> None:
    try:
        resp = requests.get("https://isc.sans.edu/api/topips/records/1000?json", timeout=15)
        if resp.status_code != 200:
            return
        data = resp.json()
        count = 0
        for entry in data:
            ip = entry.get("source", "") if isinstance(entry, dict) else ""
            if ip and is_public(ip):
                try:
                    ip_queue.put_nowait(ip)
                    count += 1
                except queue.Full:
                    break
        _inc_feed("dshield_ips", count)
        logger.info("[FEED] DShield: %d IPs atacantes", count)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Feed: Blocklist.de — IPs abusivos (sem chave)
# ---------------------------------------------------------------------------
def _feed_blocklist() -> None:
    try:
        resp = requests.get("https://lists.blocklist.de/lists/all.txt", timeout=30)
        if resp.status_code != 200:
            return
        count = 0
        for line in resp.text.splitlines():
            ip = line.strip()
            if ip and not ip.startswith("#") and is_public(ip):
                try:
                    ip_queue.put_nowait(ip)
                    count += 1
                except queue.Full:
                    break
        _inc_feed("blocklist_ips", count)
        logger.info("[FEED] Blocklist.de: %d IPs abusivos", count)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Feed: AbuseIPDB (precisa de chave)
# ---------------------------------------------------------------------------
def _feed_abuseipdb() -> None:
    if not ABUSEIPDB_KEY:
        return
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"confidenceMinimum": 50, "limit": 1000},
            timeout=15,
        )
        if resp.status_code != 200:
            return
        data = resp.json().get("data", [])
        count = 0
        for entry in data:
            ip = entry.get("ipAddress", "")
            if ip and is_public(ip):
                try:
                    ip_queue.put_nowait(ip)
                    count += 1
                except queue.Full:
                    break
        _inc_feed("abuseipdb_ips", count)
        logger.info("[FEED] AbuseIPDB: %d IPs reportados", count)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Feed: masscan — SYN scan em massa (precisa de binário + root)
# ---------------------------------------------------------------------------
def _feed_masscan() -> None:
    enabled = MASSCAN_ENABLED.lower()
    if enabled == "false":
        return

    masscan_path = shutil.which("masscan")
    if not masscan_path:
        return

    logger.info("[FEED] masscan ativo (%d pps)", MASSCAN_RATE)
    with _feed_stats_lock:
        _feed_stats["masscan_running"] = True

    while True:
        try:
            block = f"{random.randint(1,223)}.{random.randint(0,255)}.0.0/16"
            cmd = [
                masscan_path, block,
                "-p80,443,22,8080,23,21,3389,8443,25,53",
                f"--rate={MASSCAN_RATE}",
                "--open", "-oL", "/dev/stdout", "--wait", "3",
            ]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
            seen: set[str] = set()
            for line in (proc.stdout or []):
                line = line.strip()
                if line.startswith("open"):
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[3]
                        if ip not in seen and is_public(ip):
                            seen.add(ip)
                            try:
                                ip_queue.put_nowait(ip)
                            except queue.Full:
                                pass
            proc.wait()
            _inc_feed("masscan_ips", len(seen))
            if seen:
                logger.info("[FEED] masscan %s: %d IPs vivos", block, len(seen))
        except Exception:
            time.sleep(30)


# ---------------------------------------------------------------------------
# Feed: AWS IP Ranges (oficial, sem chave)
# ---------------------------------------------------------------------------
def _feed_aws_ranges() -> None:
    try:
        resp = requests.get(
            "https://ip-ranges.amazonaws.com/ip-ranges.json",
            timeout=30,
        )
        if resp.status_code != 200:
            return
        data = resp.json()
        count = 0
        with _cloud_lock:
            _cloud_prefixes["aws"].clear()
            for entry in data.get("prefixes", []):
                prefix = entry.get("ip_prefix", "")
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                    if net.version == 4 and net.prefixlen >= 16:
                        _cloud_prefixes["aws"].append(net)
                        count += 1
                except ValueError:
                    pass
        _inc_feed("aws_prefixes", count)
        logger.info("[FEED] AWS: %d prefixos IPv4", count)
    except Exception as e:
        logger.warning("[FEED] AWS ranges erro: %s", e)


# ---------------------------------------------------------------------------
# Feed: GCP IP Ranges (oficial, sem chave)
# ---------------------------------------------------------------------------
def _feed_gcp_ranges() -> None:
    try:
        resp = requests.get(
            "https://www.gstatic.com/ipranges/cloud.json",
            timeout=30,
        )
        if resp.status_code != 200:
            return
        data = resp.json()
        count = 0
        with _cloud_lock:
            _cloud_prefixes["gcp"].clear()
            for entry in data.get("prefixes", []):
                prefix = entry.get("ipv4Prefix", "")
                if not prefix:
                    continue
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                    if net.version == 4:
                        _cloud_prefixes["gcp"].append(net)
                        count += 1
                except ValueError:
                    pass
        _inc_feed("gcp_prefixes", count)
        logger.info("[FEED] GCP: %d prefixos IPv4", count)
    except Exception as e:
        logger.warning("[FEED] GCP ranges erro: %s", e)


# ---------------------------------------------------------------------------
# Feed: Azure IP Ranges (oficial, sem chave)
# ---------------------------------------------------------------------------
def _feed_azure_ranges() -> None:
    try:
        page = requests.get(
            "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
            timeout=15,
            headers={"User-Agent": "scanner-feeds/1.0"},
        )
        import re
        match = re.search(
            r'https://download\.microsoft\.com/download/[^"]+\.json',
            page.text,
        )
        if not match:
            logger.warning("[FEED] Azure: URL do JSON nao encontrada")
            return
        json_url = match.group(0)
        resp = requests.get(json_url, timeout=60)
        if resp.status_code != 200:
            return
        data = resp.json()
        count = 0
        with _cloud_lock:
            _cloud_prefixes["azure"].clear()
            for value in data.get("values", []):
                props = value.get("properties", {})
                for prefix in props.get("addressPrefixes", []):
                    if ":" in prefix:
                        continue
                    try:
                        net = ipaddress.ip_network(prefix, strict=False)
                        if net.version == 4 and net.prefixlen >= 16:
                            _cloud_prefixes["azure"].append(net)
                            count += 1
                    except ValueError:
                        pass
        _inc_feed("azure_prefixes", count)
        logger.info("[FEED] Azure: %d prefixos IPv4", count)
    except Exception as e:
        logger.warning("[FEED] Azure ranges erro: %s", e)


# ---------------------------------------------------------------------------
# Feed: Cloudflare + Fastly IP ranges (CDN identification)
# ---------------------------------------------------------------------------
def _feed_cdn_ranges() -> None:
    total = 0
    with _cdn_lock:
        _cdn_networks.clear()

    for url in [
        "https://www.cloudflare.com/ips-v4",
        "https://api.fastly.com/public-ip-list",
    ]:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                continue

            if "fastly" in url:
                data = resp.json()
                lines = data.get("addresses", [])
            else:
                lines = resp.text.strip().splitlines()

            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    if net.version == 4:
                        with _cdn_lock:
                            _cdn_networks.append(net)
                        total += 1
                except ValueError:
                    pass
        except Exception as e:
            logger.warning("[FEED] CDN ranges erro (%s): %s", url, e)

    logger.info("[FEED] CDN: %d prefixos (Cloudflare + Fastly)", total)


# ---------------------------------------------------------------------------
# Feed: IPsum — threat intel agregado de 30+ fontes (sem chave)
# ---------------------------------------------------------------------------
def _feed_ipsum() -> None:
    try:
        resp = requests.get(
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
            timeout=30,
        )
        if resp.status_code != 200:
            return
        count = 0
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = line.split("\t")[0].strip()
            if ip and is_public(ip):
                try:
                    ip_queue.put_nowait(ip)
                    count += 1
                except queue.Full:
                    break
        _inc_feed("ipsum_ips", count)
        logger.info("[FEED] IPsum: %d IPs maliciosos (level 3+)", count)
    except Exception as e:
        logger.warning("[FEED] IPsum erro: %s", e)


# ---------------------------------------------------------------------------
# Feed: Feodo Tracker — C2 botnets (Emotet, Dridex, etc.) (sem chave)
# ---------------------------------------------------------------------------
def _feed_feodo() -> None:
    try:
        resp = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            timeout=15,
        )
        if resp.status_code != 200:
            return
        count = 0
        for line in resp.text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            if is_public(ip):
                try:
                    ip_queue.put_nowait(ip)
                    count += 1
                except queue.Full:
                    break
        _inc_feed("feodo_ips", count)
        logger.info("[FEED] Feodo Tracker: %d C2 IPs", count)
    except Exception as e:
        logger.warning("[FEED] Feodo erro: %s", e)


# ---------------------------------------------------------------------------
# Feed: Emerging Threats — IPs comprometidos (sem chave)
# ---------------------------------------------------------------------------
def _feed_emerging_threats() -> None:
    try:
        resp = requests.get(
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            timeout=15,
        )
        if resp.status_code != 200:
            return
        count = 0
        for line in resp.text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            if is_public(ip):
                try:
                    ip_queue.put_nowait(ip)
                    count += 1
                except queue.Full:
                    break
        _inc_feed("et_compromised_ips", count)
        logger.info("[FEED] Emerging Threats: %d IPs comprometidos", count)
    except Exception as e:
        logger.warning("[FEED] Emerging Threats erro: %s", e)


# ---------------------------------------------------------------------------
# Feed: Spamhaus DROP + EDROP — CIDRs hijacked (sem chave)
# ---------------------------------------------------------------------------
def _feed_spamhaus() -> None:
    total = 0
    for url in [
        "https://www.spamhaus.org/drop/drop.txt",
        "https://www.spamhaus.org/drop/edrop.txt",
    ]:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                continue
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                cidr = line.split(";")[0].strip()
                if not cidr:
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if net.version == 4:
                        ip = _random_ip_from_cidr(net)
                        if is_public(ip):
                            try:
                                ip_queue.put_nowait(ip)
                                total += 1
                            except queue.Full:
                                break
                except ValueError:
                    pass
        except Exception as e:
            logger.warning("[FEED] Spamhaus erro (%s): %s", url, e)

    _inc_feed("spamhaus_nets", total)
    if total:
        logger.info("[FEED] Spamhaus DROP/EDROP: %d IPs de redes hijacked", total)


# ---------------------------------------------------------------------------
# Feed: Tor Exit Nodes (sem chave)
# ---------------------------------------------------------------------------
def _feed_tor_exits() -> None:
    try:
        resp = requests.get(
            "https://check.torproject.org/torbulkexitlist",
            timeout=15,
        )
        if resp.status_code != 200:
            return
        count = 0
        for line in resp.text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            if is_public(ip):
                try:
                    ip_queue.put_nowait(ip)
                    count += 1
                except queue.Full:
                    break
        _inc_feed("tor_exits", count)
        logger.info("[FEED] Tor: %d exit nodes", count)
    except Exception as e:
        logger.warning("[FEED] Tor exits erro: %s", e)


# ---------------------------------------------------------------------------
# Feed: Bounty target ASNs — descobre ASNs dos alvos e alimenta a fila
# ---------------------------------------------------------------------------
def _feed_bounty_targets() -> None:
    """Periodically read bounty targets from MongoDB and discover their ASNs.

    Feeds IPs from those ASNs into the queue for prioritized scanning.
    """
    if not BOUNTY_FEED_MODE:
        return

    time.sleep(30)
    logger.info("[FEED] Bounty target ASN feed iniciado")

    while True:
        try:
            from app.database import get_bounty_targets
            tcol = get_bounty_targets()
            target_ips: set[str] = set()
            for t in tcol.find({"alive": True}, {"ips": 1}).limit(200):
                for ip in t.get("ips", []):
                    if is_public(ip):
                        target_ips.add(ip)

            if not target_ips:
                time.sleep(300)
                continue

            sample = random.sample(sorted(target_ips), min(10, len(target_ips)))
            prefixes = discover_org_ip_ranges(sample)
            if prefixes:
                register_bounty_prefixes(prefixes)
                count = 0
                for net in prefixes[:50]:
                    for _ in range(5):
                        ip = _random_ip_from_cidr(net)
                        if is_public(ip):
                            try:
                                ip_queue.put_nowait(ip)
                                count += 1
                            except queue.Full:
                                break
                _inc_feed("bounty_asns_discovered", len(prefixes))
                logger.info("[FEED] Bounty ASN feed: %d IPs enfileirados de %d prefixos",
                            count, len(prefixes))
        except Exception as e:
            logger.error("[FEED] Bounty ASN feed erro: %s", e)

        time.sleep(1800)


def _periodic_feeds() -> None:
    """Refresh all lightweight feeds every 30 minutes."""
    while True:
        time.sleep(1800)
        logger.info("[FEED] Refresh periodico de %d fontes...", 9)
        for fn in [
            _feed_dshield,
            _feed_blocklist,
            _feed_abuseipdb,
            _feed_ipsum,
            _feed_feodo,
            _feed_emerging_threats,
            _feed_spamhaus,
            _feed_tor_exits,
            _feed_cdn_ranges,
        ]:
            try:
                fn()
            except Exception:
                pass


def start_feeds() -> None:
    if os.getenv("FEED_ENABLED", "true").lower() in ("0", "false", "no"):
        logger.info("[FEED] Desativado por FEED_ENABLED=false (evita timeouts sem internet)")
        return
    # One-time feeds (run once at startup)
    startup_feeds = [
        ("ripe-stat", _feed_ripe_stat),
        ("aws-ranges", _feed_aws_ranges),
        ("gcp-ranges", _feed_gcp_ranges),
        ("azure-ranges", _feed_azure_ranges),
        ("cdn-ranges", _feed_cdn_ranges),
    ]

    # IP queue feeds (run once at startup, then periodically)
    queue_feeds = [
        ("dshield", _feed_dshield),
        ("blocklist", _feed_blocklist),
        ("abuseipdb", _feed_abuseipdb),
        ("ipsum", _feed_ipsum),
        ("feodo", _feed_feodo),
        ("emerging-threats", _feed_emerging_threats),
        ("spamhaus", _feed_spamhaus),
        ("tor-exits", _feed_tor_exits),
    ]

    # Long-running feeds (run continuously)
    continuous_feeds = [
        ("masscan", _feed_masscan),
        ("bounty-targets", _feed_bounty_targets),
        ("periodic-refresh", _periodic_feeds),
        ("cidr-score-decay", _decay_cidr_scores),
    ]

    all_feeds = startup_feeds + queue_feeds + continuous_feeds
    for name, func in all_feeds:
        t = threading.Thread(target=func, name=f"feed-{name}", daemon=True)
        t.start()

    logger.info(
        "[FEED] %d fontes ativas | %d CIDRs hosting | bounty_mode=%s | fila max %d\n"
        "       Cloud: AWS+GCP+Azure | CDN: Cloudflare+Fastly\n"
        "       Threat: IPsum+Feodo+ET+Spamhaus+DShield+Blocklist+Tor",
        len(all_feeds), len(_hosting_networks),
        BOUNTY_FEED_MODE, ip_queue.maxsize,
    )
