"""
Geração inteligente de IPs com múltiplas fontes.

Fontes:
  1. CIDR blocks densos (hosting/cloud) — hit rate ~30-50%
  2. RIPE Stat API — prefixos BGP anunciados por ASNs populares
  3. DShield/SANS — top IPs atacando a internet (sem chave)
  4. Blocklist.de — IPs abusivos reportados (sem chave)
  5. AbuseIPDB (opcional, com chave) — IPs reportados
  6. masscan (opcional) — SYN scan em massa alimentando a fila
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
    # DigitalOcean
    "45.55.0.0/16", "46.101.0.0/16", "64.225.0.0/16", "68.183.0.0/16",
    "104.131.0.0/16", "134.209.0.0/16", "137.184.0.0/16", "138.197.0.0/16",
    "139.59.0.0/16", "143.198.0.0/16", "157.245.0.0/16", "159.65.0.0/16",
    "159.89.0.0/16", "161.35.0.0/16", "165.22.0.0/16", "167.71.0.0/16",
    "167.172.0.0/16", "174.138.0.0/16", "178.128.0.0/16",
    # Vultr
    "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "45.77.0.0/16",
    "64.176.0.0/16", "66.42.0.0/16", "78.141.0.0/16", "95.179.0.0/16",
    "108.61.0.0/16", "136.244.0.0/16", "140.82.0.0/16", "149.28.0.0/16",
    "155.138.0.0/16", "207.148.0.0/16",
    # Hetzner
    "5.9.0.0/16", "78.46.0.0/15", "88.99.0.0/16", "88.198.0.0/16",
    "116.202.0.0/16", "116.203.0.0/16", "135.181.0.0/16", "136.243.0.0/16",
    "138.201.0.0/16", "142.132.0.0/16", "144.76.0.0/16", "148.251.0.0/16",
    "159.69.0.0/16", "167.235.0.0/16", "168.119.0.0/16", "176.9.0.0/16",
    "178.63.0.0/16", "195.201.0.0/16",
    # OVH
    "5.39.0.0/16", "5.135.0.0/16", "5.196.0.0/16", "37.59.0.0/16",
    "37.187.0.0/16", "46.105.0.0/16", "51.38.0.0/16", "51.68.0.0/16",
    "51.75.0.0/16", "51.77.0.0/16", "51.79.0.0/16", "51.83.0.0/16",
    "51.89.0.0/16", "51.91.0.0/16", "54.36.0.0/16", "54.37.0.0/16",
    "54.38.0.0/16", "87.98.0.0/16", "91.121.0.0/16", "137.74.0.0/16",
    "145.239.0.0/16", "147.135.0.0/16", "149.56.0.0/16", "158.69.0.0/16",
    "164.132.0.0/16", "176.31.0.0/16", "178.32.0.0/16", "188.165.0.0/16",
    # Linode/Akamai
    "45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16", "50.116.0.0/16",
    "139.162.0.0/16", "172.104.0.0/15", "172.232.0.0/14",
    # AWS (blocos populares)
    "3.80.0.0/12", "13.52.0.0/14", "18.188.0.0/14", "34.192.0.0/12",
    "44.192.0.0/11", "52.0.0.0/11", "54.64.0.0/11",
    # Google Cloud
    "34.64.0.0/11", "35.184.0.0/13",
    # Cloudflare
    "104.16.0.0/13", "172.64.0.0/13",
    # Contabo
    "62.171.128.0/17", "161.97.0.0/16", "167.86.0.0/16", "173.212.192.0/18",
    "178.238.224.0/19", "193.26.156.0/22", "207.180.192.0/18",
    # Scaleway
    "51.15.0.0/16", "51.158.0.0/16", "51.159.0.0/16", "163.172.0.0/16",
    "212.47.224.0/19",
]

_hosting_networks: list[ipaddress.IPv4Network] = []
for _c in HOSTING_CIDRS:
    try:
        _hosting_networks.append(ipaddress.ip_network(_c, strict=False))
    except ValueError:
        pass

# ASNs para descoberta de prefixos via RIPE Stat
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

_feed_stats: dict[str, Any] = {
    "queue_size": 0,
    "hosting_cidrs": len(_hosting_networks),
    "discovered_prefixes": 0,
    "dshield_ips": 0,
    "blocklist_ips": 0,
    "abuseipdb_ips": 0,
    "masscan_ips": 0,
    "masscan_running": False,
}
_feed_stats_lock = threading.Lock()


def get_feed_stats() -> dict[str, Any]:
    with _feed_stats_lock:
        s = dict(_feed_stats)
    s["queue_size"] = ip_queue.qsize()
    with _prefixes_lock:
        s["discovered_prefixes"] = len(_discovered_prefixes)
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


def generate_smart_ip() -> str:
    """
    60% hosting CIDR (alta densidade)
    25% prefixos BGP descobertos
    15% aleatório puro (diversidade)
    """
    roll = random.random()

    if roll < 0.60 and _hosting_networks:
        net = random.choice(_hosting_networks)
        ip = _random_ip_from_cidr(net)
        if is_public(ip):
            return ip

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


def _periodic_feeds() -> None:
    while True:
        time.sleep(1800)
        logger.info("[FEED] Refresh periodico...")
        try:
            _feed_dshield()
        except Exception:
            pass
        try:
            _feed_blocklist()
        except Exception:
            pass
        try:
            _feed_abuseipdb()
        except Exception:
            pass


def start_feeds() -> None:
    feeds = [
        ("ripe-stat", _feed_ripe_stat),
        ("dshield", _feed_dshield),
        ("blocklist", _feed_blocklist),
        ("abuseipdb", _feed_abuseipdb),
        ("masscan", _feed_masscan),
        ("periodic-refresh", _periodic_feeds),
    ]
    for name, func in feeds:
        t = threading.Thread(target=func, name=f"feed-{name}", daemon=True)
        t.start()
    logger.info("[FEED] %d fontes ativas | %d CIDRs hosting | fila max %d", len(feeds), len(_hosting_networks), ip_queue.maxsize)
