"""
Bug Bounty mode: gerenciamento de programas, recon automatizado e scope validation.

Pipeline (17 etapas):
  1. Extract root domains
  2. Subdomain enum: 7 fontes paralelas (subfinder + crt.sh + AlienVault + HackerTarget + RapidDNS + Anubis + Wayback)
  3. Scope filter
  4. DNS resolve + DNS Zone Transfer check
  5. ASN discovery
  6. Reverse DNS
  7. Merge + second scope filter
  8. httpx probe
  9. Security checks (40+ probes: headers, CORS, SSTI, CRLF, Host Header, JWT, S3 Bucket, JS analysis)
  10. HTTP port scanner (opcional)
  11. Wayback Machine URLs + ParamSpider
  12. GitHub Dorking
  13. Change detection
  14. Save to MongoDB
  15. Nuclei auto-queue
"""

import fnmatch
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from bson import ObjectId
import requests

from app.database import get_bounty_programs, get_bounty_targets, get_vuln_results, get_bounty_changes, get_submitted_reports
from app.http_port_scanner_integration import run_http_port_scanner, HTTP_PORT_SCANNER_ENABLED
from app.ip_feeds import (
    discover_asn_for_ip,
    enumerate_asn_prefixes,
    register_bounty_prefixes,
)
from app.advanced_recon import (
    run_advanced_http_checks,
    check_dns_zone_transfer,
    run_github_dorking,
    run_paramspider,
)

logger = logging.getLogger("scanner.bounty")

BOUNTY_MODE = os.getenv("BOUNTY_MODE", "true").lower() in ("1", "true", "yes")
RECON_INTERVAL = int(os.getenv("BOUNTY_RECON_INTERVAL", "21600"))
RECON_WORKERS = int(os.getenv("BOUNTY_RECON_WORKERS", "2"))
SUBFINDER_TIMEOUT = int(os.getenv("SUBFINDER_TIMEOUT", "300"))
HTTPX_TIMEOUT = int(os.getenv("HTTPX_TIMEOUT", "300"))
RECON_HTTP_TIMEOUT = int(os.getenv("RECON_HTTP_TIMEOUT", "8"))
CRTSH_TIMEOUT = int(os.getenv("CRTSH_TIMEOUT", "30"))
KATANA_TIMEOUT = int(os.getenv("KATANA_TIMEOUT", "120"))
KATANA_DEPTH = int(os.getenv("KATANA_DEPTH", "3"))
GAU_TIMEOUT = int(os.getenv("GAU_TIMEOUT", "60"))
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

_recon_stats = {
    "recons_completed": 0,
    "subdomains_found": 0,
    "hosts_alive": 0,
    "errors": 0,
    "crtsh_subdomains": 0,
    "asns_discovered": 0,
    "rdns_subdomains": 0,
    "new_subdomains_detected": 0,
}
_stats_lock = threading.Lock()


def _inc_stat(key: str, n: int = 1) -> None:
    with _stats_lock:
        _recon_stats[key] = _recon_stats.get(key, 0) + n


def get_recon_stats() -> dict[str, Any]:
    with _stats_lock:
        return dict(_recon_stats)


# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------
def is_in_scope(target: str, in_scope: list[str], out_of_scope: list[str]) -> bool:
    """Check if a domain/IP is within the authorized scope."""
    target_lower = target.lower().strip()

    for pattern in out_of_scope:
        pattern = pattern.lower().strip()
        if not pattern:
            continue
        if _match_scope(target_lower, pattern):
            return False

    for pattern in in_scope:
        pattern = pattern.lower().strip()
        if not pattern:
            continue
        if _match_scope(target_lower, pattern):
            return True

    return False


def _match_scope(target: str, pattern: str) -> bool:
    """Match a target against a scope pattern (wildcard domain or CIDR)."""
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(target)
            return addr in net
        except ValueError:
            pass

    if pattern.startswith("*."):
        base = pattern[2:]
        return target == base or target.endswith("." + base)

    return fnmatch.fnmatch(target, pattern) or target == pattern


def _normalize_in_scope_raw(scope: Any) -> list[str]:
    """Ensure in_scope from DB is always a list of strings (never a single string)."""
    if scope is None:
        return []
    if isinstance(scope, str):
        scope = [scope]
    out = []
    for item in scope:
        if isinstance(item, str):
            for line in item.replace("\r", "\n").split("\n"):
                line = line.strip()
                if line:
                    out.append(line)
        elif item is not None:
            out.append(str(item).strip())
    return out


def extract_root_domains(in_scope: list[str]) -> list[str]:
    """Extract root domains from scope patterns for subfinder. Accepts *.domain.com, domain.com, or URLs."""
    roots = set()
    patterns = _normalize_in_scope_raw(in_scope)
    if not patterns:
        return []
    expanded = []
    for item in patterns:
        for part in item.replace(";", "\n").replace(",", "\n").split("\n"):
            part = part.strip()
            if part:
                expanded.append(part)
    patterns = expanded
    for p in patterns:
        p = p.lower().strip()
        if not p or p.startswith("#"):
            continue
        if "//" in p or p.startswith("http"):
            try:
                parsed = urlsplit(p if "//" in p else "https://" + p)
                host = (parsed.netloc or parsed.path or "").split(":")[0]
                if host and "." in host:
                    host = host[4:] if host.startswith("www.") else host
                    roots.add(host)
            except Exception:
                pass
            continue
        if "/" in p:
            continue
        if p.startswith("*."):
            p = p[2:]
        if p.startswith("www."):
            p = p[4:]
        parts = p.split(".")
        if len(parts) >= 2:
            roots.add(p)
    return sorted(roots)


# ---------------------------------------------------------------------------
# Subfinder — subdomain enumeration
# ---------------------------------------------------------------------------
def run_subdomain_enum(domain: str) -> list[str]:
    """Run subfinder to enumerate subdomains for a domain."""
    cmd = [
        "subfinder",
        "-d", domain,
        "-silent",
        "-timeout", str(min(SUBFINDER_TIMEOUT, 600)),
        "-no-color",
    ]

    subdomains = set()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=SUBFINDER_TIMEOUT + 30,
        )
        for line in result.stdout.strip().splitlines():
            sub = line.strip().lower()
            if sub and "." in sub:
                subdomains.add(sub)

        logger.info("[BOUNTY] subfinder %s: %d subdominios", domain, len(subdomains))

    except subprocess.TimeoutExpired:
        logger.warning("[BOUNTY] subfinder timeout para %s", domain)
        _inc_stat("errors")
    except FileNotFoundError:
        logger.error("[BOUNTY] subfinder nao encontrado no PATH")
        _inc_stat("errors")
    except Exception as e:
        logger.error("[BOUNTY] subfinder erro: %s", e)
        _inc_stat("errors")

    return sorted(subdomains)


# ---------------------------------------------------------------------------
# crt.sh — Certificate Transparency subdomain enumeration
# ---------------------------------------------------------------------------
def run_crtsh_enum(domain: str) -> list[str]:
    """Query crt.sh for subdomains via Certificate Transparency logs."""
    subdomains: set[str] = set()
    try:
        url = "https://crt.sh/"
        params = {"q": f"%.{domain}", "output": "json"}
        resp = requests.get(url, params=params, timeout=CRTSH_TIMEOUT)
        if resp.status_code != 200:
            logger.warning("[BOUNTY] crt.sh %s: HTTP %d", domain, resp.status_code)
            return []

        entries = resp.json()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name.startswith("*."):
                    name = name[2:]
                if name and "." in name and not name.startswith("."):
                    subdomains.add(name)

        logger.info("[BOUNTY] crt.sh %s: %d subdominios", domain, len(subdomains))
        _inc_stat("crtsh_subdomains", len(subdomains))

    except requests.RequestException as e:
        logger.warning("[BOUNTY] crt.sh erro para %s: %s", domain, e)
    except (json.JSONDecodeError, ValueError):
        logger.warning("[BOUNTY] crt.sh resposta invalida para %s", domain)

    return sorted(subdomains)


# ---------------------------------------------------------------------------
# Extra subdomain sources (all free, no API key needed)
# ---------------------------------------------------------------------------
def run_alienvault_enum(domain: str) -> list[str]:
    """Query AlienVault OTX for passive DNS subdomains."""
    subs: set[str] = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "scanner/1.0"})
        if resp.status_code != 200:
            return []
        for entry in resp.json().get("passive_dns", []):
            hostname = (entry.get("hostname") or "").strip().lower()
            if hostname and hostname.endswith(f".{domain}") and "." in hostname:
                subs.add(hostname)
        if subs:
            logger.info("[BOUNTY] AlienVault %s: %d subdomínios", domain, len(subs))
    except Exception as e:
        logger.debug("[BOUNTY] AlienVault erro %s: %s", domain, e)
    return sorted(subs)


def run_hackertarget_enum(domain: str) -> list[str]:
    """Query HackerTarget for subdomains (free, no key, 50/day limit)."""
    subs: set[str] = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200 or "error" in resp.text.lower()[:50]:
            return []
        for line in resp.text.strip().splitlines():
            parts = line.split(",")
            if parts:
                hostname = parts[0].strip().lower()
                if hostname and "." in hostname:
                    subs.add(hostname)
        if subs:
            logger.info("[BOUNTY] HackerTarget %s: %d subdomínios", domain, len(subs))
    except Exception as e:
        logger.debug("[BOUNTY] HackerTarget erro %s: %s", domain, e)
    return sorted(subs)


def run_rapiddns_enum(domain: str) -> list[str]:
    """Query RapidDNS for subdomains."""
    subs: set[str] = set()
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return []
        for match in re.finditer(
            r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>',
            resp.text,
        ):
            hostname = match.group(1).strip().lower()
            if hostname and "." in hostname:
                subs.add(hostname)
        if subs:
            logger.info("[BOUNTY] RapidDNS %s: %d subdomínios", domain, len(subs))
    except Exception as e:
        logger.debug("[BOUNTY] RapidDNS erro %s: %s", domain, e)
    return sorted(subs)


def run_anubis_enum(domain: str) -> list[str]:
    """Query Anubis for subdomains."""
    subs: set[str] = set()
    try:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
        if isinstance(data, list):
            for hostname in data:
                hostname = hostname.strip().lower()
                if hostname and "." in hostname:
                    subs.add(hostname)
        if subs:
            logger.info("[BOUNTY] Anubis %s: %d subdomínios", domain, len(subs))
    except Exception as e:
        logger.debug("[BOUNTY] Anubis erro %s: %s", domain, e)
    return sorted(subs)


def run_wayback_subdomains(domain: str) -> list[str]:
    """Extract subdomains from Wayback Machine CDX API."""
    subs: set[str] = set()
    try:
        url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "1000",
        }
        resp = requests.get(url, params=params, timeout=30)
        if resp.status_code != 200:
            return []
        rows = resp.json()
        for row in rows[1:]:
            if not row or not row[0]:
                continue
            try:
                parsed = urlsplit(row[0])
                hostname = (parsed.hostname or "").strip().lower()
                if hostname and hostname.endswith(f".{domain}") and "." in hostname:
                    subs.add(hostname)
            except Exception:
                continue
        if subs:
            logger.info("[BOUNTY] Wayback subs %s: %d subdomínios", domain, len(subs))
    except Exception as e:
        logger.debug("[BOUNTY] Wayback subs erro %s: %s", domain, e)
    return sorted(subs)


def run_all_subdomain_sources(domain: str) -> set[str]:
    """Run all subdomain enumeration sources in parallel and merge results."""
    all_subs: set[str] = set()
    lock = threading.Lock()

    sources = [
        ("subfinder", lambda: run_subdomain_enum(domain)),
        ("crtsh", lambda: run_crtsh_enum(domain)),
        ("alienvault", lambda: run_alienvault_enum(domain)),
        ("hackertarget", lambda: run_hackertarget_enum(domain)),
        ("rapiddns", lambda: run_rapiddns_enum(domain)),
        ("anubis", lambda: run_anubis_enum(domain)),
        ("wayback", lambda: run_wayback_subdomains(domain)),
    ]

    results: dict[str, list[str]] = {}

    def _run(name: str, fn: Any) -> None:
        try:
            res = fn()
            with lock:
                results[name] = res
                all_subs.update(res)
        except Exception:
            pass

    threads = [
        threading.Thread(target=_run, args=(name, fn), daemon=True)
        for name, fn in sources
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    counts = {k: len(v) for k, v in results.items() if v}
    total_unique = len(all_subs)
    logger.info("[BOUNTY] %s → %d únicos | %s",
                domain, total_unique,
                " | ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    return all_subs


# ---------------------------------------------------------------------------
# DNS resolve
# ---------------------------------------------------------------------------
def resolve_dns(subdomains: list[str]) -> dict[str, list[str]]:
    """Resolve subdomains to IP addresses. Returns {subdomain: [ips]}."""
    resolved = {}
    for sub in subdomains:
        try:
            results = socket.getaddrinfo(sub, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = sorted({r[4][0] for r in results})
            if ips:
                resolved[sub] = ips
        except (socket.gaierror, OSError):
            continue
    logger.info("[BOUNTY] DNS resolve: %d/%d resolvidos", len(resolved), len(subdomains))
    return resolved


# ---------------------------------------------------------------------------
# Reverse DNS sweep — descobre subdomínios adicionais a partir dos IPs
# ---------------------------------------------------------------------------
def reverse_dns_sweep(ips: list[str]) -> dict[str, str]:
    """Run reverse DNS on a list of IPs.

    Returns {ip: hostname} for IPs that have PTR records.
    """
    results: dict[str, str] = {}
    for ip in ips:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            hostname = hostname.lower().strip()
            if hostname and "." in hostname:
                results[ip] = hostname
        except (socket.herror, socket.gaierror, OSError):
            continue

    if results:
        logger.info("[BOUNTY] Reverse DNS: %d/%d IPs com PTR", len(results), len(ips))
        _inc_stat("rdns_subdomains", len(results))

    return results


# ---------------------------------------------------------------------------
# ASN discovery for bounty targets
# ---------------------------------------------------------------------------
def discover_target_asns(resolved_ips: list[str]) -> dict[str, Any]:
    """Discover ASNs for bounty target IPs and enumerate their full IP ranges.

    Returns {
        "asns": {asn: {"holder": str, "prefixes": int}},
        "total_prefixes": int,
        "org_ranges": [IPv4Network],
    }
    """
    unique_ips = list(set(resolved_ips))
    sample = unique_ips[:15]

    seen_asns: dict[int, dict[str, Any]] = {}
    all_prefixes: list[ipaddress.IPv4Network] = []

    for ip in sample:
        asn_info = discover_asn_for_ip(ip)
        if not asn_info or not asn_info.get("asn"):
            continue
        asn = asn_info["asn"]
        if asn in seen_asns:
            continue

        prefixes = enumerate_asn_prefixes(asn)
        seen_asns[asn] = {
            "holder": asn_info.get("holder", ""),
            "prefixes": len(prefixes),
        }
        all_prefixes.extend(prefixes)

        logger.info("[BOUNTY] ASN: IP %s → AS%d (%s) → %d prefixos",
                    ip, asn, asn_info.get("holder", "?")[:30], len(prefixes))
        time.sleep(0.5)

    _inc_stat("asns_discovered", len(seen_asns))

    register_bounty_prefixes(all_prefixes)

    return {
        "asns": seen_asns,
        "total_prefixes": len(all_prefixes),
        "org_ranges": all_prefixes,
    }


# ---------------------------------------------------------------------------
# httpx — HTTP probe
# ---------------------------------------------------------------------------
HTTPX_BATCH_SIZE = 200


def _httpx_batch(batch: list[str]) -> list[dict[str, Any]]:
    """Run httpx on a batch of targets."""
    alive = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for t in batch:
            f.write(t + "\n")
        targets_file = f.name

    cmd = [
        "httpx",
        "-l", targets_file,
        "-json",
        "-silent",
        "-timeout", "8",
        "-retries", "0",
        "-no-color",
        "-status-code",
        "-title",
        "-tech-detect",
        "-cdn",
        "-follow-redirects",
        "-threads", "50",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=HTTPX_TIMEOUT,
        )

        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                alive.append({
                    "url": obj.get("url", ""),
                    "host": obj.get("host", obj.get("input", "")),
                    "status_code": obj.get("status_code", obj.get("status-code", 0)),
                    "title": obj.get("title", ""),
                    "tech": obj.get("tech", []) or [],
                    "cdn": obj.get("cdn", False),
                    "content_length": obj.get("content_length", obj.get("content-length", 0)),
                    "webserver": obj.get("webserver", ""),
                    "scheme": obj.get("scheme", ""),
                })
            except json.JSONDecodeError:
                continue
    except subprocess.TimeoutExpired:
        logger.warning("[BOUNTY] httpx batch timeout (%d targets)", len(batch))
    except FileNotFoundError:
        logger.error("[BOUNTY] httpx nao encontrado no PATH")
    except Exception as e:
        logger.error("[BOUNTY] httpx batch erro: %s", e)
    finally:
        try:
            os.unlink(targets_file)
        except OSError:
            pass

    return alive


def run_httpx_probe(targets: list[str]) -> list[dict[str, Any]]:
    """Run httpx in batches to probe which targets are alive."""
    if not targets:
        return []

    all_alive: list[dict[str, Any]] = []
    for i in range(0, len(targets), HTTPX_BATCH_SIZE):
        batch = targets[i:i + HTTPX_BATCH_SIZE]
        batch_alive = _httpx_batch(batch)
        all_alive.extend(batch_alive)
        logger.info("[BOUNTY] httpx batch %d-%d: %d/%d vivos",
                    i + 1, min(i + HTTPX_BATCH_SIZE, len(targets)),
                    len(batch_alive), len(batch))

    logger.info("[BOUNTY] httpx total: %d/%d vivos", len(all_alive), len(targets))
    return all_alive


def _add_recon_finding(result: dict[str, Any], severity: str, code: str, title: str, evidence: str = "") -> None:
    weights = {"high": 25, "medium": 12, "low": 5}
    result["findings"].append({
        "severity": severity,
        "code": code,
        "title": title,
        "evidence": evidence[:200],
    })
    result[severity] += 1
    result["risk_score"] = min(100, result["risk_score"] + weights.get(severity, 0))


def _with_path(url: str, path: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _recon_security_checks(url: str, httpx_data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run lightweight HTTP checks during recon and return findings."""
    result: dict[str, Any] = {
        "checked": False,
        "risk_score": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total_findings": 0,
        "final_url": "",
        "findings": [],
    }
    if not url:
        return result

    headers = {"User-Agent": "ScannerRecon/1.0"}
    try:
        resp = requests.get(url, timeout=RECON_HTTP_TIMEOUT, allow_redirects=True, headers=headers)
    except requests.RequestException as e:
        _add_recon_finding(result, "low", "request_error", "Falha ao validar endpoint HTTP", str(e))
        result["checked"] = True
        result["total_findings"] = len(result["findings"])
        return result

    result["checked"] = True
    result["final_url"] = resp.url
    hdr = {k.lower(): v for k, v in resp.headers.items()}
    body = (resp.text or "")[:2000]

    if resp.url.startswith("http://"):
        _add_recon_finding(result, "medium", "no_https", "Endpoint ativo sem HTTPS", resp.url)

    missing_headers = [
        ("strict-transport-security", "medium", "missing_hsts", "Cabecalho HSTS ausente"),
        ("content-security-policy", "medium", "missing_csp", "Cabecalho CSP ausente"),
        ("x-frame-options", "low", "missing_xfo", "Cabecalho X-Frame-Options ausente"),
        ("x-content-type-options", "low", "missing_xcto", "Cabecalho X-Content-Type-Options ausente"),
        ("referrer-policy", "low", "missing_referrer_policy", "Cabecalho Referrer-Policy ausente"),
    ]
    for header_name, sev, code, title in missing_headers:
        if header_name not in hdr:
            _add_recon_finding(result, sev, code, title)

    acao = hdr.get("access-control-allow-origin", "")
    acac = hdr.get("access-control-allow-credentials", "")
    if "*" in acao and acac.lower() == "true":
        _add_recon_finding(result, "high", "cors_credentials_wildcard", "CORS permissivo com credenciais", f"{acao} + {acac}")

    title = str((httpx_data or {}).get("title", "")).lower()
    exposed_patterns = [
        ("phpmyadmin", "medium", "exposed_phpmyadmin", "Painel phpMyAdmin aparente"),
        ("jenkins", "medium", "exposed_jenkins", "Painel Jenkins aparente"),
        ("grafana", "medium", "exposed_grafana", "Painel Grafana aparente"),
        ("kibana", "medium", "exposed_kibana", "Painel Kibana aparente"),
        ("index of /", "low", "directory_listing", "Possivel listagem de diretorio"),
    ]
    for marker, sev, code, label in exposed_patterns:
        if marker in title or marker in body.lower():
            _add_recon_finding(result, sev, code, label, marker)
            break

    # --- Sensitive file/path probes ---
    sensitive_probes = [
        ("/.git/HEAD", "git_head_exposed", "Repositorio .git exposto",
         "high", lambda s, b: s == 200 and "refs/heads" in b),
        ("/.git/config", "git_config_exposed", "Arquivo .git/config exposto",
         "high", lambda s, b: s == 200 and "[core]" in b),
        ("/.env", "env_file_exposed", "Arquivo .env exposto",
         "high", lambda s, b: s == 200 and ("DB_" in b or "API_" in b or "SECRET" in b or "PASSWORD" in b or "KEY=" in b)),
        ("/.DS_Store", "ds_store_exposed", "Arquivo .DS_Store exposto",
         "medium", lambda s, b: s == 200 and "\x00\x00\x00\x01Bud1" in b),
        ("/server-status", "server_status_exposed", "Apache /server-status acessivel",
         "medium", lambda s, b: s == 200 and ("apache" in b or "server" in b)),
        ("/actuator/health", "actuator_health_exposed", "Spring Actuator health exposto",
         "medium", lambda s, b: s == 200 and '"status"' in b),
        ("/actuator/env", "actuator_env_exposed", "Spring Actuator env exposto (secrets)",
         "high", lambda s, b: s == 200 and '"property"' in b),
        ("/actuator/configprops", "actuator_configprops", "Spring Actuator configprops exposto",
         "high", lambda s, b: s == 200 and '"beans"' in b),
        ("/wp-login.php", "wordpress_login", "Painel WordPress exposto",
         "medium", lambda s, b: s == 200 and "wp-login" in b),
        ("/wp-json/wp/v2/users", "wordpress_users_enum", "WordPress user enumeration",
         "high", lambda s, b: s == 200 and '"slug"' in b and '"name"' in b),
        ("/phpinfo.php", "phpinfo_exposed", "phpinfo() exposto",
         "high", lambda s, b: s == 200 and "php version" in b.lower()),
        ("/debug", "debug_endpoint", "Endpoint /debug acessivel",
         "medium", lambda s, b: s == 200 and len(b) > 100),
        ("/elmah.axd", "elmah_exposed", "ELMAH error log exposto (.NET)",
         "high", lambda s, b: s == 200 and ("elmah" in b.lower() or "error log" in b.lower())),
        ("/swagger-ui.html", "swagger_exposed", "Swagger UI exposto",
         "medium", lambda s, b: s == 200 and "swagger" in b.lower()),
        ("/api/swagger.json", "swagger_json_exposed", "Swagger JSON exposto",
         "medium", lambda s, b: s == 200 and '"paths"' in b),
        ("/graphql", "graphql_exposed", "Endpoint GraphQL exposto",
         "medium", lambda s, b: s in (200, 400) and ("graphql" in b.lower() or '"errors"' in b)),
        ("/.well-known/openid-configuration", "openid_config", "OpenID config exposto",
         "low", lambda s, b: s == 200 and '"issuer"' in b),
        ("/crossdomain.xml", "crossdomain_permissive", "crossdomain.xml permissivo",
         "medium", lambda s, b: s == 200 and 'allow-access-from domain="*"' in b),
        ("/clientaccesspolicy.xml", "clientaccess_permissive", "clientaccesspolicy.xml permissivo",
         "medium", lambda s, b: s == 200 and 'allow-from http-request-headers="*"' in b),
        ("/robots.txt", "robots_interesting", "robots.txt com paths sensiveis",
         "low", lambda s, b: s == 200 and any(kw in b.lower() for kw in ["admin", "secret", "private", "internal", "api/v", "dashboard", "backup"])),
    ]

    for path, code, label, sev, check_fn in sensitive_probes:
        probe_url = _with_path(resp.url, path)
        try:
            p = requests.get(probe_url, timeout=4, allow_redirects=False, headers=headers)
            body_small = (p.text or "")[:500]
            if check_fn(p.status_code, body_small):
                _add_recon_finding(result, sev, code, label, probe_url)
        except requests.RequestException:
            continue

    # --- Subdomain takeover indicators ---
    if resp.status_code in (404, 0):
        takeover_sigs = [
            "There isn't a GitHub Pages site here",
            "herokucdn.com/error-pages",
            "NoSuchBucket",
            "The specified bucket does not exist",
            "Domain is not configured",
            "The feed has been deleted",
            "project not found",
            "Sorry, this shop is currently unavailable",
            "Do you want to register",
            "Help Center Closed",
            "Fastly error: unknown domain",
            "is not a registered InCloud YouTrack",
            "No settings were found for this company",
            "InvalidBucketName",
            "This UserVoice subdomain is currently available",
        ]
        for sig in takeover_sigs:
            if sig.lower() in body.lower():
                _add_recon_finding(result, "high", "subdomain_takeover",
                                   "Possivel subdomain takeover", sig)
                break

    # --- Open redirect probe ---
    redir_url = _with_path(resp.url, "/redirect?url=https://evil.com")
    try:
        rr = requests.get(redir_url, timeout=4, allow_redirects=False, headers=headers)
        loc = rr.headers.get("Location", "")
        if "evil.com" in loc:
            _add_recon_finding(result, "high", "open_redirect",
                               "Open redirect detectado", f"{redir_url} → {loc}")
    except requests.RequestException:
        pass

    # --- CORS reflected origin ---
    try:
        cors_headers = {**headers, "Origin": "https://evil.com"}
        cr = requests.get(resp.url, timeout=4, headers=cors_headers)
        acao_val = cr.headers.get("Access-Control-Allow-Origin", "")
        if "evil.com" in acao_val:
            acac_val = cr.headers.get("Access-Control-Allow-Credentials", "")
            sev = "high" if acac_val.lower() == "true" else "medium"
            _add_recon_finding(result, sev, "cors_reflected_origin",
                               "CORS reflete origin arbitrario",
                               f"Origin evil.com → ACAO={acao_val} ACAC={acac_val}")
    except requests.RequestException:
        pass

    # --- TRACE method ---
    try:
        opt = requests.options(resp.url, timeout=4, allow_redirects=False, headers=headers)
        allow_hdr = str(opt.headers.get("Allow", ""))
        if "TRACE" in allow_hdr.upper():
            _add_recon_finding(result, "medium", "trace_enabled",
                               "Metodo TRACE habilitado", allow_hdr)
    except requests.RequestException:
        pass

    # --- JS files: extract secrets and internal URLs ---
    js_secrets = _extract_js_secrets(resp.url, body, headers)
    for secret in js_secrets:
        _add_recon_finding(result, secret["severity"], secret["code"],
                           secret["title"], secret["evidence"])

    # --- Advanced checks: SSTI, CRLF, Host Header, JWT, S3 Bucket ---
    try:
        domain = (urlsplit(resp.url).hostname or "").lower()
        adv_findings = run_advanced_http_checks(resp.url, domain, resp, headers)
        for f in adv_findings:
            _add_recon_finding(result, f["severity"], f["code"], f["title"], f.get("evidence", ""))
    except Exception:
        pass

    result["total_findings"] = len(result["findings"])
    return result


def _extract_js_secrets(base_url: str, html: str, headers: dict) -> list[dict[str, str]]:
    """Extract secrets and interesting patterns from linked JS files."""
    findings: list[dict[str, str]] = []

    js_urls: set[str] = set()
    for match in re.finditer(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html):
        src = match.group(1)
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = _with_path(base_url, src)
        elif not src.startswith("http"):
            continue
        js_urls.add(src)

    secret_patterns = [
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
         "high", "js_api_key", "API key exposta em JS"),
        (r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
         "high", "js_secret_token", "Secret/token exposto em JS"),
        (r'(?:aws_access_key_id|AKIA)\s*[:=]?\s*["\']?(AKIA[A-Z0-9]{16})',
         "high", "js_aws_key", "AWS Access Key exposta em JS"),
        (r'(?:firebase|supabase|mongodb\+srv)://[^\s"\'<]{10,}',
         "high", "js_db_url", "URL de banco exposta em JS"),
        (r'(?:https?://[a-z0-9.-]+/(?:api/v[0-9]|internal|admin|private)[^\s"\'<]*)',
         "medium", "js_internal_url", "URL interna/API encontrada em JS"),
    ]

    for js_url in list(js_urls)[:5]:
        try:
            jr = requests.get(js_url, timeout=5, headers=headers)
            if jr.status_code != 200 or len(jr.text) > 2_000_000:
                continue
            js_body = jr.text[:500_000]
            for pattern, sev, code, title in secret_patterns:
                for m in re.finditer(pattern, js_body, re.IGNORECASE):
                    evidence = f"{js_url} → {m.group(0)[:100]}"
                    if not any(f["evidence"] == evidence for f in findings):
                        findings.append({
                            "severity": sev,
                            "code": code,
                            "title": title,
                            "evidence": evidence,
                        })
                    break
        except requests.RequestException:
            continue

    return findings[:10]


# ---------------------------------------------------------------------------
# Wayback Machine — URLs históricas para descobrir endpoints esquecidos
# ---------------------------------------------------------------------------
def run_wayback_enum(domain: str) -> list[str]:
    """Query Wayback Machine CDX API for historical URLs of a domain."""
    urls: set[str] = set()
    try:
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "500",
            "filter": "statuscode:200",
        }
        resp = requests.get(cdx_url, params=params, timeout=30)
        if resp.status_code != 200:
            return []
        rows = resp.json()
        for row in rows[1:]:
            if row and row[0]:
                url = row[0]
                if any(ext in url.lower() for ext in [
                    ".js", ".json", ".xml", ".conf", ".env", ".bak",
                    ".sql", ".log", ".yml", ".yaml", ".toml", ".php",
                    "/api/", "/admin", "/debug", "/internal", "/config",
                    "/backup", "/secret", "/private", "/swagger",
                ]):
                    urls.add(url)
        logger.info("[BOUNTY] Wayback %s: %d URLs interessantes", domain, len(urls))
    except Exception as e:
        logger.warning("[BOUNTY] Wayback erro para %s: %s", domain, e)
    return sorted(urls)[:100]


# ---------------------------------------------------------------------------
# Auto-queue bounty targets for Nuclei scan
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Katana — web crawler for endpoint discovery
# ---------------------------------------------------------------------------

def run_katana_crawl(urls: list[str], max_urls: int = 200) -> list[str]:
    """Crawl alive hosts with katana to discover endpoints, JS files, forms."""
    if not urls:
        return []
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            input_file = f.name

        cmd = [
            "katana", "-list", input_file,
            "-depth", str(KATANA_DEPTH),
            "-concurrency", "10",
            "-parallelism", "5",
            "-timeout", str(KATANA_TIMEOUT),
            "-silent",
            "-no-color",
            "-jc",
            "-kf", "all",
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=KATANA_TIMEOUT + 30)
        found = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        os.unlink(input_file)
        return found[:max_urls]
    except FileNotFoundError:
        logger.debug("[RECON] katana not installed, skipping")
        return []
    except Exception as e:
        logger.warning("[RECON] katana error: %s", e)
        return []


# ---------------------------------------------------------------------------
# GAU — GetAllUrls from multiple sources
# ---------------------------------------------------------------------------

def run_gau(domain: str, max_urls: int = 300) -> list[str]:
    """Fetch known URLs for a domain from Wayback, Common Crawl, OTX."""
    try:
        cmd = ["gau", "--threads", "3", "--timeout", str(GAU_TIMEOUT), "--subs", domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=GAU_TIMEOUT + 15)
        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        interesting = [u for u in urls if any(ext in u for ext in
            [".js", ".json", ".xml", ".php", ".asp", ".jsp", ".env", ".config",
             "api/", "admin", "login", "token", "key", "secret", "debug",
             "graphql", "swagger", "?", "="])]
        return interesting[:max_urls]
    except FileNotFoundError:
        logger.debug("[RECON] gau not installed, skipping")
        return []
    except Exception as e:
        logger.warning("[RECON] gau error for %s: %s", domain, e)
        return []


# ---------------------------------------------------------------------------
# JS Secret Extraction (Python-based, no external tool needed)
# ---------------------------------------------------------------------------

_JS_SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API Key"),
    (r'(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', "Access Token"),
    (r'(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']([A-Z0-9]{20})["\']', "AWS Access Key"),
    (r'(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', "AWS Secret Key"),
    (r'(?:slack[_-]?(?:token|webhook))\s*[:=]\s*["\']([a-zA-Z0-9\-_/]{20,})["\']', "Slack Token"),
    (r'(?:firebase|google)[_-]?(?:api[_-]?key)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{30,})["\']', "Google/Firebase Key"),
    (r'(?:stripe[_-]?(?:sk|pk|key))\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Stripe Key"),
    (r'(?:gh[pousr]_[a-zA-Z0-9]{36,})', "GitHub Token"),
    (r'(?:-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)', "Private Key"),
    (r'(?:mongodb(?:\+srv)?://[^\s"\']+)', "MongoDB URI"),
    (r'(?:postgres(?:ql)?://[^\s"\']+)', "PostgreSQL URI"),
    (r'(?:mysql://[^\s"\']+)', "MySQL URI"),
    (r'(?:redis://[^\s"\']+)', "Redis URI"),
]


def extract_js_secrets_from_urls(urls: list[str], max_check: int = 30) -> list[dict]:
    """Download JS files and extract secrets/sensitive data."""
    js_urls = [u for u in urls if ".js" in u and not any(x in u for x in [".json", "jquery", "bootstrap", "react.", "vue.", "angular."])][:max_check]
    findings = []
    for url in js_urls:
        try:
            resp = requests.get(url, timeout=8, headers={"User-Agent": "ScannerRecon/1.0"})
            if resp.status_code != 200 or len(resp.text) < 50:
                continue
            body = resp.text[:50000]
            for pattern, label in _JS_SECRET_PATTERNS:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for match in matches[:3]:
                    val = match if isinstance(match, str) else match[0] if match else ""
                    if len(val) > 8:
                        findings.append({
                            "severity": "high",
                            "code": "js_secret_leak",
                            "title": f"{label} exposed in JS",
                            "evidence": f"{url} → {val[:30]}...",
                        })
        except Exception:
            continue
    return findings


# ---------------------------------------------------------------------------
# Telegram notifications
# ---------------------------------------------------------------------------

def send_telegram_alert(message: str) -> bool:
    """Send alert via Telegram bot."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }, timeout=10)
        return True
    except Exception as e:
        logger.warning("[TELEGRAM] send error: %s", e)
        return False


def notify_findings(program_name: str, domain: str, findings: list[dict], h1_url: str = "") -> None:
    """Send Telegram alert for critical/high findings."""
    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    if not critical and not high:
        return

    lines = [f"🚨 *{program_name}* — `{domain}`"]
    if critical:
        lines.append(f"🔴 *{len(critical)} CRITICAL*")
        for f in critical[:3]:
            lines.append(f"  • {f.get('title', '?')}")
    if high:
        lines.append(f"🟠 *{len(high)} HIGH*")
        for f in high[:3]:
            lines.append(f"  • {f.get('title', '?')}")
    total = len(findings)
    lines.append(f"📊 Total: {total} findings")
    if h1_url:
        lines.append(f"🔗 [HackerOne]({h1_url})")
    send_telegram_alert("\n".join(lines))


def _auto_queue_bounty_targets_for_nuclei() -> int:
    """Enqueue alive bounty targets with findings for Nuclei/Nmap scan."""
    try:
        from app.vuln_scanner import enqueue_bounty_target
    except ImportError:
        return 0

    targets_col = get_bounty_targets()
    queued = 0
    for t in targets_col.find(
        {"alive": True, "recon_checks.risk_score": {"$gte": 25}},
        {"domain": 1, "ips": 1, "httpx": 1},
    ).limit(50):
        domain = t.get("domain", "")
        ips = t.get("ips", [])
        httpx_data = t.get("httpx", {})
        if enqueue_bounty_target(domain, ips, httpx_data):
            queued += 1

    if queued:
        logger.info("[BOUNTY] Auto-queued %d bounty targets para Nuclei", queued)
    return queued


# ---------------------------------------------------------------------------
# Change detection — detecta novos subdomínios entre runs de recon
# ---------------------------------------------------------------------------
def _detect_and_save_changes(
    program_id: ObjectId,
    program_name: str,
    current_subdomains: set[str],
    previous_subdomains: set[str],
) -> dict[str, Any]:
    """Compare current vs previous subdomains and save changes to MongoDB."""
    new_subs = sorted(current_subdomains - previous_subdomains)
    removed_subs = sorted(previous_subdomains - current_subdomains)

    changes: dict[str, Any] = {
        "new_subdomains": new_subs,
        "removed_subdomains": removed_subs,
        "total_new": len(new_subs),
        "total_removed": len(removed_subs),
    }

    if not new_subs and not removed_subs:
        return changes

    _inc_stat("new_subdomains_detected", len(new_subs))

    changes_col = get_bounty_changes()
    changes_col.insert_one({
        "program_id": program_id,
        "program_name": program_name,
        "timestamp": datetime.utcnow(),
        "new_subdomains": new_subs,
        "removed_subdomains": removed_subs,
        "total_current": len(current_subdomains),
        "total_previous": len(previous_subdomains),
    })

    if new_subs:
        logger.info("[RECON] NOVOS subdomínios detectados (%d): %s",
                    len(new_subs), ", ".join(new_subs[:10]))
    if removed_subs:
        logger.info("[RECON] Subdomínios removidos (%d): %s",
                    len(removed_subs), ", ".join(removed_subs[:10]))

    return changes


# ---------------------------------------------------------------------------
# Recon pipeline (expanded)
# ---------------------------------------------------------------------------
def recon_pipeline(program_id: str) -> dict[str, Any]:
    """Full recon pipeline for a bounty program. Returns summary stats."""
    programs_col = get_bounty_programs()
    targets_col = get_bounty_targets()

    try:
        oid = ObjectId(program_id)
    except Exception:
        return {"error": "invalid program_id"}

    program = programs_col.find_one({"_id": oid})
    if not program:
        return {"error": "program not found"}

    in_scope = _normalize_in_scope_raw(program.get("in_scope", []))
    out_of_scope = _normalize_in_scope_raw(program.get("out_of_scope", []))
    root_domains = extract_root_domains(in_scope)

    if not root_domains:
        program_url = (program.get("url") or "").strip()
        host = ""
        if program_url:
            try:
                parsed = urlsplit(program_url if "://" in program_url else "https://" + program_url)
                host = (parsed.hostname or parsed.netloc or "").lower().strip()
                host = host[4:] if host.startswith("www.") else host
            except Exception:
                host = ""
        if host and "." in host and not host.endswith("hackerone.com"):
            root_domains = [host]
            in_scope = [host, f"*.{host}"]
        else:
            hint = str(in_scope)[:200] if in_scope else "vazio"
            err_msg = (
                f"Nenhum dominio no escopo (recebido: {hint}). "
                "Use *.dominio.com, dominio.com ou URL (ex: https://alvo.com)."
            )
            programs_col.update_one({"_id": oid}, {"$set": {
                "status": "error",
                "last_recon_error": err_msg,
                "last_recon": datetime.utcnow(),
            }})
            return {"error": "no domains in scope"}

    start_now = datetime.utcnow()
    claim = programs_col.update_one(
        {"_id": oid, "status": {"$ne": "reconning"}},
        {
            "$set": {
                "status": "reconning",
                "last_recon_start": start_now,
            },
            "$unset": {"last_recon_error": ""},
        },
    )
    if claim.modified_count == 0:
        return {"status": "already_running", "program_id": program_id}

    prog_name = program.get("name", "?")
    logger.info("[RECON] ========== INICIO '%s' ==========", prog_name)
    logger.info("[RECON] [1/15] Escopo: dominios=%s | in_scope=%s | out_of_scope=%s",
                root_domains, in_scope[:5], out_of_scope[:5])

    # Load previous subdomains for change detection
    previous_subdomains: set[str] = set()
    for t in targets_col.find({"program_id": oid}, {"domain": 1}):
        previous_subdomains.add(t["domain"])

    try:
        # --- Etapa 2: Subdomain enumeration (7 sources in parallel) ---
        logger.info("[RECON] [2/15] Subdomain enum: 7 fontes para %d dominio(s)...", len(root_domains))
        t0 = time.time()
        all_subdomains: set[str] = set()
        for domain in root_domains:
            subs = run_all_subdomain_sources(domain)
            all_subdomains.update(subs)
            all_subdomains.add(domain)
        logger.info("[RECON] [2/15] Enum completa: %d subdominios unicos em %.1fs",
                     len(all_subdomains), time.time() - t0)

        # --- Etapa 3: Scope filter ---
        scoped = [s for s in all_subdomains if is_in_scope(s, in_scope, out_of_scope)]
        removed = len(all_subdomains) - len(scoped)
        logger.info("[RECON] [3/15] Filtro escopo: %d em escopo, %d removidos (out-of-scope)",
                     len(scoped), removed)

        # --- Etapa 4: DNS resolve + Zone Transfer ---
        logger.info("[RECON] [4/15] DNS: resolvendo %d subdominios...", len(scoped))
        t0 = time.time()
        dns_map = resolve_dns(scoped)
        resolved_hosts = list(dns_map.keys())
        all_resolved_ips = []
        for ips in dns_map.values():
            all_resolved_ips.extend(ips)
        unique_ips = list(set(all_resolved_ips))
        logger.info("[RECON] [4/15] DNS completo: %d/%d resolvidos (%d IPs unicos) em %.1fs",
                     len(resolved_hosts), len(scoped), len(unique_ips), time.time() - t0)

        # DNS Zone Transfer check on root domains
        zone_transfer_findings: list[dict] = []
        for domain in root_domains:
            try:
                zt = check_dns_zone_transfer(domain)
                zone_transfer_findings.extend(zt)
            except Exception:
                pass
        if zone_transfer_findings:
            logger.info("[RECON]        Zone Transfer: %d achados!", len(zone_transfer_findings))

        # --- Etapa 5: ASN discovery ---
        logger.info("[RECON] [5/15] ASN discovery: analisando %d IPs...", len(unique_ips))
        t0 = time.time()
        asn_result = discover_target_asns(unique_ips)
        asn_count = len(asn_result.get("asns", {}))
        prefix_count = asn_result.get("total_prefixes", 0)
        logger.info("[RECON] [5/15] ASN completo: %d ASNs, %d prefixos em %.1fs",
                     asn_count, prefix_count, time.time() - t0)

        # --- Etapa 6: Reverse DNS sweep ---
        logger.info("[RECON] [6/15] Reverse DNS: %d IPs...", len(unique_ips))
        t0 = time.time()
        rdns_results = reverse_dns_sweep(unique_ips)
        rdns_new_subs: set[str] = set()
        for ip, hostname in rdns_results.items():
            if hostname not in all_subdomains and is_in_scope(hostname, in_scope, out_of_scope):
                rdns_new_subs.add(hostname)
        logger.info("[RECON] [6/15] Reverse DNS: %d PTRs, %d novos em escopo em %.1fs",
                     len(rdns_results), len(rdns_new_subs), time.time() - t0)

        # --- Etapa 7: Second scope filter + merge reverse DNS discoveries ---
        if rdns_new_subs:
            logger.info("[RECON] [7/15] Merge: adicionando %d subdomínios do reverse DNS", len(rdns_new_subs))
            rdns_dns = resolve_dns(sorted(rdns_new_subs))
            dns_map.update(rdns_dns)
            scoped = list(set(scoped) | rdns_new_subs)
            all_subdomains.update(rdns_new_subs)
            resolved_hosts = list(dns_map.keys())
        else:
            logger.info("[RECON] [7/15] Merge: nenhum subdomínio novo do reverse DNS")

        # --- Etapa 8: httpx probe ---
        logger.info("[RECON] [8/15] httpx: verificando %d hosts vivos...", len(resolved_hosts))
        t0 = time.time()
        alive_results = run_httpx_probe(resolved_hosts)
        alive_hosts = {a["host"] for a in alive_results}
        httpx_by_host = {a.get("host", ""): a for a in alive_results if a.get("host")}
        logger.info("[RECON] [8/15] httpx completo: %d/%d vivos em %.1fs",
                     len(alive_hosts), len(resolved_hosts), time.time() - t0)

        # --- Etapa 9: Security checks ---
        logger.info("[RECON] [9/15] Security checks: analisando %d hosts vivos...", len(httpx_by_host))
        t0 = time.time()
        recon_checks_by_host = {}
        for i, (host, data) in enumerate(httpx_by_host.items(), 1):
            recon_checks_by_host[host] = _recon_security_checks(data.get("url", ""), data)
            findings = recon_checks_by_host[host].get("total_findings", 0)
            high = recon_checks_by_host[host].get("high", 0)
            if findings > 0:
                logger.info("[RECON]        [%d/%d] %s → %d achados (high=%d)",
                            i, len(httpx_by_host), host, findings, high)
        total_findings = sum(v.get("total_findings", 0) for v in recon_checks_by_host.values())
        total_high = sum(v.get("high", 0) for v in recon_checks_by_host.values())
        logger.info("[RECON] [9/15] Security checks completo: %d achados (%d HIGH) em %.1fs",
                     total_findings, total_high, time.time() - t0)

        # --- Etapa 10: HTTP Port Scanner (opcional) ---
        http_scanner_by_host: dict[str, Any] = {}
        if HTTP_PORT_SCANNER_ENABLED and alive_hosts:
            logger.info("[RECON] [10/15] HTTP Port Scanner: %d hosts...", len(alive_hosts))
            t0 = time.time()
            for host in sorted(alive_hosts):
                try:
                    extra = run_http_port_scanner(host)
                except Exception as e:
                    logger.error("[RECON]        Port Scanner falhou em %s: %s", host, e)
                    extra = []
                if extra:
                    http_scanner_by_host[host] = extra
            logger.info("[RECON] [10/15] Port Scanner completo: %d hosts com portas extras em %.1fs",
                         len(http_scanner_by_host), time.time() - t0)
        else:
            logger.info("[RECON] [10/15] HTTP Port Scanner: desabilitado ou sem hosts")

        # --- Etapa 11: Wayback Machine + ParamSpider ---
        logger.info("[RECON] [11/15] Wayback + ParamSpider: buscando URLs e parametros...")
        t0 = time.time()
        wayback_urls: dict[str, list[str]] = {}
        paramspider_data: dict[str, dict] = {}
        for domain in root_domains[:3]:
            wb = run_wayback_enum(domain)
            if wb:
                wayback_urls[domain] = wb
            try:
                ps = run_paramspider(domain)
                if ps.get("params"):
                    paramspider_data[domain] = ps
            except Exception:
                pass
        total_wb = sum(len(v) for v in wayback_urls.values())
        total_params = sum(len(v.get("params", [])) for v in paramspider_data.values())
        logger.info("[RECON] [11/15] Wayback: %d URLs | ParamSpider: %d params em %.1fs",
                     total_wb, total_params, time.time() - t0)

        # --- Etapa 12: GitHub Dorking ---
        github_findings: list[dict] = []
        if os.getenv("GITHUB_TOKEN", "").strip():
            logger.info("[RECON] [12/15] GitHub Dorking: buscando secrets vazados...")
            t0 = time.time()
            for domain in root_domains[:2]:
                try:
                    gf = run_github_dorking(domain)
                    github_findings.extend(gf)
                except Exception:
                    pass
            logger.info("[RECON] [12/15] GitHub Dorking: %d achados em %.1fs",
                         len(github_findings), time.time() - t0)
        else:
            logger.info("[RECON] [12/15] GitHub Dorking: desabilitado (sem GITHUB_TOKEN)")

        # --- Etapa 12b: Katana crawl on alive hosts ---
        katana_urls: list[str] = []
        if alive_hosts:
            logger.info("[RECON] [12b/18] Katana crawl: %d alive hosts...", len(alive_hosts))
            t0 = time.time()
            crawl_targets = []
            for host in sorted(alive_hosts)[:20]:
                hd = httpx_by_host.get(host)
                if hd and hd.get("url"):
                    crawl_targets.append(hd["url"])
                else:
                    crawl_targets.append(f"https://{host}")
            katana_urls = run_katana_crawl(crawl_targets)
            logger.info("[RECON] [12b/18] Katana: %d endpoints descobertos em %.1fs",
                         len(katana_urls), time.time() - t0)

        # --- Etapa 12c: GAU — GetAllUrls ---
        gau_urls: list[str] = []
        logger.info("[RECON] [12c/18] GAU: buscando URLs conhecidas...")
        t0 = time.time()
        for domain in root_domains[:3]:
            gau_result = run_gau(domain)
            gau_urls.extend(gau_result)
        logger.info("[RECON] [12c/18] GAU: %d URLs interessantes em %.1fs",
                     len(gau_urls), time.time() - t0)

        # --- Etapa 12d: JS Secret Extraction ---
        all_discovered_urls = katana_urls + gau_urls
        js_secrets: list[dict] = []
        if all_discovered_urls:
            logger.info("[RECON] [12d/18] JS Secrets: analisando %d URLs...", len(all_discovered_urls))
            t0 = time.time()
            js_secrets = extract_js_secrets_from_urls(all_discovered_urls)
            logger.info("[RECON] [12d/18] JS Secrets: %d leaks encontrados em %.1fs",
                         len(js_secrets), time.time() - t0)

        # --- Etapa 13: Change detection ---
        logger.info("[RECON] [13/18] Change detection...")
        changes = _detect_and_save_changes(oid, prog_name, set(scoped), previous_subdomains)

        # --- Etapa 14: Save to MongoDB ---
        logger.info("[RECON] [14/15] Salvando %d targets no MongoDB...", len(scoped))
        t0 = time.time()
        now = datetime.utcnow()
        saved = 0
        for sub in scoped:
            ips = dns_map.get(sub, [])
            is_alive = sub in alive_hosts
            httpx_data = httpx_by_host.get(sub)
            recon_checks = recon_checks_by_host.get(sub, {"checked": False, "total_findings": 0, "findings": []})
            http_scanner = http_scanner_by_host.get(sub, [])
            is_new = sub in changes.get("new_subdomains", [])

            # Inject zone transfer + github + JS secret findings into recon_checks
            extra_findings = list(zone_transfer_findings) + list(github_findings) + list(js_secrets)
            if extra_findings and is_alive:
                if not isinstance(recon_checks.get("findings"), list):
                    recon_checks["findings"] = []
                for ef in extra_findings:
                    recon_checks["findings"].append(ef)
                    recon_checks["total_findings"] = len(recon_checks["findings"])
                    sev = ef.get("severity", "low")
                    recon_checks[sev] = recon_checks.get(sev, 0) + 1
                    weights = {"high": 25, "medium": 12, "low": 5}
                    recon_checks["risk_score"] = min(100, recon_checks.get("risk_score", 0) + weights.get(sev, 0))

            wb_for_sub = []
            for d, urls in wayback_urls.items():
                if sub.endswith(d) or sub == d:
                    wb_for_sub = urls
                    break

            ps_for_sub: dict = {}
            for d, ps in paramspider_data.items():
                if sub.endswith(d) or sub == d:
                    ps_for_sub = ps
                    break

            # Katana + GAU URLs for this subdomain
            crawled_for_sub = [u for u in katana_urls + gau_urls if sub in u][:30]

            targets_col.update_one(
                {"program_id": oid, "domain": sub},
                {
                    "$set": {
                        "program_id": oid,
                        "domain": sub,
                        "ips": ips,
                        "alive": is_alive,
                        "status": "probed" if is_alive else "resolved" if ips else "discovered",
                        "httpx": httpx_data or {},
                        "recon_checks": recon_checks,
                        "http_scanner": http_scanner,
                        "wayback_urls": wb_for_sub[:20],
                        "crawled_urls": crawled_for_sub,
                        "paramspider": ps_for_sub,
                        "is_new": is_new,
                        "last_recon": now,
                    }
                },
                upsert=True,
            )
            saved += 1
        logger.info("[RECON] [14/15] MongoDB: %d targets salvos em %.1fs", saved, time.time() - t0)

        # --- Etapa 15: Auto-queue alive targets for Nuclei ---
        logger.info("[RECON] [15/15] Nuclei auto-queue...")
        nuclei_queued = _auto_queue_bounty_targets_for_nuclei()
        logger.info("[RECON] [15/15] %d targets enfileirados para Nuclei", nuclei_queued)

        # --- Etapa 16: Auto-submit eligible to HackerOne ---
        h1_submitted = []
        if AUTO_SUBMIT_H1 and "hackerone.com" in (program.get("url") or ""):
            logger.info("[RECON] [16/16] Auto-submit H1...")
            try:
                h1_submitted = auto_submit_eligible_targets(program_id)
                logger.info("[RECON] [16/16] %d reports submetidos ao HackerOne", len(h1_submitted))
            except Exception as e:
                logger.warning("[RECON] [16/16] Auto-submit erro: %s", e)

        # --- Etapa 17: Telegram notifications ---
        if TELEGRAM_BOT_TOKEN:
            for sub in scoped:
                if sub not in alive_hosts:
                    continue
                rc = recon_checks_by_host.get(sub, {})
                findings = rc.get("findings", [])
                if findings:
                    notify_findings(prog_name, sub, findings, program.get("url", ""))

        _inc_stat("subdomains_found", len(scoped))
        _inc_stat("hosts_alive", len(alive_hosts))
        _inc_stat("recons_completed")

        first_recon = program.get("first_recon_at")
        if not first_recon:
            first_recon = program.get("last_recon") or start_now

        programs_col.update_one({"_id": oid}, {"$set": {
            "status": "active",
            "last_recon": now,
            "first_recon_at": first_recon,
            "stats": {
                "subdomains": len(scoped),
                "resolved": len(resolved_hosts),
                "alive": len(alive_hosts),
                "asns_discovered": asn_count,
                "org_prefixes": prefix_count,
                "new_subdomains": changes.get("total_new", 0),
            },
        }})

        elapsed = (datetime.utcnow() - start_now).total_seconds()
        summary = {
            "program": prog_name,
            "root_domains": root_domains,
            "subdomains_found": len(scoped),
            "dns_resolved": len(resolved_hosts),
            "alive_hosts": len(alive_hosts),
            "targets_saved": saved,
            "recon_findings": total_findings,
            "risky_targets": sum(1 for v in recon_checks_by_host.values() if v.get("high", 0) > 0),
            "asns_discovered": asn_count,
            "org_prefixes": prefix_count,
            "crtsh_exclusive": sum(1 for s in scoped if s not in previous_subdomains),
            "rdns_discoveries": len(rdns_new_subs),
            "wayback_urls": total_wb,
            "nuclei_queued": nuclei_queued,
            "katana_urls": len(katana_urls),
            "gau_urls": len(gau_urls),
            "js_secrets": len(js_secrets),
            "h1_submitted": len(h1_submitted),
            "new_subdomains": changes.get("total_new", 0),
            "removed_subdomains": changes.get("total_removed", 0),
        }
        logger.info("[RECON] ========== FIM '%s' em %.1fs ==========", prog_name, elapsed)
        logger.info("[RECON] Resumo: subs=%d | DNS=%d | vivos=%d | achados=%d (HIGH=%d) | ASNs=%d | novos=%d | wayback=%d | nuclei=%d | salvos=%d",
                     len(scoped), len(resolved_hosts), len(alive_hosts), total_findings, total_high,
                     asn_count, changes.get("total_new", 0), total_wb, nuclei_queued, saved)
        return summary
    except Exception as e:
        _inc_stat("errors")
        programs_col.update_one({"_id": oid}, {"$set": {
            "status": "error",
            "last_recon_error": str(e)[:500],
            "last_recon": datetime.utcnow(),
        }})
        logger.error("[BOUNTY] Recon falhou em '%s': %s", program.get("name", "?"), e)
        raise


# ---------------------------------------------------------------------------
# Auto-submit eligible targets to HackerOne
# ---------------------------------------------------------------------------

AUTO_SUBMIT_H1 = os.getenv("AUTO_SUBMIT_H1", "true").lower() in ("1", "true", "yes")


def _build_h1_report_body(program: dict, target: dict) -> dict:
    """Build a HackerOne report payload from a target with findings."""
    findings = target.get("recon_checks", {}).get("findings", [])
    domain = target.get("domain", "?")
    url = (target.get("httpx") or {}).get("url") or f"https://{domain}"
    ips = ", ".join(target.get("ips", [])) or "-"

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    severity = "medium"
    for f in findings:
        s = (f.get("severity") or "").lower()
        if s and sev_order.get(s, 99) < sev_order.get(severity, 99):
            severity = s

    first = findings[0] if findings else None
    title = f"{first['title']} on {domain}" if first else f"Security findings on {domain}"

    desc_parts = [
        f"During reconnaissance of program **{program.get('name', '?')}**, the asset `{domain}` ({url}) was analyzed.",
        f"The following {len(findings)} issue(s) were identified:",
        "",
    ]
    for f in findings:
        desc_parts.append(f"- **[{(f.get('severity','').upper())}]** {f.get('title','?')}")
        if f.get("evidence"):
            desc_parts.append(f"  Evidence: `{f['evidence']}`")
    desc_parts += ["", "## Asset", f"- Domain: {domain}", f"- IPs: {ips}", f"- URL: {url}",
                   f"- HTTP Status: {(target.get('httpx') or {}).get('status_code', '-')}"]

    steps = [f"1. Navigate to {url}"]
    for i, f in enumerate(findings, 2):
        ev = f" (evidence: {f['evidence']})" if f.get("evidence") else ""
        steps.append(f"{i}. Observe: {f.get('title', '?')}{ev}")

    impact_map = {
        "critical": "Critical risk: possible severe compromise of the system or sensitive data.",
        "high": "High impact: data exposure or misconfiguration that facilitates attacks.",
        "medium": "Medium impact: misconfiguration or information leak that should be remediated.",
        "low": "Low impact: security improvement recommended.",
    }
    impact = impact_map.get(severity, impact_map["medium"])

    vuln_info = "\n".join(desc_parts) + "\n\n## Steps to Reproduce\n" + "\n".join(steps)

    return {
        "title": title[:250],
        "vulnerability_information": vuln_info,
        "impact": impact,
        "severity_rating": severity,
    }


def auto_submit_eligible_targets(program_id: str) -> list[dict]:
    """Find eligible targets for a H1 program and auto-submit reports.

    A target is eligible if: alive, recon_checks.checked, total_findings > 0,
    and not already submitted (checked via submitted_reports collection).
    """
    if not AUTO_SUBMIT_H1:
        return []

    username = (os.getenv("HACKERONE_API_USERNAME") or "").strip()
    token = (os.getenv("HACKERONE_API_TOKEN") or "").strip()
    if not username or not token:
        return []

    try:
        oid = ObjectId(program_id)
    except Exception:
        return []

    programs_col = get_bounty_programs()
    targets_col = get_bounty_targets()
    reports_col = get_submitted_reports()

    program = programs_col.find_one({"_id": oid})
    if not program:
        return []

    program_url = (program.get("url") or "").strip()
    if "hackerone.com" not in program_url:
        return []

    from urllib.parse import urlsplit
    path = urlsplit(program_url).path.strip("/")
    parts = [p for p in path.split("/") if p]
    handle = parts[0] if parts else None
    if not handle:
        return []

    already_submitted = set()
    for r in reports_col.find({"program_id": oid}):
        already_submitted.add(str(r.get("target_id", "")))

    targets = list(targets_col.find({"program_id": oid}))
    eligible = []
    for t in targets:
        if not t.get("alive"):
            continue
        rc = t.get("recon_checks") or {}
        if not rc.get("checked"):
            continue
        if (rc.get("total_findings") or 0) <= 0:
            continue
        tid = str(t.get("_id", ""))
        if tid in already_submitted:
            continue
        eligible.append(t)

    results = []
    for t in eligible:
        body = _build_h1_report_body(program, t)
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": handle,
                    "title": body["title"],
                    "vulnerability_information": body["vulnerability_information"],
                    "severity_rating": body["severity_rating"],
                    "impact": body["impact"],
                },
            },
        }

        report_record = {
            "program_id": oid,
            "program_name": program.get("name", "?"),
            "target_id": t.get("_id"),
            "domain": t.get("domain", "?"),
            "severity": body["severity_rating"],
            "findings_count": len((t.get("recon_checks") or {}).get("findings", [])),
            "title": body["title"],
            "timestamp": datetime.utcnow(),
            "status": "pending",
            "h1_report_id": None,
            "h1_report_url": None,
            "error": None,
            "report_body": body["vulnerability_information"][:2000],
        }

        try:
            r = requests.post(
                "https://api.hackerone.com/v1/hackers/reports",
                auth=(username, token),
                json=payload,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                timeout=30,
            )
            if r.status_code in (200, 201):
                data = r.json() or {}
                rid = (data.get("data") or {}).get("id")
                attrs = (data.get("data") or {}).get("attributes") or {}
                rurl = attrs.get("url") or (f"https://hackerone.com/reports/{rid}" if rid else "")
                report_record["status"] = "submitted"
                report_record["h1_report_id"] = rid
                report_record["h1_report_url"] = rurl
                logger.info("[H1-AUTO] Submitted: %s → %s (report %s)", t.get("domain"), program.get("name"), rid)
            else:
                err = r.text[:300]
                report_record["status"] = "error"
                report_record["error"] = err
                logger.warning("[H1-AUTO] Failed %s: %s", t.get("domain"), err)
        except Exception as e:
            report_record["status"] = "error"
            report_record["error"] = str(e)[:300]
            logger.warning("[H1-AUTO] Exception %s: %s", t.get("domain"), e)

        reports_col.insert_one(report_record)
        results.append(report_record)

    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
def generate_report(program_id: str) -> str:
    """Generate a Markdown report for all vulns found in a bounty program."""
    programs_col = get_bounty_programs()
    targets_col = get_bounty_targets()
    vuln_col = get_vuln_results()

    try:
        oid = ObjectId(program_id)
    except Exception:
        return "# Error\nInvalid program ID."

    program = programs_col.find_one({"_id": oid})
    if not program:
        return "# Error\nProgram not found."

    targets = list(targets_col.find({"program_id": oid}))
    target_ips = set()
    target_domains = set()
    for t in targets:
        target_domains.add(t.get("domain", ""))
        for ip in t.get("ips", []):
            target_ips.add(ip)

    vulns = list(vuln_col.find({"ip": {"$in": list(target_ips)}}).sort("severity", 1))

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda v: sev_order.get(v.get("severity", "info"), 5))

    lines = [
        f"# Bug Bounty Report: {program.get('name', 'Unknown')}",
        f"**Plataforma:** {program.get('platform', 'N/A')}  ",
        f"**URL:** {program.get('url', 'N/A')}  ",
        f"**Data:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Subdominios descobertos:** {len(target_domains)}  ",
        f"**Vulnerabilidades encontradas:** {len(vulns)}  ",
        "",
        "---",
        "",
    ]

    if not vulns:
        lines.append("Nenhuma vulnerabilidade confirmada encontrada ate o momento.")
        return "\n".join(lines)

    sev_counts: dict[str, int] = {}
    for v in vulns:
        s = v.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines.append("## Resumo por Severidade")
    lines.append("")
    lines.append("| Severidade | Quantidade |")
    lines.append("|---|---|")
    for s in ["critical", "high", "medium", "low", "info"]:
        if sev_counts.get(s, 0) > 0:
            lines.append(f"| {s.upper()} | {sev_counts[s]} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    for i, v in enumerate(vulns, 1):
        lines.append(f"## Finding #{i}: {v.get('name', v.get('template_id', 'Unknown'))}")
        lines.append("")
        lines.append(f"**Template:** `{v.get('template_id', 'N/A')}`  ")
        lines.append(f"**Severidade:** {v.get('severity', 'N/A').upper()}  ")
        lines.append(f"**Ferramenta:** {v.get('tool', 'N/A')}  ")
        lines.append(f"**Target:** `{v.get('matched_at', v.get('ip', 'N/A'))}`  ")
        if v.get("port"):
            lines.append(f"**Porta:** {v['port']}  ")
        lines.append("")

        if v.get("description"):
            lines.append("### Descricao")
            lines.append(v["description"])
            lines.append("")

        lines.append("### Steps to Reproduce")
        lines.append(f"1. Navigate to `{v.get('matched_at', v.get('ip', ''))}`")
        if v.get("proof"):
            lines.append(f"2. Observe: `{str(v['proof'])[:500]}`")
        lines.append("")

        if v.get("references"):
            lines.append("### References")
            for ref in v["references"][:5]:
                lines.append(f"- {ref}")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Auto recon loop
# ---------------------------------------------------------------------------
def _auto_recon_loop() -> None:
    """Periodically re-run recon on active programs.

    Priority order:
      1. Programs never scanned (no last_recon) — has_bounty first
      2. Programs with oldest last_recon that exceeded interval
    """
    logger.info("[BOUNTY] Auto-recon ativo (intervalo=%ds)", RECON_INTERVAL)
    while True:
        try:
            programs_col = get_bounty_programs()

            never_scanned = list(programs_col.find(
                {"status": {"$in": ["active", None]}, "last_recon": {"$exists": False}},
            ).sort("has_bounty", -1))

            stale = list(programs_col.find(
                {"status": {"$in": ["active", None]}, "last_recon": {"$exists": True}},
            ).sort("last_recon", 1))

            candidates = never_scanned + stale

            for prog in candidates:
                pid = str(prog["_id"])
                last = prog.get("last_recon")
                if last:
                    elapsed = (datetime.utcnow() - last).total_seconds()
                    if elapsed < RECON_INTERVAL:
                        continue
                try:
                    recon_pipeline(pid)
                except Exception as e:
                    logger.error("[BOUNTY] auto-recon erro em %s: %s",
                                 prog.get("name", "?"), e)
                    _inc_stat("errors")
        except Exception as e:
            logger.error("[BOUNTY] auto-recon loop erro: %s", e)

        time.sleep(300)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
def start_bounty_system() -> None:
    """Start bounty recon threads."""
    if not BOUNTY_MODE:
        logger.info("[BOUNTY] Modo bug bounty desabilitado")
        return

    t = threading.Thread(target=_auto_recon_loop, daemon=True)
    t.start()

    logger.info("[BOUNTY] Sistema ativo | recon_interval=%ds | fontes: subfinder+crt.sh+rdns+asn", RECON_INTERVAL)
