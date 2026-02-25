"""
Bug Bounty mode: gerenciamento de programas, recon automatizado e scope validation.

Pipeline: subfinder (enum subdominios) -> DNS resolve -> httpx (probe HTTP) -> Nuclei + Nmap.
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

from app.database import get_bounty_programs, get_bounty_targets, get_vuln_results
from app.http_port_scanner_integration import run_http_port_scanner, HTTP_PORT_SCANNER_ENABLED

logger = logging.getLogger("scanner.bounty")

BOUNTY_MODE = os.getenv("BOUNTY_MODE", "true").lower() in ("1", "true", "yes")
RECON_INTERVAL = int(os.getenv("BOUNTY_RECON_INTERVAL", "21600"))
RECON_WORKERS = int(os.getenv("BOUNTY_RECON_WORKERS", "2"))
SUBFINDER_TIMEOUT = int(os.getenv("SUBFINDER_TIMEOUT", "300"))
HTTPX_TIMEOUT = int(os.getenv("HTTPX_TIMEOUT", "300"))
RECON_HTTP_TIMEOUT = int(os.getenv("RECON_HTTP_TIMEOUT", "8"))

_recon_stats = {
    "recons_completed": 0,
    "subdomains_found": 0,
    "hosts_alive": 0,
    "errors": 0,
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
    # Flatten: accept list of strings or newline-separated in a string
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
        # URL-style: https://example.com/path -> example.com
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
        # CIDR skip
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
# Subfinder -- subdomain enumeration
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
# httpx -- HTTP probe
# ---------------------------------------------------------------------------
def run_httpx_probe(targets: list[str]) -> list[dict[str, Any]]:
    """Run httpx to probe which targets are alive and gather HTTP metadata."""
    if not targets:
        return []

    alive = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for t in targets:
            f.write(t + "\n")
        targets_file = f.name

    cmd = [
        "httpx",
        "-l", targets_file,
        "-json",
        "-silent",
        "-timeout", "10",
        "-retries", "1",
        "-no-color",
        "-status-code",
        "-title",
        "-tech-detect",
        "-cdn",
        "-follow-redirects",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=HTTPX_TIMEOUT + 30,
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

        logger.info("[BOUNTY] httpx: %d/%d vivos", len(alive), len(targets))

    except subprocess.TimeoutExpired:
        logger.warning("[BOUNTY] httpx timeout")
        _inc_stat("errors")
    except FileNotFoundError:
        logger.error("[BOUNTY] httpx nao encontrado no PATH")
        _inc_stat("errors")
    except Exception as e:
        logger.error("[BOUNTY] httpx erro: %s", e)
        _inc_stat("errors")
    finally:
        try:
            os.unlink(targets_file)
        except OSError:
            pass

    return alive


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

    for path, code, label in [
        ("/.git/HEAD", "git_head_exposed", "Repositorio .git exposto"),
        ("/server-status", "server_status_exposed", "Endpoint /server-status acessivel"),
        ("/actuator/health", "actuator_health_exposed", "Endpoint actuator health exposto"),
    ]:
        probe_url = _with_path(resp.url, path)
        try:
            p = requests.get(probe_url, timeout=4, allow_redirects=False, headers=headers)
            body_small = (p.text or "")[:300].lower()
            if code == "git_head_exposed" and p.status_code == 200 and "refs/heads" in body_small:
                _add_recon_finding(result, "high", code, label, probe_url)
            elif code == "server_status_exposed" and p.status_code == 200:
                _add_recon_finding(result, "medium", code, label, probe_url)
            elif code == "actuator_health_exposed" and p.status_code == 200 and re.search(r'"status"\s*:\s*"up"', body_small):
                _add_recon_finding(result, "medium", code, label, probe_url)
        except requests.RequestException:
            continue

    try:
        opt = requests.options(resp.url, timeout=4, allow_redirects=False, headers=headers)
        allow_hdr = str(opt.headers.get("Allow", ""))
        if "TRACE" in allow_hdr.upper():
            _add_recon_finding(result, "medium", "trace_enabled", "Metodo TRACE habilitado", allow_hdr)
    except requests.RequestException:
        pass

    result["total_findings"] = len(result["findings"])
    return result


# ---------------------------------------------------------------------------
# Recon pipeline
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

    # Fallback: se o escopo salvo estiver invalido (ex.: ["true"]), tenta derivar do URL do programa.
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
            # Ajusta escopo em memoria para algo utilizavel
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

    logger.info("[BOUNTY] Recon '%s': dominios=%s", program.get("name", "?"), root_domains)

    try:
        all_subdomains: set[str] = set()
        for domain in root_domains:
            subs = run_subdomain_enum(domain)
            all_subdomains.update(subs)
            all_subdomains.add(domain)

        scoped = [s for s in all_subdomains if is_in_scope(s, in_scope, out_of_scope)]
        logger.info("[BOUNTY] %d subdominios em escopo (de %d total)", len(scoped), len(all_subdomains))

        dns_map = resolve_dns(scoped)
        resolved_hosts = list(dns_map.keys())

        alive_results = run_httpx_probe(resolved_hosts)
        alive_hosts = {a["host"] for a in alive_results}
        httpx_by_host = {a.get("host", ""): a for a in alive_results if a.get("host")}
        recon_checks_by_host = {
            host: _recon_security_checks(data.get("url", ""), data)
            for host, data in httpx_by_host.items()
        }

        http_scanner_by_host: dict[str, Any] = {}
        if HTTP_PORT_SCANNER_ENABLED:
            logger.info(
                "[BOUNTY] HTTP Port Scanner habilitado — executando para %d hosts vivos",
                len(alive_hosts),
            )
            for host in sorted(alive_hosts):
                try:
                    extra = run_http_port_scanner(host)
                except Exception as e:
                    logger.error("[BOUNTY] HTTP Port Scanner falhou em %s: %s", host, e)
                    extra = []
                if extra:
                    http_scanner_by_host[host] = extra

        now = datetime.utcnow()
        saved = 0
        for sub in scoped:
            ips = dns_map.get(sub, [])
            is_alive = sub in alive_hosts
            httpx_data = httpx_by_host.get(sub)
            recon_checks = recon_checks_by_host.get(sub, {"checked": False, "total_findings": 0, "findings": []})
            http_scanner = http_scanner_by_host.get(sub, [])

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
                        "last_recon": now,
                    }
                },
                upsert=True,
            )
            saved += 1

        _inc_stat("subdomains_found", len(scoped))
        _inc_stat("hosts_alive", len(alive_hosts))
        _inc_stat("recons_completed")

        # first_recon_at: registra a data do primeiro recon bem-sucedido do programa
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
            },
        }})

        summary = {
            "program": program.get("name", ""),
            "root_domains": root_domains,
            "subdomains_found": len(scoped),
            "dns_resolved": len(resolved_hosts),
            "alive_hosts": len(alive_hosts),
            "targets_saved": saved,
            "recon_findings": sum(v.get("total_findings", 0) for v in recon_checks_by_host.values()),
            "risky_targets": sum(1 for v in recon_checks_by_host.values() if v.get("high", 0) > 0),
        }
        logger.info("[BOUNTY] Recon completo: %s", summary)
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
    """Periodically re-run recon on active programs."""
    logger.info("[BOUNTY] Auto-recon ativo (intervalo=%ds)", RECON_INTERVAL)
    while True:
        try:
            programs_col = get_bounty_programs()
            active = programs_col.find({"status": {"$in": ["active", None]}})
            for prog in active:
                pid = str(prog["_id"])
                last = prog.get("last_recon")
                if last:
                    elapsed = (datetime.utcnow() - last).total_seconds()
                    if elapsed < RECON_INTERVAL:
                        continue
                try:
                    recon_pipeline(pid)
                except Exception as e:
                    logger.error("[BOUNTY] auto-recon erro em %s: %s", prog.get("name", "?"), e)
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

    logger.info("[BOUNTY] Sistema ativo | recon_interval=%ds", RECON_INTERVAL)
