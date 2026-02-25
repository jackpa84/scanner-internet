"""
Scanner ativo de vulnerabilidades: Nuclei + Nmap NSE.

Consome IPs do scan_results (auto ou manual) e confirma vulns reais.
Resultados salvos em vuln_results com referencia ao documento original.
"""

import json
import logging
import os
import queue
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

from bson import ObjectId

from app.database import get_scan_results, get_vuln_results

logger = logging.getLogger("scanner.vuln")

NUM_VULN_WORKERS = int(os.getenv("VULN_WORKERS", "3"))
VULN_AUTO_SCAN = os.getenv("VULN_AUTO_SCAN", "true").lower() in ("1", "true", "yes")
NUCLEI_SEVERITY = os.getenv("NUCLEI_SEVERITY", "critical,high,medium")
NUCLEI_TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", "120"))
NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", "180"))
AUTO_MIN_SCORE = int(os.getenv("VULN_AUTO_MIN_SCORE", "70"))

_vuln_queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=500)
_scanned_ips: set[str] = set()
_scanned_lock = threading.Lock()

_vuln_stats = {
    "queued": 0,
    "scanning": 0,
    "completed": 0,
    "vulns_found": 0,
    "nuclei_runs": 0,
    "nmap_runs": 0,
    "errors": 0,
}
_stats_lock = threading.Lock()


def _inc_stat(key: str, n: int = 1) -> None:
    with _stats_lock:
        _vuln_stats[key] = _vuln_stats.get(key, 0) + n


def get_vuln_scan_stats() -> dict[str, Any]:
    with _stats_lock:
        s = dict(_vuln_stats)
    s["queue_size"] = _vuln_queue.qsize()
    return s


def _already_scanned(ip: str) -> bool:
    with _scanned_lock:
        return ip in _scanned_ips


def _mark_scanned(ip: str) -> None:
    with _scanned_lock:
        _scanned_ips.add(ip)


def enqueue_ip(ip: str, score: int = 50, scan_result_id: str | None = None, hostname: str | None = None) -> bool:
    """Add an IP to the vuln scan queue. Returns False if already queued/scanned or queue full."""
    key = hostname or ip
    if _already_scanned(key):
        return False
    try:
        _vuln_queue.put_nowait((-score, ip, scan_result_id, hostname))
        _inc_stat("queued")
        return True
    except queue.Full:
        return False


def enqueue_bounty_target(domain: str, ips: list[str], httpx_data: dict | None = None) -> bool:
    """Enqueue a bounty target (domain + IPs) for vuln scanning."""
    ip = ips[0] if ips else ""
    if not ip and not domain:
        return False
    return enqueue_ip(ip or domain, score=80, hostname=domain)


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------
def run_nuclei_scan(ip: str, ports: list[int] | None = None, cves: list[str] | None = None, hostname: str | None = None) -> list[dict]:
    """Run nuclei against an IP/host and return parsed findings."""
    targets = []
    http_ports = {80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000}
    scan_ports = set(ports or [])
    host = hostname or ip

    if hostname:
        targets.append(f"https://{hostname}")
        targets.append(f"http://{hostname}")
        for p in scan_ports & http_ports:
            if p not in (80, 443):
                scheme = "https" if p in (443, 8443) else "http"
                targets.append(f"{scheme}://{hostname}:{p}")
    else:
        for p in scan_ports & http_ports:
            scheme = "https" if p in (443, 8443) else "http"
            targets.append(f"{scheme}://{ip}:{p}")

    if not targets:
        targets.append(host)

    cmd = [
        "nuclei",
        "-target", ",".join(targets),
        "-severity", NUCLEI_SEVERITY,
        "-jsonl",
        "-silent",
        "-timeout", str(NUCLEI_TIMEOUT),
        "-retries", "1",
        "-bulk-size", "10",
        "-rate-limit", "50",
        "-no-color",
        "-stats=false",
    ]

    if cves:
        for cve in cves[:10]:
            cmd.extend(["-tags", cve.lower()])

    findings = []
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=NUCLEI_TIMEOUT + 30,
        )
        _inc_stat("nuclei_runs")

        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                findings.append({
                    "tool": "nuclei",
                    "template_id": obj.get("template-id", obj.get("templateID", "")),
                    "name": obj.get("info", {}).get("name", obj.get("template-id", "")),
                    "severity": obj.get("info", {}).get("severity", "info"),
                    "description": obj.get("info", {}).get("description", ""),
                    "matched_at": obj.get("matched-at", obj.get("host", "")),
                    "proof": obj.get("extracted-results", obj.get("matcher-name", "")),
                    "references": obj.get("info", {}).get("reference", []) or [],
                    "port": _extract_port(obj.get("matched-at", "")),
                    "tags": obj.get("info", {}).get("tags", []) or [],
                    "curl_command": obj.get("curl-command", ""),
                    "raw_output": obj,
                })
            except json.JSONDecodeError:
                continue

        if result.returncode != 0 and not findings:
            stderr = result.stderr.strip()[:200]
            if stderr and "no results" not in stderr.lower():
                logger.debug("[VULN] nuclei stderr: %s", stderr)

    except subprocess.TimeoutExpired:
        logger.warning("[VULN] nuclei timeout para %s", ip)
        _inc_stat("errors")
    except FileNotFoundError:
        logger.error("[VULN] nuclei nao encontrado no PATH")
        _inc_stat("errors")
    except Exception as e:
        logger.error("[VULN] nuclei erro: %s", e)
        _inc_stat("errors")

    return findings


def _extract_port(url: str) -> int | None:
    """Extract port from a URL like http://1.2.3.4:8080/path."""
    try:
        if "://" in url:
            host_part = url.split("://", 1)[1].split("/", 1)[0]
            if ":" in host_part:
                return int(host_part.rsplit(":", 1)[1])
            return 443 if url.startswith("https") else 80
    except (ValueError, IndexError):
        pass
    return None


# ---------------------------------------------------------------------------
# Nmap NSE
# ---------------------------------------------------------------------------
def run_nmap_deep(ip: str, ports: list[int] | None = None) -> list[dict]:
    """Run nmap with vuln/auth scripts and return parsed findings."""
    port_arg = ",".join(str(p) for p in (ports or [])[:20]) if ports else "21,22,23,25,80,443,445,3306,3389,5432,8080,8443"

    cmd = [
        "nmap", "-sV",
        "--script", "vuln,auth",
        "-p", port_arg,
        "-oX", "-",
        "--host-timeout", f"{NMAP_TIMEOUT}s",
        "-T4",
        "--open",
        ip,
    ]

    findings = []
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=NMAP_TIMEOUT + 30,
        )
        _inc_stat("nmap_runs")

        if result.stdout.strip():
            findings = _parse_nmap_xml(result.stdout, ip)

    except subprocess.TimeoutExpired:
        logger.warning("[VULN] nmap timeout para %s", ip)
        _inc_stat("errors")
    except FileNotFoundError:
        logger.error("[VULN] nmap nao encontrado no PATH")
        _inc_stat("errors")
    except Exception as e:
        logger.error("[VULN] nmap erro: %s", e)
        _inc_stat("errors")

    return findings


def _parse_nmap_xml(xml_str: str, ip: str) -> list[dict]:
    """Parse nmap XML output into vuln findings."""
    findings = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return findings

    for host in root.findall(".//host"):
        for port_el in host.findall(".//port"):
            port_id = int(port_el.get("portid", "0"))
            service_el = port_el.find("service")
            service_name = service_el.get("name", "") if service_el is not None else ""
            service_version = service_el.get("version", "") if service_el is not None else ""
            service_product = service_el.get("product", "") if service_el is not None else ""

            for script in port_el.findall("script"):
                script_id = script.get("id", "")
                output = script.get("output", "")

                if _is_vuln_output(script_id, output):
                    severity = _nmap_severity(script_id, output)
                    findings.append({
                        "tool": "nmap",
                        "template_id": script_id,
                        "name": f"{script_id} ({service_product} {service_version})".strip(),
                        "severity": severity,
                        "description": f"Nmap script {script_id} detected on port {port_id}/{service_name}",
                        "matched_at": f"{ip}:{port_id}",
                        "proof": output[:1000],
                        "references": [],
                        "port": port_id,
                        "tags": [service_name, script_id],
                        "service": service_name,
                        "service_version": f"{service_product} {service_version}".strip(),
                        "raw_output": {"script_id": script_id, "output": output[:2000]},
                    })

    return findings


def _is_vuln_output(script_id: str, output: str) -> bool:
    """Filter out nmap script outputs that are NOT actual vulns."""
    lower = output.lower()
    if "not vulnerable" in lower or "error" == lower.strip():
        return False
    if "state: vulnerable" in lower or "vulnerable" in lower:
        return True
    if "vulners" in script_id:
        return "cve-" in lower
    vuln_scripts = {"ssl-heartbleed", "smb-vuln", "http-vuln", "ftp-anon", "ssh-auth-methods"}
    if any(script_id.startswith(v) for v in vuln_scripts):
        return True
    if script_id.startswith("auth-") or "brute" in script_id:
        return bool(output.strip()) and "error" not in lower
    return False


def _nmap_severity(script_id: str, output: str) -> str:
    """Heuristic severity based on nmap script type."""
    lower = output.lower()
    critical_patterns = ["remote code execution", "rce", "heartbleed", "ms17-010", "eternalblue"]
    if any(p in lower for p in critical_patterns):
        return "critical"
    if "smb-vuln" in script_id or "ssl-" in script_id:
        return "high"
    if "http-vuln" in script_id:
        return "high"
    if "ftp-anon" in script_id or "auth" in script_id:
        return "medium"
    return "medium"


# ---------------------------------------------------------------------------
# Scan pipeline
# ---------------------------------------------------------------------------
def _vuln_scan_ip(ip: str, scan_result_id: str | None = None, hostname: str | None = None) -> int:
    """Run full vuln scan (nuclei + nmap) on a single IP, save results. Returns vuln count."""
    _inc_stat("scanning")
    _mark_scanned(hostname or ip)

    col = get_scan_results()
    doc = col.find_one({"ip": ip}, {"ports": 1, "vulns": 1})
    ports = doc.get("ports", []) if doc else []
    cves = doc.get("vulns", []) if doc else []

    ref_id = None
    if scan_result_id:
        try:
            ref_id = ObjectId(scan_result_id)
        except Exception:
            ref_id = None
    elif doc:
        ref_id = doc.get("_id")

    nuclei_findings = run_nuclei_scan(ip, ports, cves, hostname=hostname)
    nmap_findings = run_nmap_deep(ip, ports)

    all_findings = nuclei_findings + nmap_findings
    saved = 0

    if all_findings:
        vuln_col = get_vuln_results()
        docs_to_insert = []
        for f in all_findings:
            vuln_doc = {
                "ip": ip,
                "hostname": hostname or "",
                "scan_result_id": ref_id,
                "tool": f["tool"],
                "template_id": f["template_id"],
                "name": f["name"],
                "severity": f["severity"],
                "description": f["description"],
                "matched_at": f.get("matched_at", ""),
                "proof": str(f.get("proof", ""))[:2000],
                "references": f.get("references", [])[:10],
                "port": f.get("port"),
                "tags": f.get("tags", []),
                "raw_output": f.get("raw_output", {}),
                "timestamp": datetime.utcnow(),
            }
            docs_to_insert.append(vuln_doc)

        if docs_to_insert:
            vuln_col.insert_many(docs_to_insert)
            saved = len(docs_to_insert)
            _inc_stat("vulns_found", saved)

    with _stats_lock:
        _vuln_stats["scanning"] = max(0, _vuln_stats["scanning"] - 1)
    _inc_stat("completed")

    sev_summary = {}
    for f in all_findings:
        s = f["severity"]
        sev_summary[s] = sev_summary.get(s, 0) + 1
    sev_str = " ".join(f"{k}:{v}" for k, v in sorted(sev_summary.items())) if sev_summary else "nenhuma"

    target_label = f"{hostname} ({ip})" if hostname else ip
    logger.info("[VULN] %-30s  %d achados (%s)  nuclei:%d nmap:%d", target_label, saved, sev_str, len(nuclei_findings), len(nmap_findings))
    return saved


# ---------------------------------------------------------------------------
# Workers
# ---------------------------------------------------------------------------
def _vuln_worker(worker_id: int) -> None:
    """Worker loop that consumes IPs from the vuln queue."""
    while True:
        try:
            item = _vuln_queue.get(timeout=10)
        except queue.Empty:
            continue

        priority, ip, scan_result_id = item[0], item[1], item[2]
        hostname = item[3] if len(item) > 3 else None

        try:
            _vuln_scan_ip(ip, scan_result_id, hostname=hostname)
        except Exception as e:
            logger.error("[VULN] W%d erro em %s: %s", worker_id, hostname or ip, e)
            _inc_stat("errors")
        finally:
            _vuln_queue.task_done()


def _auto_enqueue_loop() -> None:
    """Periodically check scan_results for high-risk IPs and enqueue for vuln scanning."""
    logger.info("[VULN] auto-enqueue ativo (min_score=%d)", AUTO_MIN_SCORE)
    while True:
        try:
            col = get_scan_results()
            cursor = col.find(
                {"risk.score": {"$gte": AUTO_MIN_SCORE}},
                {"ip": 1, "risk.score": 1},
            ).sort("risk.score", -1).limit(50)

            enqueued = 0
            for doc in cursor:
                ip = doc.get("ip")
                score = doc.get("risk", {}).get("score", 0)
                if ip and not _already_scanned(ip):
                    sid = str(doc["_id"])
                    if enqueue_ip(ip, score, sid):
                        enqueued += 1
            if enqueued:
                logger.info("[VULN] auto-enqueue: +%d IPs na fila", enqueued)
        except Exception as e:
            logger.error("[VULN] auto-enqueue erro: %s", e)

        time.sleep(60)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
def start_vuln_scanner() -> None:
    """Start vuln scan workers and optional auto-enqueue thread."""
    for i in range(NUM_VULN_WORKERS):
        t = threading.Thread(target=_vuln_worker, args=(i + 1,), daemon=True)
        t.start()

    if VULN_AUTO_SCAN:
        t = threading.Thread(target=_auto_enqueue_loop, daemon=True)
        t.start()

    logger.info(
        "[VULN] Scanner iniciado: %d workers | auto=%s | severidade=%s",
        NUM_VULN_WORKERS, VULN_AUTO_SCAN, NUCLEI_SEVERITY,
    )
