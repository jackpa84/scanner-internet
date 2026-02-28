"""
CVE feed monitor + auto Nuclei template generator.

Monitors NVD and other feeds for critical CVEs.
Generates basic Nuclei templates for quick exploitation.
First 48h of a new CVE = highest bounty potential.
"""

import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta
from typing import Any

import requests

from app.database import get_redis

logger = logging.getLogger("scanner.cve_monitor")

CVE_MONITOR_ENABLED = os.getenv("CVE_MONITOR_ENABLED", "true").lower() in ("1", "true", "yes")
CVE_POLL_INTERVAL = int(os.getenv("CVE_POLL_INTERVAL", "1800"))
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
CUSTOM_TEMPLATES_DIR = os.getenv("CUSTOM_NUCLEI_TEMPLATES", "/app/nuclei-custom-templates")

_stats = {
    "cves_fetched": 0,
    "critical_cves": 0,
    "templates_generated": 0,
    "last_check": None,
    "errors": 0,
}
_stats_lock = threading.Lock()


def _inc_stat(key: str, n: int = 1) -> None:
    with _stats_lock:
        _stats[key] = _stats.get(key, 0) + n


def get_cve_stats() -> dict[str, Any]:
    with _stats_lock:
        return dict(_stats)


def fetch_recent_cves(hours: int = 48, severity: str = "CRITICAL,HIGH") -> list[dict]:
    """Fetch recent CVEs from NVD API."""
    cves = []
    end = datetime.utcnow()
    start = end - timedelta(hours=hours)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }

    if severity:
        params["cvssV3Severity"] = severity

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers=headers,
            timeout=30,
        )
        if resp.status_code != 200:
            logger.warning("[CVE] NVD API returned %d", resp.status_code)
            _inc_stat("errors")
            return []

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            metrics = cve_data.get("metrics", {})

            cvss_v3 = None
            cvss_score = 0.0
            for metric_list in metrics.get("cvssMetricV31", []):
                cvss_data = metric_list.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0)
                cvss_v3 = cvss_data.get("vectorString", "")
                break

            if not cvss_v3:
                for metric_list in metrics.get("cvssMetricV30", []):
                    cvss_data = metric_list.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0)
                    cvss_v3 = cvss_data.get("vectorString", "")
                    break

            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)

            weaknesses = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        weaknesses.append(desc.get("value", ""))

            cpe_matches = []
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if criteria:
                            cpe_matches.append(criteria)

            published = cve_data.get("published", "")

            cve_entry = {
                "id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_v3,
                "severity": "critical" if cvss_score >= 9.0 else "high" if cvss_score >= 7.0 else "medium",
                "published": published,
                "references": references[:10],
                "weaknesses": weaknesses,
                "affected_products": cpe_matches[:20],
                "age_hours": (end - datetime.fromisoformat(published.replace("Z", "+00:00")).replace(tzinfo=None)).total_seconds() / 3600 if published else 0,
            }
            cves.append(cve_entry)
            _inc_stat("cves_fetched")

            if cvss_score >= 9.0:
                _inc_stat("critical_cves")

    except Exception as e:
        logger.error("[CVE] NVD fetch error: %s", e)
        _inc_stat("errors")

    cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    return cves


def _extract_product_from_cpe(cpe: str) -> tuple[str, str]:
    """Extract vendor and product from CPE string."""
    parts = cpe.split(":")
    if len(parts) >= 5:
        vendor = parts[3]
        product = parts[4]
        return vendor, product
    return "", ""


def _is_web_vuln(cve: dict) -> bool:
    """Check if CVE likely affects web applications."""
    desc_lower = cve.get("description", "").lower()
    web_indicators = [
        "sql injection", "xss", "cross-site", "remote code execution",
        "rce", "ssrf", "server-side request", "directory traversal",
        "path traversal", "file inclusion", "upload", "deserialization",
        "authentication bypass", "authorization", "privilege escalation",
        "information disclosure", "api", "web application", "http",
        "wordpress", "apache", "nginx", "tomcat", "spring", "django",
        "laravel", "rails", "node.js", "express", "php", "java",
        "python", "jenkins", "gitlab", "jira", "confluence",
    ]
    return any(indicator in desc_lower for indicator in web_indicators)


def generate_nuclei_template(cve: dict) -> str | None:
    """Generate a basic Nuclei template for a CVE."""
    cve_id = cve.get("id", "")
    description = cve.get("description", "")
    severity = cve.get("severity", "high")
    references = cve.get("references", [])
    cvss_score = cve.get("cvss_score", 0)

    if not _is_web_vuln(cve):
        return None

    desc_lower = description.lower()

    paths = []
    matchers = []
    method = "GET"

    if "wordpress" in desc_lower:
        paths = ["/wp-content/plugins/", "/wp-admin/", "/wp-json/"]
        matchers = ['"wp-', "wordpress"]
    elif "apache" in desc_lower and "struts" in desc_lower:
        paths = ["/struts/", "/"]
        matchers = ["struts"]
    elif "spring" in desc_lower:
        paths = ["/actuator/env", "/actuator/health", "/api/"]
        matchers = ['"status"', "spring"]
    elif "jenkins" in desc_lower:
        paths = ["/", "/api/json", "/script"]
        matchers = ["jenkins", "x-jenkins"]
    elif "gitlab" in desc_lower:
        paths = ["/api/v4/", "/users/sign_in"]
        matchers = ["gitlab"]
    elif "jira" in desc_lower:
        paths = ["/rest/api/2/", "/secure/"]
        matchers = ["jira", "atlassian"]
    elif "sql injection" in desc_lower:
        paths = ["/"]
        matchers = ["error", "sql", "syntax"]
    elif "path traversal" in desc_lower or "directory traversal" in desc_lower:
        paths = ["/../../../etc/passwd", "/..%2f..%2f..%2fetc%2fpasswd"]
        matchers = ["root:", "/bin/"]
    else:
        paths = ["/"]
        matchers = []

    if not paths:
        return None

    ref_lines = "\n".join(f"    - {ref}" for ref in references[:5])

    template = f"""id: {cve_id.lower()}

info:
  name: "{cve_id} - Auto-generated detection"
  author: scanner-auto
  severity: {severity}
  description: |
    {description[:300]}
  reference:
{ref_lines}
  tags: cve,{cve_id.lower()},auto-generated
  metadata:
    cvss-score: {cvss_score}
    auto-generated: true
    generated-at: {datetime.utcnow().isoformat()}

http:
  - method: {method}
    path:
"""
    for path in paths[:3]:
        template += f'      - "{{{{BaseURL}}}}{path}"\n'

    template += """    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
"""

    if matchers:
        template += """      - type: word
        words:
"""
        for m in matchers[:5]:
            template += f'          - "{m}"\n'
        template += "        condition: or\n"

    return template


def save_template(cve_id: str, template_content: str) -> str | None:
    """Save a Nuclei template to disk."""
    try:
        os.makedirs(CUSTOM_TEMPLATES_DIR, exist_ok=True)
        filename = f"{cve_id.lower().replace('-', '_')}.yaml"
        filepath = os.path.join(CUSTOM_TEMPLATES_DIR, filename)

        if os.path.exists(filepath):
            return filepath

        with open(filepath, "w") as f:
            f.write(template_content)

        _inc_stat("templates_generated")
        logger.info("[CVE] Generated template: %s", filepath)
        return filepath

    except Exception as e:
        logger.error("[CVE] Failed to save template for %s: %s", cve_id, e)
        _inc_stat("errors")
        return None


def process_new_cves() -> dict[str, Any]:
    """Fetch new CVEs, generate templates, and store alerts."""
    cves = fetch_recent_cves(hours=48)
    web_cves = [c for c in cves if _is_web_vuln(c)]

    templates_created = []
    for cve in web_cves:
        template = generate_nuclei_template(cve)
        if template:
            path = save_template(cve["id"], template)
            if path:
                templates_created.append({
                    "cve_id": cve["id"],
                    "severity": cve["severity"],
                    "cvss_score": cve["cvss_score"],
                    "template_path": path,
                    "age_hours": cve.get("age_hours", 0),
                })

    try:
        r = get_redis()
        for cve in web_cves[:20]:
            r.hset("cve:recent", cve["id"], json.dumps(cve, default=str))
        r.expire("cve:recent", 172800)
    except Exception:
        pass

    with _stats_lock:
        _stats["last_check"] = datetime.utcnow().isoformat()

    return {
        "total_cves": len(cves),
        "web_cves": len(web_cves),
        "templates_created": len(templates_created),
        "templates": templates_created,
        "checked_at": datetime.utcnow().isoformat(),
    }


def get_recent_cves() -> list[dict]:
    """Get cached recent CVEs from Redis."""
    try:
        r = get_redis()
        cves = []
        for cve_id, data in r.hgetall("cve:recent").items():
            cve = json.loads(data)
            cves.append(cve)
        cves.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        return cves
    except Exception:
        return []


def _cve_monitor_loop() -> None:
    """Background loop for CVE monitoring."""
    time.sleep(45)
    logger.info("[CVE] Monitor started (interval=%ds)", CVE_POLL_INTERVAL)

    while True:
        try:
            result = process_new_cves()
            if result["templates_created"] > 0:
                logger.info("[CVE] Created %d new templates from %d web CVEs",
                            result["templates_created"], result["web_cves"])
        except Exception as e:
            logger.error("[CVE] Monitor loop error: %s", e)
            _inc_stat("errors")

        time.sleep(CVE_POLL_INTERVAL)


def start_cve_monitor() -> None:
    """Start the CVE monitor background thread."""
    if not CVE_MONITOR_ENABLED:
        logger.info("[CVE] Monitor disabled")
        return

    os.makedirs(CUSTOM_TEMPLATES_DIR, exist_ok=True)

    t = threading.Thread(target=_cve_monitor_loop, daemon=True)
    t.start()
    logger.info("[CVE] Monitor active (templates_dir=%s)", CUSTOM_TEMPLATES_DIR)
