"""
Advanced recon checks for bug bounty pipeline.

Covers gaps not handled by the base security checks:
  - DNS Zone Transfer (AXFR)
  - SSTI Detection (Jinja2, Freemarker, ERB, EL)
  - CRLF Injection
  - Host Header Injection
  - JWT Vulnerability Analysis
  - Cloud Bucket Enumeration (S3, Azure Blob, GCS)
  - GitHub Dorking (leaked secrets)
  - ParamSpider (URL parameter discovery via web archives)
"""

import base64
import json
import logging
import os
import re
import subprocess
import time
from typing import Any
from urllib.parse import urlsplit, quote

import requests

logger = logging.getLogger("scanner.advanced")

RECON_HTTP_TIMEOUT = int(os.getenv("RECON_HTTP_TIMEOUT", "8"))
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()


# ---------------------------------------------------------------------------
# Finding helper (same format as bounty.py)
# ---------------------------------------------------------------------------
def _finding(severity: str, code: str, title: str, evidence: str = "") -> dict[str, str]:
    return {"severity": severity, "code": code, "title": title, "evidence": evidence[:200]}


# ---------------------------------------------------------------------------
# 1. DNS Zone Transfer (AXFR)
# ---------------------------------------------------------------------------
def check_dns_zone_transfer(domain: str) -> list[dict[str, str]]:
    """Attempt AXFR zone transfer against each nameserver for the domain."""
    findings: list[dict[str, str]] = []
    try:
        ns_result = subprocess.run(
            ["dig", "+short", "NS", domain],
            capture_output=True, text=True, timeout=10,
        )
        nameservers = [ns.strip().rstrip(".") for ns in ns_result.stdout.strip().splitlines() if ns.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return findings

    for ns in nameservers[:4]:
        try:
            axfr = subprocess.run(
                ["dig", f"@{ns}", domain, "AXFR", "+noall", "+answer", "+time=5"],
                capture_output=True, text=True, timeout=15,
            )
            lines = [l for l in axfr.stdout.strip().splitlines() if l.strip() and not l.startswith(";")]
            if len(lines) > 2:
                findings.append(_finding(
                    "high", "dns_zone_transfer",
                    f"DNS Zone Transfer permitido em {ns}",
                    f"{len(lines)} registros descobertos via AXFR",
                ))
                logger.info("[ADV] Zone transfer em %s via %s: %d registros", domain, ns, len(lines))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    return findings


# ---------------------------------------------------------------------------
# 2. SSTI Detection
# ---------------------------------------------------------------------------
def check_ssti(url: str, headers: dict[str, str]) -> list[dict[str, str]]:
    """Probe for Server-Side Template Injection via common expressions."""
    findings: list[dict[str, str]] = []
    payloads = [
        ("{{7*7}}", "49", "ssti_jinja2", "Possivel SSTI (Jinja2/Twig)"),
        ("${7*7}", "49", "ssti_el", "Possivel SSTI (EL/Freemarker)"),
        ("#{7*7}", "49", "ssti_thymeleaf", "Possivel SSTI (Thymeleaf/Ruby)"),
        ("{{7*'7'}}", "7777777", "ssti_jinja2_str", "Possivel SSTI (Jinja2 string mult)"),
    ]

    base = url.rstrip("/")
    probe_paths = ["/search?q=", "/?q=", "/api/search?query="]

    for path in probe_paths:
        for payload, expected, code, title in payloads:
            try:
                probe_url = base + path + quote(payload)
                r = requests.get(probe_url, timeout=4, allow_redirects=True, headers=headers)
                body = r.text[:5000]
                if expected in body and payload not in body:
                    findings.append(_finding("high", code, title, f"{probe_url} → contém '{expected}'"))
                    return findings
            except requests.RequestException:
                continue

    return findings


# ---------------------------------------------------------------------------
# 3. CRLF Injection
# ---------------------------------------------------------------------------
def check_crlf_injection(url: str, headers: dict[str, str]) -> list[dict[str, str]]:
    """Test for CRLF injection in URL path and parameters."""
    findings: list[dict[str, str]] = []
    base = url.rstrip("/")

    crlf_vectors = [
        "/%0d%0aX-Injected:true",
        "/%0d%0aSet-Cookie:crlftest=1",
        "/?redirect=%0d%0aX-Injected:true",
    ]

    for vector in crlf_vectors:
        try:
            r = requests.get(base + vector, timeout=4, allow_redirects=False, headers=headers)
            resp_headers_str = str(dict(r.headers)).lower()
            if "x-injected" in resp_headers_str or "crlftest" in resp_headers_str:
                findings.append(_finding(
                    "high", "crlf_injection",
                    "CRLF Injection detectado",
                    f"Vetor: {vector}",
                ))
                return findings
        except requests.RequestException:
            continue

    return findings


# ---------------------------------------------------------------------------
# 4. Host Header Injection
# ---------------------------------------------------------------------------
def check_host_header_injection(url: str, headers: dict[str, str]) -> list[dict[str, str]]:
    """Test for Host header injection (password reset poisoning, cache poisoning)."""
    findings: list[dict[str, str]] = []
    evil_host = "evil-scanner-test.com"

    tests = [
        {"Host": evil_host},
        {"Host": headers.get("Host", ""), "X-Forwarded-Host": evil_host},
        {"Host": headers.get("Host", ""), "X-Host": evil_host},
    ]

    for extra in tests:
        try:
            test_headers = {**headers, **extra}
            r = requests.get(url, timeout=4, headers=test_headers, allow_redirects=False)
            body = r.text[:3000].lower()
            location = r.headers.get("Location", "").lower()

            if evil_host in body or evil_host in location:
                sev = "high" if evil_host in location else "medium"
                findings.append(_finding(
                    sev, "host_header_injection",
                    "Host Header Injection detectado",
                    f"Host '{evil_host}' refletido {'em Location' if evil_host in location else 'no body'}",
                ))
                return findings
        except requests.RequestException:
            continue

    return findings


# ---------------------------------------------------------------------------
# 5. JWT Vulnerability Analysis
# ---------------------------------------------------------------------------
def check_jwt_vulnerabilities(resp: requests.Response) -> list[dict[str, str]]:
    """Analyze JWTs found in cookies and response body for common flaws."""
    findings: list[dict[str, str]] = []

    jwt_candidates: list[tuple[str, str]] = []

    for name, value in resp.cookies.items():
        if value.count(".") == 2 and value.startswith("eyJ"):
            jwt_candidates.append((f"Cookie:{name}", value))

    body_jwts = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', resp.text[:5000])
    for jwt in body_jwts[:3]:
        jwt_candidates.append(("body", jwt))

    for source, token in jwt_candidates[:5]:
        try:
            header_b64 = token.split(".")[0]
            padding = 4 - len(header_b64) % 4
            header_json = base64.urlsafe_b64decode(header_b64 + "=" * padding)
            header_data = json.loads(header_json)
            alg = str(header_data.get("alg", "")).strip()

            if alg.lower() == "none":
                findings.append(_finding("high", "jwt_none_alg", "JWT com algoritmo 'none' (bypass de assinatura)", source))
            elif alg.upper() in ("HS256", "HS384", "HS512"):
                findings.append(_finding("medium", "jwt_hmac_alg", f"JWT usando {alg} — verificar strength do secret", source))

            payload_b64 = token.split(".")[1]
            padding2 = 4 - len(payload_b64) % 4
            payload_json = base64.urlsafe_b64decode(payload_b64 + "=" * padding2)
            payload_data = json.loads(payload_json)

            sensitive_keys = {"password", "secret", "private_key", "credit_card", "ssn"}
            leaked = [k for k in payload_data if k.lower() in sensitive_keys]
            if leaked:
                findings.append(_finding("high", "jwt_sensitive_data", "JWT contém dados sensiveis no payload", f"Campos: {', '.join(leaked)}"))

            exp = payload_data.get("exp")
            if exp and isinstance(exp, (int, float)):
                import datetime
                exp_dt = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
                now = datetime.datetime.now(tz=datetime.timezone.utc)
                if exp_dt > now + datetime.timedelta(days=365):
                    findings.append(_finding("low", "jwt_long_expiry", "JWT com expiração superior a 1 ano", f"Expira em {exp_dt.isoformat()}"))

        except Exception:
            continue

    return findings


# ---------------------------------------------------------------------------
# 6. Cloud Bucket Enumeration (S3, Azure Blob, GCS)
# ---------------------------------------------------------------------------
def check_open_buckets(domain: str) -> list[dict[str, str]]:
    """Probe for open/misconfigured cloud storage buckets based on domain name."""
    findings: list[dict[str, str]] = []

    parts = domain.lower().replace("www.", "").split(".")
    base_name = parts[0]
    org_name = ".".join(parts[:2]) if len(parts) > 2 else base_name

    bucket_names = list(dict.fromkeys([
        base_name,
        org_name.replace(".", "-"),
        f"{base_name}-assets",
        f"{base_name}-backup",
        f"{base_name}-uploads",
        f"{base_name}-static",
        f"{base_name}-public",
        f"{base_name}-data",
        f"{base_name}-dev",
        f"{base_name}-staging",
        f"{base_name}-prod",
    ]))

    bucket_urls = []
    for name in bucket_names:
        bucket_urls.extend([
            (f"https://{name}.s3.amazonaws.com", "AWS S3"),
            (f"https://s3.amazonaws.com/{name}", "AWS S3"),
            (f"https://{name}.blob.core.windows.net/?comp=list", "Azure Blob"),
            (f"https://storage.googleapis.com/{name}", "GCS"),
        ])

    for url, provider in bucket_urls:
        try:
            r = requests.get(url, timeout=4, headers={"User-Agent": "scanner/1.0"})
            if r.status_code == 200:
                body = r.text[:2000]
                is_open = (
                    "ListBucketResult" in body
                    or "EnumerationResults" in body
                    or "<Contents>" in body
                    or '"kind":"storage#objects"' in body
                )
                if is_open:
                    findings.append(_finding(
                        "high", "open_cloud_bucket",
                        f"Bucket {provider} aberto: {url}",
                        f"Listagem de objetos acessivel publicamente",
                    ))
            elif r.status_code == 403:
                pass
        except requests.RequestException:
            continue

    return findings


# ---------------------------------------------------------------------------
# 7. GitHub Dorking (leaked secrets)
# ---------------------------------------------------------------------------
def run_github_dorking(domain: str) -> list[dict[str, str]]:
    """Search GitHub Code Search for leaked secrets related to a domain.

    Requires GITHUB_TOKEN env var for reliable results (unauthenticated
    requests are heavily rate-limited).
    """
    findings: list[dict[str, str]] = []
    if not GITHUB_TOKEN:
        return findings

    dork_queries = [
        f'"{domain}" password',
        f'"{domain}" api_key OR apikey OR api-key',
        f'"{domain}" secret_key OR secret OR token',
        f'"{domain}" AWS_ACCESS_KEY_ID OR AKIA',
        f'"{domain}" PRIVATE KEY',
    ]

    gh_headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {GITHUB_TOKEN}",
    }

    for query in dork_queries:
        try:
            resp = requests.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 5},
                headers=gh_headers,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                total = data.get("total_count", 0)
                if total > 0:
                    items = data.get("items", [])[:3]
                    repos = [item.get("repository", {}).get("full_name", "?") for item in items]
                    findings.append(_finding(
                        "high", "github_secret_leak",
                        f"Possiveis secrets no GitHub ({total} resultados)",
                        f"Query: {query.split(domain)[1].strip()} | Repos: {', '.join(repos)}",
                    ))
            elif resp.status_code == 403:
                logger.debug("[ADV] GitHub rate limit atingido")
                break
            time.sleep(3)
        except Exception:
            continue

    return findings


# ---------------------------------------------------------------------------
# 8. ParamSpider (URL parameter discovery via web archives)
# ---------------------------------------------------------------------------
def run_paramspider(domain: str) -> dict[str, Any]:
    """Discover URL parameters from Wayback Machine and extract unique param names.

    Returns {"params": ["id", "page", ...], "urls_with_params": [...]}
    """
    params: set[str] = set()
    interesting_urls: list[str] = []

    try:
        resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}/*?*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": "1000",
            },
            timeout=30,
        )
        if resp.status_code == 200:
            rows = resp.json()
            for row in rows[1:]:
                if not row or not row[0]:
                    continue
                url = row[0]
                parsed = urlsplit(url)
                if not parsed.query:
                    continue
                for pair in parsed.query.split("&"):
                    key = pair.split("=")[0].strip()
                    if key and len(key) < 50 and re.match(r'^[a-zA-Z_][a-zA-Z0-9_.-]*$', key):
                        params.add(key)

                interesting_params = {"id", "user", "admin", "token", "key", "secret",
                                      "password", "redirect", "url", "next", "return",
                                      "file", "path", "page", "template", "action",
                                      "callback", "cmd", "exec", "query", "search",
                                      "lang", "debug", "test", "config", "email"}
                if any(p.lower() in interesting_params for p in parsed.query.split("&")):
                    interesting_urls.append(url)

    except Exception as e:
        logger.debug("[ADV] ParamSpider erro para %s: %s", domain, e)

    if params:
        logger.info("[ADV] ParamSpider %s: %d params únicos", domain, len(params))

    return {
        "params": sorted(params)[:200],
        "urls_with_params": interesting_urls[:50],
    }


# ---------------------------------------------------------------------------
# Arjun — active parameter discovery (bruteforce via wordlist)
# ---------------------------------------------------------------------------
ARJUN_TIMEOUT = int(os.getenv("ARJUN_TIMEOUT", "60"))
ARJUN_WORDLIST = os.getenv("ARJUN_WORDLIST", "")  # deixa vazio = wordlist padrão do arjun


def run_arjun(urls: list[str], chunk_size: int = 5) -> list[dict[str, Any]]:
    """Discover hidden GET/POST parameters on alive URLs using Arjun.

    Processes URLs in chunks to avoid memory issues.
    Returns list of {"url": ..., "params": [...], "method": "GET|POST"}.
    """
    results: list[dict[str, Any]] = []

    if not urls:
        return results

    # Filtra só URLs com potencial (evita estáticos)
    candidates = [
        u for u in urls
        if not any(u.lower().endswith(ext) for ext in
                   (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                    ".css", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip"))
    ][:50]  # limita para não explodir o pipeline

    if not candidates:
        return results

    import tempfile

    for i in range(0, len(candidates), chunk_size):
        batch = candidates[i:i + chunk_size]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(batch))
            urls_file = f.name

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name

        try:
            cmd = [
                "arjun",
                "-i", urls_file,
                "-oJ", out_file,
                "--stable",
                "-t", "10",
                "--timeout", str(ARJUN_TIMEOUT),
            ]
            if ARJUN_WORDLIST:
                cmd += ["-w", ARJUN_WORDLIST]

            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=ARJUN_TIMEOUT * chunk_size + 30,
            )

            if os.path.exists(out_file) and os.path.getsize(out_file) > 2:
                with open(out_file) as fj:
                    data = json.load(fj)
                # arjun output: {"url": {"GET": [...], "POST": [...]}}
                for url, methods in data.items():
                    for method, params in methods.items():
                        if params:
                            results.append({
                                "url": url,
                                "method": method,
                                "params": params,
                                "param_count": len(params),
                            })
                            logger.info("[ADV] Arjun %s %s: %d params (%s)",
                                        method, url, len(params),
                                        ", ".join(params[:5]))

        except subprocess.TimeoutExpired:
            logger.warning("[ADV] Arjun timeout no batch %d-%d", i, i + chunk_size)
        except FileNotFoundError:
            logger.debug("[ADV] arjun não instalado, pulando")
            return results
        except Exception as e:
            logger.warning("[ADV] Arjun erro: %s", e)
        finally:
            for fp in (urls_file, out_file):
                try:
                    os.unlink(fp)
                except OSError:
                    pass

    if results:
        logger.info("[ADV] Arjun total: %d endpoints com parâmetros ocultos", len(results))

    return results


def arjun_findings_to_recon(arjun_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Converte resultados do arjun para o formato padrão de findings do recon."""
    findings = []
    for r in arjun_results:
        findings.append({
            "type": "hidden_parameters",
            "severity": "medium",
            "title": f"Parâmetros ocultos descobertos ({r['method']})",
            "description": (
                f"Arjun descobriu {r['param_count']} parâmetro(s) oculto(s) via "
                f"{r['method']} em {r['url']}: {', '.join(r['params'][:10])}"
            ),
            "evidence": f"Params: {', '.join(r['params'][:20])}",
            "url": r["url"],
            "method": r["method"],
            "params": r["params"],
            "tool": "arjun",
            "remediation": (
                "Revise cada parâmetro descoberto para injeção (SQLi, XSS, SSRF, IDOR). "
                "Parâmetros ocultos frequentemente contornam validações do frontend."
            ),
        })
    return findings


# ---------------------------------------------------------------------------
# Orchestrator: run all advanced HTTP checks on a single URL
# ---------------------------------------------------------------------------
def run_advanced_http_checks(
    url: str,
    domain: str,
    resp: requests.Response,
    headers: dict[str, str],
) -> list[dict[str, str]]:
    """Run SSTI, CRLF, Host Header, JWT, and S3 Bucket checks.

    Returns list of findings in the standard format.
    """
    all_findings: list[dict[str, str]] = []

    for check_fn in [
        lambda: check_ssti(url, headers),
        lambda: check_crlf_injection(url, headers),
        lambda: check_host_header_injection(url, headers),
        lambda: check_jwt_vulnerabilities(resp),
        lambda: check_open_buckets(domain),
    ]:
        try:
            all_findings.extend(check_fn())
        except Exception as e:
            logger.debug("[ADV] Check error: %s", e)

    return all_findings
