#!/usr/bin/env python3
"""
Seed MongoDB with realistic mock HackerOne programs, targets with alive hosts,
recon_checks findings and evidence — ready to test the full submit-to-HackerOne flow.

Usage:
    python3 scripts/seed_mock_hackerone.py [--mongodb-uri URI]

Default URI: mongodb://user:password@localhost:27017/scanner_db?authSource=admin
"""

import argparse
import os
from datetime import datetime, timedelta

from bson import ObjectId
from pymongo import MongoClient

DEFAULT_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://user:password@localhost:27017/scanner_db?authSource=admin",
)

MOCK_PROGRAMS = [
    {
        "name": "Acme Corp",
        "platform": "hackerone",
        "url": "https://hackerone.com/acme_corp",
        "in_scope": ["*.acme.com", "*.api.acme.com", "acme.com"],
        "out_of_scope": ["blog.acme.com", "status.acme.com"],
        "targets": [
            {
                "domain": "app.acme.com",
                "ips": ["104.18.22.55", "104.18.23.55"],
                "alive": True,
                "status": "probed",
                "httpx": {
                    "url": "https://app.acme.com",
                    "host": "app.acme.com",
                    "status_code": 200,
                    "title": "Acme Dashboard",
                    "tech": ["React", "nginx", "Node.js"],
                    "cdn": False,
                    "webserver": "nginx/1.24.0",
                },
                "recon_checks": {
                    "checked": True,
                    "risk_score": 62,
                    "high": 1,
                    "medium": 2,
                    "low": 1,
                    "total_findings": 4,
                    "findings": [
                        {
                            "severity": "high",
                            "code": "cors_credentials_wildcard",
                            "title": "CORS permissivo com credenciais",
                            "evidence": "Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true",
                        },
                        {
                            "severity": "medium",
                            "code": "missing_hsts",
                            "title": "Cabecalho HSTS ausente",
                            "evidence": "",
                        },
                        {
                            "severity": "medium",
                            "code": "missing_csp",
                            "title": "Cabecalho CSP ausente",
                            "evidence": "",
                        },
                        {
                            "severity": "low",
                            "code": "missing_xcto",
                            "title": "Cabecalho X-Content-Type-Options ausente",
                            "evidence": "",
                        },
                    ],
                },
            },
            {
                "domain": "api.acme.com",
                "ips": ["104.18.24.55"],
                "alive": True,
                "status": "probed",
                "httpx": {
                    "url": "https://api.acme.com",
                    "host": "api.acme.com",
                    "status_code": 200,
                    "title": "Acme API v2",
                    "tech": ["Express", "Node.js"],
                    "cdn": False,
                    "webserver": "Express",
                },
                "recon_checks": {
                    "checked": True,
                    "risk_score": 75,
                    "high": 2,
                    "medium": 1,
                    "low": 0,
                    "total_findings": 3,
                    "findings": [
                        {
                            "severity": "high",
                            "code": "git_head_exposed",
                            "title": "Repositorio .git exposto",
                            "evidence": "https://api.acme.com/.git/HEAD retornou refs/heads/main",
                        },
                        {
                            "severity": "high",
                            "code": "cors_credentials_wildcard",
                            "title": "CORS permissivo com credenciais",
                            "evidence": "Access-Control-Allow-Origin: * + Credentials: true",
                        },
                        {
                            "severity": "medium",
                            "code": "trace_enabled",
                            "title": "Metodo TRACE habilitado",
                            "evidence": "Allow: GET, POST, OPTIONS, TRACE",
                        },
                    ],
                },
            },
            {
                "domain": "staging.acme.com",
                "ips": ["10.0.1.50"],
                "alive": True,
                "status": "probed",
                "httpx": {
                    "url": "http://staging.acme.com",
                    "host": "staging.acme.com",
                    "status_code": 200,
                    "title": "Acme Staging",
                    "tech": ["PHP", "Apache"],
                    "cdn": False,
                    "webserver": "Apache/2.4.57",
                },
                "recon_checks": {
                    "checked": True,
                    "risk_score": 50,
                    "high": 1,
                    "medium": 2,
                    "low": 0,
                    "total_findings": 3,
                    "findings": [
                        {
                            "severity": "high",
                            "code": "no_https",
                            "title": "Endpoint ativo sem HTTPS",
                            "evidence": "http://staging.acme.com responde sem TLS",
                        },
                        {
                            "severity": "medium",
                            "code": "exposed_phpmyadmin",
                            "title": "Painel phpMyAdmin aparente",
                            "evidence": "Titulo da pagina contem 'phpMyAdmin'",
                        },
                        {
                            "severity": "medium",
                            "code": "server_status_exposed",
                            "title": "Endpoint /server-status acessivel",
                            "evidence": "http://staging.acme.com/server-status retornou 200",
                        },
                    ],
                },
            },
            {
                "domain": "mail.acme.com",
                "ips": ["104.18.30.55"],
                "alive": False,
                "status": "resolved",
                "httpx": {},
                "recon_checks": {"checked": False, "total_findings": 0, "findings": []},
            },
        ],
    },
    {
        "name": "GlobalBank Security",
        "platform": "hackerone",
        "url": "https://hackerone.com/globalbank",
        "in_scope": ["*.globalbank.com", "*.gb-api.com"],
        "out_of_scope": ["careers.globalbank.com"],
        "targets": [
            {
                "domain": "portal.globalbank.com",
                "ips": ["203.0.113.10"],
                "alive": True,
                "status": "probed",
                "httpx": {
                    "url": "https://portal.globalbank.com",
                    "host": "portal.globalbank.com",
                    "status_code": 200,
                    "title": "GlobalBank Client Portal",
                    "tech": ["Angular", "Java", "Cloudflare"],
                    "cdn": True,
                    "webserver": "cloudflare",
                },
                "recon_checks": {
                    "checked": True,
                    "risk_score": 37,
                    "high": 0,
                    "medium": 3,
                    "low": 1,
                    "total_findings": 4,
                    "findings": [
                        {
                            "severity": "medium",
                            "code": "missing_csp",
                            "title": "Cabecalho CSP ausente",
                            "evidence": "Response headers nao contem Content-Security-Policy",
                        },
                        {
                            "severity": "medium",
                            "code": "missing_hsts",
                            "title": "Cabecalho HSTS ausente",
                            "evidence": "Response headers nao contem Strict-Transport-Security",
                        },
                        {
                            "severity": "medium",
                            "code": "actuator_health_exposed",
                            "title": "Endpoint actuator health exposto",
                            "evidence": "https://portal.globalbank.com/actuator/health retornou {\"status\":\"UP\"}",
                        },
                        {
                            "severity": "low",
                            "code": "missing_referrer_policy",
                            "title": "Cabecalho Referrer-Policy ausente",
                            "evidence": "",
                        },
                    ],
                },
            },
            {
                "domain": "api.gb-api.com",
                "ips": ["203.0.113.20"],
                "alive": True,
                "status": "probed",
                "httpx": {
                    "url": "https://api.gb-api.com",
                    "host": "api.gb-api.com",
                    "status_code": 200,
                    "title": "GB API Gateway",
                    "tech": ["Kong", "Lua"],
                    "cdn": False,
                    "webserver": "kong/3.4.0",
                },
                "recon_checks": {
                    "checked": True,
                    "risk_score": 85,
                    "high": 2,
                    "medium": 1,
                    "low": 0,
                    "total_findings": 3,
                    "findings": [
                        {
                            "severity": "high",
                            "code": "cors_credentials_wildcard",
                            "title": "CORS permissivo com credenciais",
                            "evidence": "Access-Control-Allow-Origin: * com Access-Control-Allow-Credentials: true",
                        },
                        {
                            "severity": "high",
                            "code": "git_head_exposed",
                            "title": "Repositorio .git exposto",
                            "evidence": "https://api.gb-api.com/.git/HEAD retornou ref: refs/heads/develop",
                        },
                        {
                            "severity": "medium",
                            "code": "trace_enabled",
                            "title": "Metodo TRACE habilitado",
                            "evidence": "Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE",
                        },
                    ],
                },
            },
        ],
    },
    {
        "name": "CloudSync Technologies",
        "platform": "hackerone",
        "url": "https://hackerone.com/cloudsync",
        "in_scope": ["*.cloudsync.io", "cloudsync.io"],
        "out_of_scope": ["docs.cloudsync.io"],
        "targets": [
            {
                "domain": "app.cloudsync.io",
                "ips": ["198.51.100.5"],
                "alive": True,
                "status": "probed",
                "httpx": {
                    "url": "https://app.cloudsync.io",
                    "host": "app.cloudsync.io",
                    "status_code": 200,
                    "title": "CloudSync - File Sync & Share",
                    "tech": ["Vue.js", "Go", "Cloudflare"],
                    "cdn": True,
                    "webserver": "cloudflare",
                },
                "recon_checks": {
                    "checked": True,
                    "risk_score": 92,
                    "high": 3,
                    "medium": 1,
                    "low": 0,
                    "total_findings": 4,
                    "findings": [
                        {
                            "severity": "high",
                            "code": "cors_credentials_wildcard",
                            "title": "CORS permissivo com credenciais",
                            "evidence": "Access-Control-Allow-Origin: * + Credentials: true em /api/v1/files",
                        },
                        {
                            "severity": "high",
                            "code": "git_head_exposed",
                            "title": "Repositorio .git exposto",
                            "evidence": "https://app.cloudsync.io/.git/HEAD contem refs/heads/production",
                        },
                        {
                            "severity": "high",
                            "code": "exposed_grafana",
                            "title": "Painel Grafana aparente",
                            "evidence": "https://app.cloudsync.io:3000 retornou titulo Grafana com login padrao",
                        },
                        {
                            "severity": "medium",
                            "code": "security_headers_missing",
                            "title": "Headers de seguranca ausentes",
                            "evidence": "Faltam CSP, HSTS, X-Frame-Options",
                        },
                    ],
                },
            },
            {
                "domain": "admin.cloudsync.io",
                "ips": ["198.51.100.10"],
                "alive": True,
                "status": "probed",
                "httpx": {
                    "url": "https://admin.cloudsync.io",
                    "host": "admin.cloudsync.io",
                    "status_code": 401,
                    "title": "Admin Panel - Login Required",
                    "tech": ["React", "Python", "Django"],
                    "cdn": False,
                    "webserver": "gunicorn",
                },
                "recon_checks": {
                    "checked": True,
                    "risk_score": 25,
                    "high": 0,
                    "medium": 2,
                    "low": 1,
                    "total_findings": 3,
                    "findings": [
                        {
                            "severity": "medium",
                            "code": "missing_hsts",
                            "title": "Cabecalho HSTS ausente",
                            "evidence": "Strict-Transport-Security nao presente nos headers",
                        },
                        {
                            "severity": "medium",
                            "code": "missing_csp",
                            "title": "Cabecalho CSP ausente",
                            "evidence": "Content-Security-Policy nao presente nos headers",
                        },
                        {
                            "severity": "low",
                            "code": "missing_xfo",
                            "title": "Cabecalho X-Frame-Options ausente",
                            "evidence": "",
                        },
                    ],
                },
            },
        ],
    },
]


def seed(uri: str):
    client = MongoClient(uri)
    db = client.get_database()
    programs_col = db["bounty_programs"]
    targets_col = db["bounty_targets"]

    inserted_programs = 0
    inserted_targets = 0

    for mock in MOCK_PROGRAMS:
        existing = programs_col.find_one({"name": mock["name"], "url": mock["url"]})
        if existing:
            print(f"  [skip] '{mock['name']}' ja existe")
            continue

        now = datetime.utcnow()
        program_doc = {
            "name": mock["name"],
            "platform": mock["platform"],
            "url": mock["url"],
            "in_scope": mock["in_scope"],
            "out_of_scope": mock["out_of_scope"],
            "status": "active",
            "created_at": now - timedelta(hours=2),
            "last_recon": now - timedelta(minutes=15),
            "last_recon_start": now - timedelta(minutes=20),
            "first_recon_at": now - timedelta(hours=1),
            "stats": {
                "subdomains": len(mock["targets"]) + 10,
                "resolved": len(mock["targets"]),
                "alive": sum(1 for t in mock["targets"] if t["alive"]),
            },
        }
        result = programs_col.insert_one(program_doc)
        program_id = result.inserted_id
        inserted_programs += 1
        print(f"  [+] Programa '{mock['name']}' → {program_id}")

        for t in mock["targets"]:
            target_doc = {
                "program_id": program_id,
                "domain": t["domain"],
                "ips": t["ips"],
                "alive": t["alive"],
                "status": t["status"],
                "httpx": t["httpx"],
                "recon_checks": t["recon_checks"],
                "http_scanner": [],
                "last_recon": now - timedelta(minutes=15),
            }
            targets_col.update_one(
                {"program_id": program_id, "domain": t["domain"]},
                {"$set": target_doc},
                upsert=True,
            )
            inserted_targets += 1
            findings = t["recon_checks"].get("total_findings", 0)
            high = t["recon_checks"].get("high", 0)
            status = "VIVO" if t["alive"] else "morto"
            print(f"       target {t['domain']} [{status}] findings={findings} high={high}")

    print(f"\nMock seed completo: {inserted_programs} programas, {inserted_targets} targets inseridos")
    print("Programas com botao 'Enviar ao H1' habilitado:")
    for mock in MOCK_PROGRAMS:
        for t in mock["targets"]:
            if not t["alive"]:
                continue
            findings = t["recon_checks"].get("findings", [])
            has_title = any((f.get("title") or "").strip() for f in findings)
            has_evidence = any((f.get("evidence") or "").strip() for f in findings)
            if findings and has_title and has_evidence:
                print(f"  ✓ {mock['name']} → {t['domain']} (score={t['recon_checks']['risk_score']}, high={t['recon_checks']['high']})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed mock HackerOne programs")
    parser.add_argument("--mongodb-uri", default=DEFAULT_URI, help="MongoDB URI")
    args = parser.parse_args()
    print(f"Conectando em: {args.mongodb_uri.split('@')[0]}@***")
    seed(args.mongodb_uri)
