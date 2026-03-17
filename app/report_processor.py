"""
Report Processor: Migrate from vuln_results → reports

Etapa crítica que gera relatórios formatados para HackerOne com:
  - Título compelling
  - Descrição técnica detalhada
  - Impacto nos negócios
  - Steps to Reproduce
  - Proof of Concept
  - Recomendações de remediação
  - CVSS score
  - Severity assessment
"""

import logging
import os
from datetime import datetime
from typing import Any

from bson import ObjectId
from pymongo import MongoClient

from app.report_generator import (
    generate_h1_report,
    VULN_TEMPLATES,
)
from app.program_matcher import (
    match_ip_to_programs,
    get_programs_for_report,
    filter_reports_by_eligibility,
)

logger = logging.getLogger("scanner.report_processor")

# MongoDB connection
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin",
)

BATCH_SIZE = int(os.getenv("REPORT_PROCESSOR_BATCH_SIZE", "50"))


def get_db():
    """Get MongoDB database connection."""
    client = MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=3000,
        socketTimeoutMS=10000,
    )
    return client.get_default_database()


def _format_vuln_for_h1(vuln: dict) -> dict[str, Any]:
    """
    Convert enriched vulnerability to H1-compatible format.
    Extrai evidência completa: URL, HTTP request/response, curl command, CVSS.
    
    Args:
        vuln: Enriched vulnerability document from vuln_results
    
    Returns:
        H1-formatted finding dictionary with full evidence chain
    """
    # Construir evidência rica a partir de todos os dados disponíveis
    evidence_parts = []
    if vuln.get("matched_at"):
        evidence_parts.append(f"**Affected URL:** `{vuln['matched_at']}`")
    if vuln.get("proof"):
        evidence_parts.append(f"**Proof:** {vuln['proof']}")
    if vuln.get("evidence"):
        evidence_parts.append(f"**Scanner Evidence:** {vuln['evidence']}")

    # HTTP Request/Response para reprodução
    http_request = vuln.get("http_request", "")
    http_response = vuln.get("http_response", "")
    curl_command = vuln.get("curl_command", "")

    if curl_command:
        evidence_parts.append(f"\n**cURL command to reproduce:**\n```\n{curl_command}\n```")
    if http_request:
        evidence_parts.append(f"\n**HTTP Request:**\n```http\n{http_request[:1500]}\n```")
    if http_response:
        evidence_parts.append(f"\n**HTTP Response (truncated):**\n```http\n{http_response[:1500]}\n```")

    full_evidence = "\n".join(evidence_parts) if evidence_parts else vuln.get("description", "")

    # CVSS: preferir dados reais do scanner sobre templates
    cvss_score = vuln.get("cvss_score", 0)
    cvss_vector = vuln.get("cvss_vector", "")
    if not cvss_score or cvss_score == 0:
        severity_scores = {"critical": 9.8, "high": 8.5, "medium": 5.5, "low": 3.1, "info": 0.0}
        cvss_score = severity_scores.get(vuln.get("severity", "medium"), 5.5)

    return {
        "code": vuln.get("type", vuln.get("template_id", "cve")),
        "title": vuln.get("title", vuln.get("name", f"Vulnerability: {vuln.get('cve_id', 'Unknown')}")),
        "severity": vuln.get("severity", "medium"),
        "description": vuln.get("description", ""),
        "evidence": full_evidence,
        "matched_at": vuln.get("matched_at", ""),
        "curl_command": curl_command,
        "http_request": http_request,
        "http_response": http_response,
        "response_body": http_response,
        "response_headers": "",
        "remediation": vuln.get("remediation", "Apply security updates"),
        "cve_id": vuln.get("cve_id", ""),
        "cwe": vuln.get("cwe", vuln.get("cwe_id", "")),
        "cvss_base": cvss_score,
        "cvss_vector": cvss_vector,
        "confidence": vuln.get("confidence", 0.5),
        "tool": vuln.get("tool", ""),
        "hostname": vuln.get("hostname", ""),
        "references": vuln.get("references", []),
    }


def process_vulnerabilities_to_reports(
    limit: int = 50,
    severity_threshold: str = "low",
) -> dict[str, Any]:
    """
    Process vulns from vuln_results and generate H1 reports in reports collection.
    
    Args:
        limit: Max number of vulnerabilities to process
        severity_threshold: Only process vulns >= this severity
    
    Returns:
        Dictionary with processing results
    """
    
    db = get_db()
    vuln_col = db["vuln_results"]
    report_col = db["reports"]
    
    results = {
        "processed_vulns": 0,
        "reports_generated": 0,
        "errors": 0,
    }
    
    # Severity ranking
    SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    min_rank = SEVERITY_RANK.get(severity_threshold, 0)
    
    try:
        # Get vulnerabilities
        vulns = list(vuln_col.find(
            {"status": "confirmed"},
            sort=[("severity", -1), ("timestamp", -1)]
        ).limit(limit))
        
        if not vulns:
            logger.info("No vulnerabilities to process")
            return results
        
        # Group by IP (will create one report per IP with all its vulns)
        vulns_by_ip = {}
        for vuln in vulns:
            ip = vuln.get("ip", "unknown")
            if ip not in vulns_by_ip:
                vulns_by_ip[ip] = []
            
            # Filter by severity
            severity = vuln.get("severity", "medium")
            if SEVERITY_RANK.get(severity, 0) >= min_rank:
                vulns_by_ip[ip].append(vuln)
                results["processed_vulns"] += 1
        
        # Generate reports for each IP
        for ip, ip_vulns in vulns_by_ip.items():
            if not ip_vulns:
                continue
            
            try:
                # ── Validação IN-SCOPE ──
                # Verificar se o IP/hostname pertence a algum programa bounty
                hostname = ip_vulns[0].get("hostname", "")
                matched_programs = []
                try:
                    matched_programs = match_ip_to_programs(ip)
                    if hostname and not matched_programs:
                        matched_programs = match_ip_to_programs(hostname)
                except Exception as e:
                    logger.debug(f"Program matching skipped for {ip}: {e}")

                # Se não encontrou programa, marcar como "no_program"
                program_name = "Unknown Program"
                program_handle = ""
                in_scope = False
                if matched_programs:
                    prog = matched_programs[0]  # Melhor match
                    program_name = prog.get("name", "Unknown Program")
                    program_handle = prog.get("handle", prog.get("platform_id", ""))
                    in_scope = prog.get("in_scope", True)
                
                # Format findings for H1 (agora com evidência completa)
                findings = [_format_vuln_for_h1(v) for v in ip_vulns]
                
                # Usar hostname real quando disponível
                report_domain = hostname or ip
                
                # Generate H1 report
                h1_report = generate_h1_report(
                    domain=report_domain,
                    findings=findings,
                    program_name=program_name,
                )
                
                # ── Calcular CVSS real ──
                # Preferir CVSS do scanner sobre score genérico
                real_cvss_score = h1_report["cvss_score"]
                real_cvss_vector = h1_report["cvss_vector"]
                for v in ip_vulns:
                    scanner_cvss = v.get("cvss_score", 0)
                    if scanner_cvss and scanner_cvss > real_cvss_score:
                        real_cvss_score = scanner_cvss
                        real_cvss_vector = v.get("cvss_vector", real_cvss_vector)
                
                # Build report document
                report_doc = {
                    # Core report data
                    "ip": ip,
                    "hostname": hostname,
                    "domain": report_domain,
                    "title": h1_report["title"],
                    "body": h1_report["body"],
                    "severity": h1_report["severity"],
                    "impact": h1_report["impact"],
                    "weakness": h1_report["weakness"],
                    "cvss_vector": real_cvss_vector,
                    "cvss_score": real_cvss_score,
                    "confidence": h1_report["confidence"],
                    
                    # Evidência completa para reprodução
                    "evidence": {
                        "matched_urls": [v.get("matched_at", "") for v in ip_vulns if v.get("matched_at")],
                        "curl_commands": [v.get("curl_command", "") for v in ip_vulns if v.get("curl_command")],
                        "http_requests": [v.get("http_request", "")[:1500] for v in ip_vulns if v.get("http_request")],
                        "http_responses": [v.get("http_response", "")[:1500] for v in ip_vulns if v.get("http_response")],
                        "proofs": [v.get("proof", "") for v in ip_vulns if v.get("proof")],
                        "tools_used": list(set(v.get("tool", "") for v in ip_vulns if v.get("tool"))),
                    },
                    
                    # Programa bounty e validação in-scope
                    "program": {
                        "name": program_name,
                        "handle": program_handle,
                        "in_scope": in_scope,
                        "matched": len(matched_programs) > 0,
                    },
                    
                    # Vulnerability references
                    "vulnerability_count": h1_report["findings_count"],
                    "vulnerability_ids": [v.get("_id") for v in ip_vulns],
                    "cve_ids": [v.get("cve_id") for v in ip_vulns if v.get("cve_id")],
                    "cwe_ids": list(set(
                        cwe for v in ip_vulns 
                        for cwe in (v.get("cwe_id", []) if isinstance(v.get("cwe_id"), list) else [v.get("cwe_id", "")])
                        if cwe
                    )),
                    
                    # Status tracking
                    "status": "draft" if in_scope or not matched_programs else "out_of_scope",
                    "auto_submit_eligible": h1_report["auto_submit_eligible"] and in_scope,
                    
                    # Checklist H1 — campos obrigatórios para submissão
                    "h1_readiness": {
                        "has_evidence": bool(any(v.get("matched_at") for v in ip_vulns)),
                        "has_cvss": real_cvss_score > 0,
                        "has_steps_to_reproduce": "## Steps to Reproduce" in h1_report["body"],
                        "has_impact": bool(h1_report["impact"]),
                        "has_remediation": "## Remediation" in h1_report["body"],
                        "is_in_scope": in_scope or not matched_programs,
                        "ready_to_submit": False,  # será calculado abaixo
                    },
                    
                    # Timestamps
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                    "submitted_at": None,
                    
                    # Metadata
                    "tags": [h1_report["severity"], "auto_generated"],
                    "notes": "",
                }
                
                # Calcular readiness final
                readiness = report_doc["h1_readiness"]
                readiness["ready_to_submit"] = all([
                    readiness["has_evidence"],
                    readiness["has_cvss"],
                    readiness["has_steps_to_reproduce"],
                    readiness["has_impact"],
                    readiness["has_remediation"],
                    readiness["is_in_scope"],
                ])
                
                # Insert into reports collection
                result = report_col.insert_one(report_doc)
                logger.info(f"Generated report for {ip}: {result.inserted_id}")
                results["reports_generated"] += 1

                # Update vuln_results to link report
                vuln_col.update_many(
                    {"_id": {"$in": [v.get("_id") for v in ip_vulns]}},
                    {"$set": {"report_id": result.inserted_id}},
                )
                
            except Exception as e:
                results["errors"] += 1
                logger.warning(f"Error generating report for IP {ip}: {e}")
        
        logger.info(f"Generated {results['reports_generated']} reports from {results['processed_vulns']} vulns")
        
    except Exception as e:
        logger.error(f"Error in process_vulnerabilities_to_reports: {e}")
        results["errors"] += 1
    
    return results


def get_processed_reports(
    limit: int = 100,
    status: str = "draft",
    severity: str | None = None,
) -> list[dict]:
    """Get generated reports from reports collection."""
    
    db = get_db()
    report_col = db["reports"]
    
    query = {"status": status}
    if severity:
        query["severity"] = severity
    
    reports = list(report_col.find(query).limit(limit))
    return reports


def mark_report_submitted(report_id: str, submission_id: str = "") -> bool:
    """Mark a report as submitted to HackerOne."""
    
    db = get_db()
    report_col = db["reports"]
    
    try:
        result = report_col.update_one(
            {"_id": ObjectId(report_id)},
            {
                "$set": {
                    "status": "submitted",
                    "submitted_at": datetime.utcnow(),
                    "h1_submission_id": submission_id,
                }
            }
        )
        return result.matched_count > 0
    except Exception as e:
        logger.error(f"Error marking report as submitted: {e}")
        return False


def get_report_stats() -> dict[str, Any]:
    """Get report generation statistics."""
    db = get_db()
    report_col = db["reports"]
    
    total = report_col.count_documents({})
    draft = report_col.count_documents({"status": "draft"})
    submitted = report_col.count_documents({"status": "submitted"})
    
    # Count by severity
    by_severity = {}
    for doc in report_col.aggregate([
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]):
        by_severity[doc["_id"]] = doc["count"]
    
    # Count auto-submit eligible
    auto_eligible = report_col.count_documents({"auto_submit_eligible": True})
    
    return {
        "total_reports": total,
        "draft": draft,
        "submitted": submitted,
        "auto_submit_eligible": auto_eligible,
        "by_severity": by_severity,
    }


if __name__ == "__main__":
    # Test/CLI execution
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "process":
        print("Processing vulnerabilities to reports...")
        results = process_vulnerabilities_to_reports()
        print(f"Processed {results['processed_vulns']} vulnerabilities")
        print(f"Generated {results['reports_generated']} reports")
        print(f"Errors: {results['errors']}")
        
        print("\nReport stats:")
        stats = get_report_stats()
        for key, val in stats.items():
            print(f"  {key}: {val}")
    else:
        print("Usage: python app/report_processor.py process")
