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
    
    Args:
        vuln: Enriched vulnerability document from vuln_results
    
    Returns:
        H1-formatted finding dictionary
    """
    return {
        "code": vuln.get("type", "cve"),
        "title": vuln.get("title", f"Vulnerability: {vuln.get('cve_id', 'Unknown')}"),
        "severity": vuln.get("severity", "medium"),
        "description": vuln.get("description", ""),
        "evidence": vuln.get("evidence", ""),
        "remediation": vuln.get("remediation", "Apply security updates"),
        "cve_id": vuln.get("cve_id", ""),
        "cwe": vuln.get("cwe", ""),
        "cvss_base": vuln.get("cvss_base", 5.5),
        "confidence": vuln.get("confidence", 0.5),
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
                # Format findings for H1
                findings = [_format_vuln_for_h1(v) for v in ip_vulns]
                
                # Generate H1 report
                h1_report = generate_h1_report(
                    domain=ip,
                    findings=findings,
                    program_name=f"Security Assessment - {ip}",
                )
                
                # Build report document
                report_doc = {
                    # Core report data
                    "ip": ip,
                    "title": h1_report["title"],
                    "body": h1_report["body"],
                    "severity": h1_report["severity"],
                    "impact": h1_report["impact"],
                    "weakness": h1_report["weakness"],
                    "cvss_vector": h1_report["cvss_vector"],
                    "cvss_score": h1_report["cvss_score"],
                    "confidence": h1_report["confidence"],
                    
                    # Vulnerability references
                    "vulnerability_count": h1_report["findings_count"],
                    "vulnerability_ids": [v.get("_id") for v in ip_vulns],
                    "cve_ids": [v.get("cve_id") for v in ip_vulns if v.get("cve_id")],
                    
                    # Status tracking
                    "status": "draft",
                    "auto_submit_eligible": h1_report["auto_submit_eligible"],
                    
                    # Timestamps
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                    "submitted_at": None,
                    
                    # Metadata
                    "tags": [h1_report["severity"], "auto_generated"],
                    "notes": "",
                }
                
                # Insert into reports collection
                result = report_col.insert_one(report_doc)
                logger.info(f"Generated report for {ip}: {result.inserted_id}")
                results["reports_generated"] += 1
                
                # Update vuln_results to link report
                report_col.update_many(
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
