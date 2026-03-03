"""
Vulnerability Processor: Migrate from scan_results.vulns → vuln_results

Etapa crítica que enriquece vulnerabilidades brutos com:
  - CVSS Score calculation
  - Proof of Concept formatting
  - Remediation recommendations
  - Confidence scoring
  - CWE/CVE mapping
  
Nota: vulns em scan_results são CVE strings que precisam enriquecimento.
"""

import logging
import os
from datetime import datetime
from typing import Any
import re

from bson import ObjectId
from pymongo import MongoClient

from app.report_generator import (
    VULN_TEMPLATES,
    CVSS_BASE_SCORES,
)

logger = logging.getLogger("scanner.vuln_processor")

# MongoDB connection
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin",
)

BATCH_SIZE = int(os.getenv("VULN_PROCESSOR_BATCH_SIZE", "50"))

def get_db():
    """Get MongoDB database connection."""
    client = MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=3000,
        socketTimeoutMS=10000,
    )
    return client.get_default_database()


def _parse_cve_string(cve_str: str) -> dict[str, Any]:
    """
    Parse CVE string (e.g., "CVE-2021-12345") and return basic info.
    """
    cve_str = str(cve_str).strip()
    
    # Extract CVE ID if present
    cve_match = re.search(r'CVE-\d{4}-\d+', cve_str)
    cve_id = cve_match.group(0) if cve_match else cve_str
    
    # Guess vulnerability type from templates (fallback to "cve")
    vuln_type = "cve"
    for template_key in VULN_TEMPLATES.keys():
        if template_key.lower() in cve_str.lower():
            vuln_type = template_key
            break
    
    return {
        "cve_id": cve_id,
        "type": vuln_type,
        "raw": cve_str,
    }


def _enrich_vulnerability(
    cve_str: str,
    ip: str,
    scan_id: ObjectId,
) -> dict[str, Any]:
    """
    Enrich CVE string with templates, CVSS, PoC, etc.
    """
    
    # Parse CVE string
    parsed = _parse_cve_string(cve_str)
    vuln_type = parsed["type"]
    cve_id = parsed["cve_id"]
    
    # Get template
    template = VULN_TEMPLATES.get(vuln_type, {})
    
    # Infer severity from template or default
    severity = template.get("severity", "medium").lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = "medium"
    
    # Get CVSS base score
    cvss_base = CVSS_BASE_SCORES.get(severity, 5.5)
    
    # Build enriched document
    enriched = {
        # Core vulnerability data
        "ip": ip,
        "title": template.get("title", f"{cve_id}: {vuln_type.upper()}"),
        "severity": severity,
        "type": vuln_type,
        "code": f"cve_{cve_id.replace('-', '_').lower()}",
        "description": template.get("description", f"Vulnerability: {cve_id}"),
        
        # Confidence & scoring
        "confidence": 0.8,  # CVEs are reliable
        "cvss_base": cvss_base,
        "cvss_vector": template.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        
        # CWE/CVE mapping
        "cwe": template.get("weakness", ""),
        "cve_ids": [cve_id],
        
        # Evidence (empty for CVE-only)
        "evidence": "",
        "test_url": "",
        "response": "",
        
        # Remediation (from template)
        "remediation": template.get("remediation", f"Apply security updates for {cve_id}"),
        
        # Impact & status
        "impact": template.get("impact", "Potential compromise"),
        "status": "confirmed",
        
        # Relationships
        "scan_id": scan_id,
        
        # Timestamps
        "timestamp": datetime.utcnow(),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    
    return enriched


def process_scan_vulnerabilities(
    scan_id: str | ObjectId | None = None,
    batch_size: int = BATCH_SIZE,
) -> dict[str, Any]:
    """
    Process vulnerabilities from scan_results and store in vuln_results.
    """
    
    db = get_db()
    scan_col = db["scan_results"]
    vuln_col = db["vuln_results"]
    
    results = {
        "processed_scans": 0,
        "processed_vulns": 0,
        "enriched": 0,
        "skipped_duplicates": 0,
        "errors": 0,
    }
    
    try:
        # Find scans with vulnerabilities
        if scan_id:
            try:
                oid = ObjectId(scan_id) if isinstance(scan_id, str) else scan_id
                query = {"_id": oid, "vulns": {"$exists": True, "$not": {"$size": 0}}}
            except Exception as e:
                logger.error(f"Invalid scan_id: {e}")
                return results
        else:
            query = {"vulns": {"$exists": True, "$not": {"$size": 0}}}
        
        scans = list(scan_col.find(query).limit(batch_size))
        
        if not scans:
            logger.info("No scans with vulnerabilities found")
            return results
        
        for scan in scans:
            scan_oid = scan["_id"]
            ip = scan.get("ip", "unknown")
            vulns = scan.get("vulns", [])
            
            results["processed_scans"] += 1
            
            for vuln_cve in vulns:
                # vuln_cve is a string (CVE ID)
                try:
                    # Enrich vulnerability
                    enriched = _enrich_vulnerability(vuln_cve, ip, scan_oid)
                    
                    # Insert into vuln_results
                    vuln_col.insert_one(enriched)
                    results["enriched"] += 1
                    results["processed_vulns"] += 1
                    
                except Exception as e:
                    results["errors"] += 1
                    logger.warning(f"Error processing CVE {vuln_cve} for IP {ip}: {e}")
        
        logger.info(f"Processed {results['processed_vulns']} vulns from {results['processed_scans']} scans")
        
    except Exception as e:
        logger.error(f"Error in process_scan_vulnerabilities: {e}")
        results["errors"] += 1
    
    return results


def deduplicate_vulnerabilities() -> dict[str, Any]:
    """Remove duplicate vulnerabilities from vuln_results."""
    
    db = get_db()
    vuln_col = db["vuln_results"]
    
    results = {
        "total_vulns": 0,
        "duplicates_found": 0,
        "removed": 0,
    }
    
    try:
        results["total_vulns"] = vuln_col.count_documents({})
        
        # Find duplicates by (ip, title, type)
        pipeline = [
            {
                "$group": {
                    "_id": {"ip": "$ip", "title": "$title", "type": "$type"},
                    "ids": {"$push": "$_id"},
                    "count": {"$sum": 1}
                }
            },
            {"$match": {"count": {"$gt": 1}}}
        ]
        
        duplicates = list(vuln_col.aggregate(pipeline))
        results["duplicates_found"] = len(duplicates)
        
        # Remove duplicates (keep first, delete rest)
        for dup in duplicates:
            ids = dup["ids"]
            # Keep first, delete the rest
            for dup_id in ids[1:]:
                vuln_col.delete_one({"_id": dup_id})
                results["removed"] += 1
        
        logger.info(f"Removed {results['removed']} duplicate vulnerabilities")
        
    except Exception as e:
        logger.error(f"Error in deduplicate_vulnerabilities: {e}")
    
    return results


def get_processed_vulnerabilities(
    limit: int = 100,
    severity: str | None = None,
    status: str = "confirmed"
) -> list[dict]:
    """Get processed vulnerabilities from vuln_results."""
    
    db = get_db()
    vuln_col = db["vuln_results"]
    
    query = {"status": status}
    if severity:
        query["severity"] = severity
    
    vulns = list(vuln_col.find(query).limit(limit))
    return vulns


def mark_false_positive(vuln_id: str) -> bool:
    """Mark a vulnerability as false positive."""
    
    db = get_db()
    vuln_col = db["vuln_results"]
    
    try:
        result = vuln_col.update_one(
            {"_id": ObjectId(vuln_id)},
            {"$set": {"status": "false_positive", "updated_at": datetime.utcnow()}}
        )
        return result.matched_count > 0
    except Exception as e:
        logger.error(f"Error marking false positive: {e}")
        return False


def get_processor_stats() -> dict[str, Any]:
    """Get processor statistics."""
    db = get_db()
    vuln_col = db["vuln_results"]
    
    total = vuln_col.count_documents({})
    confirmed = vuln_col.count_documents({"status": "confirmed"})
    false_positives = vuln_col.count_documents({"status": "false_positive"})
    
    # Count by severity
    by_severity = {}
    for doc in vuln_col.aggregate([
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]):
        by_severity[doc["_id"]] = doc["count"]
    
    return {
        "total_vulns": total,
        "confirmed": confirmed,
        "false_positives": false_positives,
        "by_severity": by_severity,
    }


if __name__ == "__main__":
    # Test/CLI execution
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "process":
        print("Processing vulnerabilities...")
        results = process_scan_vulnerabilities()
        print(f"Processed {results['processed_vulns']} vulnerabilities")
        print(f"Enriched: {results['enriched']}")
        print(f"Errors: {results['errors']}")
        
        print("\nDeduplicating...")
        dedup = deduplicate_vulnerabilities()
        print(f"Removed {dedup['removed']} duplicates")
        
        print("\nProcessor stats:")
        stats = get_processor_stats()
        for key, val in stats.items():
            print(f"  {key}: {val}")
    else:
        print("Usage: python app/vuln_processor_v2.py process")
