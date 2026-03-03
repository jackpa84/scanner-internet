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

# Try to use Redis, fallback to direct MongoDB if Redis unavailable
try:
    from app.database import get_scan_results, get_vuln_results
    USE_REDIS = True
except Exception:
    USE_REDIS = False
    from pymongo import MongoClient
    MONGODB_URI = os.getenv(
        "MONGODB_URI",
        "mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin",
    )

from app.report_generator import (
    VULN_TEMPLATES,
    calculate_confidence,
    CVSS_BASE_SCORES,
)

logger = logging.getLogger("scanner.vuln_processor")

BATCH_SIZE = int(os.getenv("VULN_PROCESSOR_BATCH_SIZE", "50"))
SKIP_EXISTING = os.getenv("VULN_PROCESSOR_SKIP_EXISTING", "true").lower() in ("1", "true", "yes")

_stats = {
    "processed": 0,
    "enriched": 0,
    "duplicated": 0,
    "errors": 0,
}

# CVE vulnerability severities (simplified database)
CVE_SEVERITY_MAP = {
    "critical": ("critical", 9.0),
    "high": ("high", 7.5),
    "medium": ("medium", 5.5),
    "low": ("low", 3.0),
    "info": ("info", 0.0),
}


def get_processor_stats() -> dict[str, Any]:
    """Get processor statistics."""
    return dict(_stats)


def _parse_cve_string(cve_str: str) -> dict[str, Any]:
    """
    Parse CVE string (e.g., "CVE-2021-12345") and return basic info.
    
    Since we don't have full CVE database, we infer from patterns and templates.
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
    
    Args:
        cve_str: CVE string from scan (e.g., "CVE-2021-12345")
        ip: IP address
        scan_id: ObjectId of scan_results document
    
    Returns:
        Enriched vulnerability document
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
        
        # Confidence & scoring (adjusted for CVE-only data)
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
            "1. Review vulnerability details\n2. Apply security patches\n3. Test thoroughly\n4. Deploy to production")),
        
        # Impact (from template with domain fallback)
        "impact": vuln.get("impact", template.get("impact_template", 
            "This vulnerability could allow attackers to compromise the system.")),
        
        # Source & tracking
        "source": vuln.get("source", "nuclei"),
        "scanner": vuln.get("scanner", "nuclei"),
        "scan_id": scan_id,
        "timestamp": datetime.utcnow(),
        
        # Status
        "status": "confirmed",
        "confirmed_at": datetime.utcnow(),
        
        # Additional metadata
        "tags": [severity, vuln_type, "automated_scan"],
        "metadata": {
            "original_vuln": vuln,
            "enriched_at": datetime.utcnow().isoformat(),
        }
    }
    
    return enriched


def process_scan_vulnerabilities(
    scan_id: str | ObjectId | None = None,
    batch_size: int = BATCH_SIZE,
) -> dict[str, Any]:
    """
    Process vulnerabilities from scan_results and store in vuln_results.
    
    Args:
        scan_id: Optional ObjectId to process specific scan. If None, process all.
        batch_size: Number of scans to process per batch
    
    Returns:
        Dictionary with processing results
    """
    
    scan_col = get_scan_results()
    vuln_col = get_vuln_results()
    
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
                query = {"_id": oid, "vulns": {"$not": {"$size": 0}}}
            except Exception as e:
                logger.error(f"Invalid scan_id: {e}")
                return results
        else:
            query = {"vulns": {"$not": {"$size": 0}}}
        
        scans = list(scan_col.find(query).limit(batch_size))
        
        if not scans:
            logger.info("No scans with vulnerabilities found")
            return results
        
        for scan in scans:
            scan_id = scan["_id"]
            ip = scan.get("ip", "unknown")
            vulns = scan.get("vulns", [])
            
            results["processed_scans"] += 1
            
            for vuln in vulns:
                try:
                    # Skip if already in vuln_results (optional)
                    if SKIP_EXISTING:
                        existing = vuln_col.find_one({
                            "ip": ip,
                            "title": vuln.get("title"),
                            "type": vuln.get("type"),
                        })
                        if existing:
                            results["skipped_duplicates"] += 1
                            continue
                    
                    # Enrich vulnerability
                    enriched = _enrich_vulnerability(vuln, ip, scan_id)
                    
                    # Insert into vuln_results
                    vuln_col.insert_one(enriched)
                    
                    results["processed_vulns"] += 1
                    results["enriched"] += 1
                    _stats["enriched"] += 1
                    
                except Exception as e:
                    logger.error(f"Error processing vuln on {ip}: {e}")
                    results["errors"] += 1
                    _stats["errors"] += 1
        
        _stats["processed"] += results["processed_vulns"]
        logger.info(
            f"Processed {results['processed_scans']} scans, "
            f"{results['processed_vulns']} vulns, "
            f"enriched {results['enriched']}, "
            f"skipped {results['skipped_duplicates']} duplicates"
        )
        
    except Exception as e:
        logger.error(f"Error in process_scan_vulnerabilities: {e}")
        results["errors"] += 1
        _stats["errors"] += 1
    
    return results


def get_processed_vulnerabilities(
    limit: int = 100,
    severity: str | None = None,
    status: str = "confirmed",
) -> list[dict[str, Any]]:
    """
    Get processed vulnerabilities from vuln_results.
    
    Args:
        limit: Maximum results to return
        severity: Filter by severity (critical, high, medium, low, info)
        status: Filter by status (confirmed, pending, false_positive)
    
    Returns:
        List of vulnerability documents
    """
    
    vuln_col = get_vuln_results()
    query = {"status": status}
    
    if severity:
        query["severity"] = severity.lower()
    
    return list(vuln_col.find(query).sort("severity", -1).limit(limit))


def deduplicate_vulnerabilities() -> dict[str, Any]:
    """
    Remove duplicate vulnerabilities from vuln_results.
    
    Duplicates are identified by: ip + title + type
    Keeps the most confident version.
    
    Returns:
        Dictionary with deduplication results
    """
    
    vuln_col = get_vuln_results()
    
    results = {
        "total_vulns": 0,
        "duplicates_found": 0,
        "removed": 0,
    }
    
    try:
        results["total_vulns"] = vuln_col.count_documents({})
        
        # Find duplicates using aggregation
        pipeline = [
            {
                "$group": {
                    "_id": {
                        "ip": "$ip",
                        "title": "$title",
                        "type": "$type",
                    },
                    "count": {"$sum": 1},
                    "ids": {"$push": "$_id"},
                    "max_confidence": {"$max": "$confidence"},
                }
            },
            {"$match": {"count": {"$gt": 1}}}
        ]
        
        duplicates = list(vuln_col.aggregate(pipeline))
        results["duplicates_found"] = len(duplicates)
        
        # Remove duplicates, keeping highest confidence
        for dup_group in duplicates:
            ids = dup_group["ids"]
            max_confidence = dup_group["max_confidence"]
            
            # Find the ID with max confidence
            keep_id = vuln_col.find_one({
                "_id": {"$in": ids},
                "confidence": max_confidence
            })["_id"]
            
            # Delete others
            for id_to_delete in ids:
                if id_to_delete != keep_id:
                    vuln_col.delete_one({"_id": id_to_delete})
                    results["removed"] += 1
        
        logger.info(f"Deduplication: {results['duplicates_found']} groups, {results['removed']} removed")
        
    except Exception as e:
        logger.error(f"Error in deduplicate_vulnerabilities: {e}")
    
    return results


def mark_false_positive(vuln_id: str | ObjectId) -> bool:
    """
    Mark a vulnerability as false positive.
    
    Args:
        vuln_id: Vulnerability ObjectId
    
    Returns:
        True if successful, False otherwise
    """
    
    try:
        vuln_col = get_vuln_results()
        
        if isinstance(vuln_id, str):
            vuln_id = ObjectId(vuln_id)
        
        result = vuln_col.update_one(
            {"_id": vuln_id},
            {
                "$set": {
                    "status": "false_positive",
                    "reviewed_at": datetime.utcnow(),
                }
            }
        )
        
        return result.modified_count > 0
        
    except Exception as e:
        logger.error(f"Error marking false positive: {e}")
        return False


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    print("\n" + "=" * 70)
    print("  Vulnerability Processor: scan_results.vulns → vuln_results")
    print("=" * 70 + "\n")
    
    # Process all vulnerabilities
    results = process_scan_vulnerabilities()
    
    print(f"✅ Processing Results:")
    print(f"   Scans processed:     {results['processed_scans']}")
    print(f"   Vulnerabilities:     {results['processed_vulns']}")
    print(f"   Enriched:            {results['enriched']}")
    print(f"   Duplicates skipped:  {results['skipped_duplicates']}")
    print(f"   Errors:              {results['errors']}")
    print()
    
    # Deduplicate
    dup_results = deduplicate_vulnerabilities()
    print(f"✅ Deduplication Results:")
    print(f"   Total vulns:         {dup_results['total_vulns']}")
    print(f"   Duplicates found:    {dup_results['duplicates_found']}")
    print(f"   Removed:             {dup_results['removed']}")
    print()
    
    # Show sample
    vulns = get_processed_vulnerabilities(limit=3)
    print(f"✅ Sample of Processed Vulnerabilities ({len(vulns)} shown):")
    for vuln in vulns:
        print(f"   • {vuln['title']}")
        print(f"     Severity: {vuln['severity']}, Confidence: {vuln['confidence']}")
    
    print("\n" + "=" * 70)
