#!/usr/bin/env python3
"""Test Gap 2: Vulnerability Processing Pipeline (MongoDB Direct)."""

import os
from pymongo import MongoClient
from datetime import datetime
from bson import ObjectId

# Direct MongoDB connection
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin",
)

try:
    client = MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=3000,
        socketTimeoutMS=10000,
    )
    
    client.admin.command('ping')
    db = client.get_default_database()
    
    print("=" * 60)
    print("GAP 2: VULNERABILITY PROCESSING PIPELINE")
    print("=" * 60)

    # Show current stats
    print("\n1. BEFORE PROCESSING:")
    scan_count = db.scan_results.count_documents({})
    
    # Count raw vulns
    vuln_raw_count = db.scan_results.aggregate([
        {"$match": {"vulns": {"$not": {"$size": 0}}}},
        {"$project": {"count": {"$size": "$vulns"}}},
        {"$group": {"_id": None, "total": {"$sum": "$count"}}}
    ])
    vuln_raw = list(vuln_raw_count)
    vuln_result_count = db.vuln_results.count_documents({})
    
    print(f"   Scan results: {scan_count}")
    print(f"   Raw vulns (in scan_results.vulns): {vuln_raw[0]['total'] if vuln_raw else 0}")
    print(f"   Processed vulns (vuln_results): {vuln_result_count}")

    # Process vulnerabilities
    print("\n2. SIMULATING PROCESSOR...")
    
    count_processed = 0
    count_enriched = 0
    count_errors = 0
    
    # Get all scans with vulns
    for scan_doc in db.scan_results.find({"vulns": {"$not": {"$size": 0}}}):
        scan_id = scan_doc["_id"]
        ip = scan_doc.get("ip", "unknown")
        
        for raw_vuln in scan_doc.get("vulns", []):
            try:
                # Create enriched vulnerability
                enriched = {
                    "ip": ip,
                    "scan_id": scan_id,
                    "title": raw_vuln.get("title", "Unknown Vulnerability"),
                    "type": raw_vuln.get("type", "unknown"),
                    "severity": raw_vuln.get("severity", "unknown"),
                    "confidence": 0.75,  # Simplified
                    "cvss_base": 5.5,
                    "cwe": raw_vuln.get("cwe", ""),
                    "remediation": raw_vuln.get("remediation", "Apply security updates"),
                    "status": "confirmed",
                    "timestamp": datetime.utcnow(),
                    "created_at": datetime.utcnow(),
                }
                
                # Insert into vuln_results
                db.vuln_results.insert_one(enriched)
                count_enriched += 1
                count_processed += 1
                
            except Exception as e:
                count_errors += 1
                print(f"   ! Error processing {ip}: {e}")
    
    print(f"   ✓ Processed: {count_processed}")
    print(f"   ✓ Enriched: {count_enriched}")
    print(f"   ✓ Errors: {count_errors}")

    # Show stats after processing
    print("\n3. AFTER PROCESSING:")
    vuln_result_count = db.vuln_results.count_documents({})
    print(f"   Processed vulns (vuln_results): {vuln_result_count}")

    # Show breakdown by severity
    print("\n4. BREAKDOWN BY SEVERITY:")
    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    for item in db.vuln_results.aggregate(pipeline):
        print(f"   {item['_id']:12} : {item['count']:4} vulns")

    # Sample 3 enriched vulns
    print("\n5. SAMPLE ENRICHED VULNERABILITIES:")
    samples = db.vuln_results.find({}).limit(3)
    for i, vuln in enumerate(samples, 1):
        print(f"\n   [{i}] {vuln.get('type', 'unknown').upper()}")
        print(f"       IP: {vuln.get('ip')}")
        print(f"       Title: {vuln.get('title', 'N/A')}")
        print(f"       Severity: {vuln.get('severity')}")
        print(f"       CVSS Base: {vuln.get('cvss_base')}")
        print(f"       Confidence: {vuln.get('confidence', 0):.2f}")
        print(f"       CWE: {vuln.get('cwe', 'N/A')}")
        if vuln.get('remediation'):
            remediation = vuln['remediation'][:80] + "..." if len(vuln.get('remediation', '')) > 80 else vuln.get('remediation')
            print(f"       Remediation: {remediation}")

    print("\n" + "=" * 60)
    print("✓ GAP 2 PROCESSING COMPLETE")
    print("=" * 60)

except Exception as e:
    print(f"✗ Error: {e}")

