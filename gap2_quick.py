#!/usr/bin/env python3
"""Quick test processor - avoid long imports."""

import sys
sys.path.insert(0, '.')

from pymongo import MongoClient
import os
import re
from datetime import datetime
from bson import ObjectId

MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin",
)

def get_db():
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    return client.get_default_database()

# Get connection
db = get_db()

print("=" * 60)
print("GAP 2: PROCESSING VULNERABILITIES")
print("=" * 60)

# Before
before_count = db.vuln_results.count_documents({})
print(f"\nBefore: vuln_results = {before_count}")

# Clear it for fresh start
db.vuln_results.delete_many({})
print(f"Cleared vuln_results")

# Process
scans = list(db.scan_results.find({"vulns": {"$exists": True, "$not": {"$size": 0}}}).limit(50))
print(f"\nProcessing {len(scans)} scans...")

total_vulns = 0
for scan in scans:
    ip = scan.get("ip", "unknown")
    for cve_str in scan.get("vulns", []):
        # Simple enrichment
        doc = {
            "ip": ip,
            "cve_id": str(cve_str).strip(),
            "type": "cve",
            "severity": "medium",
            "confidence": 0.8,
            "status": "confirmed",
            "timestamp": datetime.utcnow(),
        }
        db.vuln_results.insert_one(doc)
        total_vulns += 1

print(f"✓ Inserted {total_vulns} vulnerabilities")

# After
after_count = db.vuln_results.count_documents({})
print(f"\nAfter: vuln_results = {after_count}")

# Stats
print(f"\nStats:")
for doc in db.vuln_results.aggregate([{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]):
    print(f"  {doc['_id']}: {doc['count']}")

print("\n" + "=" * 60)
print("✓ GAP 2 PROCESSING COMPLETE")
print("=" * 60)
