#!/usr/bin/env python3
"""Inspect the structure of vulnerabilities in scan_results."""

import os
from pymongo import MongoClient
import json

MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin",
)

try:
    client = MongoClient(MONGODB_URI)
    db = client.get_default_database()
    
    # Get a single scan with vulns
    scan = db.scan_results.find_one({"vulns": {"$exists": True, "$not": {"$size": 0}}})
    
    if scan:
        print("=" * 60)
        print("STRUCTURE OF scan_results DOCUMENT")
        print("=" * 60)
        
        print(f"\nDocument keys: {list(scan.keys())}")
        print(f"\nVulns type: {type(scan['vulns'])}")
        print(f"Vulns count: {len(scan['vulns'])}")
        
        if scan['vulns']:
            print(f"\nFirst item type: {type(scan['vulns'][0])}")
            print(f"First 3 items:")
            for i, item in enumerate(scan['vulns'][:3]):
                print(f"\n[{i}] Type: {type(item)}")
                if isinstance(item, dict):
                    print(f"    Keys: {list(item.keys())}")
                    print(f"    Content: {json.dumps(item, indent=6, default=str)[:300]}")
                else:
                    print(f"    Value: {str(item)[:200]}")

except Exception as e:
    print(f"Error: {e}")
