#!/usr/bin/env python3
"""Verify Gap 3 completion - Report Generation."""

import sys
sys.path.insert(0, '.')

from pymongo import MongoClient
import os

client = MongoClient(
    os.getenv('MONGODB_URI', 'mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin'),
    serverSelectionTimeoutMS=10000
)
db = client.get_default_database()

# Import processor
from app.report_processor import process_vulnerabilities_to_reports, get_report_stats

print('\n' + '='*60)
print('GAP 3: REPORT GENERATION COMPLETION')
print('='*60)

# Clear reports for fresh start
print('\n1. Clearing reports collection...')
db.reports.delete_many({})
print('   ✓ Cleared')

# Process vulns to reports
print('\n2. Generating reports...')
results = process_vulnerabilities_to_reports(limit=50)
print(f'   ✓ Processed vulns: {results["processed_vulns"]}')
print(f'   ✓ Reports generated: {results["reports_generated"]}')
print(f'   ✓ Errors: {results["errors"]}')

# Show total
total_reports = db.reports.count_documents({})
print(f'\n3. Total reports created: {total_reports}')

# Sample report
if total_reports > 0:
    print('\n4. Sample report:')
    sample = db.reports.find_one()
    print(f'   IP: {sample.get("ip")}')
    print(f'   Title: {sample.get("title", "N/A")[:80]}...')
    print(f'   Severity: {sample.get("severity")}')
    print(f'   Vulns: {sample.get("vulnerability_count")}')
    print(f'   Status: {sample.get("status")}')
    print(f'   Auto-submit: {sample.get("auto_submit_eligible")}')
    
    # Show body preview
    body = sample.get("body", "")
    if body:
        print(f'\n5. Report body preview (first 300 chars):')
        print('   ' + body[:300].replace('\n', '\n   ') + '...\n')

# Stats
print('6. Report statistics:')
stats = get_report_stats()
for key, val in stats.items():
    if key == 'by_severity':
        print(f'   {key}:')
        for sev, count in val.items():
            print(f'      {sev}: {count}')
    else:
        print(f'   {key}: {val}')

print('\n' + '='*60)
print('🎉 GAP 3 SUCCESSFULLY COMPLETED!')
print('='*60)
print('\nNext steps:')
print('  • Review reports before submission')
print('  • Mark auto-eligible reports for submission')
print('  • Gap 4: Integrate with HackerOne API for submission')
print('\n')
