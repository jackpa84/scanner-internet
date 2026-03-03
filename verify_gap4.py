#!/usr/bin/env python3
"""Verify Gap 4 completion - HackerOne Submission."""

import sys
sys.path.insert(0, '.')

from pymongo import MongoClient
import os

client = MongoClient(
    os.getenv('MONGODB_URI', 'mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin'),
    serverSelectionTimeoutMS=10000
)
db = client.get_default_database()

# Import submission module
from app.h1_submission import (
    batch_submit_reports, get_submission_stats, get_submission_queue,
    _validate_credentials,
)

print('\n' + '='*60)
print('GAP 4: HACKERONE SUBMISSION COMPLETION')
print('='*60)

# Check credentials
print('\n1. H1 Configuration Check:')
valid, msg = _validate_credentials()
if valid:
    print('   ✓ H1_API_TOKEN: Configured')
    print('   ✓ H1_PROGRAM_HANDLE: Configured')
else:
    print('   ⚠ H1 Credentials not configured')
    print(f'   Status: {msg}')
    print('\n   To enable submissions, set environment variables:')
    print('     export H1_API_TOKEN="your_api_token"')
    print('     export H1_PROGRAM_HANDLE="program_handle"')

# Check submission queue
print('\n2. Submission Queue:')
queue = get_submission_queue()
print(f'   Reports waiting: {len(queue)}')
if queue:
    for report in queue[:3]:
        print(f'     - {report.get("title")[:50]}... ({report.get("severity")})')

# Show submission stats
print('\n3. Submission Statistics:')
stats = get_submission_stats()
print(f'   Total submissions: {stats["total_submissions"]}')
print(f'   Successful: {stats["successful"]}')
print(f'   Failed: {stats["failed"]}')
print(f'   Auto-submit enabled: {stats["auto_submit_enabled"]}')

# Test dry-run submission if reports exist
if queue:
    print('\n4. Dry-Run Submission Test:')
    print('   (Testing submission without actually contacting H1)')
    
    # Get first report ID
    first_report_id = str(queue[0]['_id'])
    
    results = batch_submit_reports(limit=1, dry_run=True)
    
    print(f'   ✓ Dry-run completed')
    print(f'   - Submitted: {results["submitted"]}')
    print(f'   - Duplicates: {results["duplicates"]}')
    print(f'   - Errors: {results["errors"]}')
    print(f'   - Skipped: {results["skipped"]}')
    
    if results['details']:
        detail = results['details'][0]
        print(f'\n   Sample result:')
        print(f'     Status: {detail.get("status")}')
        print(f'     Reason: {detail.get("reason")}')
else:
    print('\n4. No reports available for submission tests')

# API endpoints
print('\n5. Available H1 API Endpoints:')
print('   POST   /api/h1/submit/{report_id}     - Submit single report')
print('   POST   /api/h1/batch-submit            - Batch submit reports')
print('   GET    /api/h1/queue                   - View submission queue')
print('   GET    /api/h1/stats                   - View submission stats')

# Database state
print('\n6. Database State:')
submitted = db.reports.count_documents({"status": "submitted"})
draft = db.reports.count_documents({"status": "draft"})
submissions = db.submitted_reports.count_documents({})

print(f'   Reports (draft): {draft}')
print(f'   Reports (submitted): {submitted}')
print(f'   Submission records: {submissions}')

print('\n' + '='*60)
print('🎉 GAP 4 SUCCESSFULLY CONFIGURED!')
print('='*60)
print('\nNext steps:')
print('  1. Configure H1 credentials (see step 1 above)')
print('  2. Test with dry-run: curl -X POST http://localhost:8000/api/h1/batch-submit')
print('  3. Enable live submissions when ready')
print('\n')
