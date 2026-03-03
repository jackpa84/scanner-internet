#!/usr/bin/env python
"""
Verify Gap 1: Bounty Program Targeting

Tests:
  1. Import bounty programs (or mock data)
  2. Match discovered IPs against program scopes
  3. Build IP → programs mapping
  4. Enrich vulnerabilities with program eligibility
  5. Filter reports by program eligibility
"""

import sys
import os
import time

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

from app.database import init_db, get_bounty_programs, get_scan_results, get_vuln_results
from app.program_matcher import (
    match_ip_to_programs,
    build_ip_program_mapping,
    enrich_vulns_with_programs,
    filter_reports_by_eligibility,
    get_matcher_stats,
)

print("\n" + "=" * 80)
print("GAP 1: BOUNTY PROGRAM TARGETING VERIFICATION")
print("=" * 80 + "\n")

try:
    # Initialize database
    print("1. Initializing database...")
    init_db()
    print("   ✓ Database initialized\n")

    # Check if programs exist
    print("2. Checking bounty programs...")
    prog_col = get_bounty_programs()
    programs = prog_col.find() if hasattr(prog_col, "find") else []
    program_count = len(list(programs)) if hasattr(programs, "__len__") else 0
    
    if program_count == 0:
        print("   ⚠  No programs found in bounty_programs collection")
        print("   This is expected if programs haven't been imported yet")
        print("   → Run: curl -X POST http://localhost:8000/api/bounty-data/sync\n")
    else:
        print(f"   ✓ Found {program_count} programs\n")

    # Check if IPs exist to match
    print("3. Checking discovered IPs...")
    scan_col = get_scan_results()
    scan_docs = scan_col.find() if hasattr(scan_col, "find") else []
    scan_count = len(list(scan_docs)) if hasattr(scan_docs, "__len__") else 0
    
    if scan_count == 0:
        print("   ⚠  No IPs found in scan_results collection")
        print("   Skipping IP matching test\n")
    else:
        print(f"   ✓ Found {scan_count} discovered IPs\n")

        # Test matching for first IP
        print("4. Testing IP matching...")
        sample_ip = None
        for doc in scan_col.find():
            sample_ip = doc.get("ip")
            if sample_ip:
                break

        if sample_ip:
            print(f"   Testing with IP: {sample_ip}")
            programs = match_ip_to_programs(sample_ip)
            if programs:
                print(f"   ✓ Found {len(programs)} eligible program(s):")
                for prog in programs:
                    print(f"      - {prog['platform']}: {prog['name']} (match: {prog['scope_match']})")
            else:
                print(f"   ℹ  No eligible programs found for {sample_ip}")
            print()

    # Test IP-to-program mapping build
    print("5. Testing IP-program mapping build...")
    if scan_count > 0 and program_count > 0:
        print("   Building mapping for first 10 IPs...")
        mapping_result = build_ip_program_mapping(limit=10)
        
        ips_matched = mapping_result.get("ips_with_matches", 0)
        total_pairs = mapping_result.get("program_matches", 0)
        unique_progs = mapping_result.get("unique_programs", 0)
        
        print(f"   ✓ IPs with matches: {ips_matched}")
        print(f"   ✓ Total program assignments: {total_pairs}")
        print(f"   ✓ Unique programs matched: {unique_progs}")
        print()
    else:
        print("   ⚠  Insufficient data (need programs and IPs)")
        print()

    # Test vulnerability enrichment
    print("6. Testing vulnerability enrichment with programs...")
    vuln_col = get_vuln_results()
    vuln_docs = vuln_col.find() if hasattr(vuln_col, "find") else []
    vuln_count = len(list(vuln_docs)) if hasattr(vuln_docs, "__len__") else 0
    
    if vuln_count == 0:
        print("   ⚠  No vulnerabilities found in vuln_results")
        print("   Skipping enrichment test\n")
    else:
        print(f"   Found {vuln_count} vulnerabilities")
        if program_count > 0:
            print("   Enriching with program data...")
            enrich_result = enrich_vulns_with_programs(limit=10)
            vulns_processed = enrich_result.get("vulns_processed", 0)
            vulns_with_progs = enrich_result.get("vulns_with_programs", 0)
            assignments = enrich_result.get("program_assignments", 0)
            print(f"   ✓ Vulns processed: {vulns_processed}")
            print(f"   ✓ Vulns with programs: {vulns_with_progs}")
            print(f"   ✓ Program assignments: {assignments}")
        else:
            print("   ⚠  No programs available for enrichment")
        print()

    # Test report filtering
    print("7. Testing report filtering by program eligibility...")
    from app.report_processor import get_processed_reports
    
    reports = get_processed_reports(limit=10)
    if not reports:
        print("   ⚠  No reports found in reports collection")
        print()
    else:
        print(f"   Found {len(reports)} reports")
        if program_count > 0:
            filter_result = filter_reports_by_eligibility(limit=10)
            reports_with_progs = filter_result.get("reports_with_programs", 0)
            ready = filter_result.get("ready_for_submission", [])
            print(f"   ✓ Reports with eligible programs: {reports_with_progs}")
            print(f"   ✓ Ready for submission: {len(ready)}")
            if ready:
                sample = ready[0]
                print(f"   Sample:")
                print(f"      IP: {sample['ip']}")
                print(f"      Programs: {len(sample['programs'])}")
        else:
            print("   ⚠  No programs available for filtering")
        print()

    # Print statistics
    print("8. Program Matcher Statistics:")
    stats = get_matcher_stats()
    print(f"   ✓ Last match: {stats.get('last_match', 'never')}")
    print(f"   ✓ IPs matched: {stats.get('ips_matched', 0)}")
    print(f"   ✓ Programs loaded: {stats.get('programs_loaded', 0)}")
    print(f"   ✓ IP-program pairs: {stats.get('ip_program_pairs', 0)}")
    print(f"   ✓ Errors: {stats.get('errors', 0)}")
    print()

    # Summary
    print("=" * 80)
    if program_count == 0:
        print("❌ GAP 1 TEST INCOMPLETE: No bounty programs found")
        print("\nTo complete Gap 1, you need to:")
        print("1. Import bugbounty programs: curl -X POST http://localhost:8000/api/bounty-data/sync")
        print("2. Then run this verification script again")
        sys.exit(1)
    elif vuln_count == 0:
        print("⚠️  GAP 1 PARTIAL: Programs loaded but no vulnerabilities to match")
        print("\nTo fully test Gap 1:")
        print("1. Ensure vulnerabilities exist in vuln_results collection")
        print("2. Ensure bounty_targets contain program scopes")
        print("3. Run vulnerability enrichment: curl -X POST http://localhost:8000/api/vulns/enrich-with-programs")
        sys.exit(0)
    else:
        print("✅ GAP 1 VERIFICATION COMPLETE")
        print("\nNext steps:")
        print("1. View program matching stats: curl http://localhost:8000/api/programs/matcher/stats")
        print("2. Build IP-program mapping: curl -X POST http://localhost:8000/api/programs/build-mapping")
        print("3. Filter reports: curl http://localhost:8000/api/reports/by-program")
        print("4. View eligible programs: curl http://localhost:8000/api/bounty-data/stats")
        sys.exit(0)

except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
