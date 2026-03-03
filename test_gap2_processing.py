#!/usr/bin/env python3
"""Test Gap 2: Vulnerability Processing Pipeline."""

from app.vuln_processor import (
    process_scan_vulnerabilities,
    deduplicate_vulnerabilities,
    get_processed_vulnerabilities,
    get_processor_stats,
)
from app.database import get_scan_results, get_vuln_results


def main():
    """Run Gap 2 vulnerability processing."""
    print("=" * 60)
    print("GAP 2: VULNERABILITY PROCESSING PIPELINE")
    print("=" * 60)

    # Get collections
    scan_results = get_scan_results()
    vuln_results = get_vuln_results()

    # Show current stats
    print("\n1. BEFORE PROCESSING:")
    scans = scan_results.find({})
    scan_count = len(scans)
    
    # Count raw vulns
    vuln_raw = 0
    for scan in scans:
        vulns = scan.get("vulns", [])
        vuln_raw += len(vulns) if isinstance(vulns, list) else 0
    
    vuln_result_count = len(vuln_results.find({}))
    
    print(f"   Scan results: {scan_count}")
    print(f"   Raw vulns (in scan_results.vulns): {vuln_raw}")
    print(f"   Processed vulns (vuln_results): {vuln_result_count}")

    # Process vulnerabilities
    print("\n2. RUNNING PROCESSOR...")
    results = process_scan_vulnerabilities(batch_size=100)
    
    print(f"   ✓ Processed scans: {results['processed_scans']}")
    print(f"   ✓ Processed vulns: {results['processed_vulns']}")
    print(f"   ✓ Enriched: {results['enriched']}")
    print(f"   ✓ Skipped (duplicates): {results['skipped_duplicates']}")
    print(f"   ✓ Errors: {results['errors']}")

    # Show stats after processing
    print("\n3. AFTER FIRST PROCESSING:")
    vuln_result_count = len(vuln_results.find({}))
    print(f"   Processed vulns (vuln_results): {vuln_result_count}")

    # Deduplicate
    print("\n4. RUNNING DEDUPLICATION...")
    dedup = deduplicate_vulnerabilities()
    print(f"   ✓ Total vulns: {dedup['total_vulns']}")
    print(f"   ✓ Duplicates found: {dedup['duplicates_found']}")
    print(f"   ✓ Removed: {dedup['removed']}")

    # Show final stats
    print("\n5. AFTER DEDUPLICATION:")
    vuln_result_count = len(vuln_results.find({}))
    print(f"   Processed vulns (vuln_results): {vuln_result_count}")

    # Show breakdown by severity
    print("\n6. BREAKDOWN BY SEVERITY:")
    all_vulns = vuln_results.find({})
    severity_count = {}
    for vuln in all_vulns:
        severity = vuln.get("severity", "unknown")
        severity_count[severity] = severity_count.get(severity, 0) + 1
    
    for severity in sorted(severity_count.keys(), key=lambda x: severity_count[x], reverse=True):
        print(f"   {severity:12} : {severity_count[severity]:4} vulns")

    # Show processor stats
    print("\n7. PROCESSOR STATISTICS:")
    stats = get_processor_stats()
    for key, val in stats.items():
        print(f"   {key}: {val}")

    # Sample 3 enriched vulns
    print("\n8. SAMPLE ENRICHED VULNERABILITIES:")
    samples = get_processed_vulnerabilities(limit=3)
    for i, vuln in enumerate(samples, 1):
        print(f"\n   [{i}] {vuln.get('type', 'unknown').upper()}")
        print(f"       IP: {vuln.get('ip')}")
        print(f"       Title: {vuln.get('title', 'N/A')}")
        print(f"       Severity: {vuln.get('severity')}")
        print(f"       CVSS Base: {vuln.get('cvss_base')}")
        print(f"       Confidence: {vuln.get('confidence', 0):.2f}")
        print(f"       CWE: {vuln.get('cwe', 'N/A')}")
        if vuln.get('remediation'):
            remediation = vuln['remediation'][:100] + "..." if len(vuln.get('remediation', '')) > 100 else vuln.get('remediation')
            print(f"       Remediation: {remediation}")

    print("\n" + "=" * 60)
    print("✓ GAP 2 PROCESSING COMPLETE")
    print("=" * 60)
    print("\nNext: Run test_gap3_reporting.py to generate H1-compatible reports")


if __name__ == "__main__":
    main()
