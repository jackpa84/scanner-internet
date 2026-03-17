"""
HackerOne Submission Module: Submit reports to HackerOne platform.

Handles:
  - H1 API authentication
  - Report submission workflow
  - Duplicate detection
  - Status tracking
  - Error handling and retry logic
"""

import logging
import os
import threading
import time
import requests
from datetime import datetime
from typing import Any
from bson import ObjectId
from pymongo import MongoClient

logger = logging.getLogger("scanner.h1_submission")

# MongoDB connection
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin",
)

# HackerOne configuration – accept either H1_API_TOKEN or HACKERONE_API_TOKEN
H1_API_TOKEN = (os.getenv("H1_API_TOKEN") or os.getenv("HACKERONE_API_TOKEN") or "").strip()
H1_PROGRAM_HANDLE = (os.getenv("H1_PROGRAM_HANDLE") or "").strip()
H1_API_USERNAME = (os.getenv("HACKERONE_API_USERNAME") or "").strip()
H1_API_URL = "https://api.hackerone.com/v1"

# Submission queue settings
RETRY_LIMIT = int(os.getenv("H1_RETRY_LIMIT", "3"))
AUTO_SUBMIT_ENABLED = os.getenv("H1_AUTO_SUBMIT", "true").lower() in ("1", "true", "yes")
AUTO_SUBMIT_INTERVAL = int(os.getenv("H1_AUTO_SUBMIT_INTERVAL", "300"))  # seconds
AUTO_SUBMIT_BATCH = int(os.getenv("H1_AUTO_SUBMIT_BATCH", "10"))
AUTO_SUBMIT_DRY_RUN = os.getenv("H1_AUTO_SUBMIT_DRY_RUN", "false").lower() in ("1", "true", "yes")


def get_db():
    """Get MongoDB database connection."""
    client = MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=3000,
        socketTimeoutMS=10000,
    )
    return client.get_default_database()


def _validate_credentials() -> tuple[bool, str]:
    """Validate H1 API credentials are configured.
    
    Accepts either:
      - H1_API_TOKEN + H1_PROGRAM_HANDLE (bearer/program-specific)
      - HACKERONE_API_TOKEN + HACKERONE_API_USERNAME (basic auth)
    """
    if not H1_API_TOKEN and not H1_API_USERNAME:
        return False, "No HackerOne credentials configured (set HACKERONE_API_TOKEN+HACKERONE_API_USERNAME or H1_API_TOKEN)"
    if H1_API_TOKEN:
        return True, "OK"
    if H1_API_USERNAME:
        return True, "OK (basic auth)"
    return False, "No valid credentials"


def _get_h1_headers() -> dict[str, str]:
    """Get HTTP headers for H1 API requests."""
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {H1_API_TOKEN}",
        "User-Agent": "scanner-internet/1.0",
    }


def _check_duplicate(report_title: str, ip: str, program_handle: str = "") -> dict[str, Any] | None:
    """
    Check if a similar report already exists on H1.

    Returns the existing report if found, None otherwise.
    """
    if not H1_API_TOKEN:
        return None

    handle = program_handle or H1_PROGRAM_HANDLE
    if not handle:
        return None

    try:
        # Query H1 for reports matching this vulnerability
        url = f"{H1_API_URL}/reports"
        params = {
            "filter[program][]": handle,
            "filter[state][]": "new,triaged,needs-more-info,pre-submission",
            "sort": "-created_at",
            "page[size]": 50,
        }
        
        response = requests.get(
            url,
            headers=_get_h1_headers(),
            params=params,
            timeout=10,
        )
        
        if response.status_code == 200:
            data = response.json()
            reports = data.get("data", [])

            title_lower = report_title.lower()
            ip_lower = ip.lower()

            # Look for matching title or IP in existing reports
            for report in reports:
                attrs = report.get("attributes", {})
                existing_title = attrs.get("title", "").lower()
                existing_body = attrs.get("vulnerability_information", "").lower()

                title_match = title_lower and title_lower in existing_title
                ip_match = ip_lower and (ip_lower in existing_title or ip_lower in existing_body)

                if title_match or ip_match:
                    logger.info(f"Found potential duplicate: {report.get('id')}")
                    return report
        
        return None
        
    except Exception as e:
        logger.warning(f"Error checking duplicates: {e}")
        return None


def submit_report_to_h1(
    report_id: str,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Submit a report to HackerOne.
    
    Args:
        report_id: MongoDB ObjectId of the report document
        dry_run: If True, validate but don't actually submit
    
    Returns:
        Dictionary with submission result
    """
    
    # Validate credentials
    valid, msg = _validate_credentials()
    if not valid:
        logger.warning(f"H1 submission disabled: {msg}")
        return {
            "status": "skipped",
            "report_id": report_id,
            "reason": msg,
            "h1_issue_id": None,
        }
    
    db = get_db()
    report_col = db["reports"]
    submission_col = db["submitted_reports"]
    
    try:
        # Get report from database
        try:
            report_oid = ObjectId(report_id) if isinstance(report_id, str) else report_id
        except Exception:
            return {
                "status": "error",
                "report_id": report_id,
                "reason": "Invalid report ID",
                "h1_issue_id": None,
            }
        
        report = report_col.find_one({"_id": report_oid})
        if not report:
            return {
                "status": "error",
                "report_id": report_id,
                "reason": "Report not found",
                "h1_issue_id": None,
            }

        # Determine program handle: prefer per-report handle over global env var
        program_handle = (
            report.get("program", {}).get("handle")
            or H1_PROGRAM_HANDLE
        )
        if not program_handle:
            return {
                "status": "skipped",
                "report_id": report_id,
                "reason": "No program handle configured (set H1_PROGRAM_HANDLE or associate report with a program)",
                "h1_issue_id": None,
            }

        # Check for duplicates
        duplicate = _check_duplicate(
            report.get("title", ""),
            report.get("ip", ""),
            program_handle=program_handle,
        )
        if duplicate:
            logger.info(f"Duplicate found, not submitting: {duplicate.get('id')}")
            return {
                "status": "duplicate",
                "report_id": report_id,
                "reason": f"Duplicate of H1 report {duplicate.get('id')}",
                "h1_issue_id": duplicate.get("id"),
            }

        severity_rating = _map_severity_to_h1(report.get("severity", "medium"))

        # Prepare submission payload
        attributes: dict[str, Any] = {
            "team_handle": program_handle,
            "title": report.get("title", "Security Finding"),
            "vulnerability_information": report.get("body", ""),
            "impact": report.get("impact", ""),
            "severity_rating": severity_rating,
        }

        # Include structured CVSS when available
        cvss_vector = report.get("cvss_vector", "")
        if cvss_vector:
            attributes["severity"] = {
                "rating": severity_rating,
                "cvss_vector_string": cvss_vector,
            }

        payload = {
            "data": {
                "type": "report",
                "attributes": attributes,
            }
        }
        
        if dry_run:
            logger.info(f"DRY RUN: Would submit {report_id} to H1")
            return {
                "status": "dry_run",
                "report_id": report_id,
                "reason": "Dry run mode",
                "h1_issue_id": None,
                "payload": payload,
            }
        
        # Submit to H1
        headers = _get_h1_headers()
        url = f"{H1_API_URL}/reports"
        
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=30,
        )
        
        if response.status_code in (200, 201):
            data = response.json()
            h1_id = data.get("data", {}).get("id", "")
            
            # Record submission
            submission_doc = {
                "report_id": report_oid,
                "h1_issue_id": h1_id,
                "h1_response": data,
                "submitted_at": datetime.utcnow(),
                "status": "submitted",
                "retries": 0,
            }
            submission_col.insert_one(submission_doc)
            
            # Update report status
            report_col.update_one(
                {"_id": report_oid},
                {
                    "$set": {
                        "status": "submitted",
                        "submitted_at": datetime.utcnow(),
                        "h1_issue_id": h1_id,
                    }
                }
            )
            
            logger.info(f"Successfully submitted report {report_id} to H1: {h1_id}")
            
            return {
                "status": "submitted",
                "report_id": report_id,
                "h1_issue_id": h1_id,
                "message": "Report submitted successfully",
            }
        
        else:
            error_msg = response.text if response.text else f"HTTP {response.status_code}"
            logger.error(f"H1 submission failed: {error_msg}")
            
            # Record failed submission attempt
            submission_doc = {
                "report_id": report_oid,
                "h1_issue_id": None,
                "h1_response": response.text,
                "submitted_at": datetime.utcnow(),
                "status": "failed",
                "error_code": response.status_code,
                "retries": 0,
            }
            submission_col.insert_one(submission_doc)
            
            return {
                "status": "error",
                "report_id": report_id,
                "reason": error_msg,
                "h1_issue_id": None,
            }
    
    except Exception as e:
        logger.error(f"Error submitting to H1: {e}")
        return {
            "status": "error",
            "report_id": report_id,
            "reason": str(e),
            "h1_issue_id": None,
        }


def _map_severity_to_h1(severity: str) -> str:
    """Map internal severity to HackerOne severity_rating."""
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "none",
    }
    return mapping.get(severity.lower(), "medium")


def batch_submit_reports(
    limit: int = 10,
    auto_only: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Batch submit multiple reports to HackerOne.
    
    Args:
        limit: Max reports to submit
        auto_only: Only submit auto-eligible reports
        dry_run: Validate without submitting
    
    Returns:
        Batch submission results
    """
    
    db = get_db()
    report_col = db["reports"]
    
    results = {
        "submitted": 0,
        "duplicates": 0,
        "errors": 0,
        "skipped": 0,
        "details": [],
    }
    
    try:
        # Get ready-to-submit reports
        query = {"status": "draft"}
        if auto_only:
            query["auto_submit_eligible"] = True
        
        reports = list(report_col.find(query).limit(limit))
        
        if not reports:
            logger.info("No reports to submit")
            return results
        
        for i, report in enumerate(reports):
            result = submit_report_to_h1(str(report["_id"]), dry_run=dry_run)

            if result["status"] == "submitted":
                results["submitted"] += 1
            elif result["status"] == "duplicate":
                results["duplicates"] += 1
            elif result["status"] in ("skipped", "dry_run"):
                results["skipped"] += 1
            else:
                results["errors"] += 1

            results["details"].append(result)

            # Rate limit: pause 2s between submissions to avoid H1 throttling
            if not dry_run and i < len(reports) - 1:
                time.sleep(2)
        
        logger.info(f"Batch submission complete: {results['submitted']} submitted, {results['duplicates']} duplicates, {results['errors']} errors")
        
    except Exception as e:
        logger.error(f"Error in batch submission: {e}")
        results["errors"] += 1
    
    return results


def get_submission_stats() -> dict[str, Any]:
    """Get submission statistics."""
    db = get_db()
    submission_col = db["submitted_reports"]
    
    total = submission_col.count_documents({})
    submitted = submission_col.count_documents({"status": "submitted"})
    failed = submission_col.count_documents({"status": "failed"})
    
    return {
        "total_submissions": total,
        "successful": submitted,
        "failed": failed,
        "h1_credentials_configured": _validate_credentials()[0],
        "auto_submit_enabled": AUTO_SUBMIT_ENABLED,
    }


def get_submission_queue() -> list[dict]:
    """Get reports waiting to be submitted."""
    db = get_db()
    report_col = db["reports"]
    
    reports = list(report_col.find({"status": "draft"}).limit(50))
    return reports


# ---------------------------------------------------------------------------
# Auto-submit background loop
# ---------------------------------------------------------------------------


def _auto_submit_loop() -> None:
    """
    Background loop that automatically:
      1. Processes confirmed vulnerabilities → generates H1 reports
      2. Submits ready reports to HackerOne

    Runs every H1_AUTO_SUBMIT_INTERVAL seconds (default 300s = 5 min).
    """
    from app.report_processor import process_vulnerabilities_to_reports

    logger.info(
        "[H1-AUTO] Pipeline ativo | interval=%ds | batch=%d | dry_run=%s | credentials=%s",
        AUTO_SUBMIT_INTERVAL,
        AUTO_SUBMIT_BATCH,
        AUTO_SUBMIT_DRY_RUN,
        "OK" if _validate_credentials()[0] else "MISSING",
    )

    # Wait a bit for other systems to initialize
    time.sleep(30)

    while True:
        try:
            # ── Step 1: Generate reports from confirmed vulns ──
            gen_results = process_vulnerabilities_to_reports(
                limit=AUTO_SUBMIT_BATCH * 5,
                severity_threshold="low",
            )
            if gen_results["reports_generated"] > 0:
                logger.info(
                    "[H1-AUTO] Gerados %d reports de %d vulns (%d erros)",
                    gen_results["reports_generated"],
                    gen_results["processed_vulns"],
                    gen_results["errors"],
                )

            # ── Step 2: Submit ready reports to HackerOne ──
            valid, msg = _validate_credentials()
            if valid:
                submit_results = batch_submit_reports(
                    limit=AUTO_SUBMIT_BATCH,
                    auto_only=True,
                    dry_run=AUTO_SUBMIT_DRY_RUN,
                )
                submitted = submit_results["submitted"]
                if submitted > 0:
                    logger.info(
                        "[H1-AUTO] Enviados %d | duplicados %d | erros %d | skipped %d",
                        submitted,
                        submit_results["duplicates"],
                        submit_results["errors"],
                        submit_results["skipped"],
                    )
            else:
                # Still log periodically so user knows credentials are missing
                logger.debug("[H1-AUTO] Credenciais H1 ausentes (%s) — reports gerados mas não enviados", msg)

        except Exception as e:
            logger.warning("[H1-AUTO] Erro no pipeline: %s", e)

        time.sleep(AUTO_SUBMIT_INTERVAL)


def start_h1_auto_submit() -> None:
    """Start the H1 auto-submit background thread."""
    if not AUTO_SUBMIT_ENABLED:
        logger.info("[H1-AUTO] Auto-submit desabilitado (H1_AUTO_SUBMIT=false)")
        return

    t = threading.Thread(target=_auto_submit_loop, name="h1-auto-submit", daemon=True)
    t.start()
    logger.info("[H1-AUTO] Thread de auto-submit iniciada")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        print("H1 Configuration Test")
        valid, msg = _validate_credentials()
        print(f"  API Credentials: {'✓ Configured' if valid else '✗ Not configured'}")
        if not valid:
            print(f"  Error: {msg}")
        
        print("\nSubmission Stats:")
        stats = get_submission_stats()
        for key, val in stats.items():
            print(f"  {key}: {val}")
    
    elif len(sys.argv) > 1 and sys.argv[1] == "queue":
        print("Submission Queue:")
        queue = get_submission_queue()
        print(f"  Reports waiting: {len(queue)}")
        for report in queue:
            print(f"    - {report.get('title')} ({report.get('severity')})")
    
    else:
        print("Usage: python app/h1_submission.py [test|queue]")
