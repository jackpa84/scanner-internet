"""
ROI (Return on Investment) tracker for bug bounty operations.

Tracks earnings, time invested, and calculates ROI per program,
per vulnerability type, and overall.

Enables data-driven decisions about where to focus scanning resources.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from typing import Any

from app.database import get_bounty_programs, get_bounty_targets, get_submitted_reports, get_redis

logger = logging.getLogger("scanner.roi")

ROI_ENABLED = os.getenv("ROI_TRACKER_ENABLED", "true").lower() in ("1", "true", "yes")
ROI_UPDATE_INTERVAL = int(os.getenv("ROI_UPDATE_INTERVAL", "3600"))

_stats_lock = threading.Lock()


def _get_roi_data() -> dict:
    """Load ROI data from Redis."""
    try:
        r = get_redis()
        data = r.get("roi:data")
        if data:
            return json.loads(data)
    except Exception:
        pass
    return {}


def _save_roi_data(data: dict) -> None:
    """Save ROI data to Redis."""
    try:
        r = get_redis()
        r.set("roi:data", json.dumps(data, default=str))
    except Exception:
        pass


def record_earning(
    program_id: str,
    program_name: str,
    amount: float,
    currency: str = "USD",
    vuln_type: str = "",
    report_id: str = "",
    h1_report_id: str = "",
) -> None:
    """Record a bounty earning."""
    try:
        r = get_redis()
        earning = {
            "program_id": program_id,
            "program_name": program_name,
            "amount": amount,
            "currency": currency,
            "vuln_type": vuln_type,
            "report_id": report_id,
            "h1_report_id": h1_report_id,
            "timestamp": datetime.utcnow().isoformat(),
        }
        r.rpush("roi:earnings", json.dumps(earning))
        logger.info("[ROI] Recorded earning: $%.2f from %s (%s)", amount, program_name, vuln_type)
    except Exception as e:
        logger.error("[ROI] Error recording earning: %s", e)


def record_time_spent(
    program_id: str,
    activity: str,
    duration_seconds: float,
) -> None:
    """Record time spent on a program/activity."""
    try:
        r = get_redis()
        entry = {
            "program_id": program_id,
            "activity": activity,
            "duration_seconds": duration_seconds,
            "timestamp": datetime.utcnow().isoformat(),
        }
        r.rpush("roi:time_spent", json.dumps(entry))
    except Exception as e:
        logger.debug("[ROI] Error recording time: %s", e)


def get_earnings() -> list[dict]:
    """Get all recorded earnings."""
    try:
        r = get_redis()
        earnings_raw = r.lrange("roi:earnings", 0, -1)
        return [json.loads(e) for e in earnings_raw]
    except Exception:
        return []


def get_earnings_summary() -> dict[str, Any]:
    """Calculate earnings summary."""
    earnings = get_earnings()

    if not earnings:
        return {
            "total_earnings": 0,
            "total_reports": 0,
            "by_program": {},
            "by_vuln_type": {},
            "by_month": {},
            "avg_payout": 0,
            "highest_payout": 0,
        }

    total = sum(e.get("amount", 0) for e in earnings)

    by_program: dict[str, dict] = {}
    for e in earnings:
        name = e.get("program_name", "unknown")
        if name not in by_program:
            by_program[name] = {"earnings": 0, "count": 0, "program_id": e.get("program_id", "")}
        by_program[name]["earnings"] += e.get("amount", 0)
        by_program[name]["count"] += 1

    by_vuln: dict[str, dict] = {}
    for e in earnings:
        vtype = e.get("vuln_type", "unknown")
        if vtype not in by_vuln:
            by_vuln[vtype] = {"earnings": 0, "count": 0}
        by_vuln[vtype]["earnings"] += e.get("amount", 0)
        by_vuln[vtype]["count"] += 1

    by_month: dict[str, dict] = {}
    for e in earnings:
        ts = e.get("timestamp", "")
        month = ts[:7] if ts else "unknown"
        if month not in by_month:
            by_month[month] = {"earnings": 0, "count": 0}
        by_month[month]["earnings"] += e.get("amount", 0)
        by_month[month]["count"] += 1

    amounts = [e.get("amount", 0) for e in earnings if e.get("amount", 0) > 0]

    return {
        "total_earnings": total,
        "total_reports": len(earnings),
        "avg_payout": total / len(amounts) if amounts else 0,
        "highest_payout": max(amounts) if amounts else 0,
        "by_program": dict(sorted(by_program.items(), key=lambda x: x[1]["earnings"], reverse=True)),
        "by_vuln_type": dict(sorted(by_vuln.items(), key=lambda x: x[1]["earnings"], reverse=True)),
        "by_month": dict(sorted(by_month.items())),
    }


def get_program_roi(program_id: str) -> dict[str, Any]:
    """Calculate ROI for a specific program."""
    earnings = get_earnings()
    program_earnings = [e for e in earnings if e.get("program_id") == program_id]

    total_earned = sum(e.get("amount", 0) for e in program_earnings)
    report_count = len(program_earnings)

    time_entries = []
    try:
        r = get_redis()
        all_time = r.lrange("roi:time_spent", 0, -1)
        time_entries = [json.loads(t) for t in all_time if json.loads(t).get("program_id") == program_id]
    except Exception:
        pass

    total_time = sum(t.get("duration_seconds", 0) for t in time_entries)
    total_hours = total_time / 3600

    hourly_rate = total_earned / total_hours if total_hours > 0 else 0

    return {
        "program_id": program_id,
        "total_earned": total_earned,
        "total_reports": report_count,
        "total_hours": round(total_hours, 1),
        "hourly_rate": round(hourly_rate, 2),
        "avg_payout": total_earned / report_count if report_count > 0 else 0,
        "efficiency": "excellent" if hourly_rate > 100 else "good" if hourly_rate > 50 else "moderate" if hourly_rate > 20 else "low",
    }


def get_overall_dashboard() -> dict[str, Any]:
    """Get complete ROI dashboard data."""
    earnings_summary = get_earnings_summary()

    programs_col = get_bounty_programs()
    targets_col = get_bounty_targets()
    reports_col = get_submitted_reports()

    total_programs = programs_col.count_documents({})
    active_programs = programs_col.count_documents({"status": {"$in": ["active", "reconning"]}})
    total_targets = targets_col.count_documents({})
    alive_targets = targets_col.count_documents({"alive": True})
    total_submitted = reports_col.count_documents({})
    submitted_ok = reports_col.count_documents({"status": "submitted"})
    submitted_err = reports_col.count_documents({"status": "error"})

    acceptance_rate = (submitted_ok / total_submitted * 100) if total_submitted > 0 else 0

    program_roi = {}
    for prog in programs_col.find():
        pid = str(prog["_id"])
        roi = get_program_roi(pid)
        if roi["total_earned"] > 0 or roi["total_reports"] > 0:
            program_roi[prog.get("name", pid)] = roi

    top_programs = sorted(
        program_roi.items(),
        key=lambda x: x[1]["total_earned"],
        reverse=True,
    )[:10]

    vuln_types = earnings_summary.get("by_vuln_type", {})
    most_profitable_vulns = sorted(
        vuln_types.items(),
        key=lambda x: x[1]["earnings"],
        reverse=True,
    )[:10]

    return {
        "summary": {
            "total_earnings": earnings_summary["total_earnings"],
            "total_reports_paid": earnings_summary["total_reports"],
            "avg_payout": round(earnings_summary["avg_payout"], 2),
            "highest_payout": earnings_summary["highest_payout"],
        },
        "operations": {
            "total_programs": total_programs,
            "active_programs": active_programs,
            "total_targets": total_targets,
            "alive_targets": alive_targets,
            "reports_submitted": total_submitted,
            "reports_accepted": submitted_ok,
            "reports_failed": submitted_err,
            "acceptance_rate": round(acceptance_rate, 1),
        },
        "top_programs": [{
            "name": name,
            "earned": roi["total_earned"],
            "reports": roi["total_reports"],
            "hourly_rate": roi["hourly_rate"],
            "efficiency": roi["efficiency"],
        } for name, roi in top_programs],
        "most_profitable_vulns": [{
            "type": vtype,
            "earnings": data["earnings"],
            "count": data["count"],
            "avg_payout": round(data["earnings"] / data["count"], 2) if data["count"] > 0 else 0,
        } for vtype, data in most_profitable_vulns],
        "monthly_trend": earnings_summary.get("by_month", {}),
        "recommendations": _generate_recommendations(earnings_summary, program_roi),
        "generated_at": datetime.utcnow().isoformat(),
    }


def _generate_recommendations(earnings: dict, program_roi: dict) -> list[str]:
    """Generate data-driven recommendations."""
    recs = []

    by_vuln = earnings.get("by_vuln_type", {})
    if by_vuln:
        top_vuln = max(by_vuln.items(), key=lambda x: x[1]["earnings"])
        recs.append(f"Focus on {top_vuln[0]}: highest earning vulnerability type (${top_vuln[1]['earnings']:.0f} total)")

    if program_roi:
        best = max(program_roi.items(), key=lambda x: x[1].get("hourly_rate", 0))
        if best[1].get("hourly_rate", 0) > 0:
            recs.append(f"Best ROI program: {best[0]} (${best[1]['hourly_rate']:.0f}/hr)")

        worst = min(program_roi.items(), key=lambda x: x[1].get("hourly_rate", float("inf")))
        if worst[1].get("hourly_rate", 0) < 10 and worst[1].get("total_reports", 0) > 3:
            recs.append(f"Consider dropping {worst[0]}: low ROI (${worst[1]['hourly_rate']:.0f}/hr)")

    total = earnings.get("total_earnings", 0)
    reports = earnings.get("total_reports", 0)
    if reports > 0:
        avg = total / reports
        if avg < 500:
            recs.append("Average payout is low - focus on higher-severity bugs (IDOR, SSRF, RCE)")
        elif avg > 2000:
            recs.append("Great average payout! Continue current strategy.")

    if not recs:
        recs.append("Start recording earnings to get data-driven recommendations.")

    return recs


def _roi_update_loop() -> None:
    """Background loop to periodically update ROI calculations."""
    time.sleep(120)
    logger.info("[ROI] Tracker started (interval=%ds)", ROI_UPDATE_INTERVAL)

    while True:
        try:
            dashboard = get_overall_dashboard()
            _save_roi_data(dashboard)
            total = dashboard["summary"]["total_earnings"]
            reports = dashboard["summary"]["total_reports_paid"]
            logger.info("[ROI] Dashboard updated: $%.2f earned from %d reports", total, reports)
        except Exception as e:
            logger.error("[ROI] Update error: %s", e)

        time.sleep(ROI_UPDATE_INTERVAL)


def start_roi_tracker() -> None:
    """Start the ROI tracker background thread."""
    if not ROI_ENABLED:
        logger.info("[ROI] Tracker disabled")
        return

    t = threading.Thread(target=_roi_update_loop, daemon=True)
    t.start()
    logger.info("[ROI] Tracker active")
