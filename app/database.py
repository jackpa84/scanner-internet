"""Conexão e acesso ao MongoDB."""
import logging
import os
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://user:password@localhost:27017/scanner_db?authSource=admin")
logger = logging.getLogger("scanner.db")

_client: MongoClient | None = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        logger.debug("MongoDB client conectado")
    return _client


def get_db() -> Database:
    return get_client().get_default_database()


def get_scan_results() -> Collection:
    return get_db()["scan_results"]


def get_vuln_results() -> Collection:
    return get_db()["vuln_results"]


def init_db():
    """Garante índices para consultas rápidas."""
    col = get_scan_results()
    col.create_index("timestamp", name="idx_timestamp")
    col.create_index("ip", name="idx_ip", unique=False)
    col.create_index("risk.score", name="idx_risk_score")
    col.create_index("vulns", name="idx_vulns")
    col.create_index("geo.country", name="idx_geo_country")
    col.create_index("threat_intel.known_threat", name="idx_threat", sparse=True)
    col.create_index("network.proxy", name="idx_proxy", sparse=True)

    vcol = get_vuln_results()
    vcol.create_index("ip", name="vidx_ip")
    vcol.create_index("severity", name="vidx_severity")
    vcol.create_index("template_id", name="vidx_template")
    vcol.create_index("timestamp", name="vidx_timestamp")
    vcol.create_index("scan_result_id", name="vidx_scan_ref", sparse=True)
    vcol.create_index("tool", name="vidx_tool")

    logger.info("[DB] MongoDB conectado, indices OK (scan_results + vuln_results)")
