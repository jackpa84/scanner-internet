#!/usr/bin/env python3
"""
Script para contar reports na base MongoDB.
"""

import os
from pymongo import MongoClient

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
        retryWrites=True,
        maxPoolSize=10,
    )
    
    # Test connection
    client.admin.command('ping')
    print("✓ MongoDB conectado com sucesso\n")
    
    db = client.get_default_database()
    
    # Contar reports
    reports_count = db["reports"].count_documents({})
    print(f"📊 REPORTS NA BASE DE DADOS")
    print("=" * 50)
    print(f"Total de reports: {reports_count}")
    print()
    
    # Mostrar estatísticas por status
    print("Distribuição por status:")
    print("-" * 50)
    
    pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    
    for doc in db["reports"].aggregate(pipeline):
        status = doc["_id"] or "sem_status"
        count = doc["count"]
        percentage = (count / reports_count * 100) if reports_count > 0 else 0
        print(f"  {status:.<30} {count:>5} ({percentage:>5.1f}%)")
    
    print()
    
    # Total de reports por programa
    print("Top 10 Programas:")
    print("-" * 50)
    
    pipeline = [
        {"$group": {"_id": "$program_name", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    
    for i, doc in enumerate(db["reports"].aggregate(pipeline), 1):
        program = doc["_id"] or "sem_programa"
        count = doc["count"]
        print(f"  {i:2d}. {program:.<40} {count:>5}")
    
    print()
    
    # Severidade dos reports
    print("Distribuição por severidade:")
    print("-" * 50)
    
    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results = list(db["reports"].aggregate(pipeline))
    results.sort(key=lambda x: severity_order.get(x["_id"], 99))
    
    for doc in results:
        severity = doc["_id"] or "sem_severidade"
        count = doc["count"]
        percentage = (count / reports_count * 100) if reports_count > 0 else 0
        
        # Emoji por severidade
        emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵"
        }.get(severity, "⚪")
        
        print(f"  {emoji} {severity:.<25} {count:>5} ({percentage:>5.1f}%)")
    
    print()
    print("=" * 50)
    
    client.close()
    
except Exception as e:
    print(f"❌ Erro ao conectar MongoDB: {e}")
    print(f"\nPossíveis problemas:")
    print("  1. MongoDB não está rodando")
    print("  2. Credenciais incorretas na MONGODB_URI")
    print("  3. IP não autorizado")
    print(f"\nMONGODB_URI configurada:")
    print(f"  {MONGODB_URI[:80]}...")
