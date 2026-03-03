#!/usr/bin/env python3
"""
Script para inspecionar a estrutura completa do MongoDB.
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
    )
    
    client.admin.command('ping')
    print("✓ MongoDB conectado com sucesso\n")
    
    # Listar todas as databases
    print("📂 DATABASES:")
    print("=" * 60)
    databases = client.list_database_names()
    for db_name in databases:
        print(f"  • {db_name}")
    
    print()
    
    # Listar collections em cada database
    for db_name in databases:
        if db_name in ["admin", "config", "local"]:
            continue
        
        db = client[db_name]
        collections = db.list_collection_names()
        
        print(f"📦 DATABASE: {db_name}")
        print("-" * 60)
        
        if not collections:
            print("  (vazio)")
        else:
            for col_name in collections:
                col = db[col_name]
                count = col.count_documents({})
                size = sum(col.aggregate([{"$group": {"_id": None, "size": {"$sum": {"$bsonSize": "$$ROOT"}}}}], allowDiskUse=True) or [{"size": 0}])
                size_bytes = size.get("size", 0) if isinstance(size, dict) else size[0].get("size", 0) if size else 0
                
                size_display = f"{size_bytes / 1024 / 1024:.2f} MB" if size_bytes > 1024*1024 else f"{size_bytes / 1024:.2f} KB"
                
                print(f"  📋 {col_name:.<35} {count:>8} docs ({size_display:>10})")
        
        print()
    
    # Detalhes da database padrão
    default_db = client.get_default_database()
    print(f"📌 DATABASE PADRÃO: {default_db.name}")
    print("=" * 60)
    
    collections = default_db.list_collection_names()
    for col_name in collections:
        col = default_db[col_name]
        count = col.count_documents({})
        
        if count > 0:
            print(f"\n✓ Collection: {col_name} ({count} docs)")
            if count <= 5:
                for doc in col.find():
                    print(f"  - {doc}")
            else:
                sample = col.find_one()
                print(f"  Amostra: {sample}")
    
    client.close()
    
except Exception as e:
    print(f"❌ Erro: {e}")
    import traceback
    traceback.print_exc()
