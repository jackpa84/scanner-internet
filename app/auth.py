"""
Simple JWT authentication for the Scanner API.

Credentials are configured via environment variables:
  AUTH_USERNAME (default: admin)
  AUTH_PASSWORD (default: scanner2026)
  AUTH_SECRET   (default: auto-generated at startup)
  AUTH_TOKEN_HOURS (default: 24)

The /api/auth/login endpoint returns a JWT token.
All other /api/* endpoints require Authorization: Bearer <token>.
"""

import hashlib
import hmac
import json
import os
import time
import base64
import secrets
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

AUTH_USERNAME = os.getenv("AUTH_USERNAME", "admin")
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "scanner2026")
AUTH_SECRET = os.getenv("AUTH_SECRET", secrets.token_hex(32))
AUTH_TOKEN_HOURS = int(os.getenv("AUTH_TOKEN_HOURS", "24"))
# AUTH_ENABLED=false desativa a exigência de login; todas as rotas /api/* ficam públicas
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true").lower() in ("1", "true", "yes")

PUBLIC_PATHS = {"/api/auth/login", "/api/health", "/docs", "/openapi.json", "/redoc"}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def _sign(payload: str) -> str:
    return _b64url_encode(
        hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
    )


def create_token(username: str) -> str:
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps({
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + AUTH_TOKEN_HOURS * 3600,
    }).encode())
    signature = _sign(f"{header}.{payload}")
    return f"{header}.{payload}.{signature}"


def verify_token(token: str) -> Optional[str]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, signature = parts
        expected_sig = _sign(f"{header}.{payload}")
        if not hmac.compare_digest(signature, expected_sig):
            return None
        data = json.loads(_b64url_decode(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data.get("sub")
    except Exception:
        return None


def authenticate(username: str, password: str) -> Optional[str]:
    if username == AUTH_USERNAME and password == AUTH_PASSWORD:
        return create_token(username)
    return None


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if request.method == "OPTIONS":
            return await call_next(request)

        if not AUTH_ENABLED or path in PUBLIC_PATHS or not path.startswith("/api/"):
            return await call_next(request)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Token ausente. Faca login em /api/auth/login"},
            )

        token = auth_header[7:]
        user = verify_token(token)
        if not user:
            return JSONResponse(
                status_code=401,
                content={"detail": "Token invalido ou expirado"},
            )

        request.state.user = user
        return await call_next(request)
