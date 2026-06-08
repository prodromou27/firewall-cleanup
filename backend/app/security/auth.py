"""
API key authentication middleware.

If API_KEY is set in config, every request must include:
    X-API-Key: <key>

If API_KEY is empty, auth is disabled (development mode).
This allows a clean transition from open-dev to secured-production
by just setting the env variable.

Usage — protect a route:
    from app.security.auth import require_api_key
    @router.get("/something")
    def something(api_key: None = Depends(require_api_key)):
        ...

Usage — applied globally via middleware in main.py.
"""
import logging
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.config import settings

logger = logging.getLogger(__name__)

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Paths that are always public (health check, static assets)
_PUBLIC_PATHS = {"/api/health", "/docs", "/openapi.json", "/redoc"}


def require_api_key(api_key_header: str | None = Security(_API_KEY_HEADER)) -> None:
    """
    FastAPI dependency — raises 401 if API key is required but missing/wrong.
    No-op when API_KEY is not configured (dev mode).
    """
    configured_key = settings.api_key.strip()
    if not configured_key:
        # Auth disabled — dev mode
        return
    if not api_key_header or api_key_header != configured_key:
        logger.warning("Rejected request with invalid API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
