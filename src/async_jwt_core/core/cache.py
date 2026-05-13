import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class JWKSCache:
    """A simple in-memory cache for JWKS with TTL.
    
    Helps users manage keys without implementing their own caching logic.
    """
    
    def __init__(self, ttl: int = 3600):
        self.ttl = ttl
        self._cache: Optional[Dict[str, Any]] = None
        self._expires_at: float = 0

    async def get(self) -> Optional[Dict[str, Any]]:
        """Get the cached JWKS if not expired."""
        if self._cache is None:
            return None
            
        if time.time() > self._expires_at:
            logger.debug("JWKS cache expired")
            self._cache = None
            return None
            
        return self._cache

    async def set(self, jwks: Dict[str, Any]):
        """Set the JWKS in cache with TTL."""
        self._cache = jwks
        self._expires_at = time.time() + self.ttl
        logger.debug(f"JWKS cache set with TTL {self.ttl}s")

    async def clear(self):
        """Clear the cache."""
        self._cache = None
        self._expires_at = 0
