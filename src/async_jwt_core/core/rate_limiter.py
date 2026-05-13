import time
import asyncio
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    """A simple in-memory Token Bucket rate limiter.
    
    Helps protect the validation endpoint from brute-force or DoS attacks.
    """
    
    def __init__(self, requests_per_second: float = 10.0, bucket_size: float = 20.0):
        self.rate = requests_per_second
        self.bucket_size = bucket_size
        self.tokens = bucket_size
        self.last_check = time.time()
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        """Try to acquire a token. Returns True if successful, False otherwise."""
        async with self._lock:
            now = time.time()
            # Replenish tokens
            elapsed = now - self.last_check
            self.tokens += elapsed * self.rate
            
            if self.tokens > self.bucket_size:
                self.tokens = self.bucket_size
                
            self.last_check = now
            
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
                
            logger.warning("Rate limit exceeded")
            return False
