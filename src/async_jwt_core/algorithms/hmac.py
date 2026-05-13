import hmac
import hashlib
from typing import Dict, Any

from .base import Algorithm
from ..core.decoder import base64url_decode
from ..exceptions import InvalidSignatureError, ValidationError

class HS256(Algorithm):
    """HS256 (HMAC with SHA-256) implementation."""
    
    @property
    def name(self) -> str:
        return "HS256"

    def verify(self, message: bytes, signature: bytes, jwk: Dict[str, Any]) -> bool:
        try:
            k_b64 = jwk.get("k")
            if not k_b64:
                raise ValidationError("JWK missing 'k' for HMAC")

            # Decode secret from base64url
            secret = base64url_decode(k_b64)
            
            # Calculate expected signature
            h = hmac.new(secret, message, hashlib.sha256)
            expected_signature = h.digest()
            
            # Constant time comparison
            if not hmac.compare_digest(expected_signature, signature):
                raise InvalidSignatureError("Signature verification failed")
                
            return True
        except InvalidSignatureError:
            raise
        except Exception as e:
            raise InvalidSignatureError(f"Signature verification failed: {e}") from e
