import hmac
import hashlib
from typing import Dict, Any

from .base import Algorithm
from ..core.decoder import base64url_decode
from ..exceptions import InvalidSignatureError, ValidationError

class HMACAlgorithm(Algorithm):
    """Generic HMAC implementation supporting SHA-256, SHA-384, and SHA-512."""
    
    def __init__(self, name: str, hash_alg):
        self._name = name
        self.hash_alg = hash_alg

    @property
    def name(self) -> str:
        return self._name

    def verify(self, message: bytes, signature: bytes, jwk: Dict[str, Any]) -> bool:
        try:
            k_b64 = jwk.get("k")
            if not k_b64:
                raise ValidationError(f"JWK missing 'k' for {self._name}")

            # Decode secret from base64url
            secret = base64url_decode(k_b64)
            
            # Calculate expected signature
            h = hmac.new(secret, message, self.hash_alg)
            expected_signature = h.digest()
            
            # Constant time comparison
            if not hmac.compare_digest(expected_signature, signature):
                raise InvalidSignatureError("Signature verification failed")
                
            return True
        except InvalidSignatureError:
            raise
        except Exception as e:
            raise InvalidSignatureError(f"Signature verification failed: {e}") from e

    def sign(self, message: bytes, key: Any) -> bytes:
        """Sign the message using the provided key (bytes or JWK dict)."""
        if isinstance(key, dict):
            k_b64 = key.get("k")
            if not k_b64:
                raise ValidationError(f"JWK missing 'k' for {self._name}")
            secret = base64url_decode(k_b64)
        elif isinstance(key, bytes):
            secret = key
        else:
            raise ValidationError("Key must be bytes or JWK dict")
            
        h = hmac.new(secret, message, self.hash_alg)
        return h.digest()

# Instantiate specific algorithms
HS256 = HMACAlgorithm("HS256", hashlib.sha256)
HS384 = HMACAlgorithm("HS384", hashlib.sha384)
HS512 = HMACAlgorithm("HS512", hashlib.sha512)
