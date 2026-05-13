from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519

from .base import Algorithm
from ..core.decoder import base64url_decode
from ..exceptions import InvalidSignatureError, ValidationError

class EdDSAAlgorithm(Algorithm):
    """EdDSA (Ed25519) implementation."""
    
    @property
    def name(self) -> str:
        return "EdDSA"

    def verify(self, message: bytes, signature: bytes, jwk: Dict[str, Any]) -> bool:
        try:
            kty = jwk.get("kty")
            crv = jwk.get("crv")
            x_b64 = jwk.get("x")
            
            if kty != "OKP" or crv != "Ed25519" or not x_b64:
                raise ValidationError("Invalid JWK for EdDSA: must have kty='OKP', crv='Ed25519', and 'x'")

            # Decode x from base64url
            x_bytes = base64url_decode(x_b64)
            
            # Load public key
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(x_bytes)
            
            # Verify
            public_key.verify(signature, message)
            return True
        except Exception as e:
            raise InvalidSignatureError(f"Signature verification failed: {e}") from e

    def sign(self, message: bytes, key: Any) -> bytes:
        """Sign the message using the provided Ed25519 private key."""
        if not hasattr(key, "sign"):
            raise ValidationError("Key must be an Ed25519PrivateKey object")
            
        return key.sign(message)

# Instantiate
EdDSA = EdDSAAlgorithm()
