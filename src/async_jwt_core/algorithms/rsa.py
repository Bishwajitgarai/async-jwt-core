from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from .base import Algorithm
from ..core.decoder import base64url_decode
from ..exceptions import InvalidSignatureError, ValidationError

class RS256(Algorithm):
    """RS256 (RSA Signature with SHA-256) implementation."""
    
    @property
    def name(self) -> str:
        return "RS256"

    def verify(self, message: bytes, signature: bytes, jwk: Dict[str, Any]) -> bool:
        try:
            n_b64 = jwk.get("n")
            e_b64 = jwk.get("e")
            if not n_b64 or not e_b64:
                raise ValidationError("JWK missing 'n' or 'e' for RSA")

            def b64_to_int(b64_str):
                rem = len(b64_str) % 4
                if rem > 0:
                    b64_str += "=" * (4 - rem)
                b = base64url_decode(b64_str)
                return int.from_bytes(b, byteorder="big")

            n = b64_to_int(n_b64)
            e = b64_to_int(e_b64)

            public_numbers = RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key()

            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            raise InvalidSignatureError(f"Signature verification failed: {e}") from e
