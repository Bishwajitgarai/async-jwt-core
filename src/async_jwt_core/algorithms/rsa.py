from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from .base import Algorithm
from ..core.decoder import base64url_decode
from ..exceptions import InvalidSignatureError, ValidationError

class RSAAlgorithm(Algorithm):
    """Generic RSA implementation supporting RS256, RS384, RS512 and PS256."""
    
    def __init__(self, name: str, hash_alg, use_pss: bool = False):
        self._name = name
        self.hash_alg = hash_alg
        self.use_pss = use_pss

    @property
    def name(self) -> str:
        return self._name

    def verify(self, message: bytes, signature: bytes, jwk: Dict[str, Any]) -> bool:
        try:
            n_b64 = jwk.get("n")
            e_b64 = jwk.get("e")
            if not n_b64 or not e_b64:
                raise ValidationError(f"JWK missing 'n' or 'e' for {self._name}")

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

            if self.use_pss:
                pad = padding.PSS(
                    mgf=padding.MGF1(self.hash_alg),
                    salt_length=padding.PSS.MAX_LENGTH
                )
            else:
                pad = padding.PKCS1v15()

            public_key.verify(
                signature,
                message,
                pad,
                self.hash_alg
            )
            return True
        except Exception as e:
            raise InvalidSignatureError(f"Signature verification failed: {e}") from e

    def sign(self, message: bytes, key: Any) -> bytes:
        """Sign the message using the provided RSA private key."""
        if not hasattr(key, "sign"):
            raise ValidationError("Key must be an RSAPrivateKey object")
            
        if self.use_pss:
            pad = padding.PSS(
                mgf=padding.MGF1(self.hash_alg),
                salt_length=padding.PSS.MAX_LENGTH
            )
        else:
            pad = padding.PKCS1v15()
            
        return key.sign(
            message,
            pad,
            self.hash_alg
        )

# Instantiate specific algorithms
RS256 = RSAAlgorithm("RS256", hashes.SHA256())
RS384 = RSAAlgorithm("RS384", hashes.SHA384())
RS512 = RSAAlgorithm("RS512", hashes.SHA512())
PS256 = RSAAlgorithm("PS256", hashes.SHA256(), use_pss=True)
PS384 = RSAAlgorithm("PS384", hashes.SHA384(), use_pss=True)
PS512 = RSAAlgorithm("PS512", hashes.SHA512(), use_pss=True)
