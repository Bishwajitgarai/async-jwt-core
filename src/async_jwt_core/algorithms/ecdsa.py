from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from .base import Algorithm
from ..core.decoder import base64url_decode
from ..exceptions import InvalidSignatureError, ValidationError

class ECDSAAlgorithm(Algorithm):
    """Generic ECDSA implementation supporting ES256, ES384, and ES512."""
    
    def __init__(self, name: str, curve, hash_alg):
        self._name = name
        self.curve = curve
        self.hash_alg = hash_alg

    @property
    def name(self) -> str:
        return self._name

    def verify(self, message: bytes, signature: bytes, jwk: Dict[str, Any]) -> bool:
        try:
            x_b64 = jwk.get("x")
            y_b64 = jwk.get("y")
            if not x_b64 or not y_b64:
                raise ValidationError(f"JWK missing 'x' or 'y' for {self._name}")

            def b64_to_int(b64_str):
                rem = len(b64_str) % 4
                if rem > 0:
                    b64_str += "=" * (4 - rem)
                b = base64url_decode(b64_str)
                return int.from_bytes(b, byteorder="big")

            x = b64_to_int(x_b64)
            y = b64_to_int(y_b64)

            # Create public key
            public_numbers = ec.EllipticCurvePublicNumbers(x, y, self.curve)
            public_key = public_numbers.public_key()

            # ECDSA signature format in JWT is R || S.
            # We need to convert it to DER for cryptography.
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            
            # Split signature into R and S
            sig_len = len(signature)
            r = int.from_bytes(signature[:sig_len//2], byteorder="big")
            s = int.from_bytes(signature[sig_len//2:], byteorder="big")
            
            der_signature = encode_dss_signature(r, s)

            public_key.verify(
                der_signature,
                message,
                ec.ECDSA(self.hash_alg)
            )
            return True
        except Exception as e:
            raise InvalidSignatureError(f"Signature verification failed: {e}") from e

# Instantiate specific algorithms
ES256 = ECDSAAlgorithm("ES256", ec.SECP256R1(), hashes.SHA256())
ES384 = ECDSAAlgorithm("ES384", ec.SECP384R1(), hashes.SHA384())
ES512 = ECDSAAlgorithm("ES512", ec.SECP521R1(), hashes.SHA512())
