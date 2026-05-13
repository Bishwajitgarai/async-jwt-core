import asyncio
import base64
import json
import time
import logging
from typing import List, Optional, Dict, Any

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from .exceptions import (
    ValidationError,
    ExpiredTokenError,
    InvalidSignatureError,
    InvalidIssuerError,
    InvalidAudienceError,
)
from .claims import JWTClaims

logger = logging.getLogger(__name__)

class Validator:
    """A minimal, spec-first, framework-agnostic, async-only JWT validator.
    
    Built from scratch without using heavy JWT libraries, only cryptography for secure signature verification.
    """
    
    def __init__(
        self,
        algorithms: List[str],
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        leeway: int = 0,
    ):
        self.algorithms = algorithms
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway

    async def validate(self, token: str, jwks: Dict[str, Any]) -> JWTClaims:
        """Validate a JWT token against a JWKS.
        
        This method is async as requested. Note that cryptographic operations are CPU-bound.
        """
        logger.debug("Starting token validation")
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValidationError("Invalid token format: must have 3 parts")

            header_b64, payload_b64, signature_b64 = parts

            # 1. Decode header and payload
            try:
                header_data = self._base64url_decode(header_b64)
                header = json.loads(header_data.decode("utf-8"))
            except Exception as e:
                raise ValidationError(f"Failed to decode header: {e}") from e

            try:
                payload_data = self._base64url_decode(payload_b64)
                payload = json.loads(payload_data.decode("utf-8"))
            except Exception as e:
                raise ValidationError(f"Failed to decode payload: {e}") from e

            # 2. Check algorithm
            alg = header.get("alg")
            if not alg:
                raise ValidationError("Token header missing 'alg'")
            if alg not in self.algorithms:
                raise ValidationError(f"Algorithm {alg} not allowed")

            # 3. Find key in JWKS
            kid = header.get("kid")
            if not kid:
                raise ValidationError("Token header missing 'kid'")

            logger.debug(f"Looking for key with kid: {kid}")
            jwk = self._find_key(jwks, kid)
            if not jwk:
                raise ValidationError(f"Key with kid '{kid}' not found in JWKS")

            # 4. Verify signature
            message = f"{header_b64}.{payload_b64}".encode("utf-8")
            try:
                signature = self._base64url_decode(signature_b64)
            except Exception as e:
                raise ValidationError(f"Failed to decode signature: {e}") from e

            if alg == "RS256":
                logger.debug("Verifying RS256 signature")
                self._verify_rs256(message, signature, jwk)
                logger.debug("Signature verified successfully")
            else:
                raise ValidationError(f"Algorithm {alg} support not implemented yet")

            # 5. Verify claims
            self._verify_claims(payload)

            logger.debug("Token validation successful")
            return JWTClaims.from_dict(payload)

        except ValidationError as e:
            logger.warning(f"Validation failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during validation: {e}")
            raise ValidationError(f"Unexpected error during validation: {e}") from e

    def _base64url_decode(self, s: str) -> bytes:
        """Decode base64url string."""
        rem = len(s) % 4
        if rem > 0:
            s += "=" * (4 - rem)
        return base64.urlsafe_b64decode(s)

    def _find_key(self, jwks: Dict[str, Any], kid: str) -> Optional[Dict[str, Any]]:
        """Find the key with the given kid in the JWKS."""
        keys = jwks.get("keys", [])
        for key in keys:
            if key.get("kid") == kid:
                return key
        return None

    def _verify_rs256(self, message: bytes, signature: bytes, jwk: Dict[str, Any]):
        """Verify RS256 signature."""
        try:
            n_b64 = jwk.get("n")
            e_b64 = jwk.get("e")
            if not n_b64 or not e_b64:
                raise ValidationError("JWK missing 'n' or 'e' for RSA")

            def b64_to_int(b64_str):
                rem = len(b64_str) % 4
                if rem > 0:
                    b64_str += "=" * (4 - rem)
                b = base64.urlsafe_b64decode(b64_str)
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
        except Exception as e:
            raise InvalidSignatureError(f"Signature verification failed: {e}") from e

    def _verify_claims(self, payload: Dict[str, Any]):
        """Verify standard claims."""
        now = time.time()

        exp = payload.get("exp")
        if exp is not None:
            if now > (exp + self.leeway):
                raise ExpiredTokenError("Token has expired")

        nbf = payload.get("nbf")
        if nbf is not None:
            if now < (nbf - self.leeway):
                raise ValidationError("Token not valid yet (nbf)")

        if self.issuer:
            iss = payload.get("iss")
            if iss != self.issuer:
                raise InvalidIssuerError(f"Invalid issuer: expected {self.issuer}, got {iss}")

        audience_claim = payload.get("aud")
        if self.audience:
            if isinstance(audience_claim, list):
                if self.audience not in audience_claim:
                    raise InvalidAudienceError(f"Invalid audience: {self.audience} not in {audience_claim}")
            elif audience_claim != self.audience:
                raise InvalidAudienceError(f"Invalid audience: expected {self.audience}, got {audience_claim}")
