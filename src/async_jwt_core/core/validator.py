import asyncio
import logging
from typing import List, Optional, Dict, Any, Callable

from ..algorithms import get_algorithm
from ..claims import ClaimsValidator, JWTClaims
from .decoder import base64url_decode, decode_json
from ..exceptions import ValidationError

logger = logging.getLogger(__name__)

class Validator:
    """A minimal, spec-first, framework-agnostic, async-only JWT validator.
    
    Orchestrates decoding, signature verification, and claim validation.
    """
    
    def __init__(
        self,
        algorithms: List[str],
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        leeway: int = 0,
        custom_validators: Optional[Dict[str, Callable[[Dict[str, Any]], bool]]] = None
    ):
        self.algorithms = algorithms
        self.claims_validator = ClaimsValidator(issuer, audience, leeway, custom_validators)

    async def validate(self, token: str, jwks: Dict[str, Any]) -> JWTClaims:
        """Validate a JWT token against a JWKS."""
        logger.debug("Starting token validation")
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValidationError("Invalid token format: must have 3 parts")

            header_b64, payload_b64, signature_b64 = parts

            # 1. Decode header and payload
            try:
                header = decode_json(base64url_decode(header_b64))
            except Exception as e:
                raise ValidationError(f"Failed to decode header: {e}") from e

            try:
                payload = decode_json(base64url_decode(payload_b64))
            except Exception as e:
                raise ValidationError(f"Failed to decode payload: {e}") from e

            # 2. Check algorithm
            alg_name = header.get("alg")
            if not alg_name:
                raise ValidationError("Token header missing 'alg'")
            if alg_name not in self.algorithms:
                raise ValidationError(f"Algorithm {alg_name} not allowed")

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
                signature = base64url_decode(signature_b64)
            except Exception as e:
                raise ValidationError(f"Failed to decode signature: {e}") from e

            # Get algorithm implementation
            algorithm = get_algorithm(alg_name)
            
            logger.debug(f"Verifying signature with {alg_name}")
            algorithm.verify(message, signature, jwk)
            logger.debug("Signature verified successfully")

            # 5. Verify claims
            self.claims_validator.validate(payload)

            logger.debug("Token validation successful")
            return JWTClaims.from_dict(payload)

        except ValidationError as e:
            logger.warning(f"Validation failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during validation: {e}")
            raise ValidationError(f"Unexpected error during validation: {e}") from e

    def _find_key(self, jwks: Dict[str, Any], kid: str) -> Optional[Dict[str, Any]]:
        """Find the key with the given kid in the JWKS."""
        keys = jwks.get("keys", [])
        for key in keys:
            if key.get("kid") == kid:
                return key
        return None
