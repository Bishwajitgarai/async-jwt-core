import asyncio
import logging
import os
from typing import List, Optional, Dict, Any, Callable, Awaitable, Union

from ..algorithms import get_algorithm
from ..claims import ClaimsValidator, JWTClaims
from .decoder import base64url_decode, decode_json
from .rate_limiter import RateLimiter
from ..exceptions import ValidationError

logger = logging.getLogger(__name__)

class Validator:
    """A minimal, spec-first, framework-agnostic, async-only JWT validator.
    
    Orchestrates decoding, signature verification, and claim validation.
    """
    
    def __init__(
        self,
        algorithms: Optional[List[str]] = None,
        issuer: Optional[Union[str, List[str]]] = None,
        audience: Optional[Union[str, List[str]]] = None,
        leeway: int = 0,
        custom_validators: Optional[Dict[str, Callable[[Dict[str, Any]], bool]]] = None,
        nonce_checker: Optional[Callable[[str], Awaitable[bool]]] = None,
        clock: Optional[Callable[[], float]] = None,
        expected_typ: Optional[str] = None,
        max_age: Optional[int] = None,
        expected_sub: Optional[str] = None,
        rate_limit_rps: Optional[float] = None,
        rate_limit_burst: Optional[float] = None
    ):
        # Load from ENV defaults if not provided
        self.algorithms = algorithms or os.getenv("JWT_ALGORITHMS", "RS256").split(",")
        
        # Strip whitespace from algorithms list
        self.algorithms = [alg.strip() for alg in self.algorithms]
        
        resolved_issuer = issuer or os.getenv("JWT_ISSUER")
        resolved_audience = audience or os.getenv("JWT_AUDIENCE")
        
        self.claims_validator = ClaimsValidator(
            resolved_issuer, 
            resolved_audience, 
            leeway, 
            custom_validators, 
            clock, 
            max_age, 
            expected_sub
        )
        
        self.nonce_checker = nonce_checker
        self.expected_typ = expected_typ

        # Initialize Rate Limiter if requested
        self.rate_limiter = None
        if rate_limit_rps:
            burst = rate_limit_burst or rate_limit_rps * 2
            self.rate_limiter = RateLimiter(rate_limit_rps, burst)
            logger.info(f"Rate limiter enabled: {rate_limit_rps} RPS, burst {burst}")

    async def validate(self, token: str, jwks: Dict[str, Any]) -> JWTClaims:
        """Validate a JWT token against a JWKS."""
        
        # 0. Check Rate Limit
        if self.rate_limiter:
            if not await self.rate_limiter.acquire():
                raise ValidationError("Rate limit exceeded for token validation")

        logger.debug("Starting token validation")
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValidationError("Invalid token format: must have 3 parts")

            header_b64, payload_b64, signature_b64 = parts

            # 1. Decode header and payload
            header = await self.get_unverified_header(token)
            payload = await self.decode_unverified(token)

            # 2. Check algorithm and type
            alg_name = header.get("alg")
            if not alg_name:
                raise ValidationError("Token header missing 'alg'")
            if alg_name not in self.algorithms:
                raise ValidationError(f"Algorithm {alg_name} not allowed")

            if self.expected_typ:
                typ = header.get("typ")
                if typ != self.expected_typ:
                    raise ValidationError(f"Invalid token type: expected {self.expected_typ}, got {typ}")

            # Critical Header Check
            if "crit" in header:
                raise ValidationError("Critical headers ('crit') are not supported yet")

            # 3. Find key in JWKS
            kid = header.get("kid")
            if not kid:
                raise ValidationError("Token header missing 'kid'")

            logger.debug(f"Looking for key with kid: {kid}")
            jwk = self._find_key(jwks, kid)
            if not jwk:
                raise ValidationError(f"Key with kid '{kid}' not found in JWKS")

            # Security Check: Verify key type matches algorithm
            kty = jwk.get("kty")
            if alg_name.startswith("RS") or alg_name.startswith("PS"):
                if kty != "RSA":
                    raise ValidationError(f"Key type mismatch: algorithm {alg_name} requires kty='RSA'")
            elif alg_name.startswith("HS"):
                if kty != "oct":
                    raise ValidationError(f"Key type mismatch: algorithm {alg_name} requires kty='oct'")
            elif alg_name.startswith("ES"):
                if kty != "EC":
                    raise ValidationError(f"Key type mismatch: algorithm {alg_name} requires kty='EC'")

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

            # 6. Nonce / Replay Detection
            if self.nonce_checker and "jti" in payload:
                jti = payload["jti"]
                logger.debug(f"Checking nonce (jti): {jti}")
                is_valid = await self.nonce_checker(jti)
                if not is_valid:
                    raise ValidationError(f"Nonce (jti) '{jti}' is invalid or replayed")

            logger.debug("Token validation successful")
            return JWTClaims.from_dict(payload)

        except ValidationError as e:
            logger.warning(f"Validation failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during validation: {e}")
            raise ValidationError(f"Unexpected error during validation: {e}") from e

    async def decode_unverified(self, token: str) -> Dict[str, Any]:
        """Decode the payload without verification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValidationError("Invalid token format")
            payload_b64 = parts[1]
            return decode_json(base64url_decode(payload_b64))
        except Exception as e:
            raise ValidationError(f"Failed to decode unverified payload: {e}") from e

    async def get_unverified_header(self, token: str) -> Dict[str, Any]:
        """Decode the header without verification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValidationError("Invalid token format")
            header_b64 = parts[0]
            return decode_json(base64url_decode(header_b64))
        except Exception as e:
            raise ValidationError(f"Failed to decode unverified header: {e}") from e

    # --- Helper Methods for Header Extraction ---
    
    async def get_kid(self, token: str) -> Optional[str]:
        """Get 'kid' from header without verification."""
        header = await self.get_unverified_header(token)
        return header.get("kid")

    async def get_alg(self, token: str) -> Optional[str]:
        """Get 'alg' from header without verification."""
        header = await self.get_unverified_header(token)
        return header.get("alg")

    async def get_jku(self, token: str) -> Optional[str]:
        """Get 'jku' (JWK Set URL) from header."""
        header = await self.get_unverified_header(token)
        return header.get("jku")

    async def get_x5c(self, token: str) -> Optional[list]:
        """Get 'x5c' (X.509 Certificate Chain) from header."""
        header = await self.get_unverified_header(token)
        return header.get("x5c")

    def _find_key(self, jwks: Dict[str, Any], kid: str) -> Optional[Dict[str, Any]]:
        """Find the key with the given kid in the JWKS."""
        keys = jwks.get("keys", [])
        for key in keys:
            if key.get("kid") == kid:
                return key
        return None

    @staticmethod
    async def parse_introspection_response(response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and validate an introspection response (RFC 7662)."""
        if not isinstance(response, dict):
            raise ValidationError("Introspection response must be a dictionary")
            
        if "active" not in response:
            raise ValidationError("Introspection response missing 'active' claim")
            
        if not response["active"]:
            raise ValidationError("Token is not active according to introspection")
            
        return response
