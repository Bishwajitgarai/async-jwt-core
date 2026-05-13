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
        rate_limit_burst: Optional[float] = None,
        required_scopes: Optional[List[str]] = None,
        required_roles: Optional[List[str]] = None,
        required_access_ids: Optional[List[str]] = None,
        required_session_id: Optional[str] = None
    ):
        self.algorithms = algorithms or os.getenv("ASYNC_JWT_ALGORITHMS", "RS256").split(",")
        self.algorithms = [alg.strip() for alg in self.algorithms]
        
        resolved_issuer = issuer or os.getenv("ASYNC_JWT_ISSUER")
        resolved_audience = audience or os.getenv("ASYNC_JWT_AUDIENCE")
        
        self.claims_validator = ClaimsValidator(
            resolved_issuer, 
            resolved_audience, 
            leeway, 
            custom_validators, 
            clock, 
            max_age, 
            expected_sub,
            required_scopes,
            required_roles,
            required_access_ids,
            required_session_id
        )
        
        self.nonce_checker = nonce_checker
        self.expected_typ = expected_typ

        self.rate_limiter = None
        if rate_limit_rps:
            burst = rate_limit_burst or rate_limit_rps * 2
            self.rate_limiter = RateLimiter(rate_limit_rps, burst)
            logger.info(f"Rate limiter enabled: {rate_limit_rps} RPS, burst {burst}")

    async def validate(self, token: str, jwks: Dict[str, Any]) -> JWTClaims:
        """Validate a JWT token against a JWKS."""
        if self.rate_limiter:
            if not await self.rate_limiter.acquire():
                raise ValidationError("Rate limit exceeded for token validation")

        logger.debug("Starting token validation")
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValidationError("Invalid token format: must have 3 parts")

            header_b64, payload_b64, signature_b64 = parts

            header = await self.get_unverified_header(token)
            payload = await self.decode_unverified(token)

            alg_name = header.get("alg")
            if not alg_name:
                raise ValidationError("Token header missing 'alg'")
            if alg_name not in self.algorithms:
                raise ValidationError(f"Algorithm {alg_name} not allowed")

            if self.expected_typ:
                typ = header.get("typ")
                if typ != self.expected_typ:
                    raise ValidationError(f"Invalid token type: expected {self.expected_typ}, got {typ}")

            if "crit" in header:
                raise ValidationError("Critical headers ('crit') are not supported yet")

            kid = header.get("kid")
            if not kid:
                raise ValidationError("Token header missing 'kid'")

            logger.debug(f"Looking for key with kid: {kid}")
            jwk = self._find_key(jwks, kid)
            if not jwk:
                raise ValidationError(f"Key with kid '{kid}' not found in JWKS")

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

            message = f"{header_b64}.{payload_b64}".encode("utf-8")
            try:
                signature = base64url_decode(signature_b64)
            except Exception as e:
                raise ValidationError(f"Failed to decode signature: {e}") from e

            algorithm = get_algorithm(alg_name)
            algorithm.verify(message, signature, jwk)

            self.claims_validator.validate(payload)

            if self.nonce_checker and "jti" in payload:
                jti = payload["jti"]
                is_valid = await self.nonce_checker(jti)
                if not is_valid:
                    raise ValidationError(f"Nonce (jti) '{jti}' is invalid or replayed")

            return JWTClaims.from_dict(payload)

        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Unexpected error during validation: {e}") from e

    async def decode_unverified(self, token: str) -> Dict[str, Any]:
        """Decode the payload without verification."""
        try:
            parts = token.split(".")
            payload_b64 = parts[1]
            return decode_json(base64url_decode(payload_b64))
        except Exception as e:
            raise ValidationError(f"Failed to decode unverified payload: {e}") from e

    async def get_unverified_header(self, token: str) -> Dict[str, Any]:
        """Decode the header without verification."""
        try:
            parts = token.split(".")
            header_b64 = parts[0]
            return decode_json(base64url_decode(header_b64))
        except Exception as e:
            raise ValidationError(f"Failed to decode unverified header: {e}") from e

    async def get_kid(self, token: str) -> Optional[str]:
        """Get 'kid' from header without verification."""
        header = await self.get_unverified_header(token)
        return header.get("kid")

    async def get_alg(self, token: str) -> Optional[str]:
        """Get 'alg' from header without verification."""
        header = await self.get_unverified_header(token)
        return header.get("alg")

    def _find_key(self, jwks: Dict[str, Any], kid: str) -> Optional[Dict[str, Any]]:
        """Find the key with the given kid in the JWKS."""
        keys = jwks.get("keys", [])
        for key in keys:
            if key.get("kid") == kid:
                return key
        return None

    @staticmethod
    def extract_token(request: Any) -> str:
        """Extract JWT token from a request object or headers dict."""
        headers = None
        if isinstance(request, dict):
            headers = request
        elif hasattr(request, "headers"):
            headers = request.headers
            
        if not headers:
            raise ValidationError("Could not find headers in request object")
            
        auth_header = None
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth_header = v
                break
                
        if not auth_header:
            raise ValidationError("Authorization header missing")
            
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise ValidationError("Invalid Authorization header format: must be 'Bearer <token>'")
            
        return parts[1]

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
