import time
from typing import Dict, Any, Optional, List, Callable, Union

from ..exceptions import ExpiredTokenError, InvalidIssuerError, InvalidAudienceError, ValidationError

class ClaimsValidator:
    """Validator for standard and custom JWT claims, including RBAC, Scopes, Access IDs, and Session IDs."""
    
    def __init__(
        self,
        issuer: Optional[Union[str, List[str]]] = None,
        audience: Optional[Union[str, List[str]]] = None,
        leeway: int = 0,
        custom_validators: Optional[Dict[str, Callable[[Dict[str, Any]], bool]]] = None,
        clock: Optional[Callable[[], float]] = None,
        max_age: Optional[int] = None,
        expected_sub: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
        required_roles: Optional[List[str]] = None,
        required_access_ids: Optional[List[str]] = None,
        required_session_id: Optional[str] = None
    ):
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self.custom_validators = custom_validators or {}
        self.clock = clock or time.time
        self.max_age = max_age
        self.expected_sub = expected_sub
        self.required_scopes = required_scopes
        self.required_roles = required_roles
        self.required_access_ids = required_access_ids
        self.required_session_id = required_session_id

    def validate(self, payload: Dict[str, Any]):
        """Verify standard and custom claims."""
        now = self.clock()

        # 1. Expired
        exp = payload.get("exp")
        if exp is not None:
            if now > (exp + self.leeway):
                raise ExpiredTokenError("Token has expired")

        # 2. Not before
        nbf = payload.get("nbf")
        if nbf is not None:
            if now < (nbf - self.leeway):
                raise ValidationError("Token not valid yet (nbf)")

        # 3. Issued At in the past
        iat = payload.get("iat")
        if iat is not None:
            if now < (iat - self.leeway):
                raise ValidationError("Token issued in the future (iat)")
                
            # Max Age Check
            if self.max_age is not None:
                if now - iat > self.max_age:
                    raise ValidationError(f"Token is too old: max age is {self.max_age}s")

        # 4. Issuer
        if self.issuer:
            iss = payload.get("iss")
            if isinstance(self.issuer, list):
                if iss not in self.issuer:
                    raise InvalidIssuerError(f"Invalid issuer: {iss} not in allowed list {self.issuer}")
            elif iss != self.issuer:
                raise InvalidIssuerError(f"Invalid issuer: expected {self.issuer}, got {iss}")

        # 5. Audience
        if self.audience:
            audience_claim = payload.get("aud")
            allowed_auds = self.audience if isinstance(self.audience, list) else [self.audience]
            token_auds = audience_claim if isinstance(audience_claim, list) else [audience_claim] if audience_claim else []
            
            if not set(allowed_auds).intersection(set(token_auds)):
                raise InvalidAudienceError(f"Invalid audience: expected one of {allowed_auds}, got {audience_claim}")

        # 6. Subject Match
        if self.expected_sub:
            sub = payload.get("sub")
            if sub != self.expected_sub:
                raise ValidationError(f"Invalid subject: expected {self.expected_sub}, got {sub}")

        # 7. Role-Based Access Control (RBAC)
        if self.required_roles:
            token_roles = payload.get("roles") or payload.get("role")
            if not token_roles:
                raise ValidationError("Token missing required roles claim")
                
            if isinstance(token_roles, str):
                token_roles = [token_roles]
                
            missing_roles = [role for role in self.required_roles if role not in token_roles]
            if missing_roles:
                raise ValidationError(f"Token missing required roles: {missing_roles}")

        # 8. Scope Validation
        if self.required_scopes:
            token_scopes = payload.get("scp") or payload.get("scope") or payload.get("scopes")
            if not token_scopes:
                raise ValidationError("Token missing required scopes claim")
                
            if isinstance(token_scopes, str):
                token_scopes = token_scopes.split()
                
            missing_scopes = [scope for scope in self.required_scopes if scope not in token_scopes]
            if missing_scopes:
                raise ValidationError(f"Token missing required scopes: {missing_scopes}")

        # 9. Access IDs Validation
        if self.required_access_ids:
            token_access_ids = payload.get("access_ids")
            if not token_access_ids:
                raise ValidationError("Token missing required access_ids claim")
                
            if isinstance(token_access_ids, str):
                token_access_ids = [token_access_ids]
                
            missing_ids = [idx for idx in self.required_access_ids if idx not in token_access_ids]
            if missing_ids:
                raise ValidationError(f"Token missing required access_ids: {missing_ids}")

        # 10. Session ID Validation (Optional, defaults to allow if not required)
        if self.required_session_id:
            token_sid = payload.get("sid") or payload.get("session_id")
            if not token_sid:
                raise ValidationError("Token missing required session_id (sid) claim")
                
            if token_sid != self.required_session_id:
                raise ValidationError(f"Invalid session ID: expected {self.required_session_id}, got {token_sid}")

        # 11. Custom Validators
        for claim_name, validator_func in self.custom_validators.items():
            try:
                if not validator_func(payload):
                    raise ValidationError(f"Custom validation failed for claim: {claim_name}")
            except ValidationError:
                raise
            except Exception as e:
                raise ValidationError(f"Custom validator error for claim '{claim_name}': {e}") from e
