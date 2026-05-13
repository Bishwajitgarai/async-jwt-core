import time
from typing import Dict, Any, Optional, List, Callable, Union

from ..exceptions import ExpiredTokenError, InvalidIssuerError, InvalidAudienceError, ValidationError

class ClaimsValidator:
    """Validator for standard and custom JWT claims."""
    
    def __init__(
        self,
        issuer: Optional[Union[str, List[str]]] = None,
        audience: Optional[Union[str, List[str]]] = None,
        leeway: int = 0,
        custom_validators: Optional[Dict[str, Callable[[Dict[str, Any]], bool]]] = None,
        clock: Optional[Callable[[], float]] = None,
        max_age: Optional[int] = None,
        expected_sub: Optional[str] = None
    ):
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self.custom_validators = custom_validators or {}
        self.clock = clock or time.time
        self.max_age = max_age
        self.expected_sub = expected_sub

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

        # 7. Custom Validators
        for claim_name, validator_func in self.custom_validators.items():
            try:
                if not validator_func(payload):
                    raise ValidationError(f"Custom validation failed for claim: {claim_name}")
            except ValidationError:
                raise
            except Exception as e:
                raise ValidationError(f"Custom validator error for claim '{claim_name}': {e}") from e
