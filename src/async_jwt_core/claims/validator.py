import time
from typing import Dict, Any, Optional, List
from ..exceptions import ExpiredTokenError, InvalidIssuerError, InvalidAudienceError, ValidationError

class ClaimsValidator:
    """Validator for standard JWT claims."""
    
    def __init__(
        self,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        leeway: int = 0,
    ):
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway

    def validate(self, payload: Dict[str, Any]):
        """Verify standard claims."""
        now = time.time()

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

        # 3. Issuer
        if self.issuer:
            iss = payload.get("iss")
            if iss != self.issuer:
                raise InvalidIssuerError(f"Invalid issuer: expected {self.issuer}, got {iss}")

        # 4. Audience
        audience_claim = payload.get("aud")
        if self.audience:
            if isinstance(audience_claim, list):
                if self.audience not in audience_claim:
                    raise InvalidAudienceError(f"Invalid audience: {self.audience} not in {audience_claim}")
            elif audience_claim != self.audience:
                raise InvalidAudienceError(f"Invalid audience: expected {self.audience}, got {audience_claim}")
