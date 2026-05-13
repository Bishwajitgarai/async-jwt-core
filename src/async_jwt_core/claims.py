from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass
class JWTClaims:
    """Represents the claims of a validated JWT."""
    sub: Optional[str] = None
    iss: Optional[str] = None
    aud: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    jti: Optional[str] = None
    
    # Allow for arbitrary claims
    extra_claims: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JWTClaims":
        """Create a JWTClaims object from a dictionary."""
        known_claims = {"sub", "iss", "aud", "exp", "iat", "nbf", "jti"}
        
        kwargs = {}
        extra = {}
        
        for key, value in data.items():
            if key in known_claims:
                kwargs[key] = value
            else:
                extra[key] = value
                
        return cls(**kwargs, extra_claims=extra)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a claim by key, checking both standard and extra claims."""
        if hasattr(self, key) and getattr(self, key) is not None:
            return getattr(self, key)
        return self.extra_claims.get(key, default)
