from .core.validator import Validator
from .claims.model import JWTClaims
from .exceptions import (
    ValidationError,
    ExpiredTokenError,
    InvalidSignatureError,
    InvalidIssuerError,
    InvalidAudienceError,
)

__version__ = "0.2.0"  # Bump version as requested for a bigger architecture

__all__ = [
    "Validator",
    "JWTClaims",
    "ValidationError",
    "ExpiredTokenError",
    "InvalidSignatureError",
    "InvalidIssuerError",
    "InvalidAudienceError",
]
