class ValidationError(Exception):
    """Base exception for all validation errors."""
    pass

class ExpiredTokenError(ValidationError):
    """Raised when the token has expired."""
    pass

class InvalidSignatureError(ValidationError):
    """Raised when the token signature is invalid."""
    pass

class InvalidIssuerError(ValidationError):
    """Raised when the token issuer does not match."""
    pass

class InvalidAudienceError(ValidationError):
    """Raised when the token audience does not match."""
    pass
