import pytest
import time
from src.async_jwt_core.claims import ClaimsValidator
from src.async_jwt_core.exceptions import ExpiredTokenError, InvalidIssuerError, InvalidAudienceError, ValidationError

def test_claims_validator_valid():
    validator = ClaimsValidator(issuer="https://auth.com", audience="api")
    now = int(time.time())
    payload = {
        "iss": "https://auth.com",
        "aud": "api",
        "exp": now + 100,
        "nbf": now - 100,
        "iat": now - 100
    }
    # Should not raise any exception
    validator.validate(payload)

def test_claims_validator_expired():
    validator = ClaimsValidator()
    now = int(time.time())
    payload = {
        "exp": now - 100
    }
    with pytest.raises(ExpiredTokenError):
        validator.validate(payload)

def test_claims_validator_issuer_mismatch():
    validator = ClaimsValidator(issuer="https://auth.com")
    payload = {
        "iss": "https://wrong.com"
    }
    with pytest.raises(InvalidIssuerError):
        validator.validate(payload)

def test_claims_validator_audience_mismatch():
    validator = ClaimsValidator(audience="api")
    payload = {
        "aud": "wrong-api"
    }
    with pytest.raises(InvalidAudienceError):
        validator.validate(payload)

def test_claims_validator_custom_validator():
    def is_admin(p):
        return p.get("role") == "admin"
        
    validator = ClaimsValidator(custom_validators={"is_admin": is_admin})
    
    # Valid
    validator.validate({"role": "admin"})
    
    # Invalid
    from src.async_jwt_core.exceptions import ValidationError
    with pytest.raises(ValidationError, match="Custom validation failed for claim: is_admin"):
        validator.validate({"role": "user"})

def test_claims_validator_rbac():
    validator = ClaimsValidator(required_roles=["admin"])
    
    # Valid
    validator.validate({"roles": ["admin", "user"]})
    validator.validate({"role": "admin"})
    
    # Invalid
    with pytest.raises(ValidationError, match="Token missing required roles"):
        validator.validate({"roles": ["user"]})
    with pytest.raises(ValidationError, match="Token missing required roles claim"):
        validator.validate({})

def test_claims_validator_scopes():
    validator = ClaimsValidator(required_scopes=["read", "write"])
    
    # Valid
    validator.validate({"scopes": ["read", "write", "delete"]})
    validator.validate({"scope": "read write"})
    
    # Invalid
    with pytest.raises(ValidationError, match="Token missing required scopes"):
        validator.validate({"scopes": ["read"]})
    with pytest.raises(ValidationError, match="Token missing required scopes claim"):
        validator.validate({})

def test_claims_validator_access_ids():
    validator = ClaimsValidator(required_access_ids=["id1", "id2"])
    
    # Valid
    validator.validate({"access_ids": ["id1", "id2", "id3"]})
    
    # Invalid
    with pytest.raises(ValidationError, match="Token missing required access_ids"):
        validator.validate({"access_ids": ["id1"]})

def test_claims_validator_session_id():
    validator = ClaimsValidator(required_session_id="sess123")
    
    # Valid
    validator.validate({"sid": "sess123"})
    validator.validate({"session_id": "sess123"})
    
    # Invalid
    with pytest.raises(ValidationError, match="Invalid session ID"):
        validator.validate({"sid": "sess456"})
    with pytest.raises(ValidationError, match="Token missing required session_id"):
        validator.validate({})
