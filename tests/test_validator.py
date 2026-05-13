import pytest
import asyncio
import time
import json
import hmac
import hashlib
import base64
from src.async_jwt_core import Validator, ValidationError

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

@pytest.mark.asyncio
async def test_validator_hs256():
    secret = b"my-little-secret-key-that-is-long"
    jwk = {
        "kty": "oct",
        "kid": "key-1",
        "alg": "HS256",
        "k": base64url_encode(secret)
    }
    jwks = {"keys": [jwk]}

    validator = Validator(algorithms=["HS256"])

    # Create token
    header = {"alg": "HS256", "kid": "key-1"}
    now = int(time.time())
    payload = {"sub": "user123", "exp": now + 100}
    
    header_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    
    h = hmac.new(secret, message, hashlib.sha256)
    signature = h.digest()
    signature_b64 = base64url_encode(signature)
    
    token = f"{header_b64}.{payload_b64}.{signature_b64}"

    # Validate
    claims = await validator.validate(token, jwks)
    assert claims.sub == "user123"

@pytest.mark.asyncio
async def test_validator_invalid_signature():
    secret = b"my-little-secret-key-that-is-long"
    jwk = {
        "kty": "oct",
        "kid": "key-1",
        "alg": "HS256",
        "k": base64url_encode(secret)
    }
    jwks = {"keys": [jwk]}

    validator = Validator(algorithms=["HS256"])

    # Create token with invalid signature
    header = {"alg": "HS256", "kid": "key-1"}
    payload = {"sub": "user123"}
    
    header_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    
    token = f"{header_b64}.{payload_b64}.invalid_signature"

    # Validate should fail
    with pytest.raises(ValidationError):
        await validator.validate(token, jwks)
