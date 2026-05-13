import pytest
import json
import base64
from src.async_jwt_core import Encoder, Validator, ValidationError

def base64url_decode(b64_str):
    rem = len(b64_str) % 4
    if rem > 0:
        b64_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(b64_str)

def test_create_token_hs256():
    header = {"alg": "HS256", "kid": "key-1"}
    payload = {"sub": "1234567890", "name": "John Doe"}
    secret = b"my-secret-key-that-is-at-least-32-bytes-long!!"

    # Create token
    token = Encoder.create_token(header, payload, secret)
    assert token is not None
    
    parts = token.split(".")
    assert len(parts) == 3
    
    # Verify content
    header_decoded = json.loads(base64url_decode(parts[0]).decode("utf-8"))
    payload_decoded = json.loads(base64url_decode(parts[1]).decode("utf-8"))
    
    assert header_decoded == header
    assert payload_decoded == payload
