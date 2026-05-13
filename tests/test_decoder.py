import pytest
import json
from src.async_jwt_core.core.decoder import base64url_decode, decode_json

def test_base64url_decode():
    # Test with padding needed
    encoded = "YW55IGNhcm5hbCBwbGVhc3VyZS4"  # "any carnal pleasure."
    decoded = base64url_decode(encoded)
    assert decoded == b"any carnal pleasure."

    # Test without padding needed
    encoded = "YW55IGNhcm5hbCBwbGVhc3VyZQ"  # "any carnal pleasure"
    decoded = base64url_decode(encoded)
    assert decoded == b"any carnal pleasure"

def test_decode_json():
    data = {"sub": "123", "name": "John"}
    encoded = json.dumps(data).encode("utf-8")
    decoded = decode_json(encoded)
    assert decoded == data

def test_decode_json_invalid():
    with pytest.raises(Exception):
        decode_json(b"invalid json")
