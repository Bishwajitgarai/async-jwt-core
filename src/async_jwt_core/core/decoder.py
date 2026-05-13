import base64
import json
from typing import Any

def base64url_decode(s: str) -> bytes:
    """Decode base64url string."""
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)

def decode_json(data: bytes) -> Any:
    """Decode JSON from bytes."""
    return json.loads(data.decode("utf-8"))
