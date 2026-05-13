import json
import base64
from typing import Dict, Any
from ..algorithms import get_algorithm

def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

class Encoder:
    """A helper to create and sign JWT tokens.
    
    This makes the library a complete JWT solution, not just a validator.
    """
    
    @staticmethod
    def create_token(header: Dict[str, Any], payload: Dict[str, Any], key: Any) -> str:
        """Create a signed JWT token.
        
        Args:
            header: Dict containing 'alg' and optionally 'kid', etc.
            payload: Dict containing claims.
            key: The key to sign with (bytes for HMAC, private key object for RSA).
        """
        alg_name = header.get("alg")
        if not alg_name:
            raise ValueError("Token header missing 'alg'")
            
        algorithm = get_algorithm(alg_name)
        
        header_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
        payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
        
        message = f"{header_b64}.{payload_b64}".encode("utf-8")
        
        signature = algorithm.sign(message, key)
        signature_b64 = base64url_encode(signature)
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
