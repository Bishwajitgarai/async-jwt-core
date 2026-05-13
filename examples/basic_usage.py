import asyncio
import base64
import json
import time
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from async_jwt_core import Validator, ValidationError

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

async def run_rsa_demo():
    print("--- Running RSA (RS256) Demo ---")
    
    # 1. Generate a test RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # 2. Create a JWK from the public key
    public_numbers = public_key.public_numbers()
    n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder="big")
    e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder="big")
    
    jwk = {
        "kty": "RSA",
        "kid": "test-rsa-key",
        "alg": "RS256",
        "use": "sig",
        "n": base64url_encode(n_bytes),
        "e": base64url_encode(e_bytes),
    }
    
    jwks = {"keys": [jwk]}

    # 3. Create a JWT
    header = {
        "alg": "RS256",
        "kid": "test-rsa-key"
    }
    
    now = int(time.time())
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iss": "https://your-auth-domain.com",
        "aud": "your-api-audience",
        "exp": now + 3600,
        "iat": now,
        "role": "admin"
    }
    
    header_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    
    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    signature_b64 = base64url_encode(signature)
    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    print("Token generated.")

    # 4. Validate
    validator = Validator(
        algorithms=["RS256"],
        issuer="https://your-auth-domain.com",
        audience="your-api-audience"
    )
    
    try:
        claims = await validator.validate(token, jwks)
        print("Validation SUCCESS!")
        print(f"Subject: {claims.sub}")
    except ValidationError as e:
        print(f"Validation FAILED: {e}")

async def main():
    await run_rsa_demo()

if __name__ == "__main__":
    asyncio.run(main())
