import asyncio
import base64
import json
import time
import logging
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from src.async_jwt_core import Validator, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("async-jwt-core-demo")

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

async def run_rsa_demo():
    logger.info("--- Running RSA (RS256) Demo ---")
    
    # 1. Generate a test RSA key pair
    logger.info("Generating RSA key pair...")
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
    logger.info("JWKS created with 1 RSA key.")

    # 3. Create a JWT
    header = {
        "alg": "RS256",
        "kid": "test-rsa-key"
    }
    
    now = int(time.time())
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iss": "https://auth.example.com",
        "aud": "api.example.com",
        "exp": now + 3600,
        "iat": now,
        "role": "admin"  # For custom validation
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
    logger.info("RSA Token generated.")

    # 4. Custom Validator
    def validate_is_admin(claims_dict: dict) -> bool:
        return claims_dict.get("role") == "admin"

    # 5. Validate
    validator = Validator(
        algorithms=["RS256"],
        issuer="https://auth.example.com",
        audience="api.example.com",
        custom_validators={"is_admin": validate_is_admin}
    )
    
    try:
        claims = await validator.validate(token, jwks)
        logger.info("RSA Validation SUCCESS!")
        logger.info(f"Subject: {claims.sub}")
        logger.info(f"Role checked via custom validator: {claims.extra_claims.get('role')}")
    except ValidationError as e:
        logger.error(f"RSA Validation FAILED: {e}")

async def run_hmac_demo():
    logger.info("\n--- Running HMAC (HS256) Demo ---")
    
    # 1. Create a symmetric key
    secret = b"super-secret-key-that-is-at-least-32-bytes-long!!"
    
    jwk = {
        "kty": "oct",
        "kid": "test-hmac-key",
        "alg": "HS256",
        "k": base64url_encode(secret)
    }
    
    jwks = {"keys": [jwk]}
    logger.info("JWKS created with 1 HMAC key.")

    # 2. Create a JWT
    header = {
        "alg": "HS256",
        "kid": "test-hmac-key"
    }
    
    now = int(time.time())
    payload = {
        "sub": "0987654321",
        "name": "Jane Doe",
        "iss": "https://auth.example.com",
        "exp": now + 3600
    }
    
    header_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    
    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    
    # Sign with HMAC
    h = hmac.new(secret, message, hashlib.sha256)
    signature = h.digest()
    
    signature_b64 = base64url_encode(signature)
    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    logger.info("HMAC Token generated.")

    # 3. Validate
    validator = Validator(
        algorithms=["HS256"],
        issuer="https://auth.example.com"
    )
    
    try:
        claims = await validator.validate(token, jwks)
        logger.info("HMAC Validation SUCCESS!")
        logger.info(f"Subject: {claims.sub}")
    except ValidationError as e:
        logger.error(f"HMAC Validation FAILED: {e}")

async def main():
    await run_rsa_demo()
    await run_hmac_demo()

if __name__ == "__main__":
    asyncio.run(main())
