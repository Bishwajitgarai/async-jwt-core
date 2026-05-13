import asyncio
import base64
import json
import time
import logging
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

async def run_demo():
    logger.info("Starting async-jwt-core Demo")
    
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
        "kid": "test-key-id",
        "alg": "RS256",
        "use": "sig",
        "n": base64url_encode(n_bytes),
        "e": base64url_encode(e_bytes),
    }
    
    jwks = {"keys": [jwk]}
    logger.info("JWKS created with 1 key.")

    # 3. Create a JWT
    header = {
        "alg": "RS256",
        "kid": "test-key-id"
    }
    
    now = int(time.time())
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iss": "https://auth.example.com",
        "aud": "api.example.com",
        "exp": now + 3600,
        "iat": now
    }
    
    header_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    
    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    
    # Sign the message
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    signature_b64 = base64url_encode(signature)
    
    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    logger.info("Token generated.")

    # 4. Validate the token using our library
    logger.info("Validating token...")
    validator = Validator(
        algorithms=["RS256"],
        issuer="https://auth.example.com",
        audience="api.example.com"
    )
    
    try:
        claims = await validator.validate(token, jwks)
        logger.info("Validation SUCCESS!")
        logger.info(f"Subject: {claims.sub}")
        logger.info(f"Issuer: {claims.iss}")
        logger.info(f"Audience: {claims.aud}")
        logger.info(f"Custom claims: {claims.extra_claims}")
    except ValidationError as e:
        logger.error(f"Validation FAILED: {e}")

async def main():
    await run_demo()

if __name__ == "__main__":
    asyncio.run(main())
