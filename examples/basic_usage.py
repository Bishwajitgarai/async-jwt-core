import asyncio
import time
from async_jwt_core import Validator, Encoder, ValidationError

async def run_demo():
    print("--- Running async-jwt-core Demo ---")
    
    # 1. Create a token (HMAC)
    print("Creating token...")
    secret = b"super-secret-key-that-is-at-least-32-bytes-long!!"
    
    header = {
        "alg": "HS256",
        "kid": "test-hmac-key"
    }
    
    now = int(time.time())
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iss": "https://your-auth-domain.com",
        "aud": "your-api-audience",
        "exp": now + 3600,
        "iat": now
    }
    
    # Use our Encoder!
    token = Encoder.create_token(header, payload, secret)
    print(f"Token created: {token[:20]}...")

    # 2. Setup Validator
    validator = Validator(
        algorithms=["HS256"],
        issuer="https://your-auth-domain.com",
        audience="your-api-audience"
    )
    
    # JWKS containing the secret
    import base64
    k_b64 = base64.urlsafe_b64encode(secret).decode("utf-8").rstrip("=")
    jwks = {
        "keys": [
            {
                "kty": "oct",
                "kid": "test-hmac-key",
                "alg": "HS256",
                "k": k_b64
            }
        ]
    }

    # 3. Validate
    try:
        claims = await validator.validate(token, jwks)
        print("Validation SUCCESS!")
        print(f"Subject: {claims.sub}")
    except ValidationError as e:
        print(f"Validation FAILED: {e}")

if __name__ == "__main__":
    asyncio.run(run_demo())
