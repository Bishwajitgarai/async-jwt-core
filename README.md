# async-jwt-core

A minimal, spec-first, framework-agnostic, async-only JWT validator with zero network dependencies.

## Features

- **Zero network I/O** – Keys are fetched externally, `Validator` only does cryptographic checks.
- **Async-only** – All methods are `async def`, no sync fallbacks that could block the event loop.
- **Framework-agnostic** – No imports of FastAPI, Flask, etc. Works with any asyncio code.
- **Typed** – Returns a clean `JWTClaims` object (with typed attributes like `sub`, `exp`, `iat`).
- **Minimal surface** – Just `Validator` and a few exceptions like `ValidationError`, `ExpiredTokenError`, `InvalidSignatureError`.

## Installation

```bash
pip install async-jwt-core
```

## Usage Example

Here is an example of how to use `async-jwt-core` in an application:

```python
import asyncio
import aiohttp
from async_jwt_core import Validator, JWTClaims, ValidationError

# Framework-agnostic – no hidden I/O
validator = Validator(
    algorithms=["RS256", "EdDSA"],
    issuer="https://auth.example.com",
    audience="api.example.com",
    leeway=10,  # seconds clock skew tolerance
)

async def fetch_jwks(url: str) -> dict:
    """Developer controls all network calls."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            return await resp.json()

async def validate_request(token: str) -> JWTClaims:
    jwks = await fetch_jwks("https://auth.example.com/.well-known/jwks.json")
    # Pure async validation – no blocking I/O
    claims = await validator.validate(token, jwks)
    return claims

# Usage in any async context (bare asyncio, FastAPI, Starlette, aiohttp, etc.)
async def main():
    token = "eyJhbGciOi..."   # JWT from request
    try:
        claims = await validate_request(token)
        print(claims.sub, claims.exp)
    except ValidationError as e:
        print(f"Invalid token: {e}")

asyncio.run(main())
```

## License

MIT
