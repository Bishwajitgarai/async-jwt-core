# async-jwt-core

A minimal, spec-first, framework-agnostic, async-only JWT validator with zero network dependencies.

[![PyPI version](https://img.shields.io/pypi/v/async-jwt-core.svg)](https://pypi.org/project/async-jwt-core/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 Why `async-jwt-core`? (The Problem We Solve)

In the modern Python async ecosystem, validating JWTs using JSON Web Key Sets (JWKS) usually forces you into one of two bad situations:
1.  **Framework Lock-in**: Libraries tied directly to FastAPI, Starlette, or Django.
2.  **Opinionated I/O**: Libraries that insist on making network calls for you (often using specific HTTP clients) to fetch keys, making it hard to implement custom caching (like Redis) or use your own HTTP session.

**`async-jwt-core` solves this by doing exactly one thing perfectly: Pure Cryptographic Validation without I/O.**

We provide the core validation logic. You bring the keys. This gives you absolute control over how keys are fetched, cached, and stored, while ensuring your event loop never blocks.

## ✨ Key Features

-   🔒 **Zero Network I/O** – Keys are fetched externally. The validator only does the heavy lifting (crypto and claim checks).
-   ⚡ **Async-Only API** – Designed from the ground up for `asyncio`.
-   🧩 **Framework Agnostic** – Works with FastAPI, Sanic, aiohttp, or even pure Python background workers.
-   🛠️ **Highly Modular & Extensible** – Want to add a custom algorithm? Just inherit from `Algorithm` and register it.
-   🎯 **Custom Claim Validation** – Pass your own validation functions to enforce business rules during the validation phase.
-   📦 **Ultra Lightweight** – Only depends on `cryptography` for secure signature verification.

## 🛠️ Installation

```bash
uv add async-jwt-core
# or
pip install async-jwt-core
```

## 📖 Usage Examples

### 1. The Standard Use Case (With External Fetching)

Here is how you use it in an async environment where you control the I/O:

```python
import asyncio
import aiohttp
from async_jwt_core import Validator, ValidationError

# Initialize once
validator = Validator(
    algorithms=["RS256"],
    issuer="https://auth.example.com",
    audience="api.example.com"
)

async def fetch_jwks(url: str) -> dict:
    """Developer controls all network calls and caching."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            return await resp.json()

async def authenticate(token: str):
    # Fetch keys (ideally you'd cache this in Redis or memory)
    jwks = await fetch_jwks("https://auth.example.com/.well-known/jwks.json")
    
    try:
        # Pure async validation
        claims = await validator.validate(token, jwks)
        print(f"Authenticated user: {claims.sub}")
        return claims
    except ValidationError as e:
        print(f"Auth failed: {e}")
        return None
```

### 2. Advanced: Custom Claim Validation

Ensure your users have the right roles right during the validation step:

```python
def validate_is_admin(payload: dict) -> bool:
    return "admin" in payload.get("roles", [])

validator = Validator(
    algorithms=["RS256"],
    custom_validators={"is_admin": validate_is_admin}
)
```

## ⚖️ Why We Are Better

| Feature | Standard PyJWT | Framework Libs | `async-jwt-core` |
| :--- | :---: | :---: | :---: |
| **Async Native** | ❌ (Sync only) |  (Sometimes) |  |
| **Zero I/O** |  | ❌ (Often fetches keys) |  |
| **No Lock-in** |  | ❌ (FastAPI/Django only) |  |
| **Extensible Algs**| ❌ (Hard to add) | ❌ (Hard to add) |  |

## 🤝 Contributing

We built this for the community! If you want to add support for more algorithms (like EdDSA or ES256) or improve the claims system, check out our modular folder structure in `src/async_jwt_core/algorithms/`. It is designed to be easy to extend.

## 📄 License

MIT
