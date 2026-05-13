# async-jwt-core

A minimal, spec-first, framework-agnostic, async-only JWT validator with zero network dependencies.

[![PyPI version](https://img.shields.io/pypi/v/async-jwt-core.svg)](https://pypi.org/project/async-jwt-core/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

- **PyPI**: https://pypi.org/project/async-jwt-core/
- **GitHub**: https://github.com/Bishwajitgarai/async-jwt-core

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

## 🔐 Supported Algorithms

We support a vast range of modern cryptographic algorithms out of the box:

| Type | Algorithms |
| :--- | :--- |
| **HMAC** (Symmetric) | `HS256`, `HS384`, `HS512` |
| **RSA** (Asymmetric) | `RS256`, `RS384`, `RS512` |
| **RSA-PSS** (Asymmetric)| `PS256`, `PS384`, `PS512` |
| **ECDSA** (Elliptic Curve)| `ES256`, `ES384`, `ES512` |

## 🌟 Extra Features to Help You

To make your life easier, we include features that other libraries charge you in complexity:

### 1. JSON Web Encryption (JWE) Support
We don't just do signing. We now support **JWE decryption** (RSA-OAEP with AES-GCM). This allows you to handle encrypted tokens where the payload is hidden.
```python
from async_jwt_core import JWE

# Decrypt an encrypted token
decrypted_payload = await JWE.decrypt(token, private_key)
```

### 2. Unverified Decoding
Need to check the claims or header before you validate the token? No problem.
```python
header = await validator.get_unverified_header(token)
payload = await validator.decode_unverified(token)
```

### 3. Built-in Async JWKS Cache
Even though we don't do I/O, we provide a simple async in-memory cache with TTL so you don't have to write your own.
```python
from async_jwt_core import JWKSCache

cache = JWKSCache(ttl=3600)

# In your request handler:
jwks = await cache.get()
if not jwks:
    jwks = await fetch_jwks_from_web()
    await cache.set(jwks)
```

## 🛠️ Installation

```bash
uv add async-jwt-core
# or
pip install async-jwt-core
```

## 📖 Usage Examples

### The Standard Use Case (With External Fetching)

```python
import asyncio
import aiohttp
from async_jwt_core import Validator, ValidationError

# Initialize once
validator = Validator(
    algorithms=["RS256", "ES256"],
    issuer="https://YOUR-AUTH-DOMAIN.com",
    audience="YOUR-API-AUDIENCE"
)

async def fetch_jwks(url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            return await resp.json()

async def authenticate(token: str):
    jwks = await fetch_jwks("https://YOUR-AUTH-DOMAIN.com/.well-known/jwks.json")
    
    try:
        claims = await validator.validate(token, jwks)
        print(f"Authenticated user: {claims.sub}")
        return claims
    except ValidationError as e:
        print(f"Auth failed: {e}")
        return None
```

## ⚖️ Why We Are Better

| Feature | Standard PyJWT | Framework Libs | `async-jwt-core` |
| :--- | :---: | :---: | :---: |
| **Async Native** | ❌ (Sync only) | 🟡 (Sometimes) | ✅ |
| **Zero I/O** | ✅ | ❌ (Often fetches keys) | ✅ |
| **No Lock-in** | ✅ | ❌ (FastAPI/Django only) | ✅ |
| **Extensible Algs**| ❌ (Hard to add) | ❌ (Hard to add) | ✅ |

## 🤝 Contributing

We built this for the community! If you want to add support for more algorithms (like EdDSA) or improve the claims system, check out our modular folder structure in `src/async_jwt_core/algorithms/`. It is designed to be easy to extend.

## 📄 License

MIT
