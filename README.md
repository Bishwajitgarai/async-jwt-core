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
-   🎯 **Custom Claim Validation** – Pass your own validation functions to enforce business rules.
-   📦 **Ultra Lightweight** – Only depends on `cryptography` for secure signature verification.

## 🔐 Supported Algorithms

We support a vast range of modern cryptographic algorithms out of the box (12 total):

| Type | Algorithms |
| :--- | :--- |
| **HMAC** (Symmetric) | `HS256`, `HS384`, `HS512` |
| **RSA** (Asymmetric) | `RS256`, `RS384`, `RS512` |
| **RSA-PSS** (Asymmetric)| `PS256`, `PS384`, `PS512` |
| **ECDSA** (Elliptic Curve)| `ES256`, `ES384`, `ES512` |

## 🌟 Extra Features to Help You (30+ Features Total)

To make your life easier, we include features that other libraries charge you in complexity:

### 1. Token Extraction from Requests
Extract the JWT token directly from a request object (like FastAPI, Starlette, Flask, or Django Request) or a dictionary of headers.
```python
token = Validator.extract_token(request)
```

### 2. In-built Async Rate Limiter
Protect your validation endpoint from brute-force or DoS attacks with an in-memory Token Bucket rate limiter.

### 3. Auto Environment Variable Defaults
We automatically load critical defaults from environment variables if not specified in code (e.g., `JWT_ALGORITHMS`, `JWT_ISSUER`).

### 4. JSON Web Encryption (JWE) Support
We support **JWE decryption** (RSA-OAEP with AES-GCM) to handle encrypted tokens.

### 5. Nonce / Replay Detection
Prevent replay attacks by checking the `jti` (JWT ID) claim via an async callback.

## 📖 Examples (References for Users)

We provide full working examples in the `examples/` directory of the repository:

-   📄 **[Basic Usage](examples/basic_usage.py)**: Shows how to generate keys, create a token, and validate it using RSA.
-   🚀 **[FastAPI Demo](examples/fastapi_demo.py)**: Shows how to integrate with FastAPI using the `extract_token` helper.
-   🌶️ **[Flask Demo](examples/flask_demo.py)**: Shows how to use it in Flask 2.0+ async routes.
-   🎸 **[Django Demo](examples/django_demo.py)**: Shows how to use it in Django 3.1+ async views.

Check the folder for more references on how to use the library in real-world scenarios.

## 🛠️ Installation

```bash
uv add async-jwt-core
# or
pip install async-jwt-core
```

## ⚖️ Why We Are Better

| Feature | Standard PyJWT | Framework Libs | `async-jwt-core` |
| :--- | :---: | :---: | :---: |
| **Async Native** | ❌ (Sync only) | 🟡 (Sometimes) | ✅ |
| **Zero I/O** | ✅ | ❌ (Often fetches keys) | ✅ |
| **No Lock-in** | ✅ | ❌ (FastAPI/Django only) | ✅ |
| **Extensible Algs**| ❌ (Hard to add) | ❌ (Hard to add) | ✅ |

## 📄 License

MIT
