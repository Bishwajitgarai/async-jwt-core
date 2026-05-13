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

### 1. In-built Async Rate Limiter
Protect your validation endpoint from brute-force or DoS attacks with an in-memory Token Bucket rate limiter.
```python
validator = Validator(algorithms=["RS256"], rate_limit_rps=10.0, rate_limit_burst=20.0)
```

### 2. Auto Environment Variable Defaults
We automatically load critical defaults from environment variables if not specified in code:
-   `JWT_ALGORITHMS` (Comma separated)
-   `JWT_ISSUER`
-   `JWT_AUDIENCE`

### 3. JSON Web Encryption (JWE) Support
We don't just do signing. We now support **JWE decryption** (RSA-OAEP with AES-GCM). This allows you to handle encrypted tokens where the payload is hidden.

### 4. Nonce / Replay Detection
Prevent replay attacks by checking the `jti` (JWT ID) claim. Pass an async callback to check uniqueness against your database or Redis.

### 5. Token Introspection (RFC 7662)
Validate opaque tokens by parsing responses from an introspection endpoint.

### 6. Multiple Issuers & Audiences
Support passing a list of allowed issuers and audiences for multi-tenant applications.

### 7. Custom Clock for Testing
Pass a custom function to get the current time, making it easy to test expiration logic.

### 8. Token Type (`typ`) Validation
Enforce that the token has a specific type in the header (e.g., `JWT`).

### 9. Strict Key Type Validation (Security)
We enforce that the JWK's `kty` matches the algorithm used (e.g., `RS256` requires `RSA`), preventing algorithm confusion attacks.

### 10. Token Max Age Check
Enforce that a token was issued recently based on the `iat` claim, independent of the `exp` claim.

### 11. Subject (`sub`) Matching
Directly validate that the token belongs to a specific user.

### 12. Header Extraction Helpers
Extract `kid`, `alg`, `jku`, and `x5c` directly from the token without verification, helping you decide how to process it.

### 13. Built-in Async JWKS Cache
Even though we don't do I/O, we provide a simple async in-memory cache with TTL so you don't have to write your own.

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
