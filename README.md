# async-jwt-core

A minimal, spec-first, framework-agnostic, async-only JWT validator with zero network dependencies.

[![PyPI version](https://img.shields.io/pypi/v/async-jwt-core.svg)](https://pypi.org/project/async-jwt-core/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 Why `async-jwt-core`? (The Problem We Solve)

In the modern Python async ecosystem, validating JWTs using JSON Web Key Sets (JWKS) usually forces you into one of two bad situations:
1.  **Framework Lock-in**: Libraries tied directly to FastAPI, Starlette, or Django.
2.  **Opinionated I/O**: Libraries that insist on making network calls for you (often using specific HTTP clients) to fetch keys.

**`async-jwt-core` solves this by doing exactly one thing perfectly: Pure Cryptographic Validation without I/O.**

We provide the core validation logic. You bring the keys. This gives you absolute control over how keys are fetched, cached, and stored, while ensuring your event loop never blocks.

---

## 💡 Core Examples: Why You Should Use It

### 1. The Direct Approach (FastAPI Dependency)
Validate a token in **FastAPI** without letting the JWT library block your event loop with hidden network calls.

```python
from fastapi import FastAPI, Depends, HTTPException, Request
from async_jwt_core import Validator, ValidationError

app = FastAPI()
validator = Validator(algorithms=["RS256"])

@app.get("/protected")
async def protected_route(request: Request):
    try:
        # Extract token from request headers
        token = Validator.extract_token(request)
        
        # YOU fetch the keys (e.g., from Redis). No hidden I/O!
        jwks = await my_custom_key_fetcher() 
        
        # Validate!
        claims = await validator.validate(token, jwks)
        return {"message": f"Welcome {claims.sub}!"}
        
    except ValidationError as e:
        raise HTTPException(status_code=401, detail=str(e))
```

### 2. The Middleware Approach (FastAPI)
Just like you add `CORSMiddleware`, you can add our `FastAPIMiddleware` to protect all routes automatically!

```python
from fastapi import FastAPI
from async_jwt_core import Validator
from async_jwt_core.middleware import FastAPIMiddleware

app = FastAPI()

# 1. Initialize validator (Uses ASYNC_JWT_ISSUER from ENV)
validator = Validator(algorithms=["RS256"])

# 2. Add middleware just like CORSMiddleware!
app.add_middleware(
    FastAPIMiddleware,
    validator=validator,
    jwks={"keys": [...]} # Pass your JWKS here
)

@app.get("/protected")
async def protected_route(request: Request):
    # Claims are automatically attached to request.state!
    claims = request.state.user_claims
    return {"message": f"Hello {claims.sub}"}
```

---

## 🏆 Feature Showcase: Why We Are the Best

Here is a comparison of why `async-jwt-core` is the ultimate choice for modern Python web applications:

| Feature / Capability | Standard PyJWT | Framework Libs | `async-jwt-core` |
| :--- | :---: | :---: | :---: |
| **Async Native** | ❌ (Sync only) | 🟡 (Sometimes) | ✅ |
| **Zero I/O (Absolute Control)** | ✅ | ❌ (Often fetches keys) | ✅ |
| **No Framework Lock-in** | ✅ | ❌ (FastAPI/Django only) | ✅ |
| **Extensible Algorithms**| ❌ (Hard to add) | ❌ (Hard to add) | ✅ |
| **In-built Middlewares**| ❌ | ❌ | ✅ (FastAPI, Flask, Django) |
| **In-built Rate Limiting** | ❌ | ❌ | ✅ (Token Bucket) |
| **JWE Decryption** | ❌ | ❌ | ✅ (RSA-OAEP + AES-GCM) |
| **Token Creation (Signing)** | ✅ | ❌ | ✅ |
| **Role & Scope Validation (RBAC)**| ❌ (Do it yourself)| ❌ (Do it yourself)| ✅ |
| **Access IDs Validation** | ❌ (Do it yourself)| ❌ (Do it yourself)| ✅ |
| **Session ID Validation** | ❌ (Do it yourself)| ❌ (Do it yourself)| ✅ |

---

## ✨ Key Features

-   🔒 **Zero Network I/O** – Keys are fetched externally.
-   ⚡ **Async-Only API** – Designed from the ground up for `asyncio`.
-   🧩 **Framework Agnostic** – Works with FastAPI, Sanic, aiohttp, Flask, or Django.
-   🎯 **Custom Claim Validation** – Pass your own validation functions.
-   📦 **Ultra Lightweight** – Only depends on `cryptography`.

## 🔐 Supported Algorithms

We support a vast range of modern cryptographic algorithms out of the box (**13 total**):
`HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, `EdDSA`.

---

## 🔬 How to Test Your Application

Testing an application that uses `async-jwt-core` is easy. You can mock the `Validator` or create valid tokens for testing using `Encoder`.

Here is an example using `pytest` and `httpx` to test a FastAPI endpoint:

```python
import pytest
from httpx import AsyncClient
from async_jwt_core import Encoder

@pytest.mark.asyncio
async def test_protected_route():
    from my_app import app # Import your FastAPI app
    
    # 1. Create a valid token for testing
    header = {"alg": "HS256", "kid": "test-key"}
    payload = {"sub": "user123", "roles": ["admin"]}
    secret = "my-test-secret"
    
    token = Encoder.create_token(header, payload, secret)
    
    # 2. Call your protected endpoint
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"}
        )
        
    assert response.status_code == 200
    assert response.json()["message"] == "Welcome user123!"
```

---

## 📖 Examples (References for Users)

We provide full working examples in the GitHub repository:

-   📄 **[Basic Usage](https://github.com/Bishwajitgarai/async-jwt-core/blob/main/examples/basic_usage.py)**: Shows how to create and validate a token.
-   🚀 **[FastAPI Demo](https://github.com/Bishwajitgarai/async-jwt-core/blob/main/examples/fastapi_demo.py)**: Shows how to integrate with FastAPI.
-   🌶️ **[Flask Demo](https://github.com/Bishwajitgarai/async-jwt-core/blob/main/examples/flask_demo.py)**: Shows how to use it in Flask.
-   🎸 **[Django Demo](https://github.com/Bishwajitgarai/async-jwt-core/blob/main/examples/django_demo.py)**: Shows how to use it in Django.

---

## 🛠️ Installation

```bash
uv add async-jwt-core
```

---

## 🔗 Project Links & Resources

-   📦 **PyPI**: [https://pypi.org/project/async-jwt-core/](https://pypi.org/project/async-jwt-core/)
-   🐙 **GitHub**: [https://github.com/Bishwajitgarai/async-jwt-core](https://github.com/Bishwajitgarai/async-jwt-core)

## 🤝 Contributing

We welcome contributions! This is an open-source project designed to make async JWT validation better for everyone. If you have ideas for new features, bug fixes, or improvements, feel free to open an issue or submit a pull request on GitHub!

## 👤 Author

Developed and maintained by **[Bishwajit Garai](https://github.com/Bishwajitgarai)**.

---

## 📄 License

MIT
