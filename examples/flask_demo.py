from flask import Flask, request, jsonify
from async_jwt_core import Validator, ValidationError

app = Flask(__name__)

# Initialize validator
validator = Validator(
    algorithms=["HS256"],
    issuer="https://your-auth-domain.com"
)

MOCK_JWKS = {
    "keys": [
        {
            "kty": "oct",
            "kid": "mock-key",
            "alg": "HS256",
            "k": "c3VwZXItc2VjcmV0LWtleS10aGF0LWlzLWF0LWxlYXN0LTMyLWJ5dGVzLWxvbmchIQ" 
        }
    ]
}

@app.route("/protected")
async def protected():
    """An async route in Flask 2.0+"""
    try:
        # Use our helper to extract token from Flask request!
        token = Validator.extract_token(request)
        
        # Validate the token
        claims = await validator.validate(token, MOCK_JWKS)
        return jsonify({"message": "Access granted", "user_id": claims.sub})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 401

if __name__ == "__main__":
    app.run()
