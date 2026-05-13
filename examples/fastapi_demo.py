from fastapi import FastAPI, Depends, HTTPException, Request
from async_jwt_core import Validator, ValidationError

app = FastAPI()

# In a real app, you would fetch this from your IDP's .well-known/jwks.json
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

# Initialize validator
validator = Validator(
    algorithms=["HS256"],
    issuer="https://your-auth-domain.com"
)

async def get_current_user(request: Request):
    """Dependency to extract and validate token from request."""
    try:
        # Use our helper to extract token from request headers!
        token = Validator.extract_token(request)
        
        # Validate the token
        claims = await validator.validate(token, MOCK_JWKS)
        return claims
    except ValidationError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

@app.get("/protected")
async def protected_route(claims = Depends(get_current_user)):
    """A route that requires authentication."""
    return {
        "message": "You have access to this protected route!",
        "user_id": claims.sub
    }

@app.get("/")
def read_root():
    return {"message": "Welcome to the FastAPI async-jwt-core demo!"}
