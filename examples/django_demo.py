from django.http import JsonResponse
from async_jwt_core import Validator, ValidationError

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

async def protected_view(request):
    """An async view in Django 3.1+"""
    try:
        # Use our helper to extract token from Django request!
        # Django's request object has a .headers property.
        token = Validator.extract_token(request)
        
        # Validate the token
        claims = await validator.validate(token, MOCK_JWKS)
        return JsonResponse({"message": "Access granted", "user_id": claims.sub})
    except ValidationError as e:
        return JsonResponse({"error": str(e)}, status=401)
