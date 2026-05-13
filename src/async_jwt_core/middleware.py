import os
from typing import Optional, Dict, Any
from .core.validator import Validator
from .exceptions import ValidationError

# --- FastAPI / Starlette Middleware ---
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    class FastAPIMiddleware(BaseHTTPMiddleware):
        """FastAPI/Starlette Middleware for JWT Validation."""
        def __init__(self, app, validator: Optional[Validator] = None, jwks: Optional[Dict[str, Any]] = None):
            super().__init__(app)
            self.validator = validator or Validator()
            self.jwks = jwks or {"keys": []}

        async def dispatch(self, request: Request, call_next):
            try:
                token = Validator.extract_token(request)
                claims = await self.validator.validate(token, self.jwks)
                # Attach claims to request state
                request.state.user_claims = claims
            except ValidationError as e:
                return JSONResponse(status_code=401, content={"detail": str(e)})
            except Exception as e:
                return JSONResponse(status_code=401, content={"detail": f"Auth error: {e}"})
                
            return await call_next(request)
except ImportError:
    class FastAPIMiddleware:
        def __init__(self, *args, **kwargs):
            raise ImportError("starlette is required to use FastAPIMiddleware. Install it or use async-jwt-core[fastapi]")

# --- Flask Middleware ---
class FlaskMiddleware:
    """Flask Middleware for JWT Validation.
    
    Supports both sync and async views (Flask 2.0+).
    """
    def __init__(self, app=None, validator: Optional[Validator] = None, jwks: Optional[Dict[str, Any]] = None):
        self.validator = validator or Validator()
        self.jwks = jwks or {"keys": []}
        if app is not None:
            self.init_app(app)
            
    def init_app(self, app):
        from flask import request, jsonify, g
        import asyncio
        
        @app.before_request
        def before_request():
            try:
                token = Validator.extract_token(request)
                
                # Run async validation in a safe way
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                claims = loop.run_until_complete(self.validator.validate(token, self.jwks))
                # Attach to Flask global 'g'
                g.user_claims = claims
            except ValidationError as e:
                return jsonify({"error": str(e)}), 401
            except Exception as e:
                return jsonify({"error": f"Auth error: {e}"}), 401

# --- Django Middleware ---
class DjangoMiddleware:
    """Django Middleware for JWT Validation.
    
    Supports both sync and async views (Django 3.1+).
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.validator = Validator()
        
    def __call__(self, request):
        from django.http import JsonResponse
        import asyncio
        
        try:
            token = Validator.extract_token(request)
            
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
            # Try to get JWKS from Django settings
            jwks = {"keys": []}
            try:
                from django.conf import settings
                jwks = getattr(settings, "ASYNC_JWT_JWKS", {"keys": []})
            except:
                pass
                
            claims = loop.run_until_complete(self.validator.validate(token, jwks))
            # Attach to request object
            request.user_claims = claims
        except ValidationError as e:
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            return JsonResponse({"error": f"Auth error: {e}"}, status=401)

        response = self.get_response(request)
        return response
