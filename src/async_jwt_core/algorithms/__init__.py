from .base import Algorithm
from .rsa import RS256, RS384, RS512, PS256, PS384, PS512
from .hmac import HS256, HS384, HS512
from .ecdsa import ES256, ES384, ES512
from .eddsa import EdDSA
from ..exceptions import ValidationError

_ALGORITHMS = {
    "RS256": RS256,
    "RS384": RS384,
    "RS512": RS512,
    "PS256": PS256,
    "PS384": PS384,
    "PS512": PS512,
    "HS256": HS256,
    "HS384": HS384,
    "HS512": HS512,
    "ES256": ES256,
    "ES384": ES384,
    "ES512": ES512,
    "EdDSA": EdDSA,
}

def get_algorithm(name: str) -> Algorithm:
    """Get algorithm instance by name."""
    alg = _ALGORITHMS.get(name)
    if not alg:
        raise ValidationError(f"Unsupported algorithm: {name}")
    return alg

def register_algorithm(name: str, alg: Algorithm):
    """Register a custom algorithm. This makes the library extensible."""
    _ALGORITHMS[name] = alg
