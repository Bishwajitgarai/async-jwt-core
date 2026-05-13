from .base import Algorithm
from .rsa import RS256
from .hmac import HS256
from ..exceptions import ValidationError

_ALGORITHMS = {
    "RS256": RS256(),
    "HS256": HS256(),
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
