from abc import ABC, abstractmethod
from typing import Dict, Any

class Algorithm(ABC):
    """Abstract base class for all signature algorithms."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the algorithm (e.g., 'RS256')."""
        pass

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, jwk: Dict[str, Any]) -> bool:
        """Verify the signature of the message using the provided JWK.
        
        Should raise InvalidSignatureError if verification fails.
        """
        pass
