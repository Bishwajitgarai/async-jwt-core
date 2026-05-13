import json
import logging
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .decoder import base64url_decode
from ..exceptions import ValidationError

logger = logging.getLogger(__name__)

class JWE:
    """A minimal implementation of JSON Web Encryption (JWE) decryption.
    
    Supports RSA-OAEP and A128GCM/A256GCM.
    This is a highly advanced feature to help users handle encrypted tokens.
    """
    
    @staticmethod
    async def decrypt(token: str, private_key) -> str:
        """Decrypt a JWE token using an RSA private key.
        
        This method is async to fit the library's design.
        """
        try:
            parts = token.split(".")
            if len(parts) != 5:
                raise ValidationError("Invalid JWE format: must have 5 parts")

            header_b64, enc_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts

            # 1. Decode parts
            enc_key = base64url_decode(enc_key_b64)
            iv = base64url_decode(iv_b64)
            ciphertext = base64url_decode(ciphertext_b64)
            tag = base64url_decode(tag_b64)

            # 2. Decrypt Content Encryption Key (CEK)
            logger.debug("Decrypting CEK using RSA-OAEP")
            try:
                cek = private_key.decrypt(
                    enc_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None
                    )
                )
            except Exception as e:
                raise ValidationError(f"Failed to decrypt CEK: {e}") from e

            # 3. Decrypt payload using AES-GCM
            logger.debug("Decrypting payload using AES-GCM")
            try:
                aesgcm = AESGCM(cek)
                # Cryptography expects ciphertext and tag combined
                combined_data = ciphertext + tag
                # Associated data is the encoded header
                aad = header_b64.encode("utf-8")
                
                decrypted_bytes = aesgcm.decrypt(iv, combined_data, aad)
                return decrypted_bytes.decode("utf-8")
            except Exception as e:
                raise ValidationError(f"Failed to decrypt payload: {e}") from e

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during JWE decryption: {e}")
            raise ValidationError(f"Unexpected error during JWE decryption: {e}") from e
