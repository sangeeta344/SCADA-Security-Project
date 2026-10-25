"""Authenticated encryption using AES-GCM from the Python cryptography library."""

import os
import base64
from typing import Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from config.logging_config import logger


class AESGCMCipher:
    """Standard AES-GCM authenticated cipher with unique nonce generation per encryption."""

    def __init__(self, key_bytes: bytes):
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError(f"AES key must be 16, 24, or 32 bytes (128, 192, or 256 bits), got {len(key_bytes)}")
        self.key_bytes = key_bytes
        self.aesgcm = AESGCM(self.key_bytes)

    def encrypt(
        self,
        plaintext: str,
        associated_data: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Encrypt plaintext using AES-GCM.
        
        Args:
            plaintext: UTF-8 string to encrypt
            associated_data: Optional context string (e.g., device_id, timestamp) for AAD binding
            
        Returns:
            Dictionary containing base64 encoded ciphertext (including auth tag), nonce, and AAD
        """
        # 96-bit (12-byte) unique cryptographic nonce
        nonce = os.urandom(12)
        plaintext_bytes = plaintext.encode("utf-8")
        aad_bytes = associated_data.encode("utf-8") if associated_data else None

        # aesgcm.encrypt appends 16-byte authentication tag directly to ciphertext
        ciphertext_and_tag = self.aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)

        return {
            "ciphertext_b64": base64.b64encode(ciphertext_and_tag).decode("utf-8"),
            "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
            "associated_data": associated_data or "",
            "algorithm": "AES-256-GCM" if len(self.key_bytes) == 32 else "AES-128-GCM",
        }

    def decrypt(
        self,
        ciphertext_b64: str,
        nonce_b64: str,
        associated_data: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Decrypt and verify authentication tag of ciphertext.
        
        Returns:
            (success, decrypted_plaintext, error_message)
        """
        try:
            ciphertext_and_tag = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)
            aad_bytes = associated_data.encode("utf-8") if associated_data else None

            decrypted_bytes = self.aesgcm.decrypt(nonce, ciphertext_and_tag, aad_bytes)
            return True, decrypted_bytes.decode("utf-8"), None
        except InvalidTag:
            logger.warning("Decryption failed: Authentication tag verification failed (ciphertext or AAD modified)")
            return False, None, "Invalid authentication tag: Data was altered or forged"
        except Exception as e:
            logger.warning("Decryption error: %s", e)
            return False, None, f"Decryption failed: {str(e)}"
