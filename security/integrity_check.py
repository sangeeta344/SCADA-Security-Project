"""Payload integrity verification using HMAC-SHA256."""

import hmac
import hashlib
from typing import Dict, Any, Optional


class IntegrityVerifier:
    """Verifies tamper-evident integrity hashes for SCADA telemetry payloads."""

    @staticmethod
    def generate_hmac(payload_str: str, key_bytes: bytes) -> str:
        """Compute HMAC-SHA256 hex digest for a string payload."""
        return hmac.new(key_bytes, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_hmac(payload_str: str, expected_hmac: str, key_bytes: bytes) -> bool:
        """Constant-time comparison of HMAC digest to prevent timing attacks."""
        computed = IntegrityVerifier.generate_hmac(payload_str, key_bytes)
        return hmac.compare_digest(computed, expected_hmac)
