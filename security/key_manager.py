"""Session key management and KDF derivation from BB84 quantum bit material."""

import time
from typing import Optional, Dict, Any, List
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from security.bb84_protocol import BB84Simulation
from security.encryption import AESGCMCipher
from database.repository import Repository, repo as default_repo
from database.models import QuantumSession, QberMeasurement
from config.logging_config import logger


class KeyManager:
    """Manages active session keys derived from BB84 exchanges between MTU and RTU."""

    def __init__(self, repository: Optional[Repository] = None, session_ttl_secs: int = 3600):
        self.repo = repository or default_repo
        self.session_ttl_secs = session_ttl_secs
        self.active_session_id: Optional[str] = None
        self.session_status: str = "NO_ACTIVE_SESSION"
        self._active_cipher: Optional[AESGCMCipher] = None
        self._key_created_time: float = 0.0
        self.latest_bb84_details: Dict[str, Any] = {}

    def _derive_aes_key(self, raw_bits: List[int], salt: bytes = b"scada_bb84_salt") -> bytes:
        """
        Derive 256-bit (32-byte) AES key from sifted BB84 bit array using HKDF-SHA256.
        
        Args:
            raw_bits: Array of binary 0s and 1s from accepted BB84 key material
            salt: Domain separation salt
            
        Returns:
            32-byte cryptographically strong key
        """
        # Pack bits into bytearray
        bit_string = "".join(str(b) for b in raw_bits)
        # Pad to multiple of 8
        remainder = len(bit_string) % 8
        if remainder != 0:
            bit_string = bit_string + ("0" * (8 - remainder))

        key_material_bytes = int(bit_string, 2).to_bytes(len(bit_string) // 8, byteorder="big")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit AES key
            salt=salt,
            info=b"scada-modbus-mqtt-bb84-session-key",
        )
        return hkdf.derive(key_material_bytes)

    def initiate_bb84_exchange(
        self,
        raw_bits: int = 256,
        noise_level: float = 0.0,
        eavesdropper: bool = False,
        seed: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute simulated BB84 QKD and establish fresh AES session key if accepted.
        
        Returns:
            Summary of session outcome and parameters (keys are never exposed in plaintext).
        """
        sim = BB84Simulation(raw_bits_count=raw_bits, seed=seed)
        result = sim.run_key_exchange(
            noise_level=noise_level,
            eavesdropper_present=eavesdropper,
            seed=seed,
        )

        session_id = result["session_id"]
        status = result["status"]
        self.latest_bb84_details = {k: v for k, v in result.items() if k != "key_material_bits"}

        # Record in database
        try:
            q_sess = QuantumSession(
                session_id=session_id,
                alice_id=result["alice_id"],
                bob_id=result["bob_id"],
                raw_bits_count=result["raw_bits_count"],
                sifted_bits_count=result["sifted_bits_count"],
                disclosed_sample_count=result["disclosed_sample_count"],
                final_key_bits_count=result["final_key_bits_count"],
                qber=result["qber"],
                qber_threshold=result["qber_threshold"],
                status=status,
                eavesdropper_present=1 if eavesdropper else 0,
                noise_level=noise_level,
                rejection_reason=result.get("rejection_reason"),
            )
            self.repo.insert_quantum_session(q_sess)

            q_meas = QberMeasurement(
                session_id=session_id,
                qber=result["qber"],
                sample_size=result["disclosed_sample_count"],
                errors_detected=result["errors_detected"],
                noise_level=noise_level,
                eavesdropper_present=1 if eavesdropper else 0,
                threshold=result["qber_threshold"],
                passed=1 if result["passed"] else 0,
            )
            self.repo.insert_qber_measurement(q_meas)
        except Exception as e:
            logger.error("Failed to persist BB84 session to database: %s", e)

        # Handle Key Acceptance vs Rejection
        if result["passed"] and result.get("key_material_bits"):
            derived_key = self._derive_aes_key(result["key_material_bits"])
            self._active_cipher = AESGCMCipher(derived_key)
            self.active_session_id = session_id
            self.session_status = "ESTABLISHED"
            self._key_created_time = time.time()
            logger.info("New AES-256-GCM session key successfully established from BB84 session %s", session_id)
        else:
            # Key rejected due to high QBER or insufficient bits
            self.active_session_id = None
            self.session_status = f"REJECTED: {result.get('rejection_reason')}"
            self._active_cipher = None
            logger.warning("BB84 Session rejected: %s", result.get("rejection_reason"))

        return self.get_session_status()

    def get_cipher(self) -> Optional[AESGCMCipher]:
        """Get active AESGCM cipher if valid and not expired."""
        if not self._active_cipher or not self.active_session_id:
            return None
        # Check expiration
        if time.time() - self._key_created_time > self.session_ttl_secs:
            self.reset_session()
            return None
        return self._active_cipher

    def reset_session(self) -> None:
        """Invalidate active session and wipe cipher from memory."""
        self.active_session_id = None
        self.session_status = "SESSION_EXPIRED"
        self._active_cipher = None
        self._key_created_time = 0.0

    def get_session_status(self) -> Dict[str, Any]:
        """Return public session status for web UI."""
        is_active = self.get_cipher() is not None
        return {
            "active_session_id": self.active_session_id,
            "session_status": self.session_status if not is_active and self.session_status == "ESTABLISHED" else (
                "ESTABLISHED" if is_active else self.session_status
            ),
            "is_encrypted": is_active,
            "cipher_algorithm": "AES-256-GCM" if is_active else "NONE (UNENCRYPTED)",
            "ttl_remaining_secs": max(0, int(self.session_ttl_secs - (time.time() - self._key_created_time))) if is_active else 0,
            "latest_bb84": self.latest_bb84_details,
        }


key_manager = KeyManager()
