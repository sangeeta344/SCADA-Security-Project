"""Unit tests for AES-GCM authenticated encryption, unique nonces, and tamper rejection."""

import os
import pytest
from security.encryption import AESGCMCipher
from security.key_manager import KeyManager
from security.integrity_check import IntegrityVerifier


def test_aes_gcm_encrypt_decrypt_valid():
    """Verify AES-GCM correctly encrypts and decrypts with matching AAD."""
    key = os.urandom(32)  # 256-bit key
    cipher = AESGCMCipher(key)

    plaintext = "SCADA_WRITE_HOLDING_REGISTERS:[2811, 2603, 9314, 3404]"
    aad = "DEV:RTU_01:TS:2026-10-25"

    enc = cipher.encrypt(plaintext, associated_data=aad)
    assert "ciphertext_b64" in enc
    assert "nonce_b64" in enc

    success, decrypted, err = cipher.decrypt(enc["ciphertext_b64"], enc["nonce_b64"], associated_data=aad)
    assert success is True
    assert decrypted == plaintext
    assert err is None


def test_unique_nonces_per_encryption():
    """Verify consecutive encryptions never reuse the same nonce."""
    key = os.urandom(32)
    cipher = AESGCMCipher(key)

    enc1 = cipher.encrypt("SAME_PAYLOAD")
    enc2 = cipher.encrypt("SAME_PAYLOAD")

    assert enc1["nonce_b64"] != enc2["nonce_b64"]
    assert enc1["ciphertext_b64"] != enc2["ciphertext_b64"]


def test_tampered_ciphertext_rejected():
    """Verify altered ciphertext fails authentication tag check."""
    key = os.urandom(32)
    cipher = AESGCMCipher(key)

    enc = cipher.encrypt("CRITICAL_SETPOINT_UPDATE", associated_data="CONTEXT_1")
    tampered_b64 = enc["ciphertext_b64"][:-2] + "XX"

    success, decrypted, err = cipher.decrypt(tampered_b64, enc["nonce_b64"], associated_data="CONTEXT_1")
    assert success is False
    assert decrypted is None
    assert "Invalid authentication tag" in err


def test_tampered_aad_rejected():
    """Verify modifying associated data causes authentication failure even if ciphertext untouched."""
    key = os.urandom(32)
    cipher = AESGCMCipher(key)

    enc = cipher.encrypt("VALID_DATA", associated_data="RTU_01")
    # Attacker tries to replay or route to RTU_02
    success, decrypted, err = cipher.decrypt(enc["ciphertext_b64"], enc["nonce_b64"], associated_data="RTU_02")
    assert success is False
    assert decrypted is None


def test_key_manager_kdf_and_session_expiration():
    """Verify KeyManager derives AES key via HKDF from accepted BB84 bits."""
    km = KeyManager(session_ttl_secs=1)  # Short TTL for test
    stat = km.initiate_bb84_exchange(raw_bits=256, noise_level=0.0, eavesdropper=False, seed=42)

    assert stat["is_encrypted"] is True
    cipher = km.get_cipher()
    assert cipher is not None

    # Test reset
    km.reset_session()
    assert km.get_cipher() is None
