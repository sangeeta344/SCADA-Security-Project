"""Unit tests for QBER calculation, noise modeling, and threshold enforcement."""

import pytest
from security.qber_calculator import QBERCalculator
from security.bb84_protocol import BB84Simulation


def test_qber_exact_computation():
    """Verify QBER calculator returns exact error fractions."""
    # 0 errors out of 10 bits -> 0.0 QBER
    res_clean = QBERCalculator.calculate_qber([1, 0, 1, 0], [1, 0, 1, 0], threshold=0.11)
    assert res_clean["qber"] == 0.0
    assert res_clean["passed"] is True

    # 2 errors out of 10 bits -> 0.20 QBER (exceeds 0.11 threshold)
    a = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0]
    b = [1, 1, 1, 0, 1, 1, 1, 0, 1, 0]  # indices 1 and 5 mismatch
    res_noisy = QBERCalculator.calculate_qber(a, b, threshold=0.11)
    assert res_noisy["qber"] == 0.20
    assert res_noisy["passed"] is False
    assert res_noisy["errors"] == 2


def test_bb84_zero_noise_acceptance():
    """Verify BB84 with 0 noise and no eavesdropper succeeds and produces key material."""
    sim = BB84Simulation(raw_bits_count=256, qber_threshold=0.11, seed=42)
    res = sim.run_key_exchange(noise_level=0.0, eavesdropper_present=False, seed=42)

    assert res["status"] == "ACCEPTED"
    assert res["passed"] is True
    assert res["qber"] == 0.0
    assert res["final_key_bits_count"] >= 32
    assert res["key_material_bits"] is not None


def test_bb84_eavesdropper_detection_and_rejection():
    """Verify eavesdropper presence causes high QBER and key rejection."""
    sim = BB84Simulation(raw_bits_count=256, qber_threshold=0.11, seed=42)
    res = sim.run_key_exchange(noise_level=0.0, eavesdropper_present=True, seed=42)

    assert res["status"] == "REJECTED"
    assert res["passed"] is False
    # Theoretical expectation for intercept-resend attack is ~25% error on sifted sample
    assert res["qber"] > 0.11
    assert res["key_material_bits"] is None
    assert "exceeds threshold" in res["rejection_reason"]


def test_bb84_excessive_noise_rejection():
    """Verify environmental noise above threshold causes session rejection."""
    sim = BB84Simulation(raw_bits_count=256, qber_threshold=0.11, seed=42)
    res = sim.run_key_exchange(noise_level=0.25, eavesdropper_present=False, seed=42)

    assert res["status"] == "REJECTED"
    assert res["passed"] is False
    assert res["qber"] > 0.11
