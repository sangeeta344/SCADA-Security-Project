"""Unit tests for BB84 Quantum Key Distribution simulation and key sifting."""

import pytest
import random
from security.bb84_protocol import BB84Simulation
from security.key_sifting import KeySifter


def test_bb84_random_bits_and_bases():
    """Verify bit and basis generation respects ranges and basis options."""
    sim = BB84Simulation(raw_bits_count=100)
    rng = random.Random(42)

    bits = sim.generate_random_bits(100, rng)
    bases = sim.generate_random_bases(100, rng)

    assert len(bits) == 100
    assert all(b in (0, 1) for b in bits)
    assert len(bases) == 100
    assert all(b in ("+", "x") for b in bases)


def test_key_sifter_basis_matching():
    """Verify sifting correctly keeps bits only where bases match."""
    alice_bits = [1, 0, 1, 1, 0]
    alice_bases = ["+", "+", "x", "x", "+"]
    bob_bases = ["+", "x", "x", "+", "+"]
    bob_bits = [1, 1, 1, 0, 0]

    # Matching indices are: 0 (+ == +), 2 (x == x), 4 (+ == +)
    alice_sifted, bob_sifted, matched_idx = KeySifter.sift_keys(
        alice_bits, alice_bases, bob_bases, bob_bits
    )

    assert matched_idx == [0, 2, 4]
    assert alice_sifted == [1, 1, 0]
    assert bob_sifted == [1, 1, 0]


def test_disclosed_sample_excluded_from_final_key():
    """Verify disclosed estimation bits are strictly excluded from candidate key."""
    alice_sifted = [1, 0, 1, 0, 1, 1, 0, 1, 0, 0]
    bob_sifted = [1, 0, 1, 0, 1, 1, 0, 1, 0, 0]

    a_disc, b_disc, a_rem, b_rem = KeySifter.sample_for_error_estimation(
        alice_sifted, bob_sifted, sample_ratio=0.4, seed=42
    )

    # Disclosed + remaining must equal full sifted set length
    assert len(a_disc) + len(a_rem) == len(alice_sifted)
    assert len(b_disc) + len(b_rem) == len(bob_sifted)
    assert len(a_disc) > 0
    assert len(a_rem) > 0
